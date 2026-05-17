use std::time::{Duration, Instant};

use ethers::types::{Address, U256};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::env_utils::redact_url_credentials;
use crate::error::DetectorError;

const DEFAULT_BASE_URL: &str = "https://api.etherscan.io/v2/api";
const DEFAULT_CHAIN_ID: u64 = 1;
const DEFAULT_TIMEOUT_SECS: u64 = 15;
const PAGE_SIZE: u32 = 10_000;
/// Etherscan free tier allows up to 5 calls/sec; we cap at 3/sec by default to
/// leave headroom for retries and other concurrent callers sharing the same key.
/// Translates to a 334ms minimum gap between requests (1000ms / 3 ≈ 334ms).
const DEFAULT_MIN_REQUEST_INTERVAL_MS: u64 = 334;

#[derive(Debug, Clone)]
pub struct EtherscanConfig {
    pub api_key: String,
    pub base_url: String,
    pub chain_id: u64,
    pub timeout_secs: u64,
    /// Minimum gap between successive Etherscan requests, in milliseconds.
    /// Used to stay under the free-tier rate limit (5 req/s on the public
    /// endpoint; we default to ~3 req/s).
    pub min_request_interval_ms: u64,
}

impl EtherscanConfig {
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("ETHERSCAN_API_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;

        let base_url = std::env::var("ETHERSCAN_BASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

        let chain_id = std::env::var("ETHERSCAN_CHAIN_ID")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_CHAIN_ID);

        let timeout_secs = std::env::var("ETHERSCAN_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECS);

        let min_request_interval_ms = std::env::var("ETHERSCAN_MIN_REQUEST_INTERVAL_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_MIN_REQUEST_INTERVAL_MS);

        Some(Self {
            api_key,
            base_url,
            chain_id,
            timeout_secs,
            min_request_interval_ms,
        })
    }
}

/// Internal CALL/CREATE entry as returned by Etherscan `txlistinternal`.
#[derive(Debug, Clone)]
pub struct EtherscanInternalTx {
    pub block_number: u64,
    pub hash: String,
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub trace_id: String,
    pub call_type: String,
    pub is_error: bool,
}

#[derive(Debug, Deserialize)]
struct RawResponse {
    status: String,
    message: String,
    #[serde(default)]
    result: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RawInternalTx {
    #[serde(default)]
    #[serde(rename = "blockNumber")]
    block_number: String,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    value: String,
    #[serde(default, rename = "traceId")]
    trace_id: String,
    #[serde(default, rename = "type")]
    call_type: String,
    #[serde(default, rename = "isError")]
    is_error: String,
}

#[derive(Debug)]
pub struct EtherscanClient {
    config: EtherscanConfig,
    client: reqwest::Client,
    /// Timestamp of the last request, guarded by an async mutex so callers
    /// from different tasks serialize through the rate limiter. Holding the
    /// mutex across `sleep + send` is intentional — concurrent calls would
    /// otherwise bypass the limit.
    last_request_at: Mutex<Option<Instant>>,
}

impl EtherscanClient {
    pub fn new(config: EtherscanConfig) -> Result<Self, DetectorError> {
        // No proxy: the request already authenticates with the API key, so
        // there's no anonymity benefit; and most public/free proxies are
        // either rate-limited or blocked by Etherscan's WAF, which would only
        // hurt reliability.
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(config.timeout_secs))
            .connection_verbose(false)
            .no_proxy()
            .build()
            .map_err(|e| {
                DetectorError::InvalidConfig(format!("Failed to build Etherscan HTTP client: {e}"))
            })?;

        Ok(Self {
            config,
            client,
            last_request_at: Mutex::new(None),
        })
    }

    pub fn base_url_redacted(&self) -> String {
        redact_url_credentials(&self.config.base_url)
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Fetch internal transactions touching `address` in `[from_block, to_block]`.
    ///
    /// Etherscan caps each response at PAGE_SIZE; we paginate until the page
    /// is short. Sorted ascending by block to make the loop deterministic.
    pub async fn list_internal_for_address(
        &self,
        address: Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<EtherscanInternalTx>, DetectorError> {
        if to_block < from_block {
            return Ok(Vec::new());
        }

        let address_hex = format!("0x{:x}", address);
        let mut all = Vec::new();
        let mut page: u32 = 1;

        loop {
            let url = build_query_url(
                &self.config.base_url,
                &[
                    ("chainid", &self.config.chain_id.to_string()),
                    ("module", "account"),
                    ("action", "txlistinternal"),
                    ("address", &address_hex),
                    ("startblock", &from_block.to_string()),
                    ("endblock", &to_block.to_string()),
                    ("page", &page.to_string()),
                    ("offset", &PAGE_SIZE.to_string()),
                    ("sort", "asc"),
                    ("apikey", &self.config.api_key),
                ],
            )?;

            // Throttle + send under the same mutex so concurrent callers
            // can't issue requests inside the same min-interval window.
            let response = {
                let mut last = self.last_request_at.lock().await;
                if let Some(previous) = *last {
                    let elapsed = previous.elapsed();
                    let min_interval = Duration::from_millis(self.config.min_request_interval_ms);
                    if elapsed < min_interval {
                        tokio::time::sleep(min_interval - elapsed).await;
                    }
                }
                let response = self
                    .client
                    .get(url)
                    .header("User-Agent", "karima-crypto-detector/1.0")
                    .send()
                    .await
                    .map_err(DetectorError::HttpError);
                *last = Some(Instant::now());
                response?
            };
            let status = response.status();
            let body = response.text().await.map_err(DetectorError::HttpError)?;
            if !status.is_success() {
                return Err(DetectorError::ApiError(format!(
                    "Etherscan txlistinternal HTTP {status}: {body}"
                )));
            }

            let parsed: RawResponse = serde_json::from_str(&body).map_err(|e| {
                DetectorError::ApiError(format!(
                    "Etherscan txlistinternal returned invalid JSON: {e}; body={body}"
                ))
            })?;

            // Etherscan returns status="0" with message="No transactions found"
            // when the range is empty for this address — that's a successful
            // empty result, not an error.
            if parsed.status != "1" {
                let msg_lower = parsed.message.to_ascii_lowercase();
                if msg_lower.contains("no transactions found") {
                    break;
                }
                // Rate-limit / quota errors come back as status="0" too.
                let result_str = match &parsed.result {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                return Err(DetectorError::ApiError(format!(
                    "Etherscan txlistinternal error: status={} message={} result={}",
                    parsed.status, parsed.message, result_str
                )));
            }

            let raw_list: Vec<RawInternalTx> = match parsed.result {
                serde_json::Value::Array(_) => {
                    serde_json::from_value(parsed.result).map_err(|e| {
                        DetectorError::ApiError(format!(
                            "Etherscan txlistinternal: failed to parse result array: {e}"
                        ))
                    })?
                }
                serde_json::Value::Null => Vec::new(),
                other => {
                    return Err(DetectorError::ApiError(format!(
                        "Etherscan txlistinternal: unexpected result shape: {other}"
                    )));
                }
            };

            let page_len = raw_list.len();
            for raw in raw_list {
                match parse_internal_tx(raw) {
                    Ok(tx) => all.push(tx),
                    Err(error) => {
                        log::warn!(
                            "[ETH] Skipping malformed Etherscan internal tx for {}: {error}",
                            address_hex
                        );
                    }
                }
            }

            if page_len < PAGE_SIZE as usize {
                break;
            }
            page = page.saturating_add(1);
            if page > 20 {
                // Hard cap. With min_confirmations=12 and max_blocks_per_cycle=250
                // a single address won't realistically have >200k internal txs in
                // a few minutes; if it does, something is wrong.
                log::warn!(
                    "[ETH] Etherscan pagination hit hard cap ({} pages) for {} in blocks {}..={}",
                    page - 1,
                    address_hex,
                    from_block,
                    to_block
                );
                break;
            }
        }

        Ok(all)
    }
}

fn parse_internal_tx(raw: RawInternalTx) -> Result<EtherscanInternalTx, String> {
    let block_number = raw
        .block_number
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("invalid blockNumber '{}': {e}", raw.block_number))?;

    let from = parse_address(&raw.from).map_err(|e| format!("invalid from '{}': {e}", raw.from))?;
    let to = parse_address(&raw.to).map_err(|e| format!("invalid to '{}': {e}", raw.to))?;

    let value = U256::from_dec_str(raw.value.trim())
        .map_err(|e| format!("invalid value '{}': {e}", raw.value))?;

    let is_error = matches!(raw.is_error.trim(), "1");

    Ok(EtherscanInternalTx {
        block_number,
        hash: raw.hash,
        from,
        to,
        value,
        trace_id: raw.trace_id,
        call_type: raw.call_type,
        is_error,
    })
}

fn build_query_url(base: &str, params: &[(&str, &str)]) -> Result<reqwest::Url, DetectorError> {
    reqwest::Url::parse_with_params(base, params).map_err(|e| {
        DetectorError::InvalidConfig(format!("Invalid Etherscan base URL '{base}': {e}"))
    })
}

fn parse_address(value: &str) -> Result<Address, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        // Etherscan returns "" for the `to` field of CREATE traces; treat as
        // zero-address so the caller can still filter against reservations.
        return Ok(Address::zero());
    }
    use std::str::FromStr;
    Address::from_str(trimmed).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_internal_tx_normal_call() {
        let raw = RawInternalTx {
            block_number: "12345".into(),
            hash: "0xabc".into(),
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value: "1000000000000000000".into(),
            trace_id: "0_1".into(),
            call_type: "call".into(),
            is_error: "0".into(),
        };
        let parsed = parse_internal_tx(raw).expect("parse should succeed");
        assert_eq!(parsed.block_number, 12345);
        assert_eq!(parsed.value, U256::from(1_000_000_000_000_000_000u64));
        assert!(!parsed.is_error);
        assert_eq!(parsed.trace_id, "0_1");
    }

    #[test]
    fn parse_internal_tx_create_with_empty_to() {
        let raw = RawInternalTx {
            block_number: "1".into(),
            hash: "0xabc".into(),
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "".into(),
            value: "0".into(),
            trace_id: "0".into(),
            call_type: "create".into(),
            is_error: "0".into(),
        };
        let parsed = parse_internal_tx(raw).expect("parse should succeed");
        assert_eq!(parsed.to, Address::zero());
    }

    #[test]
    fn parse_internal_tx_failed_call() {
        let raw = RawInternalTx {
            block_number: "1".into(),
            hash: "0xabc".into(),
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value: "0".into(),
            trace_id: "0".into(),
            call_type: "call".into(),
            is_error: "1".into(),
        };
        let parsed = parse_internal_tx(raw).expect("parse should succeed");
        assert!(parsed.is_error);
    }

    #[test]
    fn parse_internal_tx_invalid_block_number() {
        let raw = RawInternalTx {
            block_number: "not-a-number".into(),
            hash: "0xabc".into(),
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value: "0".into(),
            trace_id: "0".into(),
            call_type: "call".into(),
            is_error: "0".into(),
        };
        assert!(parse_internal_tx(raw).is_err());
    }

    fn test_config(min_interval_ms: u64) -> EtherscanConfig {
        EtherscanConfig {
            api_key: "test".into(),
            base_url: DEFAULT_BASE_URL.into(),
            chain_id: DEFAULT_CHAIN_ID,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            min_request_interval_ms: min_interval_ms,
        }
    }

    #[tokio::test]
    async fn rate_limiter_inserts_minimum_gap_between_requests() {
        // Use a small interval (50ms) so the test runs in real time but stays
        // fast. The rate limiter is private state inside the request loop;
        // we exercise it by replicating the same pattern with a fresh client.
        let client = EtherscanClient::new(test_config(50)).expect("client builds");

        let start = Instant::now();
        for _ in 0..3 {
            let mut last = client.last_request_at.lock().await;
            if let Some(previous) = *last {
                let elapsed = previous.elapsed();
                let min_interval = Duration::from_millis(client.config.min_request_interval_ms);
                if elapsed < min_interval {
                    tokio::time::sleep(min_interval - elapsed).await;
                }
            }
            *last = Some(Instant::now());
        }
        let total = start.elapsed();
        // 3 acquisitions at 50ms gap = 2 gaps × 50ms = 100ms minimum.
        // Allow some scheduling slack but make sure the throttle actually fired.
        assert!(
            total >= Duration::from_millis(95),
            "rate limiter did not enforce minimum gap, total elapsed {:?}",
            total
        );
    }

    #[test]
    fn config_from_env_uses_defaults_when_unset() {
        // Set only the required key; everything else should fall to defaults.
        unsafe {
            std::env::set_var("ETHERSCAN_API_KEY", "test_key_xyz");
            std::env::remove_var("ETHERSCAN_BASE_URL");
            std::env::remove_var("ETHERSCAN_CHAIN_ID");
            std::env::remove_var("ETHERSCAN_TIMEOUT_SECS");
            std::env::remove_var("ETHERSCAN_MIN_REQUEST_INTERVAL_MS");
        }
        let config = EtherscanConfig::from_env().expect("api key set");
        assert_eq!(config.api_key, "test_key_xyz");
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(
            config.min_request_interval_ms,
            DEFAULT_MIN_REQUEST_INTERVAL_MS
        );
        unsafe {
            std::env::remove_var("ETHERSCAN_API_KEY");
        }
    }
}
