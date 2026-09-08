//! QuickNode push notifications are scan hints, never payment evidence.
//! Amounts, receipts, confirmations and ownership remain verified by RPC.
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, StatusCode};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::sync::{Mutex, mpsc};

use crate::{Chain, DetectorError, EthereumDetector, SolanaDetector};

const MAX_BODY: usize = 2 * 1024 * 1024;
pub type HttpError = (StatusCode, String);

fn setting(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn prefix(chain: Chain) -> &'static str {
    match chain {
        Chain::Solana => "SOLANA",
        Chain::Ethereum => "ETH",
        Chain::Base => "BASE",
        _ => unreachable!("QuickNode supports SOL/ETH/BASE here"),
    }
}

pub struct QuickNodeConfig {
    security_token: String,
    pub list_name: Option<String>,
    pub token_list_name: Option<String>,
}

impl QuickNodeConfig {
    pub fn from_env(chain: Chain) -> Result<Option<Self>, DetectorError> {
        let prefix = prefix(chain);
        let enabled = crate::env_utils::env_bool(&format!("QUICKNODE_{prefix}_WEBHOOK_ENABLED"))
            .or_else(|| crate::env_utils::env_bool("QUICKNODE_WEBHOOK_ENABLED"))
            .unwrap_or(false);
        if !enabled {
            return Ok(None);
        }
        let name = format!("QUICKNODE_{prefix}_SECURITY_TOKEN");
        let security_token = setting(&name).ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "{name} is required when QuickNode is enabled for {prefix}"
            ))
        })?;
        Ok(Some(Self {
            security_token,
            list_name: setting(&format!("QUICKNODE_{prefix}_LIST_NAME")),
            token_list_name: if chain == Chain::Solana {
                None
            } else {
                setting(&format!("QUICKNODE_{prefix}_TOKEN_LIST_NAME"))
            },
        }))
    }
}

/// One account client shared by all chains and the usage endpoint.
pub struct QuickNodeClient {
    http: reqwest::Client,
    base_url: reqwest::Url,
    usage_cache: Mutex<Option<(Instant, CreditsResponse)>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreditUsage {
    pub credits_used: i64,
    pub credits_remaining: i64,
    pub limit: i64,
    pub overages: Option<i64>,
    pub start_time: i64,
    pub end_time: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CreditsResponse {
    pub provider: &'static str,
    pub source: &'static str,
    pub fetched_at_unix: u64,
    pub cached: bool,
    #[serde(flatten)]
    pub usage: CreditUsage,
}

impl QuickNodeClient {
    pub fn from_env() -> Result<Option<Arc<Self>>, DetectorError> {
        let Some(key) = setting("QUICKNODE_API_KEY") else {
            return Ok(None);
        };
        Self::new(
            &key,
            &setting("QUICKNODE_API_BASE_URL")
                .unwrap_or_else(|| "https://api.quicknode.com".into()),
        )
        .map(|client| Some(Arc::new(client)))
    }

    pub fn new(key: &str, base_url: &str) -> Result<Self, DetectorError> {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut value = reqwest::header::HeaderValue::from_str(key)
            .map_err(|_| DetectorError::InvalidConfig("Invalid QUICKNODE_API_KEY header".into()))?;
        value.set_sensitive(true);
        headers.insert("x-api-key", value);
        let base_url = reqwest::Url::parse(base_url)
            .map_err(|_| DetectorError::InvalidConfig("Invalid QUICKNODE_API_BASE_URL".into()))?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            return Err(DetectorError::InvalidConfig(
                "QuickNode API URL must be HTTP(S)".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .user_agent(concat!(
                "crypto-payment-detector/",
                env!("CARGO_PKG_VERSION")
            ))
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| DetectorError::InvalidConfig("Cannot build QuickNode client".into()))?;
        Ok(Self {
            http,
            base_url,
            usage_cache: Mutex::new(None),
        })
    }

    pub async fn credits(&self) -> Result<CreditsResponse, HttpError> {
        // Serialize refreshes so multiple dashboards do not multiply API calls.
        let mut cache = self.usage_cache.lock().await;
        if let Some((when, value)) = cache.as_ref() {
            if when.elapsed() < Duration::from_secs(60) {
                let mut value = value.clone();
                value.cached = true;
                return Ok(value);
            }
        }
        let response = self
            .http
            .get(self.base_url.join("/v0/usage/rpc").unwrap())
            .send()
            .await
            .map_err(|_| upstream("QuickNode usage request failed"))?;
        let response = checked_response(response).await?;
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Envelope {
            Wrapped { data: CreditUsage },
            Direct(CreditUsage),
        }
        let envelope: Envelope = response
            .json()
            .await
            .map_err(|_| upstream("Invalid QuickNode usage response"))?;
        let value = CreditsResponse {
            provider: "quicknode",
            source: "/v0/usage/rpc",
            fetched_at_unix: unix_now(),
            cached: false,
            usage: match envelope {
                Envelope::Wrapped { data } => data,
                Envelope::Direct(data) => data,
            },
        };
        *cache = Some((Instant::now(), value.clone()));
        Ok(value)
    }

    /// Atomic additive updates preserve old wallets and concurrent assignments.
    pub async fn add_addresses(&self, list: &str, addresses: &[String]) -> Result<(), HttpError> {
        let mut url = self.base_url.join("/kv/rest/v1/lists/").unwrap();
        url.path_segments_mut().unwrap().pop_if_empty().push(list);
        for chunk in addresses.chunks(100) {
            let response = self
                .http
                .patch(url.clone())
                .json(&json!({"addItems": chunk}))
                .send()
                .await
                .map_err(|_| upstream("QuickNode address sync failed"))?;
            checked_response(response).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        routing::{get, patch},
    };
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn signed(body: &[u8]) -> HeaderMap {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(b"nonce1700000000");
        mac.update(body);
        let mut headers = HeaderMap::new();
        headers.insert("x-qn-nonce", "nonce".parse().unwrap());
        headers.insert("x-qn-timestamp", "1700000000".parse().unwrap());
        headers.insert(
            "x-qn-signature",
            hex::encode(mac.finalize().into_bytes()).parse().unwrap(),
        );
        headers
    }

    #[test]
    fn verifies_exact_bytes_and_rejects_tampering_missing_headers_and_replays() {
        let body = br#"{ "data": [{"value": 1}] }"#;
        let headers = signed(body);
        assert!(verify_delivery("secret", &headers, body, 1700000000).is_ok());
        for (secret, headers, body, now) in [
            (
                "wrong-chain-secret",
                headers.clone(),
                body.as_slice(),
                1700000000,
            ),
            ("secret", HeaderMap::new(), body.as_slice(), 1700000000),
            (
                "secret",
                headers.clone(),
                br#"{"data":[{"value":1}]}"#.as_slice(),
                1700000000,
            ),
            ("secret", headers.clone(), body.as_slice(), 1700000301),
            ("secret", headers.clone(), body.as_slice(), 1699999699),
        ] {
            assert_eq!(
                verify_delivery(secret, &headers, body, now).unwrap_err().0,
                StatusCode::UNAUTHORIZED
            );
        }
        let mut invalid = headers;
        invalid.insert("x-qn-signature", "not-hex".parse().unwrap());
        assert_eq!(
            verify_delivery("secret", &invalid, body, 1700000000)
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn gzip_signature_is_over_uncompressed_payload_and_expansion_is_bounded() {
        let body = br#"{"data":[]}"#;
        let gzip = |body: &[u8]| {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(body).unwrap();
            encoder.finish().unwrap()
        };
        let mut headers = signed(body);
        headers.insert("content-encoding", "gzip".parse().unwrap());
        assert_eq!(
            verify_delivery("secret", &headers, &gzip(body), 1700000000).unwrap(),
            json!({"data":[]})
        );
        assert_eq!(
            verify_delivery("secret", &headers, b"broken", 1700000000)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            verify_delivery(
                "secret",
                &headers,
                &gzip(&vec![b' '; MAX_BODY + 1]),
                1700000000
            )
            .unwrap_err()
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn signed_malformed_json_and_unsupported_encoding_are_rejected() {
        assert_eq!(
            verify_delivery("secret", &signed(b"bad"), b"bad", 1700000000)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut headers = signed(b"{}");
        headers.insert("content-encoding", "br".parse().unwrap());
        assert_eq!(
            verify_delivery("secret", &headers, b"{}", 1700000000)
                .unwrap_err()
                .0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn extracts_evm_native_and_erc20_recipients_from_raw_and_wrapped_payloads() {
        let address = format!("0x{}", "ab".repeat(20));
        let payload = json!({"data":[{"transactions":[{"to":address.to_uppercase()}],
            "receipts":[{"logs":[{"topics":[format!("0x{}", "f".repeat(64)),
                format!("0x{}{}", "0".repeat(24), &address[2..])]}]}]}],
            "malformed": format!("0x{}", "é".repeat(32))});
        assert_eq!(
            collect_evm_addresses(&payload),
            HashSet::from([address.to_string()])
        );
        assert_eq!(
            collect_evm_addresses(&json!([{"to":address}])),
            HashSet::from([address.to_string()])
        );
    }

    fn usage() -> Value {
        json!({"credits_used":100, "credits_remaining":79999900, "limit":80000000,
            "overages":null, "start_time":1700000000, "end_time":1700001000})
    }

    #[tokio::test]
    async fn usage_reads_real_upstream_values_and_coalesces_refreshes() {
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let server = crate::test_support::serve(Router::new().route(
            "/v0/usage/rpc",
            get(move |headers: HeaderMap| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert_eq!(headers["x-api-key"], "api-key");
                    assert_eq!(
                        headers["user-agent"],
                        concat!("crypto-payment-detector/", env!("CARGO_PKG_VERSION"))
                    );
                    Json(json!({"data": usage()}))
                }
            }),
        ))
        .await;
        let client = QuickNodeClient::new("api-key", &server.url).unwrap();
        let (first, second) = tokio::join!(client.credits(), client.credits());
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_eq!(first.usage.credits_remaining, 79999900);
        assert_eq!(first.usage.overages, None);
        assert_ne!(first.cached, second.cached);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn usage_accepts_direct_response_and_rejects_incomplete_data() {
        for valid in [true, false] {
            let server = crate::test_support::serve(Router::new().route(
                "/v0/usage/rpc",
                get(move || async move {
                    Json(if valid {
                        usage()
                    } else {
                        json!({"data":{"limit":80000000}})
                    })
                }),
            ))
            .await;
            let client = QuickNodeClient::new("key", &server.url).unwrap();
            let result = client.credits().await;
            assert_eq!(result.is_ok(), valid);
        }
    }

    #[tokio::test]
    async fn failed_usage_is_not_cached_or_returned_as_zero() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let server = crate::test_support::serve(Router::new().route(
            "/v0/usage/rpc",
            get(move || {
                let call = count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 0 {
                        (
                            StatusCode::TOO_MANY_REQUESTS,
                            Json(json!({"error":"private provider detail"})),
                        )
                    } else {
                        (StatusCode::OK, Json(usage()))
                    }
                }
            }),
        ))
        .await;
        let client = QuickNodeClient::new("key", &server.url).unwrap();
        let error = client.credits().await.unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_GATEWAY);
        assert!(!error.1.contains("private provider detail"));
        assert_eq!(client.credits().await.unwrap().usage.credits_used, 100);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn address_sync_uses_additive_batches_without_removing_old_wallets() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let server = crate::test_support::serve(Router::new().route(
            "/kv/rest/v1/lists/my-list",
            patch(move |headers: HeaderMap, Json(body): Json<Value>| {
                count.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert_eq!(headers["x-api-key"], "key");
                    assert!(body.get("removeItems").is_none());
                    assert!(body["addItems"].as_array().unwrap().len() <= 100);
                    StatusCode::OK
                }
            }),
        ))
        .await;
        let client = QuickNodeClient::new("key", &server.url).unwrap();
        let addresses: Vec<_> = (0..201).map(|i| i.to_string()).collect();
        client.add_addresses("my-list", &addresses).await.unwrap();
        client.add_addresses("my-list", &[]).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}

async fn checked_response(response: reqwest::Response) -> Result<reqwest::Response, HttpError> {
    if response.status().is_success() {
        return Ok(response);
    }
    // Do not reflect upstream bodies: they can contain account data or tokens.
    Err(upstream(&format!(
        "QuickNode returned HTTP {}",
        response.status().as_u16()
    )))
}

fn upstream(message: &str) -> HttpError {
    (StatusCode::BAD_GATEWAY, message.into())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Verify the exact decompressed bytes, before parsing JSON.
pub fn verify_delivery(
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
    now: u64,
) -> Result<Value, HttpError> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing QuickNode signature headers".into(),
            ))
    };
    let nonce = header("x-qn-nonce")?;
    let timestamp = header("x-qn-timestamp")?;
    let signature = header("x-qn-signature")?;
    let signed_at = timestamp.parse::<u64>().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid QuickNode timestamp".into(),
        )
    })?;
    if now.abs_diff(signed_at) > 300 {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Expired QuickNode signature".into(),
        ));
    }
    if body.len() > MAX_BODY {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Webhook body too large".into(),
        ));
    }
    let decoded;
    let body = match headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("identity")
    {
        "identity" => body,
        "gzip" => {
            let mut bytes = Vec::new();
            flate2::read::GzDecoder::new(body)
                .take((MAX_BODY + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid gzip payload".into()))?;
            if bytes.len() > MAX_BODY {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Decoded webhook body too large".into(),
                ));
            }
            decoded = bytes;
            &decoded
        }
        _ => {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Unsupported content encoding".into(),
            ));
        }
    };
    let signature = hex::decode(signature).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid QuickNode signature".into(),
        )
    })?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(nonce.as_bytes());
    mac.update(timestamp.as_bytes());
    mac.update(body);
    mac.verify_slice(&signature).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid QuickNode signature".into(),
        )
    })?;
    serde_json::from_slice(body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid JSON payload".into()))
}

/// QuickNode raw EVM logs encode recipients as zero-padded topic words.
pub fn collect_evm_addresses(payload: &Value) -> HashSet<String> {
    fn walk(value: &Value, out: &mut HashSet<String>) {
        match value {
            Value::String(value) => {
                if let Some(hex) = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                {
                    let hex = if hex.len() == 64 && hex.as_bytes()[..24].iter().all(|b| *b == b'0')
                    {
                        &hex[24..]
                    } else {
                        hex
                    };
                    if hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                        out.insert(format!("0x{}", hex.to_ascii_lowercase()));
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, out);
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    walk(value, out);
                }
            }
            _ => {}
        }
    }
    let mut out = HashSet::new();
    walk(payload, &mut out);
    out
}

#[derive(Clone)]
pub enum QuickNodeDetector {
    Solana(Arc<SolanaDetector>),
    Evm(Arc<EthereumDetector>),
}

impl QuickNodeDetector {
    fn addresses(&self) -> Vec<String> {
        match self {
            Self::Solana(d) => d.webhook_address_set(),
            Self::Evm(d) => d.webhook_address_set(),
        }
    }

    fn token_contracts(&self) -> Vec<String> {
        match self {
            Self::Solana(_) => Vec::new(),
            Self::Evm(d) => d.webhook_token_contracts(),
        }
    }

    async fn scan(&self, candidates: &HashSet<String>) -> Result<(), DetectorError> {
        match self {
            Self::Solana(d) => d.process_address_set_now(candidates).await.map(|_| ()),
            Self::Evm(d) => d.process_webhook_now().await,
        }
    }
}

pub struct QuickNodeWebhook {
    config: QuickNodeConfig,
    chain: Chain,
    detector: QuickNodeDetector,
    sender: mpsc::Sender<HashSet<String>>,
    client: Option<Arc<QuickNodeClient>>,
    synced: Mutex<HashSet<String>>,
    synced_tokens: Mutex<HashSet<String>>,
}

impl QuickNodeWebhook {
    pub fn start(
        chain: Chain,
        detector: QuickNodeDetector,
        client: Option<Arc<QuickNodeClient>>,
    ) -> Result<Option<Arc<Self>>, DetectorError> {
        let Some(config) = QuickNodeConfig::from_env(chain)? else {
            return Ok(None);
        };
        if (config.list_name.is_some() || config.token_list_name.is_some()) && client.is_none() {
            return Err(DetectorError::InvalidConfig(
                "QUICKNODE_API_KEY is required for address list sync".into(),
            ));
        }
        let (sender, mut receiver) = mpsc::channel::<HashSet<String>>(64);
        let worker = detector.clone();
        tokio::spawn(async move {
            while let Some(mut candidates) = receiver.recv().await {
                // Coalesce bursts while retaining at least one scan after arrivals.
                while let Ok(next) = receiver.try_recv() {
                    candidates.extend(next);
                }
                if let Err(error) = worker.scan(&candidates).await {
                    log::warn!(
                        "[QUICKNODE/{}] Scan failed; polling will retry: {error}",
                        chain.ticker()
                    );
                }
            }
        });
        let webhook = Arc::new(Self {
            config,
            chain,
            detector,
            sender,
            client,
            synced: Mutex::new(HashSet::new()),
            synced_tokens: Mutex::new(HashSet::new()),
        });
        log::info!(
            "[QUICKNODE/{}] Webhook enabled (address sync={}, token contract sync={})",
            chain.ticker(),
            webhook.config.list_name.is_some(),
            webhook.config.token_list_name.is_some()
        );
        if webhook.config.list_name.is_some() || webhook.config.token_list_name.is_some() {
            let weak = Arc::downgrade(&webhook);
            tokio::spawn(async move {
                loop {
                    let Some(webhook) = weak.upgrade() else {
                        break;
                    };
                    webhook.sync_addresses().await;
                    drop(webhook);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            });
        }
        Ok(Some(webhook))
    }

    pub async fn sync_addresses(&self) {
        if let Some(list) = &self.config.list_name {
            self.sync_list(list, self.detector.addresses(), &self.synced)
                .await;
        }
        if let Some(list) = &self.config.token_list_name {
            self.sync_list(list, self.detector.token_contracts(), &self.synced_tokens)
                .await;
        }
    }

    async fn sync_list(&self, list: &str, addresses: Vec<String>, synced: &Mutex<HashSet<String>>) {
        let Some(client) = &self.client else {
            return;
        };
        let mut synced = synced.lock().await;
        let missing: Vec<_> = addresses
            .into_iter()
            .filter(|a| !synced.contains(a))
            .collect();
        if missing.is_empty() {
            return;
        }
        match client.add_addresses(list, &missing).await {
            Ok(()) => {
                synced.extend(missing);
            }
            Err((_, error)) => log::warn!(
                "[QUICKNODE/{}] Address sync will retry: {error}",
                self.chain.ticker()
            ),
        }
    }

    pub fn accept(&self, headers: &HeaderMap, body: &[u8]) -> Result<usize, HttpError> {
        let payload = verify_delivery(&self.config.security_token, headers, body, unix_now())?;
        let mut candidates = match self.chain {
            Chain::Solana => crate::helius_webhooks::collect_candidate_addresses(&payload),
            _ => collect_evm_addresses(&payload),
        };
        let managed: HashSet<_> = self.detector.addresses().into_iter().collect();
        candidates.retain(|a| managed.contains(a));
        let count = candidates.len();
        if count > 0 {
            self.sender.try_send(candidates).map_err(|_| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "QuickNode scan queue unavailable; retry delivery".into(),
                )
            })?;
        }
        Ok(count)
    }
}
