use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::bitcoin_sweep::{self, BitcoinSweepConfig, BitcoinSweepResult, validate_sweep_config};
use crate::derivation::derive_address;
use crate::env_utils::redact_url_credentials;
use crate::error::DetectorError;
use crate::persistence::PendingPayment;
use crate::pricing::PriceFetcher;
use crate::recover::{RecoverResponse, RecoverStatus};
use crate::trait_def::PaymentDetector;
use crate::types::{Chain, DetectedPayment, DetectorConfig, WebhookEvent};
use crate::webhook::send_webhook;
use bitcoin::consensus::Decodable;
use rayon::prelude::*;
use serde::Deserialize;

#[derive(Debug, Clone)]
enum ExplorerApi {
    Esplora { base_url: String },
    Blockchair { base_url: String },
}

impl ExplorerApi {
    fn from_url(chain: Chain, url: &str) -> Self {
        let normalized = normalize_api_url(url);
        if normalized
            .to_ascii_lowercase()
            .contains("api.blockchair.com")
        {
            Self::Blockchair {
                base_url: normalize_blockchair_api_url(chain, &normalized),
            }
        } else {
            Self::Esplora {
                base_url: normalized,
            }
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Esplora { base_url } => format!("Esplora({base_url})"),
            Self::Blockchair { base_url } => format!("Blockchair({base_url})"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct BlockchairStatsResponse {
    data: BlockchairStatsData,
}

#[derive(Debug, Deserialize)]
struct BlockchairStatsData {
    best_block_height: u64,
}

#[derive(Debug, Deserialize)]
struct BlockchairBlockResponse {
    data: HashMap<String, BlockchairBlockEntry>,
}

#[derive(Debug, Deserialize)]
struct BlockchairBlockEntry {
    block: BlockchairBlockData,
}

#[derive(Debug, Deserialize)]
struct BlockchairBlockData {
    hash: String,
}

#[derive(Debug, Deserialize)]
struct BlockchairRawBlockResponse {
    data: HashMap<String, BlockchairRawBlockEntry>,
}

#[derive(Debug, Deserialize)]
struct BlockchairRawBlockEntry {
    raw_block: String,
}

fn normalize_api_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn blockchair_chain_slug(chain: Chain) -> &'static str {
    match chain {
        Chain::Bitcoin => "bitcoin",
        Chain::Litecoin => "litecoin",
        Chain::Solana => "solana",
        Chain::Ethereum => "ethereum",
        Chain::Base => "base",
    }
}

fn normalize_blockchair_api_url(chain: Chain, url: &str) -> String {
    let base_url = normalize_api_url(url);
    let slug = blockchair_chain_slug(chain);
    let lower = base_url.to_ascii_lowercase();

    if lower.ends_with(&format!("/{slug}")) || lower.contains(&format!("/{slug}/")) {
        base_url
    } else {
        format!("{base_url}/{slug}")
    }
}

fn blockchair_url(base_url: &str, path: &str) -> String {
    let mut url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    if let Ok(key) = std::env::var("BLOCKCHAIR_API_KEY") {
        let key = key.trim();
        if !key.is_empty() {
            let separator = if url.contains('?') { '&' } else { '?' };
            url.push(separator);
            url.push_str("key=");
            url.push_str(key);
        }
    }

    url
}

/// Upper bound on a single backoff sleep. `base_delay_ms << attempt` reaches
/// hours within ~20 attempts, which stalls the scan loop far longer than any
/// explorer outage warrants — and overflows outright past 64 attempts.
const MAX_RETRY_DELAY_MS: u64 = 30_000;

async fn retry<F, Fut, T>(
    name: &str,
    max_retries: u32,
    base_delay_ms: u64,
    f: F,
) -> Result<T, DetectorError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, DetectorError>>,
{
    // `MAX_RETRIES=0` would otherwise skip the loop entirely and leave no error
    // to return — the operation must run at least once.
    let attempts = max_retries.max(1);
    let mut last_err = None;

    for attempt in 0..attempts {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 == attempts {
                    break;
                }
                let delay = base_delay_ms
                    .saturating_mul(2u64.saturating_pow(attempt.min(32)))
                    .min(MAX_RETRY_DELAY_MS);
                log::warn!(
                    "Retry {}/{} for '{}' in {}ms - {}",
                    attempt + 1,
                    attempts,
                    name,
                    delay,
                    last_err.as_ref().expect("error recorded above")
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        DetectorError::ApiError(format!("'{name}' failed without recording an error"))
    }))
}

#[derive(Debug)]
struct SharedState {
    notified_confirmed: HashSet<String>,
    last_scanned_height: Option<u64>,
    pending: Vec<PendingPayment>,
    known_block_hashes: HashMap<u64, String>,
}

pub struct ChainDetector {
    config: DetectorConfig,
    client: reqwest::Client,
    webhook_client: reqwest::Client,
    price_fetcher: PriceFetcher,
    state: Arc<Mutex<SharedState>>,
    explorer_apis: Vec<ExplorerApi>,
    active_explorer_index: Mutex<usize>,
    sweep_config: Option<BitcoinSweepConfig>,
}

impl ChainDetector {
    pub fn new(config: DetectorConfig) -> Result<Self, DetectorError> {
        if config.xpub.is_empty() {
            return Err(DetectorError::InvalidConfig("xpub is required".into()));
        }
        if config.webhook_url.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "webhook_url is required".into(),
            ));
        }
        if config.webhook_hmac_secret.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "webhook_hmac_secret is required".into(),
            ));
        }

        derive_address(&config.xpub, 0, config.chain)?;

        let explorer_apis = config
            .chain
            .explorer_api_urls(config.explorer_api_url.as_deref())
            .into_iter()
            .map(|url| ExplorerApi::from_url(config.chain, &url))
            .collect::<Vec<_>>();

        if explorer_apis.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "At least one explorer API URL is required".into(),
            ));
        }

        let mut client_builder = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .connection_verbose(false);
        if let Some(ref proxy_url) = config.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| DetectorError::InvalidConfig(format!("Invalid proxy URL: {e}")))?;
            client_builder = client_builder.proxy(proxy);
            log::info!(
                "[{}] Using proxy: {}",
                config.chain.ticker(),
                redact_url_credentials(proxy_url)
            );
        }
        let client = client_builder.build().map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to build HTTP client: {e}"))
        })?;

        let webhook_client = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .connection_verbose(false)
            .build()
            .map_err(|e| {
                DetectorError::InvalidConfig(format!("Failed to build webhook client: {e}"))
            })?;

        let price_fetcher =
            PriceFetcher::new(webhook_client.clone(), &config.fiat_currency, config.chain);

        let explorer_list = explorer_apis
            .iter()
            .map(ExplorerApi::label)
            .collect::<Vec<_>>()
            .join(", ");

        let sweep_config = match (&config.sweep_xpriv, &config.sweep_destination) {
            (Some(xpriv), Some(destination))
                if !xpriv.trim().is_empty() && !destination.trim().is_empty() =>
            {
                let candidate = BitcoinSweepConfig {
                    chain: config.chain,
                    xpriv: xpriv.clone(),
                    destination: destination.clone(),
                    fee_rate_sats_per_vb: config.sweep_fee_rate_sats_per_vb.max(1),
                    min_sweep_sat: config.sweep_min_sat,
                    max_fee_ratio: config.sweep_max_fee_ratio,
                };
                validate_sweep_config(&candidate)?;
                log::info!(
                    "[{}] Sweep enabled - destination: {} (fee_rate {} sat/vB, min_sweep {} sat)",
                    config.chain.ticker(),
                    candidate.destination,
                    candidate.fee_rate_sats_per_vb,
                    candidate.min_sweep_sat
                );
                Some(candidate)
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(DetectorError::InvalidConfig(format!(
                    "[{}] sweep_xpriv and sweep_destination must both be set to enable sweep",
                    config.chain.ticker()
                )));
            }
            _ => None,
        };

        log::info!(
            "[{}] Detector initialized - explorers: {}",
            config.chain.ticker(),
            explorer_list
        );

        Ok(Self {
            config,
            client,
            webhook_client,
            price_fetcher,
            state: Arc::new(Mutex::new(SharedState {
                notified_confirmed: HashSet::new(),
                last_scanned_height: None,
                pending: Vec::new(),
                known_block_hashes: HashMap::new(),
            })),
            explorer_apis,
            active_explorer_index: Mutex::new(0),
            sweep_config,
        })
    }

    pub fn sweep_destination(&self) -> Option<&str> {
        self.sweep_config.as_ref().map(|c| c.destination.as_str())
    }

    fn esplora_base_url(&self) -> Option<String> {
        let index = *self
            .active_explorer_index
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.explorer_apis
            .get(index)
            .or_else(|| self.explorer_apis.first())
            .and_then(|explorer| match explorer {
                ExplorerApi::Esplora { base_url } => Some(base_url.clone()),
                ExplorerApi::Blockchair { .. } => None,
            })
            .or_else(|| {
                self.explorer_apis
                    .iter()
                    .find_map(|explorer| match explorer {
                        ExplorerApi::Esplora { base_url } => Some(base_url.clone()),
                        ExplorerApi::Blockchair { .. } => None,
                    })
            })
    }

    async fn maybe_sweep(
        &self,
        derivation_index: u32,
        address: &str,
    ) -> Option<BitcoinSweepResult> {
        let sweep_config = self.sweep_config.as_ref()?;
        let esplora = match self.esplora_base_url() {
            Some(url) => url,
            None => {
                log::warn!(
                    "[{}] Cannot sweep {}: no Esplora-compatible explorer configured (Blockchair-only fallback does not support UTXOs/broadcast)",
                    self.config.chain.ticker(),
                    address
                );
                return None;
            }
        };

        match bitcoin_sweep::sweep_address(
            &self.client,
            &esplora,
            sweep_config,
            derivation_index,
            address,
        )
        .await
        {
            Ok(result) => Some(result),
            Err(error) => {
                log::error!(
                    "[{}] Sweep failed for {} (index {}): {error}",
                    self.config.chain.ticker(),
                    address,
                    derivation_index
                );
                None
            }
        }
    }

    pub fn chain(&self) -> Chain {
        self.config.chain
    }

    /// Poison-tolerant state lock.
    ///
    /// A panic anywhere under the lock would otherwise poison it, and every
    /// later `lock().unwrap()` would panic in turn — one transient bug would
    /// take the detector down permanently instead of for a single cycle. The
    /// guarded state is plain data with no invariant that a partial update can
    /// break, so recovering the inner value is safe.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, SharedState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Snapshot the mutable state and write it to the state file.
    ///
    /// Everything the scan loop cannot reconstruct after a restart lives here:
    /// the scan height, the reorg hash window, payments still waiting for
    /// confirmations, and the txids already credited.
    fn persist_state(&self) -> Result<(), DetectorError> {
        let snapshot = {
            let state = self.lock_state();
            crate::persistence::PersistedState {
                last_scanned_height: state.last_scanned_height,
                known_block_hashes: state.known_block_hashes.clone(),
                pending: state.pending.clone(),
                notified_confirmed: state.notified_confirmed.clone(),
            }
        };
        crate::persistence::save_state(&self.config.state_file, &snapshot)
    }

    async fn try_explorers<T, F, Fut>(&self, name: &str, mut call: F) -> Result<T, DetectorError>
    where
        F: FnMut(ExplorerApi) -> Fut,
        Fut: Future<Output = Result<T, DetectorError>>,
    {
        let len = self.explorer_apis.len();
        let start = *self
            .active_explorer_index
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut last_err = None;

        for offset in 0..len {
            let index = (start + offset) % len;
            let explorer = self.explorer_apis[index].clone();
            let label = explorer.label();

            match call(explorer).await {
                Ok(value) => {
                    if index != start {
                        log::warn!(
                            "[{}] Switching explorer API to {} after fallback during {}",
                            self.config.chain.ticker(),
                            label,
                            name
                        );
                    }
                    *self
                        .active_explorer_index
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = index;
                    return Ok(value);
                }
                Err(error) => {
                    log::warn!(
                        "[{}] Explorer {} failed during {}: {}",
                        self.config.chain.ticker(),
                        label,
                        name,
                        error
                    );
                    last_err = Some(error);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            DetectorError::ApiError(format!("No explorer API configured for {name}"))
        }))
    }

    async fn get_chain_tip(&self) -> Result<u64, DetectorError> {
        self.try_explorers("get_chain_tip", |explorer| async move {
            self.get_chain_tip_from(&explorer).await
        })
        .await
    }

    async fn get_chain_tip_from(&self, explorer: &ExplorerApi) -> Result<u64, DetectorError> {
        let max_retries = self.config.retry.max_retries;
        let base_delay = self.config.retry.base_delay_ms;

        match explorer {
            ExplorerApi::Esplora { base_url } => {
                let client = &self.client;
                let url = format!("{base_url}/blocks/tip/height");
                let name = format!("get_chain_tip {}", explorer.label());
                retry(&name, max_retries, base_delay, || async {
                    let resp = client.get(&url).send().await?;
                    if !resp.status().is_success() {
                        return Err(DetectorError::ApiError(format!(
                            "Failed to fetch chain tip (status {})",
                            resp.status()
                        )));
                    }
                    let body = resp.text().await?;
                    body.trim().parse::<u64>().map_err(|e| {
                        DetectorError::ApiError(format!("Failed to parse tip height: {e}"))
                    })
                })
                .await
            }
            ExplorerApi::Blockchair { base_url } => {
                let client = &self.client;
                let url = blockchair_url(base_url, "stats");
                let name = format!("get_chain_tip {}", explorer.label());
                retry(&name, max_retries, base_delay, || async {
                    let resp = client.get(&url).send().await?;
                    if !resp.status().is_success() {
                        return Err(DetectorError::ApiError(format!(
                            "Failed to fetch Blockchair stats (status {})",
                            resp.status()
                        )));
                    }
                    let body = resp.json::<BlockchairStatsResponse>().await?;
                    Ok(body.data.best_block_height)
                })
                .await
            }
        }
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, DetectorError> {
        self.try_explorers("get_block_hash", |explorer| async move {
            self.get_block_hash_from(&explorer, height).await
        })
        .await
    }

    async fn get_block_hash_from(
        &self,
        explorer: &ExplorerApi,
        height: u64,
    ) -> Result<String, DetectorError> {
        let max_retries = self.config.retry.max_retries;
        let base_delay = self.config.retry.base_delay_ms;

        match explorer {
            ExplorerApi::Esplora { base_url } => {
                let client = &self.client;
                let url = format!("{base_url}/block-height/{height}");
                let name = format!("get_block_hash {}", explorer.label());
                retry(&name, max_retries, base_delay, || async {
                    let resp = client.get(&url).send().await?;
                    if !resp.status().is_success() {
                        return Err(DetectorError::ApiError(format!(
                            "Block height {} not found (status {})",
                            height,
                            resp.status()
                        )));
                    }
                    let hash = resp.text().await?;
                    Ok(hash.trim().to_string())
                })
                .await
            }
            ExplorerApi::Blockchair { base_url } => {
                let client = &self.client;
                let url = blockchair_url(base_url, &format!("dashboards/block/{height}?limit=0"));
                let name = format!("get_block_hash {}", explorer.label());
                retry(&name, max_retries, base_delay, || async {
                    let resp = client.get(&url).send().await?;
                    if !resp.status().is_success() {
                        return Err(DetectorError::ApiError(format!(
                            "Blockchair block height {} not found (status {})",
                            height,
                            resp.status()
                        )));
                    }
                    let body = resp.json::<BlockchairBlockResponse>().await?;
                    body.data
                        .values()
                        .next()
                        .map(|entry| entry.block.hash.clone())
                        .ok_or_else(|| {
                            DetectorError::ApiError(format!(
                                "Blockchair returned no block data for height {height}"
                            ))
                        })
                })
                .await
            }
        }
    }

    async fn fetch_raw_block(&self, hash: &str) -> Result<bitcoin::Block, DetectorError> {
        self.try_explorers("fetch_raw_block", |explorer| async move {
            self.fetch_raw_block_from(&explorer, hash).await
        })
        .await
    }

    async fn fetch_raw_block_from(
        &self,
        explorer: &ExplorerApi,
        hash: &str,
    ) -> Result<bitcoin::Block, DetectorError> {
        let bytes = self.fetch_raw_block_bytes_from(explorer, hash).await?;

        // Litecoin blocks carry MWEB extensions the bitcoin crate cannot decode.
        let block = match self.config.chain {
            Chain::Litecoin => crate::litecoin_block::deserialize_litecoin_block(&bytes)?,
            _ => bitcoin::Block::consensus_decode(&mut bytes.as_slice())
                .map_err(|e| DetectorError::ApiError(format!("Failed to parse raw block: {e}")))?,
        };

        Ok(block)
    }

    async fn fetch_raw_block_bytes_from(
        &self,
        explorer: &ExplorerApi,
        hash: &str,
    ) -> Result<Vec<u8>, DetectorError> {
        let max_retries = self.config.retry.max_retries;
        let base_delay = self.config.retry.base_delay_ms;

        match explorer {
            ExplorerApi::Esplora { base_url } => {
                let client = &self.client;
                let url = format!("{base_url}/block/{hash}/raw");
                let name = format!("fetch_raw_block {}", explorer.label());
                retry(&name, max_retries, base_delay, || async {
                    let resp = client
                        .get(&url)
                        .send()
                        .await
                        .map_err(|e| DetectorError::ApiError(e.to_string()))?;

                    if !resp.status().is_success() {
                        return Err(DetectorError::ApiError(format!(
                            "Failed to fetch raw block (status {})",
                            resp.status()
                        )));
                    }

                    resp.bytes()
                        .await
                        .map(|b| b.to_vec())
                        .map_err(|e| DetectorError::ApiError(e.to_string()))
                })
                .await
            }
            ExplorerApi::Blockchair { base_url } => {
                let client = &self.client;
                let url = blockchair_url(base_url, &format!("raw/block/{hash}"));
                let name = format!("fetch_raw_block {}", explorer.label());
                let hex_str: String = retry(&name, max_retries, base_delay, || async {
                    let resp = client
                        .get(&url)
                        .send()
                        .await
                        .map_err(|e| DetectorError::ApiError(e.to_string()))?;

                    if !resp.status().is_success() {
                        return Err(DetectorError::ApiError(format!(
                            "Failed to fetch Blockchair raw block (status {})",
                            resp.status()
                        )));
                    }

                    let body = resp
                        .json::<BlockchairRawBlockResponse>()
                        .await
                        .map_err(|e| DetectorError::ApiError(e.to_string()))?;

                    body.data
                        .values()
                        .next()
                        .map(|entry| entry.raw_block.clone())
                        .ok_or_else(|| {
                            DetectorError::ApiError(format!(
                                "Blockchair returned no raw block data for {hash}"
                            ))
                        })
                })
                .await?;

                hex::decode(hex_str.trim()).map_err(|e| {
                    DetectorError::ApiError(format!("Failed to decode Blockchair block hex: {e}"))
                })
            }
        }
    }

    fn build_address_lookup(&self, max_index: u32) -> Result<HashMap<String, u32>, DetectorError> {
        let mut map = HashMap::with_capacity(max_index as usize + 1);
        for i in 0..=max_index {
            let addr = derive_address(&self.config.xpub, i, self.config.chain)?;
            map.insert(addr, i);
        }
        Ok(map)
    }

    fn scan_raw_block_parallel(
        &self,
        block: &bitcoin::Block,
        address_lookup: &HashMap<String, u32>,
        block_height: u64,
        tip_height: u64,
    ) -> Vec<DetectedPayment> {
        let chain = self.config.chain;
        let network = chain.bitcoin_network();
        let confirmations = tip_height.saturating_sub(block_height) + 1;

        block
            .txdata
            .par_iter()
            .flat_map(|tx| {
                let txid = tx.compute_txid().to_string();
                tx.output
                    .par_iter()
                    .filter_map(move |output| {
                        let script = &output.script_pubkey;
                        let addr_str = bitcoin::Address::from_script(script, network)
                            .ok()
                            .map(|a| a.to_string());

                        let addr_str = match chain {
                            Chain::Bitcoin => addr_str?,
                            Chain::Litecoin => {
                                let btc_addr = addr_str?;
                                if btc_addr.starts_with("bc1") {
                                    use bech32::Hrp;
                                    let (_hrp, witness_version, witness_program) =
                                        bech32::segwit::decode(&btc_addr).ok()?;
                                    let ltc_hrp = Hrp::parse("ltc").unwrap();
                                    bech32::segwit::encode(
                                        ltc_hrp,
                                        witness_version,
                                        &witness_program,
                                    )
                                    .ok()?
                                } else {
                                    btc_addr
                                }
                            }
                            Chain::Solana | Chain::Ethereum | Chain::Base => return None,
                        };

                        let &index = address_lookup.get(&addr_str)?;
                        let amount_sat = output.value.to_sat();
                        Some(DetectedPayment {
                            chain,
                            ticker: chain.ticker().to_string(),
                            txid: txid.clone(),
                            address: addr_str,
                            user_id: None,
                            amount_sat,
                            amount_coin: amount_sat as f64 / chain.sats_per_unit() as f64,
                            confirmations,
                            block_height: Some(block_height),
                            derivation_index: index,
                            memo: None,
                            swept_to_address: None,
                            swept_amount_sat: None,
                            swept_amount_coin: None,
                            sweep_txid: None,
                            fiat_amount: None,
                            fiat_currency: None,
                            coin_price: None,
                            event_id: None,
                            log_index: None,
                            asset: None,
                            asset_decimals: None,
                            amount_base_units: None,
                            swept_amount_base_units: None,
                            token_contract: None,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    async fn detect_reorg(&self, current_height: u64) -> u64 {
        let known = {
            let state = self.lock_state();
            state.known_block_hashes.clone()
        };

        let mut depth = 0u64;
        let mut check_height = current_height.saturating_sub(1);

        loop {
            let stored_hash = match known.get(&check_height) {
                Some(h) => h.clone(),
                None => break,
            };

            let chain_hash = match self.get_block_hash(check_height).await {
                Ok(h) => h,
                Err(e) => {
                    log::warn!(
                        "[{}] Failed to verify block hash at height {}: {e}",
                        self.config.chain.ticker(),
                        check_height
                    );
                    break;
                }
            };

            if stored_hash == chain_hash {
                break;
            }

            depth += 1;
            log::warn!(
                "[{}] Block {} hash mismatch: stored={} chain={} (reorg depth {})",
                self.config.chain.ticker(),
                check_height,
                &stored_hash[..8],
                &chain_hash[..8],
                depth
            );

            if check_height == 0 {
                break;
            }
            check_height -= 1;
        }

        depth
    }

    fn enqueue_or_confirm(&self, payments: Vec<DetectedPayment>) {
        let min_conf = self.config.min_confirmations;
        let mut state = self.lock_state();
        for payment in payments {
            if state.notified_confirmed.contains(&payment.txid) {
                continue;
            }
            let already_pending = state.pending.iter().any(|p| p.payment.txid == payment.txid);
            if already_pending {
                continue;
            }
            if payment.confirmations < min_conf {
                log::info!(
                    "[{}] Payment pending ({}/{} confirmations): txid={} amount={} sats",
                    self.config.chain.ticker(),
                    payment.confirmations,
                    min_conf,
                    &payment.txid[..12],
                    payment.amount_sat,
                );
            }
            state.pending.push(PendingPayment {
                payment: payment.clone(),
                block_height: payment.block_height.unwrap_or(0),
            });
        }
    }

    async fn process_confirmed(&self, tip_height: u64) -> Result<(), DetectorError> {
        let min_conf = self.config.min_confirmations;
        let ticker = self.config.chain.ticker();

        // Pull every confirmed entry — including ones already credited —
        // so we can keep retrying a deferred sweep without re-firing the
        // webhook.
        let ready: Vec<PendingPayment> = {
            let state = self.lock_state();
            state
                .pending
                .iter()
                .filter(|p| {
                    let confs = tip_height.saturating_sub(p.block_height) + 1;
                    confs >= min_conf
                })
                .cloned()
                .collect()
        };

        let mut to_remove: HashSet<String> = HashSet::new();
        for pending in &ready {
            let confs = tip_height.saturating_sub(pending.block_height) + 1;
            let mut enriched = pending.payment.clone();
            enriched.confirmations = confs;

            let sweep_outcome = self
                .maybe_sweep(pending.payment.derivation_index, &pending.payment.address)
                .await;
            let sweep_deferred = matches!(&sweep_outcome, Some(r) if r.deferred);

            if let Some(result) = &sweep_outcome {
                if !result.deferred {
                    if let Some(destination) = self.sweep_destination() {
                        enriched.swept_to_address = Some(destination.to_string());
                    }
                    enriched.swept_amount_sat = Some(result.amount_sat);
                    enriched.swept_amount_coin =
                        Some(result.amount_sat as f64 / self.config.chain.sats_per_unit() as f64);
                    enriched.sweep_txid = result.txid.clone();
                }
            }

            let already_notified = {
                let state = self.lock_state();
                state.notified_confirmed.contains(&pending.payment.txid)
            };

            if !already_notified {
                match self.price_fetcher.get_price().await {
                    Ok(price) => {
                        enriched.coin_price = Some(price);
                        enriched.fiat_currency = Some(self.price_fetcher.currency().to_string());
                        let coin =
                            enriched.amount_sat as f64 / self.config.chain.sats_per_unit() as f64;
                        enriched.fiat_amount = Some(coin * price);
                    }
                    Err(e) => {
                        log::warn!("[{}] Failed to fetch price: {e}", ticker);
                    }
                }

                let event = WebhookEvent::PaymentCredited(enriched.clone());
                send_webhook(
                    &self.webhook_client,
                    &self.config.webhook_url,
                    &self.config.webhook_hmac_secret,
                    &event,
                )
                .await?;

                {
                    let mut state = self.lock_state();
                    state
                        .notified_confirmed
                        .insert(pending.payment.txid.clone());
                }
                log::info!(
                    "[{}] Payment confirmed ({} confs): txid={} address={} amount={} sats fiat={:?} {}{}",
                    ticker,
                    confs,
                    pending.payment.txid,
                    pending.payment.address,
                    pending.payment.amount_sat,
                    enriched.fiat_amount,
                    self.price_fetcher.currency(),
                    if sweep_deferred {
                        " (sweep deferred)"
                    } else {
                        ""
                    },
                );
            }

            if sweep_deferred {
                log::info!(
                    "[{}] Sweep deferred for txid {} - keeping in pending until next cycle",
                    ticker,
                    pending.payment.txid
                );
            } else {
                to_remove.insert(pending.payment.txid.clone());
            }
        }

        if !to_remove.is_empty() {
            let mut state = self.lock_state();
            state
                .pending
                .retain(|p| !to_remove.contains(&p.payment.txid));
        }

        Ok(())
    }

    /// On-demand TXID recovery for BTC / LTC. The user submits a tx
    /// hash claiming they paid but never got credited; the detector
    /// fetches the transaction from an Esplora-compatible explorer,
    /// reverse-derives each output address against our xpub, and
    /// requires the matching derivation index to equal `user_id`
    /// (refuses cross-user TXID submissions).
    ///
    /// `max_derivation_index` bounds the reverse-derivation scan and
    /// must match the value passed to `run_block_scan_loop` — set
    /// from `MAX_DERIVATION_INDEX` env at the API binary level.
    pub async fn recover_txid(
        &self,
        txid: &str,
        user_id: u32,
        max_derivation_index: u32,
    ) -> Result<RecoverResponse, DetectorError> {
        let txid = txid.trim();
        let chain = self.config.chain;
        let txid_owned = txid.to_string();
        let user_id_str = user_id.to_string();
        let mk = |status: RecoverStatus| {
            RecoverResponse::new(chain, txid_owned.clone(), user_id_str.clone(), status)
        };
        if txid.is_empty() {
            return Err(DetectorError::InvalidConfig("txid cannot be empty".into()));
        }
        if user_id > max_derivation_index {
            log::warn!(
                "[{}] /recover-txid: user_id {user_id} exceeds MAX_DERIVATION_INDEX={max_derivation_index}",
                chain.ticker()
            );
            return Ok(mk(RecoverStatus::WrongUser));
        }

        // Detector-side dedup: already credited via the regular block
        // scan or a previous recovery. Backend's unique DB index will
        // also catch duplicates if a webhook somehow re-fires.
        {
            let state = self.lock_state();
            if state.notified_confirmed.contains(txid) {
                log::info!(
                    "[{}] /recover-txid: txid={txid} already credited (user_id={user_id})",
                    chain.ticker()
                );
                return Ok(mk(RecoverStatus::AlreadyCredited));
            }
            if state.pending.iter().any(|p| p.payment.txid == txid) {
                log::info!(
                    "[{}] /recover-txid: txid={txid} already pending sweep (user_id={user_id})",
                    chain.ticker()
                );
                return Ok(mk(RecoverStatus::PendingSweep));
            }
        }

        // The address we expect to credit. If the supplied user_id
        // doesn't yield the same address as one of the tx outputs,
        // the recovery is rejected.
        let expected_address = derive_address(&self.config.xpub, user_id, chain).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Failed to derive xpub address for user_id={user_id}: {e}"
            ))
        })?;

        let tx = match self.fetch_esplora_tx(txid).await? {
            Some(tx) => tx,
            None => {
                log::info!(
                    "[{}] /recover-txid: txid={txid} not found on chain (user_id={user_id})",
                    chain.ticker()
                );
                return Ok(mk(RecoverStatus::TxNotFound));
            }
        };
        if !tx.status.confirmed {
            log::info!(
                "[{}] /recover-txid: txid={txid} not yet confirmed (user_id={user_id})",
                chain.ticker()
            );
            return Ok(mk(RecoverStatus::TxNotFound));
        }
        let block_height = tx.status.block_height.unwrap_or(0);

        // Sum positive outputs whose address matches `expected_address`.
        // Multiple outputs to the same address in one tx are rare but
        // possible (CoinJoin, batched payouts) — credit the total.
        let mut amount_sat: u64 = 0;
        let mut matched_other_user = false;
        for vout in &tx.vout {
            let Some(address) = vout.scriptpubkey_address.as_deref() else {
                continue;
            };
            if address == expected_address {
                amount_sat = amount_sat.saturating_add(vout.value);
                continue;
            }
            // Side-effect: detect that the tx targets *some* address
            // we own (different user). Used only to refine the error
            // returned to the caller.
            if !matched_other_user
                && let Some(found_index) =
                    self.reverse_derive_address(address, max_derivation_index)?
                && found_index != user_id
            {
                matched_other_user = true;
            }
        }

        if amount_sat == 0 {
            if matched_other_user {
                log::warn!(
                    "[{}] /recover-txid: txid={txid} credits a different user, not user_id={user_id}",
                    chain.ticker()
                );
                return Ok(mk(RecoverStatus::WrongUser));
            }
            log::info!(
                "[{}] /recover-txid: txid={txid} has no output to {expected_address} (user_id={user_id})",
                chain.ticker()
            );
            return Ok(mk(RecoverStatus::AddressNotOwned));
        }

        let amount_coin = amount_sat as f64 / chain.sats_per_unit() as f64;
        let tip_height = self.get_chain_tip().await?;
        let confirmations = tip_height.saturating_sub(block_height) + 1;

        let detected = DetectedPayment {
            chain,
            ticker: chain.ticker().to_string(),
            txid: txid.to_string(),
            address: expected_address.clone(),
            user_id: None,
            amount_sat,
            amount_coin,
            confirmations,
            block_height: Some(block_height),
            derivation_index: user_id,
            memo: None,
            swept_to_address: None,
            swept_amount_sat: None,
            swept_amount_coin: None,
            sweep_txid: None,
            fiat_amount: None,
            fiat_currency: None,
            coin_price: None,
            event_id: None,
            log_index: None,
            asset: None,
            asset_decimals: None,
            amount_base_units: None,
            swept_amount_base_units: None,
            token_contract: None,
        };

        // First send a `payment_detected` so the backend records the
        // event. Idempotent on the backend side via the same key the
        // regular scan loop would have produced.
        send_webhook(
            &self.webhook_client,
            &self.config.webhook_url,
            &self.config.webhook_hmac_secret,
            &WebhookEvent::PaymentDetected(detected.clone()),
        )
        .await?;

        // Enqueue and run the confirmation/sweep cycle synchronously so
        // an already-confirmed tx fires `payment_credited` immediately
        // rather than waiting for the next poll tick.
        self.enqueue_or_confirm(vec![detected]);
        self.process_confirmed(tip_height).await?;

        // A recovery runs outside the scan loop, so nothing else would write
        // the credit (or the still-pending entry) to disk.
        if let Err(e) = self.persist_state() {
            log::error!(
                "[{}] Failed to persist state after recovery: {e}",
                chain.ticker()
            );
        }

        let credited = {
            let state = self.lock_state();
            state.notified_confirmed.contains(txid)
        };
        let status = if credited {
            RecoverStatus::Credited
        } else {
            RecoverStatus::PendingSweep
        };
        Ok(
            RecoverResponse::new(chain, txid.to_string(), user_id_str, status)
                .with_asset(chain.ticker().to_string(), amount_coin),
        )
    }

    /// Fetch a transaction by id from the first available
    /// Esplora-compatible explorer. Returns `Ok(None)` for 404 (tx not
    /// found yet / never existed) and an error for transport failures.
    /// Blockchair-only configurations cause an error because the
    /// transaction-by-id schema is different and not used elsewhere.
    async fn fetch_esplora_tx(&self, txid: &str) -> Result<Option<EsploraTx>, DetectorError> {
        let base_url = match self.esplora_base_url() {
            Some(url) => url,
            None => {
                return Err(DetectorError::ApiError(
                    "Recovery requires an Esplora-compatible explorer (none configured)".into(),
                ));
            }
        };
        let url = format!("{}/tx/{}", base_url.trim_end_matches('/'), txid);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| DetectorError::ApiError(format!("Esplora /tx fetch failed: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(DetectorError::ApiError(format!(
                "Esplora /tx returned status {status}"
            )));
        }
        let parsed: EsploraTx = resp
            .json()
            .await
            .map_err(|e| DetectorError::ApiError(format!("Esplora /tx parse failed: {e}")))?;
        Ok(Some(parsed))
    }

    /// Reverse-derive a BTC/LTC address against our xpub by trying
    /// every index in `0..=max_derivation_index`. Returns the matching
    /// index when found, otherwise `Ok(None)`. Used only to produce
    /// better error messages — not in the credit path.
    fn reverse_derive_address(
        &self,
        address: &str,
        max_derivation_index: u32,
    ) -> Result<Option<u32>, DetectorError> {
        for index in 0..=max_derivation_index {
            let derived = derive_address(&self.config.xpub, index, self.config.chain)?;
            if derived == address {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Deserialize)]
struct EsploraTx {
    #[serde(default)]
    vout: Vec<EsploraVout>,
    status: EsploraTxStatus,
}

#[derive(Debug, Deserialize)]
struct EsploraVout {
    #[serde(default)]
    scriptpubkey_address: Option<String>,
    #[serde(default)]
    value: u64,
}

#[derive(Debug, Deserialize)]
struct EsploraTxStatus {
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u64>,
}

impl PaymentDetector for ChainDetector {
    fn derive_address(&self, index: u32) -> Result<String, DetectorError> {
        derive_address(&self.config.xpub, index, self.config.chain)
    }

    async fn scan_block(
        &self,
        block_height: u64,
        max_derivation_index: u32,
    ) -> Result<Vec<DetectedPayment>, DetectorError> {
        let tip_height = self.get_chain_tip().await?;
        let block_hash = self.get_block_hash(block_height).await?;
        let address_lookup = self.build_address_lookup(max_derivation_index)?;

        let block = self.fetch_raw_block(&block_hash).await?;

        log::info!(
            "[{}] Scanning block {} ({}) - {} txs, checking {} addresses",
            self.config.chain.ticker(),
            block_height,
            block_hash,
            block.txdata.len(),
            address_lookup.len()
        );

        Ok(self.scan_raw_block_parallel(&block, &address_lookup, block_height, tip_height))
    }

    async fn run_block_scan_loop(
        &self,
        start_height: Option<u64>,
        max_derivation_index: u32,
    ) -> Result<(), DetectorError> {
        let poll_interval = std::time::Duration::from_secs(self.config.poll_interval_secs);
        let ticker = self.config.chain.ticker();

        let address_lookup = self.build_address_lookup(max_derivation_index)?;
        log::info!(
            "[{}] Block scan loop started - watching {} addresses (index 0..={})",
            ticker,
            address_lookup.len(),
            max_derivation_index
        );

        let persisted = crate::persistence::load_state(&self.config.state_file)?;
        let mut known_block_hashes = persisted.known_block_hashes.clone();

        let mut current_height = if let Some(h) = start_height {
            h
        } else if self.config.skip_initial_block_sync {
            let tip_height = self.get_chain_tip().await?;
            let persisted_height = persisted
                .last_scanned_height
                .map(|height| height.to_string())
                .unwrap_or_else(|| "none".to_string());
            log::info!(
                "[{}] Initial block sync disabled, ignoring persisted height {} and waiting for blocks after tip {}",
                ticker,
                persisted_height,
                tip_height
            );
            known_block_hashes.clear();
            tip_height.saturating_add(1)
        } else if let Some(last) = persisted.last_scanned_height {
            log::info!("[{}] Resuming from persisted height {}", ticker, last + 1);
            last + 1
        } else {
            self.get_chain_tip().await?
        };

        {
            let mut state = self.lock_state();
            state.last_scanned_height = Some(current_height.saturating_sub(1));
            state.known_block_hashes = known_block_hashes.clone();
            // Payments detected before the last restart but not yet confirmed:
            // their block is already behind `last_scanned_height`, so the scan
            // will never surface them again. Restoring them here is what makes
            // a restart mid-confirmation non-destructive.
            //
            // Merged, not assigned: `run_detector` re-enters this function after
            // a scan error, and in that case the in-memory state is newer than
            // the file. Overwriting it would resurrect entries already credited
            // since the last save.
            state
                .notified_confirmed
                .extend(persisted.notified_confirmed.iter().cloned());
            let mut restored = 0usize;
            for entry in &persisted.pending {
                let txid = &entry.payment.txid;
                let known = state.notified_confirmed.contains(txid)
                    || state.pending.iter().any(|p| &p.payment.txid == txid);
                if !known {
                    state.pending.push(entry.clone());
                    restored += 1;
                }
            }
            if restored > 0 {
                log::info!(
                    "[{}] Restored {} pending payment(s) awaiting confirmation from state file",
                    ticker,
                    restored
                );
            }
        }

        if self.config.skip_initial_block_sync {
            self.persist_state()?;
        }

        loop {
            let tip_height = match self.get_chain_tip().await {
                Ok(h) => h,
                Err(e) => {
                    log::error!("[{}] Failed to get chain tip: {e}", ticker);
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            };

            if current_height > tip_height {
                if let Err(e) = self.process_confirmed(tip_height).await {
                    log::error!("[{}] Failed to process confirmed payments: {e}", ticker);
                }
                // At the tip there is no block save to piggyback on, so credits
                // and sweeps settled just now would only exist in memory.
                if let Err(e) = self.persist_state() {
                    log::error!("[{}] Failed to persist state: {e}", ticker);
                }
                tokio::time::sleep(poll_interval).await;
                continue;
            }

            let total_blocks = tip_height - current_height + 1;
            let batch_start = current_height;
            let batch_start_time = Instant::now();

            while current_height <= tip_height {
                let reorg_depth = self.detect_reorg(current_height).await;
                if reorg_depth > 0 {
                    log::warn!(
                        "[{}] Reorg detected! Rolling back {} block(s) from height {}",
                        ticker,
                        reorg_depth,
                        current_height - 1
                    );
                    let rollback_from = current_height - reorg_depth;
                    {
                        let mut state = self.lock_state();
                        state.pending.retain(|p| p.block_height < rollback_from);
                        for h in rollback_from..current_height {
                            state.known_block_hashes.remove(&h);
                        }
                        state.last_scanned_height = Some(rollback_from.saturating_sub(1));
                    }
                    current_height = rollback_from;
                    log::info!(
                        "[{}] Rolled back to height {}, re-scanning",
                        ticker,
                        current_height
                    );
                    continue;
                }

                let block_start_time = Instant::now();
                let blocks_done = current_height - batch_start;
                let progress = if total_blocks > 0 {
                    (blocks_done as f64 / total_blocks as f64) * 100.0
                } else {
                    100.0
                };

                let block_hash = match self.get_block_hash(current_height).await {
                    Ok(h) => h,
                    Err(e) => {
                        log::error!(
                            "[{}] Failed to get block hash for height {}: {e}",
                            ticker,
                            current_height
                        );
                        break;
                    }
                };

                let block = match self.fetch_raw_block(&block_hash).await {
                    Ok(b) => b,
                    Err(e) => {
                        log::error!(
                            "[{}] Failed to fetch block {} raw: {e}",
                            ticker,
                            current_height
                        );
                        break;
                    }
                };

                let block_elapsed = block_start_time.elapsed();

                let eta = if blocks_done > 0 {
                    let avg_per_block =
                        batch_start_time.elapsed().as_secs_f64() / blocks_done as f64;
                    let remaining = (tip_height - current_height) as f64;
                    let eta_secs = avg_per_block * remaining;
                    format!("ETA: {:.0}s", eta_secs)
                } else {
                    "ETA: calculating...".to_string()
                };

                log::info!(
                    "[{}] [{:.1}%] Block {}/{} ({}) - {} txs - {:.2}s - {}",
                    ticker,
                    progress,
                    current_height,
                    tip_height,
                    &block_hash[..8],
                    block.txdata.len(),
                    block_elapsed.as_secs_f64(),
                    eta
                );

                let payments = self.scan_raw_block_parallel(
                    &block,
                    &address_lookup,
                    current_height,
                    tip_height,
                );

                if !payments.is_empty() {
                    log::info!(
                        "[{}] Found {} payment(s) in block {}",
                        ticker,
                        payments.len(),
                        current_height
                    );
                    self.enqueue_or_confirm(payments);
                }

                if let Err(e) = self.process_confirmed(tip_height).await {
                    log::error!("[{}] Failed to process confirmed payments: {e}", ticker);
                }

                {
                    let mut state = self.lock_state();
                    state.last_scanned_height = Some(current_height);
                    state
                        .known_block_hashes
                        .insert(current_height, block_hash.clone());
                    let min_keep =
                        current_height.saturating_sub(self.config.min_confirmations + 10);
                    state.known_block_hashes.retain(|&h, _| h >= min_keep);
                }

                if let Err(e) = self.persist_state() {
                    log::error!("[{}] Failed to persist state: {e}", ticker);
                }

                current_height += 1;
            }

            if total_blocks > 0 {
                let total_elapsed = batch_start_time.elapsed();
                log::info!(
                    "[{}] [100%] Batch complete - {} blocks in {:.2}s ({:.2}s/block)",
                    ticker,
                    total_blocks,
                    total_elapsed.as_secs_f64(),
                    total_elapsed.as_secs_f64() / total_blocks as f64
                );
            }

            tokio::time::sleep(poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RetryConfig;
    use std::time::Duration;

    fn blockchair_litecoin_detector() -> ChainDetector {
        let chain = Chain::Litecoin;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("test HTTP client should build");
        let webhook_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("test webhook HTTP client should build");
        let price_fetcher = PriceFetcher::new(webhook_client.clone(), "EUR", chain);

        ChainDetector {
            config: DetectorConfig {
                chain,
                fiat_currency: "EUR".to_string(),
                retry: RetryConfig {
                    max_retries: 1,
                    base_delay_ms: 10,
                },
                ..DetectorConfig::default()
            },
            client,
            webhook_client,
            price_fetcher,
            state: Arc::new(Mutex::new(SharedState {
                notified_confirmed: HashSet::new(),
                last_scanned_height: None,
                pending: Vec::new(),
                known_block_hashes: HashMap::new(),
            })),
            explorer_apis: vec![ExplorerApi::from_url(
                chain,
                "https://api.blockchair.com/litecoin",
            )],
            active_explorer_index: Mutex::new(0),
            sweep_config: None,
        }
    }

    fn sample_payment(txid: &str, block_height: u64) -> DetectedPayment {
        DetectedPayment {
            chain: Chain::Litecoin,
            ticker: "LTC".to_string(),
            txid: txid.to_string(),
            address: "ltc1qexample".to_string(),
            user_id: None,
            amount_sat: 500_000,
            amount_coin: 0.005,
            confirmations: 1,
            block_height: Some(block_height),
            derivation_index: 3,
            memo: None,
            swept_to_address: None,
            swept_amount_sat: None,
            swept_amount_coin: None,
            sweep_txid: None,
            fiat_amount: None,
            fiat_currency: None,
            coin_price: None,
            event_id: None,
            log_index: None,
            asset: None,
            asset_decimals: None,
            amount_base_units: None,
            swept_amount_base_units: None,
            token_contract: None,
        }
    }

    /// A payment detected but not yet confirmed used to live only in memory,
    /// while `last_scanned_height` was persisted — so a restart in that window
    /// dropped the deposit for good (the scan never revisits the block).
    #[test]
    fn persists_pending_payments_across_restart() {
        let mut state_file = std::env::temp_dir();
        state_file.push("cpd_blockstream_pending_restart.json");
        let state_file = state_file.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&state_file);

        let mut detector = blockchair_litecoin_detector();
        detector.config.state_file = state_file.clone();
        detector.config.min_confirmations = 6;

        detector.enqueue_or_confirm(vec![sample_payment("deadbeef", 3_000_000)]);
        {
            let mut state = detector.lock_state();
            state.last_scanned_height = Some(3_000_000);
            state.notified_confirmed.insert("cafe".to_string());
        }
        detector.persist_state().expect("state should persist");

        let reloaded = crate::persistence::load_state(&state_file).expect("state should reload");
        assert_eq!(reloaded.last_scanned_height, Some(3_000_000));
        assert_eq!(reloaded.pending.len(), 1);
        assert_eq!(reloaded.pending[0].payment.txid, "deadbeef");
        assert_eq!(reloaded.pending[0].block_height, 3_000_000);
        assert!(reloaded.notified_confirmed.contains("cafe"));

        let _ = std::fs::remove_file(&state_file);
    }

    /// A panic under the state lock used to poison it, so every later
    /// `lock().unwrap()` panicked too and the detector stayed dead until the
    /// process was restarted.
    #[test]
    fn survives_a_poisoned_state_lock() {
        let detector = Arc::new(blockchair_litecoin_detector());

        let poisoner = Arc::clone(&detector.state);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the lock");
        })
        .join();

        assert!(detector.state.is_poisoned());

        let mut state = detector.lock_state();
        state.last_scanned_height = Some(42);
        drop(state);
        assert_eq!(detector.lock_state().last_scanned_height, Some(42));
    }

    #[tokio::test]
    async fn retry_runs_once_and_reports_the_error_when_max_retries_is_zero() {
        // `MAX_RETRIES=0` used to skip the loop entirely and then unwrap a
        // `None` error, panicking the detector task.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<(), DetectorError> = retry("test_op", 0, 1, || async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(DetectorError::ApiError("boom".into()))
        })
        .await;

        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            result.unwrap_err().to_string().contains("boom"),
            "the real error must survive"
        );
    }

    #[tokio::test]
    async fn retry_returns_the_first_success_without_sleeping_again() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<u32, DetectorError> = retry("test_op", 5, 1, || async {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Err(DetectorError::ApiError("transient".into()))
            } else {
                Ok(7)
            }
        })
        .await;

        assert_eq!(result.expect("should succeed on the second attempt"), 7);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[ignore = "hits the live Blockchair Litecoin API"]
    async fn blockchair_live_gets_litecoin_tip_height() {
        let detector = blockchair_litecoin_detector();

        let tip_height = detector
            .get_chain_tip()
            .await
            .expect("Blockchair should return a Litecoin tip height");

        assert!(
            tip_height > 2_000_000,
            "unexpected Litecoin tip height: {tip_height}"
        );
    }

    #[tokio::test]
    #[ignore = "hits the live Blockchair Litecoin API"]
    async fn blockchair_live_downloads_recent_litecoin_raw_block_bytes() {
        let detector = blockchair_litecoin_detector();
        let explorer = detector.explorer_apis[0].clone();
        let tip_height = detector
            .get_chain_tip()
            .await
            .expect("Blockchair should return a Litecoin tip height");
        let block_height = tip_height.saturating_sub(6);
        let block_hash = detector
            .get_block_hash(block_height)
            .await
            .expect("Blockchair should return a Litecoin block hash by height");

        let raw_block = detector
            .fetch_raw_block_bytes_from(&explorer, &block_hash)
            .await
            .expect("Blockchair should return raw Litecoin block bytes");

        assert!(
            raw_block.len() > 80,
            "downloaded Litecoin block {block_hash} at height {block_height} is too small: {} bytes",
            raw_block.len()
        );
    }

    #[tokio::test]
    #[ignore = "hits the live Blockchair Litecoin API"]
    async fn blockchair_live_decodes_pre_mweb_litecoin_block() {
        let detector = blockchair_litecoin_detector();
        let block_height = 2_000_000;
        let block_hash = detector
            .get_block_hash(block_height)
            .await
            .expect("Blockchair should return a Litecoin block hash by height");

        let block = detector
            .fetch_raw_block(&block_hash)
            .await
            .expect("Blockchair should return a decodable raw Litecoin block");

        assert!(
            !block.txdata.is_empty(),
            "downloaded Litecoin block {block_hash} at height {block_height} has no transactions"
        );
        assert!(
            block.header.time > 1_600_000_000,
            "downloaded Litecoin block {block_hash} has an implausible timestamp: {}",
            block.header.time
        );
    }

    /// Companion to the pre-MWEB test above: every block mined since the MWEB
    /// activation ends with a HogEx transaction whose flag byte is `0x08`, which
    /// used to abort the scan loop with "unsupported segwit version: 8".
    #[tokio::test]
    #[ignore = "hits the live Blockchair Litecoin API"]
    async fn blockchair_live_decodes_recent_mweb_litecoin_block() {
        let detector = blockchair_litecoin_detector();
        let tip_height = detector
            .get_chain_tip()
            .await
            .expect("Blockchair should return a Litecoin tip height");
        let block_height = tip_height.saturating_sub(6);
        let block_hash = detector
            .get_block_hash(block_height)
            .await
            .expect("Blockchair should return a Litecoin block hash by height");

        let block = detector
            .fetch_raw_block(&block_hash)
            .await
            .expect("Blockchair should return a decodable raw Litecoin block");

        assert_eq!(block.block_hash().to_string(), block_hash);
        assert!(
            block.check_merkle_root(),
            "merkle root mismatch on Litecoin block {block_hash} at height {block_height}"
        );
    }
}
