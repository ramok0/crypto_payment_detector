use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::derivation::derive_address;
use crate::error::DetectorError;
use crate::pricing::PriceFetcher;
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
    let mut last_err = None;
    for attempt in 0..max_retries {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                let delay = base_delay_ms * 2u64.pow(attempt);
                log::warn!(
                    "Retry {}/{} for '{}' in {}ms - {}",
                    attempt + 1,
                    max_retries,
                    name,
                    delay,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

#[derive(Debug, Clone)]
struct PendingPayment {
    payment: DetectedPayment,
    block_height: u64,
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
            log::info!("[{}] Using proxy: {}", config.chain.ticker(), proxy_url);
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
        })
    }

    pub fn chain(&self) -> Chain {
        self.config.chain
    }

    async fn try_explorers<T, F, Fut>(&self, name: &str, mut call: F) -> Result<T, DetectorError>
    where
        F: FnMut(ExplorerApi) -> Fut,
        Fut: Future<Output = Result<T, DetectorError>>,
    {
        let len = self.explorer_apis.len();
        let start = *self.active_explorer_index.lock().unwrap();
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
                    *self.active_explorer_index.lock().unwrap() = index;
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

        let block = bitcoin::Block::consensus_decode(&mut bytes.as_slice())
            .map_err(|e| DetectorError::ApiError(format!("Failed to parse raw block: {e}")))?;

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
                            Chain::Solana => return None,
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
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    async fn detect_reorg(&self, current_height: u64) -> u64 {
        let known = {
            let state = self.state.lock().unwrap();
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
        let mut state = self.state.lock().unwrap();
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

        let ready: Vec<PendingPayment> = {
            let state = self.state.lock().unwrap();
            state
                .pending
                .iter()
                .filter(|p| {
                    let confs = tip_height.saturating_sub(p.block_height) + 1;
                    confs >= min_conf && !state.notified_confirmed.contains(&p.payment.txid)
                })
                .cloned()
                .collect()
        };

        for pending in &ready {
            let confs = tip_height.saturating_sub(pending.block_height) + 1;
            let mut enriched = pending.payment.clone();
            enriched.confirmations = confs;

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

            let mut state = self.state.lock().unwrap();
            state
                .notified_confirmed
                .insert(pending.payment.txid.clone());
            log::info!(
                "[{}] Payment confirmed ({} confs): txid={} address={} amount={} sats fiat={:?} {}",
                ticker,
                confs,
                pending.payment.txid,
                pending.payment.address,
                pending.payment.amount_sat,
                enriched.fiat_amount,
                self.price_fetcher.currency(),
            );
        }

        if !ready.is_empty() {
            let mut state = self.state.lock().unwrap();
            let confirmed = state.notified_confirmed.clone();
            state
                .pending
                .retain(|p| !confirmed.contains(&p.payment.txid));
        }

        Ok(())
    }
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
            let mut state = self.state.lock().unwrap();
            state.last_scanned_height = Some(current_height.saturating_sub(1));
            state.known_block_hashes = known_block_hashes.clone();
        }

        if self.config.skip_initial_block_sync {
            crate::persistence::save_state(
                &self.config.state_file,
                &crate::persistence::PersistedState {
                    last_scanned_height: Some(current_height.saturating_sub(1)),
                    known_block_hashes: known_block_hashes.clone(),
                },
            )?;
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
                        let mut state = self.state.lock().unwrap();
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
                    let mut state = self.state.lock().unwrap();
                    state.last_scanned_height = Some(current_height);
                    state
                        .known_block_hashes
                        .insert(current_height, block_hash.clone());
                    let min_keep =
                        current_height.saturating_sub(self.config.min_confirmations + 10);
                    state.known_block_hashes.retain(|&h, _| h >= min_keep);
                }

                let persisted_hashes = {
                    let state = self.state.lock().unwrap();
                    state.known_block_hashes.clone()
                };
                if let Err(e) = crate::persistence::save_state(
                    &self.config.state_file,
                    &crate::persistence::PersistedState {
                        last_scanned_height: Some(current_height),
                        known_block_hashes: persisted_hashes,
                    },
                ) {
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
        }
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
}
