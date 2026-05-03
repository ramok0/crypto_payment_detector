use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{
    Address, BlockNumber, Bytes, Filter, H256, TransactionRequest, U256, ValueOrArray,
    transaction::eip2718::TypedTransaction,
};
use ethers::utils::keccak256;
use serde::{Deserialize, Serialize};

use crate::env_utils::redact_url_credentials;
use crate::error::DetectorError;
use crate::ethereum_pool::{
    EthereumReservation, SharedEthereumWallets, find_ethereum_wallet, format_address,
    load_active_ethereum_reservations, snapshot_ethereum_wallets,
};
use crate::etherscan::{EtherscanClient, EtherscanConfig};
use crate::pricing::PriceFetcher;
use crate::trait_def::PaymentDetector;
use crate::types::{Chain, DetectedPayment, WebhookEvent};
use crate::webhook::send_webhook;

const ETH_DECIMALS: u8 = 18;
const DEFAULT_TOKEN_TRANSFER_GAS_LIMIT: u64 = 100_000;
const NATIVE_TRANSFER_GAS_LIMIT: u64 = 21_000;

#[derive(Debug, Clone)]
pub struct Erc20TokenConfig {
    pub symbol: String,
    pub contract: Address,
    pub decimals: u8,
}

#[derive(Debug, Clone)]
pub struct EthereumConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub wallet_pool_file: String,
    pub gas_tank_private_key: String,
    pub ledger_address: String,
    pub webhook_url: String,
    pub webhook_hmac_secret: String,
    pub redis_url: String,
    pub reservation_ttl_secs: u64,
    pub state_file: String,
    pub poll_interval_secs: u64,
    pub min_confirmations: u64,
    pub fiat_currency: String,
    pub proxy_url: Option<String>,
    pub max_blocks_per_cycle: u64,
    pub start_block: Option<u64>,
    pub gas_tank_target_usd: f64,
    pub gas_tank_check_interval_secs: u64,
    pub token_transfer_gas_limit: u64,
    pub gas_top_up_multiplier: f64,
    pub max_fee_ratio: f64,
    /// Optional Etherscan client config. When set, the detector also scans
    /// internal CALL traces for native ETH (e.g. Coinbase withdrawals routed
    /// through their hot-wallet contract) which are invisible to
    /// `eth_getBlockByNumber`.
    pub etherscan: Option<EtherscanConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EthereumPendingPayment {
    event_id: String,
    txid: String,
    block_number: u64,
    amount_base_units: String,
    asset: String,
    asset_decimals: u8,
    token_contract: Option<String>,
    address: String,
    user_id: String,
    wallet_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EthereumState {
    last_scanned_block: Option<u64>,
    #[serde(default)]
    pending: Vec<EthereumPendingPayment>,
    #[serde(default)]
    credited_events: HashSet<String>,
    #[serde(default)]
    ignored_events: HashSet<String>,
    #[serde(default)]
    gas_tank_last_maintenance_unix: Option<i64>,
}

#[derive(Debug, Clone)]
struct DetectedEthereumPayment {
    event_id: String,
    txid: String,
    block_number: u64,
    amount: U256,
    asset: String,
    asset_decimals: u8,
    token_contract: Option<Address>,
    reservation: EthereumReservation,
}

#[derive(Debug, Clone)]
struct SweepResult {
    amount: U256,
    txid: Option<String>,
    deferred: bool,
}

#[derive(Debug)]
pub struct EthereumDetector {
    config: EthereumConfig,
    wallets: SharedEthereumWallets,
    tokens: Vec<Erc20TokenConfig>,
    provider: Provider<Http>,
    gas_tank_wallet: LocalWallet,
    gas_tank_address: Address,
    ledger_address: Address,
    webhook_client: reqwest::Client,
    price_fetcher: PriceFetcher,
    eth_usd_fetcher: PriceFetcher,
    eth_eur_fetcher: PriceFetcher,
    etherscan: Option<EtherscanClient>,
    state: Arc<Mutex<EthereumState>>,
}

impl EthereumDetector {
    pub fn new(
        config: EthereumConfig,
        tokens: Vec<Erc20TokenConfig>,
        wallets: SharedEthereumWallets,
    ) -> Result<Self, DetectorError> {
        if config.rpc_url.trim().is_empty() {
            return Err(DetectorError::InvalidConfig(
                "ETH_RPC_URL is required for CHAIN=ethereum".into(),
            ));
        }
        if config.wallet_pool_file.trim().is_empty() {
            return Err(DetectorError::InvalidConfig(
                "ETH_WALLET_POOL_FILE is required for CHAIN=ethereum".into(),
            ));
        }
        if config.gas_tank_private_key.trim().is_empty() {
            return Err(DetectorError::InvalidConfig(
                "ETH_GAS_TANK_PRIVATE_KEY is required for CHAIN=ethereum".into(),
            ));
        }
        if config.ledger_address.trim().is_empty() {
            return Err(DetectorError::InvalidConfig(
                "ETH_LEDGER_ADDRESS is required for CHAIN=ethereum".into(),
            ));
        }
        if config.redis_url.trim().is_empty() {
            return Err(DetectorError::InvalidConfig("REDIS_URL is required".into()));
        }
        if config.webhook_url.trim().is_empty() {
            return Err(DetectorError::InvalidConfig(
                "webhook_url is required".into(),
            ));
        }
        if config.webhook_hmac_secret.trim().is_empty() {
            return Err(DetectorError::InvalidConfig(
                "webhook_hmac_secret is required".into(),
            ));
        }

        let provider = build_ethereum_provider(&config)?;

        let gas_tank_wallet = config
            .gas_tank_private_key
            .trim()
            .parse::<LocalWallet>()
            .map_err(|e| {
                DetectorError::InvalidConfig(format!("Invalid ETH_GAS_TANK_PRIVATE_KEY: {e}"))
            })?
            .with_chain_id(config.chain_id);
        let gas_tank_address = gas_tank_wallet.address();
        let ledger_address = Address::from_str(config.ledger_address.trim()).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid ETH_LEDGER_ADDRESS '{}': {e}",
                config.ledger_address
            ))
        })?;

        let webhook_client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .connection_verbose(false)
            .build()
            .map_err(DetectorError::HttpError)?;
        let price_fetcher = PriceFetcher::new(
            webhook_client.clone(),
            &config.fiat_currency,
            Chain::Ethereum,
        );
        let eth_usd_fetcher = PriceFetcher::new(webhook_client.clone(), "USD", Chain::Ethereum);
        let eth_eur_fetcher = PriceFetcher::new(webhook_client.clone(), "EUR", Chain::Ethereum);

        let etherscan = match config.etherscan.clone() {
            Some(etherscan_config) => {
                let client = EtherscanClient::new(etherscan_config)?;
                log::info!(
                    "[ETH] Etherscan internal-tx scan enabled (chain_id={}, base_url={})",
                    client.chain_id(),
                    client.base_url_redacted()
                );
                Some(client)
            }
            None => {
                log::info!(
                    "[ETH] Etherscan internal-tx scan disabled (set ETHERSCAN_API_KEY to enable; \
                     deposits routed through contracts e.g. Coinbase withdrawals will not be detected)"
                );
                None
            }
        };

        let state = load_ethereum_state(&config.state_file);

        Ok(Self {
            config,
            wallets,
            tokens,
            provider,
            gas_tank_wallet,
            gas_tank_address,
            ledger_address,
            webhook_client,
            price_fetcher,
            eth_usd_fetcher,
            eth_eur_fetcher,
            etherscan,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn wallet_count(&self) -> usize {
        self.wallets.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn gas_tank_address(&self) -> String {
        format_address(self.gas_tank_address)
    }

    pub fn ledger_address(&self) -> String {
        format_address(self.ledger_address)
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub async fn sweep_orphan_balances(&self) -> Result<(), DetectorError> {
        let active_addresses: HashSet<String> =
            match load_active_ethereum_reservations(&self.config.redis_url).await {
                Ok(reservations) => reservations
                    .into_iter()
                    .map(|r| r.address.to_ascii_lowercase())
                    .collect(),
                Err(error) => {
                    log::warn!(
                        "[ETH] Orphan sweep: failed to load active reservations ({error}); \
                         skipping to avoid touching reserved wallets"
                    );
                    return Ok(());
                }
            };

        let snapshot = snapshot_ethereum_wallets(&self.wallets);
        log::info!(
            "[ETH] Orphan sweep starting: {} managed wallet(s), skipping {} active reservation(s)",
            snapshot.len(),
            active_addresses.len()
        );

        let mut native_swept_count: usize = 0;
        let mut native_swept_wei: U256 = U256::zero();
        let mut token_swept_count: usize = 0;

        for wallet in &snapshot {
            if active_addresses.contains(&wallet.address.to_ascii_lowercase()) {
                continue;
            }

            // Native ETH
            match self.eth_balance(wallet.eth_address).await {
                Ok(balance) if !balance.is_zero() => {
                    match self.sweep_native_from_address(&wallet.address).await {
                        Ok(result) if result.txid.is_some() => {
                            log::info!(
                                "[ETH] Orphan ETH swept: {} wei from {} (index {}, tx={})",
                                result.amount,
                                wallet.address,
                                wallet.index,
                                result.txid.clone().unwrap_or_default()
                            );
                            native_swept_wei = native_swept_wei.saturating_add(result.amount);
                            native_swept_count += 1;
                        }
                        Ok(_) => {}
                        Err(error) => log::warn!(
                            "[ETH] Failed to sweep orphan ETH from {} (index {}): {error}",
                            wallet.address,
                            wallet.index
                        ),
                    }
                }
                Ok(_) => {}
                Err(error) => log::warn!(
                    "[ETH] Failed to read ETH balance for {} (index {}): {error}",
                    wallet.address,
                    wallet.index
                ),
            }

            // Tokens
            for token in &self.tokens {
                let balance = match self.erc20_balance(token.contract, wallet.eth_address).await {
                    Ok(b) => b,
                    Err(error) => {
                        log::warn!(
                            "[ETH] Failed to read {} balance for {} (index {}): {error}",
                            token.symbol,
                            wallet.address,
                            wallet.index
                        );
                        continue;
                    }
                };
                if balance.is_zero() {
                    continue;
                }

                match self
                    .sweep_erc20_from_address(&wallet.address, token.contract, balance)
                    .await
                {
                    Ok(result) if result.txid.is_some() => {
                        log::info!(
                            "[ETH] Orphan {} swept: {} units from {} (index {}, tx={})",
                            token.symbol,
                            result.amount,
                            wallet.address,
                            wallet.index,
                            result.txid.clone().unwrap_or_default()
                        );
                        token_swept_count += 1;
                    }
                    Ok(_) => {}
                    Err(error) => log::warn!(
                        "[ETH] Failed to sweep orphan {} from {} (index {}): {error}",
                        token.symbol,
                        wallet.address,
                        wallet.index
                    ),
                }
            }
        }

        log::info!(
            "[ETH] Orphan sweep complete: {} ETH sweep(s) ({} wei total), {} token sweep(s)",
            native_swept_count,
            native_swept_wei,
            token_swept_count
        );

        Ok(())
    }

    async fn process_cycle(&self) -> Result<(), DetectorError> {
        let reservations = load_active_ethereum_reservations(&self.config.redis_url).await?;
        let current_block = self.current_block_number().await?;
        let safe_block =
            current_block.saturating_sub(self.config.min_confirmations.saturating_sub(1));

        self.scan_new_blocks(&reservations, current_block, safe_block)
            .await?;
        self.process_credits(current_block).await?;
        self.maybe_maintain_gas_tank().await?;

        Ok(())
    }

    async fn scan_new_blocks(
        &self,
        reservations: &[EthereumReservation],
        current_block: u64,
        safe_block: u64,
    ) -> Result<(), DetectorError> {
        if reservations.is_empty() {
            self.initialize_or_advance_cursor(safe_block)?;
            return Ok(());
        }

        let maybe_last = { self.state.lock().unwrap().last_scanned_block };
        let from_block = match maybe_last {
            Some(last) => last.saturating_add(1),
            None => {
                if let Some(start_block) = self.config.start_block {
                    start_block
                } else {
                    self.set_last_scanned_block(safe_block)?;
                    log::info!(
                        "[ETH] No state found; starting fresh after block {}. Set ETH_START_BLOCK to backfill.",
                        safe_block
                    );
                    return Ok(());
                }
            }
        };

        if from_block > safe_block {
            return Ok(());
        }

        let max_blocks = self.config.max_blocks_per_cycle.max(1);
        let to_block = safe_block.min(from_block.saturating_add(max_blocks).saturating_sub(1));
        let reservation_lookup = self.reservation_lookup(reservations);

        log::info!(
            "[ETH] Scanning blocks {}..={} for {} reserved address(es)",
            from_block,
            to_block,
            reservation_lookup.len()
        );

        let mut detected = Vec::new();
        detected.extend(
            self.scan_native_eth(from_block, to_block, current_block, &reservation_lookup)
                .await?,
        );
        detected.extend(
            self.scan_erc20_logs(from_block, to_block, current_block, &reservation_lookup)
                .await?,
        );
        detected.extend(
            self.scan_internal_calls(from_block, to_block, current_block, &reservation_lookup)
                .await?,
        );

        for payment in detected {
            self.emit_detected_and_enqueue(payment, current_block)
                .await?;
        }

        self.set_last_scanned_block(to_block)?;
        Ok(())
    }

    fn initialize_or_advance_cursor(&self, safe_block: u64) -> Result<(), DetectorError> {
        let should_update = {
            let state = self.state.lock().unwrap();
            state
                .last_scanned_block
                .map_or(true, |last| last < safe_block)
        };
        if should_update {
            self.set_last_scanned_block(safe_block)?;
        }
        Ok(())
    }

    fn reservation_lookup(
        &self,
        reservations: &[EthereumReservation],
    ) -> HashMap<Address, EthereumReservation> {
        reservations
            .iter()
            .filter_map(|reservation| {
                Address::from_str(&reservation.address)
                    .ok()
                    .map(|address| (address, reservation.clone()))
            })
            .collect()
    }

    async fn scan_native_eth(
        &self,
        from_block: u64,
        to_block: u64,
        current_block: u64,
        reservations: &HashMap<Address, EthereumReservation>,
    ) -> Result<Vec<DetectedEthereumPayment>, DetectorError> {
        let mut detected = Vec::new();

        for block_number in from_block..=to_block {
            let block = self
                .provider
                .get_block_with_txs(block_number)
                .await
                .map_err(|e| eth_rpc_error("eth_getBlockByNumber", e))?;
            let Some(block) = block else {
                continue;
            };

            for tx in block.transactions {
                if tx.value.is_zero() {
                    continue;
                }
                let Some(to) = tx.to else {
                    continue;
                };
                let Some(reservation) = reservations.get(&to) else {
                    continue;
                };
                if is_native_gas_tank_top_up(tx.from, to, self.gas_tank_address) {
                    log::debug!(
                        "[ETH] Ignoring gas tank top-up tx {:#x} to reserved address {}",
                        tx.hash,
                        format_address(to)
                    );
                    continue;
                }

                let event_id = format!("native:{:#x}:{}", tx.hash, format_address(to));
                if self.is_known_event(&event_id) {
                    continue;
                }

                detected.push(DetectedEthereumPayment {
                    event_id,
                    txid: format!("{:#x}", tx.hash),
                    block_number,
                    amount: tx.value,
                    asset: "ETH".into(),
                    asset_decimals: ETH_DECIMALS,
                    token_contract: None,
                    reservation: reservation.clone(),
                });
            }
        }

        log::debug!(
            "[ETH] Native scan {}..={} produced {} candidate(s), current block {}",
            from_block,
            to_block,
            detected.len(),
            current_block
        );
        Ok(detected)
    }

    async fn scan_erc20_logs(
        &self,
        from_block: u64,
        to_block: u64,
        _current_block: u64,
        reservations: &HashMap<Address, EthereumReservation>,
    ) -> Result<Vec<DetectedEthereumPayment>, DetectorError> {
        let to_topics = reservations
            .keys()
            .copied()
            .map(address_to_topic)
            .collect::<Vec<_>>();
        if to_topics.is_empty() || self.tokens.is_empty() {
            return Ok(Vec::new());
        }

        let transfer_topic = H256::from_slice(&keccak256("Transfer(address,address,uint256)"));
        let mut detected = Vec::new();

        for token in &self.tokens {
            let filter = Filter::new()
                .address(token.contract)
                .from_block(BlockNumber::Number(from_block.into()))
                .to_block(BlockNumber::Number(to_block.into()))
                .topic0(transfer_topic)
                .topic2(ValueOrArray::Array(to_topics.clone()));

            let logs = self
                .provider
                .get_logs(&filter)
                .await
                .map_err(|e| eth_rpc_error("eth_getLogs", e))?;

            for log in logs {
                if log.topics.len() < 3 || log.data.0.len() != 32 {
                    continue;
                }
                let to = address_from_topic(log.topics[2]);
                let Some(reservation) = reservations.get(&to) else {
                    continue;
                };
                let amount = U256::from_big_endian(&log.data.0);
                if amount.is_zero() {
                    continue;
                }

                let tx_hash = log.transaction_hash.unwrap_or_default();
                let log_index = log.log_index.unwrap_or_default().as_u64();
                let block_number = log.block_number.unwrap_or_default().as_u64();
                let event_id = format!(
                    "erc20:{}:{:#x}:{}",
                    format_address(token.contract),
                    tx_hash,
                    log_index
                );
                if self.is_known_event(&event_id) {
                    continue;
                }

                detected.push(DetectedEthereumPayment {
                    event_id,
                    txid: format!("{:#x}", tx_hash),
                    block_number,
                    amount,
                    asset: token.symbol.clone(),
                    asset_decimals: token.decimals,
                    token_contract: Some(token.contract),
                    reservation: reservation.clone(),
                });
            }
        }

        Ok(detected)
    }

    /// Detect native ETH transfers that happened via internal CALLs (e.g.
    /// Coinbase routes user withdrawals through their hot-wallet contract;
    /// the actual ETH transfer to the user is an internal CALL invisible to
    /// `eth_getBlockByNumber`). Uses Etherscan `txlistinternal` per reserved
    /// address. Disabled if `EtherscanClient` was not configured.
    async fn scan_internal_calls(
        &self,
        from_block: u64,
        to_block: u64,
        _current_block: u64,
        reservations: &HashMap<Address, EthereumReservation>,
    ) -> Result<Vec<DetectedEthereumPayment>, DetectorError> {
        let Some(ref etherscan) = self.etherscan else {
            return Ok(Vec::new());
        };
        if reservations.is_empty() {
            return Ok(Vec::new());
        }

        let mut detected = Vec::new();
        let mut total_internal_seen: usize = 0;

        for (address, reservation) in reservations {
            let internals = match etherscan
                .list_internal_for_address(*address, from_block, to_block)
                .await
            {
                Ok(list) => list,
                Err(error) => {
                    // Don't fail the whole scan on a transient Etherscan error
                    // (rate-limit, timeout, transient HTTP). The cursor only
                    // advances after the whole loop succeeds via the caller's
                    // `set_last_scanned_block`, so we return the error to keep
                    // the cursor put and retry next cycle.
                    log::warn!(
                        "[ETH] Etherscan scan failed for {} ({}..={}): {error}",
                        format_address(*address),
                        from_block,
                        to_block
                    );
                    return Err(error);
                }
            };

            total_internal_seen += internals.len();

            for tx in internals {
                if tx.is_error {
                    continue;
                }
                if tx.value.is_zero() {
                    continue;
                }
                // Server-side filter is by address but the API returns both
                // incoming and outgoing internals; only credit incoming.
                if tx.to != *address {
                    continue;
                }
                if is_native_gas_tank_top_up(tx.from, tx.to, self.gas_tank_address) {
                    log::debug!(
                        "[ETH] Ignoring internal gas tank top-up tx {} to reserved address {}",
                        tx.hash,
                        format_address(tx.to)
                    );
                    continue;
                }

                // traceId disambiguates multiple internal CALLs in the same tx.
                // Distinct from the `native:...` event_id namespace so a top-level
                // tx that ALSO produces an internal call (rare but possible)
                // wouldn't collide.
                let txid = normalize_etherscan_hash(&tx.hash);
                let event_id = format!(
                    "internal:{}:{}:{}",
                    txid,
                    tx.trace_id,
                    format_address(tx.to)
                );
                if self.is_known_event(&event_id) {
                    continue;
                }

                detected.push(DetectedEthereumPayment {
                    event_id,
                    txid,
                    block_number: tx.block_number,
                    amount: tx.value,
                    asset: "ETH".into(),
                    asset_decimals: ETH_DECIMALS,
                    token_contract: None,
                    reservation: reservation.clone(),
                });
            }
        }

        log::debug!(
            "[ETH] Internal scan {}..={} across {} reserved address(es) inspected {} entry(ies), produced {} candidate(s)",
            from_block,
            to_block,
            reservations.len(),
            total_internal_seen,
            detected.len()
        );

        Ok(detected)
    }

    async fn emit_detected_and_enqueue(
        &self,
        payment: DetectedEthereumPayment,
        current_block: u64,
    ) -> Result<(), DetectorError> {
        if self.is_known_event(&payment.event_id) {
            return Ok(());
        }

        let detected = self.payment_to_webhook(&payment, current_block, None);
        send_webhook(
            &self.webhook_client,
            &self.config.webhook_url,
            &self.config.webhook_hmac_secret,
            &WebhookEvent::PaymentDetected(detected),
        )
        .await?;

        {
            let mut state = self.state.lock().unwrap();
            let already_pending = state.pending.iter().any(|p| p.event_id == payment.event_id);
            let already_credited = state.credited_events.contains(&payment.event_id);
            if !already_pending && !already_credited {
                state.pending.push(EthereumPendingPayment {
                    event_id: payment.event_id,
                    txid: payment.txid,
                    block_number: payment.block_number,
                    amount_base_units: payment.amount.to_string(),
                    asset: payment.asset,
                    asset_decimals: payment.asset_decimals,
                    token_contract: payment.token_contract.map(format_address),
                    address: payment.reservation.address,
                    user_id: payment.reservation.user_id,
                    wallet_index: payment.reservation.wallet_index,
                });
            }
        }

        self.persist_state()
    }

    async fn process_credits(&self, current_block: u64) -> Result<(), DetectorError> {
        let pending = { self.state.lock().unwrap().pending.clone() };

        for entry in pending {
            let confirmations = current_block.saturating_sub(entry.block_number) + 1;
            if confirmations < self.config.min_confirmations {
                continue;
            }
            if self.is_credited_event(&entry.event_id) {
                continue;
            }
            if entry.token_contract.is_none() && self.is_pending_gas_tank_top_up(&entry).await? {
                log::info!(
                    "[ETH] Ignoring previously queued gas tank top-up {} for {}",
                    entry.txid,
                    entry.address
                );
                self.mark_event_ignored(&entry.event_id)?;
                continue;
            }

            let amount = U256::from_dec_str(&entry.amount_base_units).map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid persisted Ethereum amount for {}: {e}",
                    entry.event_id
                ))
            })?;

            let sweep = if let Some(ref contract) = entry.token_contract {
                let contract = Address::from_str(contract).map_err(|e| {
                    DetectorError::InvalidConfig(format!(
                        "Invalid persisted token contract '{}': {e}",
                        contract
                    ))
                })?;
                self.sweep_erc20_from_address(&entry.address, contract, amount)
                    .await?
            } else {
                self.sweep_native_from_address(&entry.address).await?
            };

            if sweep.deferred {
                log::info!(
                    "[ETH] Sweep deferred for {} (will retry next cycle)",
                    entry.event_id
                );
                continue;
            }

            let mut credited_payment =
                self.pending_to_webhook(&entry, current_block, Some(&sweep), amount);
            self.enrich_fiat(&mut credited_payment).await;

            send_webhook(
                &self.webhook_client,
                &self.config.webhook_url,
                &self.config.webhook_hmac_secret,
                &WebhookEvent::PaymentCredited(credited_payment),
            )
            .await?;

            {
                let mut state = self.state.lock().unwrap();
                state.credited_events.insert(entry.event_id.clone());
                state
                    .pending
                    .retain(|pending| pending.event_id != entry.event_id);
            }
            self.persist_state()?;
        }

        Ok(())
    }

    async fn is_pending_gas_tank_top_up(
        &self,
        entry: &EthereumPendingPayment,
    ) -> Result<bool, DetectorError> {
        let Ok(tx_hash) = H256::from_str(&entry.txid) else {
            return Ok(false);
        };
        let eth_address = Address::from_str(&entry.address).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid managed Ethereum address '{}': {e}",
                entry.address
            ))
        })?;
        let Some(tx) = self
            .provider
            .get_transaction(tx_hash)
            .await
            .map_err(|e| eth_rpc_error("eth_getTransactionByHash", e))?
        else {
            return Ok(false);
        };
        let Some(to) = tx.to else {
            return Ok(false);
        };

        Ok(to == eth_address && is_native_gas_tank_top_up(tx.from, to, self.gas_tank_address))
    }

    async fn sweep_native_from_address(&self, address: &str) -> Result<SweepResult, DetectorError> {
        let eth_address = Address::from_str(address).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid managed Ethereum address '{address}': {e}"
            ))
        })?;
        let wallet = find_ethereum_wallet(&snapshot_ethereum_wallets(&self.wallets), eth_address)
            .ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "No managed Ethereum wallet found for address '{}'",
                address
            ))
        })?;

        let balance = self.eth_balance(eth_address).await?;
        if balance.is_zero() {
            return Ok(SweepResult {
                amount: U256::zero(),
                txid: None,
                deferred: false,
            });
        }

        let gas_price = self.gas_price().await?;
        let fee = U256::from(NATIVE_TRANSFER_GAS_LIMIT) * gas_price;
        if balance <= fee {
            log::info!(
                "[ETH] Address {} balance {} wei is not enough to cover native sweep fee {} - deferring",
                address,
                balance,
                fee
            );
            return Ok(SweepResult {
                amount: U256::zero(),
                txid: None,
                deferred: true,
            });
        }

        if fee_ratio_too_high_u256(fee, balance, self.config.max_fee_ratio) {
            log::info!(
                "[ETH] Deferring native sweep for {}: fee {} wei would be {:.1}% of balance {} wei (max {:.1}%) - retry when gas drops",
                address,
                fee,
                ratio_percent_u256(fee, balance),
                balance,
                self.config.max_fee_ratio * 100.0
            );
            return Ok(SweepResult {
                amount: U256::zero(),
                txid: None,
                deferred: true,
            });
        }

        let amount = balance - fee;
        let wallet = wallet
            .wallet
            .as_ref()
            .clone()
            .with_chain_id(self.config.chain_id);
        let txid = self
            .send_native(
                wallet,
                eth_address,
                self.gas_tank_address,
                amount,
                gas_price,
            )
            .await?;

        log::info!(
            "[ETH] Swept {} wei from {} to gas tank {} (tx={})",
            amount,
            address,
            self.gas_tank_address(),
            txid
        );

        Ok(SweepResult {
            amount,
            txid: Some(txid),
            deferred: false,
        })
    }

    async fn sweep_erc20_from_address(
        &self,
        address: &str,
        contract: Address,
        amount: U256,
    ) -> Result<SweepResult, DetectorError> {
        let eth_address = Address::from_str(address).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid managed Ethereum address '{address}': {e}"
            ))
        })?;
        let wallet = find_ethereum_wallet(&snapshot_ethereum_wallets(&self.wallets), eth_address)
            .ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "No managed Ethereum wallet found for address '{}'",
                address
            ))
        })?;

        if amount.is_zero() {
            return Ok(SweepResult {
                amount,
                txid: None,
                deferred: false,
            });
        }

        let gas_price = self.gas_price().await?;
        let gas_limit = self
            .estimate_token_transfer_gas(eth_address, contract, self.gas_tank_address, amount)
            .await
            .unwrap_or_else(|e| {
                log::warn!(
                    "[ETH] Token gas estimate failed for {} -> {}: {}; using configured limit {}",
                    address,
                    format_address(contract),
                    e,
                    self.config.token_transfer_gas_limit
                );
                U256::from(
                    self.config
                        .token_transfer_gas_limit
                        .max(DEFAULT_TOKEN_TRANSFER_GAS_LIMIT),
                )
            });
        let needed_fee =
            multiply_u256_by_f64(gas_limit * gas_price, self.config.gas_top_up_multiplier);

        if let Some(token) = self.tokens.iter().find(|t| t.contract == contract) {
            if let Some(peg) = token_peg_currency(&token.symbol) {
                let amount_pegged = u256_to_units_f64(amount, token.decimals.max(1)).max(0.0);
                if amount_pegged > 0.0 {
                    match self.eth_peg_price(peg).await {
                        Ok(eth_peg) if eth_peg > 0.0 => {
                            let fee_eth = u256_to_units_f64(needed_fee, ETH_DECIMALS);
                            let fee_pegged = fee_eth * eth_peg;
                            if fee_pegged > amount_pegged * self.config.max_fee_ratio {
                                log::info!(
                                    "[ETH] Deferring {} sweep for {}: fee ~{:.2}{} would be {:.1}% of swept ~{:.2}{} (max {:.1}%) - retry when gas drops",
                                    token.symbol,
                                    address,
                                    fee_pegged,
                                    peg,
                                    fee_pegged / amount_pegged * 100.0,
                                    amount_pegged,
                                    peg,
                                    self.config.max_fee_ratio * 100.0
                                );
                                return Ok(SweepResult {
                                    amount: U256::zero(),
                                    txid: None,
                                    deferred: true,
                                });
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            log::warn!(
                                "[ETH] Skipping fee-ratio check for {} sweep: failed to fetch ETH/{}: {}",
                                token.symbol,
                                peg,
                                error
                            );
                        }
                    }
                }
            }
        }

        self.ensure_eth_for_token_sweep(eth_address, needed_fee)
            .await?;

        let wallet = wallet
            .wallet
            .as_ref()
            .clone()
            .with_chain_id(self.config.chain_id);
        let data = erc20_transfer_data(self.ledger_address, amount);
        let tx = TransactionRequest::new()
            .from(eth_address)
            .to(contract)
            .value(U256::zero())
            .data(data)
            .gas(gas_limit)
            .gas_price(gas_price);
        let txid = self.send_transaction(wallet, tx).await?;

        log::info!(
            "[ETH] Swept ERC-20 {} units from {} directly to ledger {} (contract={}, tx={})",
            amount,
            address,
            self.ledger_address(),
            format_address(contract),
            txid
        );

        if let Err(error) = self.sweep_native_from_address(address).await {
            log::warn!(
                "[ETH] Failed to sweep leftover ETH after token sweep from {}: {}",
                address,
                error
            );
        }

        Ok(SweepResult {
            amount,
            txid: Some(txid),
            deferred: false,
        })
    }

    async fn ensure_eth_for_token_sweep(
        &self,
        address: Address,
        needed_fee: U256,
    ) -> Result<(), DetectorError> {
        let balance = self.eth_balance(address).await?;
        if balance >= needed_fee {
            return Ok(());
        }

        let top_up_amount = needed_fee - balance;
        let gas_price = self.gas_price().await?;
        let top_up_fee = U256::from(NATIVE_TRANSFER_GAS_LIMIT) * gas_price;
        let gas_tank_balance = self.eth_balance(self.gas_tank_address).await?;
        if gas_tank_balance <= top_up_amount + top_up_fee {
            return Err(DetectorError::InvalidConfig(format!(
                "ETH gas tank {} has {} wei, needs {} wei to top up {} plus fee {}",
                self.gas_tank_address(),
                gas_tank_balance,
                top_up_amount,
                format_address(address),
                top_up_fee
            )));
        }

        let txid = self
            .send_native(
                self.gas_tank_wallet.clone(),
                self.gas_tank_address,
                address,
                top_up_amount,
                gas_price,
            )
            .await?;
        log::info!(
            "[ETH] Topped up {} with {} wei from gas tank (tx={})",
            format_address(address),
            top_up_amount,
            txid
        );

        Ok(())
    }

    async fn maybe_maintain_gas_tank(&self) -> Result<(), DetectorError> {
        let now = unix_timestamp();
        let interval = i64::try_from(self.config.gas_tank_check_interval_secs)
            .unwrap_or(i64::MAX)
            .max(1);
        let should_run = {
            let state = self.state.lock().unwrap();
            state
                .gas_tank_last_maintenance_unix
                .map_or(true, |last| now.saturating_sub(last) >= interval)
        };
        if !should_run {
            return Ok(());
        }

        self.maintain_gas_tank().await?;
        {
            let mut state = self.state.lock().unwrap();
            state.gas_tank_last_maintenance_unix = Some(now);
        }
        self.persist_state()
    }

    async fn maintain_gas_tank(&self) -> Result<(), DetectorError> {
        self.sweep_gas_tank_tokens_to_ledger().await?;

        let eth_usd = match self.eth_usd_fetcher.get_price().await {
            Ok(price) if price > 0.0 => price,
            Ok(price) => {
                log::warn!("[ETH] Ignoring invalid ETH/USD price {}", price);
                return Ok(());
            }
            Err(error) => {
                log::warn!("[ETH] Failed to fetch ETH/USD for gas tank maintenance: {error}");
                return Ok(());
            }
        };

        let target_wei = usd_to_wei(self.config.gas_tank_target_usd, eth_usd)?;
        let balance = self.eth_balance(self.gas_tank_address).await?;
        if balance <= target_wei {
            log::info!(
                "[ETH] Gas tank balance {} wei is at or below target {} wei (${:.2})",
                balance,
                target_wei,
                self.config.gas_tank_target_usd
            );
            return Ok(());
        }

        let gas_price = self.gas_price().await?;
        let fee = U256::from(NATIVE_TRANSFER_GAS_LIMIT) * gas_price;
        if balance <= target_wei + fee {
            return Ok(());
        }

        let amount = balance - target_wei - fee;
        if amount.is_zero() {
            return Ok(());
        }

        if fee_ratio_too_high_u256(fee, amount, self.config.max_fee_ratio) {
            log::info!(
                "[ETH] Deferring gas tank excess sweep: fee {} wei would be {:.1}% of {} wei excess (max {:.1}%)",
                fee,
                ratio_percent_u256(fee, amount),
                amount,
                self.config.max_fee_ratio * 100.0
            );
            return Ok(());
        }

        let txid = self
            .send_native(
                self.gas_tank_wallet.clone(),
                self.gas_tank_address,
                self.ledger_address,
                amount,
                gas_price,
            )
            .await?;

        log::info!(
            "[ETH] Gas tank excess sweep: {} wei to ledger {} (kept ~${:.2}, tx={})",
            amount,
            self.ledger_address(),
            self.config.gas_tank_target_usd,
            txid
        );

        Ok(())
    }

    async fn sweep_gas_tank_tokens_to_ledger(&self) -> Result<(), DetectorError> {
        for token in &self.tokens {
            let balance = self
                .erc20_balance(token.contract, self.gas_tank_address)
                .await?;
            if balance.is_zero() {
                continue;
            }

            let gas_price = self.gas_price().await?;
            let gas_limit = self
                .estimate_token_transfer_gas(
                    self.gas_tank_address,
                    token.contract,
                    self.ledger_address,
                    balance,
                )
                .await
                .unwrap_or_else(|e| {
                    log::warn!(
                        "[ETH] Gas tank token sweep estimate failed for {}: {}; using configured limit {}",
                        token.symbol,
                        e,
                        self.config.token_transfer_gas_limit
                    );
                    U256::from(
                        self.config
                            .token_transfer_gas_limit
                            .max(DEFAULT_TOKEN_TRANSFER_GAS_LIMIT),
                    )
                });
            let fee = gas_limit * gas_price;
            let eth_balance = self.eth_balance(self.gas_tank_address).await?;
            if eth_balance < fee {
                return Err(DetectorError::InvalidConfig(format!(
                    "ETH gas tank {} has {} wei, needs at least {} wei to sweep {} {} token units to ledger",
                    self.gas_tank_address(),
                    eth_balance,
                    fee,
                    balance,
                    token.symbol
                )));
            }

            if let Some(peg) = token_peg_currency(&token.symbol) {
                let amount_pegged = u256_to_units_f64(balance, token.decimals.max(1));
                if amount_pegged > 0.0 {
                    if let Ok(eth_peg) = self.eth_peg_price(peg).await {
                        if eth_peg > 0.0 {
                            let fee_pegged = u256_to_units_f64(fee, ETH_DECIMALS) * eth_peg;
                            if fee_pegged > amount_pegged * self.config.max_fee_ratio {
                                log::info!(
                                    "[ETH] Deferring gas tank {} sweep to ledger: fee ~{:.2}{} would be {:.1}% of swept ~{:.2}{} (max {:.1}%)",
                                    token.symbol,
                                    fee_pegged,
                                    peg,
                                    fee_pegged / amount_pegged * 100.0,
                                    amount_pegged,
                                    peg,
                                    self.config.max_fee_ratio * 100.0
                                );
                                continue;
                            }
                        }
                    }
                }
            }

            let tx = TransactionRequest::new()
                .from(self.gas_tank_address)
                .to(token.contract)
                .value(U256::zero())
                .data(erc20_transfer_data(self.ledger_address, balance))
                .gas(gas_limit)
                .gas_price(gas_price);
            let txid = self
                .send_transaction(self.gas_tank_wallet.clone(), tx)
                .await?;

            log::info!(
                "[ETH] Gas tank token sweep: {} {} units to ledger {} (contract={}, tx={})",
                balance,
                token.symbol,
                self.ledger_address(),
                format_address(token.contract),
                txid
            );
        }

        Ok(())
    }

    async fn send_native(
        &self,
        wallet: LocalWallet,
        from: Address,
        to: Address,
        amount: U256,
        gas_price: U256,
    ) -> Result<String, DetectorError> {
        let tx = TransactionRequest::new()
            .from(from)
            .to(to)
            .value(amount)
            .gas(U256::from(NATIVE_TRANSFER_GAS_LIMIT))
            .gas_price(gas_price);
        self.send_transaction(wallet, tx).await
    }

    async fn send_transaction(
        &self,
        wallet: LocalWallet,
        tx: TransactionRequest,
    ) -> Result<String, DetectorError> {
        let client = SignerMiddleware::new(self.provider.clone(), wallet);
        let pending = client
            .send_transaction(tx, None)
            .await
            .map_err(|e| eth_rpc_error("eth_sendRawTransaction", e))?;
        let tx_hash = pending.tx_hash();
        let receipt = pending
            .await
            .map_err(|e| eth_rpc_error("eth_getTransactionReceipt", e))?;

        if let Some(receipt) = receipt {
            if receipt.status.map(|status| status.as_u64()) == Some(0) {
                return Err(DetectorError::ApiError(format!(
                    "Ethereum transaction {:#x} reverted",
                    tx_hash
                )));
            }
        }

        Ok(format!("{:#x}", tx_hash))
    }

    async fn estimate_token_transfer_gas(
        &self,
        from: Address,
        contract: Address,
        to: Address,
        amount: U256,
    ) -> Result<U256, DetectorError> {
        let tx = TransactionRequest::new()
            .from(from)
            .to(contract)
            .value(U256::zero())
            .data(erc20_transfer_data(to, amount));
        let typed: TypedTransaction = tx.into();
        self.provider
            .estimate_gas(&typed, None)
            .await
            .map_err(|e| eth_rpc_error("eth_estimateGas", e))
    }

    async fn current_block_number(&self) -> Result<u64, DetectorError> {
        self.provider
            .get_block_number()
            .await
            .map(|block| block.as_u64())
            .map_err(|e| eth_rpc_error("eth_blockNumber", e))
    }

    async fn eth_balance(&self, address: Address) -> Result<U256, DetectorError> {
        self.provider
            .get_balance(address, None)
            .await
            .map_err(|e| eth_rpc_error("eth_getBalance", e))
    }

    async fn erc20_balance(
        &self,
        contract: Address,
        owner: Address,
    ) -> Result<U256, DetectorError> {
        let tx = TransactionRequest::new()
            .to(contract)
            .data(erc20_balance_of_data(owner));
        let typed: TypedTransaction = tx.into();
        let response = self
            .provider
            .call(&typed, None)
            .await
            .map_err(|e| eth_rpc_error("eth_call", e))?;

        u256_from_erc20_return(&response).ok_or_else(|| {
            DetectorError::ApiError(format!(
                "ERC-20 balanceOf({}) for contract {} returned {} byte(s), expected at least 32",
                format_address(owner),
                format_address(contract),
                response.0.len()
            ))
        })
    }

    async fn gas_price(&self) -> Result<U256, DetectorError> {
        self.provider
            .get_gas_price()
            .await
            .map_err(|e| eth_rpc_error("eth_gasPrice", e))
    }

    fn payment_to_webhook(
        &self,
        payment: &DetectedEthereumPayment,
        current_block: u64,
        sweep: Option<&SweepResult>,
    ) -> DetectedPayment {
        let amount_coin = u256_to_units_f64(payment.amount, payment.asset_decimals);
        let swept_amount = sweep.map(|result| result.amount);
        let is_token = payment.token_contract.is_some();
        DetectedPayment {
            chain: Chain::Ethereum,
            ticker: payment.asset.clone(),
            txid: payment.txid.clone(),
            address: payment.reservation.address.clone(),
            user_id: Some(payment.reservation.user_id.clone()),
            amount_sat: u256_to_u64_saturating(payment.amount),
            amount_coin,
            confirmations: current_block.saturating_sub(payment.block_number) + 1,
            block_height: Some(payment.block_number),
            derivation_index: payment.reservation.wallet_index,
            memo: None,
            swept_to_address: sweep.map(|_| {
                if is_token {
                    self.ledger_address()
                } else {
                    self.gas_tank_address()
                }
            }),
            swept_amount_sat: swept_amount.map(u256_to_u64_saturating),
            swept_amount_coin: swept_amount
                .map(|amount| u256_to_units_f64(amount, payment.asset_decimals)),
            sweep_txid: sweep.and_then(|result| result.txid.clone()),
            fiat_amount: None,
            fiat_currency: None,
            coin_price: None,
            asset: Some(payment.asset.clone()),
            asset_decimals: Some(payment.asset_decimals),
            amount_base_units: Some(payment.amount.to_string()),
            swept_amount_base_units: swept_amount.map(|amount| amount.to_string()),
            token_contract: payment.token_contract.map(format_address),
        }
    }

    fn pending_to_webhook(
        &self,
        entry: &EthereumPendingPayment,
        current_block: u64,
        sweep: Option<&SweepResult>,
        amount: U256,
    ) -> DetectedPayment {
        let swept_amount = sweep.map(|result| result.amount);
        let is_token = entry.token_contract.is_some();
        DetectedPayment {
            chain: Chain::Ethereum,
            ticker: entry.asset.clone(),
            txid: entry.txid.clone(),
            address: entry.address.clone(),
            user_id: Some(entry.user_id.clone()),
            amount_sat: u256_to_u64_saturating(amount),
            amount_coin: u256_to_units_f64(amount, entry.asset_decimals),
            confirmations: current_block.saturating_sub(entry.block_number) + 1,
            block_height: Some(entry.block_number),
            derivation_index: entry.wallet_index,
            memo: None,
            swept_to_address: sweep.map(|_| {
                if is_token {
                    self.ledger_address()
                } else {
                    self.gas_tank_address()
                }
            }),
            swept_amount_sat: swept_amount.map(u256_to_u64_saturating),
            swept_amount_coin: swept_amount
                .map(|value| u256_to_units_f64(value, entry.asset_decimals)),
            sweep_txid: sweep.and_then(|result| result.txid.clone()),
            fiat_amount: None,
            fiat_currency: None,
            coin_price: None,
            asset: Some(entry.asset.clone()),
            asset_decimals: Some(entry.asset_decimals),
            amount_base_units: Some(entry.amount_base_units.clone()),
            swept_amount_base_units: swept_amount.map(|value| value.to_string()),
            token_contract: entry.token_contract.clone(),
        }
    }

    async fn enrich_fiat(&self, payment: &mut DetectedPayment) {
        if payment.ticker == "ETH" {
            match self.price_fetcher.get_price().await {
                Ok(price) => {
                    payment.coin_price = Some(price);
                    payment.fiat_currency = Some(self.price_fetcher.currency().to_string());
                    payment.fiat_amount = Some(payment.amount_coin * price);
                }
                Err(error) => {
                    log::warn!("[ETH] Failed to fetch ETH price: {error}");
                }
            }
        } else if let Some(peg) = token_peg_currency(&payment.ticker) {
            match self.peg_to_configured_fiat_rate(peg).await {
                Ok(rate) => {
                    payment.coin_price = Some(rate);
                    payment.fiat_currency = Some(self.price_fetcher.currency().to_string());
                    payment.fiat_amount = Some(payment.amount_coin * rate);
                }
                Err(error) => {
                    log::warn!(
                        "[ETH] Failed to convert {} from {} peg to {}: {error}",
                        payment.ticker,
                        peg,
                        self.price_fetcher.currency()
                    );
                }
            }
        }
    }

    async fn peg_to_configured_fiat_rate(&self, peg: &str) -> Result<f64, DetectorError> {
        let peg_upper = peg.to_ascii_uppercase();
        if self.price_fetcher.currency() == peg_upper {
            return Ok(1.0);
        }
        let eth_fiat = self.price_fetcher.get_price().await?;
        let eth_peg = self.eth_peg_price(&peg_upper).await?;
        usd_to_fiat_rate_from_eth_prices(eth_fiat, eth_peg)
    }

    async fn eth_peg_price(&self, peg: &str) -> Result<f64, DetectorError> {
        match peg.to_ascii_uppercase().as_str() {
            "USD" => self.eth_usd_fetcher.get_price().await,
            "EUR" => self.eth_eur_fetcher.get_price().await,
            other => Err(DetectorError::ApiError(format!(
                "No ETH/{other} price source available for stablecoin conversion"
            ))),
        }
    }

    fn is_known_event(&self, event_id: &str) -> bool {
        let state = self.state.lock().unwrap();
        state.credited_events.contains(event_id)
            || state.ignored_events.contains(event_id)
            || state
                .pending
                .iter()
                .any(|pending| pending.event_id == event_id)
    }

    fn is_credited_event(&self, event_id: &str) -> bool {
        let state = self.state.lock().unwrap();
        state.credited_events.contains(event_id)
    }

    fn mark_event_ignored(&self, event_id: &str) -> Result<(), DetectorError> {
        {
            let mut state = self.state.lock().unwrap();
            state.ignored_events.insert(event_id.to_string());
            state.pending.retain(|pending| pending.event_id != event_id);
        }
        self.persist_state()
    }

    fn set_last_scanned_block(&self, block_number: u64) -> Result<(), DetectorError> {
        {
            let mut state = self.state.lock().unwrap();
            state.last_scanned_block = Some(block_number);
        }
        self.persist_state()
    }

    fn persist_state(&self) -> Result<(), DetectorError> {
        let state = { self.state.lock().unwrap().clone() };
        let tmp_path = format!("{}.tmp", self.config.state_file);
        let data = serde_json::to_string_pretty(&state)?;
        std::fs::write(&tmp_path, &data).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to write Ethereum state file: {e}"))
        })?;
        std::fs::rename(&tmp_path, &self.config.state_file).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to rename Ethereum state file: {e}"))
        })?;
        Ok(())
    }
}

fn build_ethereum_provider(config: &EthereumConfig) -> Result<Provider<Http>, DetectorError> {
    let rpc_url = reqwest_ethers::Url::parse(config.rpc_url.as_str()).map_err(|e| {
        DetectorError::InvalidConfig(format!("Invalid ETH_RPC_URL '{}': {e}", config.rpc_url))
    })?;

    let mut client_builder = reqwest_ethers::Client::builder()
        .pool_max_idle_per_host(0)
        .connection_verbose(false);

    if let Some(ref proxy_url) = config.proxy_url {
        let proxy = reqwest_ethers::Proxy::all(proxy_url)
            .map_err(|e| DetectorError::InvalidConfig(format!("Invalid proxy URL: {e}")))?;
        client_builder = client_builder.proxy(proxy);
        log::info!("[ETH] Using proxy: {}", redact_url_credentials(proxy_url));
    } else {
        client_builder = client_builder.no_proxy();
    }

    let client = client_builder.build().map_err(|e| {
        DetectorError::InvalidConfig(format!("Failed to build Ethereum RPC client: {e}"))
    })?;

    Ok(Provider::new(Http::new_with_client(rpc_url, client)))
}

impl PaymentDetector for EthereumDetector {
    fn derive_address(&self, _index: u32) -> Result<String, DetectorError> {
        Ok(self.gas_tank_address())
    }

    async fn scan_block(
        &self,
        _block_height: u64,
        _max_derivation_index: u32,
    ) -> Result<Vec<DetectedPayment>, DetectorError> {
        self.process_cycle().await?;
        Ok(Vec::new())
    }

    async fn run_block_scan_loop(
        &self,
        _start_height: Option<u64>,
        _max_derivation_index: u32,
    ) -> Result<(), DetectorError> {
        loop {
            self.process_cycle().await?;
            tokio::time::sleep(std::time::Duration::from_secs(
                self.config.poll_interval_secs,
            ))
            .await;
        }
    }
}

pub fn default_erc20_tokens() -> Vec<Erc20TokenConfig> {
    vec![
        Erc20TokenConfig {
            symbol: "USDC".into(),
            contract: Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .expect("valid USDC contract"),
            decimals: 6,
        },
        Erc20TokenConfig {
            symbol: "USDT".into(),
            contract: Address::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7")
                .expect("valid USDT contract"),
            decimals: 6,
        },
    ]
}

pub fn parse_erc20_tokens(value: Option<&str>) -> Result<Vec<Erc20TokenConfig>, DetectorError> {
    let Some(value) = value else {
        return Ok(default_erc20_tokens());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("default") {
        return Ok(default_erc20_tokens());
    }
    if trimmed.eq_ignore_ascii_case("none") || trimmed.eq_ignore_ascii_case("off") {
        return Ok(Vec::new());
    }

    trimmed
        .split([',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let parts = entry.split(':').map(str::trim).collect::<Vec<_>>();
            if parts.len() != 3 {
                return Err(DetectorError::InvalidConfig(format!(
                    "Invalid ETH_ERC20_TOKENS entry '{}'; expected SYMBOL:0xcontract:decimals",
                    entry
                )));
            }
            let contract = Address::from_str(parts[1]).map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid token contract '{}' in ETH_ERC20_TOKENS: {e}",
                    parts[1]
                ))
            })?;
            let decimals = parts[2].parse::<u8>().map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid token decimals '{}' in ETH_ERC20_TOKENS: {e}",
                    parts[2]
                ))
            })?;
            Ok(Erc20TokenConfig {
                symbol: parts[0].to_ascii_uppercase(),
                contract,
                decimals,
            })
        })
        .collect()
}

fn load_ethereum_state(path: &str) -> EthereumState {
    let file = std::path::Path::new(path);
    if !file.exists() {
        log::info!(
            "[ETH] No persisted state file found at '{}', starting fresh",
            path
        );
        return EthereumState::default();
    }

    match std::fs::read_to_string(file) {
        Ok(data) => match serde_json::from_str::<EthereumState>(&data) {
            Ok(state) => {
                log::info!(
                    "[ETH] Loaded state from '{}' with {} pending payment(s), last_scanned_block={:?}",
                    path,
                    state.pending.len(),
                    state.last_scanned_block
                );
                state
            }
            Err(error) => {
                log::warn!(
                    "[ETH] Failed to parse state file '{}': {} - starting fresh",
                    path,
                    error
                );
                EthereumState::default()
            }
        },
        Err(error) => {
            log::warn!(
                "[ETH] Failed to read state file '{}': {} - starting fresh",
                path,
                error
            );
            EthereumState::default()
        }
    }
}

fn erc20_transfer_data(to: Address, amount: U256) -> Bytes {
    let mut data = Vec::with_capacity(4 + 32 + 32);
    data.extend_from_slice(&keccak256("transfer(address,uint256)")[..4]);

    let mut to_word = [0u8; 32];
    to_word[12..].copy_from_slice(to.as_bytes());
    data.extend_from_slice(&to_word);

    let mut amount_word = [0u8; 32];
    amount.to_big_endian(&mut amount_word);
    data.extend_from_slice(&amount_word);

    Bytes::from(data)
}

fn erc20_balance_of_data(owner: Address) -> Bytes {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&keccak256("balanceOf(address)")[..4]);

    let mut owner_word = [0u8; 32];
    owner_word[12..].copy_from_slice(owner.as_bytes());
    data.extend_from_slice(&owner_word);

    Bytes::from(data)
}

fn u256_from_erc20_return(data: &Bytes) -> Option<U256> {
    if data.0.len() < 32 {
        return None;
    }

    let start = data.0.len() - 32;
    Some(U256::from_big_endian(&data.0[start..]))
}

fn address_to_topic(address: Address) -> H256 {
    let mut topic = [0u8; 32];
    topic[12..].copy_from_slice(address.as_bytes());
    H256::from(topic)
}

fn address_from_topic(topic: H256) -> Address {
    Address::from_slice(&topic.as_bytes()[12..])
}

fn is_native_gas_tank_top_up(from: Address, to: Address, gas_tank_address: Address) -> bool {
    from == gas_tank_address && to != gas_tank_address
}

/// Normalize a tx hash returned by Etherscan to the same `0x{:x}` format used
/// by the rest of the detector (otherwise idempotency event_ids and pending
/// entry txids would diverge between native scan and internal scan).
fn normalize_etherscan_hash(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if let Ok(hash) = H256::from_str(stripped) {
        format!("{:#x}", hash)
    } else {
        trimmed.to_string()
    }
}

fn fee_ratio_too_high_u256(fee: U256, total: U256, max_ratio: f64) -> bool {
    if total.is_zero() || !max_ratio.is_finite() || max_ratio <= 0.0 || max_ratio >= 1.0 {
        return false;
    }
    let fee_f = u256_to_f64_lossy(fee);
    let total_f = u256_to_f64_lossy(total);
    if total_f <= 0.0 {
        return false;
    }
    fee_f / total_f > max_ratio
}

fn ratio_percent_u256(fee: U256, total: U256) -> f64 {
    let total_f = u256_to_f64_lossy(total);
    if total_f <= 0.0 {
        return 0.0;
    }
    u256_to_f64_lossy(fee) / total_f * 100.0
}

fn u256_to_f64_lossy(value: U256) -> f64 {
    value.to_string().parse::<f64>().unwrap_or(f64::MAX)
}

fn multiply_u256_by_f64(value: U256, multiplier: f64) -> U256 {
    if !multiplier.is_finite() || multiplier <= 1.0 {
        return value;
    }
    let basis_points = (multiplier * 10_000.0).ceil() as u64;
    value * U256::from(basis_points) / U256::from(10_000u64)
}

fn usd_to_wei(usd: f64, eth_usd: f64) -> Result<U256, DetectorError> {
    if !usd.is_finite() || usd <= 0.0 {
        return Err(DetectorError::InvalidConfig(
            "ETH_GAS_TANK_TARGET_USD must be positive".into(),
        ));
    }
    if !eth_usd.is_finite() || eth_usd <= 0.0 {
        return Err(DetectorError::ApiError(
            "ETH/USD price must be positive for gas tank maintenance".into(),
        ));
    }
    let wei = (usd / eth_usd) * 1_000_000_000_000_000_000f64;
    if !wei.is_finite() || wei <= 0.0 || wei > u128::MAX as f64 {
        return Err(DetectorError::InvalidConfig(format!(
            "Cannot convert ${usd:.2} at ETH/USD {eth_usd:.2} to wei"
        )));
    }
    Ok(U256::from(wei.ceil() as u128))
}

fn usd_to_fiat_rate_from_eth_prices(eth_fiat: f64, eth_usd: f64) -> Result<f64, DetectorError> {
    if !eth_fiat.is_finite() || eth_fiat <= 0.0 {
        return Err(DetectorError::ApiError(
            "ETH/fiat price must be positive for stablecoin conversion".into(),
        ));
    }
    if !eth_usd.is_finite() || eth_usd <= 0.0 {
        return Err(DetectorError::ApiError(
            "ETH/USD price must be positive for stablecoin conversion".into(),
        ));
    }

    Ok(eth_fiat / eth_usd)
}

fn is_usd_pegged_token(symbol: &str) -> bool {
    matches!(
        symbol.trim().to_ascii_uppercase().as_str(),
        "USDC" | "USDT" | "DAI" | "BUSD" | "TUSD" | "USDP" | "GUSD" | "PYUSD"
    )
}

fn is_eur_pegged_token(symbol: &str) -> bool {
    matches!(
        symbol.trim().to_ascii_uppercase().as_str(),
        "EURC" | "EURT" | "AGEUR" | "EURE" | "EUROE"
    )
}

fn token_peg_currency(symbol: &str) -> Option<&'static str> {
    if is_usd_pegged_token(symbol) {
        Some("USD")
    } else if is_eur_pegged_token(symbol) {
        Some("EUR")
    } else {
        None
    }
}

fn u256_to_units_f64(value: U256, decimals: u8) -> f64 {
    let base = value.to_string().parse::<f64>().unwrap_or(f64::MAX);
    base / 10f64.powi(i32::from(decimals))
}

fn u256_to_u64_saturating(value: U256) -> u64 {
    if value > U256::from(u64::MAX) {
        u64::MAX
    } else {
        value.as_u64()
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn eth_rpc_error<E: std::fmt::Display>(context: &str, error: E) -> DetectorError {
    DetectorError::ApiError(format!("Ethereum RPC {context} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_gas_tank_top_up_is_internal() {
        let gas_tank = Address::from_low_u64_be(1);
        let reserved = Address::from_low_u64_be(2);
        let customer = Address::from_low_u64_be(3);

        assert!(is_native_gas_tank_top_up(gas_tank, reserved, gas_tank));
        assert!(!is_native_gas_tank_top_up(customer, reserved, gas_tank));
        assert!(!is_native_gas_tank_top_up(reserved, gas_tank, gas_tank));
        assert!(!is_native_gas_tank_top_up(gas_tank, gas_tank, gas_tank));
    }

    #[test]
    fn ethereum_state_defaults_ignored_events() {
        let state: EthereumState = serde_json::from_str(
            r#"{
                "last_scanned_block": 123,
                "pending": [],
                "credited_events": [],
                "gas_tank_last_maintenance_unix": null
            }"#,
        )
        .unwrap();

        assert!(state.ignored_events.is_empty());
    }

    #[test]
    fn encodes_erc20_balance_of_call() {
        let owner = Address::from_low_u64_be(0x1234);
        let data = erc20_balance_of_data(owner);

        assert_eq!(&data.0[..4], &keccak256("balanceOf(address)")[..4]);
        assert_eq!(data.0.len(), 36);
        assert_eq!(&data.0[16..36], owner.as_bytes());
    }

    #[test]
    fn decodes_erc20_u256_return() {
        let value = U256::from(42u64);
        let mut word = [0u8; 32];
        value.to_big_endian(&mut word);

        assert_eq!(
            u256_from_erc20_return(&Bytes::from(word.to_vec())),
            Some(value)
        );
        assert_eq!(u256_from_erc20_return(&Bytes::from(vec![1, 2, 3])), None);
    }

    #[test]
    fn identifies_usd_pegged_tokens() {
        assert!(is_usd_pegged_token("USDT"));
        assert!(is_usd_pegged_token(" usdc "));
        assert!(!is_usd_pegged_token("ETH"));
        assert!(!is_usd_pegged_token("WBTC"));
    }

    #[test]
    fn derives_usd_to_fiat_rate_from_eth_prices() {
        let rate = usd_to_fiat_rate_from_eth_prices(1_800.0, 2_000.0).unwrap();

        assert!((rate - 0.9).abs() < f64::EPSILON);
        assert!(usd_to_fiat_rate_from_eth_prices(0.0, 2_000.0).is_err());
        assert!(usd_to_fiat_rate_from_eth_prices(1_800.0, 0.0).is_err());
    }
}
