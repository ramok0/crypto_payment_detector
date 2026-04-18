use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use solana_sdk::hash::Hash;
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::transaction::Transaction;
use solana_system_interface::instruction as system_instruction;

use crate::error::DetectorError;
use crate::pricing::PriceFetcher;
use crate::solana_pool::{
    ManagedSolanaWallet, SolanaReservation, find_wallet, load_active_reservations, load_wallet_pool,
};
use crate::trait_def::PaymentDetector;
use crate::types::{Chain, DetectedPayment, WebhookEvent};
use crate::webhook::send_webhook;

#[derive(Debug, Clone)]
pub struct SolanaConfig {
    pub rpc_url: String,
    pub wallet_pool_file: String,
    pub secure_deposit_address: String,
    pub webhook_url: String,
    pub webhook_hmac_secret: String,
    pub redis_url: String,
    pub reservation_ttl_secs: u64,
    pub state_file: String,
    pub poll_interval_secs: u64,
    pub min_confirmations: u64,
    pub fiat_currency: String,
    pub proxy_url: Option<String>,
    pub max_retries: u32,
    pub retry_base_delay_ms: u64,
    pub min_deposit_fiat: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SolanaPendingPayment {
    signature: String,
    slot: u64,
    amount_lamports: u64,
    address: String,
    user_id: String,
    wallet_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SolanaAddressState {
    last_processed_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SolanaState {
    #[serde(default)]
    addresses: HashMap<String, SolanaAddressState>,
    #[serde(default)]
    pending: Vec<SolanaPendingPayment>,
    #[serde(default)]
    credited_signatures: HashSet<String>,
}

#[derive(Debug, Clone)]
struct SignatureInfo {
    signature: String,
}

#[derive(Debug, Clone)]
struct SweepResult {
    amount_lamports: u64,
    txid: Option<String>,
}

#[derive(Debug)]
pub struct SolanaDetector {
    config: SolanaConfig,
    wallets: Vec<ManagedSolanaWallet>,
    rpc_client: reqwest::Client,
    webhook_client: reqwest::Client,
    price_fetcher: PriceFetcher,
    state: Arc<Mutex<SolanaState>>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: T,
}

#[derive(Debug, Deserialize)]
struct RpcSignatureInfo {
    signature: String,
}

#[derive(Debug, Deserialize)]
struct RpcTransactionResult {
    slot: u64,
    #[serde(default)]
    meta: Option<RpcMeta>,
    transaction: RpcTransaction,
}

#[derive(Debug, Deserialize)]
struct RpcMeta {
    #[serde(rename = "preBalances")]
    pre_balances: Vec<u64>,
    #[serde(rename = "postBalances")]
    post_balances: Vec<u64>,
    #[serde(default)]
    err: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RpcTransaction {
    message: RpcMessage,
}

#[derive(Debug, Deserialize)]
struct RpcMessage {
    #[serde(rename = "accountKeys")]
    account_keys: Vec<RpcAccountKey>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RpcAccountKey {
    String(String),
    Object { pubkey: String },
}

impl RpcAccountKey {
    fn pubkey(&self) -> &str {
        match self {
            RpcAccountKey::String(value) => value,
            RpcAccountKey::Object { pubkey } => pubkey,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcBalanceResult {
    value: u64,
}

#[derive(Debug, Deserialize)]
struct RpcLatestBlockhashResult {
    value: RpcLatestBlockhashValue,
}

#[derive(Debug, Deserialize)]
struct RpcLatestBlockhashValue {
    blockhash: String,
}

#[derive(Debug, Deserialize)]
struct RpcFeeResult {
    value: Option<u64>,
}

impl SolanaDetector {
    pub fn new(config: SolanaConfig) -> Result<Self, DetectorError> {
        if config.secure_deposit_address.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "SOLANA_DEPOSIT_ADDRESS is required".into(),
            ));
        }
        Pubkey::from_str(&config.secure_deposit_address).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid SOLANA_DEPOSIT_ADDRESS '{}': {e}",
                config.secure_deposit_address
            ))
        })?;
        if config.wallet_pool_file.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "SOLANA_WALLET_POOL_FILE is required".into(),
            ));
        }
        if config.redis_url.is_empty() {
            return Err(DetectorError::InvalidConfig("REDIS_URL is required".into()));
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

        let wallets = load_wallet_pool(&config.wallet_pool_file)?;

        let mut rpc_builder = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .connection_verbose(false);
        if let Some(ref proxy_url) = config.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| DetectorError::InvalidConfig(format!("Invalid proxy URL: {e}")))?;
            rpc_builder = rpc_builder.proxy(proxy);
            log::info!("[SOL] Using proxy: {}", proxy_url);
        }
        let rpc_client = rpc_builder.build().map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to build RPC client: {e}"))
        })?;

        let webhook_client = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .connection_verbose(false)
            .build()
            .map_err(|e| {
                DetectorError::InvalidConfig(format!("Failed to build webhook client: {e}"))
            })?;

        let state = load_solana_state(&config.state_file);

        Ok(Self {
            price_fetcher: PriceFetcher::new(
                webhook_client.clone(),
                &config.fiat_currency,
                Chain::Solana,
            ),
            config,
            wallets,
            rpc_client,
            webhook_client,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn wallet_count(&self) -> usize {
        load_wallet_pool(&self.config.wallet_pool_file)
            .map(|wallets| wallets.len())
            .unwrap_or_else(|error| {
                log::warn!("[SOL] Failed to reload wallet pool for count: {error}");
                self.wallets.len()
            })
    }

    async fn process_cycle(&self) -> Result<(), DetectorError> {
        let reservations = load_active_reservations(&self.config.redis_url).await?;
        let current_slot = self.get_current_slot().await?;
        let spot_price = match self.price_fetcher.get_price().await {
            Ok(price) => Some(price),
            Err(e) => {
                log::warn!(
                    "[SOL] Failed to fetch price for dust filter (continuing without fiat filter): {e}"
                );
                None
            }
        };

        for reservation in &reservations {
            self.process_reservation(reservation, current_slot, spot_price)
                .await?;
        }

        self.process_credits(current_slot).await?;
        Ok(())
    }

    async fn process_reservation(
        &self,
        reservation: &SolanaReservation,
        current_slot: u64,
        spot_price: Option<f64>,
    ) -> Result<(), DetectorError> {
        let new_signatures = self.get_new_signatures(&reservation.address).await?;
        if new_signatures.is_empty() {
            return Ok(());
        }

        for sig in &new_signatures {
            let tx = match self.get_transaction(&sig.signature).await {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!("[SOL] Failed to load tx {}: {}", sig.signature, e);
                    continue;
                }
            };

            let Some(amount_lamports) =
                Self::extract_positive_lamports_to_address(&tx, &reservation.address)
            else {
                self.update_last_processed_signature(&reservation.address, &sig.signature)?;
                continue;
            };

            if let Some(price) = spot_price {
                let amount_coin = amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64;
                let fiat_value = amount_coin * price;
                if fiat_value < self.config.min_deposit_fiat {
                    log::info!(
                        "[SOL] Ignoring dust deposit tx={} address={} amount={} SOL (~{:.4} {}) < min {:.2}",
                        sig.signature,
                        reservation.address,
                        amount_coin,
                        fiat_value,
                        self.price_fetcher.currency(),
                        self.config.min_deposit_fiat
                    );
                    self.update_last_processed_signature(&reservation.address, &sig.signature)?;
                    continue;
                }
            }

            let confirmations = current_slot.saturating_sub(tx.slot) + 1;
            let detected = DetectedPayment {
                chain: Chain::Solana,
                ticker: Chain::Solana.ticker().to_string(),
                txid: sig.signature.clone(),
                address: reservation.address.clone(),
                user_id: Some(reservation.user_id.clone()),
                amount_sat: amount_lamports,
                amount_coin: amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
                confirmations,
                block_height: Some(tx.slot),
                derivation_index: reservation.wallet_index,
                memo: None,
                swept_to_address: None,
                swept_amount_sat: None,
                swept_amount_coin: None,
                sweep_txid: None,
                fiat_amount: None,
                fiat_currency: None,
                coin_price: None,
            };

            let event = WebhookEvent::PaymentDetected(detected.clone());
            send_webhook(
                &self.webhook_client,
                &self.config.webhook_url,
                &self.config.webhook_hmac_secret,
                &event,
            )
            .await?;

            {
                let mut state = self.state.lock().unwrap();
                let already_pending = state.pending.iter().any(|p| p.signature == sig.signature);
                let already_credited = state.credited_signatures.contains(&sig.signature);

                if !already_pending && !already_credited {
                    state.pending.push(SolanaPendingPayment {
                        signature: sig.signature.clone(),
                        slot: tx.slot,
                        amount_lamports,
                        address: reservation.address.clone(),
                        user_id: reservation.user_id.clone(),
                        wallet_index: reservation.wallet_index,
                    });
                }
            }

            self.update_last_processed_signature(&reservation.address, &sig.signature)?;
        }

        Ok(())
    }

    async fn process_credits(&self, current_slot: u64) -> Result<(), DetectorError> {
        let pending = {
            let state = self.state.lock().unwrap();
            state.pending.clone()
        };

        for entry in pending {
            let confirmations = current_slot.saturating_sub(entry.slot) + 1;
            if confirmations < self.config.min_confirmations {
                continue;
            }

            let sweep_result = self.sweep_available_balance(&entry.address).await?;
            let mut credited_payment = DetectedPayment {
                chain: Chain::Solana,
                ticker: Chain::Solana.ticker().to_string(),
                txid: entry.signature.clone(),
                address: entry.address.clone(),
                user_id: Some(entry.user_id.clone()),
                amount_sat: entry.amount_lamports,
                amount_coin: entry.amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
                confirmations,
                block_height: Some(entry.slot),
                derivation_index: entry.wallet_index,
                memo: None,
                swept_to_address: Some(self.config.secure_deposit_address.clone()),
                swept_amount_sat: Some(sweep_result.amount_lamports),
                swept_amount_coin: Some(
                    sweep_result.amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
                ),
                sweep_txid: sweep_result.txid.clone(),
                fiat_amount: None,
                fiat_currency: None,
                coin_price: None,
            };

            if let Ok(price) = self.price_fetcher.get_price().await {
                credited_payment.coin_price = Some(price);
                credited_payment.fiat_currency = Some(self.price_fetcher.currency().to_string());
                credited_payment.fiat_amount = Some(credited_payment.amount_coin * price);
            }

            let event = WebhookEvent::PaymentCredited(credited_payment);
            send_webhook(
                &self.webhook_client,
                &self.config.webhook_url,
                &self.config.webhook_hmac_secret,
                &event,
            )
            .await?;

            {
                let mut state = self.state.lock().unwrap();
                state.credited_signatures.insert(entry.signature.clone());
                state
                    .pending
                    .retain(|pending| pending.signature != entry.signature);
            }

            self.persist_state()?;
        }

        Ok(())
    }

    async fn sweep_available_balance(&self, address: &str) -> Result<SweepResult, DetectorError> {
        let wallets = load_wallet_pool(&self.config.wallet_pool_file)?;
        let wallet = find_wallet(&wallets, address).ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "No managed Solana wallet found for address '{}'",
                address
            ))
        })?;

        let balance = self.get_balance(address).await?;
        if balance == 0 {
            return Ok(SweepResult {
                amount_lamports: 0,
                txid: None,
            });
        }

        let recent_blockhash = self.get_latest_blockhash().await?;
        let fee = self.estimate_transfer_fee(wallet, recent_blockhash).await?;

        if balance <= fee {
            log::info!(
                "[SOL] Address {} balance {} lamports is not enough to cover sweep fee {}",
                address,
                balance,
                fee
            );
            return Ok(SweepResult {
                amount_lamports: 0,
                txid: None,
            });
        }

        let destination = Pubkey::from_str(&self.config.secure_deposit_address).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid secure Solana deposit address '{}': {e}",
                self.config.secure_deposit_address
            ))
        })?;
        let from = wallet.keypair.pubkey();
        let amount_lamports = balance - fee;
        let tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &from,
                &destination,
                amount_lamports,
            )],
            Some(&from),
            &[wallet.keypair.as_ref()],
            recent_blockhash,
        );

        let tx_bytes = bincode::serialize(&tx).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to serialize Solana sweep tx: {e}"))
        })?;
        let tx_b64 = BASE64_STANDARD.encode(tx_bytes);
        let txid: String = self
            .rpc_call(
                "sendTransaction",
                serde_json::json!([
                    tx_b64,
                    {
                        "encoding": "base64",
                        "preflightCommitment": "confirmed",
                        "maxRetries": self.config.max_retries
                    }
                ]),
            )
            .await?;

        log::info!(
            "[SOL] Swept {:.9} SOL from {} to {} (tx={})",
            amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
            address,
            self.config.secure_deposit_address,
            txid
        );

        Ok(SweepResult {
            amount_lamports,
            txid: Some(txid),
        })
    }

    async fn estimate_transfer_fee(
        &self,
        wallet: &ManagedSolanaWallet,
        recent_blockhash: Hash,
    ) -> Result<u64, DetectorError> {
        let destination = Pubkey::from_str(&self.config.secure_deposit_address).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid secure Solana deposit address '{}': {e}",
                self.config.secure_deposit_address
            ))
        })?;
        let from = wallet.keypair.pubkey();
        let message = Message::new_with_blockhash(
            &[system_instruction::transfer(&from, &destination, 1)],
            Some(&from),
            &recent_blockhash,
        );
        let message_bytes = bincode::serialize(&message).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to serialize Solana message: {e}"))
        })?;
        let message_b64 = BASE64_STANDARD.encode(message_bytes);
        let fee_result: RpcFeeResult = self
            .rpc_call(
                "getFeeForMessage",
                serde_json::json!([
                    message_b64,
                    {
                        "commitment": "confirmed"
                    }
                ]),
            )
            .await?;

        fee_result.value.ok_or_else(|| {
            DetectorError::ApiError(
                "Solana RPC returned no fee for the generated sweep message".into(),
            )
        })
    }

    async fn get_current_slot(&self) -> Result<u64, DetectorError> {
        self.rpc_call("getSlot", serde_json::json!([{"commitment":"confirmed"}]))
            .await
    }

    async fn get_balance(&self, address: &str) -> Result<u64, DetectorError> {
        let result: RpcBalanceResult = self
            .rpc_call(
                "getBalance",
                serde_json::json!([address, {"commitment":"confirmed"}]),
            )
            .await?;
        Ok(result.value)
    }

    async fn get_latest_blockhash(&self) -> Result<Hash, DetectorError> {
        let result: RpcLatestBlockhashResult = self
            .rpc_call(
                "getLatestBlockhash",
                serde_json::json!([{"commitment":"confirmed"}]),
            )
            .await?;

        Hash::from_str(&result.value.blockhash).map_err(|e| {
            DetectorError::ApiError(format!(
                "Failed to parse Solana blockhash '{}': {e}",
                result.value.blockhash
            ))
        })
    }

    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, DetectorError> {
        let max_retries = self.config.max_retries.max(1);
        let mut attempt: u32 = 0;
        let mut last_error = String::new();

        while attempt < max_retries {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });

            let response = self
                .rpc_client
                .post(&self.config.rpc_url)
                .json(&body)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let parsed: RpcResponse<T> = resp.json().await.map_err(|e| {
                        DetectorError::ApiError(format!("Solana RPC parse failed: {e}"))
                    })?;
                    return Ok(parsed.result);
                }
                Ok(resp) => {
                    let status = resp.status();
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u64>().ok());

                    last_error = format!("Solana RPC {} failed with status {}", method, status);
                    attempt += 1;
                    if attempt >= max_retries {
                        break;
                    }

                    let backoff_delay = self.config.retry_base_delay_ms * 2u64.pow(attempt - 1);
                    let delay_ms = retry_after
                        .map(|seconds| seconds.saturating_mul(1000))
                        .unwrap_or(backoff_delay);
                    log::warn!(
                        "[SOL] {} (attempt {}/{}) - retry in {}ms",
                        last_error,
                        attempt,
                        max_retries,
                        delay_ms
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    last_error = format!("Solana RPC request failed: {e}");
                    attempt += 1;
                    if attempt >= max_retries {
                        break;
                    }

                    let delay_ms = self.config.retry_base_delay_ms * 2u64.pow(attempt - 1);
                    log::warn!(
                        "[SOL] {} (attempt {}/{}) - retry in {}ms",
                        last_error,
                        attempt,
                        max_retries,
                        delay_ms
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }

        Err(DetectorError::ApiError(last_error))
    }

    async fn get_new_signatures(&self, address: &str) -> Result<Vec<SignatureInfo>, DetectorError> {
        let last_processed = {
            let state = self.state.lock().unwrap();
            state
                .addresses
                .get(address)
                .and_then(|entry| entry.last_processed_signature.clone())
        };

        let mut before: Option<String> = None;
        let mut collected = Vec::new();
        let mut found_cursor = false;

        loop {
            let mut config = serde_json::json!({
                "limit": 1000,
                "commitment": "confirmed"
            });
            if let Some(ref signature) = before {
                config["before"] = serde_json::Value::String(signature.clone());
            }

            let page: Vec<RpcSignatureInfo> = self
                .rpc_call(
                    "getSignaturesForAddress",
                    serde_json::json!([address, config]),
                )
                .await?;

            if page.is_empty() {
                break;
            }

            for info in &page {
                if last_processed.as_deref() == Some(info.signature.as_str()) {
                    found_cursor = true;
                    break;
                }

                collected.push(SignatureInfo {
                    signature: info.signature.clone(),
                });
            }

            if found_cursor || page.len() < 1000 {
                break;
            }

            before = page.last().map(|entry| entry.signature.clone());
        }

        collected.reverse();
        Ok(collected)
    }

    async fn get_transaction(
        &self,
        signature: &str,
    ) -> Result<RpcTransactionResult, DetectorError> {
        self.rpc_call(
            "getTransaction",
            serde_json::json!([
                signature,
                {
                    "encoding": "jsonParsed",
                    "commitment": "confirmed",
                    "maxSupportedTransactionVersion": 0
                }
            ]),
        )
        .await
    }

    fn extract_positive_lamports_to_address(
        result: &RpcTransactionResult,
        address: &str,
    ) -> Option<u64> {
        let meta = result.meta.as_ref()?;
        if meta.err.is_some() {
            return None;
        }

        for (index, key) in result.transaction.message.account_keys.iter().enumerate() {
            if key.pubkey() == address {
                let pre = *meta.pre_balances.get(index)?;
                let post = *meta.post_balances.get(index)?;
                if post > pre {
                    return Some(post - pre);
                }
            }
        }

        None
    }

    fn update_last_processed_signature(
        &self,
        address: &str,
        signature: &str,
    ) -> Result<(), DetectorError> {
        {
            let mut state = self.state.lock().unwrap();
            state
                .addresses
                .entry(address.to_string())
                .or_default()
                .last_processed_signature = Some(signature.to_string());
        }

        self.persist_state()
    }

    fn persist_state(&self) -> Result<(), DetectorError> {
        let state = {
            let state = self.state.lock().unwrap();
            state.clone()
        };

        let tmp_path = format!("{}.tmp", self.config.state_file);
        let data = serde_json::to_string_pretty(&state)?;
        std::fs::write(&tmp_path, &data).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to write state file: {e}"))
        })?;
        std::fs::rename(&tmp_path, &self.config.state_file).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to rename state file: {e}"))
        })?;
        Ok(())
    }
}

impl PaymentDetector for SolanaDetector {
    fn derive_address(&self, _index: u32) -> Result<String, DetectorError> {
        Ok(self.config.secure_deposit_address.clone())
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

fn load_solana_state(path: &str) -> SolanaState {
    let file = std::path::Path::new(path);
    if !file.exists() {
        log::info!(
            "[SOL] No persisted state file found at '{}', starting fresh",
            path
        );
        return SolanaState::default();
    }

    match std::fs::read_to_string(file) {
        Ok(data) => match serde_json::from_str::<SolanaState>(&data) {
            Ok(state) => {
                log::info!(
                    "[SOL] Loaded state from '{}' with {} pending payment(s) and {} tracked address cursor(s)",
                    path,
                    state.pending.len(),
                    state.addresses.len()
                );
                state
            }
            Err(e) => {
                log::warn!(
                    "[SOL] Failed to parse state file '{}': {} - starting fresh",
                    path,
                    e
                );
                SolanaState::default()
            }
        },
        Err(e) => {
            log::warn!(
                "[SOL] Failed to read state file '{}': {} - starting fresh",
                path,
                e
            );
            SolanaState::default()
        }
    }
}
