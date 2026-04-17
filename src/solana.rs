use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::DetectorError;
use crate::pricing::PriceFetcher;
use crate::trait_def::PaymentDetector;
use crate::types::{Chain, DetectedPayment, WebhookEvent};
use crate::webhook::{send_discord_webhook, send_webhook};

#[derive(Debug, Clone)]
pub struct SolanaConfig {
    pub rpc_url: String,
    pub deposit_address: String,
    pub webhook_url: String,
    pub webhook_hmac_secret: String,
    pub discord_invalid_webhook_url: Option<String>,
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
    memo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SolanaState {
    last_processed_signature: Option<String>,
    #[serde(default)]
    pending: Vec<SolanaPendingPayment>,
    #[serde(default)]
    credited_signatures: HashSet<String>,
    #[serde(default)]
    invalid_alerted_signatures: HashSet<String>,
}

#[derive(Debug, Clone)]
struct SignatureInfo {
    signature: String,
}

#[derive(Debug)]
pub struct SolanaDetector {
    config: SolanaConfig,
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
    #[serde(default)]
    instructions: Vec<RpcInstruction>,
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
            RpcAccountKey::String(s) => s,
            RpcAccountKey::Object { pubkey } => pubkey,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcInstruction {
    #[serde(default)]
    program: Option<String>,
    #[serde(default)]
    parsed: Option<serde_json::Value>,
}

impl SolanaDetector {
    pub fn new(config: SolanaConfig) -> Result<Self, DetectorError> {
        if config.deposit_address.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "SOLANA_DEPOSIT_ADDRESS is required".into(),
            ));
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

        let state = load_solana_state(&config.state_file)?;

        Ok(Self {
            price_fetcher: PriceFetcher::new(
                webhook_client.clone(),
                &config.fiat_currency,
                Chain::Solana,
            ),
            config,
            rpc_client,
            webhook_client,
            state: Arc::new(Mutex::new(state)),
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
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok());

                    last_error = format!("Solana RPC {} failed with status {}", method, status);
                    attempt += 1;
                    if attempt >= max_retries {
                        break;
                    }

                    let backoff_delay = self.config.retry_base_delay_ms * 2u64.pow(attempt - 1);
                    let delay_ms = retry_after
                        .map(|sec| sec.saturating_mul(1000))
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

    async fn get_current_slot(&self) -> Result<u64, DetectorError> {
        self.rpc_call("getSlot", serde_json::json!([{"commitment":"confirmed"}]))
            .await
    }

    async fn get_new_signatures(&self) -> Result<Vec<SignatureInfo>, DetectorError> {
        let last_processed = {
            let state = self.state.lock().unwrap();
            state.last_processed_signature.clone()
        };

        let mut before: Option<String> = None;
        let mut collected = Vec::new();
        let mut found_cursor = false;

        loop {
            let mut config = serde_json::json!({
                "limit": 1000,
                "commitment": "confirmed"
            });
            if let Some(ref sig) = before {
                config["before"] = serde_json::Value::String(sig.clone());
            }

            let page: Vec<RpcSignatureInfo> = self
                .rpc_call(
                    "getSignaturesForAddress",
                    serde_json::json!([self.config.deposit_address, config]),
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

            if found_cursor {
                break;
            }

            if page.len() < 1000 {
                break;
            }

            before = page.last().map(|s| s.signature.clone());
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

    fn extract_memo(result: &RpcTransactionResult) -> Option<String> {
        result
            .transaction
            .message
            .instructions
            .iter()
            .find_map(|ix| {
                if ix.program.as_deref() == Some("spl-memo") {
                    match &ix.parsed {
                        Some(serde_json::Value::String(s)) => Some(s.clone()),
                        Some(serde_json::Value::Object(map)) => map
                            .get("memo")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
    }

    fn extract_positive_lamports_to_address(
        result: &RpcTransactionResult,
        address: &str,
    ) -> Option<u64> {
        let meta = result.meta.as_ref()?;
        if meta.err.is_some() {
            return None;
        }

        for (i, key) in result.transaction.message.account_keys.iter().enumerate() {
            if key.pubkey() == address {
                let pre = *meta.pre_balances.get(i)?;
                let post = *meta.post_balances.get(i)?;
                if post > pre {
                    return Some(post - pre);
                }
            }
        }

        None
    }

    fn is_valid_numeric_memo(memo: &str) -> bool {
        !memo.is_empty() && memo.chars().all(|c| c.is_ascii_digit())
    }

    async fn process_new_signatures(&self) -> Result<(), DetectorError> {
        let new_sigs = self.get_new_signatures().await?;
        if new_sigs.is_empty() {
            return Ok(());
        }

        let current_slot = self.get_current_slot().await?;
        let spot_price = match self.price_fetcher.get_price().await {
            Ok(p) => Some(p),
            Err(e) => {
                log::warn!(
                    "[SOL] Failed to fetch price for dust filter (continuing without fiat filter): {e}"
                );
                None
            }
        };

        for sig in &new_sigs {
            let tx = match self.get_transaction(&sig.signature).await {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!("[SOL] Failed to load tx {}: {}", sig.signature, e);
                    continue;
                }
            };

            let Some(amount_lamports) =
                Self::extract_positive_lamports_to_address(&tx, &self.config.deposit_address)
            else {
                self.persist_state(None)?;
                continue;
            };

            let memo = Self::extract_memo(&tx);
            let is_valid = memo
                .as_ref()
                .map(|m| Self::is_valid_numeric_memo(m))
                .unwrap_or(false);

            if !is_valid {
                let mut should_alert = false;
                {
                    let mut state = self.state.lock().unwrap();
                    if !state.invalid_alerted_signatures.contains(&sig.signature) {
                        state
                            .invalid_alerted_signatures
                            .insert(sig.signature.clone());
                        should_alert = true;
                    }
                }

                if should_alert {
                    if let Some(ref discord_url) = self.config.discord_invalid_webhook_url {
                        let memo_display = memo.clone().unwrap_or_else(|| "<absent>".to_string());
                        let content = format!(
                            "🚨 Invalid Solana deposit memo detected\nsignature: {}\naddress: {}\namount_lamports: {}\namount_sol: {:.9}\nmemo: {}",
                            sig.signature,
                            self.config.deposit_address,
                            amount_lamports,
                            amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
                            memo_display,
                        );
                        if let Err(e) =
                            send_discord_webhook(&self.webhook_client, discord_url, &content).await
                        {
                            log::error!("[SOL] Failed to send invalid memo Discord alert: {e}");
                        }
                    }
                }

                self.persist_state(Some(sig.signature.clone()))?;
                continue;
            }

            let memo = memo.unwrap();
            if let Some(price) = spot_price {
                let amount_coin = amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64;
                let fiat_value = amount_coin * price;
                if fiat_value < self.config.min_deposit_fiat {
                    log::info!(
                        "[SOL] Ignoring dust deposit tx={} amount={} SOL (~{:.4} {}) < min {:.2}",
                        sig.signature,
                        amount_coin,
                        fiat_value,
                        self.price_fetcher.currency(),
                        self.config.min_deposit_fiat
                    );
                    self.persist_state(Some(sig.signature.clone()))?;
                    continue;
                }
            }

            let confirmations = current_slot.saturating_sub(tx.slot) + 1;
            let detected = DetectedPayment {
                chain: Chain::Solana,
                ticker: Chain::Solana.ticker().to_string(),
                txid: sig.signature.clone(),
                address: self.config.deposit_address.clone(),
                amount_sat: amount_lamports,
                amount_coin: amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
                confirmations,
                block_height: Some(tx.slot),
                derivation_index: 0,
                memo: Some(memo.clone()),
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
                if !state.pending.iter().any(|p| p.signature == sig.signature)
                    && !state.credited_signatures.contains(&sig.signature)
                {
                    state.pending.push(SolanaPendingPayment {
                        signature: sig.signature.clone(),
                        slot: tx.slot,
                        amount_lamports,
                        memo,
                    });
                }
            }

            self.persist_state(Some(sig.signature.clone()))?;
        }

        Ok(())
    }

    async fn process_credits(&self) -> Result<(), DetectorError> {
        let current_slot = self.get_current_slot().await?;

        let pending = {
            let state = self.state.lock().unwrap();
            state.pending.clone()
        };

        for p in &pending {
            let confirmations = current_slot.saturating_sub(p.slot) + 1;
            if confirmations < self.config.min_confirmations {
                continue;
            }

            let mut credited_payment = DetectedPayment {
                chain: Chain::Solana,
                ticker: Chain::Solana.ticker().to_string(),
                txid: p.signature.clone(),
                address: self.config.deposit_address.clone(),
                amount_sat: p.amount_lamports,
                amount_coin: p.amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
                confirmations,
                block_height: Some(p.slot),
                derivation_index: 0,
                memo: Some(p.memo.clone()),
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
                state.credited_signatures.insert(p.signature.clone());
                state.pending.retain(|x| x.signature != p.signature);
            }

            self.persist_state(None)?;
        }

        Ok(())
    }

    fn persist_state(&self, last_processed_signature: Option<String>) -> Result<(), DetectorError> {
        let state_snapshot = {
            let mut state = self.state.lock().unwrap();
            if let Some(sig) = last_processed_signature {
                state.last_processed_signature = Some(sig);
            }
            state.clone()
        };

        let data = serde_json::to_string_pretty(&state_snapshot)?;
        let tmp_path = format!("{}.tmp", self.config.state_file);
        std::fs::write(&tmp_path, data).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to write state file: {e}"))
        })?;
        std::fs::rename(tmp_path, &self.config.state_file).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to rename state file: {e}"))
        })?;
        Ok(())
    }

    pub async fn run_loop(&self) -> Result<(), DetectorError> {
        let poll = std::time::Duration::from_secs(self.config.poll_interval_secs);
        loop {
            if let Err(e) = self.process_new_signatures().await {
                log::error!("[SOL] process_new_signatures failed: {e}");
            }
            if let Err(e) = self.process_credits().await {
                log::error!("[SOL] process_credits failed: {e}");
            }
            tokio::time::sleep(poll).await;
        }
    }
}

impl PaymentDetector for SolanaDetector {
    fn derive_address(&self, _index: u32) -> Result<String, DetectorError> {
        Ok(self.config.deposit_address.clone())
    }

    async fn scan_block(
        &self,
        _block_height: u64,
        _max_derivation_index: u32,
    ) -> Result<Vec<DetectedPayment>, DetectorError> {
        Ok(Vec::new())
    }

    async fn run_block_scan_loop(
        &self,
        _start_height: Option<u64>,
        _max_derivation_index: u32,
    ) -> Result<(), DetectorError> {
        self.run_loop().await
    }
}

fn load_solana_state(path: &str) -> Result<SolanaState, DetectorError> {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return Ok(SolanaState::default());
    }

    let data = std::fs::read_to_string(p)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to read state file: {e}")))?;
    let state: SolanaState = serde_json::from_str(&data)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to parse state file: {e}")))?;

    Ok(state)
}
