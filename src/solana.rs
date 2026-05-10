use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use solana_sdk::hash::Hash;
use solana_sdk::instruction::Instruction;
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use solana_system_interface::instruction as system_instruction;

use crate::env_utils::redact_url_credentials;
use crate::error::DetectorError;
use crate::pricing::PriceFetcher;
use crate::solana_pool::{
    ManagedSolanaWallet, SharedSolanaWallets, SolanaReservation, find_wallet,
    load_active_reservations, load_assignment_for_address, load_assignment_for_user,
    snapshot_wallets,
};
use crate::solana_tokens::{
    SplTokenConfig, create_associated_token_account_idempotent_instruction,
    derive_associated_token_address, spl_transfer_checked_instruction,
};
use crate::recover::{RecoverResponse, RecoverStatus};
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
    pub gas_tank_private_key: Option<String>,
    pub gas_tank_target_usd: f64,
    pub gas_tank_check_interval_secs: u64,
    pub max_fee_ratio: f64,
    /// Internal URL of the autoshop backend, used to commit scheduled-SOL
    /// payment status updates. Feature is disabled when either this or
    /// `internal_service_token` is empty.
    pub core_api_url: Option<String>,
    /// Shared secret for the backend's `x-internal-service-token` header.
    pub internal_service_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SolanaPendingPayment {
    signature: String,
    slot: u64,
    amount_base_units: u64,
    address: String,
    user_id: String,
    wallet_index: u32,
    #[serde(default)]
    asset: Option<String>,
    #[serde(default)]
    asset_decimals: Option<u8>,
    #[serde(default)]
    token_mint: Option<String>,
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
    /// Legacy, signature-only credit ledger. Kept readable for state-file
    /// backward compatibility but no longer written to and not consulted
    /// by dedup checks: it conflated `(signature)` with `(signature,
    /// address, asset)` and silently dropped the second deposit when a
    /// single tx (e.g. Binance batch sends) credited two of our managed
    /// addresses. New credits go to `credited_payments` below, keyed by
    /// the composite tuple.
    #[serde(default)]
    credited_signatures: HashSet<String>,
    /// Per-deposit credit ledger keyed by `payment_key(sig, addr, asset)`.
    /// Multiple distinct entries can exist for the same signature when a
    /// transaction deposits to several of our addresses.
    #[serde(default)]
    credited_payments: HashSet<String>,
    #[serde(default)]
    gas_tank_last_maintenance_unix: Option<i64>,
}

/// Composite key uniquely identifying a single deposit. Two deposits in
/// the same Solana transaction (e.g. a Binance batch send hitting two of
/// our managed wallets) collide on `signature` but differ on `address` —
/// keying the dedup ledgers on the full tuple keeps both visible.
///
/// `asset == None` is the native SOL channel; tokens pass their SPL
/// symbol. We pin the native sentinel to "SOL" so a tx containing both
/// native and token transfers to the same address still produces two
/// distinct keys.
fn payment_key(signature: &str, address: &str, asset: Option<&str>) -> String {
    format!("{}|{}|{}", signature, address, asset.unwrap_or("SOL"))
}

#[derive(Debug, Clone)]
struct SignatureInfo {
    signature: String,
}

#[derive(Debug, Clone)]
struct SweepResult {
    amount_base_units: u64,
    txid: Option<String>,
    deferred: bool,
}

#[derive(Debug)]
pub struct SolanaDetector {
    config: SolanaConfig,
    wallets: SharedSolanaWallets,
    tokens: Vec<SplTokenConfig>,
    gas_tank_keypair: Option<Arc<Keypair>>,
    gas_tank_pubkey: Option<Pubkey>,
    ledger_pubkey: Pubkey,
    rpc_client: reqwest::Client,
    webhook_client: reqwest::Client,
    price_fetcher: PriceFetcher,
    sol_usd_fetcher: PriceFetcher,
    sol_eur_fetcher: PriceFetcher,
    state: Arc<Mutex<SolanaState>>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
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
    #[serde(default, rename = "preTokenBalances")]
    pre_token_balances: Vec<RpcTokenBalance>,
    #[serde(default, rename = "postTokenBalances")]
    post_token_balances: Vec<RpcTokenBalance>,
    #[serde(default, rename = "loadedAddresses")]
    loaded_addresses: Option<RpcLoadedAddresses>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RpcLoadedAddresses {
    #[serde(default)]
    writable: Vec<String>,
    #[serde(default)]
    readonly: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct RpcTokenBalance {
    #[serde(rename = "accountIndex")]
    account_index: u32,
    mint: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(rename = "uiTokenAmount")]
    ui_token_amount: RpcUiTokenAmount,
}

#[derive(Debug, Deserialize, Clone)]
struct RpcUiTokenAmount {
    amount: String,
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

fn compact_error_body(body: &str) -> String {
    let compact = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let truncated: String = chars.by_ref().take(300).collect();

    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn describe_reqwest_error(context: &str, error: &reqwest::Error) -> String {
    let mut labels = Vec::new();
    if error.is_timeout() {
        labels.push("timeout");
    }
    if error.is_connect() {
        labels.push("connect");
    }
    if error.is_request() {
        labels.push("request");
    }
    if error.is_body() {
        labels.push("body");
    }
    if error.is_decode() {
        labels.push("decode");
    }
    if error.is_status() {
        labels.push("status");
    }

    let label = if labels.is_empty() {
        String::new()
    } else {
        format!(" ({})", labels.join(", "))
    };
    let mut message = format!("{context}{label}: {error}");

    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str("; caused by: ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }

    message
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
    pub fn new(
        config: SolanaConfig,
        tokens: Vec<SplTokenConfig>,
        wallets: SharedSolanaWallets,
    ) -> Result<Self, DetectorError> {
        if config.secure_deposit_address.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "SOLANA_DEPOSIT_ADDRESS is required".into(),
            ));
        }
        let ledger_pubkey =
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

        let gas_tank_keypair = match config.gas_tank_private_key.as_deref() {
            Some(value) if !value.trim().is_empty() => {
                Some(Arc::new(parse_solana_keypair(value.trim()).map_err(|e| {
                    DetectorError::InvalidConfig(format!(
                        "Invalid SOLANA_GAS_TANK_PRIVATE_KEY: {e}"
                    ))
                })?))
            }
            _ => None,
        };
        let gas_tank_pubkey = gas_tank_keypair.as_ref().map(|kp| kp.pubkey());

        if let Some(gas_tank) = gas_tank_pubkey {
            if gas_tank == ledger_pubkey {
                log::warn!(
                    "[SOL] SOLANA_GAS_TANK_PRIVATE_KEY pubkey {} matches SOLANA_DEPOSIT_ADDRESS; \
                     funds will accumulate on the same wallet that pays fees (use distinct wallets to keep cold storage segregated)",
                    gas_tank
                );
            } else {
                log::info!(
                    "[SOL] Gas tank wallet: {} (target ${:.2}) - excess swept to ledger {}",
                    gas_tank,
                    config.gas_tank_target_usd,
                    ledger_pubkey
                );
            }
        }

        if !tokens.is_empty() && gas_tank_keypair.is_none() {
            log::warn!(
                "[SOL] {} SPL token(s) configured but SOLANA_GAS_TANK_PRIVATE_KEY is not set; \
                 token detection will work but token sweeps will fail unless managed wallets hold SOL",
                tokens.len()
            );
        }

        let mut rpc_builder = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .connection_verbose(false);
        if let Some(ref proxy_url) = config.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| DetectorError::InvalidConfig(format!("Invalid proxy URL: {e}")))?;
            rpc_builder = rpc_builder.proxy(proxy);
            log::info!("[SOL] Using proxy: {}", redact_url_credentials(proxy_url));
        } else {
            rpc_builder = rpc_builder.no_proxy();
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
            sol_usd_fetcher: PriceFetcher::new(webhook_client.clone(), "USD", Chain::Solana),
            sol_eur_fetcher: PriceFetcher::new(webhook_client.clone(), "EUR", Chain::Solana),
            config,
            wallets,
            tokens,
            gas_tank_keypair,
            gas_tank_pubkey,
            ledger_pubkey,
            rpc_client,
            webhook_client,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn wallet_count(&self) -> usize {
        self.wallets.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub fn token_summary(&self) -> Vec<(String, String, u8)> {
        self.tokens
            .iter()
            .map(|t| (t.symbol.clone(), t.mint.to_string(), t.decimals))
            .collect()
    }

    pub fn gas_tank_address(&self) -> Option<String> {
        self.gas_tank_pubkey.map(|pk| pk.to_string())
    }

    pub fn ledger_address(&self) -> String {
        self.ledger_pubkey.to_string()
    }

    fn ata_for_wallet(&self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        derive_associated_token_address(owner, mint)
    }

    /// Manually scan + sweep + credit deposits for a single user's assigned
    /// Solana address. Triggered by the `/solana/claim` HTTP endpoint when
    /// the user clicks "I deposited" on the frontend. Returns the address
    /// that was scanned. The webhook (`payment_detected` then
    /// `payment_credited`) is fired by the underlying scan/credit pipeline.
    pub async fn claim_for_user(&self, user_id: &str) -> Result<String, DetectorError> {
        let assignment = load_assignment_for_user(&self.config.redis_url, user_id)
            .await?
            .ok_or_else(|| {
                DetectorError::InvalidConfig(format!(
                    "No Solana deposit address assigned to user_id={user_id} - call /solana/address first"
                ))
            })?;

        let address = assignment.address.clone();
        log::info!(
            "[SOL] /claim triggered for user_id={} address={}",
            user_id,
            address
        );

        let current_slot = self.get_current_slot().await?;
        let spot_price = match self.price_fetcher.get_price().await {
            Ok(price) => Some(price),
            Err(error) => {
                log::warn!(
                    "[SOL] /claim: failed to fetch spot price (continuing without fiat dust filter): {error}"
                );
                None
            }
        };

        self.process_reservation(&assignment, current_slot, spot_price)
            .await?;
        self.process_credits(current_slot).await?;

        Ok(address)
    }

    /// Cheap retry tick for pending-but-not-yet-credited payments.
    ///
    /// Unlike `process_cycle`, this does **not** scan any address — it
    /// only iterates the in-memory `pending` queue and retries the sweep
    /// + credit step. Useful as a fast-cadence loop (e.g. every 30 s)
    /// alongside the slow full-scan loop (e.g. every 30 min):
    ///
    /// - A Helius webhook normally adds an entry to `pending` and credits
    ///   it within a single push. Most deposits are done in <10 s.
    /// - When the credit step inside the Helius handler fails (RPC 429
    ///   on `getLatestBlockhash`, fee guard deferred, transient sweep
    ///   error), the pending entry stays. Without this loop it would
    ///   wait for either another Helius push from any user OR the
    ///   30-minute polling cycle to retry — both unbounded in the worst
    ///   case.
    ///
    /// When the pending queue is empty this is a no-op (one cheap mutex
    /// read, no RPC calls). Returns the number of entries that were
    /// queued for processing.
    pub async fn confirm_pending_payments(&self) -> Result<usize, DetectorError> {
        let pending_count = {
            let state = self.state.lock().unwrap();
            state.pending.len()
        };
        if pending_count == 0 {
            return Ok(0);
        }
        let current_slot = self.get_current_slot().await?;
        self.process_credits(current_slot).await?;
        Ok(pending_count)
    }

    /// For each assignment in Redis whose owner address or any of its
    /// monitored SPL token ATAs is contained in `candidate_addresses`, run
    /// `process_reservation` (native + token scans) immediately, then run
    /// `process_credits` once. Used by the `/solana/webhook` route to react
    /// to a Helius push without waiting for the next polling cycle.
    /// Returns the list of owner addresses that were scanned.
    pub async fn process_address_set_now(
        &self,
        candidate_addresses: &std::collections::HashSet<String>,
    ) -> Result<Vec<String>, DetectorError> {
        if candidate_addresses.is_empty() {
            return Ok(Vec::new());
        }

        let assignments = load_active_reservations(&self.config.redis_url).await?;
        let mut to_scan: Vec<SolanaReservation> = Vec::new();
        for assignment in &assignments {
            if candidate_addresses.contains(&assignment.address) {
                to_scan.push(assignment.clone());
                continue;
            }
            // Also match if the candidate set contains any ATA derived
            // from this owner for one of our monitored mints.
            let owner = match Pubkey::from_str(&assignment.address) {
                Ok(pk) => pk,
                Err(_) => continue,
            };
            for token in &self.tokens {
                let ata = self.ata_for_wallet(&owner, &token.mint).to_string();
                if candidate_addresses.contains(&ata) {
                    to_scan.push(assignment.clone());
                    break;
                }
            }
        }

        if to_scan.is_empty() {
            return Ok(Vec::new());
        }

        let current_slot = self.get_current_slot().await?;
        let spot_price = self.price_fetcher.get_price().await.ok();

        let mut scanned = Vec::with_capacity(to_scan.len());
        for assignment in to_scan {
            let address = assignment.address.clone();
            if let Err(error) = self
                .process_reservation(&assignment, current_slot, spot_price)
                .await
            {
                // Don't abort the whole webhook on one address failing —
                // the polling fallback will pick it up. Just log and skip.
                log::warn!(
                    "[SOL] Webhook-triggered scan failed for {address}: {error}"
                );
                continue;
            }
            scanned.push(address);
        }

        self.process_credits(current_slot).await?;
        Ok(scanned)
    }

    /// Returns the full set of addresses that should be watched on the
    /// Helius webhook for the current wallet pool: every owner address
    /// plus every ATA derived from each owner for each configured SPL
    /// token. Used to bootstrap and reconcile the webhook config.
    pub fn webhook_address_set(&self) -> Vec<String> {
        let wallets = snapshot_wallets(&self.wallets);
        let mut out = Vec::with_capacity(wallets.len() * (1 + self.tokens.len()));
        for wallet in &wallets {
            out.push(wallet.address.clone());
            if let Ok(owner) = Pubkey::from_str(&wallet.address) {
                for token in &self.tokens {
                    out.push(self.ata_for_wallet(&owner, &token.mint).to_string());
                }
            }
        }
        out
    }

    /// Returns the addresses to register on the Helius webhook for a
    /// single newly assigned wallet: the owner address plus its ATA for
    /// each configured SPL token.
    pub fn webhook_addresses_for_wallet(&self, wallet_address: &str) -> Vec<String> {
        let mut out = vec![wallet_address.to_string()];
        if let Ok(owner) = Pubkey::from_str(wallet_address) {
            for token in &self.tokens {
                out.push(self.ata_for_wallet(&owner, &token.mint).to_string());
            }
        }
        out
    }

    async fn process_cycle(&self) -> Result<(), DetectorError> {
        let cycle_start = std::time::Instant::now();
        let reservations = load_active_reservations(&self.config.redis_url).await?;
        let reservations_loaded_at = cycle_start.elapsed();
        log::info!(
            "[SOL] process_cycle: starting scan of {} reservation(s) ({} SPL token(s) per wallet)",
            reservations.len(),
            self.tokens.len()
        );
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

        // Catch per-reservation errors so a single rate-limited 429 (or any
        // other transient RPC failure) doesn't abort the whole cycle and
        // — critically — doesn't prevent `process_credits` from running.
        // Pending payments would otherwise stay un-credited indefinitely
        // because the cycle never reaches the credit step. Each failure is
        // logged at WARN; the next cycle retries the same reservations.
        let scan_start = std::time::Instant::now();
        let mut failed_scans: usize = 0;
        for reservation in &reservations {
            if let Err(error) = self
                .process_reservation(reservation, current_slot, spot_price)
                .await
            {
                failed_scans += 1;
                log::warn!(
                    "[SOL] process_cycle: scan failed for {} (will retry next cycle): {error}",
                    reservation.address
                );
            }
        }
        let scan_elapsed = scan_start.elapsed();
        if failed_scans > 0 {
            log::warn!(
                "[SOL] process_cycle: {}/{} reservation scan(s) failed this cycle - proceeding to process_credits anyway",
                failed_scans,
                reservations.len()
            );
        }

        // Don't propagate process_credits errors either - just log and let
        // the next cycle (or the Helius webhook path) retry. Returning Err
        // here would skip gas tank maintenance for no good reason.
        let credits_start = std::time::Instant::now();
        if let Err(error) = self.process_credits(current_slot).await {
            log::warn!(
                "[SOL] process_cycle: process_credits errored (will retry next cycle): {error}"
            );
        }
        let credits_elapsed = credits_start.elapsed();

        self.maybe_maintain_gas_tank().await?;
        let total_elapsed = cycle_start.elapsed();

        // One concise summary line so the operator can spot slow cycles
        // without grepping. Per-address RTT = scan_elapsed / reservations,
        // useful for sanity-checking against the configured RPC.
        let avg_per_addr_ms = if reservations.is_empty() {
            0.0
        } else {
            scan_elapsed.as_secs_f64() * 1000.0 / reservations.len() as f64
        };
        log::info!(
            "[SOL] process_cycle: done in {:.2}s (load_reservations={:.2}s, scan_loop={:.2}s for {} addr {:.0}ms/addr avg, process_credits={:.2}s, failed_scans={})",
            total_elapsed.as_secs_f64(),
            reservations_loaded_at.as_secs_f64(),
            scan_elapsed.as_secs_f64(),
            reservations.len(),
            avg_per_addr_ms,
            credits_elapsed.as_secs_f64(),
            failed_scans,
        );

        Ok(())
    }

    async fn maybe_maintain_gas_tank(&self) -> Result<(), DetectorError> {
        let Some(gas_tank_pubkey) = self.gas_tank_pubkey else {
            return Ok(());
        };
        if gas_tank_pubkey == self.ledger_pubkey {
            return Ok(());
        }
        if !self.config.gas_tank_target_usd.is_finite()
            || self.config.gas_tank_target_usd <= 0.0
        {
            return Ok(());
        }

        let now = unix_timestamp();
        let interval = i64::try_from(self.config.gas_tank_check_interval_secs.max(1))
            .unwrap_or(i64::MAX);
        let should_run = {
            let state = self.state.lock().unwrap();
            state
                .gas_tank_last_maintenance_unix
                .map_or(true, |last| now.saturating_sub(last) >= interval)
        };
        if !should_run {
            return Ok(());
        }

        if let Err(error) = self.maintain_gas_tank(gas_tank_pubkey).await {
            log::warn!("[SOL] Gas tank maintenance failed: {error}");
        }

        {
            let mut state = self.state.lock().unwrap();
            state.gas_tank_last_maintenance_unix = Some(now);
        }
        self.persist_state()
    }

    async fn maintain_gas_tank(&self, gas_tank_pubkey: Pubkey) -> Result<(), DetectorError> {
        let sol_usd = match self.sol_usd_fetcher.get_price().await {
            Ok(price) if price > 0.0 => price,
            Ok(price) => {
                log::warn!("[SOL] Ignoring invalid SOL/USD price {}", price);
                return Ok(());
            }
            Err(error) => {
                log::warn!("[SOL] Failed to fetch SOL/USD for gas tank maintenance: {error}");
                return Ok(());
            }
        };

        let target_lamports =
            usd_to_lamports(self.config.gas_tank_target_usd, sol_usd).unwrap_or(0);
        if target_lamports == 0 {
            return Ok(());
        }

        let balance = self.get_balance(&gas_tank_pubkey.to_string()).await?;
        if balance < target_lamports {
            log::warn!(
                "[SOL] Gas tank balance {} lamports below target {} lamports (~${:.2}); top up the gas tank to keep token sweeps running",
                balance,
                target_lamports,
                self.config.gas_tank_target_usd
            );
            return Ok(());
        }

        // Check for an admin-scheduled outbound payment. If one exists and is
        // not yet expired, divert the excess sweep to that destination
        // instead of the ledger. We process a single payment per maintenance
        // tick to keep the logic predictable; multi-payment queues fulfill
        // one payment at a time, oldest first.
        match self.try_fulfill_scheduled_payment(
            gas_tank_pubkey,
            balance,
            target_lamports,
            sol_usd,
        )
        .await
        {
            ScheduledOutcome::Sent => return Ok(()),
            ScheduledOutcome::WaitingForFunds => {
                // A payment is scheduled but the gas tank doesn't yet hold
                // enough lamports to cover both the buffer and the requested
                // amount. Skip the ledger sweep so funds keep accumulating.
                return Ok(());
            }
            ScheduledOutcome::None => {}
        }

        let recent_blockhash = self.get_latest_blockhash().await?;
        let gas_tank = self
            .gas_tank_keypair
            .as_ref()
            .ok_or_else(|| DetectorError::InvalidConfig("Gas tank keypair missing".into()))?;
        let fee = self
            .estimate_native_transfer_fee(gas_tank.as_ref(), &self.ledger_pubkey, recent_blockhash)
            .await?;

        if balance <= target_lamports + fee {
            return Ok(());
        }
        let excess = balance - target_lamports - fee;
        if excess == 0 {
            return Ok(());
        }

        let tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &gas_tank_pubkey,
                &self.ledger_pubkey,
                excess,
            )],
            Some(&gas_tank_pubkey),
            &[gas_tank.as_ref()],
            recent_blockhash,
        );

        let txid = self.send_solana_transaction(&tx).await?;
        log::info!(
            "[SOL] Gas tank excess sweep: {} lamports ({:.9} SOL) to ledger {} (kept ~${:.2}, tx={})",
            excess,
            excess as f64 / Chain::Solana.sats_per_unit() as f64,
            self.ledger_pubkey,
            self.config.gas_tank_target_usd,
            txid
        );

        Ok(())
    }

    /// Drains pending scheduled SOL payments from Redis. Tries the oldest
    /// payment first; only one is sent per maintenance tick. Returns
    /// `Sent` when a payment fired (or terminally failed and was reported),
    /// `WaitingForFunds` when a pending payment exists but the balance is
    /// not yet sufficient (caller must skip the ledger sweep), or `None`
    /// when no pending payments exist (caller proceeds with normal sweep).
    async fn try_fulfill_scheduled_payment(
        &self,
        gas_tank_pubkey: Pubkey,
        balance: u64,
        target_lamports: u64,
        sol_usd: f64,
    ) -> ScheduledOutcome {
        let (Some(core_api_url), Some(internal_token)) = (
            self.config.core_api_url.as_deref(),
            self.config.internal_service_token.as_deref(),
        ) else {
            return ScheduledOutcome::None;
        };

        let pending = match crate::solana_scheduled::load_pending_scheduled_payments(
            &self.config.redis_url,
        )
        .await
        {
            Ok(list) => list,
            Err(error) => {
                log::warn!(
                    "[SOL][SCHED] Failed to load pending scheduled payments: {error}"
                );
                return ScheduledOutcome::None;
            }
        };
        if pending.is_empty() {
            return ScheduledOutcome::None;
        }

        let now_unix = unix_timestamp();
        let candidate = pending
            .into_iter()
            .find(|payment| payment.expires_at_unix > now_unix);
        let Some(payment) = candidate else {
            // All pending payments are past their expiry. The backend's
            // list endpoint will mark them expired the next time an admin
            // looks at them; nothing to do here.
            return ScheduledOutcome::None;
        };

        let amount_lamports = match payment_amount_lamports(&payment, sol_usd, &self.sol_eur_fetcher).await {
            Ok(value) => value,
            Err(reason) => {
                log::warn!(
                    "[SOL][SCHED] Payment {} has invalid amount/currency ({}); marking failed",
                    payment.id,
                    reason
                );
                crate::solana_scheduled::notify_payment_failed(
                    &self.webhook_client,
                    core_api_url,
                    internal_token,
                    payment.id,
                    &reason,
                )
                .await;
                return ScheduledOutcome::Sent;
            }
        };
        if amount_lamports == 0 {
            crate::solana_scheduled::notify_payment_failed(
                &self.webhook_client,
                core_api_url,
                internal_token,
                payment.id,
                "Resolved amount is zero lamports",
            )
            .await;
            return ScheduledOutcome::Sent;
        }

        let destination = match Pubkey::from_str(&payment.destination_address) {
            Ok(pubkey) => pubkey,
            Err(error) => {
                let reason = format!("Invalid destination address: {error}");
                log::warn!(
                    "[SOL][SCHED] Payment {} has invalid destination '{}'; marking failed",
                    payment.id,
                    payment.destination_address
                );
                crate::solana_scheduled::notify_payment_failed(
                    &self.webhook_client,
                    core_api_url,
                    internal_token,
                    payment.id,
                    &reason,
                )
                .await;
                return ScheduledOutcome::Sent;
            }
        };

        let recent_blockhash = match self.get_latest_blockhash().await {
            Ok(value) => value,
            Err(error) => {
                log::warn!("[SOL][SCHED] Failed to fetch blockhash: {error}");
                return ScheduledOutcome::WaitingForFunds;
            }
        };
        let Some(gas_tank) = self.gas_tank_keypair.as_ref() else {
            return ScheduledOutcome::None;
        };
        let fee = match self
            .estimate_native_transfer_fee(gas_tank.as_ref(), &destination, recent_blockhash)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                log::warn!("[SOL][SCHED] Failed to estimate fee: {error}");
                return ScheduledOutcome::WaitingForFunds;
            }
        };

        // Keep the gas-tank fee buffer intact: only fire when the balance
        // covers the requested amount AND the buffer AND the network fee.
        let required = target_lamports.saturating_add(amount_lamports).saturating_add(fee);
        if balance < required {
            log::info!(
                "[SOL][SCHED] Payment {} waiting: balance {} < required {} (target_buffer={} amount={} fee={})",
                payment.id,
                balance,
                required,
                target_lamports,
                amount_lamports,
                fee
            );
            return ScheduledOutcome::WaitingForFunds;
        }

        let tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &gas_tank_pubkey,
                &destination,
                amount_lamports,
            )],
            Some(&gas_tank_pubkey),
            &[gas_tank.as_ref()],
            recent_blockhash,
        );

        let txid = match self.send_solana_transaction(&tx).await {
            Ok(value) => value,
            Err(error) => {
                log::warn!(
                    "[SOL][SCHED] Failed to send scheduled payment {}: {error}",
                    payment.id
                );
                // Treat as waiting; the next tick will retry.
                return ScheduledOutcome::WaitingForFunds;
            }
        };

        log::warn!(
            "[SOL][SCHED] Sent scheduled payment {}: {} lamports ({:.9} SOL) to {} (tx={})",
            payment.id,
            amount_lamports,
            amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
            destination,
            txid
        );

        let lamports_i64 = amount_lamports.min(i64::MAX as u64) as i64;
        crate::solana_scheduled::notify_payment_sent(
            &self.webhook_client,
            core_api_url,
            internal_token,
            payment.id,
            &txid,
            lamports_i64,
        )
        .await;

        ScheduledOutcome::Sent
    }

    async fn estimate_native_transfer_fee(
        &self,
        from_keypair: &Keypair,
        destination: &Pubkey,
        recent_blockhash: Hash,
    ) -> Result<u64, DetectorError> {
        let from = from_keypair.pubkey();
        let message = Message::new_with_blockhash(
            &[system_instruction::transfer(&from, destination, 1)],
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
                    {"commitment": "confirmed"}
                ]),
            )
            .await?;
        Ok(fee_result.value.unwrap_or(5_000))
    }

    async fn process_reservation(
        &self,
        reservation: &SolanaReservation,
        current_slot: u64,
        spot_price: Option<f64>,
    ) -> Result<(), DetectorError> {
        self.process_native_for_reservation(reservation, current_slot, spot_price)
            .await?;

        let owner = match Pubkey::from_str(&reservation.address) {
            Ok(owner) => owner,
            Err(error) => {
                log::warn!(
                    "[SOL] Skipping token scan for invalid reservation address '{}': {error}",
                    reservation.address
                );
                return Ok(());
            }
        };

        let tokens = self.tokens.clone();
        for token in &tokens {
            self.process_token_for_reservation(reservation, &owner, token, current_slot)
                .await?;
        }

        Ok(())
    }

    async fn process_native_for_reservation(
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
            let dedup_key = payment_key(&sig.signature, &reservation.address, None);
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
                // Composite event_id makes the backend's idempotency lock
                // per-(sig, addr, asset) instead of per-sig: two deposits
                // in the same tx will produce two distinct credit rows.
                event_id: Some(dedup_key.clone()),
                log_index: None,
                asset: None,
                asset_decimals: None,
                amount_base_units: None,
                swept_amount_base_units: None,
                token_contract: None,
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
                let already_pending = state.pending.iter().any(|p| {
                    p.signature == sig.signature
                        && p.address == reservation.address
                        && p.asset.is_none()
                });
                let already_credited = state.credited_payments.contains(&dedup_key);

                if !already_pending && !already_credited {
                    state.pending.push(SolanaPendingPayment {
                        signature: sig.signature.clone(),
                        slot: tx.slot,
                        amount_base_units: amount_lamports,
                        address: reservation.address.clone(),
                        user_id: reservation.user_id.clone(),
                        wallet_index: reservation.wallet_index,
                        asset: None,
                        asset_decimals: None,
                        token_mint: None,
                    });
                }
            }

            self.update_last_processed_signature(&reservation.address, &sig.signature)?;
        }

        Ok(())
    }

    async fn process_token_for_reservation(
        &self,
        reservation: &SolanaReservation,
        owner: &Pubkey,
        token: &SplTokenConfig,
        current_slot: u64,
    ) -> Result<(), DetectorError> {
        let ata = self.ata_for_wallet(owner, &token.mint);
        let ata_string = ata.to_string();

        log::debug!(
            "[SOL] Scanning {} ATA {} for reservation {} (mint={})",
            token.symbol, ata_string, reservation.address, token.mint
        );

        let new_signatures = self.get_new_signatures(&ata_string).await?;
        if new_signatures.is_empty() {
            return Ok(());
        }

        log::info!(
            "[SOL] Found {} new {} signature(s) on ATA {} (owner={})",
            new_signatures.len(),
            token.symbol,
            ata_string,
            reservation.address
        );

        let mint_string = token.mint.to_string();
        let owner_string = owner.to_string();

        for sig in &new_signatures {
            let tx = match self.get_transaction(&sig.signature).await {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!("[SOL] Failed to load token tx {}: {}", sig.signature, e);
                    continue;
                }
            };

            let Some(amount_base_units) = Self::extract_positive_token_amount(
                &tx,
                &owner_string,
                &mint_string,
                &ata_string,
            ) else {
                log::info!(
                    "[SOL] {} tx {} on ata {} produced no positive balance change for owner {} (likely outgoing transfer or zero-amount)",
                    token.symbol, sig.signature, ata_string, owner_string
                );
                self.update_last_processed_signature(&ata_string, &sig.signature)?;
                continue;
            };

            let amount_coin = amount_base_units as f64 / 10f64.powi(i32::from(token.decimals));
            if is_fiat_pegged_token(&token.symbol)
                && self.config.min_deposit_fiat > 0.0
                && amount_coin > 0.0
            {
                if let Some(rate) = self.token_to_configured_fiat_rate(&token.symbol).await {
                    let fiat_value = amount_coin * rate;
                    if fiat_value < self.config.min_deposit_fiat {
                        log::info!(
                            "[SOL] Ignoring dust {} deposit tx={} ata={} amount={} (~{:.4} {}) < min {:.2}",
                            token.symbol,
                            sig.signature,
                            ata_string,
                            amount_coin,
                            fiat_value,
                            self.price_fetcher.currency(),
                            self.config.min_deposit_fiat
                        );
                        self.update_last_processed_signature(&ata_string, &sig.signature)?;
                        continue;
                    }
                }
            }

            let confirmations = current_slot.saturating_sub(tx.slot) + 1;
            let dedup_key = payment_key(
                &sig.signature,
                &reservation.address,
                Some(token.symbol.as_str()),
            );
            let detected = DetectedPayment {
                chain: Chain::Solana,
                ticker: token.symbol.clone(),
                txid: sig.signature.clone(),
                address: reservation.address.clone(),
                user_id: Some(reservation.user_id.clone()),
                amount_sat: amount_base_units,
                amount_coin,
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
                event_id: Some(dedup_key.clone()),
                log_index: None,
                asset: Some(token.symbol.clone()),
                asset_decimals: Some(token.decimals),
                amount_base_units: Some(amount_base_units.to_string()),
                swept_amount_base_units: None,
                token_contract: Some(mint_string.clone()),
            };

            send_webhook(
                &self.webhook_client,
                &self.config.webhook_url,
                &self.config.webhook_hmac_secret,
                &WebhookEvent::PaymentDetected(detected),
            )
            .await?;

            {
                let mut state = self.state.lock().unwrap();
                let already_pending = state.pending.iter().any(|p| {
                    p.signature == sig.signature
                        && p.address == reservation.address
                        && p.asset.as_deref() == Some(token.symbol.as_str())
                });
                let already_credited = state.credited_payments.contains(&dedup_key);

                if !already_pending && !already_credited {
                    state.pending.push(SolanaPendingPayment {
                        signature: sig.signature.clone(),
                        slot: tx.slot,
                        amount_base_units,
                        address: reservation.address.clone(),
                        user_id: reservation.user_id.clone(),
                        wallet_index: reservation.wallet_index,
                        asset: Some(token.symbol.clone()),
                        asset_decimals: Some(token.decimals),
                        token_mint: Some(mint_string.clone()),
                    });
                }
            }

            self.update_last_processed_signature(&ata_string, &sig.signature)?;
        }

        Ok(())
    }

    async fn process_credits(&self, current_slot: u64) -> Result<(), DetectorError> {
        let pending = {
            let state = self.state.lock().unwrap();
            state.pending.clone()
        };

        // Process each pending entry independently. A failure on one
        // (e.g. RPC 429 during sweep, transient blockhash fetch error)
        // must NOT skip the rest — otherwise a single stuck entry blocks
        // every subsequent credit forever. Errors are logged WARN and
        // the entry stays in `pending` so the next cycle retries it.
        for entry in pending {
            let signature = entry.signature.clone();
            let address = entry.address.clone();
            if let Err(error) = self.process_credit_entry(entry, current_slot).await {
                log::warn!(
                    "[SOL] process_credits: failed to credit signature {} (address {}, will retry next cycle): {error}",
                    signature,
                    address
                );
            }
        }
        Ok(())
    }

    async fn process_credit_entry(
        &self,
        entry: SolanaPendingPayment,
        current_slot: u64,
    ) -> Result<(), DetectorError> {
        {
            let confirmations = current_slot.saturating_sub(entry.slot) + 1;
            if confirmations < self.config.min_confirmations {
                return Ok(());
            }

            let entry_dedup_key =
                payment_key(&entry.signature, &entry.address, entry.asset.as_deref());
            let already_credited = {
                let state = self.state.lock().unwrap();
                state.credited_payments.contains(&entry_dedup_key)
            };

            // Defense-in-depth: before crediting (and especially before
            // sweeping the user's funds out of the managed wallet), make
            // sure the address still belongs to the user_id captured at
            // detection time. If the assignment was rewritten (admin
            // cancel-all + reclaim, manual Redis edit, etc.) we'd be
            // about to credit the wrong user. We refuse to credit and
            // keep the entry in pending for manual review — the funds
            // stay safe on the managed wallet because the sweep call
            // happens *after* this check.
            if !already_credited {
                match load_assignment_for_address(&self.config.redis_url, &entry.address).await {
                    Ok(Some(current)) if current.user_id != entry.user_id => {
                        log::error!(
                            "[SOL][SECURITY] Refusing to credit signature {} for address {}: \
                             pending entry user_id={} but Redis now says user_id={} (dormant={}). \
                             Keeping entry pending for manual review.",
                            entry.signature,
                            entry.address,
                            entry.user_id,
                            current.user_id,
                            current.dormant
                        );
                        return Ok(());
                    }
                    Ok(None) => {
                        log::warn!(
                            "[SOL] No current Redis assignment for address {} when crediting \
                             signature {} (pending user_id={}); proceeding with pending entry's \
                             user_id since the depositor's intent was captured at detection time.",
                            entry.address,
                            entry.signature,
                            entry.user_id,
                        );
                    }
                    Ok(Some(_)) => {
                        // owner matches — proceed normally
                    }
                    Err(error) => {
                        log::warn!(
                            "[SOL] Failed to verify Redis assignment for {} before credit \
                             (continuing): {error}",
                            entry.address
                        );
                    }
                }
            }

            let payment_and_deferred: Option<(DetectedPayment, bool)> = match entry.asset.as_deref() {
                None => {
                    let sweep_result = self.sweep_native_sol_from_address(&entry.address).await?;
                    let was_deferred = sweep_result.deferred;
                    if was_deferred {
                        if already_credited {
                            log::info!(
                                "[SOL] Native sweep retry deferred for already-credited {} (signature {})",
                                entry.address, entry.signature
                            );
                        } else {
                            log::info!(
                                "[SOL] Crediting {} immediately (funds on managed wallet); native sweep deferred and will retry next cycle (signature {})",
                                entry.address, entry.signature
                            );
                        }
                    }
                    let amount_coin =
                        entry.amount_base_units as f64 / Chain::Solana.sats_per_unit() as f64;
                    let mut payment = DetectedPayment {
                        chain: Chain::Solana,
                        ticker: Chain::Solana.ticker().to_string(),
                        txid: entry.signature.clone(),
                        address: entry.address.clone(),
                        user_id: Some(entry.user_id.clone()),
                        amount_sat: entry.amount_base_units,
                        amount_coin,
                        confirmations,
                        block_height: Some(entry.slot),
                        derivation_index: entry.wallet_index,
                        memo: None,
                        swept_to_address: if was_deferred {
                            None
                        } else {
                            Some(self.sol_native_sweep_destination().to_string())
                        },
                        swept_amount_sat: if was_deferred {
                            None
                        } else {
                            Some(sweep_result.amount_base_units)
                        },
                        swept_amount_coin: if was_deferred {
                            None
                        } else {
                            Some(
                                sweep_result.amount_base_units as f64
                                    / Chain::Solana.sats_per_unit() as f64,
                            )
                        },
                        sweep_txid: if was_deferred { None } else { sweep_result.txid.clone() },
                        fiat_amount: None,
                        fiat_currency: None,
                        coin_price: None,
                        event_id: Some(entry_dedup_key.clone()),
                        log_index: None,
                        asset: None,
                        asset_decimals: None,
                        amount_base_units: None,
                        swept_amount_base_units: None,
                        token_contract: None,
                    };
                    if let Ok(price) = self.price_fetcher.get_price().await {
                        payment.coin_price = Some(price);
                        payment.fiat_currency = Some(self.price_fetcher.currency().to_string());
                        payment.fiat_amount = Some(payment.amount_coin * price);
                    }
                    Some((payment, was_deferred))
                }
                Some(symbol) => {
                    let mint_str = entry.token_mint.as_deref().ok_or_else(|| {
                        DetectorError::InvalidConfig(format!(
                            "Pending token payment {} is missing token_mint",
                            entry.signature
                        ))
                    })?;
                    let mint = Pubkey::from_str(mint_str).map_err(|e| {
                        DetectorError::InvalidConfig(format!(
                            "Invalid persisted token mint '{mint_str}': {e}"
                        ))
                    })?;
                    let decimals = entry.asset_decimals.ok_or_else(|| {
                        DetectorError::InvalidConfig(format!(
                            "Pending token payment {} is missing asset_decimals",
                            entry.signature
                        ))
                    })?;

                    let sweep_result = self
                        .sweep_token_from_address(
                            &entry.address,
                            &mint,
                            symbol,
                            decimals,
                            entry.amount_base_units,
                        )
                        .await?;
                    let was_deferred = sweep_result.deferred;
                    if was_deferred {
                        if already_credited {
                            log::info!(
                                "[SOL] {} sweep retry deferred for already-credited {} (signature {})",
                                symbol, entry.address, entry.signature
                            );
                        } else {
                            log::info!(
                                "[SOL] Crediting {} {} immediately (funds on managed wallet); sweep deferred and will retry next cycle (signature {})",
                                entry.address, symbol, entry.signature
                            );
                        }
                    }

                    let amount_coin =
                        entry.amount_base_units as f64 / 10f64.powi(i32::from(decimals));
                    let swept_coin = sweep_result.amount_base_units as f64
                        / 10f64.powi(i32::from(decimals));
                    let mut payment = DetectedPayment {
                        chain: Chain::Solana,
                        ticker: symbol.to_string(),
                        txid: entry.signature.clone(),
                        address: entry.address.clone(),
                        user_id: Some(entry.user_id.clone()),
                        amount_sat: entry.amount_base_units,
                        amount_coin,
                        confirmations,
                        block_height: Some(entry.slot),
                        derivation_index: entry.wallet_index,
                        memo: None,
                        swept_to_address: if was_deferred {
                            None
                        } else {
                            Some(self.config.secure_deposit_address.clone())
                        },
                        swept_amount_sat: if was_deferred {
                            None
                        } else {
                            Some(sweep_result.amount_base_units)
                        },
                        swept_amount_coin: if was_deferred { None } else { Some(swept_coin) },
                        sweep_txid: if was_deferred { None } else { sweep_result.txid.clone() },
                        fiat_amount: None,
                        fiat_currency: None,
                        coin_price: None,
                        event_id: Some(entry_dedup_key.clone()),
                        log_index: None,
                        asset: Some(symbol.to_string()),
                        asset_decimals: Some(decimals),
                        amount_base_units: Some(entry.amount_base_units.to_string()),
                        swept_amount_base_units: if was_deferred {
                            None
                        } else {
                            Some(sweep_result.amount_base_units.to_string())
                        },
                        token_contract: Some(mint_str.to_string()),
                    };

                    if is_fiat_pegged_token(symbol) {
                        if let Some(rate) = self.token_to_configured_fiat_rate(symbol).await {
                            payment.coin_price = Some(rate);
                            payment.fiat_currency =
                                Some(self.price_fetcher.currency().to_string());
                            payment.fiat_amount = Some(amount_coin * rate);
                        }
                    }

                    Some((payment, was_deferred))
                }
            };

            let Some((credited_payment, was_deferred)) = payment_and_deferred else {
                return Ok(());
            };

            if !already_credited {
                send_webhook(
                    &self.webhook_client,
                    &self.config.webhook_url,
                    &self.config.webhook_hmac_secret,
                    &WebhookEvent::PaymentCredited(credited_payment),
                )
                .await?;

                {
                    let mut state = self.state.lock().unwrap();
                    state.credited_payments.insert(entry_dedup_key.clone());
                }
                self.persist_state()?;
            }

            if !was_deferred {
                {
                    let mut state = self.state.lock().unwrap();
                    // Match by the same composite key we used to insert the
                    // pending entry — multiple entries can share a signature
                    // when one tx credits several of our addresses, and we
                    // must only retain *this* entry's slot.
                    state.pending.retain(|pending| {
                        !(pending.signature == entry.signature
                            && pending.address == entry.address
                            && pending.asset == entry.asset)
                    });
                }
                self.persist_state()?;
            }
        }

        Ok(())
    }

    async fn sweep_native_sol_from_address(
        &self,
        address: &str,
    ) -> Result<SweepResult, DetectorError> {
        let snapshot = snapshot_wallets(&self.wallets);
        let wallet = find_wallet(&snapshot, address).ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "No managed Solana wallet found for address '{}'",
                address
            ))
        })?;

        let balance = self.get_balance(address).await?;
        if balance == 0 {
            return Ok(SweepResult {
                amount_base_units: 0,
                txid: None,
                deferred: false,
            });
        }

        let recent_blockhash = self.get_latest_blockhash().await?;
        let fee = self.estimate_transfer_fee(&wallet, recent_blockhash).await?;

        if balance <= fee {
            log::info!(
                "[SOL] Address {} balance {} lamports is not enough to cover sweep fee {} - deferring",
                address,
                balance,
                fee
            );
            return Ok(SweepResult {
                amount_base_units: 0,
                txid: None,
                deferred: true,
            });
        }

        if fee_ratio_too_high(fee, balance, self.config.max_fee_ratio) {
            log::info!(
                "[SOL] Deferring native sweep for {}: fee {} lamports would be {:.1}% of balance {} (max {:.1}%) - retry later",
                address,
                fee,
                fee as f64 / balance as f64 * 100.0,
                balance,
                self.config.max_fee_ratio * 100.0
            );
            return Ok(SweepResult {
                amount_base_units: 0,
                txid: None,
                deferred: true,
            });
        }

        let from = wallet.keypair.pubkey();
        let amount_lamports = balance - fee;
        let destination = self.sol_native_sweep_destination();
        let tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&from, &destination, amount_lamports)],
            Some(&from),
            &[wallet.keypair.as_ref()],
            recent_blockhash,
        );

        let txid = match self.send_solana_transaction(&tx).await {
            Ok(txid) => txid,
            Err(error) if is_account_drained_error(&error) => {
                // The wallet has no record of a prior credit (rent-reaped
                // or never funded) by the time the RPC simulates our tx,
                // even though `get_balance` returned non-zero a moment
                // ago. Causes seen in the wild:
                //   - The boot orphan-sweep already drained the wallet
                //     after consolidation dropped a duplicate assignment
                //     for this user (race between consolidation cleanup
                //     and a stale pending entry).
                //   - Two concurrent sweep attempts (Helius push +
                //     pending-confirmation loop): the first wins, the
                //     second simulates against the now-empty account.
                //   - The wallet balance was below rent-exempt and the
                //     account got reaped between balance read and send.
                // The deposit was real (we observed it on-chain when we
                // added it to pending) and the funds went somewhere we
                // control, so we still owe the user the credit. Treat
                // this exactly like balance==0: no sweep, no defer, the
                // outer credit step emits `payment_credited` with
                // sweep_txid=None and the entry leaves pending.
                log::warn!(
                    "[SOL] Native sweep for {} skipped: wallet has no SOL to debit (already drained / rent-reaped). Marking pending entry as credited; original deposit will still be paid out to the user. error={error}",
                    address
                );
                return Ok(SweepResult {
                    amount_base_units: 0,
                    txid: None,
                    deferred: false,
                });
            }
            Err(error) => return Err(error),
        };

        log::info!(
            "[SOL] Swept {:.9} SOL from {} to {} (tx={})",
            amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
            address,
            destination,
            txid
        );

        Ok(SweepResult {
            amount_base_units: amount_lamports,
            txid: Some(txid),
            deferred: false,
        })
    }

    fn sol_native_sweep_destination(&self) -> Pubkey {
        self.gas_tank_pubkey.unwrap_or(self.ledger_pubkey)
    }

    pub async fn sweep_orphan_balances(&self) -> Result<(), DetectorError> {
        let active_addresses: HashSet<String> =
            match load_active_reservations(&self.config.redis_url).await {
                Ok(reservations) => reservations.into_iter().map(|r| r.address).collect(),
                Err(error) => {
                    log::warn!(
                        "[SOL] Orphan sweep: failed to load active reservations ({error}); \
                         skipping to avoid touching reserved wallets"
                    );
                    return Ok(());
                }
            };

        let wallet_list = snapshot_wallets(&self.wallets);

        log::info!(
            "[SOL] Orphan sweep starting: {} managed wallet(s), skipping {} active reservation(s)",
            wallet_list.len(),
            active_addresses.len()
        );

        let mut swept_sol_lamports: u64 = 0;
        let mut swept_sol_count: usize = 0;
        let mut swept_token_count: usize = 0;

        for wallet in &wallet_list {
            if active_addresses.contains(&wallet.address) {
                continue;
            }

            // SOL natif
            match self.get_balance(&wallet.address).await {
                Ok(balance) if balance > 0 => {
                    match self.sweep_native_sol_from_address(&wallet.address).await {
                        Ok(result) if result.txid.is_some() => {
                            log::info!(
                                "[SOL] Orphan SOL swept: {} lamports from {} (index {}, tx={})",
                                result.amount_base_units,
                                wallet.address,
                                wallet.index,
                                result.txid.unwrap_or_default()
                            );
                            swept_sol_lamports =
                                swept_sol_lamports.saturating_add(result.amount_base_units);
                            swept_sol_count += 1;
                        }
                        Ok(_) => {}
                        Err(error) => log::warn!(
                            "[SOL] Failed to sweep orphan SOL from {} (index {}): {error}",
                            wallet.address,
                            wallet.index
                        ),
                    }
                }
                Ok(_) => {}
                Err(error) => log::warn!(
                    "[SOL] Failed to fetch SOL balance for {} (index {}): {error}",
                    wallet.address,
                    wallet.index
                ),
            }

            // Tokens SPL
            for token in &self.tokens {
                let owner = wallet.keypair.pubkey();
                let ata = self.ata_for_wallet(&owner, &token.mint);
                let ata_str = ata.to_string();

                let balance = match self.get_token_account_balance(&ata_str).await {
                    Ok(balance) => balance,
                    Err(_) => continue, // ATA n'existe pas → pas de fonds
                };
                if balance == 0 {
                    continue;
                }

                match self
                    .sweep_token_from_address(
                        &wallet.address,
                        &token.mint,
                        &token.symbol,
                        token.decimals,
                        balance,
                    )
                    .await
                {
                    Ok(result) if result.txid.is_some() => {
                        log::info!(
                            "[SOL] Orphan {} swept: {} units from {} (index {}, ata={}, tx={})",
                            token.symbol,
                            result.amount_base_units,
                            wallet.address,
                            wallet.index,
                            ata_str,
                            result.txid.unwrap_or_default()
                        );
                        swept_token_count += 1;
                    }
                    Ok(_) => {}
                    Err(error) => log::warn!(
                        "[SOL] Failed to sweep orphan {} from {} (index {}): {error}",
                        token.symbol,
                        wallet.address,
                        wallet.index
                    ),
                }
            }
        }

        log::info!(
            "[SOL] Orphan sweep complete: {} SOL sweep(s) ({} lamports total), {} token sweep(s)",
            swept_sol_count,
            swept_sol_lamports,
            swept_token_count
        );

        Ok(())
    }

    async fn sweep_token_from_address(
        &self,
        owner_address: &str,
        mint: &Pubkey,
        symbol: &str,
        decimals: u8,
        deposited_amount: u64,
    ) -> Result<SweepResult, DetectorError> {
        let snapshot = snapshot_wallets(&self.wallets);
        let wallet = find_wallet(&snapshot, owner_address).ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "No managed Solana wallet found for address '{}'",
                owner_address
            ))
        })?;

        let owner = wallet.keypair.pubkey();
        let source_ata = self.ata_for_wallet(&owner, mint);
        let destination_ata = self.ata_for_wallet(&self.ledger_pubkey, mint);

        let actual_balance = self
            .get_token_account_balance(&source_ata.to_string())
            .await
            .unwrap_or(deposited_amount);
        let amount = actual_balance.min(u64::MAX);
        if amount == 0 {
            log::info!(
                "[SOL] Token ATA {} has zero {} balance; nothing to sweep",
                source_ata,
                symbol
            );
            return Ok(SweepResult {
                amount_base_units: 0,
                txid: None,
                deferred: false,
            });
        }

        if let Some(peg) = token_peg_currency(symbol) {
            if self.config.max_fee_ratio > 0.0 {
                let amount_pegged = amount as f64 / 10f64.powi(i32::from(decimals));
                if amount_pegged > 0.0 {
                    if let Ok(sol_peg) = self.sol_peg_price(peg).await {
                        if sol_peg > 0.0 {
                            // tx fee only (~5000 lamports). Don't include rent for ATA creation
                            // since that's a one-time bootstrap cost amortized over future sweeps.
                            let fee_lamports = 5_000u64;
                            let fee_pegged =
                                (fee_lamports as f64 / 1_000_000_000.0) * sol_peg;
                            if fee_pegged > amount_pegged * self.config.max_fee_ratio {
                                log::info!(
                                    "[SOL] Deferring {} sweep for {}: fee ~{:.4}{} would be {:.1}% of swept ~{:.2}{} (max {:.1}%)",
                                    symbol,
                                    owner_address,
                                    fee_pegged,
                                    peg,
                                    fee_pegged / amount_pegged * 100.0,
                                    amount_pegged,
                                    peg,
                                    self.config.max_fee_ratio * 100.0
                                );
                                return Ok(SweepResult {
                                    amount_base_units: 0,
                                    txid: None,
                                    deferred: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        let fee_payer = self.gas_tank_keypair.as_deref().ok_or_else(|| {
            DetectorError::InvalidConfig(
                "SOLANA_GAS_TANK_PRIVATE_KEY is required to sweep SPL tokens".into(),
            )
        })?;

        let recent_blockhash = self.get_latest_blockhash().await?;
        let create_destination_ata = create_associated_token_account_idempotent_instruction(
            &fee_payer.pubkey(),
            &destination_ata,
            &self.ledger_pubkey,
            mint,
        );
        let transfer = spl_transfer_checked_instruction(
            &source_ata,
            mint,
            &destination_ata,
            &owner,
            amount,
            decimals,
        );
        let tx = self.build_signed_token_tx(
            &[create_destination_ata, transfer],
            fee_payer,
            wallet.keypair.as_ref(),
            recent_blockhash,
        )?;

        let txid = match self.send_solana_transaction(&tx).await {
            Ok(txid) => txid,
            Err(error) if is_account_drained_error(&error) => {
                // Same defensive fallback as the native sweep path:
                // simulation reports the source ATA has nothing to debit
                // (closed or never funded). Likely already swept by the
                // boot orphan-sweep or by a concurrent sweep attempt.
                // Treat as already-drained → no sweep, but the outer
                // credit step still emits payment_credited so the user
                // gets the original deposit amount.
                log::warn!(
                    "[SOL] {symbol} sweep for {owner_address} skipped: source ATA {source_ata} has no balance to debit (already drained / closed). Marking pending entry as credited; original deposit will still be paid out. error={error}"
                );
                return Ok(SweepResult {
                    amount_base_units: 0,
                    txid: None,
                    deferred: false,
                });
            }
            Err(error) => return Err(error),
        };

        log::info!(
            "[SOL] Swept {} {} units from {} (ata={}) to {} (ata={}) (tx={})",
            amount,
            symbol,
            owner_address,
            source_ata,
            self.config.secure_deposit_address,
            destination_ata,
            txid
        );

        Ok(SweepResult {
            amount_base_units: amount,
            txid: Some(txid),
            deferred: false,
        })
    }

    fn build_signed_token_tx(
        &self,
        instructions: &[Instruction],
        fee_payer: &Keypair,
        owner: &Keypair,
        recent_blockhash: Hash,
    ) -> Result<Transaction, DetectorError> {
        let fee_payer_pubkey = fee_payer.pubkey();
        let owner_pubkey = owner.pubkey();
        let signers: Vec<&Keypair> = if fee_payer_pubkey == owner_pubkey {
            vec![fee_payer]
        } else {
            vec![fee_payer, owner]
        };
        let tx = Transaction::new_signed_with_payer(
            instructions,
            Some(&fee_payer_pubkey),
            &signers,
            recent_blockhash,
        );
        Ok(tx)
    }

    async fn send_solana_transaction(&self, tx: &Transaction) -> Result<String, DetectorError> {
        let tx_bytes = bincode::serialize(tx).map_err(|e| {
            DetectorError::InvalidConfig(format!("Failed to serialize Solana tx: {e}"))
        })?;
        let tx_b64 = BASE64_STANDARD.encode(tx_bytes);
        self.rpc_call(
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
        .await
    }

    async fn get_token_account_balance(&self, ata: &str) -> Result<u64, DetectorError> {
        #[derive(Deserialize)]
        struct TokenBalanceResult {
            value: TokenBalanceValue,
        }
        #[derive(Deserialize)]
        struct TokenBalanceValue {
            amount: String,
        }

        let result: TokenBalanceResult = self
            .rpc_call(
                "getTokenAccountBalance",
                serde_json::json!([ata, {"commitment": "confirmed"}]),
            )
            .await?;
        result.value.amount.parse::<u64>().map_err(|e| {
            DetectorError::ApiError(format!(
                "Failed to parse token account balance for {}: {e}",
                ata
            ))
        })
    }

    async fn peg_to_configured_fiat_rate(&self, peg: &str) -> Result<f64, DetectorError> {
        let peg_upper = peg.to_ascii_uppercase();
        if self.price_fetcher.currency() == peg_upper {
            return Ok(1.0);
        }
        let sol_fiat = self.price_fetcher.get_price().await?;
        let sol_peg = self.sol_peg_price(&peg_upper).await?;
        if !sol_fiat.is_finite() || sol_fiat <= 0.0 || !sol_peg.is_finite() || sol_peg <= 0.0 {
            return Err(DetectorError::ApiError(format!(
                "Invalid SOL/{peg_upper} price for stablecoin conversion"
            )));
        }
        Ok(sol_fiat / sol_peg)
    }

    async fn sol_peg_price(&self, peg: &str) -> Result<f64, DetectorError> {
        match peg.to_ascii_uppercase().as_str() {
            "USD" => self.sol_usd_fetcher.get_price().await,
            "EUR" => self.sol_eur_fetcher.get_price().await,
            other => Err(DetectorError::ApiError(format!(
                "No SOL/{other} price source available for stablecoin conversion"
            ))),
        }
    }

    async fn token_to_configured_fiat_rate(&self, symbol: &str) -> Option<f64> {
        let peg = token_peg_currency(symbol)?;
        self.peg_to_configured_fiat_rate(peg).await.ok()
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
                        DetectorError::ApiError(format!("Solana RPC {method} parse failed: {e}"))
                    })?;
                    if let Some(error) = parsed.error {
                        return Err(DetectorError::ApiError(format!(
                            "Solana RPC {method} returned error {}: {}",
                            error.code, error.message
                        )));
                    }

                    return parsed.result.ok_or_else(|| {
                        DetectorError::ApiError(format!("Solana RPC {method} returned no result"))
                    });
                }
                Ok(resp) => {
                    let status = resp.status();
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u64>().ok());

                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
                    let compact_body = compact_error_body(&body);
                    last_error = format!("Solana RPC {method} failed with status {status}");
                    if !compact_body.is_empty() {
                        last_error.push_str(": ");
                        last_error.push_str(&compact_body);
                    }
                    attempt += 1;
                    if attempt >= max_retries {
                        break;
                    }

                    let backoff_delay = self.config.retry_base_delay_ms * 2u64.pow(attempt - 1);
                    let delay_ms = retry_after
                        .map(|seconds| seconds.saturating_mul(1000))
                        .unwrap_or(backoff_delay);
                    log::debug!(
                        "[SOL] {} (attempt {}/{}) - retry in {}ms",
                        last_error,
                        attempt,
                        max_retries,
                        delay_ms
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    last_error = describe_reqwest_error(
                        &format!("Solana RPC {method} transport failed"),
                        &e,
                    );
                    attempt += 1;
                    if attempt >= max_retries {
                        break;
                    }

                    let delay_ms = self.config.retry_base_delay_ms * 2u64.pow(attempt - 1);
                    log::debug!(
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

    fn extract_positive_token_amount(
        result: &RpcTransactionResult,
        owner: &str,
        mint: &str,
        ata: &str,
    ) -> Option<u64> {
        let meta = result.meta.as_ref()?;
        if meta.err.is_some() {
            return None;
        }

        let post = meta.post_token_balances.iter().find(|balance| {
            balance.mint == mint
                && (matches_owner_balance(balance, owner)
                    || account_at_index(result, balance.account_index) == Some(ata))
        })?;

        let pre_amount = meta
            .pre_token_balances
            .iter()
            .find(|balance| balance.account_index == post.account_index && balance.mint == mint)
            .and_then(|balance| balance.ui_token_amount.amount.parse::<u128>().ok())
            .unwrap_or(0);

        let post_amount = post.ui_token_amount.amount.parse::<u128>().ok()?;
        if post_amount <= pre_amount {
            return None;
        }
        let delta = post_amount - pre_amount;
        if delta > u64::MAX as u128 {
            return None;
        }
        Some(delta as u64)
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

    /// On-demand TXID recovery. Called when a user submits a Solana
    /// signature claiming they paid but never got credited (e.g. the
    /// detector was offline, the webhook failed, or — most commonly —
    /// the reservation TTL expired before the deposit confirmed and
    /// the regular scan loop never picked it up).
    ///
    /// Verifies the destination of the transaction is the address
    /// **currently reserved** for `user_id` (refuses cross-user TXID
    /// stealing — if the user's reservation has expired they must
    /// re-reserve via `/solana/reserve` first), checks the detector's
    /// own `credited_signatures` set to short-circuit duplicates,
    /// otherwise enqueues into pending state and runs a single
    /// `process_credits` cycle so the sweep + `payment_credited`
    /// webhook fire synchronously before returning. The backend's
    /// DB unique index on the credited TXID gives the final layer of
    /// double-credit protection.
    pub async fn recover_txid(
        &self,
        signature: &str,
        user_id: &str,
    ) -> Result<RecoverResponse, DetectorError> {
        let signature = signature.trim();
        let user_id = user_id.trim();
        if signature.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "signature cannot be empty".into(),
            ));
        }
        if user_id.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "user_id cannot be empty".into(),
            ));
        }
        let txid_owned = signature.to_string();
        let user_id_owned = user_id.to_string();
        let mk = |status: RecoverStatus| {
            RecoverResponse::new(
                Chain::Solana,
                txid_owned.clone(),
                user_id_owned.clone(),
                status,
            )
        };

        // The detector-side dedup is now per-(sig, address, asset), not
        // per-signature: a single tx can credit two of our managed
        // wallets (Binance batch sends being the canonical case) and
        // each leg gets its own credit row. We therefore can't
        // short-circuit here without the address — the actual
        // already-credited check happens inside the per-asset enqueue
        // paths once we know which address the recovered tx hits.
        // The backend's per-user/per-signature legacy row check then
        // catches double-credits against pre-upgrade state.

        // Look up the user's permanent assignment. Refusing here when
        // the user has no assignment prevents anyone from sliding a
        // stranger's TXID through the recovery path — the assignment
        // table is the authoritative user_id ↔ address binding.
        let reservation = match load_assignment_for_user(&self.config.redis_url, user_id).await? {
            Some(a) => a,
            None => {
                log::warn!(
                    "[SOL] /recover-txid: user_id={user_id} has no Solana address assignment; ask them to call /solana/address first"
                );
                return Ok(mk(RecoverStatus::WrongUser));
            }
        };

        log::info!(
            "[SOL] /recover-txid: signature={} user_id={} assigned_address={}",
            signature, user_id, reservation.address
        );

        // Sanity check: the reserved address must still exist in our
        // local wallet pool (we hold the keys). Defends against stale
        // Redis state pointing to a wallet that's no longer loaded.
        {
            let snapshot = snapshot_wallets(&self.wallets);
            if find_wallet(&snapshot, &reservation.address).is_none() {
                log::warn!(
                    "[SOL] /recover-txid: reserved address {} not in pool — refusing recovery",
                    reservation.address
                );
                return Ok(mk(RecoverStatus::AddressNotOwned));
            }
        }

        // Fetch the transaction from RPC. A "could not find" result
        // surfaces as an `ApiError` with the RPC error message; map
        // common shapes to TxNotFound and let other errors bubble up.
        let tx = match self.get_transaction(signature).await {
            Ok(tx) => tx,
            Err(error) => {
                let message = error.to_string().to_ascii_lowercase();
                if message.contains("not found")
                    || message.contains("could not")
                    || message.contains("-32004")
                    || message.contains("invalid param")
                {
                    log::info!(
                        "[SOL] /recover-txid: signature={} not found on chain ({})",
                        signature, error
                    );
                    return Ok(mk(RecoverStatus::TxNotFound));
                }
                return Err(error);
            }
        };

        // First try native SOL credit to the reserved owner address.
        if let Some(amount_lamports) =
            Self::extract_positive_lamports_to_address(&tx, &reservation.address)
        {
            let amount_coin = amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64;
            self.enqueue_recovered_native(&reservation, signature, &tx, amount_lamports)
                .await?;
            self.run_recovery_credit_cycle().await?;
            return Ok(self.recover_outcome_for_signature(
                signature,
                &reservation.address,
                None,
                Chain::Solana.ticker().to_string(),
                amount_coin,
                user_id,
            ));
        }

        // Otherwise scan each configured SPL token for a positive
        // balance change on the owner / corresponding ATA.
        let owner = match Pubkey::from_str(&reservation.address) {
            Ok(owner) => owner,
            Err(error) => {
                log::warn!(
                    "[SOL] /recover-txid: invalid reserved address '{}': {error}",
                    reservation.address
                );
                return Ok(mk(RecoverStatus::AddressNotOwned));
            }
        };
        let tokens = self.tokens.clone();
        for token in &tokens {
            let ata = self.ata_for_wallet(&owner, &token.mint);
            let ata_string = ata.to_string();
            let mint_string = token.mint.to_string();
            let owner_string = owner.to_string();
            if let Some(amount_base_units) = Self::extract_positive_token_amount(
                &tx,
                &owner_string,
                &mint_string,
                &ata_string,
            ) {
                let amount_coin =
                    amount_base_units as f64 / 10f64.powi(i32::from(token.decimals));
                self.enqueue_recovered_token(
                    &reservation,
                    signature,
                    &tx,
                    token,
                    amount_base_units,
                )
                .await?;
                self.run_recovery_credit_cycle().await?;
                return Ok(self.recover_outcome_for_signature(
                    signature,
                    &reservation.address,
                    Some(token.symbol.as_str()),
                    token.symbol.clone(),
                    amount_coin,
                    user_id,
                ));
            }
        }

        log::info!(
            "[SOL] /recover-txid: signature={} produced no positive credit to {} (for user_id={user_id})",
            signature, reservation.address
        );
        Ok(mk(RecoverStatus::NoCreditAmount))
    }

    async fn enqueue_recovered_native(
        &self,
        reservation: &SolanaReservation,
        signature: &str,
        tx: &RpcTransactionResult,
        amount_lamports: u64,
    ) -> Result<(), DetectorError> {
        let dedup_key = payment_key(signature, &reservation.address, None);
        let detected = DetectedPayment {
            chain: Chain::Solana,
            ticker: Chain::Solana.ticker().to_string(),
            txid: signature.to_string(),
            address: reservation.address.clone(),
            user_id: Some(reservation.user_id.clone()),
            amount_sat: amount_lamports,
            amount_coin: amount_lamports as f64 / Chain::Solana.sats_per_unit() as f64,
            confirmations: 1,
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
            event_id: Some(dedup_key.clone()),
            log_index: None,
            asset: None,
            asset_decimals: None,
            amount_base_units: None,
            swept_amount_base_units: None,
            token_contract: None,
        };

        send_webhook(
            &self.webhook_client,
            &self.config.webhook_url,
            &self.config.webhook_hmac_secret,
            &WebhookEvent::PaymentDetected(detected),
        )
        .await?;

        {
            let mut state = self.state.lock().unwrap();
            let already_pending = state.pending.iter().any(|p| {
                p.signature == signature
                    && p.address == reservation.address
                    && p.asset.is_none()
            });
            let already_credited = state.credited_payments.contains(&dedup_key);
            if !already_pending && !already_credited {
                state.pending.push(SolanaPendingPayment {
                    signature: signature.to_string(),
                    slot: tx.slot,
                    amount_base_units: amount_lamports,
                    address: reservation.address.clone(),
                    user_id: reservation.user_id.clone(),
                    wallet_index: reservation.wallet_index,
                    asset: None,
                    asset_decimals: None,
                    token_mint: None,
                });
            }
        }

        // Best-effort cursor advance so the regular scan loop doesn't
        // re-emit a `payment_detected` for the same signature.
        let _ = self.update_last_processed_signature(&reservation.address, signature);
        Ok(())
    }

    async fn enqueue_recovered_token(
        &self,
        reservation: &SolanaReservation,
        signature: &str,
        tx: &RpcTransactionResult,
        token: &SplTokenConfig,
        amount_base_units: u64,
    ) -> Result<(), DetectorError> {
        let mint_string = token.mint.to_string();
        let amount_coin =
            amount_base_units as f64 / 10f64.powi(i32::from(token.decimals));
        let dedup_key = payment_key(
            signature,
            &reservation.address,
            Some(token.symbol.as_str()),
        );
        let detected = DetectedPayment {
            chain: Chain::Solana,
            ticker: token.symbol.clone(),
            txid: signature.to_string(),
            address: reservation.address.clone(),
            user_id: Some(reservation.user_id.clone()),
            amount_sat: amount_base_units,
            amount_coin,
            confirmations: 1,
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
            event_id: Some(dedup_key.clone()),
            log_index: None,
            asset: Some(token.symbol.clone()),
            asset_decimals: Some(token.decimals),
            amount_base_units: Some(amount_base_units.to_string()),
            swept_amount_base_units: None,
            token_contract: Some(mint_string.clone()),
        };

        send_webhook(
            &self.webhook_client,
            &self.config.webhook_url,
            &self.config.webhook_hmac_secret,
            &WebhookEvent::PaymentDetected(detected),
        )
        .await?;

        {
            let mut state = self.state.lock().unwrap();
            let already_pending = state.pending.iter().any(|p| {
                p.signature == signature
                    && p.address == reservation.address
                    && p.asset.as_deref() == Some(token.symbol.as_str())
            });
            let already_credited = state.credited_payments.contains(&dedup_key);
            if !already_pending && !already_credited {
                state.pending.push(SolanaPendingPayment {
                    signature: signature.to_string(),
                    slot: tx.slot,
                    amount_base_units,
                    address: reservation.address.clone(),
                    user_id: reservation.user_id.clone(),
                    wallet_index: reservation.wallet_index,
                    asset: Some(token.symbol.clone()),
                    asset_decimals: Some(token.decimals),
                    token_mint: Some(mint_string),
                });
            }
        }

        let owner = Pubkey::from_str(&reservation.address).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid reserved Solana address '{}': {e}",
                reservation.address
            ))
        })?;
        let ata_string = self.ata_for_wallet(&owner, &token.mint).to_string();
        let _ = self.update_last_processed_signature(&ata_string, signature);
        Ok(())
    }

    async fn run_recovery_credit_cycle(&self) -> Result<(), DetectorError> {
        let current_slot = self.get_current_slot().await?;
        self.process_credits(current_slot).await
    }

    fn recover_outcome_for_signature(
        &self,
        signature: &str,
        address: &str,
        dedup_asset: Option<&str>,
        asset_label: String,
        amount_coin: f64,
        user_id: &str,
    ) -> RecoverResponse {
        let dedup_key = payment_key(signature, address, dedup_asset);
        let credited = {
            let state = self.state.lock().unwrap();
            state.credited_payments.contains(&dedup_key)
        };
        let status = if credited {
            RecoverStatus::Credited
        } else {
            RecoverStatus::PendingSweep
        };
        RecoverResponse::new(
            Chain::Solana,
            signature.to_string(),
            user_id.to_string(),
            status,
        )
        .with_asset(asset_label, amount_coin)
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

fn matches_owner_balance(balance: &RpcTokenBalance, owner: &str) -> bool {
    balance
        .owner
        .as_deref()
        .map(|stored| stored == owner)
        .unwrap_or(false)
}

fn account_at_index(result: &RpcTransactionResult, index: u32) -> Option<&str> {
    let static_keys = &result.transaction.message.account_keys;
    let static_len = static_keys.len();
    let idx = index as usize;

    if idx < static_len {
        return static_keys.get(idx).map(|key| key.pubkey());
    }

    let loaded = result.meta.as_ref()?.loaded_addresses.as_ref()?;
    let writable_idx = idx - static_len;
    if writable_idx < loaded.writable.len() {
        return loaded.writable.get(writable_idx).map(String::as_str);
    }

    let readonly_idx = writable_idx - loaded.writable.len();
    loaded.readonly.get(readonly_idx).map(String::as_str)
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

fn is_fiat_pegged_token(symbol: &str) -> bool {
    is_usd_pegged_token(symbol) || is_eur_pegged_token(symbol)
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

fn fee_ratio_too_high(fee: u64, total: u64, max_ratio: f64) -> bool {
    if total == 0 || !max_ratio.is_finite() || max_ratio <= 0.0 || max_ratio >= 1.0 {
        return false;
    }
    (fee as f64) / (total as f64) > max_ratio
}

/// Detect "the source account has nothing left to debit" errors returned
/// by `sendTransaction` simulation. These mean a previous sweep (orphan
/// or concurrent) already drained the wallet, so the pending entry should
/// be treated as credited rather than retried forever.
///
/// Matches the canonical Solana strings:
/// - `"Attempt to debit an account but found no record of a prior credit"`
///   (account never funded / rent-reaped after balance dropped to 0)
/// - `"insufficient lamports"` (balance check raced with concurrent sweep)
/// - `"AccountNotFound"` / `"could not find account"` (account closed)
fn is_account_drained_error(error: &DetectorError) -> bool {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    lower.contains("found no record of a prior credit")
        || lower.contains("attempt to debit an account but found")
        || lower.contains("insufficient lamports")
        || lower.contains("accountnotfound")
        || lower.contains("could not find account")
}

fn usd_to_lamports(usd: f64, sol_usd: f64) -> Option<u64> {
    if !usd.is_finite() || usd <= 0.0 || !sol_usd.is_finite() || sol_usd <= 0.0 {
        return None;
    }
    let lamports = (usd / sol_usd) * 1_000_000_000.0;
    if !lamports.is_finite() || lamports < 0.0 || lamports > u64::MAX as f64 {
        return None;
    }
    Some(lamports.ceil() as u64)
}

fn unix_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, Clone, Copy)]
enum ScheduledOutcome {
    /// A scheduled payment was successfully sent — or definitively failed
    /// and reported back. The caller should NOT also do a ledger sweep.
    Sent,
    /// A scheduled payment is pending but the gas tank can't cover it yet.
    /// The caller must skip ledger sweeps so funds keep accumulating.
    WaitingForFunds,
    /// No eligible scheduled payment. Caller proceeds with a normal sweep.
    None,
}

/// Resolves the lamport amount for a scheduled payment from its declared
/// `(amount_value, amount_currency)`. SOL is treated as exact; EUR/USD are
/// recomputed at send time using the live FX rate so the admin's intent
/// ("send 100 EUR") survives across price moves between scheduling and
/// execution.
async fn payment_amount_lamports(
    payment: &crate::solana_scheduled::ScheduledSolPayment,
    sol_usd: f64,
    sol_eur_fetcher: &crate::pricing::PriceFetcher,
) -> Result<u64, String> {
    let amount: f64 = payment
        .amount_value
        .parse()
        .map_err(|e| format!("amount_value not a decimal: {e}"))?;
    if !amount.is_finite() || amount <= 0.0 {
        return Err(format!("non-positive amount: {amount}"));
    }
    let lamports = match payment.amount_currency.as_str() {
        "SOL" => amount * 1_000_000_000.0,
        "USD" => {
            if !sol_usd.is_finite() || sol_usd <= 0.0 {
                return Err("invalid SOL/USD price".into());
            }
            (amount / sol_usd) * 1_000_000_000.0
        }
        "EUR" => {
            let sol_eur = sol_eur_fetcher
                .get_price()
                .await
                .map_err(|e| format!("failed to fetch SOL/EUR: {e}"))?;
            if !sol_eur.is_finite() || sol_eur <= 0.0 {
                return Err("invalid SOL/EUR price".into());
            }
            (amount / sol_eur) * 1_000_000_000.0
        }
        other => return Err(format!("unsupported currency '{other}'")),
    };
    if !lamports.is_finite() || lamports < 0.0 || lamports > u64::MAX as f64 {
        return Err("lamports overflow".into());
    }
    Ok(lamports.ceil() as u64)
}

fn parse_solana_keypair(value: &str) -> Result<Keypair, String> {
    let trimmed = value.trim();
    let bytes: Vec<u8> = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<u8>>(trimmed)
            .map_err(|e| format!("invalid JSON byte array: {e}"))?
    } else {
        bs58::decode(trimmed)
            .into_vec()
            .map_err(|e| format!("invalid base58 string: {e}"))?
    };

    if bytes.len() != 64 {
        return Err(format!(
            "expected 64-byte Solana keypair, got {} byte(s)",
            bytes.len()
        ));
    }

    Keypair::try_from(bytes.as_slice()).map_err(|e| format!("failed to decode keypair: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drained_error_matches_real_rpc_response() {
        // Exact wording observed in production:
        let exact = DetectorError::ApiError(
            "Solana RPC sendTransaction returned error -32002: Transaction simulation failed: Attempt to debit an account but found no record of a prior credit.".into(),
        );
        assert!(is_account_drained_error(&exact));

        // Variations the matcher must also recognise
        let insufficient = DetectorError::ApiError(
            "Transaction simulation failed: insufficient lamports 0, need 5000".into(),
        );
        assert!(is_account_drained_error(&insufficient));

        let not_found = DetectorError::ApiError("AccountNotFound: 9xZ...".into());
        assert!(is_account_drained_error(&not_found));

        // Unrelated errors must NOT trigger the fallback
        let generic_429 = DetectorError::ApiError(
            "Solana RPC getLatestBlockhash returned error -32016: Too many requests".into(),
        );
        assert!(!is_account_drained_error(&generic_429));

        let invalid_blockhash = DetectorError::ApiError(
            "Transaction simulation failed: Blockhash not found".into(),
        );
        assert!(!is_account_drained_error(&invalid_blockhash));
    }
}
