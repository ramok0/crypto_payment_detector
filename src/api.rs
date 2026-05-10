use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crypto_payment_detector::derivation::derive_address;
use crypto_payment_detector::env_utils::{
    chain_env_bool, chain_env_prefix, chain_env_var, env_bool, proxy_env_var,
};
use crypto_payment_detector::persistence::load_state;
use crypto_payment_detector::recover::{RecoverRequest, RecoverResponse, RecoverStatus};
use crypto_payment_detector::types::Chain;
use crypto_payment_detector::helius_webhooks::{
    HeliusWebhookClient, HeliusWebhookConfig, collect_candidate_addresses, verify_auth_header,
};
use crypto_payment_detector::{
    BasicAuth, ChainDetector, DetectorConfig, DetectorError, EthereumConfig, EthereumDetector,
    EthereumReservation, EtherscanConfig, PaymentDetector, RetryConfig, SharedEthereumWallets,
    SharedSolanaWallets, SolanaConfig, SolanaDetector, SolanaReservation,
    assign_ethereum_wallet_for_user, assign_wallet_for_user, delete_all_assignments,
    delete_all_ethereum_assignments, ethereum_reservation_store_url_from_env,
    load_active_ethereum_reservations, load_active_reservations, load_ethereum_wallet_pool,
    load_wallet_pool, parse_erc20_tokens, parse_spl_tokens, rotate_assignment,
    shared_ethereum_wallets, shared_wallets,
};

#[derive(Clone)]
struct AppState {
    chains: Vec<ChainInfo>,
    solana_pool: Option<SolanaPoolApiState>,
    ethereum_pool: Option<EthereumPoolApiState>,
    base_pool: Option<EthereumPoolApiState>,
    /// Per-chain BTC/LTC detector handles. Used by `/recover-txid` to
    /// look up an old TXID against the configured xpub and enqueue
    /// the missed payment for sweep + webhook synchronously.
    bitcoin_detectors: HashMap<Chain, BitcoinRecoveryState>,
}

#[derive(Clone)]
struct SolanaPoolApiState {
    wallets: SharedSolanaWallets,
    wallet_pool_path: String,
    redis_url: String,
    secure_deposit_address: String,
    /// Live detector handle used by `/solana/claim` to trigger an
    /// immediate scan + sweep + credit cycle on demand, and by
    /// `/solana/recover-txid` to fetch a historical signature, verify
    /// ownership against the user's permanent assignment, and emit the
    /// credit webhook synchronously. `None` when the API binary runs
    /// without a co-located detector (rare; primarily for tests and
    /// read-only deployments).
    detector: Option<Arc<SolanaDetector>>,
    /// Optional Helius webhook integration. `None` when
    /// `HELIUS_WEBHOOK_ENABLED` is unset or falsy — in that case the API
    /// behaves exactly as before (polling is the only detection path).
    helius: Option<Arc<HeliusWebhookClient>>,
}

#[derive(Clone)]
struct EthereumPoolApiState {
    chain: Chain,
    wallets: SharedEthereumWallets,
    wallet_pool_path: String,
    redis_url: String,
    gas_tank_address: String,
    ledger_address: String,
    /// Live detector handle used by `/<chain>/claim` to trigger an
    /// immediate scan + sweep + credit cycle on demand, and by
    /// `/<chain>/recover-txid` for historical TXID recovery.
    detector: Option<Arc<EthereumDetector>>,
}

#[derive(Clone)]
struct BitcoinRecoveryState {
    detector: Arc<ChainDetector>,
    max_derivation_index: u32,
}

#[derive(Clone)]
struct ChainInfo {
    chain: Chain,
    address_source: AddressSource,
    state_file: String,
    endpoint: HealthEndpoint,
}

#[derive(Clone)]
enum AddressSource {
    Xpub(String),
    Static(String),
}

#[derive(Clone)]
enum HealthEndpoint {
    ExplorerApis(Vec<String>),
    SolanaRpc(String),
    EthereumRpc(String),
}

#[derive(Deserialize)]
struct DeriveParams {
    chain: String,
    #[serde(default)]
    start: u32,
    #[serde(default = "default_count")]
    count: u32,
}

/// Request body for the `/<chain>/address` endpoint. Returns the user's
/// permanent deposit address, creating one if it does not yet exist.
#[derive(Deserialize)]
struct AddressRequest {
    user_id: String,
}

/// Request body for the `/<chain>/claim` endpoint. Triggered by the user
/// clicking "I deposited" on the frontend; runs an immediate scan + sweep
/// + credit cycle for that user's assigned address.
#[derive(Deserialize)]
struct ClaimRequest {
    user_id: String,
}

fn default_count() -> u32 {
    1
}

fn explorer_api_config(chain: Chain) -> Option<String> {
    chain_env_var(chain, "EXPLORER_API_URLS")
        .or_else(|| chain_env_var(chain, "EXPLORER_API_URL"))
        .or_else(|| std::env::var("EXPLORER_API_URLS").ok())
        .or_else(|| std::env::var("EXPLORER_API_URL").ok())
}

fn is_blockchair_api_url(url: &str) -> bool {
    url.to_ascii_lowercase().contains("api.blockchair.com")
}

fn blockchair_health_url(url: &str) -> String {
    let mut health_url = format!("{}/stats", url.trim_end_matches('/'));
    if let Ok(key) = std::env::var("BLOCKCHAIR_API_KEY") {
        let key = key.trim();
        if !key.is_empty() {
            health_url.push_str("?key=");
            health_url.push_str(key);
        }
    }
    health_url
}

fn esplora_health_url(url: &str) -> String {
    format!("{}/blocks/tip/height", url.trim_end_matches('/'))
}

#[derive(Serialize)]
struct DeriveResponse {
    chain: String,
    addresses: Vec<AddressEntry>,
}

#[derive(Serialize)]
struct AddressEntry {
    index: u32,
    address: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    chains: Vec<ChainHealthStatus>,
}

#[derive(Serialize)]
struct ChainHealthStatus {
    chain: String,
    ticker: String,
    last_scanned_height: Option<u64>,
    last_processed_signature: Option<String>,
    explorer_reachable: bool,
}

#[derive(Serialize)]
struct SolanaAddressResponse {
    user_id: String,
    address: String,
    wallet_index: u32,
    assigned_at_unix: i64,
    sweep_destination_address: String,
}

#[derive(Serialize)]
struct ActiveSolanaAssignmentsResponse {
    count: usize,
    assignments: Vec<SolanaReservation>,
}

#[derive(Serialize)]
struct EthereumAddressResponse {
    user_id: String,
    address: String,
    wallet_index: u32,
    assigned_at_unix: i64,
    gas_tank_address: String,
    ledger_address: String,
}

#[derive(Serialize)]
struct ActiveEthereumAssignmentsResponse {
    count: usize,
    assignments: Vec<EthereumReservation>,
}

#[derive(Serialize)]
struct CancelAllReservationsResponse {
    solana_cancelled: usize,
    ethereum_cancelled: usize,
    base_cancelled: usize,
    total_cancelled: usize,
}

#[derive(Serialize)]
struct ClaimResponse {
    user_id: String,
    address: String,
    chain: String,
    /// Always "scanning" — the actual credit/sweep result is delivered
    /// asynchronously via the configured webhook (`payment_credited`).
    status: &'static str,
}

#[derive(Deserialize)]
struct SolanaHealthState {
    #[serde(default)]
    addresses: HashMap<String, SolanaAddressHealthCursor>,
}

#[derive(Deserialize)]
struct SolanaAddressHealthCursor {
    last_processed_signature: Option<String>,
}

#[derive(Deserialize)]
struct EthereumHealthState {
    last_scanned_block: Option<u64>,
}

async fn handle_derive(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DeriveParams>,
) -> Result<Json<DeriveResponse>, (StatusCode, String)> {
    let chain: Chain = params
        .chain
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, e))?;

    let info = state
        .chains
        .iter()
        .find(|chain_info| chain_info.chain == chain)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("Chain {} not configured", chain),
            )
        })?;

    if params.count > 100000 {
        return Err((StatusCode::BAD_REQUEST, "count must be <= 100000".into()));
    }

    let mut addresses = Vec::with_capacity(params.count as usize);
    match &info.address_source {
        AddressSource::Xpub(xpub) => {
            for index in params.start..params.start + params.count {
                let address = derive_address(xpub, index, chain).map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Derivation error at index {index}: {e}"),
                    )
                })?;
                addresses.push(AddressEntry { index, address });
            }
        }
        AddressSource::Static(address) => {
            addresses.push(AddressEntry {
                index: 0,
                address: address.clone(),
            });
        }
    }

    Ok(Json(DeriveResponse {
        chain: chain.name().to_string(),
        addresses,
    }))
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let mut chains = Vec::new();
    let mut all_ok = true;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    for info in &state.chains {
        let (last_scanned_height, last_processed_signature, explorer_reachable, chain_ok) =
            match &info.endpoint {
                HealthEndpoint::ExplorerApis(explorer_api_urls) => {
                    let persisted = load_state(&info.state_file).ok();
                    let mut reachable = false;
                    for explorer_api_url in explorer_api_urls {
                        let health_url = if is_blockchair_api_url(explorer_api_url) {
                            blockchair_health_url(explorer_api_url)
                        } else {
                            esplora_health_url(explorer_api_url)
                        };
                        reachable = client
                            .get(&health_url)
                            .send()
                            .await
                            .map(|response| response.status().is_success())
                            .unwrap_or(false);
                        if reachable {
                            break;
                        }
                    }
                    let last_scanned_height = persisted.and_then(|state| state.last_scanned_height);
                    let chain_ok = reachable && last_scanned_height.is_some();
                    (last_scanned_height, None, reachable, chain_ok)
                }
                HealthEndpoint::SolanaRpc(rpc_url) => {
                    let last_processed_signature =
                        load_solana_last_processed_signature(&info.state_file);
                    let reachable = client
                        .post(rpc_url)
                        .json(&serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "getSlot",
                            "params": [{"commitment": "confirmed"}],
                        }))
                        .send()
                        .await
                        .map(|response| response.status().is_success())
                        .unwrap_or(false);
                    (None, last_processed_signature, reachable, reachable)
                }
                HealthEndpoint::EthereumRpc(rpc_url) => {
                    let last_scanned_height = load_ethereum_last_scanned_block(&info.state_file);
                    let reachable = client
                        .post(rpc_url)
                        .json(&serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "eth_blockNumber",
                            "params": [],
                        }))
                        .send()
                        .await
                        .map(|response| response.status().is_success())
                        .unwrap_or(false);
                    let chain_ok = reachable && last_scanned_height.is_some();
                    (last_scanned_height, None, reachable, chain_ok)
                }
            };

        all_ok &= chain_ok;
        chains.push(ChainHealthStatus {
            chain: info.chain.name().to_string(),
            ticker: info.chain.ticker().to_string(),
            last_scanned_height,
            last_processed_signature,
            explorer_reachable,
        });
    }

    Json(HealthResponse {
        status: if all_ok {
            "ok".into()
        } else {
            "degraded".into()
        },
        chains,
    })
}

async fn handle_solana_address(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddressRequest>,
) -> Result<Json<SolanaAddressResponse>, (StatusCode, String)> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };

    let assignment = assign_wallet_for_user(
        &solana_pool.redis_url,
        &solana_pool.wallets,
        &solana_pool.wallet_pool_path,
        &payload.user_id,
    )
    .await
    .map_err(map_assignment_error)?;

    // Best-effort: register the new address (and its ATAs) on the Helius
    // webhook so future deposits trigger an instant push. A failure here
    // must not block the assignment — the polling fallback will still
    // catch the deposit, just with the usual cycle latency.
    if let (Some(helius), Some(detector)) =
        (solana_pool.helius.as_ref(), solana_pool.detector.as_ref())
    {
        let addresses = detector.webhook_addresses_for_wallet(&assignment.address);
        if let Err(error) = helius.add_addresses(&addresses).await {
            log::warn!(
                "[HELIUS] Failed to register {} on webhook (will rely on polling): {error}",
                assignment.address
            );
        }
    }

    Ok(Json(SolanaAddressResponse {
        user_id: assignment.user_id,
        address: assignment.address,
        wallet_index: assignment.wallet_index,
        assigned_at_unix: assignment.reserved_at_unix,
        sweep_destination_address: solana_pool.secure_deposit_address.clone(),
    }))
}

/// Rotate the user's Solana deposit address to a brand-new wallet from
/// the pool. The previous address is preserved in Redis as `dormant`, so
/// late deposits still credit the original user — the slot is simply not
/// returned by `/solana/address` any more. The autoshop backend
/// rate-limits this to once per day per user; the detector itself does
/// not enforce a cooldown.
#[derive(Serialize)]
struct SolanaRotateResponse {
    user_id: String,
    new_address: String,
    new_wallet_index: u32,
    new_assigned_at_unix: i64,
    previous_address: String,
    previous_wallet_index: u32,
    sweep_destination_address: String,
}

async fn handle_solana_rotate(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddressRequest>,
) -> Result<Json<SolanaRotateResponse>, (StatusCode, String)> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };

    let (old, fresh) = rotate_assignment(
        &solana_pool.redis_url,
        &solana_pool.wallets,
        &solana_pool.wallet_pool_path,
        &payload.user_id,
    )
    .await
    .map_err(map_assignment_error)?;

    // Register the new address on Helius. The OLD address stays watched
    // because we never remove it from the webhook list — leaving it
    // there is exactly what we want, since late deposits to the dormant
    // address still need to fire the detection path.
    if let (Some(helius), Some(detector)) =
        (solana_pool.helius.as_ref(), solana_pool.detector.as_ref())
    {
        let addresses = detector.webhook_addresses_for_wallet(&fresh.address);
        if let Err(error) = helius.add_addresses(&addresses).await {
            log::warn!(
                "[HELIUS] Failed to register rotated address {} on webhook (will rely on polling): {error}",
                fresh.address
            );
        }
    }

    Ok(Json(SolanaRotateResponse {
        user_id: fresh.user_id.clone(),
        new_address: fresh.address.clone(),
        new_wallet_index: fresh.wallet_index,
        new_assigned_at_unix: fresh.reserved_at_unix,
        previous_address: old.address,
        previous_wallet_index: old.wallet_index,
        sweep_destination_address: solana_pool.secure_deposit_address.clone(),
    }))
}

async fn handle_solana_active(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ActiveSolanaAssignmentsResponse>, (StatusCode, String)> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };

    let assignments = load_active_reservations(&solana_pool.redis_url)
        .await
        .map_err(map_internal_error)?;

    Ok(Json(ActiveSolanaAssignmentsResponse {
        count: assignments.len(),
        assignments,
    }))
}

async fn handle_solana_claim(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, (StatusCode, String)> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };
    let detector = solana_pool.detector.clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Solana detector is not running in this process".to_string(),
    ))?;

    let address = detector
        .claim_for_user(&payment_user_id(&payload.user_id)?)
        .await
        .map_err(map_claim_error)?;

    Ok(Json(ClaimResponse {
        user_id: payload.user_id,
        address,
        chain: "solana".to_string(),
        status: "scanning",
    }))
}

async fn handle_evm_address(
    pool: Option<&EthereumPoolApiState>,
    payload: AddressRequest,
) -> Result<Json<EthereumAddressResponse>, (StatusCode, String)> {
    let Some(pool) = pool else {
        return Err((
            StatusCode::BAD_REQUEST,
            "EVM address pool is not configured".into(),
        ));
    };

    let assignment = assign_ethereum_wallet_for_user(
        pool.chain,
        &pool.redis_url,
        &pool.wallets,
        &pool.wallet_pool_path,
        &payload.user_id,
    )
    .await
    .map_err(map_assignment_error)?;

    Ok(Json(EthereumAddressResponse {
        user_id: assignment.user_id,
        address: assignment.address,
        wallet_index: assignment.wallet_index,
        assigned_at_unix: assignment.reserved_at_unix,
        gas_tank_address: pool.gas_tank_address.clone(),
        ledger_address: pool.ledger_address.clone(),
    }))
}

async fn handle_evm_active(
    pool: Option<&EthereumPoolApiState>,
) -> Result<Json<ActiveEthereumAssignmentsResponse>, (StatusCode, String)> {
    let Some(pool) = pool else {
        return Err((
            StatusCode::BAD_REQUEST,
            "EVM address pool is not configured".into(),
        ));
    };

    let assignments = load_active_ethereum_reservations(pool.chain, &pool.redis_url)
        .await
        .map_err(map_internal_error)?;

    Ok(Json(ActiveEthereumAssignmentsResponse {
        count: assignments.len(),
        assignments,
    }))
}

async fn handle_evm_claim(
    pool: Option<&EthereumPoolApiState>,
    payload: ClaimRequest,
) -> Result<Json<ClaimResponse>, (StatusCode, String)> {
    let Some(pool) = pool else {
        return Err((
            StatusCode::BAD_REQUEST,
            "EVM address pool is not configured".into(),
        ));
    };
    let detector = pool.detector.clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        format!(
            "{} detector is not running in this process",
            pool.chain.ticker()
        ),
    ))?;

    let address = detector
        .claim_for_user(&payment_user_id(&payload.user_id)?)
        .await
        .map_err(map_claim_error)?;

    Ok(Json(ClaimResponse {
        user_id: payload.user_id,
        address,
        chain: pool.chain.name().to_string(),
        status: "scanning",
    }))
}

async fn handle_ethereum_address(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddressRequest>,
) -> Result<Json<EthereumAddressResponse>, (StatusCode, String)> {
    handle_evm_address(state.ethereum_pool.as_ref(), payload).await
}

async fn handle_ethereum_active(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ActiveEthereumAssignmentsResponse>, (StatusCode, String)> {
    handle_evm_active(state.ethereum_pool.as_ref()).await
}

async fn handle_ethereum_claim(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, (StatusCode, String)> {
    handle_evm_claim(state.ethereum_pool.as_ref(), payload).await
}

async fn handle_base_address(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddressRequest>,
) -> Result<Json<EthereumAddressResponse>, (StatusCode, String)> {
    handle_evm_address(state.base_pool.as_ref(), payload).await
}

async fn handle_base_active(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ActiveEthereumAssignmentsResponse>, (StatusCode, String)> {
    handle_evm_active(state.base_pool.as_ref()).await
}

async fn handle_base_claim(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, (StatusCode, String)> {
    handle_evm_claim(state.base_pool.as_ref(), payload).await
}

/// Admin endpoint: release every active assignment across Solana, Ethereum
/// and Base. Returns per-chain and total counts of records removed. Pools
/// that aren't configured in this process contribute 0 and don't error.
async fn handle_admin_cancel_all_reservations(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CancelAllReservationsResponse>, (StatusCode, String)> {
    let solana_cancelled = if let Some(pool) = state.solana_pool.as_ref() {
        let count = delete_all_assignments(&pool.redis_url)
            .await
            .map_err(map_internal_error)?;
        // After clearing assignments, behave according to the watch
        // mode:
        // - WholePool: keep the webhook untouched. The pool wallets
        //   still belong to us and incoming deposits should still be
        //   recoverable via the orphan sweep.
        // - AssignedOnly: clear the webhook list so we don't keep
        //   receiving pushes for now-released wallets.
        // Best-effort either way — a failure here is logged and ignored.
        if let (Some(helius), Some(detector)) =
            (pool.helius.as_ref(), pool.detector.as_ref())
        {
            match helius_watch_mode(detector.as_ref()) {
                HeliusWatchMode::WholePool => {
                    log::info!(
                        "[HELIUS] cancel-all: keeping {} pool address(es) on webhook (WholePool mode)",
                        detector.webhook_address_set().len()
                    );
                }
                HeliusWatchMode::AssignedOnly => {
                    if let Err(error) = helius.replace_addresses(Vec::new()).await {
                        log::warn!(
                            "[HELIUS] Failed to clear webhook address list after cancel-all: {error}"
                        );
                    }
                }
            }
        }
        count
    } else {
        0
    };

    let ethereum_cancelled = if let Some(pool) = state.ethereum_pool.as_ref() {
        delete_all_ethereum_assignments(pool.chain, &pool.redis_url)
            .await
            .map_err(map_internal_error)?
    } else {
        0
    };

    let base_cancelled = if let Some(pool) = state.base_pool.as_ref() {
        delete_all_ethereum_assignments(pool.chain, &pool.redis_url)
            .await
            .map_err(map_internal_error)?
    } else {
        0
    };

    let total_cancelled = solana_cancelled + ethereum_cancelled + base_cancelled;
    log::warn!(
        "[ADMIN] Cancel-all reservations triggered: SOL={} ETH={} BASE={} (total={})",
        solana_cancelled,
        ethereum_cancelled,
        base_cancelled,
        total_cancelled
    );

    Ok(Json(CancelAllReservationsResponse {
        solana_cancelled,
        ethereum_cancelled,
        base_cancelled,
        total_cancelled,
    }))
}

fn payment_user_id(raw: &str) -> Result<String, (StatusCode, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id cannot be empty".into()));
    }
    Ok(trimmed.to_string())
}

async fn handle_solana_recover(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, (StatusCode, String)> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };
    let detector = solana_pool.detector.clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Solana detector is not running in this process".to_string(),
    ))?;

    let user_id = payment_user_id(&payload.user_id)?;
    let response = detector
        .recover_txid(payload.txid.trim(), &user_id)
        .await
        .map_err(map_internal_error)?;
    Ok(Json(response))
}

#[derive(Serialize)]
struct SolanaWebhookResponse {
    /// Number of candidate addresses the webhook handler queued for
    /// background scanning. The actual scan runs in a `tokio::spawn`
    /// task so the HTTP response stays under Helius's delivery timeout
    /// (~10s). `0` means the payload had no Solana-looking addresses
    /// (typically: a Helius "Test Webhook" synthetic body).
    accepted: usize,
}

#[derive(Serialize)]
struct SolanaWebhookStatusResponse {
    /// Whether the integration is enabled at all (i.e. whether
    /// `HELIUS_WEBHOOK_ENABLED=true` was set at boot).
    enabled: bool,
    /// Current watch mode — `"WholePool"` or `"AssignedOnly"`. Computed
    /// dynamically from the projected address count vs
    /// `HELIUS_MAX_WATCH_ADDRESSES`.
    mode: Option<String>,
    /// Number of addresses we expect to be on the webhook (owners + ATAs
    /// for the relevant set per the current mode).
    expected_address_count: Option<usize>,
    /// Number of addresses Helius reports on the webhook right now.
    /// `None` if the GET to Helius failed.
    actual_address_count: Option<usize>,
    /// Helius URL configured on the webhook (sanity check that
    /// `HELIUS_WEBHOOK_ID` points at the right webhook).
    webhook_url: Option<String>,
    /// `"enhanced"` / `"raw"` — the webhook's configured type.
    webhook_type: Option<String>,
    /// Whether expected and actual address counts match. `false` flags
    /// drift (e.g. a sync failed silently).
    in_sync: Option<bool>,
    /// Human-readable diagnostic when something is off.
    note: Option<String>,
}

/// Handler for `GET /solana/webhook/status`. Operator-facing diagnostic:
/// reports whether the Helius integration is enabled, what mode it's in,
/// and whether the address list registered on Helius matches what the
/// detector expects. Safe to call from inside the Docker network — it
/// does no work beyond a single Helius GET.
async fn handle_solana_webhook_status(
    State(state): State<Arc<AppState>>,
) -> Json<SolanaWebhookStatusResponse> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Json(SolanaWebhookStatusResponse {
            enabled: false,
            mode: None,
            expected_address_count: None,
            actual_address_count: None,
            webhook_url: None,
            webhook_type: None,
            in_sync: None,
            note: Some("Solana address pool is not configured".to_string()),
        });
    };
    let Some(helius) = solana_pool.helius.as_ref() else {
        return Json(SolanaWebhookStatusResponse {
            enabled: false,
            mode: None,
            expected_address_count: None,
            actual_address_count: None,
            webhook_url: None,
            webhook_type: None,
            in_sync: None,
            note: Some(
                "Helius integration disabled (HELIUS_WEBHOOK_ENABLED is not true)"
                    .to_string(),
            ),
        });
    };
    let Some(detector) = solana_pool.detector.as_ref() else {
        return Json(SolanaWebhookStatusResponse {
            enabled: true,
            mode: None,
            expected_address_count: None,
            actual_address_count: None,
            webhook_url: None,
            webhook_type: None,
            in_sync: None,
            note: Some("Detector handle missing in this process".to_string()),
        });
    };

    let mode = helius_watch_mode(detector.as_ref());
    let expected = match mode {
        HeliusWatchMode::WholePool => detector.webhook_address_set().len(),
        HeliusWatchMode::AssignedOnly => {
            // Cheap projection: count of (owner + ATAs) per active assignment.
            match load_active_reservations(&solana_pool.redis_url).await {
                Ok(assignments) => {
                    assignments.len() * (1 + detector.token_count())
                }
                Err(_) => 0,
            }
        }
    };

    match helius.get_webhook().await {
        Ok(value) => {
            let actual_addresses = value
                .get("accountAddresses")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let webhook_url = value
                .get("webhookURL")
                .and_then(|v| v.as_str())
                .map(String::from);
            let webhook_type = value
                .get("webhookType")
                .and_then(|v| v.as_str())
                .map(String::from);
            let in_sync = expected == actual_addresses;
            Json(SolanaWebhookStatusResponse {
                enabled: true,
                mode: Some(format!("{mode:?}")),
                expected_address_count: Some(expected),
                actual_address_count: Some(actual_addresses),
                webhook_url,
                webhook_type,
                in_sync: Some(in_sync),
                note: if in_sync {
                    None
                } else {
                    Some(format!(
                        "Drift: expected {} addresses (mode={:?}) but Helius reports {}. \
                         Restart the API to trigger a fresh sync, or POST to \
                         /admin/reservations/cancel-all to reset.",
                        expected, mode, actual_addresses
                    ))
                },
            })
        }
        Err(error) => Json(SolanaWebhookStatusResponse {
            enabled: true,
            mode: Some(format!("{mode:?}")),
            expected_address_count: Some(expected),
            actual_address_count: None,
            webhook_url: None,
            webhook_type: None,
            in_sync: None,
            note: Some(format!("Helius GET failed: {error}")),
        }),
    }
}

/// Handler for `POST /solana/webhook`. Intended target of a Helius webhook
/// (raw or enhanced). When `HELIUS_WEBHOOK_ENABLED` is unset the route is
/// still registered but rejects every request — this keeps the optional
/// integration symmetrical with the other Solana endpoints. Accepts the
/// body as a raw `Bytes` so a malformed/test payload still produces a
/// useful log line instead of a 422 from the JSON extractor.
async fn handle_solana_webhook(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<SolanaWebhookResponse>, (StatusCode, String)> {
    let body_len = body.len();
    // Try to capture the original client IP — Traefik puts it in
    // X-Forwarded-For. Useful to confirm Helius is the actual sender.
    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let auth_present = headers.contains_key(axum::http::header::AUTHORIZATION);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    log::info!(
        "[HELIUS] Webhook POST received: source={} ua=\"{}\" body_bytes={} auth_header={}",
        source_ip,
        user_agent,
        body_len,
        if auth_present { "present" } else { "missing" }
    );

    let Some(solana_pool) = state.solana_pool.as_ref() else {
        log::warn!("[HELIUS] Webhook rejected: Solana pool not configured in this process");
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };
    let Some(helius) = solana_pool.helius.as_ref() else {
        log::warn!(
            "[HELIUS] Webhook rejected: HELIUS_WEBHOOK_ENABLED is not true (integration disabled)"
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Helius webhook integration is disabled (HELIUS_WEBHOOK_ENABLED is not true)"
                .into(),
        ));
    };
    let detector = solana_pool.detector.clone().ok_or_else(|| {
        log::warn!("[HELIUS] Webhook rejected: Solana detector handle missing in this process");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Solana detector is not running in this process".to_string(),
        )
    })?;

    if let Some(expected) = helius.auth_header() {
        let received = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !verify_auth_header(expected, received) {
            log::warn!(
                "[HELIUS] Webhook rejected: Authorization header mismatch (source={})",
                source_ip
            );
            return Err((StatusCode::UNAUTHORIZED, "invalid Authorization header".into()));
        }
    }

    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            // Helius's "Test Webhook" button sometimes sends an empty body
            // or a non-JSON payload. Don't 500 — answer 200 so the dashboard
            // shows green, and log enough to debug.
            let preview: String = String::from_utf8_lossy(&body).chars().take(200).collect();
            log::warn!(
                "[HELIUS] Webhook body is not valid JSON ({} bytes, error={}): {:?}",
                body_len,
                error,
                preview
            );
            return Ok(Json(SolanaWebhookResponse { accepted: 0 }));
        }
    };

    let candidates = collect_candidate_addresses(&payload);
    if candidates.is_empty() {
        // Most likely cause: Helius sent its synthetic test payload
        // (sample addresses unrelated to our pool). Log at INFO so the
        // operator can confirm reachability when clicking "Test Webhook".
        log::info!(
            "[HELIUS] Webhook payload parsed but contained no recognisable Solana addresses (probably a test payload). source={} body_bytes={}",
            source_ip,
            body_len
        );
        return Ok(Json(SolanaWebhookResponse { accepted: 0 }));
    }

    let candidate_count = candidates.len();
    log::info!(
        "[HELIUS] Webhook payload contains {} candidate address(es) — dispatching background scan and ack'ing 200",
        candidate_count
    );

    // Hand the actual scan off to a background task. The scan path can
    // take 5-15s on a real deposit (Redis SCAN of all assignments,
    // multiple RPC calls per matched address, sweep + outbound webhook
    // emission), which exceeds Helius's webhook delivery timeout
    // (~10s). Returning 200 immediately is the documented pattern for
    // long-running webhook handlers; correctness still holds because
    // (a) the polling loop is the safety net, and (b) sweep/credit
    // dedup via `state.credited_signatures` prevents double-credits if
    // Helius retries before our background task finishes.
    let detector_for_task = detector.clone();
    tokio::spawn(async move {
        match detector_for_task
            .process_address_set_now(&candidates)
            .await
        {
            Ok(scanned) if scanned.is_empty() => {
                log::info!(
                    "[HELIUS] background scan: {} candidate(s) had no matching active assignment (orphan/external — polling will recover if relevant)",
                    candidate_count
                );
            }
            Ok(scanned) => {
                log::info!(
                    "[HELIUS] background scan completed for {} managed address(es): {}",
                    scanned.len(),
                    scanned.join(", ")
                );
            }
            Err(error) => {
                log::warn!(
                    "[HELIUS] background scan failed (polling will retry): {error}"
                );
            }
        }
    });

    Ok(Json(SolanaWebhookResponse {
        accepted: candidate_count,
    }))
}

async fn handle_evm_recover(
    pool: Option<&EthereumPoolApiState>,
    payload: RecoverRequest,
) -> Result<Json<RecoverResponse>, (StatusCode, String)> {
    let Some(pool) = pool else {
        return Err((
            StatusCode::BAD_REQUEST,
            "EVM address pool is not configured".into(),
        ));
    };
    let detector = pool.detector.clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        format!(
            "{} detector is not running in this process",
            pool.chain.ticker()
        ),
    ))?;

    let user_id = payment_user_id(&payload.user_id)?;
    let response = detector
        .recover_txid(payload.txid.trim(), &user_id)
        .await
        .map_err(map_internal_error)?;
    Ok(Json(response))
}

async fn handle_ethereum_recover(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, (StatusCode, String)> {
    handle_evm_recover(state.ethereum_pool.as_ref(), payload).await
}

async fn handle_base_recover(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, (StatusCode, String)> {
    handle_evm_recover(state.base_pool.as_ref(), payload).await
}

async fn handle_bitcoin_recover(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, (StatusCode, String)> {
    handle_btc_recover(&state, Chain::Bitcoin, payload).await
}

async fn handle_litecoin_recover(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, (StatusCode, String)> {
    handle_btc_recover(&state, Chain::Litecoin, payload).await
}

async fn handle_btc_recover(
    state: &AppState,
    chain: Chain,
    payload: RecoverRequest,
) -> Result<Json<RecoverResponse>, (StatusCode, String)> {
    let recovery = state.bitcoin_detectors.get(&chain).ok_or((
        StatusCode::BAD_REQUEST,
        format!(
            "{} detector is not configured (set {}_XPUB to enable)",
            chain.ticker(),
            chain.ticker(),
        ),
    ))?;

    let user_id_str = payment_user_id(&payload.user_id)?;
    let user_id_u32: u32 = user_id_str.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "{} recovery: user_id must be a non-negative xpub derivation index",
                chain.ticker()
            ),
        )
    })?;

    let response = recovery
        .detector
        .recover_txid(payload.txid.trim(), user_id_u32, recovery.max_derivation_index)
        .await
        .map_err(map_internal_error)?;
    if matches!(response.status, RecoverStatus::WrongUser) {
        log::warn!(
            "[{}] /recover-txid rejected for user_id={user_id_u32}: address ownership mismatch",
            chain.ticker()
        );
    }
    Ok(Json(response))
}

fn build_config(chain: Chain, xpub: String) -> DetectorConfig {
    let state_file_default = match chain {
        Chain::Bitcoin => "btc_detector_state.json",
        Chain::Litecoin => "ltc_detector_state.json",
        Chain::Solana => "sol_detector_state.json",
        Chain::Ethereum => "eth_detector_state.json",
        Chain::Base => "base_detector_state.json",
    };
    let state_file_var = match chain {
        Chain::Bitcoin => "BTC_STATE_FILE",
        Chain::Litecoin => "LTC_STATE_FILE",
        Chain::Solana => "SOL_STATE_FILE",
        Chain::Ethereum => "ETH_STATE_FILE",
        Chain::Base => "BASE_STATE_FILE",
    };

    let (sweep_xpriv_var, sweep_dest_var) = match chain {
        Chain::Bitcoin => ("BTC_XPRIV", "BTC_SWEEP_DESTINATION"),
        Chain::Litecoin => ("LTC_XPRIV", "LTC_SWEEP_DESTINATION"),
        _ => ("", ""),
    };
    let sweep_xpriv = std::env::var(sweep_xpriv_var)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let sweep_destination = std::env::var(sweep_dest_var)
        .ok()
        .filter(|value| !value.trim().is_empty());

    DetectorConfig {
        chain,
        xpub,
        webhook_url: std::env::var("WEBHOOK_URL").expect("WEBHOOK_URL env var required"),
        webhook_hmac_secret: std::env::var("WEBHOOK_SECRET")
            .expect("WEBHOOK_SECRET env var required"),
        basic_auth: BasicAuth {
            username: std::env::var("AUTH_USER").unwrap_or_default(),
            password: std::env::var("AUTH_PASS").unwrap_or_default(),
        },
        poll_interval_secs: {
            let chain_var = match chain {
                Chain::Bitcoin => "BTC_POLL_INTERVAL",
                Chain::Litecoin => "LTC_POLL_INTERVAL",
                Chain::Solana => "SOL_POLL_INTERVAL",
                Chain::Ethereum => "ETH_POLL_INTERVAL",
                Chain::Base => "BASE_POLL_INTERVAL",
            };
            std::env::var(chain_var)
                .or_else(|_| std::env::var("POLL_INTERVAL"))
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(30)
        },
        proxy_url: std::env::var("PROXY").ok(),
        state_file: std::env::var(state_file_var)
            .or_else(|_| std::env::var("STATE_FILE"))
            .unwrap_or_else(|_| state_file_default.to_string()),
        fiat_currency: std::env::var("FIAT_CURRENCY").unwrap_or_else(|_| "EUR".to_string()),
        retry: RetryConfig {
            max_retries: std::env::var("MAX_RETRIES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5),
            base_delay_ms: std::env::var("RETRY_BASE_DELAY_MS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1000),
        },
        explorer_api_url: explorer_api_config(chain),
        min_confirmations: {
            let chain_var = match chain {
                Chain::Bitcoin => "BTC_MIN_CONFIRMATIONS",
                Chain::Litecoin => "LTC_MIN_CONFIRMATIONS",
                Chain::Solana => "SOL_MIN_CONFIRMATIONS",
                Chain::Ethereum => "ETH_MIN_CONFIRMATIONS",
                Chain::Base => "BASE_MIN_CONFIRMATIONS",
            };
            std::env::var(chain_var)
                .or_else(|_| std::env::var("MIN_CONFIRMATIONS"))
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1)
        },
        skip_initial_block_sync: chain_env_bool(
            chain,
            "SKIP_INITIAL_BLOCK_SYNC",
            "SKIP_INITIAL_BLOCK_SYNC",
        ),
        sweep_xpriv,
        sweep_destination,
        sweep_fee_rate_sats_per_vb: {
            let chain_var = match chain {
                Chain::Bitcoin => "BTC_SWEEP_FEE_RATE_SATS_PER_VB",
                Chain::Litecoin => "LTC_SWEEP_FEE_RATE_SATS_PER_VB",
                _ => "",
            };
            std::env::var(chain_var)
                .or_else(|_| std::env::var("SWEEP_FEE_RATE_SATS_PER_VB"))
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5)
        },
        sweep_min_sat: {
            let chain_var = match chain {
                Chain::Bitcoin => "BTC_SWEEP_MIN_SAT",
                Chain::Litecoin => "LTC_SWEEP_MIN_SAT",
                _ => "",
            };
            std::env::var(chain_var)
                .or_else(|_| std::env::var("SWEEP_MIN_SAT"))
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5_000)
        },
        sweep_max_fee_ratio: {
            let chain_var = match chain {
                Chain::Bitcoin => "BTC_MAX_FEE_RATIO",
                Chain::Litecoin => "LTC_MAX_FEE_RATIO",
                _ => "",
            };
            std::env::var(chain_var)
                .or_else(|_| std::env::var("MAX_FEE_RATIO"))
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0.10)
        },
    }
}

fn build_solana_config() -> SolanaConfig {
    SolanaConfig {
        rpc_url: std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.mainnet.solana.com".to_string()),
        wallet_pool_file: std::env::var("SOLANA_WALLET_POOL_FILE")
            .expect("SOLANA_WALLET_POOL_FILE env var required for CHAIN=solana"),
        secure_deposit_address: std::env::var("SOLANA_DEPOSIT_ADDRESS")
            .expect("SOLANA_DEPOSIT_ADDRESS env var required for CHAIN=solana"),
        webhook_url: std::env::var("WEBHOOK_URL").expect("WEBHOOK_URL env var required"),
        webhook_hmac_secret: std::env::var("WEBHOOK_SECRET")
            .expect("WEBHOOK_SECRET env var required"),
        redis_url: std::env::var("REDIS_URL").expect("REDIS_URL env var required"),
        reservation_ttl_secs: std::env::var("SOLANA_RESERVATION_TTL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(3600),
        state_file: std::env::var("SOL_STATE_FILE")
            .or_else(|_| std::env::var("STATE_FILE"))
            .unwrap_or_else(|_| "sol_detector_state.json".to_string()),
        poll_interval_secs: std::env::var("SOL_POLL_INTERVAL")
            .or_else(|_| std::env::var("POLL_INTERVAL"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(60),
        min_confirmations: std::env::var("SOL_MIN_CONFIRMATIONS")
            .or_else(|_| std::env::var("MIN_CONFIRMATIONS"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1),
        fiat_currency: std::env::var("FIAT_CURRENCY").unwrap_or_else(|_| "EUR".to_string()),
        proxy_url: proxy_env_var(&["SOLANA_PROXY", "SOL_PROXY", "PROXY"]),
        max_retries: std::env::var("MAX_RETRIES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(5),
        retry_base_delay_ms: std::env::var("RETRY_BASE_DELAY_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1000),
        min_deposit_fiat: std::env::var("SOL_MIN_DEPOSIT_FIAT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.5),
        gas_tank_private_key: std::env::var("SOLANA_GAS_TANK_PRIVATE_KEY")
            .or_else(|_| std::env::var("SOLANA_FEE_PAYER_PRIVATE_KEY"))
            .ok()
            .filter(|value| !value.trim().is_empty()),
        gas_tank_target_usd: std::env::var("SOLANA_GAS_TANK_TARGET_USD")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10.0),
        gas_tank_check_interval_secs: std::env::var("SOLANA_GAS_TANK_INTERVAL_SECS")
            .or_else(|_| std::env::var("SOLANA_GAS_TANK_CHECK_INTERVAL_SECS"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(900),
        max_fee_ratio: std::env::var("SOLANA_MAX_FEE_RATIO")
            .or_else(|_| std::env::var("SOL_MAX_FEE_RATIO"))
            .or_else(|_| std::env::var("MAX_FEE_RATIO"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.10),
        core_api_url: std::env::var("CORE_API_INTERNAL_URL")
            .or_else(|_| std::env::var("BACKEND_API_INTERNAL_URL"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        internal_service_token: std::env::var("INTERNAL_SERVICE_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    }
}

/// Parse `{prefix}_ETHERSCAN_ENABLED`. Defaults to `true`. Setting the
/// chain-specific var to `false`/`0`/`no`/`off` disables the etherscan client
/// for that chain only — useful when the free Etherscan plan covers
/// Ethereum mainnet but rejects Base.
fn parse_etherscan_enabled_env(prefix: &str) -> bool {
    match std::env::var(format!("{prefix}_ETHERSCAN_ENABLED")) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "0" | "false" | "no" | "off" | "disabled" => false,
            _ => true,
        },
        Err(_) => true,
    }
}

fn build_evm_config(chain: Chain) -> EthereumConfig {
    assert!(chain.is_evm(), "build_evm_config requires an EVM chain");
    let prefix = chain_env_prefix(chain);
    let chain_lower = chain.name().to_ascii_lowercase();

    let default_rpc_url = match chain {
        Chain::Ethereum => "https://cloudflare-eth.com",
        Chain::Base => "https://mainnet.base.org",
        _ => unreachable!(),
    };
    let default_chain_id: u64 = match chain {
        Chain::Ethereum => 1,
        Chain::Base => 8453,
        _ => unreachable!(),
    };
    let default_state_file = match chain {
        Chain::Ethereum => "eth_detector_state.json",
        Chain::Base => "base_detector_state.json",
        _ => unreachable!(),
    };

    let chain_id = std::env::var(format!("{prefix}_CHAIN_ID"))
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default_chain_id);

    // Etherscan's free tier does NOT cover Base. Set BASE_ETHERSCAN_ENABLED=false
    // to skip the etherscan client on Base while keeping it on Ethereum.
    let etherscan_enabled = parse_etherscan_enabled_env(prefix);
    let etherscan = if etherscan_enabled {
        EtherscanConfig::from_env().map(|mut config| {
            config.chain_id = chain_id;
            config
        })
    } else {
        log::info!(
            "[{}] Etherscan internal-tx scan disabled via {prefix}_ETHERSCAN_ENABLED=false",
            chain.ticker()
        );
        None
    };

    EthereumConfig {
        chain,
        rpc_url: std::env::var(format!("{prefix}_RPC_URL"))
            .unwrap_or_else(|_| default_rpc_url.to_string()),
        chain_id,
        wallet_pool_file: std::env::var(format!("{prefix}_WALLET_POOL_FILE")).unwrap_or_else(
            |_| panic!("{prefix}_WALLET_POOL_FILE env var required for CHAIN={chain_lower}"),
        ),
        gas_tank_private_key: std::env::var(format!("{prefix}_GAS_TANK_PRIVATE_KEY"))
            .unwrap_or_else(|_| {
                panic!("{prefix}_GAS_TANK_PRIVATE_KEY env var required for CHAIN={chain_lower}")
            }),
        ledger_address: std::env::var(format!("{prefix}_LEDGER_ADDRESS")).unwrap_or_else(|_| {
            panic!("{prefix}_LEDGER_ADDRESS env var required for CHAIN={chain_lower}")
        }),
        webhook_url: std::env::var("WEBHOOK_URL").expect("WEBHOOK_URL env var required"),
        webhook_hmac_secret: std::env::var("WEBHOOK_SECRET")
            .expect("WEBHOOK_SECRET env var required"),
        redis_url: ethereum_reservation_store_url_from_env(chain),
        reservation_ttl_secs: std::env::var(format!("{prefix}_RESERVATION_TTL_SECS"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(3600),
        state_file: std::env::var(format!("{prefix}_STATE_FILE"))
            .or_else(|_| std::env::var("STATE_FILE"))
            .unwrap_or_else(|_| default_state_file.to_string()),
        poll_interval_secs: std::env::var(format!("{prefix}_POLL_INTERVAL"))
            .or_else(|_| std::env::var("POLL_INTERVAL"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(30),
        min_confirmations: std::env::var(format!("{prefix}_MIN_CONFIRMATIONS"))
            .or_else(|_| std::env::var("MIN_CONFIRMATIONS"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(match chain {
                Chain::Ethereum => 12,
                Chain::Base => 5,
                _ => 12,
            }),
        fiat_currency: std::env::var("FIAT_CURRENCY").unwrap_or_else(|_| "EUR".to_string()),
        proxy_url: {
            let chain_proxy_var = format!("{prefix}_PROXY");
            proxy_env_var(&[chain_proxy_var.as_str(), "PROXY"])
        },
        max_blocks_per_cycle: std::env::var(format!("{prefix}_MAX_BLOCKS_PER_CYCLE"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(250),
        start_block: std::env::var(format!("{prefix}_START_BLOCK"))
            .ok()
            .and_then(|value| value.parse().ok()),
        gas_tank_target_usd: std::env::var(format!("{prefix}_GAS_TANK_TARGET_USD"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20.0),
        gas_tank_check_interval_secs: std::env::var(format!("{prefix}_GAS_TANK_INTERVAL_SECS"))
            .or_else(|_| std::env::var(format!("{prefix}_GAS_TANK_CHECK_INTERVAL_SECS")))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(900),
        token_transfer_gas_limit: std::env::var(format!("{prefix}_TOKEN_TRANSFER_GAS_LIMIT"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100_000),
        gas_top_up_multiplier: std::env::var(format!("{prefix}_GAS_TOP_UP_MULTIPLIER"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1.25),
        max_fee_ratio: std::env::var(format!("{prefix}_MAX_FEE_RATIO"))
            .or_else(|_| std::env::var("MAX_FEE_RATIO"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.10),
        rpc_min_request_interval_ms: std::env::var(format!(
            "{prefix}_RPC_MIN_REQUEST_INTERVAL_MS"
        ))
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(match chain {
            Chain::Ethereum => 0,
            Chain::Base => 200,
            _ => 0,
        }),
        etherscan,
    }
}

fn build_chain_info(chain: Chain) -> Option<(ChainInfo, String)> {
    let xpub_var = match chain {
        Chain::Bitcoin => "BTC_XPUB",
        Chain::Litecoin => "LTC_XPUB",
        Chain::Solana | Chain::Ethereum | Chain::Base => return None,
    };
    let xpub = match std::env::var(xpub_var) {
        Ok(value) if !value.is_empty() => value,
        _ => return None,
    };

    let (state_file_var, state_file_default) = match chain {
        Chain::Bitcoin => ("BTC_STATE_FILE", "btc_detector_state.json"),
        Chain::Litecoin => ("LTC_STATE_FILE", "ltc_detector_state.json"),
        Chain::Solana => ("SOL_STATE_FILE", "sol_detector_state.json"),
        Chain::Ethereum => ("ETH_STATE_FILE", "eth_detector_state.json"),
        Chain::Base => ("BASE_STATE_FILE", "base_detector_state.json"),
    };
    let state_file = std::env::var(state_file_var)
        .or_else(|_| std::env::var("STATE_FILE"))
        .unwrap_or_else(|_| state_file_default.to_string());

    let explorer_api_urls = chain.explorer_api_urls(explorer_api_config(chain).as_deref());

    Some((
        ChainInfo {
            chain,
            address_source: AddressSource::Xpub(xpub.clone()),
            state_file,
            endpoint: HealthEndpoint::ExplorerApis(explorer_api_urls),
        },
        xpub,
    ))
}

fn build_solana_chain_info() -> Option<ChainInfo> {
    let secure_deposit_address = match std::env::var("SOLANA_DEPOSIT_ADDRESS") {
        Ok(value) if !value.is_empty() => value,
        _ => return None,
    };

    let state_file = std::env::var("SOL_STATE_FILE")
        .or_else(|_| std::env::var("STATE_FILE"))
        .unwrap_or_else(|_| "sol_detector_state.json".to_string());
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet.solana.com".to_string());

    Some(ChainInfo {
        chain: Chain::Solana,
        address_source: AddressSource::Static(secure_deposit_address),
        state_file,
        endpoint: HealthEndpoint::SolanaRpc(rpc_url),
    })
}

fn build_evm_chain_info(config: &EthereumConfig, gas_tank_address: String) -> ChainInfo {
    ChainInfo {
        chain: config.chain,
        address_source: AddressSource::Static(gas_tank_address),
        state_file: config.state_file.clone(),
        endpoint: HealthEndpoint::EthereumRpc(config.rpc_url.clone()),
    }
}

fn build_solana_pool_api_state(
    config: &SolanaConfig,
    wallets: SharedSolanaWallets,
    detector: Option<Arc<SolanaDetector>>,
    helius: Option<Arc<HeliusWebhookClient>>,
) -> Result<SolanaPoolApiState, DetectorError> {
    Ok(SolanaPoolApiState {
        wallets,
        wallet_pool_path: config.wallet_pool_file.clone(),
        redis_url: config.redis_url.clone(),
        secure_deposit_address: config.secure_deposit_address.clone(),
        detector,
        helius,
    })
}

/// Build the Helius webhook client from env vars. Returns `Ok(None)` when
/// `HELIUS_WEBHOOK_ENABLED` is unset or falsy — the API then runs in the
/// original polling-only mode and `/solana/webhook` returns 503 to any
/// caller. Panics only on misconfiguration (enabled flag set but a
/// required value is missing or invalid).
fn build_helius_client() -> Option<Arc<HeliusWebhookClient>> {
    match HeliusWebhookConfig::from_env() {
        Ok(None) => None,
        Ok(Some(config)) => match HeliusWebhookClient::new(config) {
            Ok(client) => {
                log::info!(
                    "[HELIUS] Webhook integration enabled — /solana/webhook will accept Helius pushes"
                );
                Some(Arc::new(client))
            }
            Err(error) => {
                log::error!("[HELIUS] Failed to build webhook client: {error}");
                None
            }
        },
        Err(error) => panic!("Invalid Helius webhook configuration: {error}"),
    }
}

const DEFAULT_HELIUS_MAX_WATCH_ADDRESSES: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeliusWatchMode {
    /// Register every wallet in the pool (owner + ATAs for each
    /// configured SPL token) on the Helius webhook. Cheaper to operate
    /// (no per-assignment PATCH, no race between assignment and first
    /// deposit) and also catches deposits to wallets whose assignment
    /// has been released — the webhook still fires, the handler simply
    /// finds no active assignment and skips, while the polling/orphan
    /// sweep recovers the funds. Used by default while the projected
    /// address count stays under `HELIUS_MAX_WATCH_ADDRESSES`.
    WholePool,
    /// Register only the wallets currently assigned to a user, plus
    /// their ATAs. Used as a fallback when watching the whole pool
    /// would push the webhook past the configured limit. Restores the
    /// previous behaviour: addresses are added on `/solana/address` and
    /// cleared on `/admin/reservations/cancel-all`.
    AssignedOnly,
}

fn helius_max_watch_addresses() -> usize {
    std::env::var("HELIUS_MAX_WATCH_ADDRESSES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_HELIUS_MAX_WATCH_ADDRESSES)
}

fn helius_watch_mode(detector: &SolanaDetector) -> HeliusWatchMode {
    let limit = helius_max_watch_addresses();
    let projected = detector.webhook_address_set().len();
    if projected <= limit {
        HeliusWatchMode::WholePool
    } else {
        HeliusWatchMode::AssignedOnly
    }
}

/// Best-effort: push the right set of addresses onto the Helius webhook
/// at startup. In `WholePool` mode that's every wallet (owner + ATAs); in
/// `AssignedOnly` mode it's only currently active assignments. Drift from
/// either side (someone edited the webhook in the dashboard, a new wallet
/// was generated since the last run) converges on the next call. Logged
/// failures do not abort startup — polling fallback still works.
async fn sync_helius_webhook_addresses(
    detector: &SolanaDetector,
    helius: &HeliusWebhookClient,
    redis_url: &str,
) {
    let mode = helius_watch_mode(detector);
    let addresses = match mode {
        HeliusWatchMode::WholePool => detector.webhook_address_set(),
        HeliusWatchMode::AssignedOnly => {
            match load_active_reservations(redis_url).await {
                Ok(assignments) => {
                    let mut out = Vec::with_capacity(assignments.len() * 4);
                    for assignment in assignments {
                        out.extend(detector.webhook_addresses_for_wallet(&assignment.address));
                    }
                    out
                }
                Err(error) => {
                    log::warn!(
                        "[HELIUS] Failed to load assignments for startup sync: {error}"
                    );
                    return;
                }
            }
        }
    };
    let count = addresses.len();
    match helius.replace_addresses(addresses).await {
        Ok(()) => log::info!(
            "[HELIUS] Startup sync OK — mode={:?}, {} address(es) registered (threshold: {})",
            mode,
            count,
            helius_max_watch_addresses(),
        ),
        Err(error) => log::warn!(
            "[HELIUS] Startup sync failed (will rely on per-assignment add): {error}"
        ),
    }
}

fn build_ethereum_pool_api_state(
    config: &EthereumConfig,
    wallets: SharedEthereumWallets,
    gas_tank_address: String,
    detector: Option<Arc<EthereumDetector>>,
) -> Result<EthereumPoolApiState, DetectorError> {
    Ok(EthereumPoolApiState {
        chain: config.chain,
        wallets,
        wallet_pool_path: config.wallet_pool_file.clone(),
        redis_url: config.redis_url.clone(),
        gas_tank_address,
        ledger_address: config.ledger_address.clone(),
        detector,
    })
}

async fn run_detector(detector: Arc<ChainDetector>, max_index: u32) {
    let ticker = detector.chain().ticker();
    loop {
        if let Err(error) = detector.run_block_scan_loop(None, max_index).await {
            log::error!(
                "[{}] Block scan loop error: {error} - restarting in 10s",
                ticker
            );
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

async fn run_solana_detector(detector: Arc<SolanaDetector>) {
    if let Err(error) = detector.sweep_orphan_balances().await {
        log::warn!("[SOL] Startup orphan sweep failed: {error}");
    }
    loop {
        if let Err(error) = detector.run_block_scan_loop(None, 0).await {
            log::error!("[SOL] Solana scan loop error: {error} - restarting in 10s");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

/// Fast-cadence loop that retries pending-but-not-yet-credited Solana
/// payments. Independent of `run_solana_detector` (full scan): this one
/// touches no addresses, just iterates the pending queue every
/// `SOL_PENDING_POLL_INTERVAL` seconds (default 30) and retries the
/// sweep + credit step. Cheap when pending is empty (one mutex read).
async fn run_solana_pending_confirmation_loop(detector: Arc<SolanaDetector>) {
    let interval_secs = std::env::var("SOL_PENDING_POLL_INTERVAL")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30);
    let interval = std::time::Duration::from_secs(interval_secs);
    log::info!(
        "[SOL] Pending-confirmation loop running every {interval_secs}s (override via SOL_PENDING_POLL_INTERVAL)"
    );
    loop {
        tokio::time::sleep(interval).await;
        let started = std::time::Instant::now();
        match detector.confirm_pending_payments().await {
            Ok(0) => {}
            Ok(count) => log::info!(
                "[SOL] Pending-confirmation tick: processed {count} entry(ies) in {:.2}s",
                started.elapsed().as_secs_f64()
            ),
            Err(error) => log::warn!(
                "[SOL] Pending-confirmation tick failed (will retry next interval): {error}"
            ),
        }
    }
}

async fn run_ethereum_detector(detector: Arc<EthereumDetector>, ticker: &'static str) {
    if let Err(error) = detector.sweep_orphan_balances().await {
        log::warn!("[{ticker}] Startup orphan sweep failed: {error}");
    }
    loop {
        if let Err(error) = detector.run_block_scan_loop(None, 0).await {
            log::error!("[{ticker}] EVM scan loop error: {error} - restarting in 10s");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

fn load_solana_last_processed_signature(path: &str) -> Option<String> {
    let file = std::path::Path::new(path);
    if !file.exists() {
        return None;
    }

    let data = match std::fs::read_to_string(file) {
        Ok(data) => data,
        Err(error) => {
            log::warn!("[SOL] Failed to read state file '{}': {}", path, error);
            return None;
        }
    };

    match serde_json::from_str::<SolanaHealthState>(&data) {
        Ok(state) => state
            .addresses
            .values()
            .find_map(|cursor| cursor.last_processed_signature.clone()),
        Err(error) => {
            log::warn!("[SOL] Failed to parse state file '{}': {}", path, error);
            None
        }
    }
}

fn load_ethereum_last_scanned_block(path: &str) -> Option<u64> {
    let file = std::path::Path::new(path);
    if !file.exists() {
        return None;
    }

    let data = match std::fs::read_to_string(file) {
        Ok(data) => data,
        Err(error) => {
            log::warn!("[ETH] Failed to read state file '{}': {}", path, error);
            return None;
        }
    };

    match serde_json::from_str::<EthereumHealthState>(&data) {
        Ok(state) => state.last_scanned_block,
        Err(error) => {
            log::warn!("[ETH] Failed to parse state file '{}': {}", path, error);
            None
        }
    }
}

fn map_assignment_error(error: DetectorError) -> (StatusCode, String) {
    let message = error.to_string();
    if message.contains("user_id cannot be empty") {
        (StatusCode::BAD_REQUEST, message)
    } else if message.contains("MAX_POOL_SIZE") {
        (StatusCode::CONFLICT, message)
    } else {
        map_internal_error(error)
    }
}

fn map_claim_error(error: DetectorError) -> (StatusCode, String) {
    let message = error.to_string();
    if message.contains("No Solana deposit address assigned")
        || message.contains("No Ethereum deposit address assigned")
        || message.contains("No Base deposit address assigned")
    {
        (StatusCode::NOT_FOUND, message)
    } else {
        map_internal_error(error)
    }
}

fn map_internal_error(error: DetectorError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();

    let chain_str = std::env::var("CHAIN").unwrap_or_else(|_| "bitcoin".to_string());
    let max_index: u32 = std::env::var("MAX_DERIVATION_INDEX")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let mut chains: Vec<Chain> = match chain_str.to_lowercase().as_str() {
        "both" => vec![Chain::Bitcoin, Chain::Litecoin],
        "solbtc" => vec![Chain::Bitcoin, Chain::Solana],
        "all" => vec![
            Chain::Bitcoin,
            Chain::Litecoin,
            Chain::Solana,
            Chain::Ethereum,
            Chain::Base,
        ],
        other if other.contains(',') => other
            .split(',')
            .map(|piece| piece.trim())
            .filter(|piece| !piece.is_empty())
            .map(|piece| piece.parse::<Chain>().expect("Invalid chain in CHAIN list"))
            .collect(),
        other => vec![other.parse().expect(
            "Invalid CHAIN value (expected: bitcoin, litecoin, solana, ethereum, base, btc, ltc, sol, eth, both, solbtc, all)",
        )],
    };

    if env_bool("DISABLE_BASE").unwrap_or(false) {
        let before = chains.len();
        chains.retain(|chain| *chain != Chain::Base);
        if chains.len() < before {
            log::info!("[BASE] Disabled via DISABLE_BASE=true — skipping detector, sweep, orphan scan, and /base/* endpoints will return errors");
        }
    }

    let mut chain_infos = Vec::new();
    let mut detector_handles = Vec::new();
    let mut bitcoin_detectors: HashMap<Chain, BitcoinRecoveryState> = HashMap::new();
    let mut solana_pool = None;
    let mut ethereum_pool = None;
    let mut base_pool = None;

    for chain in &chains {
        match chain {
            Chain::Bitcoin | Chain::Litecoin => {
                if let Some((info, xpub)) = build_chain_info(*chain) {
                    if let AddressSource::Xpub(ref configured_xpub) = info.address_source {
                        log::info!(
                            "[{}] Configured with xpub {}...{}",
                            chain.ticker(),
                            &configured_xpub[..8],
                            &configured_xpub[configured_xpub.len() - 4..]
                        );
                    }

                    let config = build_config(*chain, xpub);
                    let detector = Arc::new(
                        ChainDetector::new(config)
                            .expect(&format!("Failed to create {} detector", chain.ticker())),
                    );

                    log::info!(
                        "[{}] Detector started - address 0: {}",
                        chain.ticker(),
                        detector.derive_address(0).unwrap()
                    );

                    let detector_handle = detector.clone();
                    detector_handles.push(tokio::spawn(async move {
                        run_detector(detector_handle, max_index).await;
                    }));

                    bitcoin_detectors.insert(
                        *chain,
                        BitcoinRecoveryState {
                            detector: detector.clone(),
                            max_derivation_index: max_index,
                        },
                    );
                    chain_infos.push(info);
                } else {
                    let xpub_var = match chain {
                        Chain::Bitcoin => "BTC_XPUB",
                        Chain::Litecoin => "LTC_XPUB",
                        Chain::Solana | Chain::Ethereum | Chain::Base => unreachable!(),
                    };
                    log::warn!("[{}] {} not set, skipping", chain.ticker(), xpub_var);
                }
            }
            Chain::Solana => {
                if let Some(info) = build_solana_chain_info() {
                    let config = build_solana_config();
                    let tokens =
                        parse_spl_tokens(std::env::var("SOLANA_SPL_TOKENS").ok().as_deref())
                            .expect("Invalid SOLANA_SPL_TOKENS");
                    let wallets = shared_wallets(
                        load_wallet_pool(&config.wallet_pool_file)
                            .expect("Failed to load Solana wallet pool"),
                    );
                    let detector = Arc::new(
                        SolanaDetector::new(config.clone(), tokens, wallets.clone())
                            .expect("Failed to create SOL detector"),
                    );

                    // Reconcile per-user indices and drop any duplicate
                    // assignments left by the historical race in
                    // `assign_wallet_for_user` (concurrent calls for the
                    // same user_id used to create multiple
                    // `solana:assignment:*` entries, leading to deposit
                    // addresses that "changed" between page loads).
                    // Idempotent — safe to run every boot.
                    match crypto_payment_detector::consolidate_assignments(
                        &config.redis_url,
                    )
                    .await
                    {
                        Ok((indexed, dropped)) => {
                            if dropped > 0 {
                                log::warn!(
                                    "[SOL] Boot consolidation: indexed {indexed} user(s), DROPPED {dropped} duplicate assignment(s) (orphan sweep will recover any funds left on dropped wallets)"
                                );
                            } else {
                                log::info!(
                                    "[SOL] Boot consolidation: indexed {indexed} user(s) (no duplicates)"
                                );
                            }
                        }
                        Err(error) => {
                            log::warn!(
                                "[SOL] Boot consolidation failed (will continue, lookups may be slower): {error}"
                            );
                        }
                    }

                    let helius_client = build_helius_client();
                    if let Some(client) = helius_client.as_ref() {
                        sync_helius_webhook_addresses(
                            detector.as_ref(),
                            client.as_ref(),
                            &config.redis_url,
                        )
                        .await;
                    }
                    let pool_state = build_solana_pool_api_state(
                        &config,
                        wallets,
                        Some(detector.clone()),
                        helius_client,
                    )
                    .expect("Failed to build Solana pool state");

                    log::info!(
                        "[SOL] Detector started - ledger: {} - gas tank: {} - managed wallets: {} - tokens: {} - permanent address assignments (no TTL)",
                        detector.ledger_address(),
                        detector
                            .gas_tank_address()
                            .unwrap_or_else(|| "<not configured>".to_string()),
                        detector.wallet_count(),
                        detector.token_count(),
                    );
                    for (symbol, mint, decimals) in detector.token_summary() {
                        log::info!(
                            "[SOL] SPL token configured: {} mint={} decimals={}",
                            symbol,
                            mint,
                            decimals
                        );
                    }

                    let detector_handle = detector.clone();
                    detector_handles.push(tokio::spawn(async move {
                        run_solana_detector(detector_handle).await;
                    }));
                    let pending_handle = detector.clone();
                    detector_handles.push(tokio::spawn(async move {
                        run_solana_pending_confirmation_loop(pending_handle).await;
                    }));

                    chain_infos.push(info);
                    solana_pool = Some(pool_state);
                } else {
                    log::warn!("[SOL] SOLANA_DEPOSIT_ADDRESS not set, skipping");
                }
            }
            Chain::Ethereum | Chain::Base => {
                let evm_chain = *chain;
                let ticker = evm_chain.ticker();
                let config = build_evm_config(evm_chain);
                let tokens_env = format!("{}_ERC20_TOKENS", chain_env_prefix(evm_chain));
                let tokens = parse_erc20_tokens(std::env::var(&tokens_env).ok().as_deref())
                    .unwrap_or_else(|e| panic!("Invalid {tokens_env}: {e}"));
                let wallets = shared_ethereum_wallets(
                    load_ethereum_wallet_pool(evm_chain, &config.wallet_pool_file).unwrap_or_else(
                        |e| panic!("Failed to load {} wallet pool: {e}", evm_chain.name()),
                    ),
                );
                let detector = Arc::new(
                    EthereumDetector::new(config.clone(), tokens, wallets.clone()).unwrap_or_else(
                        |e| panic!("Failed to create {ticker} detector: {e}"),
                    ),
                );
                let gas_tank_address = detector.gas_tank_address();
                let pool_state = build_ethereum_pool_api_state(
                    &config,
                    wallets,
                    gas_tank_address.clone(),
                    Some(detector.clone()),
                )
                .unwrap_or_else(|e| panic!("Failed to build {} pool state: {e}", evm_chain.name()));

                log::info!(
                    "[{}] Detector started - gas tank: {} - ledger: {} - managed wallets: {} - tokens: {} - permanent address assignments (no TTL)",
                    ticker,
                    gas_tank_address,
                    detector.ledger_address(),
                    detector.wallet_count(),
                    detector.token_count(),
                );

                let detector_handle = detector.clone();
                detector_handles.push(tokio::spawn(async move {
                    run_ethereum_detector(detector_handle, ticker).await;
                }));

                chain_infos.push(build_evm_chain_info(&config, gas_tank_address));
                match evm_chain {
                    Chain::Ethereum => ethereum_pool = Some(pool_state),
                    Chain::Base => base_pool = Some(pool_state),
                    _ => unreachable!(),
                }
            }
        }
    }

    if chain_infos.is_empty() {
        eprintln!(
            "No chain configured. Set BTC_XPUB/LTC_XPUB, SOLANA_DEPOSIT_ADDRESS, ETH_GAS_TANK_PRIVATE_KEY, or BASE_GAS_TANK_PRIVATE_KEY."
        );
        std::process::exit(1);
    }

    let state = Arc::new(AppState {
        chains: chain_infos,
        solana_pool,
        ethereum_pool,
        base_pool,
        bitcoin_detectors,
    });

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/derive", get(handle_derive))
        .route("/solana/address", post(handle_solana_address))
        .route("/solana/rotate", post(handle_solana_rotate))
        .route("/solana/active", get(handle_solana_active))
        .route("/solana/claim", post(handle_solana_claim))
        .route("/solana/recover-txid", post(handle_solana_recover))
        .route("/solana/webhook", post(handle_solana_webhook))
        .route("/solana/webhook/status", get(handle_solana_webhook_status))
        .route("/ethereum/address", post(handle_ethereum_address))
        .route("/ethereum/active", get(handle_ethereum_active))
        .route("/ethereum/claim", post(handle_ethereum_claim))
        .route("/ethereum/recover-txid", post(handle_ethereum_recover))
        .route("/base/address", post(handle_base_address))
        .route("/base/active", get(handle_base_active))
        .route("/base/claim", post(handle_base_claim))
        .route("/base/recover-txid", post(handle_base_recover))
        .route("/bitcoin/recover-txid", post(handle_bitcoin_recover))
        .route("/litecoin/recover-txid", post(handle_litecoin_recover))
        .route(
            "/admin/reservations/cancel-all",
            post(handle_admin_cancel_all_reservations),
        )
        .with_state(state);

    let bind = std::env::var("API_BIND").unwrap_or_else(|_| "0.0.0.0:3030".to_string());
    log::info!("API server listening on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
