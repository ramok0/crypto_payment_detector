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
use crypto_payment_detector::types::Chain;
use crypto_payment_detector::{
    BasicAuth, ChainDetector, DetectorConfig, DetectorError, EthereumConfig, EthereumDetector,
    EthereumReservation, EtherscanConfig, PaymentDetector, RetryConfig, SharedEthereumWallets,
    SharedSolanaWallets, SolanaConfig, SolanaDetector, SolanaReservation,
    assign_ethereum_wallet_for_user, assign_wallet_for_user,
    ethereum_reservation_store_url_from_env, load_active_ethereum_reservations,
    load_active_reservations, load_ethereum_wallet_pool, load_wallet_pool, parse_erc20_tokens,
    parse_spl_tokens, shared_ethereum_wallets, shared_wallets,
};

#[derive(Clone)]
struct AppState {
    chains: Vec<ChainInfo>,
    solana_pool: Option<SolanaPoolApiState>,
    ethereum_pool: Option<EthereumPoolApiState>,
    base_pool: Option<EthereumPoolApiState>,
}

#[derive(Clone)]
struct SolanaPoolApiState {
    wallets: SharedSolanaWallets,
    wallet_pool_path: String,
    redis_url: String,
    secure_deposit_address: String,
    /// Live detector handle used by `/solana/claim` to trigger an
    /// immediate scan + sweep + credit cycle on demand. `None` when the
    /// API binary runs without a co-located detector (rare; primarily for
    /// tests and read-only deployments).
    detector: Option<Arc<SolanaDetector>>,
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
    /// immediate scan + sweep + credit cycle on demand.
    detector: Option<Arc<EthereumDetector>>,
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

    Ok(Json(SolanaAddressResponse {
        user_id: assignment.user_id,
        address: assignment.address,
        wallet_index: assignment.wallet_index,
        assigned_at_unix: assignment.reserved_at_unix,
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

fn payment_user_id(raw: &str) -> Result<String, (StatusCode, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "user_id cannot be empty".into()));
    }
    Ok(trimmed.to_string())
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
) -> Result<SolanaPoolApiState, DetectorError> {
    Ok(SolanaPoolApiState {
        wallets,
        wallet_pool_path: config.wallet_pool_file.clone(),
        redis_url: config.redis_url.clone(),
        secure_deposit_address: config.secure_deposit_address.clone(),
        detector,
    })
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
                    let pool_state = build_solana_pool_api_state(
                        &config,
                        wallets,
                        Some(detector.clone()),
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
    });

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/derive", get(handle_derive))
        .route("/solana/address", post(handle_solana_address))
        .route("/solana/active", get(handle_solana_active))
        .route("/solana/claim", post(handle_solana_claim))
        .route("/ethereum/address", post(handle_ethereum_address))
        .route("/ethereum/active", get(handle_ethereum_active))
        .route("/ethereum/claim", post(handle_ethereum_claim))
        .route("/base/address", post(handle_base_address))
        .route("/base/active", get(handle_base_active))
        .route("/base/claim", post(handle_base_claim))
        .with_state(state);

    let bind = std::env::var("API_BIND").unwrap_or_else(|_| "0.0.0.0:3030".to_string());
    log::info!("API server listening on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
