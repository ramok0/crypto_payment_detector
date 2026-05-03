use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crypto_payment_detector::derivation::derive_address;
use crypto_payment_detector::env_utils::{chain_env_bool, chain_env_var, proxy_env_var};
use crypto_payment_detector::persistence::load_state;
use crypto_payment_detector::types::Chain;
use crypto_payment_detector::{
    BasicAuth, ChainDetector, DetectorConfig, DetectorError, EthereumConfig, EthereumDetector,
    EthereumReservation, PaymentDetector, RetryConfig, SharedEthereumWallets, SharedSolanaWallets,
    SolanaConfig, SolanaDetector, SolanaReservation, ethereum_reservation_store_url_from_env,
    load_active_ethereum_reservations, load_active_reservations, load_ethereum_wallet_pool,
    load_wallet_pool, parse_erc20_tokens, parse_spl_tokens, reserve_ethereum_wallet_for_user,
    reserve_wallet_for_user, shared_ethereum_wallets, shared_wallets,
};

#[derive(Clone)]
struct AppState {
    chains: Vec<ChainInfo>,
    solana_pool: Option<SolanaPoolApiState>,
    ethereum_pool: Option<EthereumPoolApiState>,
}

#[derive(Clone)]
struct SolanaPoolApiState {
    wallets: SharedSolanaWallets,
    wallet_pool_path: String,
    redis_url: String,
    reservation_ttl_secs: u64,
    secure_deposit_address: String,
}

#[derive(Clone)]
struct EthereumPoolApiState {
    wallets: SharedEthereumWallets,
    wallet_pool_path: String,
    redis_url: String,
    reservation_ttl_secs: u64,
    gas_tank_address: String,
    ledger_address: String,
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

const MAX_RESERVATION_TTL_SECS: u64 = 30 * 24 * 3600; // 30 days hard cap

#[derive(Deserialize)]
struct ReserveSolanaAddressRequest {
    user_id: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Deserialize)]
struct ReserveEthereumAddressRequest {
    user_id: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

fn resolve_ttl(requested: Option<u64>, default: u64) -> u64 {
    match requested {
        Some(value) if value > 0 => value.min(MAX_RESERVATION_TTL_SECS),
        _ => default,
    }
}

fn log_ttl_resolution(chain: &str, user_id: &str, requested: Option<u64>, default: u64, applied: u64) {
    log::info!(
        "[{}] TTL resolution for user_id={}: requested={:?}, default={}s, applied={}s",
        chain, user_id, requested, default, applied
    );
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
struct ReserveSolanaAddressResponse {
    user_id: String,
    address: String,
    wallet_index: u32,
    reserved_at_unix: i64,
    expires_at_unix: i64,
    reservation_ttl_secs: u64,
    sweep_destination_address: String,
}

#[derive(Serialize)]
struct ActiveSolanaReservationsResponse {
    count: usize,
    reservations: Vec<SolanaReservation>,
}

#[derive(Serialize)]
struct ReserveEthereumAddressResponse {
    user_id: String,
    address: String,
    wallet_index: u32,
    reserved_at_unix: i64,
    expires_at_unix: i64,
    reservation_ttl_secs: u64,
    gas_tank_address: String,
    ledger_address: String,
}

#[derive(Serialize)]
struct ActiveEthereumReservationsResponse {
    count: usize,
    reservations: Vec<EthereumReservation>,
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

async fn handle_solana_reserve(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReserveSolanaAddressRequest>,
) -> Result<Json<ReserveSolanaAddressResponse>, (StatusCode, String)> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };

    let ttl = resolve_ttl(payload.ttl_secs, solana_pool.reservation_ttl_secs);
    log_ttl_resolution(
        "SOL",
        &payload.user_id,
        payload.ttl_secs,
        solana_pool.reservation_ttl_secs,
        ttl,
    );
    let reservation = reserve_wallet_for_user(
        &solana_pool.redis_url,
        &solana_pool.wallets,
        &solana_pool.wallet_pool_path,
        &payload.user_id,
        ttl,
    )
    .await
    .map_err(map_reservation_error)?;

    Ok(Json(ReserveSolanaAddressResponse {
        user_id: reservation.user_id,
        address: reservation.address,
        wallet_index: reservation.wallet_index,
        reserved_at_unix: reservation.reserved_at_unix,
        expires_at_unix: reservation.expires_at_unix,
        reservation_ttl_secs: ttl,
        sweep_destination_address: solana_pool.secure_deposit_address.clone(),
    }))
}

async fn handle_solana_active(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ActiveSolanaReservationsResponse>, (StatusCode, String)> {
    let Some(solana_pool) = state.solana_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Solana address pool is not configured".into(),
        ));
    };

    let reservations = load_active_reservations(&solana_pool.redis_url)
        .await
        .map_err(map_internal_error)?;

    Ok(Json(ActiveSolanaReservationsResponse {
        count: reservations.len(),
        reservations,
    }))
}

async fn handle_ethereum_reserve(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReserveEthereumAddressRequest>,
) -> Result<Json<ReserveEthereumAddressResponse>, (StatusCode, String)> {
    let Some(ethereum_pool) = state.ethereum_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Ethereum address pool is not configured".into(),
        ));
    };

    let ttl = resolve_ttl(payload.ttl_secs, ethereum_pool.reservation_ttl_secs);
    log_ttl_resolution(
        "ETH",
        &payload.user_id,
        payload.ttl_secs,
        ethereum_pool.reservation_ttl_secs,
        ttl,
    );
    let reservation = reserve_ethereum_wallet_for_user(
        &ethereum_pool.redis_url,
        &ethereum_pool.wallets,
        &ethereum_pool.wallet_pool_path,
        &payload.user_id,
        ttl,
    )
    .await
    .map_err(map_reservation_error)?;

    Ok(Json(ReserveEthereumAddressResponse {
        user_id: reservation.user_id,
        address: reservation.address,
        wallet_index: reservation.wallet_index,
        reserved_at_unix: reservation.reserved_at_unix,
        expires_at_unix: reservation.expires_at_unix,
        reservation_ttl_secs: ttl,
        gas_tank_address: ethereum_pool.gas_tank_address.clone(),
        ledger_address: ethereum_pool.ledger_address.clone(),
    }))
}

async fn handle_ethereum_active(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ActiveEthereumReservationsResponse>, (StatusCode, String)> {
    let Some(ethereum_pool) = state.ethereum_pool.as_ref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Ethereum address pool is not configured".into(),
        ));
    };

    let reservations = load_active_ethereum_reservations(&ethereum_pool.redis_url)
        .await
        .map_err(map_internal_error)?;

    Ok(Json(ActiveEthereumReservationsResponse {
        count: reservations.len(),
        reservations,
    }))
}

fn build_config(chain: Chain, xpub: String) -> DetectorConfig {
    let state_file_default = match chain {
        Chain::Bitcoin => "btc_detector_state.json",
        Chain::Litecoin => "ltc_detector_state.json",
        Chain::Solana => "sol_detector_state.json",
        Chain::Ethereum => "eth_detector_state.json",
    };
    let state_file_var = match chain {
        Chain::Bitcoin => "BTC_STATE_FILE",
        Chain::Litecoin => "LTC_STATE_FILE",
        Chain::Solana => "SOL_STATE_FILE",
        Chain::Ethereum => "ETH_STATE_FILE",
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

fn build_ethereum_config() -> EthereumConfig {
    EthereumConfig {
        rpc_url: std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://cloudflare-eth.com".to_string()),
        chain_id: std::env::var("ETH_CHAIN_ID")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1),
        wallet_pool_file: std::env::var("ETH_WALLET_POOL_FILE")
            .expect("ETH_WALLET_POOL_FILE env var required for CHAIN=ethereum"),
        gas_tank_private_key: std::env::var("ETH_GAS_TANK_PRIVATE_KEY")
            .expect("ETH_GAS_TANK_PRIVATE_KEY env var required for CHAIN=ethereum"),
        ledger_address: std::env::var("ETH_LEDGER_ADDRESS")
            .expect("ETH_LEDGER_ADDRESS env var required for CHAIN=ethereum"),
        webhook_url: std::env::var("WEBHOOK_URL").expect("WEBHOOK_URL env var required"),
        webhook_hmac_secret: std::env::var("WEBHOOK_SECRET")
            .expect("WEBHOOK_SECRET env var required"),
        redis_url: ethereum_reservation_store_url_from_env(),
        reservation_ttl_secs: std::env::var("ETH_RESERVATION_TTL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(3600),
        state_file: std::env::var("ETH_STATE_FILE")
            .or_else(|_| std::env::var("STATE_FILE"))
            .unwrap_or_else(|_| "eth_detector_state.json".to_string()),
        poll_interval_secs: std::env::var("ETH_POLL_INTERVAL")
            .or_else(|_| std::env::var("POLL_INTERVAL"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(30),
        min_confirmations: std::env::var("ETH_MIN_CONFIRMATIONS")
            .or_else(|_| std::env::var("MIN_CONFIRMATIONS"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(12),
        fiat_currency: std::env::var("FIAT_CURRENCY").unwrap_or_else(|_| "EUR".to_string()),
        proxy_url: proxy_env_var(&["ETH_PROXY", "PROXY"]),
        max_blocks_per_cycle: std::env::var("ETH_MAX_BLOCKS_PER_CYCLE")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(250),
        start_block: std::env::var("ETH_START_BLOCK")
            .ok()
            .and_then(|value| value.parse().ok()),
        gas_tank_target_usd: std::env::var("ETH_GAS_TANK_TARGET_USD")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20.0),
        gas_tank_check_interval_secs: std::env::var("ETH_GAS_TANK_INTERVAL_SECS")
            .or_else(|_| std::env::var("ETH_GAS_TANK_CHECK_INTERVAL_SECS"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(900),
        token_transfer_gas_limit: std::env::var("ETH_TOKEN_TRANSFER_GAS_LIMIT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100_000),
        gas_top_up_multiplier: std::env::var("ETH_GAS_TOP_UP_MULTIPLIER")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1.25),
        max_fee_ratio: std::env::var("ETH_MAX_FEE_RATIO")
            .or_else(|_| std::env::var("MAX_FEE_RATIO"))
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.10),
    }
}

fn build_chain_info(chain: Chain) -> Option<(ChainInfo, String)> {
    let xpub_var = match chain {
        Chain::Bitcoin => "BTC_XPUB",
        Chain::Litecoin => "LTC_XPUB",
        Chain::Solana | Chain::Ethereum => return None,
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

fn build_ethereum_chain_info(config: &EthereumConfig, gas_tank_address: String) -> ChainInfo {
    ChainInfo {
        chain: Chain::Ethereum,
        address_source: AddressSource::Static(gas_tank_address),
        state_file: config.state_file.clone(),
        endpoint: HealthEndpoint::EthereumRpc(config.rpc_url.clone()),
    }
}

fn build_solana_pool_api_state(
    config: &SolanaConfig,
    wallets: SharedSolanaWallets,
) -> Result<SolanaPoolApiState, DetectorError> {
    Ok(SolanaPoolApiState {
        wallets,
        wallet_pool_path: config.wallet_pool_file.clone(),
        redis_url: config.redis_url.clone(),
        reservation_ttl_secs: config.reservation_ttl_secs,
        secure_deposit_address: config.secure_deposit_address.clone(),
    })
}

fn build_ethereum_pool_api_state(
    config: &EthereumConfig,
    wallets: SharedEthereumWallets,
    gas_tank_address: String,
) -> Result<EthereumPoolApiState, DetectorError> {
    Ok(EthereumPoolApiState {
        wallets,
        wallet_pool_path: config.wallet_pool_file.clone(),
        redis_url: config.redis_url.clone(),
        reservation_ttl_secs: config.reservation_ttl_secs,
        gas_tank_address,
        ledger_address: config.ledger_address.clone(),
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

async fn run_ethereum_detector(detector: Arc<EthereumDetector>) {
    if let Err(error) = detector.sweep_orphan_balances().await {
        log::warn!("[ETH] Startup orphan sweep failed: {error}");
    }
    loop {
        if let Err(error) = detector.run_block_scan_loop(None, 0).await {
            log::error!("[ETH] Ethereum scan loop error: {error} - restarting in 10s");
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

fn map_reservation_error(error: DetectorError) -> (StatusCode, String) {
    let message = error.to_string();
    if message.contains("No unreserved Solana wallet")
        || message.contains("No unreserved Ethereum wallet")
    {
        (StatusCode::CONFLICT, message)
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
    let chains: Vec<Chain> = match chain_str.to_lowercase().as_str() {
        "both" => vec![Chain::Bitcoin, Chain::Litecoin],
        "solbtc" => vec![Chain::Bitcoin, Chain::Solana],
        "all" => vec![
            Chain::Bitcoin,
            Chain::Litecoin,
            Chain::Solana,
            Chain::Ethereum,
        ],
        other => vec![other.parse().expect(
            "Invalid CHAIN value (expected: bitcoin, litecoin, solana, ethereum, btc, ltc, sol, eth, both, solbtc, all)",
        )],
    };

    let mut chain_infos = Vec::new();
    let mut detector_handles = Vec::new();
    let mut solana_pool = None;
    let mut ethereum_pool = None;

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
                        Chain::Solana => unreachable!(),
                        Chain::Ethereum => unreachable!(),
                    };
                    log::warn!("[{}] {} not set, skipping", chain.ticker(), xpub_var);
                }
            }
            Chain::Solana => {
                if let Some(info) = build_solana_chain_info() {
                    let config = build_solana_config();
                    let tokens = parse_spl_tokens(
                        std::env::var("SOLANA_SPL_TOKENS").ok().as_deref(),
                    )
                    .expect("Invalid SOLANA_SPL_TOKENS");
                    let wallets = shared_wallets(
                        load_wallet_pool(&config.wallet_pool_file)
                            .expect("Failed to load Solana wallet pool"),
                    );
                    let pool_state = build_solana_pool_api_state(&config, wallets.clone())
                        .expect("Failed to build Solana pool state");
                    let detector = Arc::new(
                        SolanaDetector::new(config.clone(), tokens, wallets)
                            .expect("Failed to create SOL detector"),
                    );

                    log::info!(
                        "[SOL] Detector started - ledger: {} - gas tank: {} - managed wallets: {} - tokens: {} - default reservation TTL: {}s",
                        detector.ledger_address(),
                        detector
                            .gas_tank_address()
                            .unwrap_or_else(|| "<not configured>".to_string()),
                        detector.wallet_count(),
                        detector.token_count(),
                        config.reservation_ttl_secs
                    );
                    for (symbol, mint, decimals) in detector.token_summary() {
                        log::info!(
                            "[SOL] SPL token configured: {} mint={} decimals={}",
                            symbol, mint, decimals
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
            Chain::Ethereum => {
                let config = build_ethereum_config();
                let tokens = parse_erc20_tokens(std::env::var("ETH_ERC20_TOKENS").ok().as_deref())
                    .expect("Invalid ETH_ERC20_TOKENS");
                let wallets = shared_ethereum_wallets(
                    load_ethereum_wallet_pool(&config.wallet_pool_file)
                        .expect("Failed to load Ethereum wallet pool"),
                );
                let detector = Arc::new(
                    EthereumDetector::new(config.clone(), tokens, wallets.clone())
                        .expect("Failed to create ETH detector"),
                );
                let gas_tank_address = detector.gas_tank_address();
                let pool_state =
                    build_ethereum_pool_api_state(&config, wallets, gas_tank_address.clone())
                        .expect("Failed to build Ethereum pool state");

                log::info!(
                    "[ETH] Detector started - gas tank: {} - ledger: {} - managed wallets: {} - tokens: {} - default reservation TTL: {}s",
                    gas_tank_address,
                    detector.ledger_address(),
                    detector.wallet_count(),
                    detector.token_count(),
                    config.reservation_ttl_secs
                );

                let detector_handle = detector.clone();
                detector_handles.push(tokio::spawn(async move {
                    run_ethereum_detector(detector_handle).await;
                }));

                chain_infos.push(build_ethereum_chain_info(&config, gas_tank_address));
                ethereum_pool = Some(pool_state);
            }
        }
    }

    if chain_infos.is_empty() {
        eprintln!(
            "No chain configured. Set BTC_XPUB/LTC_XPUB, SOLANA_DEPOSIT_ADDRESS, or ETH_GAS_TANK_PRIVATE_KEY."
        );
        std::process::exit(1);
    }

    let state = Arc::new(AppState {
        chains: chain_infos,
        solana_pool,
        ethereum_pool,
    });

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/derive", get(handle_derive))
        .route("/solana/reserve", post(handle_solana_reserve))
        .route("/solana/active", get(handle_solana_active))
        .route("/ethereum/reserve", post(handle_ethereum_reserve))
        .route("/ethereum/active", get(handle_ethereum_active))
        .with_state(state);

    let bind = std::env::var("API_BIND").unwrap_or_else(|_| "0.0.0.0:3030".to_string());
    log::info!("API server listening on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
