use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crypto_payment_detector::derivation::derive_address;
use crypto_payment_detector::env_utils::{chain_env_bool, chain_env_var};
use crypto_payment_detector::persistence::load_state;
use crypto_payment_detector::types::Chain;
use crypto_payment_detector::{
    BasicAuth, ChainDetector, DetectorConfig, DetectorError, ManagedSolanaWallet, PaymentDetector,
    RetryConfig, SolanaConfig, SolanaDetector, SolanaReservation, load_active_reservations,
    load_wallet_pool, reserve_wallet_for_user,
};

#[derive(Clone)]
struct AppState {
    chains: Vec<ChainInfo>,
    solana_pool: Option<SolanaPoolApiState>,
}

#[derive(Clone)]
struct SolanaPoolApiState {
    wallets: Vec<ManagedSolanaWallet>,
    redis_url: String,
    reservation_ttl_secs: u64,
    secure_deposit_address: String,
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
}

#[derive(Deserialize)]
struct DeriveParams {
    chain: String,
    #[serde(default)]
    start: u32,
    #[serde(default = "default_count")]
    count: u32,
}

#[derive(Deserialize)]
struct ReserveSolanaAddressRequest {
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

#[derive(Deserialize)]
struct SolanaHealthState {
    #[serde(default)]
    addresses: HashMap<String, SolanaAddressHealthCursor>,
}

#[derive(Deserialize)]
struct SolanaAddressHealthCursor {
    last_processed_signature: Option<String>,
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

    let reservation = reserve_wallet_for_user(
        &solana_pool.redis_url,
        &solana_pool.wallets,
        &payload.user_id,
        solana_pool.reservation_ttl_secs,
    )
    .await
    .map_err(map_reservation_error)?;

    Ok(Json(ReserveSolanaAddressResponse {
        user_id: reservation.user_id,
        address: reservation.address,
        wallet_index: reservation.wallet_index,
        reserved_at_unix: reservation.reserved_at_unix,
        expires_at_unix: reservation.expires_at_unix,
        reservation_ttl_secs: solana_pool.reservation_ttl_secs,
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

fn build_config(chain: Chain, xpub: String) -> DetectorConfig {
    let state_file_default = match chain {
        Chain::Bitcoin => "btc_detector_state.json",
        Chain::Litecoin => "ltc_detector_state.json",
        Chain::Solana => "sol_detector_state.json",
    };
    let state_file_var = match chain {
        Chain::Bitcoin => "BTC_STATE_FILE",
        Chain::Litecoin => "LTC_STATE_FILE",
        Chain::Solana => "SOL_STATE_FILE",
    };

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
        proxy_url: std::env::var("PROXY").ok(),
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
    }
}

fn build_chain_info(chain: Chain) -> Option<(ChainInfo, String)> {
    let xpub_var = match chain {
        Chain::Bitcoin => "BTC_XPUB",
        Chain::Litecoin => "LTC_XPUB",
        Chain::Solana => return None,
    };
    let xpub = match std::env::var(xpub_var) {
        Ok(value) if !value.is_empty() => value,
        _ => return None,
    };

    let (state_file_var, state_file_default) = match chain {
        Chain::Bitcoin => ("BTC_STATE_FILE", "btc_detector_state.json"),
        Chain::Litecoin => ("LTC_STATE_FILE", "ltc_detector_state.json"),
        Chain::Solana => ("SOL_STATE_FILE", "sol_detector_state.json"),
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

fn build_solana_pool_api_state(config: &SolanaConfig) -> Result<SolanaPoolApiState, DetectorError> {
    Ok(SolanaPoolApiState {
        wallets: load_wallet_pool(&config.wallet_pool_file)?,
        redis_url: config.redis_url.clone(),
        reservation_ttl_secs: config.reservation_ttl_secs,
        secure_deposit_address: config.secure_deposit_address.clone(),
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
    loop {
        if let Err(error) = detector.run_block_scan_loop(None, 0).await {
            log::error!("[SOL] Solana scan loop error: {error} - restarting in 10s");
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

fn map_reservation_error(error: DetectorError) -> (StatusCode, String) {
    let message = error.to_string();
    if message.contains("No unreserved Solana wallet") {
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
        "all" => vec![Chain::Bitcoin, Chain::Litecoin, Chain::Solana],
        other => vec![other.parse().expect(
            "Invalid CHAIN value (expected: bitcoin, litecoin, solana, btc, ltc, sol, both, all)",
        )],
    };

    let mut chain_infos = Vec::new();
    let mut detector_handles = Vec::new();
    let mut solana_pool = None;

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
                    };
                    log::warn!("[{}] {} not set, skipping", chain.ticker(), xpub_var);
                }
            }
            Chain::Solana => {
                if let Some(info) = build_solana_chain_info() {
                    let config = build_solana_config();
                    let pool_state = build_solana_pool_api_state(&config)
                        .expect("Failed to load Solana wallet pool");
                    let detector = Arc::new(
                        SolanaDetector::new(config.clone()).expect("Failed to create SOL detector"),
                    );

                    log::info!(
                        "[SOL] Detector started - sweep destination: {} - managed wallets: {}",
                        detector.derive_address(0).unwrap(),
                        detector.wallet_count()
                    );

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
        }
    }

    if chain_infos.is_empty() {
        eprintln!("No chain configured. Set BTC_XPUB/LTC_XPUB and/or SOLANA_DEPOSIT_ADDRESS.");
        std::process::exit(1);
    }

    let state = Arc::new(AppState {
        chains: chain_infos,
        solana_pool,
    });

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/derive", get(handle_derive))
        .route("/solana/reserve", post(handle_solana_reserve))
        .route("/solana/active", get(handle_solana_active))
        .with_state(state);

    let bind = std::env::var("API_BIND").unwrap_or_else(|_| "0.0.0.0:3030".to_string());
    log::info!("API server listening on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
