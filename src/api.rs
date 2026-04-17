use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use crypto_payment_detector::derivation::derive_address;
use crypto_payment_detector::env_utils::chain_env_bool;
use crypto_payment_detector::persistence::load_state;
use crypto_payment_detector::types::Chain;
use crypto_payment_detector::{
    BasicAuth, ChainDetector, DetectorConfig, PaymentDetector, RetryConfig, SolanaConfig,
    SolanaDetector,
};

#[derive(Clone)]
struct AppState {
    chains: Vec<ChainInfo>,
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
    ExplorerApi(String),
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

fn default_count() -> u32 {
    1
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

#[derive(Deserialize)]
struct SolanaHealthState {
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
        .find(|c| c.chain == chain)
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
            for i in params.start..params.start + params.count {
                let addr = derive_address(xpub, i, chain).map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Derivation error at index {i}: {e}"),
                    )
                })?;
                addresses.push(AddressEntry {
                    index: i,
                    address: addr,
                });
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
                HealthEndpoint::ExplorerApi(explorer_api_url) => {
                    let persisted = load_state(&info.state_file).ok();
                    let tip_url = format!("{}/blocks/tip/height", explorer_api_url);
                    let reachable = client
                        .get(&tip_url)
                        .send()
                        .await
                        .map(|r| r.status().is_success())
                        .unwrap_or(false);
                    let last_scanned_height = persisted.and_then(|s| s.last_scanned_height);
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
                        .map(|r| r.status().is_success())
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
                .and_then(|s| s.parse().ok())
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
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            base_delay_ms: std::env::var("RETRY_BASE_DELAY_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
        },
        explorer_api_url: std::env::var("EXPLORER_API_URL").ok(),
        min_confirmations: {
            let chain_var = match chain {
                Chain::Bitcoin => "BTC_MIN_CONFIRMATIONS",
                Chain::Litecoin => "LTC_MIN_CONFIRMATIONS",
                Chain::Solana => "SOL_MIN_CONFIRMATIONS",
            };
            std::env::var(chain_var)
                .or_else(|_| std::env::var("MIN_CONFIRMATIONS"))
                .ok()
                .and_then(|s| s.parse().ok())
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
        deposit_address: std::env::var("SOLANA_DEPOSIT_ADDRESS")
            .expect("SOLANA_DEPOSIT_ADDRESS env var required for CHAIN=solana"),
        webhook_url: std::env::var("WEBHOOK_URL").expect("WEBHOOK_URL env var required"),
        webhook_hmac_secret: std::env::var("WEBHOOK_SECRET")
            .expect("WEBHOOK_SECRET env var required"),
        discord_invalid_webhook_url: std::env::var("DISCORD_INVALID_MEMO_WEBHOOK_URL").ok(),
        state_file: std::env::var("SOL_STATE_FILE")
            .or_else(|_| std::env::var("STATE_FILE"))
            .unwrap_or_else(|_| "sol_detector_state.json".to_string()),
        poll_interval_secs: std::env::var("SOL_POLL_INTERVAL")
            .or_else(|_| std::env::var("POLL_INTERVAL"))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60),
        min_confirmations: std::env::var("SOL_MIN_CONFIRMATIONS")
            .or_else(|_| std::env::var("MIN_CONFIRMATIONS"))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1),
        fiat_currency: std::env::var("FIAT_CURRENCY").unwrap_or_else(|_| "EUR".to_string()),
        proxy_url: std::env::var("PROXY").ok(),
        max_retries: std::env::var("MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5),
        retry_base_delay_ms: std::env::var("RETRY_BASE_DELAY_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000),
        min_deposit_fiat: std::env::var("SOL_MIN_DEPOSIT_FIAT")
            .ok()
            .and_then(|s| s.parse().ok())
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
        Ok(v) if !v.is_empty() => v,
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

    let explorer_api_url = std::env::var("EXPLORER_API_URL")
        .unwrap_or_else(|_| chain.default_explorer_api().to_string());

    Some((
        ChainInfo {
            chain,
            address_source: AddressSource::Xpub(xpub.clone()),
            state_file,
            endpoint: HealthEndpoint::ExplorerApi(explorer_api_url),
        },
        xpub,
    ))
}

fn build_solana_chain_info() -> Option<ChainInfo> {
    let deposit_address = match std::env::var("SOLANA_DEPOSIT_ADDRESS") {
        Ok(v) if !v.is_empty() => v,
        _ => return None,
    };

    let state_file = std::env::var("SOL_STATE_FILE")
        .or_else(|_| std::env::var("STATE_FILE"))
        .unwrap_or_else(|_| "sol_detector_state.json".to_string());
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet.solana.com".to_string());

    Some(ChainInfo {
        chain: Chain::Solana,
        address_source: AddressSource::Static(deposit_address),
        state_file,
        endpoint: HealthEndpoint::SolanaRpc(rpc_url),
    })
}

async fn run_detector(detector: Arc<ChainDetector>, max_index: u32) {
    let ticker = detector.chain().ticker();
    loop {
        if let Err(e) = detector.run_block_scan_loop(None, max_index).await {
            log::error!(
                "[{}] Block scan loop error: {e} - restarting in 10s",
                ticker
            );
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

async fn run_solana_detector(detector: Arc<SolanaDetector>) {
    loop {
        if let Err(e) = detector.run_block_scan_loop(None, 0).await {
            log::error!("[SOL] Solana scan loop error: {e} - restarting in 10s");
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
        Err(e) => {
            log::warn!("[SOL] Failed to read state file '{}': {}", path, e);
            return None;
        }
    };

    match serde_json::from_str::<SolanaHealthState>(&data) {
        Ok(state) => state.last_processed_signature,
        Err(e) => {
            log::warn!("[SOL] Failed to parse state file '{}': {}", path, e);
            None
        }
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();

    let chain_str = std::env::var("CHAIN").unwrap_or_else(|_| "bitcoin".to_string());
    let max_index: u32 = std::env::var("MAX_DERIVATION_INDEX")
        .ok()
        .and_then(|s| s.parse().ok())
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

                    let det = detector.clone();
                    detector_handles.push(tokio::spawn(async move {
                        run_detector(det, max_index).await;
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
                    let detector = Arc::new(
                        SolanaDetector::new(config).expect("Failed to create SOL detector"),
                    );

                    log::info!(
                        "[SOL] Detector started - deposit address: {}",
                        detector.derive_address(0).unwrap()
                    );

                    let det = detector.clone();
                    detector_handles.push(tokio::spawn(async move {
                        run_solana_detector(det).await;
                    }));

                    chain_infos.push(info);
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
    });

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/derive", get(handle_derive))
        .with_state(state);

    let bind = std::env::var("API_BIND").unwrap_or_else(|_| "0.0.0.0:3030".to_string());
    log::info!("API server listening on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
