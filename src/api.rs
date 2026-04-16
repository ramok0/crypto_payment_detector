use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use crypto_payment_detector::derivation::derive_address;
use crypto_payment_detector::persistence::{PersistedState, load_state};
use crypto_payment_detector::types::Chain;
use crypto_payment_detector::{
    BasicAuth, ChainDetector, DetectorConfig, PaymentDetector, RetryConfig,
};

#[derive(Clone)]
struct AppState {
    chains: Vec<ChainInfo>,
}

#[derive(Clone)]
struct ChainInfo {
    chain: Chain,
    xpub: String,
    state_file: String,
    explorer_api_url: String,
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
    explorer_reachable: bool,
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
    for i in params.start..params.start + params.count {
        let addr = derive_address(&info.xpub, i, chain).map_err(|e| {
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

    Ok(Json(DeriveResponse {
        chain: chain.name().to_string(),
        addresses,
    }))
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let mut chains = Vec::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    for info in &state.chains {
        let persisted: Option<PersistedState> = load_state(&info.state_file).ok();

        let tip_url = format!("{}/blocks/tip/height", info.explorer_api_url);
        let explorer_reachable = client
            .get(&tip_url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);

        chains.push(ChainHealthStatus {
            chain: info.chain.name().to_string(),
            ticker: info.chain.ticker().to_string(),
            last_scanned_height: persisted.and_then(|s| s.last_scanned_height),
            explorer_reachable,
        });
    }

    let all_ok = chains
        .iter()
        .all(|c| c.explorer_reachable && c.last_scanned_height.is_some());

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
        Chain::Bitcoin => ("BTC_STATE_FILE", "btc_state.json"),
        Chain::Litecoin => ("LTC_STATE_FILE", "ltc_state.json"),
        Chain::Solana => ("SOL_STATE_FILE", "sol_state.json"),
    };
    let state_file = std::env::var(state_file_var)
        .or_else(|_| std::env::var("STATE_FILE"))
        .unwrap_or_else(|_| state_file_default.to_string());

    let explorer_api_url = std::env::var("EXPLORER_API_URL")
        .unwrap_or_else(|_| chain.default_explorer_api().to_string());

    Some((
        ChainInfo {
            chain,
            xpub: xpub.clone(),
            state_file,
            explorer_api_url,
        },
        xpub,
    ))
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

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();

    let max_index: u32 = std::env::var("MAX_DERIVATION_INDEX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let mut chain_infos = Vec::new();
    let mut detector_handles = Vec::new();

    for chain in [Chain::Bitcoin, Chain::Litecoin] {
        if let Some((info, xpub)) = build_chain_info(chain) {
            log::info!(
                "[{}] Configured with xpub {}...{}",
                chain.ticker(),
                &info.xpub[..8],
                &info.xpub[info.xpub.len() - 4..]
            );

            let config = build_config(chain, xpub);
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
        }
    }

    if chain_infos.is_empty() {
        eprintln!("No chain configured. Set BTC_XPUB and/or LTC_XPUB.");
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
