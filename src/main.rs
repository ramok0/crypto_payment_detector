use crypto_payment_detector::{
    BasicAuth, Chain, ChainDetector, DetectorConfig, PaymentDetector, RetryConfig, SolanaConfig,
    SolanaDetector,
};
use std::sync::Arc;

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
    }
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

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();

    let chain_str = std::env::var("CHAIN").unwrap_or_else(|_| "bitcoin".to_string());

    let max_index: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let chains: Vec<Chain> = match chain_str.to_lowercase().as_str() {
        "both" => vec![Chain::Bitcoin, Chain::Litecoin],
        "all" => vec![Chain::Bitcoin, Chain::Litecoin, Chain::Solana],
        other => vec![other.parse().expect(
            "Invalid CHAIN value (expected: bitcoin, litecoin, solana, btc, ltc, sol, both, all)",
        )],
    };

    let mut handles = Vec::new();

    for chain in &chains {
        match chain {
            Chain::Bitcoin | Chain::Litecoin => {
                let xpub_var = match chain {
                    Chain::Bitcoin => "BTC_XPUB",
                    Chain::Litecoin => "LTC_XPUB",
                    Chain::Solana => unreachable!(),
                };

                let xpub = match std::env::var(xpub_var) {
                    Ok(v) if !v.is_empty() => v,
                    _ => {
                        log::warn!("[{}] {} not set, skipping", chain.ticker(), xpub_var);
                        continue;
                    }
                };

                let config = build_config(*chain, xpub);
                let detector = Arc::new(
                    ChainDetector::new(config)
                        .expect(&format!("Failed to create {} detector", chain.ticker())),
                );

                println!("{} Payment Detector starting", detector.chain().name());
                println!("  Chain: {}", detector.chain().ticker());
                println!("  Max derivation index: {}", max_index);
                println!("  Address 0: {}", detector.derive_address(0).unwrap());
                println!();

                let det = detector.clone();
                handles.push(tokio::spawn(async move {
                    run_detector(det, max_index).await;
                }));
            }
            Chain::Solana => {
                let config = build_solana_config();
                let detector =
                    Arc::new(SolanaDetector::new(config).expect("Failed to create SOL detector"));

                println!("Solana Payment Detector starting");
                println!("  Chain: SOL");
                println!("  Deposit address: {}", detector.derive_address(0).unwrap());
                println!();

                let det = detector.clone();
                handles.push(tokio::spawn(async move {
                    run_solana_detector(det).await;
                }));
            }
        }
    }

    if handles.is_empty() {
        eprintln!("No chains configured. Set BTC_XPUB/LTC_XPUB and/or SOLANA_DEPOSIT_ADDRESS.");
        std::process::exit(1);
    }

    let _ = handles.remove(0).await;
}
