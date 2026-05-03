use crypto_payment_detector::{
    BasicAuth, Chain, ChainDetector, DetectorConfig, EthereumConfig, EthereumDetector,
    PaymentDetector, RetryConfig, SolanaConfig, SolanaDetector,
    env_utils::{chain_env_bool, chain_env_var, proxy_env_var},
    ethereum_reservation_store_url_from_env, parse_erc20_tokens, parse_spl_tokens,
};
use std::sync::Arc;

fn explorer_api_config(chain: Chain) -> Option<String> {
    chain_env_var(chain, "EXPLORER_API_URLS")
        .or_else(|| chain_env_var(chain, "EXPLORER_API_URL"))
        .or_else(|| std::env::var("EXPLORER_API_URLS").ok())
        .or_else(|| std::env::var("EXPLORER_API_URL").ok())
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
    loop {
        if let Err(error) = detector.run_block_scan_loop(None, 0).await {
            log::error!("[ETH] Ethereum scan loop error: {error} - restarting in 10s");
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

    let mut handles = Vec::new();

    for chain in &chains {
        match chain {
            Chain::Bitcoin | Chain::Litecoin => {
                let xpub_var = match chain {
                    Chain::Bitcoin => "BTC_XPUB",
                    Chain::Litecoin => "LTC_XPUB",
                    Chain::Solana => unreachable!(),
                    Chain::Ethereum => unreachable!(),
                };

                let xpub = match std::env::var(xpub_var) {
                    Ok(value) if !value.is_empty() => value,
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

                let detector_handle = detector.clone();
                handles.push(tokio::spawn(async move {
                    run_detector(detector_handle, max_index).await;
                }));
            }
            Chain::Solana => {
                let config = build_solana_config();
                let tokens = parse_spl_tokens(std::env::var("SOLANA_SPL_TOKENS").ok().as_deref())
                    .expect("Invalid SOLANA_SPL_TOKENS");
                let detector = Arc::new(
                    SolanaDetector::new(config, tokens).expect("Failed to create SOL detector"),
                );

                println!("Solana Payment Detector starting");
                println!("  Chain: SOL");
                println!("  Cold/ledger destination: {}", detector.ledger_address());
                println!(
                    "  Gas tank address: {}",
                    detector
                        .gas_tank_address()
                        .unwrap_or_else(|| "<not configured>".to_string())
                );
                println!("  Managed wallet count: {}", detector.wallet_count());
                println!("  SPL token count: {}", detector.token_count());
                for (symbol, mint, decimals) in detector.token_summary() {
                    println!("    - {} mint={} decimals={}", symbol, mint, decimals);
                }
                println!();

                let detector_handle = detector.clone();
                handles.push(tokio::spawn(async move {
                    run_solana_detector(detector_handle).await;
                }));
            }
            Chain::Ethereum => {
                let config = build_ethereum_config();
                let tokens = parse_erc20_tokens(std::env::var("ETH_ERC20_TOKENS").ok().as_deref())
                    .expect("Invalid ETH_ERC20_TOKENS");
                let detector = Arc::new(
                    EthereumDetector::new(config, tokens).expect("Failed to create ETH detector"),
                );

                println!("Ethereum Payment Detector starting");
                println!("  Chain: ETH");
                println!("  Gas tank: {}", detector.gas_tank_address());
                println!("  Ledger sweep address: {}", detector.ledger_address());
                println!("  Managed wallet count: {}", detector.wallet_count());
                println!("  ERC-20 token count: {}", detector.token_count());
                println!();

                let detector_handle = detector.clone();
                handles.push(tokio::spawn(async move {
                    run_ethereum_detector(detector_handle).await;
                }));
            }
        }
    }

    if handles.is_empty() {
        eprintln!(
            "No chains configured. Set BTC_XPUB/LTC_XPUB, SOLANA_DEPOSIT_ADDRESS, or ETH_GAS_TANK_PRIVATE_KEY."
        );
        std::process::exit(1);
    }

    let _ = handles.remove(0).await;
}
