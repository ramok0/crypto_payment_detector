use crypto_payment_detector::{
    BasicAuth, Chain, ChainDetector, DetectorConfig, EthereumConfig, EthereumDetector,
    EtherscanConfig, PaymentDetector, RetryConfig, SolanaConfig, SolanaDetector,
    env_utils::{chain_env_bool, chain_env_prefix, chain_env_var, env_bool, proxy_env_var},
    ethereum_reservation_store_url_from_env, load_ethereum_wallet_pool, load_wallet_pool,
    parse_erc20_tokens, parse_spl_tokens, shared_ethereum_wallets, shared_wallets,
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

/// Parse `{prefix}_ETHERSCAN_ENABLED`. Defaults to `true` (preserve existing
/// behavior — when ETHERSCAN_API_KEY is set, the scan runs). Setting the
/// chain-specific var to `false`/`0`/`no`/`off` disables the etherscan client
/// for that chain only — useful when the free Etherscan plan covers
/// Ethereum mainnet but rejects Base (`Free API access is not supported for
/// this chain`).
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

    // Etherscan V2 multichain endpoint serves both Ethereum and Base off the
    // same API key — only the chain_id changes. Pin the etherscan client to
    // this detector's chain so a process running both chains side-by-side
    // hits the right endpoint per detector.
    //
    // Etherscan's free tier does NOT cover Base (returns
    // `Free API access is not supported for this chain`). To run Base on the
    // free tier without crashing the scan loop, set BASE_ETHERSCAN_ENABLED=false.
    // The detector falls back to the standard `eth_getBlockByNumber` scan,
    // which still catches direct ETH transfers — just not internal CALLs
    // (Coinbase-style contract withdrawals).
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
            // Base finalizes faster (~2s blocks); 5 is a reasonable default to
            // get ~10s of finality. Mainnet keeps its conservative 12.
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
        // Public Base RPC (mainnet.base.org) returns -32016 "over rate limit"
        // under burst load (orphan sweep on a 10-wallet pool). 200ms ≈ 5 req/s
        // is a safe default for the public endpoint. Mainnet Ethereum users
        // typically have a paid endpoint and don't need throttling — default 0.
        // Override per-chain: ETH_RPC_MIN_REQUEST_INTERVAL_MS / BASE_RPC_MIN_REQUEST_INTERVAL_MS.
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
/// payments (no address scan; just iterates the in-memory pending queue).
/// Cheap when nothing is pending. Runs alongside `run_solana_detector`.
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

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();

    let chain_str = std::env::var("CHAIN").unwrap_or_else(|_| "bitcoin".to_string());

    let max_index: u32 = std::env::args()
        .nth(1)
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
        // Comma-separated list, e.g. CHAIN=ethereum,base
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
            log::info!("[BASE] Disabled via DISABLE_BASE=true — skipping detector, sweep, and orphan scan");
        }
    }

    let mut handles = Vec::new();

    for chain in &chains {
        match chain {
            Chain::Bitcoin | Chain::Litecoin => {
                let xpub_var = match chain {
                    Chain::Bitcoin => "BTC_XPUB",
                    Chain::Litecoin => "LTC_XPUB",
                    Chain::Solana | Chain::Ethereum | Chain::Base => unreachable!(),
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
                let wallets = shared_wallets(
                    load_wallet_pool(&config.wallet_pool_file)
                        .expect("Failed to load Solana wallet pool"),
                );
                let detector = Arc::new(
                    SolanaDetector::new(config, tokens, wallets)
                        .expect("Failed to create SOL detector"),
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
                let pending_handle = detector.clone();
                handles.push(tokio::spawn(async move {
                    run_solana_pending_confirmation_loop(pending_handle).await;
                }));
            }
            Chain::Ethereum | Chain::Base => {
                let evm_chain = *chain;
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
                    EthereumDetector::new(config, tokens, wallets)
                        .unwrap_or_else(|e| panic!("Failed to create {} detector: {e}", evm_chain.ticker())),
                );

                println!("{} Payment Detector starting", evm_chain.name());
                println!("  Chain: {}", evm_chain.ticker());
                println!("  Gas tank: {}", detector.gas_tank_address());
                println!("  Ledger sweep address: {}", detector.ledger_address());
                println!("  Managed wallet count: {}", detector.wallet_count());
                println!("  ERC-20 token count: {}", detector.token_count());
                println!();

                let detector_handle = detector.clone();
                let ticker = evm_chain.ticker();
                handles.push(tokio::spawn(async move {
                    run_ethereum_detector(detector_handle, ticker).await;
                }));
            }
        }
    }

    if handles.is_empty() {
        eprintln!(
            "No chains configured. Set BTC_XPUB/LTC_XPUB, SOLANA_DEPOSIT_ADDRESS, ETH_GAS_TANK_PRIVATE_KEY, or BASE_GAS_TANK_PRIVATE_KEY."
        );
        std::process::exit(1);
    }

    let _ = handles.remove(0).await;
}
