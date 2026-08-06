use crypto_payment_detector::{
    Chain, ChainDetector, ChainReadiness, EthereumDetector, PaymentDetector, SolanaDetector,
    build_config, build_evm_config, build_solana_config, chain_enable_key, chain_is_requested,
    env_utils::{chain_env_prefix, env_bool},
    load_ethereum_wallet_pool, load_wallet_pool, parse_erc20_tokens, parse_spl_tokens,
    print_readiness_report, shared_ethereum_wallets, shared_wallets,
};
use std::sync::Arc;

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
    // Default to `info` rather than env_logger's `error`. Without this, an
    // operator who never sets RUST_LOG sees a process that starts, prints
    // nothing at all, and appears to hang.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Apply owner-managed configuration from the admin Configuration panel
    // over the local env BEFORE any config builder runs, then watch for
    // changes (a change triggers a clean restart so it always applies).
    let cfg_sig = crypto_payment_detector::remote_config::bootstrap().await;
    crypto_payment_detector::remote_config::spawn_watcher(cfg_sig);

    let chain_str = std::env::var("CHAIN").unwrap_or_else(|_| "bitcoin".to_string());

    // argv wins for ad-hoc runs, then MAX_DERIVATION_INDEX. Reading the env var
    // too is what lets a container configure this at all — it has no argv.
    let max_index: u32 = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            std::env::var("MAX_DERIVATION_INDEX")
                .ok()
                .and_then(|value| value.trim().parse().ok())
        })
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
            log::info!(
                "[BASE] Disabled via DISABLE_BASE=true — skipping detector, sweep, and orphan scan"
            );
        }
    }

    // Every detector runs in its own task. `JoinSet` (rather than a bare Vec of
    // handles) is what lets us notice the *first* one to stop, whichever it is:
    // these loops are infinite, so a task that finishes has panicked, and a
    // silently dead chain stops crediting deposits with nothing in the logs.
    let mut tasks: tokio::task::JoinSet<&'static str> = tokio::task::JoinSet::new();
    // Collected as we go so the operator gets ONE report naming every gap,
    // instead of discovering them one panic and one restart at a time.
    let mut readiness: Vec<ChainReadiness> = Vec::new();

    for chain in &chains {
        let chain = *chain;

        // Nothing at all supplied for this chain: it simply isn't wanted here.
        // Say so once, and don't list every other variable it would need.
        if !chain_is_requested(chain) {
            readiness.push(ChainReadiness::disabled(
                chain,
                vec![crypto_payment_detector::MissingSetting {
                    key: chain_enable_key(chain),
                    description: "Not set — this chain stays off until it is.",
                }],
            ));
            continue;
        }

        match chain {
            Chain::Bitcoin | Chain::Litecoin => {
                let xpub = std::env::var(chain_enable_key(chain)).unwrap_or_default();
                let config = match build_config(chain, xpub) {
                    Ok(config) => config,
                    Err(missing) => {
                        readiness.push(ChainReadiness::disabled(chain, missing));
                        continue;
                    }
                };
                let detector = match ChainDetector::new(config) {
                    Ok(detector) => Arc::new(detector),
                    Err(error) => {
                        log::error!("[{}] Invalid configuration: {error}", chain.ticker());
                        readiness.push(ChainReadiness::disabled(chain, Vec::new()));
                        continue;
                    }
                };

                readiness.push(ChainReadiness::enabled(
                    chain,
                    format!(
                        "address 0 {}, max derivation index {}",
                        detector
                            .derive_address(0)
                            .unwrap_or_else(|_| "<unavailable>".to_string()),
                        max_index
                    ),
                ));

                let detector_handle = detector.clone();
                let ticker = chain.ticker();
                tasks.spawn(async move {
                    run_detector(detector_handle, max_index).await;
                    ticker
                });
            }
            Chain::Solana => {
                let config = match build_solana_config() {
                    Ok(config) => config,
                    Err(missing) => {
                        readiness.push(ChainReadiness::disabled(chain, missing));
                        continue;
                    }
                };
                let tokens = parse_spl_tokens(std::env::var("SOLANA_SPL_TOKENS").ok().as_deref())
                    .unwrap_or_else(|e| panic!("Invalid SOLANA_SPL_TOKENS: {e}"));
                let wallets = shared_wallets(
                    load_wallet_pool(&config.wallet_pool_file)
                        .unwrap_or_else(|e| panic!("Failed to load Solana wallet pool: {e}")),
                );
                let detector = Arc::new(
                    SolanaDetector::new(config, tokens, wallets)
                        .unwrap_or_else(|e| panic!("Failed to create SOL detector: {e}")),
                );

                readiness.push(ChainReadiness::enabled(
                    chain,
                    format!(
                        "ledger {}, gas tank {}, {} wallet(s), {} SPL token(s)",
                        detector.ledger_address(),
                        detector
                            .gas_tank_address()
                            .unwrap_or_else(|| "<not configured>".to_string()),
                        detector.wallet_count(),
                        detector.token_count()
                    ),
                ));

                let detector_handle = detector.clone();
                tasks.spawn(async move {
                    run_solana_detector(detector_handle).await;
                    "SOL"
                });
                let pending_handle = detector.clone();
                tasks.spawn(async move {
                    run_solana_pending_confirmation_loop(pending_handle).await;
                    "SOL pending-confirmation"
                });
            }
            Chain::Ethereum | Chain::Base => {
                let config = match build_evm_config(chain) {
                    Ok(config) => config,
                    Err(missing) => {
                        readiness.push(ChainReadiness::disabled(chain, missing));
                        continue;
                    }
                };
                let tokens_env = format!("{}_ERC20_TOKENS", chain_env_prefix(chain));
                let tokens = parse_erc20_tokens(std::env::var(&tokens_env).ok().as_deref(), chain)
                    .unwrap_or_else(|e| panic!("Invalid {tokens_env}: {e}"));
                let wallets = shared_ethereum_wallets(
                    load_ethereum_wallet_pool(chain, &config.wallet_pool_file)
                        .unwrap_or_else(|e| panic!("Failed to load {} wallet pool: {e}", chain.name())),
                );
                let detector = Arc::new(
                    EthereumDetector::new(config, tokens, wallets)
                        .unwrap_or_else(|e| panic!("Failed to create {} detector: {e}", chain.ticker())),
                );

                readiness.push(ChainReadiness::enabled(
                    chain,
                    format!(
                        "gas tank {}, ledger {}, {} wallet(s), {} ERC-20 token(s)",
                        detector.gas_tank_address(),
                        detector.ledger_address(),
                        detector.wallet_count(),
                        detector.token_count()
                    ),
                ));

                let detector_handle = detector.clone();
                let ticker = chain.ticker();
                tasks.spawn(async move {
                    run_ethereum_detector(detector_handle, ticker).await;
                    ticker
                });
            }
        }
    }

    print_readiness_report(&readiness);

    if tasks.is_empty() {
        std::future::pending::<()>().await;
    }

    // The detector loops never return on their own, so the first task to finish
    // has died. Exiting non-zero hands the restart to the process supervisor
    // (systemd/docker) with its own backoff, instead of limping along with one
    // chain silently stopped.
    match tasks.join_next().await {
        Some(Ok(label)) => {
            log::error!("[{label}] Detector task exited unexpectedly - stopping the process");
        }
        Some(Err(join_error)) if join_error.is_panic() => {
            log::error!("A detector task panicked ({join_error}) - stopping the process");
        }
        Some(Err(join_error)) => {
            log::error!("A detector task was cancelled ({join_error}) - stopping the process");
        }
        None => {
            log::error!("No detector task left to supervise - stopping the process");
        }
    }
    std::process::exit(1);
}
