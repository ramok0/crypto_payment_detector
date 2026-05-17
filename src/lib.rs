pub mod bitcoin_sweep;
pub mod blockstream;
pub mod derivation;
pub mod env_utils;
pub mod error;
pub mod ethereum;
pub mod ethereum_pool;
pub mod etherscan;
pub mod helius_webhooks;
pub mod persistence;
pub mod pricing;
pub mod recover;
pub mod remote_config;
pub mod solana;
pub mod solana_pool;
pub mod solana_scheduled;
pub mod solana_tokens;
pub mod trait_def;
pub mod types;
pub mod webhook;

pub use bitcoin_sweep::{BitcoinSweepConfig, BitcoinSweepResult};
pub use blockstream::ChainDetector;
pub use error::DetectorError;
pub use ethereum::{
    Erc20TokenConfig, EthereumConfig, EthereumDetector, default_erc20_tokens, parse_erc20_tokens,
};
pub use ethereum_pool::{
    EthereumAssignment, EthereumReservation, ManagedEthereumWallet, SharedEthereumWallets,
    assign_ethereum_wallet_for_user, delete_all_ethereum_assignments,
    ethereum_reservation_store_url_from_env, ethereum_reservations_use_memory,
    load_active_ethereum_assignments, load_active_ethereum_reservations,
    load_ethereum_assignment_for_user, load_ethereum_wallet_pool, reserve_ethereum_wallet_for_user,
    shared_ethereum_wallets,
};
pub use etherscan::{EtherscanClient, EtherscanConfig, EtherscanInternalTx};
pub use helius_webhooks::{
    HeliusWebhookClient, HeliusWebhookConfig, collect_candidate_addresses, verify_auth_header,
};
pub use pricing::PriceFetcher;
pub use recover::{RecoverRequest, RecoverResponse, RecoverStatus};
pub use solana::{SolanaConfig, SolanaDetector};
pub use solana_pool::{
    ManagedSolanaWallet, SharedSolanaWallets, SolanaAssignment, SolanaReservation,
    assign_wallet_for_user, consolidate_assignments, delete_all_assignments,
    load_active_assignments, load_active_reservations, load_assignment_for_address,
    load_assignment_for_user, load_wallet_pool, reserve_wallet_for_user, rotate_assignment,
    shared_wallets,
};
pub use solana_tokens::{SplTokenConfig, default_spl_tokens, parse_spl_tokens};
pub use trait_def::PaymentDetector;
pub use types::{BasicAuth, Chain, DetectedPayment, DetectorConfig, RetryConfig, WebhookEvent};
pub use webhook::{send_discord_webhook, send_webhook, verify_signature};
