pub mod blockstream;
pub mod derivation;
pub mod env_utils;
pub mod error;
pub mod ethereum;
pub mod ethereum_pool;
pub mod persistence;
pub mod pricing;
pub mod solana;
pub mod solana_pool;
pub mod trait_def;
pub mod types;
pub mod webhook;

pub use blockstream::ChainDetector;
pub use error::DetectorError;
pub use ethereum::{
    Erc20TokenConfig, EthereumConfig, EthereumDetector, default_erc20_tokens, parse_erc20_tokens,
};
pub use ethereum_pool::{
    EthereumReservation, ManagedEthereumWallet, ethereum_reservation_store_url_from_env,
    ethereum_reservations_use_memory, load_active_ethereum_reservations, load_ethereum_wallet_pool,
    reserve_ethereum_wallet_for_user,
};
pub use pricing::PriceFetcher;
pub use solana::{SolanaConfig, SolanaDetector};
pub use solana_pool::{
    ManagedSolanaWallet, SolanaReservation, load_active_reservations, load_wallet_pool,
    reserve_wallet_for_user,
};
pub use trait_def::PaymentDetector;
pub use types::{BasicAuth, Chain, DetectedPayment, DetectorConfig, RetryConfig, WebhookEvent};
pub use webhook::{send_discord_webhook, send_webhook, verify_signature};
