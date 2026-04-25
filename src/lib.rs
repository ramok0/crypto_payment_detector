pub mod blockstream;
pub mod derivation;
pub mod env_utils;
pub mod error;
pub mod persistence;
pub mod pricing;
pub mod solana;
pub mod solana_pool;
pub mod trait_def;
pub mod types;
pub mod webhook;

pub use blockstream::ChainDetector;
pub use error::DetectorError;
pub use pricing::PriceFetcher;
pub use solana::{SolanaConfig, SolanaDetector};
pub use solana_pool::{
    ManagedSolanaWallet, SolanaReservation, load_active_reservations, load_wallet_pool,
    reserve_wallet_for_user,
};
pub use trait_def::PaymentDetector;
pub use types::{BasicAuth, Chain, DetectedPayment, DetectorConfig, RetryConfig, WebhookEvent};
pub use webhook::{send_discord_webhook, send_webhook, verify_signature};
