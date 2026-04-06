pub mod blockstream;
pub mod derivation;
pub mod error;
pub mod persistence;
pub mod pricing;
pub mod trait_def;
pub mod types;
pub mod webhook;

pub use blockstream::ChainDetector;
pub use error::DetectorError;
pub use pricing::PriceFetcher;
pub use trait_def::PaymentDetector;
pub use types::{BasicAuth, Chain, DetectedPayment, DetectorConfig, RetryConfig, WebhookEvent};
pub use webhook::{send_webhook, verify_signature};
