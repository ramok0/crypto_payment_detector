use thiserror::Error;

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error("Invalid xpub key: {0}")]
    InvalidXpub(String),

    #[error("Address derivation failed for index {index}: {reason}")]
    DerivationFailed { index: u32, reason: String },

    #[error("API request failed: {0}")]
    ApiError(String),

    #[error("Webhook delivery failed: {0}")]
    WebhookError(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Redis error: {0}")]
    RedisError(String),

    #[error("Bitcoin key error: {0}")]
    BitcoinError(String),
}
