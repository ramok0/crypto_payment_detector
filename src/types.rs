use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Bitcoin,
    Litecoin,
    Solana,
}

impl Chain {
    pub fn ticker(&self) -> &'static str {
        match self {
            Chain::Bitcoin => "BTC",
            Chain::Litecoin => "LTC",
            Chain::Solana => "SOL",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Chain::Bitcoin => "Bitcoin",
            Chain::Litecoin => "Litecoin",
            Chain::Solana => "Solana",
        }
    }

    pub fn default_explorer_api(&self) -> &'static str {
        match self {
            Chain::Bitcoin => "https://blockstream.info/api",
            Chain::Litecoin => "https://litecoinspace.org/api",
            Chain::Solana => "https://api.mainnet.solana.com",
        }
    }

    pub fn raw_block_url(&self, hash: &str) -> String {
        match self {
            Chain::Bitcoin => format!("https://blockchain.info/rawblock/{}?format=hex", hash),
            Chain::Litecoin => format!("https://litecoinspace.org/api/block/{}/raw", hash),
            Chain::Solana => format!("https://api.mainnet.solana.com/block/{}", hash),
        }
    }

    pub fn raw_block_is_hex(&self) -> bool {
        match self {
            Chain::Bitcoin => true,
            Chain::Litecoin => false,
            Chain::Solana => false,
        }
    }

    pub fn sats_per_unit(&self) -> u64 {
        match self {
            Chain::Bitcoin | Chain::Litecoin => 100_000_000,
            Chain::Solana => 1_000_000_000,
        }
    }

    pub fn bitcoin_network(&self) -> bitcoin::Network {
        match self {
            Chain::Bitcoin => bitcoin::Network::Bitcoin,
            Chain::Litecoin => bitcoin::Network::Bitcoin,
            Chain::Solana => bitcoin::Network::Bitcoin,
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bitcoin" | "btc" => Ok(Chain::Bitcoin),
            "litecoin" | "ltc" => Ok(Chain::Litecoin),
            "solana" | "sol" => Ok(Chain::Solana),
            _ => Err(format!("Unknown chain: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPayment {
    pub chain: Chain,
    pub ticker: String,
    pub txid: String,
    pub address: String,
    pub amount_sat: u64,
    pub amount_coin: f64,
    pub confirmations: u64,
    pub block_height: Option<u64>,
    pub derivation_index: u32,
    pub memo: Option<String>,
    pub fiat_amount: Option<f64>,
    pub fiat_currency: Option<String>,
    pub coin_price: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum WebhookEvent {
    #[serde(rename = "payment_detected")]
    PaymentDetected(DetectedPayment),
    #[serde(rename = "payment_credited")]
    PaymentCredited(DetectedPayment),
}

#[derive(Debug, Clone)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_delay_ms: 1000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectorConfig {
    pub chain: Chain,
    pub xpub: String,
    pub webhook_url: String,
    pub webhook_hmac_secret: String,
    pub basic_auth: BasicAuth,
    pub poll_interval_secs: u64,
    pub proxy_url: Option<String>,
    pub state_file: String,
    pub fiat_currency: String,
    pub retry: RetryConfig,
    pub explorer_api_url: Option<String>,
    pub min_confirmations: u64,
    pub skip_initial_block_sync: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            chain: Chain::Bitcoin,
            xpub: String::new(),
            webhook_url: String::new(),
            webhook_hmac_secret: String::new(),
            basic_auth: BasicAuth {
                username: String::new(),
                password: String::new(),
            },
            poll_interval_secs: 30,
            proxy_url: None,
            state_file: "detector_state.json".to_string(),
            fiat_currency: "EUR".to_string(),
            retry: RetryConfig::default(),
            explorer_api_url: None,
            min_confirmations: 1,
            skip_initial_block_sync: false,
        }
    }
}
