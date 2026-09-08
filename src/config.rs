//! Declarative settings catalog and env-driven config builders.
//!
//! Single source of truth for three things that used to drift apart:
//!
//! 1. **Runtime resolution** — the value each detector actually runs with.
//! 2. **The boot preflight report** — what is missing, per chain, all at once.
//! 3. **The schema served to the admin panel** — so it can render its fields
//!    pre-filled with the same defaults this process would apply.
//!
//! Before this module, `build_config` / `build_solana_config` /
//! `build_evm_config` were duplicated byte-for-byte between the two binaries
//! and every missing variable was a `panic!` deep inside a struct literal: the
//! operator discovered them one at a time, one restart each, and a single
//! half-configured chain took the whole process down. Builders here return
//! `Err(Vec<MissingSetting>)` instead, so a caller can report everything at
//! once and disable just that chain.
//!
//! Adding a setting means adding one [`Setting`] to [`SETTINGS`] and reading it
//! from the relevant builder. The panel picks it up for free.

use std::fmt::Display;
use std::str::FromStr;

use serde::Serialize;

use crate::env_utils::{chain_env_prefix, proxy_env_var};
use crate::ethereum::EthereumConfig;
use crate::etherscan::EtherscanConfig;
use crate::solana::SolanaConfig;
use crate::types::{BasicAuth, Chain, DetectorConfig, RetryConfig};

/// Placeholder in a [`Setting::key`] replaced by [`chain_env_prefix`]
/// (`BTC`/`LTC`/`SOL`/`ETH`/`BASE`).
pub const PREFIX_PLACEHOLDER: &str = "{P}";

const ALL_CHAINS: &[Chain] = &[
    Chain::Bitcoin,
    Chain::Litecoin,
    Chain::Solana,
    Chain::Ethereum,
    Chain::Base,
];
const EVM_CHAINS: &[Chain] = &[Chain::Ethereum, Chain::Base];
const UTXO_CHAINS: &[Chain] = &[Chain::Bitcoin, Chain::Litecoin];

// -----------------------------------------------------------------------------
// Catalog types
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// One process-wide variable, `key` written in full.
    Global,
    /// Exactly one chain, `key` written in full (used where the historical
    /// name doesn't follow the `{P}_` convention, e.g. `SOLANA_*`).
    Chain(Chain),
    /// `key` (and every alias) contains `{P}`, expanded once per listed chain.
    Prefixed(&'static [Chain]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    Required,
    Optional,
}

/// Hint for the admin panel on how to render the field. `Secret` additionally
/// means "never echo this value anywhere".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Url,
    Integer,
    Decimal,
    Boolean,
    Address,
    Secret,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::Url => "url",
            Kind::Integer => "integer",
            Kind::Decimal => "decimal",
            Kind::Boolean => "boolean",
            Kind::Address => "address",
            Kind::Secret => "secret",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DefaultValue {
    /// No default: either genuinely optional, or `Required` and the operator
    /// must supply it.
    None,
    Static(&'static str),
    /// Differs per chain (e.g. `MIN_CONFIRMATIONS` is 12 on Ethereum, 5 on Base).
    PerChain(&'static [(Chain, &'static str)]),
}

impl DefaultValue {
    pub fn resolve(&self, chain: Option<Chain>) -> Option<&'static str> {
        match self {
            DefaultValue::None => None,
            DefaultValue::Static(value) => Some(value),
            DefaultValue::PerChain(entries) => {
                let chain = chain?;
                entries
                    .iter()
                    .find(|(candidate, _)| *candidate == chain)
                    .map(|(_, value)| *value)
            }
        }
    }
}

pub struct Setting {
    /// Canonical env var name, possibly containing [`PREFIX_PLACEHOLDER`].
    pub key: &'static str,
    /// Fallback names tried in order after `key`. Kept verbatim from the
    /// pre-refactor builders — these are a backward-compatibility contract,
    /// not a place to tidy up.
    pub aliases: &'static [&'static str],
    pub scope: Scope,
    pub kind: Kind,
    pub requirement: Requirement,
    pub default: DefaultValue,
    pub secret: bool,
    pub description: &'static str,
}

impl Setting {
    pub fn is_required(&self) -> bool {
        self.requirement == Requirement::Required
    }

    /// Chains this setting applies to, or `None` when process-wide.
    pub fn chains(&self) -> Option<&'static [Chain]> {
        match self.scope {
            Scope::Global => None,
            Scope::Chain(_) => None,
            Scope::Prefixed(chains) => Some(chains),
        }
    }
}

/// Expand `{P}` using the chain prefix. A key without the placeholder is
/// returned unchanged, so this is safe to call unconditionally.
pub fn expand_key(key: &str, chain: Option<Chain>) -> String {
    match chain {
        Some(chain) if key.contains(PREFIX_PLACEHOLDER) => {
            key.replace(PREFIX_PLACEHOLDER, chain_env_prefix(chain))
        }
        _ => key.to_string(),
    }
}

pub fn find_setting(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|setting| setting.key == key)
}

// -----------------------------------------------------------------------------
// The catalog
// -----------------------------------------------------------------------------

const MIN_CONFIRMATIONS_DEFAULTS: &[(Chain, &str)] = &[
    (Chain::Bitcoin, "1"),
    (Chain::Litecoin, "1"),
    (Chain::Solana, "1"),
    // Base finalizes faster (~2s blocks); 5 gives ~10s of finality. Mainnet
    // keeps its conservative 12.
    (Chain::Ethereum, "12"),
    (Chain::Base, "5"),
];

const POLL_INTERVAL_DEFAULTS: &[(Chain, &str)] = &[
    (Chain::Bitcoin, "30"),
    (Chain::Litecoin, "30"),
    (Chain::Solana, "60"),
    (Chain::Ethereum, "30"),
    (Chain::Base, "30"),
];

const STATE_FILE_DEFAULTS: &[(Chain, &str)] = &[
    (Chain::Bitcoin, "btc_detector_state.json"),
    (Chain::Litecoin, "ltc_detector_state.json"),
    (Chain::Solana, "sol_detector_state.json"),
    (Chain::Ethereum, "eth_detector_state.json"),
    (Chain::Base, "base_detector_state.json"),
];

const RPC_URL_DEFAULTS: &[(Chain, &str)] = &[
    (Chain::Ethereum, "https://cloudflare-eth.com"),
    (Chain::Base, "https://mainnet.base.org"),
];

const CHAIN_ID_DEFAULTS: &[(Chain, &str)] = &[(Chain::Ethereum, "1"), (Chain::Base, "8453")];

const WALLET_POOL_FILE_DEFAULTS: &[(Chain, &str)] = &[
    (Chain::Ethereum, "wallet_pool/ethereum_wallets.json"),
    (Chain::Base, "wallet_pool/base_wallets.json"),
];

// The public Base RPC (mainnet.base.org) returns -32016 "over rate limit"
// under burst load, e.g. the orphan sweep on a 10-wallet pool. 200ms is ~5
// req/s. Ethereum operators typically pay for an endpoint and need no throttle.
const RPC_THROTTLE_DEFAULTS: &[(Chain, &str)] = &[(Chain::Ethereum, "0"), (Chain::Base, "200")];

pub const SETTINGS: &[Setting] = &[
    Setting {
        key: "QUICKNODE_API_KEY",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "QuickNode Admin API key for usage and KV lists.",
    },
    Setting {
        key: "QUICKNODE_API_BASE_URL",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("https://api.quicknode.com"),
        secret: false,
        description: "QuickNode Admin API base URL.",
    },
    Setting {
        key: "QUICKNODE_WEBHOOK_ENABLED",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Boolean,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("false"),
        secret: false,
        description: "Enable QuickNode push notifications globally; polling remains enabled.",
    },
    Setting {
        key: "QUICKNODE_SOLANA_WEBHOOK_ENABLED",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Boolean,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Override global QuickNode activation for this chain.",
    },
    Setting {
        key: "QUICKNODE_SOLANA_SECURITY_TOKEN",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "QuickNode webhook HMAC security token.",
    },
    Setting {
        key: "QUICKNODE_SOLANA_LIST_NAME",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Existing QuickNode KV list for wallet addresses.",
    },
    Setting {
        key: "QUICKNODE_ETH_WEBHOOK_ENABLED",
        aliases: &[],
        scope: Scope::Chain(Chain::Ethereum),
        kind: Kind::Boolean,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Override global QuickNode activation for this chain.",
    },
    Setting {
        key: "QUICKNODE_ETH_SECURITY_TOKEN",
        aliases: &[],
        scope: Scope::Chain(Chain::Ethereum),
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "QuickNode webhook HMAC security token.",
    },
    Setting {
        key: "QUICKNODE_ETH_LIST_NAME",
        aliases: &[],
        scope: Scope::Chain(Chain::Ethereum),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Existing QuickNode KV list for wallet addresses.",
    },
    Setting {
        key: "QUICKNODE_ETH_TOKEN_LIST_NAME",
        aliases: &[],
        scope: Scope::Chain(Chain::Ethereum),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Existing QuickNode KV list for token contracts.",
    },
    Setting {
        key: "QUICKNODE_BASE_WEBHOOK_ENABLED",
        aliases: &[],
        scope: Scope::Chain(Chain::Base),
        kind: Kind::Boolean,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Override global QuickNode activation for this chain.",
    },
    Setting {
        key: "QUICKNODE_BASE_SECURITY_TOKEN",
        aliases: &[],
        scope: Scope::Chain(Chain::Base),
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "QuickNode webhook HMAC security token.",
    },
    Setting {
        key: "QUICKNODE_BASE_LIST_NAME",
        aliases: &[],
        scope: Scope::Chain(Chain::Base),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Existing QuickNode KV list for wallet addresses.",
    },
    Setting {
        key: "QUICKNODE_BASE_TOKEN_LIST_NAME",
        aliases: &[],
        scope: Scope::Chain(Chain::Base),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Existing QuickNode KV list for token contracts.",
    },
    // --- Global ------------------------------------------------------------
    Setting {
        key: "CHAIN",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("bitcoin"),
        secret: false,
        description: "Chains to run: bitcoin, litecoin, solana, ethereum, base, a comma-separated list, or the aliases both / solbtc / all.",
    },
    Setting {
        key: "WEBHOOK_URL",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Url,
        requirement: Requirement::Required,
        default: DefaultValue::None,
        secret: false,
        description: "Endpoint receiving payment_detected / payment_credited events.",
    },
    Setting {
        key: "WEBHOOK_SECRET",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Secret,
        requirement: Requirement::Required,
        default: DefaultValue::None,
        secret: true,
        description: "HMAC-SHA256 key used to sign webhooks (X-Signature-256 header).",
    },
    Setting {
        key: "REDIS_URL",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("redis://127.0.0.1:6379"),
        secret: false,
        description: "Redis holding Solana address assignments and EVM reservations. Required for Solana; EVM chains can opt out with {P}_RESERVATION_STORE=memory.",
    },
    Setting {
        key: "FIAT_CURRENCY",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("EUR"),
        secret: false,
        description: "Currency used to enrich webhook payloads with a fiat amount.",
    },
    Setting {
        key: "API_BIND",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("0.0.0.0:3030"),
        secret: false,
        description: "Address the HTTP API listens on.",
    },
    Setting {
        key: "MAX_RETRIES",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("5"),
        secret: false,
        description: "Retry budget for explorer/RPC calls.",
    },
    Setting {
        key: "RETRY_BASE_DELAY_MS",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("1000"),
        secret: false,
        description: "Base delay for exponential backoff, in milliseconds.",
    },
    Setting {
        key: "MAX_DERIVATION_INDEX",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("100"),
        secret: false,
        description: "How many BTC/LTC addresses to pre-derive from the xpub. High values slow startup and cost memory.",
    },
    Setting {
        key: "AUTH_USER",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Optional HTTP basic-auth user for explorer endpoints that require it.",
    },
    Setting {
        key: "AUTH_PASS",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "Password paired with AUTH_USER.",
    },
    Setting {
        key: "PROXY",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Global outbound proxy (http/socks5). Per-chain {P}_PROXY overrides it; set a chain one to off/none to bypass.",
    },
    Setting {
        key: "DISABLE_BASE",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Boolean,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("false"),
        secret: false,
        description: "Killswitch removing Base from the chain list before any detector spawns, independent of CHAIN.",
    },
    Setting {
        key: "CORE_API_INTERNAL_URL",
        aliases: &["BACKEND_API_INTERNAL_URL"],
        scope: Scope::Global,
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Backend base URL serving the admin-panel runtime config and receiving scheduled-payment commits.",
    },
    Setting {
        key: "INTERNAL_SERVICE_TOKEN",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "Shared secret for the X-Internal-Service-Token header, both outbound and for /internal routes.",
    },
    Setting {
        key: "RUNTIME_CONFIG_POLL_SECS",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("30"),
        secret: false,
        description: "How often to poll the admin panel for config changes (minimum 5).",
    },
    Setting {
        key: "MAX_FEE_RATIO",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Decimal,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("0.10"),
        secret: false,
        description: "Global fee guard: defer a sweep whose fee exceeds this fraction of the swept amount.",
    },
    // --- Per-chain, prefixed ----------------------------------------------
    Setting {
        key: "{P}_POLL_INTERVAL",
        aliases: &["POLL_INTERVAL"],
        scope: Scope::Prefixed(ALL_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::PerChain(POLL_INTERVAL_DEFAULTS),
        secret: false,
        description: "Seconds between scan cycles.",
    },
    Setting {
        key: "{P}_MIN_CONFIRMATIONS",
        aliases: &["MIN_CONFIRMATIONS"],
        scope: Scope::Prefixed(ALL_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::PerChain(MIN_CONFIRMATIONS_DEFAULTS),
        secret: false,
        description: "Confirmations required before sweeping and emitting payment_credited.",
    },
    Setting {
        key: "{P}_STATE_FILE",
        aliases: &["STATE_FILE"],
        scope: Scope::Prefixed(ALL_CHAINS),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::PerChain(STATE_FILE_DEFAULTS),
        secret: false,
        description: "JSON file holding the scan cursor and pending payments. Relative paths resolve against the working directory.",
    },
    Setting {
        key: "{P}_MAX_FEE_RATIO",
        aliases: &["MAX_FEE_RATIO"],
        scope: Scope::Prefixed(ALL_CHAINS),
        kind: Kind::Decimal,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("0.10"),
        secret: false,
        description: "Per-chain fee guard, overriding MAX_FEE_RATIO.",
    },
    Setting {
        key: "{P}_PROXY",
        aliases: &[],
        scope: Scope::Prefixed(ALL_CHAINS),
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Per-chain proxy. Set to off/none/direct to bypass the global PROXY for this chain only.",
    },
    // --- Bitcoin / Litecoin ------------------------------------------------
    Setting {
        key: "{P}_XPUB",
        aliases: &[],
        scope: Scope::Prefixed(UTXO_CHAINS),
        kind: Kind::Text,
        requirement: Requirement::Required,
        default: DefaultValue::None,
        secret: false,
        description: "Extended public key (BIP84) the deposit addresses are derived from. Litecoin accepts Ltub or xpub. Enables the chain.",
    },
    Setting {
        key: "{P}_XPRIV",
        aliases: &[],
        scope: Scope::Prefixed(UTXO_CHAINS),
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "Extended private key. Only needed to enable sweeping; pair with {P}_SWEEP_DESTINATION.",
    },
    Setting {
        key: "{P}_SWEEP_DESTINATION",
        aliases: &[],
        scope: Scope::Prefixed(UTXO_CHAINS),
        kind: Kind::Address,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Cold P2WPKH bech32 address receiving swept funds. Without it the detector is a read-only monitor.",
    },
    Setting {
        key: "{P}_SWEEP_FEE_RATE_SATS_PER_VB",
        aliases: &["SWEEP_FEE_RATE_SATS_PER_VB"],
        scope: Scope::Prefixed(UTXO_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("5"),
        secret: false,
        description: "Fee rate used to build sweep transactions.",
    },
    Setting {
        key: "{P}_SWEEP_MIN_SAT",
        aliases: &["SWEEP_MIN_SAT"],
        scope: Scope::Prefixed(UTXO_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("5000"),
        secret: false,
        description: "Do not sweep below this amount in satoshis.",
    },
    Setting {
        key: "{P}_EXPLORER_API_URLS",
        aliases: &[
            "{P}_EXPLORER_API_URL",
            "EXPLORER_API_URLS",
            "EXPLORER_API_URL",
        ],
        scope: Scope::Prefixed(UTXO_CHAINS),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Comma-separated Esplora/Blockchair endpoints, tried in order. Falls back to the built-in list.",
    },
    Setting {
        key: "{P}_SKIP_INITIAL_BLOCK_SYNC",
        aliases: &["SKIP_INITIAL_BLOCK_SYNC"],
        scope: Scope::Prefixed(UTXO_CHAINS),
        kind: Kind::Boolean,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("false"),
        secret: false,
        description: "Start scanning at the current tip instead of replaying history.",
    },
    Setting {
        key: "BLOCKCHAIR_API_KEY",
        aliases: &[],
        scope: Scope::Chain(Chain::Litecoin),
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "Optional Blockchair key, appended to Blockchair explorer URLs.",
    },
    // --- Solana ------------------------------------------------------------
    Setting {
        key: "SOLANA_DEPOSIT_ADDRESS",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Address,
        requirement: Requirement::Required,
        default: DefaultValue::None,
        secret: false,
        description: "Cold destination receiving swept SOL and SPL tokens. Enables the Solana chain.",
    },
    Setting {
        key: "SOLANA_RPC_URL",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("https://api.mainnet.solana.com"),
        secret: false,
        description: "Solana JSON-RPC endpoint.",
    },
    Setting {
        key: "SOLANA_WALLET_POOL_FILE",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("wallet_pool/solana_wallets.json"),
        secret: false,
        description: "JSON file holding the managed wallet private keys. Created automatically if absent — back it up.",
    },
    Setting {
        key: "SOLANA_WALLET_POOL_SIZE",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("10"),
        secret: false,
        description: "How many wallets to generate when creating the pool file. The pool also grows on demand.",
    },
    Setting {
        key: "SOLANA_MAX_POOL_SIZE",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("10000"),
        secret: false,
        description: "Upper bound on automatic pool growth.",
    },
    Setting {
        key: "SOLANA_GAS_TANK_PRIVATE_KEY",
        aliases: &["SOLANA_FEE_PAYER_PRIVATE_KEY"],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "Hot wallet paying SPL transaction fees and absorbing native SOL sweeps. Required to sweep SPL tokens; should differ from SOLANA_DEPOSIT_ADDRESS.",
    },
    Setting {
        key: "SOLANA_GAS_TANK_TARGET_USD",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Decimal,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("10"),
        secret: false,
        description: "Balance kept on the gas tank; the excess is forwarded to the deposit address.",
    },
    Setting {
        key: "SOLANA_GAS_TANK_INTERVAL_SECS",
        aliases: &["SOLANA_GAS_TANK_CHECK_INTERVAL_SECS"],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("900"),
        secret: false,
        description: "How often to run gas-tank maintenance.",
    },
    Setting {
        key: "SOLANA_SPL_TOKENS",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("default"),
        secret: false,
        description: "SYMBOL:mint:decimals list, or default (mainnet USDC) or none.",
    },
    Setting {
        key: "SOLANA_RESERVATION_TTL_SECS",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("3600"),
        secret: false,
        description: "Legacy TTL field. Address assignments are permanent, so this is inert on the assignment path.",
    },
    Setting {
        key: "SOL_MIN_DEPOSIT_FIAT",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Decimal,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("0.5"),
        secret: false,
        description: "Ignore deposits worth less than this in FIAT_CURRENCY.",
    },
    Setting {
        key: "SOL_PENDING_POLL_INTERVAL",
        aliases: &[],
        scope: Scope::Chain(Chain::Solana),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("30"),
        secret: false,
        description: "Seconds between checks of payments awaiting confirmation.",
    },
    // --- Ethereum / Base ---------------------------------------------------
    Setting {
        key: "{P}_GAS_TANK_PRIVATE_KEY",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Secret,
        requirement: Requirement::Required,
        default: DefaultValue::None,
        secret: true,
        description: "Hot wallet funding gas top-ups and receiving native sweeps. Enables the chain.",
    },
    Setting {
        key: "{P}_LEDGER_ADDRESS",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Address,
        requirement: Requirement::Required,
        default: DefaultValue::None,
        secret: false,
        description: "Cold destination receiving ERC-20 sweeps and the gas tank's excess ETH.",
    },
    Setting {
        key: "{P}_RPC_URL",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::PerChain(RPC_URL_DEFAULTS),
        secret: false,
        description: "JSON-RPC endpoint.",
    },
    Setting {
        key: "{P}_CHAIN_ID",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::PerChain(CHAIN_ID_DEFAULTS),
        secret: false,
        description: "EIP-155 chain id used when signing.",
    },
    Setting {
        key: "{P}_WALLET_POOL_FILE",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::PerChain(WALLET_POOL_FILE_DEFAULTS),
        secret: false,
        description: "JSON file holding the managed wallet private keys. Created automatically if absent — back it up.",
    },
    Setting {
        key: "{P}_WALLET_POOL_SIZE",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("10"),
        secret: false,
        description: "How many wallets to generate when creating the pool file.",
    },
    Setting {
        key: "{P}_MAX_POOL_SIZE",
        aliases: &["{P}_WALLET_POOL_MAX_SIZE"],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("10000"),
        secret: false,
        description: "Upper bound on automatic pool growth.",
    },
    Setting {
        key: "{P}_ERC20_TOKENS",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("default"),
        secret: false,
        description: "SYMBOL:0xcontract:decimals list, or default (USDC + USDT for that chain) or none.",
    },
    Setting {
        key: "{P}_RESERVATION_STORE",
        aliases: &["RESERVATION_STORE"],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Text,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Set to memory to keep reservations in process memory instead of Redis. Testing only: they are lost on restart.",
    },
    Setting {
        key: "{P}_RESERVATION_TTL_SECS",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("3600"),
        secret: false,
        description: "How long a reserved address stays assigned to a user.",
    },
    Setting {
        key: "{P}_GAS_TANK_TARGET_USD",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Decimal,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("20"),
        secret: false,
        description: "Balance kept on the gas tank; the excess is forwarded to the ledger address.",
    },
    Setting {
        key: "{P}_GAS_TANK_INTERVAL_SECS",
        aliases: &["{P}_GAS_TANK_CHECK_INTERVAL_SECS"],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("900"),
        secret: false,
        description: "How often to run gas-tank maintenance.",
    },
    Setting {
        key: "{P}_TOKEN_TRANSFER_GAS_LIMIT",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("100000"),
        secret: false,
        description: "Gas limit used for ERC-20 transfers.",
    },
    Setting {
        key: "{P}_GAS_TOP_UP_MULTIPLIER",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Decimal,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("1.25"),
        secret: false,
        description: "Safety margin applied when topping up a managed wallet's gas.",
    },
    Setting {
        key: "{P}_MAX_BLOCKS_PER_CYCLE",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("250"),
        secret: false,
        description: "Cap on blocks scanned per cycle when catching up.",
    },
    Setting {
        key: "{P}_START_BLOCK",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: false,
        description: "Backfill from this block instead of starting at the tip.",
    },
    Setting {
        key: "{P}_RPC_MIN_REQUEST_INTERVAL_MS",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::PerChain(RPC_THROTTLE_DEFAULTS),
        secret: false,
        description: "Client-side throttle between JSON-RPC calls. The public Base endpoint needs ~200ms; set 0 with a paid RPC.",
    },
    Setting {
        key: "{P}_ETHERSCAN_ENABLED",
        aliases: &[],
        scope: Scope::Prefixed(EVM_CHAINS),
        kind: Kind::Boolean,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("true"),
        secret: false,
        description: "Per-chain toggle for the internal-tx scan. The free Etherscan plan rejects Base, so set BASE_ETHERSCAN_ENABLED=false there.",
    },
    Setting {
        key: "ETHERSCAN_API_KEY",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Secret,
        requirement: Requirement::Optional,
        default: DefaultValue::None,
        secret: true,
        description: "Enables detection of ETH arriving through contract internal calls (Coinbase withdrawals). One key covers both EVM chains.",
    },
    Setting {
        key: "ETHERSCAN_BASE_URL",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Url,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("https://api.etherscan.io/v2/api"),
        secret: false,
        description: "Etherscan V2 multichain endpoint.",
    },
    Setting {
        key: "ETHERSCAN_TIMEOUT_SECS",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("15"),
        secret: false,
        description: "Per-request timeout for Etherscan calls.",
    },
    Setting {
        key: "ETHERSCAN_MIN_REQUEST_INTERVAL_MS",
        aliases: &[],
        scope: Scope::Global,
        kind: Kind::Integer,
        requirement: Requirement::Optional,
        default: DefaultValue::Static("334"),
        secret: false,
        description: "Client-side throttle; 334ms is about 3 req/s, under the 5 req/s free tier.",
    },
];

// -----------------------------------------------------------------------------
// Resolution
// -----------------------------------------------------------------------------

/// A required setting the operator has not supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingSetting {
    /// Fully expanded env var name (e.g. `BASE_LEDGER_ADDRESS`).
    pub key: String,
    pub description: &'static str,
}

/// Reads settings through the catalog, collecting what is missing instead of
/// panicking on the first gap.
pub struct Resolver {
    chain: Option<Chain>,
    missing: Vec<MissingSetting>,
}

impl Resolver {
    pub fn new(chain: Option<Chain>) -> Self {
        Self {
            chain,
            missing: Vec::new(),
        }
    }

    /// Everything collected so far, or `Ok(())` when the config is complete.
    pub fn finish(self) -> Result<(), Vec<MissingSetting>> {
        if self.missing.is_empty() {
            Ok(())
        } else {
            Err(self.missing)
        }
    }

    fn expand(&self, key: &str) -> String {
        expand_key(key, self.chain)
    }

    /// First non-empty value among the canonical key and its aliases, else the
    /// catalog default. An empty or whitespace-only value counts as unset —
    /// otherwise `FOO=` would satisfy a required setting and fail later, deeper.
    fn lookup(&mut self, key: &str) -> Option<String> {
        let Some(setting) = find_setting(key) else {
            // A builder asked for a key that is not in the catalog. That is a
            // programming error, not an operator one: fail loudly in debug and
            // degrade to a plain env read in release.
            debug_assert!(false, "setting '{key}' is missing from SETTINGS");
            log::error!("Setting '{key}' is missing from the config catalog");
            return std::env::var(self.expand(key))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
        };

        let found = std::iter::once(setting.key)
            .chain(setting.aliases.iter().copied())
            .find_map(|name| {
                std::env::var(self.expand(name))
                    .ok()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
            });

        found.or_else(|| {
            setting
                .default
                .resolve(self.chain)
                .map(|value| value.to_string())
        })
    }

    fn record_missing(&mut self, key: &str) {
        let expanded = self.expand(key);
        if self.missing.iter().any(|entry| entry.key == expanded) {
            return;
        }
        let description = find_setting(key)
            .map(|setting| setting.description)
            .unwrap_or("");
        self.missing.push(MissingSetting {
            key: expanded,
            description,
        });
    }

    /// Value of a required setting. Records it as missing and returns an empty
    /// string when absent — the caller discards the config via [`Self::finish`].
    pub fn text(&mut self, key: &str) -> String {
        match self.lookup(key) {
            Some(value) => value,
            None => {
                self.record_missing(key);
                String::new()
            }
        }
    }

    pub fn opt_text(&mut self, key: &str) -> Option<String> {
        self.lookup(key)
    }

    /// Parsed numeric value, falling back to the catalog default.
    ///
    /// A malformed value warns before falling back. The pre-refactor builders
    /// swallowed it silently (`.parse().ok().unwrap_or(default)`), so a typo in
    /// `ETH_MIN_CONFIRMATIONS` looked exactly like not setting it at all.
    pub fn number<T>(&mut self, key: &str) -> T
    where
        T: FromStr + Default,
        T::Err: Display,
    {
        self.opt_number(key).unwrap_or_else(|| {
            log::error!(
                "Setting '{}' has no default in the config catalog; using the type default",
                self.expand(key)
            );
            T::default()
        })
    }

    pub fn opt_number<T>(&mut self, key: &str) -> Option<T>
    where
        T: FromStr,
        T::Err: Display,
    {
        let raw = self.lookup(key)?;
        match raw.parse::<T>() {
            Ok(value) => Some(value),
            Err(error) => {
                log::warn!(
                    "Ignoring invalid value {}={:?} ({error}); falling back to the default",
                    self.expand(key),
                    raw
                );
                // Retry with the catalog default so a typo degrades to the
                // documented value rather than to whatever the caller guessed.
                find_setting(key)
                    .and_then(|setting| setting.default.resolve(self.chain))
                    .and_then(|value| value.parse::<T>().ok())
            }
        }
    }

    pub fn flag(&mut self, key: &str) -> bool {
        let Some(raw) = self.lookup(key) else {
            return false;
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => {
                log::warn!(
                    "Ignoring invalid boolean {}={:?}; expected one of 1/0, true/false, yes/no, on/off",
                    self.expand(key),
                    raw
                );
                false
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Preflight reporting
// -----------------------------------------------------------------------------

/// Outcome of building one chain's config.
pub struct ChainReadiness {
    pub chain: Chain,
    pub detail: String,
    pub missing: Vec<MissingSetting>,
}

impl ChainReadiness {
    pub fn enabled(chain: Chain, detail: impl Into<String>) -> Self {
        Self {
            chain,
            detail: detail.into(),
            missing: Vec::new(),
        }
    }

    pub fn disabled(chain: Chain, missing: Vec<MissingSetting>) -> Self {
        Self {
            chain,
            detail: String::new(),
            missing,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Print one aggregated report covering every requested chain.
///
/// Deliberately on stderr rather than through `log`: with `RUST_LOG` unset,
/// `env_logger` filters at `error`, so the old `log::warn!` hints were invisible
/// and an unconfigured process looked like it had started fine and then hung.
pub fn print_readiness_report(report: &[ChainReadiness]) {
    eprintln!();
    eprintln!("=== Detector configuration ===");
    if report.is_empty() {
        eprintln!(
            "  No chain requested. Set CHAIN (bitcoin, litecoin, solana, ethereum, base, all)."
        );
    }
    for entry in report {
        if entry.is_enabled() {
            eprintln!("  [{}] enabled — {}", entry.chain.ticker(), entry.detail);
        } else {
            eprintln!("  [{}] DISABLED — missing settings:", entry.chain.ticker());
            for missing in &entry.missing {
                eprintln!("        {} — {}", missing.key, missing.description);
            }
        }
    }
    if report.iter().all(|entry| !entry.is_enabled()) {
        eprintln!();
        eprintln!(
            "  No chain is active. The process stays up so the admin panel can push a \
             configuration; it restarts itself once one arrives."
        );
    }
    eprintln!();
}

// -----------------------------------------------------------------------------
// Schema (served to the admin panel)
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SettingSchema {
    pub key: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub chain: Option<String>,
    pub kind: &'static str,
    pub required: bool,
    pub secret: bool,
    pub default: Option<String>,
    pub description: &'static str,
}

/// The catalog, flattened for the admin panel: `{P}` already expanded per
/// chain, defaults resolved per chain.
///
/// Describes the *shape* of the configuration only — it never reads the
/// environment, so no secret can leak through this endpoint.
pub fn settings_schema() -> Vec<SettingSchema> {
    let mut schema = Vec::new();

    for setting in SETTINGS {
        let chains: Vec<Option<Chain>> = match setting.scope {
            Scope::Global => vec![None],
            Scope::Chain(chain) => vec![Some(chain)],
            Scope::Prefixed(chains) => chains.iter().copied().map(Some).collect(),
        };

        for chain in chains {
            schema.push(SettingSchema {
                key: expand_key(setting.key, chain),
                aliases: setting
                    .aliases
                    .iter()
                    .map(|alias| expand_key(alias, chain))
                    .collect(),
                chain: chain.map(|chain| chain.ticker().to_string()),
                kind: setting.kind.as_str(),
                required: setting.is_required(),
                secret: setting.secret,
                default: setting
                    .default
                    .resolve(chain)
                    .map(|value| value.to_string()),
                description: setting.description,
            });
        }
    }

    schema
}

// -----------------------------------------------------------------------------
// Builders
// -----------------------------------------------------------------------------

fn explorer_api_config(resolver: &mut Resolver) -> Option<String> {
    resolver.opt_text("{P}_EXPLORER_API_URLS")
}

/// Parse `{P}_ETHERSCAN_ENABLED`.
///
/// Kept separate from [`Resolver::flag`] on purpose: this one treats *any*
/// unrecognised value as `true` and additionally accepts `disabled`. Routing it
/// through the strict boolean parser would turn `BASE_ETHERSCAN_ENABLED=disabled`
/// from "off" into "on".
fn etherscan_enabled(chain: Chain) -> bool {
    let prefix = chain_env_prefix(chain);
    match std::env::var(format!("{prefix}_ETHERSCAN_ENABLED")) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off" | "disabled"
        ),
        Err(_) => true,
    }
}

/// True when the operator has supplied the setting that switches this chain on.
///
/// Kept separate from the builders so a caller can tell "not configured at all"
/// (stay quiet, the chain simply isn't wanted) from "half configured" (report
/// exactly what is missing).
pub fn chain_is_requested(chain: Chain) -> bool {
    let key = match chain {
        Chain::Bitcoin | Chain::Litecoin => "{P}_XPUB",
        Chain::Solana => "SOLANA_DEPOSIT_ADDRESS",
        Chain::Ethereum | Chain::Base => "{P}_GAS_TANK_PRIVATE_KEY",
    };
    Resolver::new(Some(chain)).opt_text(key).is_some()
}

/// Env var that enables `chain`, for use in operator-facing messages.
pub fn chain_enable_key(chain: Chain) -> String {
    let key = match chain {
        Chain::Bitcoin | Chain::Litecoin => "{P}_XPUB",
        Chain::Solana => "SOLANA_DEPOSIT_ADDRESS",
        Chain::Ethereum | Chain::Base => "{P}_GAS_TANK_PRIVATE_KEY",
    };
    expand_key(key, Some(chain))
}

pub fn build_config(chain: Chain, xpub: String) -> Result<DetectorConfig, Vec<MissingSetting>> {
    let mut resolver = Resolver::new(Some(chain));

    let config = DetectorConfig {
        chain,
        xpub,
        webhook_url: resolver.text("WEBHOOK_URL"),
        webhook_hmac_secret: resolver.text("WEBHOOK_SECRET"),
        basic_auth: BasicAuth {
            username: resolver.opt_text("AUTH_USER").unwrap_or_default(),
            password: resolver.opt_text("AUTH_PASS").unwrap_or_default(),
        },
        poll_interval_secs: resolver.number("{P}_POLL_INTERVAL"),
        // Note: BTC/LTC deliberately read the raw global PROXY rather than
        // going through proxy_env_var, matching the pre-refactor behavior.
        proxy_url: std::env::var("PROXY").ok(),
        state_file: resolver.text("{P}_STATE_FILE"),
        fiat_currency: resolver.text("FIAT_CURRENCY"),
        retry: RetryConfig {
            max_retries: resolver.number("MAX_RETRIES"),
            base_delay_ms: resolver.number("RETRY_BASE_DELAY_MS"),
        },
        explorer_api_url: explorer_api_config(&mut resolver),
        min_confirmations: resolver.number("{P}_MIN_CONFIRMATIONS"),
        skip_initial_block_sync: resolver.flag("{P}_SKIP_INITIAL_BLOCK_SYNC"),
        sweep_xpriv: resolver.opt_text("{P}_XPRIV"),
        sweep_destination: resolver.opt_text("{P}_SWEEP_DESTINATION"),
        sweep_fee_rate_sats_per_vb: resolver.number("{P}_SWEEP_FEE_RATE_SATS_PER_VB"),
        sweep_min_sat: resolver.number("{P}_SWEEP_MIN_SAT"),
        sweep_max_fee_ratio: resolver.number("{P}_MAX_FEE_RATIO"),
    };

    resolver.finish()?;
    Ok(config)
}

pub fn build_solana_config() -> Result<SolanaConfig, Vec<MissingSetting>> {
    let mut resolver = Resolver::new(Some(Chain::Solana));

    let config = SolanaConfig {
        rpc_url: resolver.text("SOLANA_RPC_URL"),
        wallet_pool_file: resolver.text("SOLANA_WALLET_POOL_FILE"),
        secure_deposit_address: resolver.text("SOLANA_DEPOSIT_ADDRESS"),
        webhook_url: resolver.text("WEBHOOK_URL"),
        webhook_hmac_secret: resolver.text("WEBHOOK_SECRET"),
        redis_url: resolver.text("REDIS_URL"),
        reservation_ttl_secs: resolver.number("SOLANA_RESERVATION_TTL_SECS"),
        state_file: resolver.text("{P}_STATE_FILE"),
        poll_interval_secs: resolver.number("{P}_POLL_INTERVAL"),
        min_confirmations: resolver.number("{P}_MIN_CONFIRMATIONS"),
        fiat_currency: resolver.text("FIAT_CURRENCY"),
        proxy_url: proxy_env_var(&["SOLANA_PROXY", "SOL_PROXY", "PROXY"]),
        max_retries: resolver.number("MAX_RETRIES"),
        retry_base_delay_ms: resolver.number("RETRY_BASE_DELAY_MS"),
        min_deposit_fiat: resolver.number("SOL_MIN_DEPOSIT_FIAT"),
        gas_tank_private_key: resolver.opt_text("SOLANA_GAS_TANK_PRIVATE_KEY"),
        gas_tank_target_usd: resolver.number("SOLANA_GAS_TANK_TARGET_USD"),
        gas_tank_check_interval_secs: resolver.number("SOLANA_GAS_TANK_INTERVAL_SECS"),
        max_fee_ratio: resolver.number("{P}_MAX_FEE_RATIO"),
        core_api_url: resolver.opt_text("CORE_API_INTERNAL_URL"),
        internal_service_token: resolver.opt_text("INTERNAL_SERVICE_TOKEN"),
    };

    resolver.finish()?;
    Ok(config)
}

pub fn build_evm_config(chain: Chain) -> Result<EthereumConfig, Vec<MissingSetting>> {
    assert!(chain.is_evm(), "build_evm_config requires an EVM chain");
    let mut resolver = Resolver::new(Some(chain));

    let chain_id = resolver.number("{P}_CHAIN_ID");

    // Etherscan V2 serves both chains off one API key; only the chain_id
    // differs. Pin the client to this detector's chain so two detectors sharing
    // the same env template still hit the right per-chain endpoint.
    let etherscan = if etherscan_enabled(chain) {
        EtherscanConfig::from_env().map(|mut config| {
            config.chain_id = chain_id;
            config
        })
    } else {
        log::info!(
            "[{}] Etherscan internal-tx scan disabled via {}_ETHERSCAN_ENABLED=false",
            chain.ticker(),
            chain_env_prefix(chain)
        );
        None
    };

    let config = EthereumConfig {
        chain,
        rpc_url: resolver.text("{P}_RPC_URL"),
        chain_id,
        wallet_pool_file: resolver.text("{P}_WALLET_POOL_FILE"),
        gas_tank_private_key: resolver.text("{P}_GAS_TANK_PRIVATE_KEY"),
        ledger_address: resolver.text("{P}_LEDGER_ADDRESS"),
        webhook_url: resolver.text("WEBHOOK_URL"),
        webhook_hmac_secret: resolver.text("WEBHOOK_SECRET"),
        redis_url: evm_reservation_store_url(chain, &mut resolver),
        reservation_ttl_secs: resolver.number("{P}_RESERVATION_TTL_SECS"),
        state_file: resolver.text("{P}_STATE_FILE"),
        poll_interval_secs: resolver.number("{P}_POLL_INTERVAL"),
        min_confirmations: resolver.number("{P}_MIN_CONFIRMATIONS"),
        fiat_currency: resolver.text("FIAT_CURRENCY"),
        proxy_url: {
            let chain_proxy = expand_key("{P}_PROXY", Some(chain));
            proxy_env_var(&[chain_proxy.as_str(), "PROXY"])
        },
        max_blocks_per_cycle: resolver.number("{P}_MAX_BLOCKS_PER_CYCLE"),
        start_block: resolver.opt_number("{P}_START_BLOCK"),
        gas_tank_target_usd: resolver.number("{P}_GAS_TANK_TARGET_USD"),
        gas_tank_check_interval_secs: resolver.number("{P}_GAS_TANK_INTERVAL_SECS"),
        token_transfer_gas_limit: resolver.number("{P}_TOKEN_TRANSFER_GAS_LIMIT"),
        gas_top_up_multiplier: resolver.number("{P}_GAS_TOP_UP_MULTIPLIER"),
        max_fee_ratio: resolver.number("{P}_MAX_FEE_RATIO"),
        rpc_min_request_interval_ms: resolver.number("{P}_RPC_MIN_REQUEST_INTERVAL_MS"),
        etherscan,
    };

    resolver.finish()?;
    Ok(config)
}

/// Redis URL for EVM reservations, or the in-memory sentinel when the operator
/// opted out. Unlike the pre-refactor helper this never panics — a missing
/// `REDIS_URL` now falls back to the catalog default.
fn evm_reservation_store_url(chain: Chain, resolver: &mut Resolver) -> String {
    if crate::ethereum_pool::ethereum_reservations_use_memory(chain) {
        return crate::ethereum_pool::IN_MEMORY_RESERVATION_URL.to_string();
    }
    resolver.text("REDIS_URL")
}

// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards against a copy-paste duplicate silently shadowing an entry:
    /// `find_setting` returns the first match, so a second entry with the same
    /// key would be unreachable and its default never applied.
    #[test]
    fn catalog_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for setting in SETTINGS {
            assert!(
                seen.insert(setting.key),
                "duplicate catalog key '{}'",
                setting.key
            );
        }
    }

    /// Two settings must not collapse onto the same env var once `{P}` is
    /// expanded (e.g. a `Prefixed` entry colliding with a hand-written one).
    #[test]
    fn expanded_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for entry in settings_schema() {
            assert!(
                seen.insert(entry.key.clone()),
                "duplicate expanded key '{}'",
                entry.key
            );
        }
    }

    #[test]
    fn every_required_setting_has_no_default() {
        for setting in SETTINGS {
            if setting.is_required() {
                for chain in [None, Some(Chain::Ethereum), Some(Chain::Base)] {
                    assert!(
                        setting.default.resolve(chain).is_none(),
                        "required setting '{}' must not have a default",
                        setting.key
                    );
                }
            }
        }
    }

    #[test]
    fn prefix_placeholder_expands_per_chain() {
        assert_eq!(
            expand_key("{P}_LEDGER_ADDRESS", Some(Chain::Base)),
            "BASE_LEDGER_ADDRESS"
        );
        assert_eq!(
            expand_key("{P}_LEDGER_ADDRESS", Some(Chain::Ethereum)),
            "ETH_LEDGER_ADDRESS"
        );
        assert_eq!(expand_key("REDIS_URL", Some(Chain::Base)), "REDIS_URL");
    }

    #[test]
    fn per_chain_defaults_differ() {
        let setting = find_setting("{P}_MIN_CONFIRMATIONS").expect("catalog entry");
        assert_eq!(setting.default.resolve(Some(Chain::Ethereum)), Some("12"));
        assert_eq!(setting.default.resolve(Some(Chain::Base)), Some("5"));

        let pool = find_setting("{P}_WALLET_POOL_FILE").expect("catalog entry");
        assert_eq!(
            pool.default.resolve(Some(Chain::Base)),
            Some("wallet_pool/base_wallets.json")
        );
    }

    /// A missing required setting must be *collected*, never panic — that is
    /// the whole point of the refactor.
    #[test]
    fn missing_required_settings_are_collected_not_fatal() {
        let mut resolver = Resolver::new(Some(Chain::Base));
        let value = resolver.text("{P}_LEDGER_ADDRESS");
        assert!(value.is_empty());

        let missing = resolver.finish().expect_err("should report the gap");
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].key, "BASE_LEDGER_ADDRESS");
    }

    #[test]
    fn defaults_apply_when_unset() {
        let mut resolver = Resolver::new(Some(Chain::Base));
        assert_eq!(resolver.number::<u64>("{P}_MIN_CONFIRMATIONS"), 5);
        assert_eq!(
            resolver.text("{P}_WALLET_POOL_FILE"),
            "wallet_pool/base_wallets.json"
        );
        assert!(resolver.finish().is_ok());
    }

    #[test]
    fn schema_never_carries_a_default_for_secrets() {
        for entry in settings_schema() {
            if entry.secret {
                assert!(
                    entry.default.is_none(),
                    "secret '{}' must not ship a default value",
                    entry.key
                );
            }
        }
    }

    #[test]
    fn schema_expands_evm_settings_for_both_chains() {
        let schema = settings_schema();
        let keys: Vec<&str> = schema.iter().map(|entry| entry.key.as_str()).collect();
        assert!(keys.contains(&"ETH_LEDGER_ADDRESS"));
        assert!(keys.contains(&"BASE_LEDGER_ADDRESS"));
        assert!(keys.contains(&"SOLANA_DEPOSIT_ADDRESS"));
    }
}
