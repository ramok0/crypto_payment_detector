use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ethers::core::rand::RngCore;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::Address;
use serde::{Deserialize, Serialize};

use crate::env_utils::chain_env_prefix;
use crate::error::DetectorError;
use crate::types::Chain;

pub const IN_MEMORY_RESERVATION_URL: &str = "memory://evm-reservations";
const DEFAULT_ETHEREUM_WALLET_POOL_SIZE: usize = 10;
const MAX_ETHEREUM_WALLET_POOL_SIZE: usize = 10_000;

/// Sentinel `expires_at_unix` value meaning "no expiration".
pub const NEVER_EXPIRES: i64 = 0;

/// Redis key namespace per EVM chain. Distinct prefixes prevent two detectors
/// (e.g. Ethereum + Base) from colliding on the same address space when both
/// chains run in the same process and share a Redis instance. The new
/// "assignment:" prefix replaces the old "reservation:" prefix that used a
/// Redis TTL to expire stale entries — assignments are now permanent and the
/// user explicitly triggers a /claim to credit their balance.
fn reservation_key_prefix(chain: Chain) -> &'static str {
    match chain {
        Chain::Ethereum => "ethereum:assignment:",
        Chain::Base => "base:assignment:",
        _ => panic!("reservation_key_prefix called with non-EVM chain {chain:?}"),
    }
}

pub type SharedEthereumWallets = Arc<RwLock<Vec<ManagedEthereumWallet>>>;

pub fn shared_ethereum_wallets(wallets: Vec<ManagedEthereumWallet>) -> SharedEthereumWallets {
    Arc::new(RwLock::new(wallets))
}

pub fn snapshot_ethereum_wallets(shared: &SharedEthereumWallets) -> Vec<ManagedEthereumWallet> {
    shared.read().unwrap_or_else(|p| p.into_inner()).clone()
}

static IN_MEMORY_RESERVATIONS: OnceLock<Mutex<HashMap<String, EthereumReservation>>> =
    OnceLock::new();

#[derive(Debug, Clone)]
pub struct ManagedEthereumWallet {
    pub index: u32,
    pub address: String,
    pub eth_address: Address,
    pub wallet: Arc<LocalWallet>,
}

/// Permanent assignment of a managed EVM wallet to a single user.
///
/// Replaces the previous TTL-based reservation: the assignment never
/// expires, and the user explicitly triggers a /claim to scan + sweep +
/// credit funds received at `address`. The `expires_at_unix` field is kept
/// for wire-format compatibility and is set to the sentinel value 0 to
/// indicate "no expiration".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumReservation {
    pub user_id: String,
    pub address: String,
    pub wallet_index: u32,
    pub reserved_at_unix: i64,
    /// Sentinel value `0` indicates the assignment never expires.
    #[serde(default)]
    pub expires_at_unix: i64,
}

/// Public alias matching the new domain language. Internally identical to
/// [`EthereumReservation`] for source-compatibility with the existing
/// detector loop.
pub type EthereumAssignment = EthereumReservation;

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum WalletPoolInput {
    List(Vec<WalletEntry>),
    Wrapped { wallets: Vec<WalletEntry> },
}

#[derive(Debug, Deserialize, Serialize)]
struct WalletEntry {
    #[serde(default)]
    address: Option<String>,
    #[serde(default, alias = "secret_key", alias = "secretKey")]
    private_key: String,
}

pub fn load_ethereum_wallet_pool(
    chain: Chain,
    path: &str,
) -> Result<Vec<ManagedEthereumWallet>, DetectorError> {
    let data = read_or_create_ethereum_wallet_pool_file(chain, path)?;

    let input: WalletPoolInput = serde_json::from_str(&data).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to parse Ethereum wallet pool file '{}': {e}",
            path
        ))
    })?;

    let entries = match input {
        WalletPoolInput::List(entries) => entries,
        WalletPoolInput::Wrapped { wallets } => wallets,
    };

    if entries.is_empty() {
        return Err(DetectorError::InvalidConfig(
            "Ethereum wallet pool file is empty".into(),
        ));
    }

    let mut wallets = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        if entry.private_key.trim().is_empty() {
            return Err(DetectorError::InvalidConfig(format!(
                "Ethereum wallet #{index} private_key is required"
            )));
        }

        let wallet = entry
            .private_key
            .trim()
            .parse::<LocalWallet>()
            .map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Failed to decode Ethereum private key for wallet #{index}: {e}"
                ))
            })?;
        let eth_address = wallet.address();
        let derived_address = format_address(eth_address);

        if let Some(expected_address) = entry.address {
            let parsed = Address::from_str(expected_address.trim()).map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid Ethereum address '{}' for wallet #{index}: {e}",
                    expected_address
                ))
            })?;

            if parsed != eth_address {
                return Err(DetectorError::InvalidConfig(format!(
                    "Wallet #{index} address mismatch: file has '{}', key derives '{}'",
                    expected_address, derived_address
                )));
            }
        }

        wallets.push(ManagedEthereumWallet {
            index: index as u32,
            address: derived_address,
            eth_address,
            wallet: Arc::new(wallet),
        });
    }

    Ok(wallets)
}

fn read_or_create_ethereum_wallet_pool_file(
    chain: Chain,
    path: &str,
) -> Result<String, DetectorError> {
    match std::fs::read_to_string(path) {
        Ok(data) => Ok(data),
        Err(e) if e.kind() == ErrorKind::NotFound => create_ethereum_wallet_pool_file(chain, path),
        Err(e) => Err(DetectorError::InvalidConfig(format!(
            "Failed to read Ethereum wallet pool file '{}': {e}",
            path
        ))),
    }
}

fn create_ethereum_wallet_pool_file(chain: Chain, path: &str) -> Result<String, DetectorError> {
    let wallet_count = ethereum_wallet_pool_size_from_env(chain)?;
    let data = generate_ethereum_wallet_pool_json(wallet_count)?;
    let path_ref = Path::new(path);

    if let Some(parent) = path_ref
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Failed to create Ethereum wallet pool directory '{}': {e}",
                parent.display()
            ))
        })?;
    }

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path_ref)
    {
        Ok(mut file) => {
            file.write_all(data.as_bytes()).map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Failed to write Ethereum wallet pool file '{}': {e}",
                    path
                ))
            })?;
            file.write_all(b"\n").map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Failed to write Ethereum wallet pool file '{}': {e}",
                    path
                ))
            })?;
            log::warn!(
                "[{}] Created missing wallet pool file '{}' with {} generated wallets. Back up this file securely.",
                chain.ticker(),
                path,
                wallet_count
            );
            Ok(data)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            std::fs::read_to_string(path).map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Failed to read Ethereum wallet pool file '{}': {e}",
                    path
                ))
            })
        }
        Err(e) => Err(DetectorError::InvalidConfig(format!(
            "Failed to create Ethereum wallet pool file '{}': {e}",
            path
        ))),
    }
}

fn generate_ethereum_wallet_pool_json(wallet_count: usize) -> Result<String, DetectorError> {
    let wallets = generate_ethereum_wallet_entries(wallet_count)?;
    serde_json::to_string_pretty(&WalletPoolInput::Wrapped { wallets }).map_err(Into::into)
}

fn generate_ethereum_wallet_entries(
    wallet_count: usize,
) -> Result<Vec<WalletEntry>, DetectorError> {
    if wallet_count == 0 || wallet_count > MAX_ETHEREUM_WALLET_POOL_SIZE {
        return Err(DetectorError::InvalidConfig(format!(
            "ETH_WALLET_POOL_SIZE must be between 1 and {MAX_ETHEREUM_WALLET_POOL_SIZE}"
        )));
    }

    let mut rng = ethers::core::rand::thread_rng();
    let mut wallets = Vec::with_capacity(wallet_count);

    while wallets.len() < wallet_count {
        let mut private_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut private_key_bytes);

        let Ok(wallet) = LocalWallet::from_bytes(&private_key_bytes) else {
            continue;
        };

        wallets.push(WalletEntry {
            address: Some(format_address(wallet.address())),
            private_key: format!("0x{}", hex::encode(private_key_bytes)),
        });
    }

    Ok(wallets)
}

fn ethereum_wallet_pool_size_from_env(chain: Chain) -> Result<usize, DetectorError> {
    let env_name = format!("{}_WALLET_POOL_SIZE", chain_env_prefix(chain));
    match std::env::var(&env_name) {
        Ok(value) if value.trim().is_empty() => Ok(DEFAULT_ETHEREUM_WALLET_POOL_SIZE),
        Ok(value) => value.trim().parse::<usize>().map_err(|_| {
            DetectorError::InvalidConfig(format!(
                "{env_name} must be between 1 and {MAX_ETHEREUM_WALLET_POOL_SIZE}"
            ))
        }),
        Err(_) => Ok(DEFAULT_ETHEREUM_WALLET_POOL_SIZE),
    }
}

pub fn find_ethereum_wallet(
    wallets: &[ManagedEthereumWallet],
    address: Address,
) -> Option<ManagedEthereumWallet> {
    wallets
        .iter()
        .find(|wallet| wallet.eth_address == address)
        .cloned()
}

pub fn generate_random_ethereum_wallet(index: u32) -> Result<ManagedEthereumWallet, DetectorError> {
    let mut rng = ethers::core::rand::thread_rng();
    for _ in 0..32 {
        let mut private_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut private_key_bytes);
        if let Ok(wallet) = LocalWallet::from_bytes(&private_key_bytes) {
            let eth_address = wallet.address();
            return Ok(ManagedEthereumWallet {
                index,
                address: format_address(eth_address),
                eth_address,
                wallet: Arc::new(wallet),
            });
        }
    }
    Err(DetectorError::ApiError(
        "Failed to generate a valid Ethereum keypair after several attempts".into(),
    ))
}

pub fn append_ethereum_wallet_to_pool_file(
    path: &str,
    wallet: &ManagedEthereumWallet,
) -> Result<(), DetectorError> {
    let data = std::fs::read_to_string(path).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to read Ethereum wallet pool file '{}' for append: {e}",
            path
        ))
    })?;
    let mut value: serde_json::Value = serde_json::from_str(&data).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to parse Ethereum wallet pool file '{}' for append: {e}",
            path
        ))
    })?;

    let private_key_hex = format!("0x{}", hex::encode(wallet.wallet.signer().to_bytes()));
    let new_entry = serde_json::json!({
        "address": wallet.address.clone(),
        "private_key": private_key_hex,
    });

    let entries = if let Some(arr) = value.as_array_mut() {
        arr
    } else if let Some(obj) = value.as_object_mut() {
        let entry = obj
            .entry("wallets".to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        entry.as_array_mut().ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "Ethereum wallet pool 'wallets' field in '{}' is not an array",
                path
            ))
        })?
    } else {
        return Err(DetectorError::InvalidConfig(format!(
            "Ethereum wallet pool file '{}' is neither a JSON array nor object",
            path
        )));
    };
    entries.push(new_entry);

    // Durable write: this file is the only copy of the new wallet's private
    // key, and the caller reserves the address for a user right after. Losing
    // it to an unsynced rename would strand whatever gets deposited there.
    crate::persistence::write_json_atomic(path, &value)
}

fn ethereum_max_pool_size(chain: Chain) -> usize {
    let prefix = chain_env_prefix(chain);
    std::env::var(format!("{prefix}_MAX_POOL_SIZE"))
        .or_else(|_| std::env::var(format!("{prefix}_WALLET_POOL_MAX_SIZE")))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .map(|n| n.min(MAX_ETHEREUM_WALLET_POOL_SIZE))
        .unwrap_or(MAX_ETHEREUM_WALLET_POOL_SIZE)
}

pub async fn load_active_ethereum_reservations(
    chain: Chain,
    redis_url: &str,
) -> Result<Vec<EthereumReservation>, DetectorError> {
    if should_use_in_memory_reservations(chain, redis_url) {
        return load_active_ethereum_reservations_from_memory(chain);
    }

    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let keys = scan_reservation_keys(chain, &mut connection).await?;
    let mut reservations = Vec::with_capacity(keys.len());

    for key in keys {
        let payload: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;

        let Some(payload) = payload else {
            continue;
        };

        match serde_json::from_str::<EthereumReservation>(&payload) {
            Ok(reservation) => reservations.push(reservation),
            Err(e) => {
                log::warn!(
                    "[{}] Failed to parse assignment '{}': {}",
                    chain.ticker(),
                    key,
                    e
                );
            }
        }
    }

    reservations.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(reservations)
}

/// Domain-aliased wrapper around [`load_active_ethereum_reservations`]
/// using the new "assignment" terminology.
pub async fn load_active_ethereum_assignments(
    chain: Chain,
    redis_url: &str,
) -> Result<Vec<EthereumAssignment>, DetectorError> {
    load_active_ethereum_reservations(chain, redis_url).await
}

/// Look up the permanent EVM assignment for a single `user_id` on `chain`,
/// if any.
pub async fn load_ethereum_assignment_for_user(
    chain: Chain,
    redis_url: &str,
    user_id: &str,
) -> Result<Option<EthereumAssignment>, DetectorError> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Ok(None);
    }
    let assignments = load_active_ethereum_assignments(chain, redis_url).await?;
    Ok(assignments.into_iter().find(|a| a.user_id == user_id))
}

/// Get-or-create the permanent EVM deposit address for `user_id` on
/// `chain`. Replaces the previous TTL-based reservation flow: returns the
/// same address every call, with no expiration.
pub async fn assign_ethereum_wallet_for_user(
    chain: Chain,
    redis_url: &str,
    wallets: &SharedEthereumWallets,
    pool_path: &str,
    user_id: &str,
) -> Result<EthereumAssignment, DetectorError> {
    if user_id.trim().is_empty() {
        return Err(DetectorError::InvalidConfig(format!(
            "user_id cannot be empty when assigning a {} wallet",
            chain.name()
        )));
    }

    if should_use_in_memory_reservations(chain, redis_url) {
        return assign_ethereum_wallet_for_user_in_memory(chain, wallets, pool_path, user_id);
    }

    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let now = unix_timestamp();

    let existing = load_active_ethereum_assignments(chain, redis_url).await?;
    if let Some(existing_assignment) = existing.into_iter().find(|a| a.user_id == user_id.trim()) {
        return Ok(existing_assignment);
    }

    let candidates: Vec<(String, u32)> = {
        let pool = wallets.read().unwrap_or_else(|p| p.into_inner());
        pool.iter()
            .map(|wallet| (wallet.address.clone(), wallet.index))
            .collect()
    };

    for (address, index) in candidates {
        let assignment = EthereumAssignment {
            user_id: user_id.trim().to_string(),
            address: address.clone(),
            wallet_index: index,
            reserved_at_unix: now,
            expires_at_unix: NEVER_EXPIRES,
        };

        let payload = serde_json::to_string(&assignment)?;
        let response: Option<String> = redis::cmd("SET")
            .arg(reservation_key(chain, &address))
            .arg(payload)
            .arg("NX")
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;

        if response.is_some() {
            log::info!(
                "[{}] Assigned wallet {} (index {}) to user_id={} (no TTL)",
                chain.ticker(),
                address,
                index,
                user_id
            );
            return Ok(assignment);
        }
    }

    // Pool exhausted — generate, persist, then assign.
    let new_wallet = grow_ethereum_pool(chain, wallets, pool_path)?;
    let assignment = EthereumAssignment {
        user_id: user_id.trim().to_string(),
        address: new_wallet.address.clone(),
        wallet_index: new_wallet.index,
        reserved_at_unix: now,
        expires_at_unix: NEVER_EXPIRES,
    };
    let payload = serde_json::to_string(&assignment)?;
    let response: Option<String> = redis::cmd("SET")
        .arg(reservation_key(chain, &new_wallet.address))
        .arg(payload)
        .arg("NX")
        .query_async(&mut connection)
        .await
        .map_err(redis_error)?;

    if response.is_some() {
        Ok(assignment)
    } else {
        Err(DetectorError::ApiError(format!(
            "Failed to register assignment for newly generated {} wallet",
            chain.name()
        )))
    }
}

/// Delete every `<chain>:assignment:*` entry (Redis or in-memory). Returns
/// the number of records removed. Used by the admin "cancel all
/// reservations" endpoint to release every managed wallet on `chain` so the
/// detector stops scanning them.
pub async fn delete_all_ethereum_assignments(
    chain: Chain,
    redis_url: &str,
) -> Result<usize, DetectorError> {
    if should_use_in_memory_reservations(chain, redis_url) {
        let prefix = reservation_key_prefix(chain);
        let mut store = lock_in_memory_reservations();
        let to_remove: Vec<String> = store
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        for key in &to_remove {
            store.remove(key);
        }
        let removed = to_remove.len();
        log::info!(
            "[{}] Cancelled {} in-memory assignment(s)",
            chain.ticker(),
            removed
        );
        return Ok(removed);
    }

    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let keys = scan_reservation_keys(chain, &mut connection).await?;
    if keys.is_empty() {
        return Ok(0);
    }

    let deleted: usize = redis::cmd("DEL")
        .arg(&keys)
        .query_async(&mut connection)
        .await
        .map_err(redis_error)?;

    log::info!(
        "[{}] Cancelled {} assignment(s) (scanned {} key(s))",
        chain.ticker(),
        deleted,
        keys.len()
    );
    Ok(deleted)
}

/// Backwards-compatible alias used by older callers. The `_ttl_secs`
/// argument is ignored — the new system never expires assignments.
pub async fn reserve_ethereum_wallet_for_user(
    chain: Chain,
    redis_url: &str,
    wallets: &SharedEthereumWallets,
    pool_path: &str,
    user_id: &str,
    _ttl_secs: u64,
) -> Result<EthereumReservation, DetectorError> {
    assign_ethereum_wallet_for_user(chain, redis_url, wallets, pool_path, user_id).await
}

fn grow_ethereum_pool(
    chain: Chain,
    wallets: &SharedEthereumWallets,
    pool_path: &str,
) -> Result<ManagedEthereumWallet, DetectorError> {
    let max_pool_size = ethereum_max_pool_size(chain);
    let mut pool = wallets.write().unwrap_or_else(|p| p.into_inner());
    if pool.len() >= max_pool_size {
        return Err(DetectorError::InvalidConfig(format!(
            "{} wallet pool reached {}_MAX_POOL_SIZE={} - refusing to grow further",
            chain.name(),
            chain_env_prefix(chain),
            max_pool_size
        )));
    }
    let next_index = pool.len() as u32;
    let new_wallet = generate_random_ethereum_wallet(next_index)?;
    append_ethereum_wallet_to_pool_file(pool_path, &new_wallet)?;
    pool.push(new_wallet.clone());
    log::info!(
        "[{}] Auto-generated new managed wallet at index {} address {} (pool path: {}); pool grew to handle exhausted reservations",
        chain.ticker(),
        new_wallet.index,
        new_wallet.address,
        pool_path
    );
    Ok(new_wallet)
}

pub fn reservation_key(chain: Chain, address: &str) -> String {
    format!("{}{}", reservation_key_prefix(chain), address)
}

pub fn format_address(address: Address) -> String {
    format!("{:#x}", address)
}

pub fn ethereum_reservation_store_url_from_env(chain: Chain) -> String {
    if ethereum_reservations_use_memory(chain) {
        IN_MEMORY_RESERVATION_URL.to_string()
    } else {
        let prefix = chain_env_prefix(chain);
        std::env::var("REDIS_URL").unwrap_or_else(|_| {
            panic!("REDIS_URL env var required unless {prefix}_RESERVATION_STORE=memory")
        })
    }
}

pub fn ethereum_reservations_use_memory(chain: Chain) -> bool {
    let prefix = chain_env_prefix(chain);
    env_uses_memory_store(&format!("{prefix}_RESERVATION_STORE"))
        || env_uses_memory_store("RESERVATION_STORE")
        || env_bool(&format!("{prefix}_RESERVATIONS_IN_MEMORY"))
        || env_bool("RESERVATIONS_IN_MEMORY")
}

fn should_use_in_memory_reservations(chain: Chain, redis_url: &str) -> bool {
    ethereum_reservations_use_memory(chain)
        || redis_url.trim().eq_ignore_ascii_case("memory")
        || redis_url
            .trim()
            .eq_ignore_ascii_case(IN_MEMORY_RESERVATION_URL)
}

fn env_uses_memory_store(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "memory" | "mem" | "in-memory" | "in_memory"
            )
        })
        .unwrap_or(false)
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn load_active_ethereum_reservations_from_memory(
    chain: Chain,
) -> Result<Vec<EthereumReservation>, DetectorError> {
    let prefix = reservation_key_prefix(chain);
    let store = lock_in_memory_reservations();

    let mut reservations = store
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(_, reservation)| reservation.clone())
        .collect::<Vec<_>>();
    reservations.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(reservations)
}

fn assign_ethereum_wallet_for_user_in_memory(
    chain: Chain,
    wallets: &SharedEthereumWallets,
    pool_path: &str,
    user_id: &str,
) -> Result<EthereumAssignment, DetectorError> {
    let user_id = user_id.trim();
    let now = unix_timestamp();
    let prefix = reservation_key_prefix(chain);

    {
        let mut store = lock_in_memory_reservations();

        // Match `user_id` only within this chain's namespace so a Base
        // assignment doesn't collide with an Ethereum one for the same user.
        if let Some(existing) = store
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .find(|(_, reservation)| reservation.user_id == user_id)
            .map(|(_, v)| v.clone())
        {
            return Ok(existing);
        }

        let candidate_addresses: Vec<(String, u32)> = {
            let pool = wallets.read().unwrap_or_else(|p| p.into_inner());
            pool.iter().map(|w| (w.address.clone(), w.index)).collect()
        };

        for (address, index) in candidate_addresses {
            let key = reservation_key(chain, &address);
            if store.contains_key(&key) {
                continue;
            }
            let assignment = EthereumAssignment {
                user_id: user_id.to_string(),
                address,
                wallet_index: index,
                reserved_at_unix: now,
                expires_at_unix: NEVER_EXPIRES,
            };
            store.insert(key, assignment.clone());
            return Ok(assignment);
        }
    }

    // Pool exhausted — grow it. (We re-acquire the in-memory lock after the grow.)
    let new_wallet = grow_ethereum_pool(chain, wallets, pool_path)?;
    let mut store = lock_in_memory_reservations();
    let assignment = EthereumAssignment {
        user_id: user_id.to_string(),
        address: new_wallet.address.clone(),
        wallet_index: new_wallet.index,
        reserved_at_unix: now,
        expires_at_unix: NEVER_EXPIRES,
    };
    store.insert(
        reservation_key(chain, &new_wallet.address),
        assignment.clone(),
    );
    Ok(assignment)
}

fn lock_in_memory_reservations()
-> std::sync::MutexGuard<'static, HashMap<String, EthereumReservation>> {
    IN_MEMORY_RESERVATIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn scan_reservation_keys(
    chain: Chain,
    connection: &mut redis::aio::MultiplexedConnection,
) -> Result<Vec<String>, DetectorError> {
    let mut cursor: u64 = 0;
    let mut keys = Vec::new();
    let prefix = reservation_key_prefix(chain);

    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(format!("{prefix}*"))
            .arg("COUNT")
            .arg(256)
            .query_async(connection)
            .await
            .map_err(redis_error)?;

        keys.extend(batch);
        cursor = next_cursor;

        if cursor == 0 {
            break;
        }
    }

    Ok(keys)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn redis_error(error: redis::RedisError) -> DetectorError {
    DetectorError::RedisError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_missing_ethereum_wallet_pool_file() {
        let test_dir = Path::new("target")
            .join("ethereum_pool_tests")
            .join(format!(
                "pool_{}_{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
        let path = test_dir.join("ethereum_wallets.json");
        let path_string = path.to_string_lossy().to_string();

        let wallets = load_ethereum_wallet_pool(Chain::Ethereum, &path_string)
            .expect("wallet pool should load");

        assert_eq!(wallets.len(), DEFAULT_ETHEREUM_WALLET_POOL_SIZE);
        assert!(path.exists());

        let reloaded = load_ethereum_wallet_pool(Chain::Ethereum, &path_string)
            .expect("created wallet pool should reload");
        assert_eq!(reloaded.len(), DEFAULT_ETHEREUM_WALLET_POOL_SIZE);
        assert_eq!(reloaded[0].address, wallets[0].address);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(test_dir);
    }
}
