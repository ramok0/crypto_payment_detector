use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ethers::core::rand::RngCore;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::Address;
use serde::{Deserialize, Serialize};

use crate::error::DetectorError;

const RESERVATION_KEY_PREFIX: &str = "ethereum:reservation:";
const IN_MEMORY_RESERVATION_URL: &str = "memory://ethereum-reservations";
const DEFAULT_ETHEREUM_WALLET_POOL_SIZE: usize = 10;
const MAX_ETHEREUM_WALLET_POOL_SIZE: usize = 10_000;

static IN_MEMORY_RESERVATIONS: OnceLock<Mutex<HashMap<String, EthereumReservation>>> =
    OnceLock::new();

#[derive(Debug, Clone)]
pub struct ManagedEthereumWallet {
    pub index: u32,
    pub address: String,
    pub eth_address: Address,
    pub wallet: Arc<LocalWallet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumReservation {
    pub user_id: String,
    pub address: String,
    pub wallet_index: u32,
    pub reserved_at_unix: i64,
    pub expires_at_unix: i64,
}

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

pub fn load_ethereum_wallet_pool(path: &str) -> Result<Vec<ManagedEthereumWallet>, DetectorError> {
    let data = read_or_create_ethereum_wallet_pool_file(path)?;

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

fn read_or_create_ethereum_wallet_pool_file(path: &str) -> Result<String, DetectorError> {
    match std::fs::read_to_string(path) {
        Ok(data) => Ok(data),
        Err(e) if e.kind() == ErrorKind::NotFound => create_ethereum_wallet_pool_file(path),
        Err(e) => Err(DetectorError::InvalidConfig(format!(
            "Failed to read Ethereum wallet pool file '{}': {e}",
            path
        ))),
    }
}

fn create_ethereum_wallet_pool_file(path: &str) -> Result<String, DetectorError> {
    let wallet_count = ethereum_wallet_pool_size_from_env()?;
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
                "[ETH] Created missing Ethereum wallet pool file '{}' with {} generated wallets. Back up this file securely.",
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

fn ethereum_wallet_pool_size_from_env() -> Result<usize, DetectorError> {
    match std::env::var("ETH_WALLET_POOL_SIZE") {
        Ok(value) if value.trim().is_empty() => Ok(DEFAULT_ETHEREUM_WALLET_POOL_SIZE),
        Ok(value) => value.trim().parse::<usize>().map_err(|_| {
            DetectorError::InvalidConfig(format!(
                "ETH_WALLET_POOL_SIZE must be between 1 and {MAX_ETHEREUM_WALLET_POOL_SIZE}"
            ))
        }),
        Err(_) => Ok(DEFAULT_ETHEREUM_WALLET_POOL_SIZE),
    }
}

pub fn find_ethereum_wallet<'a>(
    wallets: &'a [ManagedEthereumWallet],
    address: Address,
) -> Option<&'a ManagedEthereumWallet> {
    wallets.iter().find(|wallet| wallet.eth_address == address)
}

pub async fn load_active_ethereum_reservations(
    redis_url: &str,
) -> Result<Vec<EthereumReservation>, DetectorError> {
    if should_use_in_memory_reservations(redis_url) {
        return load_active_ethereum_reservations_from_memory();
    }

    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let keys = scan_reservation_keys(&mut connection).await?;
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
                log::warn!("[ETH] Failed to parse reservation '{}': {}", key, e);
            }
        }
    }

    reservations.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(reservations)
}

pub async fn reserve_ethereum_wallet_for_user(
    redis_url: &str,
    wallets: &[ManagedEthereumWallet],
    user_id: &str,
    ttl_secs: u64,
) -> Result<EthereumReservation, DetectorError> {
    if user_id.trim().is_empty() {
        return Err(DetectorError::InvalidConfig(
            "user_id cannot be empty when reserving an Ethereum wallet".into(),
        ));
    }

    if should_use_in_memory_reservations(redis_url) {
        return reserve_ethereum_wallet_for_user_in_memory(wallets, user_id, ttl_secs);
    }

    let existing = load_active_ethereum_reservations(redis_url).await?;
    if let Some(reservation) = existing.into_iter().find(|r| r.user_id == user_id) {
        return Ok(reservation);
    }

    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let now = unix_timestamp();
    let ttl_secs_i64 = i64::try_from(ttl_secs).map_err(|_| {
        DetectorError::InvalidConfig("Reservation TTL is too large to store".into())
    })?;

    for wallet in wallets {
        let reservation = EthereumReservation {
            user_id: user_id.trim().to_string(),
            address: wallet.address.clone(),
            wallet_index: wallet.index,
            reserved_at_unix: now,
            expires_at_unix: now + ttl_secs_i64,
        };

        let payload = serde_json::to_string(&reservation)?;
        let response: Option<String> = redis::cmd("SET")
            .arg(reservation_key(&wallet.address))
            .arg(payload)
            .arg("EX")
            .arg(ttl_secs)
            .arg("NX")
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;

        if response.is_some() {
            return Ok(reservation);
        }
    }

    Err(DetectorError::InvalidConfig(
        "No unreserved Ethereum wallet is currently available".into(),
    ))
}

pub fn reservation_key(address: &str) -> String {
    format!("{RESERVATION_KEY_PREFIX}{address}")
}

pub fn format_address(address: Address) -> String {
    format!("{:#x}", address)
}

pub fn ethereum_reservation_store_url_from_env() -> String {
    if ethereum_reservations_use_memory() {
        IN_MEMORY_RESERVATION_URL.to_string()
    } else {
        std::env::var("REDIS_URL")
            .expect("REDIS_URL env var required unless ETH_RESERVATION_STORE=memory")
    }
}

pub fn ethereum_reservations_use_memory() -> bool {
    env_uses_memory_store("ETH_RESERVATION_STORE")
        || env_uses_memory_store("RESERVATION_STORE")
        || env_bool("ETH_RESERVATIONS_IN_MEMORY")
        || env_bool("RESERVATIONS_IN_MEMORY")
}

fn should_use_in_memory_reservations(redis_url: &str) -> bool {
    ethereum_reservations_use_memory()
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

fn load_active_ethereum_reservations_from_memory() -> Result<Vec<EthereumReservation>, DetectorError>
{
    let now = unix_timestamp();
    let mut store = lock_in_memory_reservations();
    store.retain(|_, reservation| reservation.expires_at_unix > now);

    let mut reservations = store.values().cloned().collect::<Vec<_>>();
    reservations.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(reservations)
}

fn reserve_ethereum_wallet_for_user_in_memory(
    wallets: &[ManagedEthereumWallet],
    user_id: &str,
    ttl_secs: u64,
) -> Result<EthereumReservation, DetectorError> {
    let user_id = user_id.trim();
    let now = unix_timestamp();
    let ttl_secs_i64 = i64::try_from(ttl_secs).map_err(|_| {
        DetectorError::InvalidConfig("Reservation TTL is too large to store".into())
    })?;

    let mut store = lock_in_memory_reservations();
    store.retain(|_, reservation| reservation.expires_at_unix > now);

    if let Some(reservation) = store
        .values()
        .find(|reservation| reservation.user_id == user_id)
        .cloned()
    {
        return Ok(reservation);
    }

    for wallet in wallets {
        let key = reservation_key(&wallet.address);
        if store.contains_key(&key) {
            continue;
        }

        let reservation = EthereumReservation {
            user_id: user_id.to_string(),
            address: wallet.address.clone(),
            wallet_index: wallet.index,
            reserved_at_unix: now,
            expires_at_unix: now + ttl_secs_i64,
        };
        store.insert(key, reservation.clone());
        return Ok(reservation);
    }

    Err(DetectorError::InvalidConfig(
        "No unreserved Ethereum wallet is currently available".into(),
    ))
}

fn lock_in_memory_reservations()
-> std::sync::MutexGuard<'static, HashMap<String, EthereumReservation>> {
    IN_MEMORY_RESERVATIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn scan_reservation_keys(
    connection: &mut redis::aio::MultiplexedConnection,
) -> Result<Vec<String>, DetectorError> {
    let mut cursor: u64 = 0;
    let mut keys = Vec::new();

    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(format!("{RESERVATION_KEY_PREFIX}*"))
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

        let wallets = load_ethereum_wallet_pool(&path_string).expect("wallet pool should load");

        assert_eq!(wallets.len(), DEFAULT_ETHEREUM_WALLET_POOL_SIZE);
        assert!(path.exists());

        let reloaded =
            load_ethereum_wallet_pool(&path_string).expect("created wallet pool should reload");
        assert_eq!(reloaded.len(), DEFAULT_ETHEREUM_WALLET_POOL_SIZE);
        assert_eq!(reloaded[0].address, wallets[0].address);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(test_dir);
    }
}
