use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signature::Signer;

use crate::error::DetectorError;

const RESERVATION_KEY_PREFIX: &str = "solana:reservation:";

#[derive(Debug, Clone)]
pub struct ManagedSolanaWallet {
    pub index: u32,
    pub address: String,
    pub keypair: Arc<Keypair>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaReservation {
    pub user_id: String,
    pub address: String,
    pub wallet_index: u32,
    pub reserved_at_unix: i64,
    pub expires_at_unix: i64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WalletPoolInput {
    List(Vec<WalletEntry>),
    Wrapped { wallets: Vec<WalletEntry> },
}

#[derive(Debug, Deserialize)]
struct WalletEntry {
    #[serde(default)]
    address: Option<String>,
    #[serde(default, alias = "secret_key", alias = "secretKey", alias = "keypair")]
    private_key: serde_json::Value,
}

pub fn load_wallet_pool(path: &str) -> Result<Vec<ManagedSolanaWallet>, DetectorError> {
    let data = std::fs::read_to_string(path).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to read Solana wallet pool file '{}': {e}",
            path
        ))
    })?;

    let input: WalletPoolInput = serde_json::from_str(&data).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to parse Solana wallet pool file '{}': {e}",
            path
        ))
    })?;

    let entries = match input {
        WalletPoolInput::List(entries) => entries,
        WalletPoolInput::Wrapped { wallets } => wallets,
    };

    if entries.is_empty() {
        return Err(DetectorError::InvalidConfig(
            "Solana wallet pool file is empty".into(),
        ));
    }

    let mut wallets = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let key_bytes = parse_private_key_bytes(&entry.private_key, index as u32)?;
        if key_bytes.len() != 64 {
            return Err(DetectorError::InvalidConfig(format!(
                "Solana wallet #{index} must contain a 64-byte private key, got {} bytes",
                key_bytes.len()
            )));
        }

        let keypair = Keypair::try_from(key_bytes.as_slice()).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Failed to decode Solana keypair for wallet #{index}: {e}"
            ))
        })?;

        let derived_address = keypair.pubkey().to_string();
        if let Some(expected_address) = entry.address {
            let parsed = Pubkey::from_str(&expected_address).map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid address '{}' for wallet #{index}: {e}",
                    expected_address
                ))
            })?;

            if parsed.to_string() != derived_address {
                return Err(DetectorError::InvalidConfig(format!(
                    "Wallet #{index} address mismatch: file has '{}', keypair derives '{}'",
                    expected_address, derived_address
                )));
            }
        }

        wallets.push(ManagedSolanaWallet {
            index: index as u32,
            address: derived_address,
            keypair: Arc::new(keypair),
        });
    }

    Ok(wallets)
}

pub fn find_wallet<'a>(
    wallets: &'a [ManagedSolanaWallet],
    address: &str,
) -> Option<&'a ManagedSolanaWallet> {
    wallets.iter().find(|wallet| wallet.address == address)
}

pub async fn load_active_reservations(
    redis_url: &str,
) -> Result<Vec<SolanaReservation>, DetectorError> {
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

        match serde_json::from_str::<SolanaReservation>(&payload) {
            Ok(reservation) => reservations.push(reservation),
            Err(e) => {
                log::warn!("[SOL] Failed to parse reservation '{}': {}", key, e);
            }
        }
    }

    reservations.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(reservations)
}

pub async fn reserve_wallet_for_user(
    redis_url: &str,
    wallets: &[ManagedSolanaWallet],
    user_id: &str,
    ttl_secs: u64,
) -> Result<SolanaReservation, DetectorError> {
    if user_id.trim().is_empty() {
        return Err(DetectorError::InvalidConfig(
            "user_id cannot be empty when reserving a Solana wallet".into(),
        ));
    }

    let existing = load_active_reservations(redis_url).await?;
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
        let reservation = SolanaReservation {
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
        "No unreserved Solana wallet is currently available".into(),
    ))
}

pub fn reservation_key(address: &str) -> String {
    format!("{RESERVATION_KEY_PREFIX}{address}")
}

fn parse_private_key_bytes(
    value: &serde_json::Value,
    index: u32,
) -> Result<Vec<u8>, DetectorError> {
    match value {
        serde_json::Value::String(s) => parse_private_key_string(s, index),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| {
                let value = item.as_u64().ok_or_else(|| {
                    DetectorError::InvalidConfig(format!(
                        "Wallet #{index} contains a non-numeric byte in the private key array"
                    ))
                })?;
                u8::try_from(value).map_err(|_| {
                    DetectorError::InvalidConfig(format!(
                        "Wallet #{index} contains a private key byte outside the u8 range"
                    ))
                })
            })
            .collect(),
        _ => Err(DetectorError::InvalidConfig(format!(
            "Wallet #{index} private_key must be a base58 string or an array of bytes"
        ))),
    }
}

fn parse_private_key_string(value: &str, index: u32) -> Result<Vec<u8>, DetectorError> {
    let trimmed = value.trim();

    if trimmed.starts_with('[') {
        return serde_json::from_str::<Vec<u8>>(trimmed).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Wallet #{index} contains an invalid JSON private key array: {e}"
            ))
        });
    }

    bs58::decode(trimmed).into_vec().map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Wallet #{index} contains an invalid base58 private key: {e}"
        ))
    })
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
        if next_cursor == 0 {
            break;
        }
        cursor = next_cursor;
    }

    Ok(keys)
}

fn redis_error(error: redis::RedisError) -> DetectorError {
    DetectorError::RedisError(error.to_string())
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
