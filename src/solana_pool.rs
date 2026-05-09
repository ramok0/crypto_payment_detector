use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signature::Signer;

use crate::error::DetectorError;

// Permanent address assignments (no TTL). Each user gets a single managed
// wallet for the lifetime of the deposit address — the user explicitly
// triggers a /claim to credit their balance.
const ASSIGNMENT_KEY_PREFIX: &str = "solana:assignment:";
/// Per-user index mapping `user_id -> address`. Authoritative source of
/// truth for "which wallet does this user own?" — every read goes
/// through this key, so concurrent calls for the same user always see
/// the same address.
const USER_INDEX_KEY_PREFIX: &str = "solana:user_assignment:";
/// Per-user advisory lock used to serialise concurrent
/// `assign_wallet_for_user` calls for the same `user_id`. Prevents the
/// race that historically created multiple assignments per user. TTL'd
/// in case a holder crashes mid-assignment.
const USER_LOCK_KEY_PREFIX: &str = "solana:user_assignment_lock:";
const USER_LOCK_TTL_SECS: u64 = 30;
const DEFAULT_SOLANA_MAX_POOL_SIZE: usize = 10_000;

pub type SharedSolanaWallets = Arc<RwLock<Vec<ManagedSolanaWallet>>>;

#[derive(Debug, Clone)]
pub struct ManagedSolanaWallet {
    pub index: u32,
    pub address: String,
    pub keypair: Arc<Keypair>,
}

/// Permanent assignment of a managed Solana wallet to a single user.
///
/// Replaces the previous TTL-based reservation: the assignment never
/// expires (stored without Redis EX), and the user explicitly triggers a
/// /claim to scan + sweep + credit funds received at `address`. The
/// `expires_at_unix` field is kept for wire-format compatibility with
/// downstream consumers and is set to the sentinel value 0 to indicate
/// "no expiration".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaReservation {
    pub user_id: String,
    pub address: String,
    pub wallet_index: u32,
    pub reserved_at_unix: i64,
    /// Sentinel value `0` indicates the assignment never expires. Older
    /// payloads written by the previous TTL-based reservation system may
    /// still carry a real Unix timestamp here; both are tolerated.
    #[serde(default)]
    pub expires_at_unix: i64,
}

/// Public alias matching the new domain language. Internally identical to
/// [`SolanaReservation`] for source-compatibility with the existing
/// detector loop.
pub type SolanaAssignment = SolanaReservation;

/// Sentinel `expires_at_unix` value meaning "no expiration".
pub const NEVER_EXPIRES: i64 = 0;

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

pub fn find_wallet(wallets: &[ManagedSolanaWallet], address: &str) -> Option<ManagedSolanaWallet> {
    wallets.iter().find(|wallet| wallet.address == address).cloned()
}

pub fn snapshot_wallets(shared: &SharedSolanaWallets) -> Vec<ManagedSolanaWallet> {
    shared.read().unwrap_or_else(|p| p.into_inner()).clone()
}

pub fn shared_wallets(wallets: Vec<ManagedSolanaWallet>) -> SharedSolanaWallets {
    Arc::new(RwLock::new(wallets))
}

pub fn generate_random_solana_wallet(index: u32) -> ManagedSolanaWallet {
    let keypair = Keypair::new();
    let address = keypair.pubkey().to_string();
    ManagedSolanaWallet {
        index,
        address,
        keypair: Arc::new(keypair),
    }
}

pub fn append_solana_wallet_to_pool_file(
    path: &str,
    wallet: &ManagedSolanaWallet,
) -> Result<(), DetectorError> {
    let data = std::fs::read_to_string(path).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to read Solana wallet pool file '{}' for append: {e}",
            path
        ))
    })?;
    let mut value: serde_json::Value = serde_json::from_str(&data).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to parse Solana wallet pool file '{}' for append: {e}",
            path
        ))
    })?;

    let secret_b58 = bs58::encode(wallet.keypair.to_bytes()).into_string();
    let new_entry = serde_json::json!({
        "address": wallet.address.clone(),
        "private_key": secret_b58,
    });

    let entries = if let Some(arr) = value.as_array_mut() {
        arr
    } else if let Some(obj) = value.as_object_mut() {
        let entry = obj
            .entry("wallets".to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        entry.as_array_mut().ok_or_else(|| {
            DetectorError::InvalidConfig(format!(
                "Solana wallet pool 'wallets' field in '{}' is not an array",
                path
            ))
        })?
    } else {
        return Err(DetectorError::InvalidConfig(format!(
            "Solana wallet pool file '{}' is neither a JSON array nor object",
            path
        )));
    };
    entries.push(new_entry);

    let serialized = serde_json::to_string_pretty(&value)?;
    let tmp_path = format!("{}.tmp", path);
    std::fs::write(&tmp_path, serialized).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to write Solana wallet pool tmp file '{}': {e}",
            tmp_path
        ))
    })?;
    std::fs::rename(&tmp_path, path).map_err(|e| {
        DetectorError::InvalidConfig(format!(
            "Failed to rename Solana wallet pool tmp file '{}' -> '{}': {e}",
            tmp_path, path
        ))
    })?;
    Ok(())
}

fn solana_max_pool_size() -> usize {
    std::env::var("SOLANA_MAX_POOL_SIZE")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_SOLANA_MAX_POOL_SIZE)
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
                log::warn!("[SOL] Failed to parse assignment '{}': {}", key, e);
            }
        }
    }

    reservations.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(reservations)
}

/// Domain-aliased wrapper around [`load_active_reservations`] using the
/// new "assignment" terminology. Returns the same payload — all currently
/// assigned addresses with their owning user.
pub async fn load_active_assignments(
    redis_url: &str,
) -> Result<Vec<SolanaAssignment>, DetectorError> {
    load_active_reservations(redis_url).await
}

/// Look up the permanent assignment for a single `user_id` if any.
/// Prefers the per-user index (`solana:user_assignment:<user_id>`) for
/// O(1) lookup; falls back to a full scan only when the index is missing
/// (legacy data from before the index existed). When the scan finds
/// multiple assignments for the user — historical race-condition damage
/// — the earliest one (smallest `reserved_at_unix`) is returned, matching
/// the consolidation logic at startup.
pub async fn load_assignment_for_user(
    redis_url: &str,
    user_id: &str,
) -> Result<Option<SolanaAssignment>, DetectorError> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Ok(None);
    }
    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    // Fast path: per-user index
    if let Some(address) = redis_get_string(&mut connection, &user_index_key(user_id)).await? {
        if let Some(assignment) = read_assignment_payload(&mut connection, &address).await? {
            return Ok(Some(assignment));
        }
        // Stale pointer: the assignment payload was deleted. Drop the
        // index and fall through to the scan path below.
        log::warn!(
            "[SOL] Stale user_index for user_id={user_id} pointed at {address}; scanning to recover"
        );
        let _: i64 = redis::cmd("DEL")
            .arg(user_index_key(user_id))
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
    }

    // Slow path: scan + return the earliest assignment for this user
    let mut matches: Vec<SolanaAssignment> = load_active_assignments(redis_url)
        .await?
        .into_iter()
        .filter(|a| a.user_id == user_id)
        .collect();
    matches.sort_by_key(|a| a.reserved_at_unix);
    Ok(matches.into_iter().next())
}

/// Get-or-create the permanent Solana deposit address for `user_id`.
///
/// Concurrency-safe: uses a per-user advisory lock
/// (`solana:user_assignment_lock:<user_id>`, TTL 30 s) so two parallel
/// callers for the same user can't both assign different wallets. Once
/// the wallet is claimed, the per-user index
/// (`solana:user_assignment:<user_id>`) is written so every subsequent
/// `load_assignment_for_user` call returns the same address in O(1).
pub async fn assign_wallet_for_user(
    redis_url: &str,
    wallets: &SharedSolanaWallets,
    pool_path: &str,
    user_id: &str,
) -> Result<SolanaAssignment, DetectorError> {
    let user_id = user_id.trim().to_string();
    if user_id.is_empty() {
        return Err(DetectorError::InvalidConfig(
            "user_id cannot be empty when assigning a Solana wallet".into(),
        ));
    }

    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let now = unix_timestamp();
    let user_idx = user_index_key(&user_id);
    let lock_key = user_lock_key(&user_id);

    // Fast path: index already populated.
    if let Some(addr) = redis_get_string(&mut connection, &user_idx).await? {
        if let Some(assignment) = read_assignment_payload(&mut connection, &addr).await? {
            return Ok(assignment);
        }
        log::warn!(
            "[SOL] user_idx for user_id={user_id} pointed at {addr} but payload is missing; reassigning"
        );
        let _: i64 = redis::cmd("DEL")
            .arg(&user_idx)
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
    }

    // Acquire per-user lock (SET NX EX). Retry briefly so concurrent
    // callers all converge on the winning assignment instead of erroring.
    let mut acquired = false;
    for _ in 0..30 {
        let response: Option<String> = redis::cmd("SET")
            .arg(&lock_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(USER_LOCK_TTL_SECS)
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        if response.is_some() {
            acquired = true;
            break;
        }
        // Lock held by a peer. Maybe they finished — re-read the index.
        if let Some(addr) = redis_get_string(&mut connection, &user_idx).await? {
            if let Some(assignment) = read_assignment_payload(&mut connection, &addr).await? {
                return Ok(assignment);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if !acquired {
        return Err(DetectorError::ApiError(format!(
            "Failed to acquire assignment lock for user_id={user_id} after 3s; another caller may be stuck"
        )));
    }

    // We hold the lock. Re-check the index in case the previous holder
    // finished between our failed SET NX and the retry.
    if let Some(addr) = redis_get_string(&mut connection, &user_idx).await? {
        if let Some(assignment) = read_assignment_payload(&mut connection, &addr).await? {
            release_user_lock(&mut connection, &lock_key).await;
            return Ok(assignment);
        }
    }

    // Find an unassigned wallet from the pool.
    let result = claim_first_unassigned_wallet(
        &mut connection,
        wallets,
        pool_path,
        &user_id,
        now,
    )
    .await;

    match result {
        Ok(assignment) => {
            // Publish the index so future calls (and concurrent waiters
            // who lost the lock) find this assignment in O(1).
            let _: () = redis::cmd("SET")
                .arg(&user_idx)
                .arg(&assignment.address)
                .query_async(&mut connection)
                .await
                .map_err(redis_error)?;
            log::info!(
                "[SOL] Assigned wallet {} (index {}) to user_id={} (no TTL, indexed)",
                assignment.address,
                assignment.wallet_index,
                user_id
            );
            release_user_lock(&mut connection, &lock_key).await;
            Ok(assignment)
        }
        Err(error) => {
            release_user_lock(&mut connection, &lock_key).await;
            Err(error)
        }
    }
}

async fn claim_first_unassigned_wallet(
    connection: &mut redis::aio::MultiplexedConnection,
    wallets: &SharedSolanaWallets,
    pool_path: &str,
    user_id: &str,
    now: i64,
) -> Result<SolanaAssignment, DetectorError> {
    let candidates: Vec<(String, u32)> = {
        let pool = wallets.read().unwrap_or_else(|p| p.into_inner());
        pool.iter()
            .map(|wallet| (wallet.address.clone(), wallet.index))
            .collect()
    };

    for (address, index) in candidates {
        let assignment = SolanaAssignment {
            user_id: user_id.to_string(),
            address: address.clone(),
            wallet_index: index,
            reserved_at_unix: now,
            expires_at_unix: NEVER_EXPIRES,
        };

        let payload = serde_json::to_string(&assignment)?;
        let response: Option<String> = redis::cmd("SET")
            .arg(reservation_key(&address))
            .arg(payload)
            .arg("NX")
            .query_async(connection)
            .await
            .map_err(redis_error)?;

        if response.is_some() {
            return Ok(assignment);
        }
    }

    // Pool exhausted — auto-grow.
    let max_pool_size = solana_max_pool_size();
    let new_wallet = {
        let mut pool = wallets.write().unwrap_or_else(|p| p.into_inner());
        if pool.len() >= max_pool_size {
            return Err(DetectorError::InvalidConfig(format!(
                "Solana wallet pool reached SOLANA_MAX_POOL_SIZE={} - refusing to grow further",
                max_pool_size
            )));
        }
        let next_index = pool.len() as u32;
        let new_wallet = generate_random_solana_wallet(next_index);
        append_solana_wallet_to_pool_file(pool_path, &new_wallet)?;
        pool.push(new_wallet.clone());
        new_wallet
    };

    log::info!(
        "[SOL] Auto-generated new managed wallet at index {} address {} (pool path: {}); pool grew to handle exhausted assignments",
        new_wallet.index,
        new_wallet.address,
        pool_path
    );

    let assignment = SolanaAssignment {
        user_id: user_id.to_string(),
        address: new_wallet.address.clone(),
        wallet_index: new_wallet.index,
        reserved_at_unix: now,
        expires_at_unix: NEVER_EXPIRES,
    };
    let payload = serde_json::to_string(&assignment)?;
    let response: Option<String> = redis::cmd("SET")
        .arg(reservation_key(&new_wallet.address))
        .arg(payload)
        .arg("NX")
        .query_async(connection)
        .await
        .map_err(redis_error)?;

    if response.is_some() {
        Ok(assignment)
    } else {
        Err(DetectorError::ApiError(
            "Failed to register assignment for newly generated Solana wallet".into(),
        ))
    }
}

async fn redis_get_string(
    connection: &mut redis::aio::MultiplexedConnection,
    key: &str,
) -> Result<Option<String>, DetectorError> {
    redis::cmd("GET")
        .arg(key)
        .query_async(connection)
        .await
        .map_err(redis_error)
}

async fn read_assignment_payload(
    connection: &mut redis::aio::MultiplexedConnection,
    address: &str,
) -> Result<Option<SolanaAssignment>, DetectorError> {
    let Some(raw) = redis_get_string(connection, &reservation_key(address)).await? else {
        return Ok(None);
    };
    match serde_json::from_str::<SolanaAssignment>(&raw) {
        Ok(a) => Ok(Some(a)),
        Err(error) => {
            log::warn!(
                "[SOL] Failed to parse assignment payload for {address}: {error}"
            );
            Ok(None)
        }
    }
}

async fn release_user_lock(
    connection: &mut redis::aio::MultiplexedConnection,
    lock_key: &str,
) {
    let result: Result<i64, redis::RedisError> = redis::cmd("DEL")
        .arg(lock_key)
        .query_async(connection)
        .await;
    if let Err(error) = result {
        log::warn!(
            "[SOL] Failed to release per-user assignment lock {lock_key}: {error} (will TTL out in <{}s)",
            USER_LOCK_TTL_SECS
        );
    }
}

/// Delete every `solana:assignment:*` key from Redis. Returns the number of
/// keys removed. Used by the admin "cancel all reservations" endpoint to
/// release every managed wallet so the detector stops scanning them.
pub async fn delete_all_assignments(redis_url: &str) -> Result<usize, DetectorError> {
    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let assignment_keys = scan_reservation_keys(&mut connection).await?;
    let user_idx_keys = scan_keys_by_prefix(&mut connection, USER_INDEX_KEY_PREFIX).await?;
    let lock_keys = scan_keys_by_prefix(&mut connection, USER_LOCK_KEY_PREFIX).await?;

    let mut all_keys = Vec::with_capacity(
        assignment_keys.len() + user_idx_keys.len() + lock_keys.len(),
    );
    all_keys.extend(assignment_keys.iter().cloned());
    all_keys.extend(user_idx_keys.iter().cloned());
    all_keys.extend(lock_keys.iter().cloned());
    if all_keys.is_empty() {
        return Ok(0);
    }

    let deleted: usize = redis::cmd("DEL")
        .arg(&all_keys)
        .query_async(&mut connection)
        .await
        .map_err(redis_error)?;

    log::info!(
        "[SOL] Cancelled {} assignment(s) ({} primary, {} user_idx, {} locks deleted)",
        assignment_keys.len(),
        assignment_keys.len(),
        user_idx_keys.len(),
        lock_keys.len()
    );
    let _ = deleted; // total reflects all key types; expose primary count
    Ok(assignment_keys.len())
}

/// Reconcile per-user indices with the actual `solana:assignment:*`
/// payloads. Two failure modes this targets:
///
/// 1. **Race-created duplicates** — historically, concurrent
///    `assign_wallet_for_user` calls for the same `user_id` could leave
///    the user with multiple `solana:assignment:*` entries. This
///    function picks the canonical one (smallest `reserved_at_unix`,
///    address sort as tiebreaker), writes the per-user index to point
///    at it, and **deletes the duplicate assignment payloads** so the
///    detector stops scanning them. Funds that may sit on a deleted
///    duplicate are recovered automatically by the existing orphan
///    sweep at startup.
///
/// 2. **Missing index** — assignments created before the user_index key
///    existed have no `solana:user_assignment:*` entry. This function
///    publishes the index for them so future O(1) lookups work.
///
/// Returns `(users_indexed, duplicates_dropped)`. Safe to run every
/// startup; idempotent once converged.
pub async fn consolidate_assignments(
    redis_url: &str,
) -> Result<(usize, usize), DetectorError> {
    let client = redis::Client::open(redis_url)
        .map_err(|e| DetectorError::RedisError(format!("Invalid Redis URL: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_error)?;

    let assignments = load_active_reservations(redis_url).await?;
    if assignments.is_empty() {
        return Ok((0, 0));
    }

    // Group by user_id
    let mut by_user: std::collections::HashMap<String, Vec<SolanaAssignment>> =
        std::collections::HashMap::new();
    for assignment in assignments {
        by_user
            .entry(assignment.user_id.clone())
            .or_default()
            .push(assignment);
    }

    let mut indexed: usize = 0;
    let mut dropped: usize = 0;
    for (user_id, mut group) in by_user {
        // Canonical = smallest reserved_at_unix, then smallest address
        group.sort_by(|a, b| {
            a.reserved_at_unix
                .cmp(&b.reserved_at_unix)
                .then(a.address.cmp(&b.address))
        });
        let canonical = group.remove(0);

        // Drop the duplicates (everything after canonical)
        for dupe in &group {
            log::warn!(
                "[SOL] consolidate: dropping duplicate assignment {} for user_id={} (canonical={}, reserved_at={})",
                dupe.address,
                user_id,
                canonical.address,
                dupe.reserved_at_unix
            );
            let _: i64 = redis::cmd("DEL")
                .arg(reservation_key(&dupe.address))
                .query_async(&mut connection)
                .await
                .map_err(redis_error)?;
            dropped += 1;
        }

        // Publish (or refresh) the per-user index pointing at canonical
        let _: () = redis::cmd("SET")
            .arg(user_index_key(&user_id))
            .arg(&canonical.address)
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        indexed += 1;
    }

    log::info!(
        "[SOL] consolidate: indexed {} user(s), dropped {} duplicate assignment(s) (any funds on dropped addresses will be recovered by the orphan sweep)",
        indexed,
        dropped
    );
    Ok((indexed, dropped))
}

/// Backwards-compatible alias used by older callers (and the API binary
/// during the transition). The `_ttl_secs` argument is ignored — the new
/// system never expires assignments.
pub async fn reserve_wallet_for_user(
    redis_url: &str,
    wallets: &SharedSolanaWallets,
    pool_path: &str,
    user_id: &str,
    _ttl_secs: u64,
) -> Result<SolanaReservation, DetectorError> {
    assign_wallet_for_user(redis_url, wallets, pool_path, user_id).await
}

pub fn reservation_key(address: &str) -> String {
    format!("{ASSIGNMENT_KEY_PREFIX}{address}")
}

pub fn user_index_key(user_id: &str) -> String {
    format!("{USER_INDEX_KEY_PREFIX}{user_id}")
}

pub fn user_lock_key(user_id: &str) -> String {
    format!("{USER_LOCK_KEY_PREFIX}{user_id}")
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
    scan_keys_by_prefix(connection, ASSIGNMENT_KEY_PREFIX).await
}

async fn scan_keys_by_prefix(
    connection: &mut redis::aio::MultiplexedConnection,
    prefix: &str,
) -> Result<Vec<String>, DetectorError> {
    let mut cursor: u64 = 0;
    let mut keys = Vec::new();

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
