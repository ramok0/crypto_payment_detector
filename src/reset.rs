//! Offline, journaled reset. The journal is durable before any active data changes.
//! A receipt makes an initContainer retry idempotent; a pending journal blocks daemons.
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use bitcoin::{
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    Chain, ChainDetector, DetectorConfig, build_config, build_evm_config, build_solana_config,
    chain_is_requested, env_utils::chain_env_prefix,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn root() -> PathBuf {
    // Must be identical for the API, standalone detector and reset binary and on
    // the same durable volume. Relative paths resolve from the Docker /data cwd.
    std::env::var_os("DETECTOR_MAINTENANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".detector-maintenance"))
}

fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn durable_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("File has no parent")?;
    fs::create_dir_all(parent)?;
    // Same filesystem as the destination; never use shared predictable temp files.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".reset-tmp");
    let tmp = PathBuf::from(tmp);
    // The process holds the exclusive storage lock. A crash can leave this file.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn lock(root: &Path, exclusive: bool) -> Result<File> {
    private_dir(root)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("lock"))?;
    if exclusive {
        FileExt::try_lock_exclusive(&file)?;
    } else {
        FileExt::try_lock_shared(&file)?;
    }
    Ok(file)
}

pub fn detector_guard() -> Result<File> {
    detector_guard_at(&root())
}

fn detector_guard_at(root: &Path) -> Result<File> {
    let guard = lock(root, false)?;
    if root.join("pending.json").try_exists()? {
        return Err("An interrupted reset must be resumed before detection".into());
    }
    Ok(guard)
}

fn generation_path(state: &str) -> PathBuf {
    PathBuf::from(format!("{state}.wallet-generation.json"))
}

#[derive(Serialize, Deserialize)]
struct Generation {
    version: u32,
    generation: u32,
}

fn generation(state: &str) -> Result<u32> {
    match fs::read(generation_path(state)) {
        Ok(bytes) => {
            let g: Generation = serde_json::from_slice(&bytes)?;
            if g.version != 1 || g.generation == 0 || g.generation >= (1 << 31) {
                return Err("Invalid wallet generation".into());
            }
            Ok(g.generation)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e.into()),
    }
}

fn rotate(config: &mut DetectorConfig, generation: u32) -> Result<()> {
    if generation == 0 {
        return Ok(());
    }
    // The legacy address path is 0/user_id. Branch 1/generation/0/user_id
    // never overlaps with it and preserves user_id in webhook derivation_index.
    let path = [
        ChildNumber::from_normal_idx(1)?,
        ChildNumber::from_normal_idx(generation)?,
    ];
    let secp = Secp256k1::new();
    let root = Xpub::from_str(&crate::derivation::normalize_xpub_to_bitcoin(
        &config.xpub,
        config.chain,
    )?)?;
    let active = root.derive_pub(&secp, &path)?;
    if let Some(key) = &config.sweep_xpriv {
        let private = Xpriv::from_str(&crate::bitcoin_sweep::normalize_xpriv_to_bitcoin(
            key,
            config.chain,
        )?)?;
        if Xpub::from_priv(&secp, &private) != root {
            return Err("XPUB and XPRIV do not match".into());
        }
        config.sweep_xpriv = Some(private.derive_priv(&secp, &path)?.to_string());
    }
    config.xpub = active.to_string();
    Ok(())
}

pub fn apply_wallet_generation(config: &mut DetectorConfig) -> Result<()> {
    rotate(config, generation(&config.state_file)?)
}

#[derive(Serialize, Deserialize)]
struct FileChange {
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct RedisKey {
    key: String,
    dump: Vec<u8>,
    ttl_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct RedisChange {
    chain: String,
    store_hash: String,
    keys: Vec<RedisKey>,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    id: String,
    selection: String,
    files: Vec<FileChange>,
    redis: Vec<RedisChange>,
    // Keep the original BTC/LTC root credentials for offline fund recovery,
    // even when an operator later replaces the Infisical master keys.
    recovery: Vec<Value>,
}

fn add_file(journal: &mut Journal, path: &Path, after: Vec<u8>) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    // Normalize parents to catch aliases between chain files or the archive.
    let parent = absolute.parent().ok_or("Missing parent")?;
    fs::create_dir_all(parent)?;
    let absolute = fs::canonicalize(parent)?.join(absolute.file_name().ok_or("Missing file name")?);
    if absolute.starts_with(fs::canonicalize(root())?)
        || journal.files.iter().any(|f| f.path == absolute)
    {
        return Err("Overlapping reset storage paths".into());
    }
    if fs::symlink_metadata(&absolute).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
        return Err("Reset paths must be regular files".into());
    }
    let before = match fs::read(&absolute) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    journal.files.push(FileChange {
        path: absolute,
        before,
        after,
    });
    Ok(())
}

fn chain(ticker: &str) -> Result<Chain> {
    match ticker {
        "ETH" => Ok(Chain::Ethereum),
        "BASE" => Ok(Chain::Base),
        "SOL" => Ok(Chain::Solana),
        "BTC" => Ok(Chain::Bitcoin),
        "LTC" => Ok(Chain::Litecoin),
        _ => Err("Unknown chain".into()),
    }
}

fn redis_url(ticker: &str) -> Result<String> {
    let c = chain(ticker)?;
    if c == Chain::Solana {
        Ok(build_solana_config()
            .map_err(|_| "Incomplete SOL settings")?
            .redis_url)
    } else {
        Ok(build_evm_config(c)
            .map_err(|_| "Incomplete EVM settings")?
            .redis_url)
    }
}

fn prefixes(ticker: &str) -> Result<Vec<String>> {
    let name = match ticker {
        "SOL" => "solana",
        "ETH" => "ethereum",
        "BASE" => "base",
        _ => return Err("Invalid assignment chain".into()),
    };
    let mut prefixes = vec![
        format!("{name}:assignment:"),
        format!("{name}:reservation:"),
    ];
    if ticker == "SOL" {
        prefixes.extend([
            "solana:user_assignment:".into(),
            "solana:user_assignment_lock:".into(),
        ]);
    }
    Ok(prefixes)
}

async fn snapshot_redis(ticker: &str) -> Result<Option<RedisChange>> {
    let url = redis_url(ticker)?;
    if ticker != "SOL"
        && (crate::ethereum_reservations_use_memory(chain(ticker)?)
            || url.trim().eq_ignore_ascii_case("memory")
            || url.starts_with("memory://"))
    {
        return Ok(None);
    }
    let mut conn = redis::Client::open(url.as_str())?
        .get_multiplexed_async_connection()
        .await?;
    let mut found = HashSet::new();
    for prefix in prefixes(ticker)? {
        let mut cursor = 0u64;
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{prefix}*"))
                .arg("COUNT")
                .arg(500)
                .query_async(&mut conn)
                .await?;
            found.extend(keys);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
    }
    let mut keys = Vec::new();
    for key in found {
        let dump: Option<Vec<u8>> = redis::cmd("DUMP").arg(&key).query_async(&mut conn).await?;
        let ttl_ms: i64 = redis::cmd("PTTL").arg(&key).query_async(&mut conn).await?;
        if let Some(dump) = dump {
            keys.push(RedisKey { key, dump, ttl_ms });
        }
    }
    Ok(Some(RedisChange {
        chain: ticker.into(),
        store_hash: hex::encode(Sha256::digest(url.as_bytes())),
        keys,
    }))
}

async fn rpc_height(url: &str, proxy: Option<&str>, method: &str) -> Result<u64> {
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
    if let Some(proxy) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    let value: Value = builder
        .build()?
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let height = if method == "getSlot" {
        value["result"].as_u64().ok_or("Missing slot")?
    } else {
        u64::from_str_radix(
            value["result"]
                .as_str()
                .ok_or("Missing block height")?
                .strip_prefix("0x")
                .ok_or("Invalid block height")?,
            16,
        )?
    };
    if height == 0 {
        return Err("Invalid chain tip".into());
    }
    Ok(height)
}

fn pool_size(path: &str) -> Result<usize> {
    match fs::read(path) {
        Ok(bytes) => {
            let v: Value = serde_json::from_slice(&bytes)?;
            Ok(v.as_array()
                .or_else(|| v.get("wallets").and_then(Value::as_array))
                .ok_or("Invalid wallet pool")?
                .len()
                .max(10))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(10),
        Err(e) => Err(e.into()),
    }
}

async fn prepare(selection: &str, id: &str) -> Result<Journal> {
    let tickers = if selection == "ALL" {
        vec!["ETH", "SOL", "BASE", "BTC", "LTC"]
    } else {
        chain(selection)?;
        vec![selection]
    };
    let mut journal = Journal {
        version: 1,
        id: id.into(),
        selection: selection.into(),
        files: vec![],
        redis: vec![],
        recovery: vec![],
    };
    validate_storage_paths()?;
    for ticker in tickers {
        let c = chain(ticker)?;
        if !chain_is_requested(c) {
            if selection == "ALL" {
                continue;
            }
            return Err("Selected chain is not configured".into());
        }
        if c == Chain::Bitcoin || c == Chain::Litecoin {
            let prefix = chain_env_prefix(c);
            let master = std::env::var(format!("{prefix}_XPUB"))?;
            let config =
                build_config(c, master.clone()).map_err(|_| "Incomplete BTC/LTC settings")?;
            let next = generation(&config.state_file)?
                .checked_add(1)
                .ok_or("Generation exhausted")?;
            let state = config.state_file.clone();
            let tip = ChainDetector::new_for_reset(config)?
                .get_chain_tip()
                .await?;
            let master_private = std::env::var(format!("{prefix}_XPRIV"))
                .ok()
                .filter(|s| !s.trim().is_empty());
            // Validate the next branch before persisting any changes.
            let mut check =
                build_config(c, master.clone()).map_err(|_| "Invalid BTC/LTC settings")?;
            check.xpub = master.clone();
            check.sweep_xpriv = master_private.clone();
            rotate(&mut check, next)?;
            journal.recovery.push(json!({"chain":ticker,"master_xpub":master,"master_xpriv":master_private,"previous_generation":next-1,"reset_height":tip}));
            add_file(
                &mut journal,
                &generation_path(&state),
                serde_json::to_vec(&Generation {
                    version: 1,
                    generation: next,
                })?,
            )?;
            add_file(
                &mut journal,
                Path::new(&state),
                serde_json::to_vec(
                    &json!({"last_scanned_height":tip,"known_block_hashes":{},"pending":[],"notified_confirmed":[]}),
                )?,
            )?;
        } else {
            let (state, pool, wallets, height) = if c == Chain::Solana {
                let cfg = build_solana_config().map_err(|_| "Incomplete SOL settings")?;
                let height = rpc_height(&cfg.rpc_url, cfg.proxy_url.as_deref(), "getSlot").await?;
                let wallets = crate::solana_pool::generate_wallet_pool_json(pool_size(
                    &cfg.wallet_pool_file,
                )?)?;
                (cfg.state_file, cfg.wallet_pool_file, wallets, height)
            } else {
                let cfg = build_evm_config(c).map_err(|_| "Incomplete EVM settings")?;
                let height =
                    rpc_height(&cfg.rpc_url, cfg.proxy_url.as_deref(), "eth_blockNumber").await?;
                let wallets = crate::ethereum_pool::generate_ethereum_wallet_pool_json(pool_size(
                    &cfg.wallet_pool_file,
                )?)?;
                (cfg.state_file, cfg.wallet_pool_file, wallets, height)
            };
            let clean = if c == Chain::Solana {
                json!({"addresses":{},"pending":[],"credited_signatures":[],"credited_payments":[],"gas_tank_last_maintenance_unix":null})
            } else {
                json!({"last_scanned_block":height,"scan_cursors":{"native":height,"erc20":height,"internal":height},"pending":[],"credited_events":[],"ignored_events":[],"gas_tank_last_maintenance_unix":null})
            };
            add_file(&mut journal, Path::new(&state), serde_json::to_vec(&clean)?)?;
            add_file(&mut journal, Path::new(&pool), wallets.into_bytes())?;
            if let Some(change) = snapshot_redis(ticker).await? {
                journal.redis.push(change);
            }
            journal
                .recovery
                .push(json!({"chain":ticker,"reset_height_or_slot":height}));
        }
    }
    if journal.files.is_empty() {
        return Err("No configured chain selected".into());
    }
    Ok(journal)
}

async fn commit(journal: &Journal) -> Result<()> {
    for recovery in &journal.recovery {
        let ticker = recovery["chain"].as_str().ok_or("Missing recovery chain")?;
        if ticker == "BTC" || ticker == "LTC" {
            let private = std::env::var(format!("{ticker}_XPRIV"))
                .ok()
                .filter(|s| !s.trim().is_empty());
            if recovery["master_xpub"].as_str()
                != Some(std::env::var(format!("{ticker}_XPUB"))?.as_str())
                || recovery["master_xpriv"].as_str() != private.as_deref()
            {
                return Err("Master keys changed during reset".into());
            }
        }
        for path in configured_paths(chain(ticker)?)? {
            let normalized = canonical_file(&path)?;
            if !journal.files.iter().any(|file| file.path == normalized) {
                return Err("Storage configuration changed during reset".into());
            }
        }
    }
    // Refuse a concurrent filesystem writer or a manually altered partial reset.
    for file in &journal.files {
        let current = match fs::read(&file.path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if current != file.before && current.as_deref() != Some(file.after.as_slice()) {
            return Err("Active file changed while reset was pending".into());
        }
    }
    for change in &journal.redis {
        let url = redis_url(&change.chain)?;
        if hex::encode(Sha256::digest(url.as_bytes())) != change.store_hash {
            return Err("Redis configuration changed during reset".into());
        }
        let mut conn = redis::Client::open(url.as_str())?
            .get_multiplexed_async_connection()
            .await?;
        let archived: HashSet<&str> = change.keys.iter().map(|k| k.key.as_str()).collect();
        for prefix in prefixes(&change.chain)? {
            let mut cursor = 0u64;
            loop {
                let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(format!("{prefix}*"))
                    .arg("COUNT")
                    .arg(500)
                    .query_async(&mut conn)
                    .await?;
                if keys.iter().any(|key| !archived.contains(key.as_str())) {
                    return Err("New assignments appeared during reset".into());
                }
                cursor = next;
                if cursor == 0 {
                    break;
                }
            }
        }
        // Compare-and-delete: a different writer must never lose a new assignment.
        // A missing key is expected on an idempotent retry or expired old reservation.
        for key in &change.keys {
            if !prefixes(&change.chain)?
                .iter()
                .any(|p| key.key.starts_with(p))
            {
                return Err("Invalid archived Redis key".into());
            }
            let result: i64 = redis::Script::new("local v = redis.call('DUMP', KEYS[1]); if not v then return 0 end; if v ~= ARGV[1] then return -1 end; return redis.call('DEL', KEYS[1])")
                .key(&key.key).arg(&key.dump).invoke_async(&mut conn).await?;
            if result < 0 {
                return Err("Assignment changed while detector was stopped".into());
            }
        }
    }
    for file in &journal.files {
        durable_write(&file.path, &file.after)?;
    }
    Ok(())
}

fn validate_storage_paths() -> Result<()> {
    // Check unselected chains too: a shared STATE_FILE must never erase them.
    let mut paths = HashSet::new();
    for ticker in ["ETH", "SOL", "BASE", "BTC", "LTC"] {
        let c = chain(ticker)?;
        if !chain_is_requested(c) {
            continue;
        }
        let files = configured_paths(c)?;
        for path in files {
            let absolute = if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            };
            let parent = absolute.parent().ok_or("Missing storage directory")?;
            fs::create_dir_all(parent)?;
            let normalized =
                fs::canonicalize(parent)?.join(absolute.file_name().ok_or("Missing filename")?);
            if !paths.insert(normalized.clone())
                || normalized.starts_with(fs::canonicalize(root())?)
            {
                return Err("Configured chains share a storage path".into());
            }
            if fs::symlink_metadata(&normalized)
                .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
            {
                return Err("Storage must use regular files".into());
            }
        }
    }
    Ok(())
}

fn canonical_file(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().ok_or("Missing storage directory")?;
    fs::create_dir_all(parent)?;
    Ok(fs::canonicalize(parent)?.join(absolute.file_name().ok_or("Missing filename")?))
}

fn configured_paths(c: Chain) -> Result<Vec<PathBuf>> {
    Ok(match c {
        Chain::Bitcoin | Chain::Litecoin => {
            let cfg = build_config(c, std::env::var(format!("{}_XPUB", chain_env_prefix(c)))?)
                .map_err(|_| "Invalid BTC/LTC configuration")?;
            vec![
                PathBuf::from(&cfg.state_file),
                generation_path(&cfg.state_file),
            ]
        }
        Chain::Solana => {
            let cfg = build_solana_config().map_err(|_| "Invalid SOL configuration")?;
            vec![
                PathBuf::from(cfg.state_file),
                PathBuf::from(cfg.wallet_pool_file),
            ]
        }
        _ => {
            let cfg = build_evm_config(c).map_err(|_| "Invalid EVM configuration")?;
            vec![
                PathBuf::from(cfg.state_file),
                PathBuf::from(cfg.wallet_pool_file),
            ]
        }
    })
}

pub async fn execute(selection: &str, id: &str) -> Result<()> {
    execute_at(&root(), selection, id).await
}

async fn execute_at(root: &Path, selection: &str, id: &str) -> Result<()> {
    if id.len() < 12 || id.len() > 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid operation ID".into());
    }
    if selection != "ALL" {
        chain(selection)?;
    }
    let _guard = lock(root, true)?;
    let archive = root.join("archives").join(id);
    let pending = root.join("pending.json");
    let manifest = archive.join("archive.json");
    if pending.try_exists()? && fs::read_to_string(&pending)? != id {
        return Err("A different reset is pending".into());
    }
    if archive.join("complete").try_exists()? {
        let completed: Journal = serde_json::from_slice(&fs::read(&manifest)?)?;
        if completed.selection != selection || completed.id != id {
            return Err("Operation ID already used for a different reset".into());
        }
        // A crash after the receipt but before removing the journal is harmless.
        if pending.try_exists()? && fs::read_to_string(&pending)? == id {
            fs::remove_file(&pending)?;
            File::open(&root)?.sync_all()?;
        }
        return Ok(());
    }
    let journal: Journal = if manifest.try_exists()? {
        // A crash between durable archive and pending marker is also resumable.
        // commit verifies current files, configuration and Redis against this archive.
        serde_json::from_slice(&fs::read(&manifest)?)?
    } else {
        if pending.try_exists()? {
            return Err("Pending reset archive is missing".into());
        }
        let journal = prepare(selection, id).await?;
        private_dir(&root.join("archives"))?;
        private_dir(&archive)?;
        durable_write(&manifest, &serde_json::to_vec(&journal)?)?;
        File::open(root.join("archives"))?.sync_all()?;
        journal
    };
    if journal.version != 1 || journal.id != id || journal.selection != selection {
        return Err("Reset journal mismatch".into());
    }
    durable_write(&pending, id.as_bytes())?;
    commit(&journal).await?;
    durable_write(&archive.join("complete"), b"complete\n")?;
    fs::remove_file(&pending)?;
    File::open(&root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{CompressedPublicKey, Network};

    #[test]
    fn rotated_addresses_are_new_and_private_keys_still_match_user_index() {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Bitcoin, &[42; 32]).unwrap();
        let public = Xpub::from_priv(&secp, &master).to_string();
        for chain in [Chain::Bitcoin, Chain::Litecoin] {
            let mut addresses = HashSet::new();
            for generation in [0, 1, 2] {
                let mut config = DetectorConfig {
                    chain,
                    xpub: public.clone(),
                    sweep_xpriv: Some(master.to_string()),
                    ..Default::default()
                };
                rotate(&mut config, generation).unwrap();
                for user in [0, 1, 42, 9999] {
                    let address =
                        crate::derivation::derive_address(&config.xpub, user, chain).unwrap();
                    assert!(addresses.insert(address));
                    let key = crate::bitcoin_sweep::derive_private_key(
                        config.sweep_xpriv.as_ref().unwrap(),
                        user,
                        chain,
                    )
                    .unwrap();
                    let expected = Xpub::from_str(&config.xpub)
                        .unwrap()
                        .derive_pub(
                            &secp,
                            &[
                                ChildNumber::Normal { index: 0 },
                                ChildNumber::Normal { index: user },
                            ],
                        )
                        .unwrap();
                    assert_eq!(
                        CompressedPublicKey(expected.public_key).0,
                        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key)
                    );
                }
            }
        }
    }

    #[test]
    fn reset_excludes_live_detectors_and_journal_blocks_startup() {
        let root = tempfile::tempdir().unwrap();
        let live = detector_guard_at(root.path()).unwrap();
        assert!(lock(root.path(), true).is_err());
        drop(live);
        let reset = lock(root.path(), true).unwrap();
        assert!(detector_guard_at(root.path()).is_err());
        drop(reset);
        durable_write(&root.path().join("pending.json"), b"012345abcdef").unwrap();
        assert!(detector_guard_at(root.path()).is_err());
    }

    #[test]
    fn corrupt_generation_and_mismatching_master_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("btc.json").to_str().unwrap().to_owned();
        assert_eq!(generation(&path).unwrap(), 0);
        fs::write(generation_path(&path), b"{}").unwrap();
        assert!(generation(&path).is_err());
        let private = Xpriv::new_master(Network::Bitcoin, &[1; 32]).unwrap();
        let other = Xpriv::new_master(Network::Bitcoin, &[2; 32]).unwrap();
        let mut config = DetectorConfig {
            xpub: Xpub::from_priv(&Secp256k1::new(), &private).to_string(),
            sweep_xpriv: Some(other.to_string()),
            ..Default::default()
        };
        assert!(rotate(&mut config, 1).is_err());
    }

    #[tokio::test]
    async fn file_commit_is_idempotent_and_preserves_unselected_files() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("eth.json");
        let other = dir.path().join("base.json");
        fs::write(&selected, b"old").unwrap();
        fs::write(&other, b"untouched").unwrap();
        let j = Journal {
            version: 1,
            id: "012345abcdef".into(),
            selection: "ETH".into(),
            files: vec![FileChange {
                path: selected.clone(),
                before: Some(b"old".to_vec()),
                after: b"new".to_vec(),
            }],
            redis: vec![],
            recovery: vec![],
        };
        commit(&j).await.unwrap();
        commit(&j).await.unwrap();
        assert_eq!(fs::read(&selected).unwrap(), b"new");
        assert_eq!(fs::read(&other).unwrap(), b"untouched");
        fs::write(&selected, b"concurrent").unwrap();
        assert!(commit(&j).await.is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&selected).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn invalid_selection_or_id_has_no_side_effects() {
        assert!(execute("DOGE", "012345abcdef").await.is_err());
        assert!(execute("ALL", "../escape").await.is_err());
    }

    #[tokio::test]
    async fn interrupted_reset_resumes_once_and_receipt_never_erases_new_payments() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("maintenance");
        let id = "012345abcdef";
        let archive = root.join("archives").join(id);
        private_dir(&archive).unwrap();
        let state = dir.path().join("eth.json");
        fs::write(&state, b"old payments").unwrap();
        let journal = Journal {
            version: 1,
            id: id.into(),
            selection: "ETH".into(),
            files: vec![FileChange {
                path: state.clone(),
                before: Some(b"old payments".to_vec()),
                after: b"clean".to_vec(),
            }],
            redis: vec![],
            recovery: vec![],
        };
        durable_write(
            &archive.join("archive.json"),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        durable_write(&root.join("pending.json"), id.as_bytes()).unwrap();
        assert!(execute_at(&root, "BASE", id).await.is_err());
        assert!(execute_at(&root, "ETH", "ffffffffffff").await.is_err());
        assert!(detector_guard_at(&root).is_err());
        execute_at(&root, "ETH", id).await.unwrap();
        assert_eq!(fs::read(&state).unwrap(), b"clean");
        assert!(!root.join("pending.json").exists());
        assert!(archive.join("complete").exists());
        assert!(detector_guard_at(&root).is_ok());
        fs::write(&state, b"new payments").unwrap();
        // Re-running the initContainer after successful reset is a no-op.
        execute_at(&root, "ETH", id).await.unwrap();
        assert_eq!(fs::read(&state).unwrap(), b"new payments");
        let archived: Journal =
            serde_json::from_slice(&fs::read(archive.join("archive.json")).unwrap()).unwrap();
        assert_eq!(
            archived.files[0].before.as_deref(),
            Some(b"old payments".as_slice())
        );
    }

    #[test]
    fn reset_generates_valid_fresh_wallet_pools() {
        let dir = tempfile::tempdir().unwrap();
        for solana in [false, true] {
            let mut seen = HashSet::new();
            for n in 0..2 {
                let bytes = if solana {
                    crate::solana_pool::generate_wallet_pool_json(10).unwrap()
                } else {
                    crate::ethereum_pool::generate_ethereum_wallet_pool_json(10).unwrap()
                };
                let value: Value = serde_json::from_str(&bytes).unwrap();
                for wallet in value["wallets"].as_array().unwrap() {
                    assert!(seen.insert(wallet["address"].as_str().unwrap().to_owned()));
                }
                let file = dir.path().join(format!("{solana}-{n}.json"));
                durable_write(&file, bytes.as_bytes()).unwrap();
                if solana {
                    assert_eq!(
                        crate::load_wallet_pool(file.to_str().unwrap())
                            .unwrap()
                            .len(),
                        10
                    );
                } else {
                    assert_eq!(
                        crate::load_ethereum_wallet_pool(Chain::Ethereum, file.to_str().unwrap())
                            .unwrap()
                            .len(),
                        10
                    );
                }
            }
        }
    }
}
