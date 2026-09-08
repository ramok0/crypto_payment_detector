use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::DetectorError;
use crate::types::DetectedPayment;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPendingPayment {
    pub payment: DetectedPayment,
    pub block_height: u64,
    #[serde(default)]
    pub detected_notified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub last_scanned_height: Option<u64>,
    #[serde(default)]
    pub known_block_hashes: std::collections::HashMap<u64, String>,
    #[serde(default)]
    pub pending: Vec<PersistedPendingPayment>,
    #[serde(default)]
    pub notified_confirmed: std::collections::HashSet<String>,
}

pub(crate) fn load_json_state<T: serde::de::DeserializeOwned + Default>(
    path: &str,
) -> Result<T, DetectorError> {
    match std::fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(&data).map_err(|e| DetectorError::InvalidConfig(
            format!("Cannot parse state '{path}'; preserve this file and repair it before restarting: {e}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(DetectorError::InvalidConfig(format!("Cannot read state '{path}': {error}"))),
    }
}

pub fn load_state(path: &str) -> Result<PersistedState, DetectorError> {
    let p = Path::new(path);
    if !p.exists() {
        log::info!(
            "No persisted state file found at '{}', starting fresh",
            path
        );
        return Ok(PersistedState::default());
    }

    let data = std::fs::read_to_string(p)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to read state file: {e}")))?;
    let state: PersistedState = serde_json::from_str(&data)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to parse state file: {e}")))?;

    log::info!(
        "Loaded persisted state from '{}': last_scanned_height={:?} pending={} credited={}",
        path,
        state.last_scanned_height,
        state.pending.len(),
        state.notified_confirmed.len()
    );
    Ok(state)
}

pub fn save_state(path: &str, state: &PersistedState) -> Result<(), DetectorError> {
    save_json_state(path, state)
}

/// Call while holding the detector's state lock: serialization and replacement
/// must describe the same snapshot, and concurrent writers must not share .tmp.
pub(crate) fn save_json_state<T: Serialize>(path: &str, state: &T) -> Result<(), DetectorError> {
    let tmp_path = format!("{}.tmp", path);
    let data = serde_json::to_string_pretty(state)?;
    let mut file = std::fs::File::create(&tmp_path)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to create state file: {e}")))?;
    file.write_all(data.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to flush state file: {e}")))?;
    drop(file);
    std::fs::rename(&tmp_path, path)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to rename state file: {e}")))?;
    fsync_parent_dir(path);
    Ok(())
}

pub fn write_json_atomic<T: Serialize>(path: &str, value: &T) -> Result<(), DetectorError> {
    save_json_state(path, value)
}

/// Persist the directory entry pointing at `path`.
///
/// Best-effort: some filesystems reject fsync on a directory handle, and a
/// failure here only costs durability of the directory update, not correctness
/// of the data already written and synced.
pub fn fsync_parent_dir(path: &str) {
    let Some(parent) = Path::new(path).parent() else {
        return;
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    if let Ok(dir) = std::fs::File::open(parent)
        && let Err(e) = dir.sync_all()
    {
        log::debug!("Could not fsync directory '{}': {e}", parent.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Chain;

    fn scratch(name: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("cpd_persistence_{name}.json"));
        path.to_string_lossy().into_owned()
    }

    fn sample_payment(txid: &str) -> DetectedPayment {
        DetectedPayment {
            chain: Chain::Bitcoin,
            ticker: "BTC".into(),
            txid: txid.into(),
            address: "bc1qexample".into(),
            user_id: None,
            amount_sat: 12_345,
            amount_coin: 0.00012345,
            confirmations: 1,
            block_height: Some(900_000),
            derivation_index: 7,
            memo: None,
            swept_to_address: None,
            swept_amount_sat: None,
            swept_amount_coin: None,
            sweep_txid: None,
            fiat_amount: None,
            fiat_currency: None,
            coin_price: None,
            event_id: None,
            log_index: None,
            asset: None,
            asset_decimals: None,
            amount_base_units: None,
            swept_amount_base_units: None,
            token_contract: None,
        }
    }

    #[test]
    fn round_trips_pending_payments_and_credited_txids() {
        let path = scratch("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut state = PersistedState {
            last_scanned_height: Some(900_000),
            ..Default::default()
        };
        state.pending.push(PersistedPendingPayment {
            payment: sample_payment("aa"),
            block_height: 900_000,
            detected_notified: false,
        });
        state.notified_confirmed.insert("bb".to_string());

        save_state(&path, &state).expect("save");
        let loaded = load_state(&path).expect("load");

        assert_eq!(loaded.last_scanned_height, Some(900_000));
        assert_eq!(loaded.pending.len(), 1);
        assert_eq!(loaded.pending[0].payment.txid, "aa");
        assert_eq!(loaded.pending[0].block_height, 900_000);
        assert!(loaded.notified_confirmed.contains("bb"));

        let _ = std::fs::remove_file(&path);
    }

    /// State files written before pending/credited persistence existed must
    /// still load — otherwise an upgrade restarts every chain from scratch.
    #[test]
    fn loads_legacy_state_file_without_new_fields() {
        let path = scratch("legacy");
        std::fs::write(
            &path,
            r#"{"last_scanned_height": 42, "known_block_hashes": {"42": "abcd"}}"#,
        )
        .expect("write legacy file");

        let loaded = load_state(&path).expect("legacy state should load");
        assert_eq!(loaded.last_scanned_height, Some(42));
        assert_eq!(loaded.known_block_hashes.len(), 1);
        assert!(loaded.pending.is_empty());
        assert!(loaded.notified_confirmed.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let path = scratch("tmpcleanup");
        let _ = std::fs::remove_file(&path);

        save_state(&path, &PersistedState::default()).expect("save");
        assert!(!Path::new(&format!("{path}.tmp")).exists());

        let _ = std::fs::remove_file(&path);
    }
}
