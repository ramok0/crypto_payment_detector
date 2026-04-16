use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::DetectorError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub last_scanned_height: Option<u64>,
    #[serde(default)]
    pub known_block_hashes: std::collections::HashMap<u64, String>,
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
        "Loaded persisted state from '{}': last_scanned_height={:?}",
        path,
        state.last_scanned_height
    );
    Ok(state)
}

pub fn save_state(path: &str, state: &PersistedState) -> Result<(), DetectorError> {
    let tmp_path = format!("{}.tmp", path);
    let data = serde_json::to_string_pretty(state)?;
    std::fs::write(&tmp_path, &data)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to write state file: {e}")))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| DetectorError::InvalidConfig(format!("Failed to rename state file: {e}")))?;
    Ok(())
}
