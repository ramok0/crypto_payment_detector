//! Remote runtime configuration.
//!
//! The owner manages detector settings (private keys, RPC URLs, Helius /
//! Etherscan keys, sweep destinations, intervals, …) from the Karima admin
//! Configuration panel. They are persisted (secrets AES-encrypted) in the
//! backend and exposed at `GET /internal/runtime-config?scope=detector`
//! (internal-service-token auth), keyed by the exact env var this process
//! already reads.
//!
//! Boot: fetch overrides and apply them into the process environment *before*
//! any config builder runs, so the entire existing env-driven config path
//! transparently sources from the panel. The local `.env` only acts as a
//! fallback when the backend is unreachable (backward compatible).
//!
//! Apply-on-change: a watcher polls the same endpoint. Detector loops capture
//! their config at spawn, so to apply *any* change safely (including
//! structural ones — xpub, chain set, wallet pool) the process performs a
//! clean exit; Docker `restart: unless-stopped` immediately restarts it and
//! it resumes from its state files. From the operator's point of view a panel
//! change applies automatically within one poll interval, with no manual step
//! and no risk of half-applied config on a money-handling service.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;

const FETCH_TIMEOUT_SECS: u64 = 10;
const DEFAULT_POLL_SECS: u64 = 30;

fn base_url() -> Option<String> {
    std::env::var("CORE_API_INTERNAL_URL")
        .or_else(|_| std::env::var("BACKEND_API_INTERNAL_URL"))
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
}

fn internal_token() -> Option<String> {
    std::env::var("INTERNAL_SERVICE_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn poll_interval() -> Duration {
    let secs = std::env::var("RUNTIME_CONFIG_POLL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s >= 5)
        .unwrap_or(DEFAULT_POLL_SECS);
    Duration::from_secs(secs)
}

/// Stable fingerprint of an override set so the watcher can detect changes
/// without logging any (potentially secret) values.
fn signature(map: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (k, v) in map {
        hasher.update(k.as_bytes());
        hasher.update([0u8]);
        hasher.update(v.as_bytes());
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

async fn fetch() -> Option<BTreeMap<String, String>> {
    let base = base_url()?;
    let token = internal_token()?;
    let url = format!("{base}/internal/runtime-config?scope=detector");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .build()
        .ok()?;

    let resp = client
        .get(&url)
        .header("X-Internal-Service-Token", token)
        .send()
        .await
        .map_err(|e| log::warn!("[config] fetch failed: {e}"))
        .ok()?;

    if !resp.status().is_success() {
        log::warn!("[config] backend returned HTTP {}", resp.status());
        return None;
    }

    resp.json::<BTreeMap<String, String>>()
        .await
        .map_err(|e| log::warn!("[config] invalid JSON: {e}"))
        .ok()
}

/// Fetch + apply overrides into the process env. MUST be called at the very
/// top of `main` (single-threaded, before any task/builder) so the `set_var`
/// calls are sound. Returns the applied signature, or `None` when the backend
/// is unreachable (process keeps its local env — backward compatible).
pub async fn bootstrap() -> Option<String> {
    let overrides = fetch().await?;
    let sig = signature(&overrides);
    let count = overrides.len();

    for (key, value) in &overrides {
        // SAFETY: called at the start of `main` before any thread or async
        // task is spawned; no concurrent env access exists yet.
        unsafe {
            std::env::set_var(key, value);
        }
    }
    log::info!(
        "[config] applied {count} override(s) from admin panel (sig {})",
        &sig[..8]
    );
    Some(sig)
}

/// Background watcher: when the panel config changes, exit cleanly so the
/// container restarts with the new values applied. No-op when the backend is
/// unreachable (transient failures never trigger a restart).
pub fn spawn_watcher(boot_signature: Option<String>) {
    tokio::spawn(async move {
        let interval = poll_interval();
        loop {
            tokio::time::sleep(interval).await;
            let Some(current) = fetch().await else {
                continue;
            };
            let sig = signature(&current);
            let changed = match &boot_signature {
                Some(boot) => &sig != boot,
                // Backend was unreachable at boot but is now serving overrides
                // → apply them via a restart.
                None => !current.is_empty(),
            };
            if changed {
                log::warn!(
                    "[config] admin panel configuration changed — restarting to apply \
                     (the container will resume from its state files)"
                );
                std::process::exit(0);
            }
        }
    });
}
