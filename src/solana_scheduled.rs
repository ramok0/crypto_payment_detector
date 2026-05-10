//! Outbound scheduled SOL payments routed through the gas wallet.
//!
//! The autoshop backend writes a JSON list of pending payments to the Redis
//! key `scheduled_sol_payments:active`. On every gas-tank maintenance tick
//! the detector reads this list; if any payment is pending and not expired
//! it diverts the gas-tank-to-ledger sweep to the scheduled destination
//! once enough lamports have accumulated. When a send succeeds (or fails
//! permanently), the detector POSTs to the backend's internal API so the
//! status is committed to the source-of-truth Postgres table.
//!
//! The Redis snapshot is the only contract between backend and detector.
//! It is rewritten by the backend on every state change and on backend boot.

use serde::{Deserialize, Serialize};

use crate::error::DetectorError;

const SCHEDULED_REDIS_KEY: &str = "scheduled_sol_payments:active";

/// Mirror of the JSON payload the backend writes to Redis. The `status`
/// field isn't included because the backend filters to `pending` before
/// publishing — anything we read here is, by construction, still pending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledSolPayment {
    pub id: i32,
    pub destination_address: String,
    /// Decimal amount as a string. Detector parses on demand to avoid f64
    /// precision loss before comparing against lamport balances.
    pub amount_value: String,
    /// One of "SOL" | "EUR" | "USD".
    pub amount_currency: String,
    pub expires_at_unix: i64,
}

/// Reads the current set of pending scheduled payments from Redis.
/// Returns an empty Vec when the key is missing, when the JSON cannot be
/// parsed, or when Redis is unreachable — the maintenance loop must keep
/// running and the next tick will retry.
pub async fn load_pending_scheduled_payments(
    redis_url: &str,
) -> Result<Vec<ScheduledSolPayment>, DetectorError> {
    let client = redis::Client::open(redis_url).map_err(|error| {
        DetectorError::RedisError(format!("Invalid Redis URL: {error}"))
    })?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|error| DetectorError::RedisError(format!("Redis connect failed: {error}")))?;

    let payload: Option<String> = redis::cmd("GET")
        .arg(SCHEDULED_REDIS_KEY)
        .query_async(&mut connection)
        .await
        .map_err(|error| DetectorError::RedisError(format!("Redis GET failed: {error}")))?;

    let Some(payload) = payload else {
        return Ok(Vec::new());
    };
    if payload.trim().is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str::<Vec<ScheduledSolPayment>>(&payload).map_err(|error| {
        DetectorError::InvalidConfig(format!(
            "Failed to parse scheduled SOL payments snapshot: {error}"
        ))
    })
}

/// POST `/internal/scheduled-sol-payments/{id}/mark-sent` on the backend
/// to commit a successful payout. We retry transient failures briefly —
/// this call is the *only* signal the backend gets that the funds left,
/// so we want to be robust without blocking the maintenance loop forever.
pub async fn notify_payment_sent(
    http_client: &reqwest::Client,
    backend_url: &str,
    internal_token: &str,
    payment_id: i32,
    txid: &str,
    sent_amount_lamports: i64,
) {
    let url = format!(
        "{}/internal/scheduled-sol-payments/{}/mark-sent",
        backend_url.trim_end_matches('/'),
        payment_id
    );
    let body = serde_json::json!({
        "txid": txid,
        "sent_amount_lamports": sent_amount_lamports,
    });
    post_internal(http_client, &url, internal_token, &body).await;
}

/// POST `/internal/scheduled-sol-payments/{id}/mark-failed` to record an
/// unrecoverable error (e.g. invalid destination address). Recoverable RPC
/// blips should NOT call this — the next maintenance tick will retry.
pub async fn notify_payment_failed(
    http_client: &reqwest::Client,
    backend_url: &str,
    internal_token: &str,
    payment_id: i32,
    reason: &str,
) {
    let url = format!(
        "{}/internal/scheduled-sol-payments/{}/mark-failed",
        backend_url.trim_end_matches('/'),
        payment_id
    );
    let body = serde_json::json!({ "reason": reason });
    post_internal(http_client, &url, internal_token, &body).await;
}

async fn post_internal(
    http_client: &reqwest::Client,
    url: &str,
    internal_token: &str,
    body: &serde_json::Value,
) {
    const MAX_ATTEMPTS: u32 = 5;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let result = http_client
            .post(url)
            .header("Content-Type", "application/json")
            .header("x-internal-service-token", internal_token)
            .json(body)
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                log::warn!(
                    "[SOL][SCHED] Internal callback {} returned {} (attempt {})",
                    url,
                    response.status(),
                    attempt
                );
            }
            Err(error) => {
                log::warn!(
                    "[SOL][SCHED] Internal callback {} failed: {} (attempt {})",
                    url,
                    error,
                    attempt
                );
            }
        }
        if attempt >= MAX_ATTEMPTS {
            log::error!(
                "[SOL][SCHED] Giving up on internal callback {} after {} attempts",
                url,
                attempt
            );
            return;
        }
        let delay = std::cmp::min(1000u64 * 2u64.pow(attempt.min(5)), 30_000);
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
}
