use std::collections::HashSet;

use serde::Deserialize;
use serde_json::Value;

use crate::error::DetectorError;

const DEFAULT_BASE_URL: &str = "https://api.helius.xyz";

/// Configuration for the Helius webhook integration. The whole module is a
/// no-op when [`HeliusWebhookConfig::from_env`] returns `None` — i.e. when
/// `HELIUS_WEBHOOK_ENABLED` is unset or falsy. This keeps the original
/// polling-only behaviour reachable by simply unsetting the env var.
#[derive(Debug, Clone)]
pub struct HeliusWebhookConfig {
    pub api_key: String,
    pub webhook_id: String,
    pub base_url: String,
    /// Optional shared secret echoed by Helius in the inbound POST's
    /// `Authorization` header. When set, the `/solana/webhook` route
    /// rejects requests whose header does not match.
    pub auth_header: Option<String>,
}

impl HeliusWebhookConfig {
    /// Parse the env vars into a config. Returns `Ok(None)` when the
    /// integration is disabled, `Err` when it is enabled but mandatory
    /// values are missing.
    pub fn from_env() -> Result<Option<Self>, DetectorError> {
        let enabled = std::env::var("HELIUS_WEBHOOK_ENABLED")
            .ok()
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if !enabled {
            return Ok(None);
        }

        let api_key = std::env::var("HELIUS_API_KEY")
            .map_err(|_| {
                DetectorError::InvalidConfig(
                    "HELIUS_WEBHOOK_ENABLED=true but HELIUS_API_KEY is not set".into(),
                )
            })?
            .trim()
            .to_string();
        if api_key.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "HELIUS_API_KEY cannot be empty".into(),
            ));
        }

        let webhook_id = std::env::var("HELIUS_WEBHOOK_ID")
            .map_err(|_| {
                DetectorError::InvalidConfig(
                    "HELIUS_WEBHOOK_ENABLED=true but HELIUS_WEBHOOK_ID is not set".into(),
                )
            })?
            .trim()
            .to_string();
        if webhook_id.is_empty() {
            return Err(DetectorError::InvalidConfig(
                "HELIUS_WEBHOOK_ID cannot be empty".into(),
            ));
        }

        let base_url = std::env::var("HELIUS_API_BASE_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

        let auth_header = std::env::var("HELIUS_WEBHOOK_AUTH_HEADER")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        Ok(Some(Self {
            api_key,
            webhook_id,
            base_url,
            auth_header,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct HeliusWebhookClient {
    config: HeliusWebhookConfig,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct HeliusErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

impl HeliusWebhookClient {
    pub fn new(config: HeliusWebhookConfig) -> Result<Self, DetectorError> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Failed to build Helius HTTP client: {e}"
                ))
            })?;
        Ok(Self { config, http })
    }

    pub fn auth_header(&self) -> Option<&str> {
        self.config.auth_header.as_deref()
    }

    fn webhook_url(&self) -> String {
        format!(
            "{}/v0/webhooks/{}?api-key={}",
            self.config.base_url, self.config.webhook_id, self.config.api_key
        )
    }

    /// Fetch the current webhook config. Returns the raw JSON the
    /// `Edit Webhook` endpoint sent us — note that the GET response
    /// includes read-only metadata (`webhookID`, `project`, `wallet`,
    /// `createdAt`, ...) which the PUT endpoint **rejects with 400**.
    /// Always run the result through [`Self::sanitize_for_put`] before
    /// PUTing it back.
    pub async fn get_webhook(&self) -> Result<Value, DetectorError> {
        let url = self.webhook_url();
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| DetectorError::ApiError(format!("Helius GET webhook failed: {e}")))?;
        let status = response.status();
        let body = response.text().await.map_err(|e| {
            DetectorError::ApiError(format!("Helius GET webhook body read failed: {e}"))
        })?;
        if !status.is_success() {
            return Err(DetectorError::ApiError(format!(
                "Helius GET webhook returned {}: {}",
                status,
                short_body(&body)
            )));
        }
        serde_json::from_str::<Value>(&body).map_err(|e| {
            DetectorError::ApiError(format!(
                "Helius GET webhook returned invalid JSON: {e}"
            ))
        })
    }

    /// Replace the webhook's `accountAddresses` field wholesale and PUT the
    /// merged payload back. Preserves every other field returned by GET.
    /// Caller is responsible for de-duplicating the input.
    pub async fn replace_addresses(
        &self,
        addresses: Vec<String>,
    ) -> Result<(), DetectorError> {
        let mut current = self.get_webhook().await?;
        let dedup: Vec<String> = {
            let set: HashSet<String> = addresses.into_iter().collect();
            let mut v: Vec<String> = set.into_iter().collect();
            v.sort();
            v
        };
        if let Some(obj) = current.as_object_mut() {
            obj.insert(
                "accountAddresses".to_string(),
                Value::Array(dedup.iter().map(|s| Value::String(s.clone())).collect()),
            );
        } else {
            return Err(DetectorError::ApiError(
                "Helius webhook payload is not a JSON object".into(),
            ));
        }
        self.put_webhook(&current).await?;
        log::info!(
            "[HELIUS] Replaced webhook {} address list ({} addresses)",
            self.config.webhook_id,
            dedup.len()
        );
        Ok(())
    }

    /// Add the given addresses to the webhook (idempotent — already-known
    /// addresses are kept unchanged). Empty input returns `Ok(())` without
    /// hitting the API.
    pub async fn add_addresses(&self, addresses: &[String]) -> Result<(), DetectorError> {
        if addresses.is_empty() {
            return Ok(());
        }
        let mut current = self.get_webhook().await?;
        let mut existing: Vec<String> = current
            .get("accountAddresses")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let before = existing.len();
        let mut set: HashSet<String> = existing.drain(..).collect();
        for addr in addresses {
            set.insert(addr.clone());
        }
        let mut merged: Vec<String> = set.into_iter().collect();
        merged.sort();
        if merged.len() == before {
            log::debug!(
                "[HELIUS] No change to webhook {} address list (already contains {} addresses)",
                self.config.webhook_id,
                before
            );
            return Ok(());
        }
        if let Some(obj) = current.as_object_mut() {
            obj.insert(
                "accountAddresses".to_string(),
                Value::Array(merged.iter().map(|s| Value::String(s.clone())).collect()),
            );
        }
        self.put_webhook(&current).await?;
        log::info!(
            "[HELIUS] Added {} address(es) to webhook {} (total now {})",
            merged.len() - before,
            self.config.webhook_id,
            merged.len()
        );
        Ok(())
    }

    /// Remove the given addresses from the webhook. No-op if none of them
    /// are currently registered.
    pub async fn remove_addresses(&self, addresses: &[String]) -> Result<(), DetectorError> {
        if addresses.is_empty() {
            return Ok(());
        }
        let mut current = self.get_webhook().await?;
        let existing: Vec<String> = current
            .get("accountAddresses")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let to_remove: HashSet<&String> = addresses.iter().collect();
        let mut filtered: Vec<String> = existing
            .into_iter()
            .filter(|addr| !to_remove.contains(addr))
            .collect();
        filtered.sort();
        if let Some(obj) = current.as_object_mut() {
            obj.insert(
                "accountAddresses".to_string(),
                Value::Array(filtered.iter().map(|s| Value::String(s.clone())).collect()),
            );
        }
        self.put_webhook(&current).await?;
        log::info!(
            "[HELIUS] Pruned webhook {} address list down to {} address(es)",
            self.config.webhook_id,
            filtered.len()
        );
        Ok(())
    }

    /// Build a PUT-safe body from a raw GET response. Helius's
    /// `Edit Webhook` endpoint validates the input strictly and returns
    /// 400 with `"property X should not exist"` when it sees any read-only
    /// field (`webhookID`, `project`, `wallet`, `createdAt`, ...). We
    /// whitelist the documented writable fields and drop everything else.
    fn sanitize_for_put(body: &Value) -> Value {
        const WRITABLE_FIELDS: &[&str] = &[
            "webhookURL",
            "transactionTypes",
            "accountAddresses",
            "webhookType",
            "authHeader",
            "txnStatus",
            "encoding",
        ];
        let mut out = serde_json::Map::new();
        if let Some(obj) = body.as_object() {
            for field in WRITABLE_FIELDS {
                if let Some(value) = obj.get(*field) {
                    out.insert((*field).to_string(), value.clone());
                }
            }
        }
        Value::Object(out)
    }

    async fn put_webhook(&self, body: &Value) -> Result<(), DetectorError> {
        let url = self.webhook_url();
        let sanitized = Self::sanitize_for_put(body);
        let response = self
            .http
            .put(&url)
            .json(&sanitized)
            .send()
            .await
            .map_err(|e| DetectorError::ApiError(format!("Helius PUT webhook failed: {e}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            let parsed: Option<HeliusErrorBody> = serde_json::from_str(&text).ok();
            let detail = parsed
                .and_then(|b| b.error.or(b.message))
                .unwrap_or_else(|| short_body(&text));
            return Err(DetectorError::ApiError(format!(
                "Helius PUT webhook returned {}: {}",
                status, detail
            )));
        }
        Ok(())
    }
}

/// Constant-time string equality for verifying the inbound `Authorization`
/// header. `expected` is the value configured server-side and `received` is
/// what arrived in the request.
pub fn verify_auth_header(expected: &str, received: &str) -> bool {
    let a = expected.as_bytes();
    let b = received.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Walk an arbitrary JSON value and collect every string that looks like a
/// Solana base58 pubkey (32-44 chars, base58 alphabet). The webhook handler
/// uses this to extract candidate addresses from a Helius payload without
/// being tied to either the raw or enhanced schema. Caller intersects the
/// result with the active assignment list to find which managed wallets
/// were touched.
pub fn collect_candidate_addresses(payload: &Value) -> HashSet<String> {
    let mut out = HashSet::new();
    walk(payload, &mut out);
    out
}

fn walk(value: &Value, out: &mut HashSet<String>) {
    match value {
        Value::String(s) => {
            if looks_like_solana_pubkey(s) {
                out.insert(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                walk(v, out);
            }
        }
        _ => {}
    }
}

fn looks_like_solana_pubkey(s: &str) -> bool {
    let len = s.len();
    if !(32..=44).contains(&len) {
        return false;
    }
    s.bytes().all(|b| {
        matches!(b,
            b'1'..=b'9' |
            b'A'..=b'H' |
            b'J'..=b'N' |
            b'P'..=b'Z' |
            b'a'..=b'k' |
            b'm'..=b'z'
        )
    })
}

fn short_body(body: &str) -> String {
    let trimmed: String = body.chars().take(300).collect();
    if body.len() > trimmed.len() {
        format!("{trimmed}...")
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_recognition() {
        assert!(looks_like_solana_pubkey(
            "5xZkF6JxmRgGq3rXzQ7P3sUYVD1bjYV1tfgSC2dKjcre"
        ));
        // contains 'O' which is excluded from base58
        assert!(!looks_like_solana_pubkey(
            "5xOkF6JxmRgGq3rXzQ7P3sUYVD1bjYV1tfgSC2dKjcre"
        ));
        // too short
        assert!(!looks_like_solana_pubkey("abc"));
        // contains '0' which is excluded
        assert!(!looks_like_solana_pubkey(
            "0xZkF6JxmRgGq3rXzQ7P3sUYVD1bjYV1tfgSC2dKjcre"
        ));
    }

    #[test]
    fn collect_walks_nested_payload() {
        let payload = serde_json::json!([{
            "signature": "5xZkF6JxmRgGq3rXzQ7P3sUYVD1bjYV1tfgSC2dKjcre",
            "tokenTransfers": [{
                "toUserAccount": "8xZkF6JxmRgGq3rXzQ7P3sUYVD1bjYV1tfgSC2dKjcre"
            }],
            "amount": 100,
        }]);
        let collected = collect_candidate_addresses(&payload);
        assert!(collected.contains("5xZkF6JxmRgGq3rXzQ7P3sUYVD1bjYV1tfgSC2dKjcre"));
        assert!(collected.contains("8xZkF6JxmRgGq3rXzQ7P3sUYVD1bjYV1tfgSC2dKjcre"));
    }

    #[test]
    fn auth_header_compare() {
        assert!(verify_auth_header("secret", "secret"));
        assert!(!verify_auth_header("secret", "Secret"));
        assert!(!verify_auth_header("secret", "secre"));
    }

    #[test]
    fn sanitize_strips_read_only_fields() {
        // What Helius actually returns from GET /v0/webhooks/:id — the
        // shape that triggered the 400 in production.
        let raw_get = serde_json::json!({
            "webhookID": "abc-123",
            "wallet": "wal-456",
            "project": "proj-789",
            "createdAt": "2026-05-09T00:00:00Z",
            "webhookURL": "https://example.com/webhook",
            "transactionTypes": ["Any"],
            "accountAddresses": ["AAA", "BBB"],
            "webhookType": "enhanced",
            "authHeader": "secret",
            "txnStatus": "all",
            "encoding": "jsonParsed"
        });
        let sanitized = HeliusWebhookClient::sanitize_for_put(&raw_get);
        let obj = sanitized.as_object().unwrap();
        // Read-only metadata is gone
        assert!(!obj.contains_key("webhookID"));
        assert!(!obj.contains_key("wallet"));
        assert!(!obj.contains_key("project"));
        assert!(!obj.contains_key("createdAt"));
        // Writable fields are preserved untouched
        assert_eq!(obj.get("webhookURL").unwrap(), "https://example.com/webhook");
        assert_eq!(
            obj.get("accountAddresses").unwrap(),
            &serde_json::json!(["AAA", "BBB"])
        );
        assert_eq!(obj.get("webhookType").unwrap(), "enhanced");
        assert_eq!(obj.get("authHeader").unwrap(), "secret");
    }
}
