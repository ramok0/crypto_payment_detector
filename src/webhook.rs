use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::DetectorError;
use crate::types::WebhookEvent;

type HmacSha256 = Hmac<Sha256>;

pub async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    secret: &str,
    event: &WebhookEvent,
) -> Result<(), DetectorError> {
    let payload = serde_json::to_string(event)?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| DetectorError::WebhookError(format!("HMAC init failed: {e}")))?;
    mac.update(payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let mut attempt: u32 = 0;
    loop {
        let result = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Signature-256", &signature)
            .body(payload.clone())
            .send()
            .await;

        match result {
            Ok(response) if response.status().is_success() => {
                if attempt > 0 {
                    log::info!("Webhook delivered after {} retries", attempt);
                }
                return Ok(());
            }
            Ok(response) => {
                let status = response.status();
                attempt += 1;
                let delay = std::cmp::min(1000 * 2u64.pow(attempt.min(6)), 60_000);
                log::warn!(
                    "Webhook returned status {} - retry #{} in {}ms",
                    status,
                    attempt,
                    delay
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            Err(e) => {
                attempt += 1;
                let delay = std::cmp::min(1000 * 2u64.pow(attempt.min(6)), 60_000);
                log::warn!(
                    "Webhook request failed: {} - retry #{} in {}ms",
                    e,
                    attempt,
                    delay
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
        }
    }
}

pub fn verify_signature(secret: &str, payload: &[u8], signature_hex: &str) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(payload);

    let Ok(expected) = hex::decode(signature_hex) else {
        return false;
    };

    mac.verify_slice(&expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_signature_roundtrip() {
        let secret = "test_secret_key";
        let payload = b"hello world";

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload);
        let sig = hex::encode(mac.finalize().into_bytes());

        assert!(verify_signature(secret, payload, &sig));
        assert!(!verify_signature("wrong_secret", payload, &sig));
        assert!(!verify_signature(secret, b"wrong payload", &sig));
    }
}
