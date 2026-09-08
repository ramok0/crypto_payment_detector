use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::DetectorError;
use crate::types::{DetectedPayment, WebhookEvent};

type HmacSha256 = Hmac<Sha256>;

pub async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    secret: &str,
    event: &WebhookEvent,
) -> Result<(), DetectorError> {
    log_payment_webhook(event);

    let payload = serde_json::to_string(event)?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| DetectorError::WebhookError(format!("HMAC init failed: {e}")))?;
    mac.update(payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // The durable detector outbox retries on later cycles. A permanently
    // rejected payload must never monopolize the scan/credit task forever.
    const ATTEMPTS: u32 = 3;
    for attempt in 0..ATTEMPTS {
        let result = client
            .post(url)
            .timeout(std::time::Duration::from_secs(10))
            .header("Content-Type", "application/json")
            .header("X-Signature-256", &signature)
            .body(payload.clone())
            .send()
            .await;
        let error = match result {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                let status = response.status();
                let error =
                    DetectorError::WebhookError(format!("Webhook returned status {status}"));
                if status.is_client_error() && status.as_u16() != 408 && status.as_u16() != 429 {
                    return Err(error);
                }
                error
            }
            Err(error) => DetectorError::WebhookError(format!("Webhook request failed: {error}")),
        };
        if attempt + 1 == ATTEMPTS {
            return Err(error);
        }
        let delay = 1000 * (1u64 << attempt);
        log::warn!("{error}; retrying in {delay}ms");
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
    unreachable!()
}

fn log_payment_webhook(event: &WebhookEvent) {
    match event {
        WebhookEvent::PaymentDetected(payment) => {
            log_payment_webhook_event("payment_detected", payment);
        }
        WebhookEvent::PaymentCredited(payment) => {
            log_payment_webhook_event("payment_credited", payment);
        }
    }
}

fn log_payment_webhook_event(event_name: &str, payment: &DetectedPayment) {
    log::info!(
        "[{}] Sending {} webhook: txid={} address={} amount={} {} confirmations={} user_id={:?}",
        payment.ticker,
        event_name,
        payment.txid,
        payment.address,
        payment.amount_coin,
        payment.ticker,
        payment.confirmations,
        payment.user_id
    );
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

pub async fn send_discord_webhook(
    client: &reqwest::Client,
    url: &str,
    content: &str,
) -> Result<(), DetectorError> {
    let body = serde_json::json!({
        "content": content,
    });

    let response =
        client.post(url).json(&body).send().await.map_err(|e| {
            DetectorError::WebhookError(format!("Discord webhook request failed: {e}"))
        })?;

    if !response.status().is_success() {
        return Err(DetectorError::WebhookError(format!(
            "Discord webhook returned status {}",
            response.status()
        )));
    }

    Ok(())
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
