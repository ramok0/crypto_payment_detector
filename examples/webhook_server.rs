use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use crypto_payment_detector::{WebhookEvent, verify_signature};

#[derive(Clone)]
struct AppState {
    webhook_secret: String,
}

async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let signature = match headers.get("X-Signature-256") {
        Some(val) => match val.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                eprintln!("[REJECTED] Invalid X-Signature-256 header encoding");
                return StatusCode::BAD_REQUEST;
            }
        },
        None => {
            eprintln!("[REJECTED] Missing X-Signature-256 header");
            return StatusCode::UNAUTHORIZED;
        }
    };

    if !verify_signature(&state.webhook_secret, &body, &signature) {
        eprintln!("[REJECTED] Invalid HMAC signature");
        return StatusCode::UNAUTHORIZED;
    }

    let event: WebhookEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("[ERROR] Failed to parse webhook payload: {err}");
            return StatusCode::BAD_REQUEST;
        }
    };

    match &event {
        WebhookEvent::PaymentDetected(payment) => {
            println!("=== PAYMENT DETECTED ({}) ===", payment.chain);
            println!("  TxID:           {}", payment.txid);
            println!("  Address:        {}", payment.address);
            println!("  User ID:        {:?}", payment.user_id);
            println!("  Amount:         {}", payment.amount_coin);
            println!("  Base units:     {}", payment.amount_sat);
            println!("  Confirmations:  {}", payment.confirmations);
            println!("  Block height:   {:?}", payment.block_height);
            println!("  Memo:           {:?}", payment.memo);
            println!();
        }
        WebhookEvent::PaymentCredited(payment) => {
            println!("=== PAYMENT CREDITED ({}) ===", payment.chain);
            println!("  TxID:           {}", payment.txid);
            println!("  Address:        {}", payment.address);
            println!("  User ID:        {:?}", payment.user_id);
            println!("  Amount:         {}", payment.amount_coin);
            println!("  Base units:     {}", payment.amount_sat);
            println!("  Confirmations:  {}", payment.confirmations);
            println!("  Block height:   {:?}", payment.block_height);
            println!("  Index:          {}", payment.derivation_index);
            println!("  Memo:           {:?}", payment.memo);
            println!("  Swept To:       {:?}", payment.swept_to_address);
            println!("  Swept Amount:   {:?}", payment.swept_amount_coin);
            println!("  Sweep TxID:     {:?}", payment.sweep_txid);
            if let Some(price) = payment.coin_price {
                println!(
                    "  {} price:    {:.2} {}",
                    payment.chain,
                    price,
                    payment.fiat_currency.as_deref().unwrap_or("?")
                );
            }
            if let Some(fiat) = payment.fiat_amount {
                println!(
                    "  Fiat value:     {:.2} {}",
                    fiat,
                    payment.fiat_currency.as_deref().unwrap_or("?")
                );
            }
            println!();
        }
    }

    StatusCode::OK
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let secret = std::env::var("WEBHOOK_SECRET").expect("WEBHOOK_SECRET env var required");

    let state = AppState {
        webhook_secret: secret,
    };

    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(state);

    let bind = "0.0.0.0:8080";
    println!("Webhook server listening on http://{bind}/webhook");

    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
