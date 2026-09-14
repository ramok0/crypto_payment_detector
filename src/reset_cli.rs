//! Offline only: never expose this operation on the public detector HTTP API.
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("crypto-reset-v1");
        return;
    }
    if args.len() != 3 || args[0] != "--replace-wallets" {
        eprintln!(
            "Usage: crypto_payment_reset --replace-wallets ETH|SOL|BASE|BTC|LTC|ALL OPERATION_ID"
        );
        std::process::exit(2);
    }
    dotenvy::dotenv().ok();
    crypto_payment_detector::remote_config::bootstrap().await;
    if crypto_payment_detector::reset::execute(&args[1], &args[2])
        .await
        .is_err()
    {
        // Errors from Redis/config/providers may contain sensitive information.
        eprintln!(
            "Reset failed. Keep detector stopped; inspect the protected reset archive and retry the SAME operation ID."
        );
        std::process::exit(1);
    }
    println!(
        "Reset complete; previous wallets and assignments archived, new deposit wallets active."
    );
}
