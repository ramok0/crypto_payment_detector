//! Opt-in integration test. Use ONLY a disposable local Redis, never application Redis.
use axum::{Json, Router, routing::post};
use fs2::FileExt;
use redis::AsyncCommands;
use serde_json::{Value, json};
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[tokio::test]
#[ignore = "requires disposable Redis at 127.0.0.1:16379 (database 15)"]
async fn offline_reset_archives_rotates_isolates_and_retries_without_losing_new_payments() {
    let redis_url = "redis://127.0.0.1:16379/15";
    let mut conn = redis::Client::open(redis_url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let size: usize = redis::cmd("DBSIZE").query_async(&mut conn).await.unwrap();
    assert_eq!(size, 0, "Test requires an EMPTY disposable Redis database");
    let dir = tempfile::tempdir().unwrap();
    let wallet_file = dir.path().join("eth-wallets.json");
    crypto_payment_detector::load_ethereum_wallet_pool(
        crypto_payment_detector::Chain::Ethereum,
        wallet_file.to_str().unwrap(),
    )
    .unwrap();
    let old_wallets = fs::read(&wallet_file).unwrap();
    fs::write(dir.path().join("eth-state.json"), b"old detector history").unwrap();
    fs::write(dir.path().join("base-state.json"), b"keep base").unwrap();
    for (key, value) in [
        ("ethereum:assignment:old", "old owner"),
        ("base:assignment:keep", "base owner"),
        ("solana:assignment:keep", "sol owner"),
        ("autoshop:balance:1", "12345"),
    ] {
        let _: () = conn.set(key, value).await.unwrap();
    }
    let _: () = conn
        .set_ex("ethereum:reservation:legacy", "legacy owner", 300)
        .await
        .unwrap();
    let available = Arc::new(AtomicBool::new(false));
    let flag = available.clone();
    let app = Router::new().route(
        "/",
        post(move || {
            let flag = flag.clone();
            async move {
                Json(if flag.load(Ordering::SeqCst) {
                    json!({"jsonrpc":"2.0","id":1,"result":"0x1234"})
                } else {
                    json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"offline"}})
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let id = "012345abcdef";
    let run = || {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_crypto_payment_reset"));
        cmd.current_dir(dir.path())
            .env_clear()
            .env("ETH_GAS_TANK_PRIVATE_KEY", "01".repeat(32))
            .env(
                "ETH_LEDGER_ADDRESS",
                "0x0000000000000000000000000000000000000001",
            )
            .env("ETH_WALLET_POOL_FILE", &wallet_file)
            .env("ETH_STATE_FILE", "eth-state.json")
            .env("ETH_RPC_URL", &rpc)
            .env("ETH_ETHERSCAN_ENABLED", "false")
            .env("REDIS_URL", redis_url)
            .env("WEBHOOK_URL", "http://127.0.0.1:1/no-webhooks-during-reset")
            .env("WEBHOOK_SECRET", "test-only")
            .args(["--replace-wallets", "ETH", id]);
        cmd
    };
    // A provider failure must leave every active file and assignment intact.
    assert!(!run().output().await.unwrap().status.success());
    assert_eq!(fs::read(&wallet_file).unwrap(), old_wallets);
    assert_eq!(
        fs::read(dir.path().join("eth-state.json")).unwrap(),
        b"old detector history"
    );
    assert!(
        conn.exists::<_, bool>("ethereum:assignment:old")
            .await
            .unwrap()
    );
    available.store(true, Ordering::SeqCst);
    // A separate live daemon holding the shared lock excludes the CLI process.
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join(".detector-maintenance/lock"))
        .unwrap();
    FileExt::lock_shared(&lock).unwrap();
    assert!(!run().output().await.unwrap().status.success());
    drop(lock);
    let result = run().output().await.unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_ne!(fs::read(&wallet_file).unwrap(), old_wallets);
    let old: Value = serde_json::from_slice(&old_wallets).unwrap();
    let new: Value = serde_json::from_slice(&fs::read(&wallet_file).unwrap()).unwrap();
    for wallet in new["wallets"].as_array().unwrap() {
        assert!(
            !old["wallets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["address"] == wallet["address"])
        );
    }
    let state: Value =
        serde_json::from_slice(&fs::read(dir.path().join("eth-state.json")).unwrap()).unwrap();
    assert_eq!(state["scan_cursors"]["native"], 0x1234);
    assert_eq!(state["pending"], json!([]));
    assert_eq!(state["credited_events"], json!([]));
    assert!(
        !conn
            .exists::<_, bool>("ethereum:assignment:old")
            .await
            .unwrap()
    );
    assert!(
        !conn
            .exists::<_, bool>("ethereum:reservation:legacy")
            .await
            .unwrap()
    );
    for key in [
        "base:assignment:keep",
        "solana:assignment:keep",
        "autoshop:balance:1",
    ] {
        assert!(conn.exists::<_, bool>(key).await.unwrap());
    }
    assert_eq!(
        fs::read(dir.path().join("base-state.json")).unwrap(),
        b"keep base"
    );
    let archive: Value = serde_json::from_slice(
        &fs::read(
            dir.path()
                .join(format!(".detector-maintenance/archives/{id}/archive.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(archive["redis"][0]["keys"].as_array().unwrap().len(), 2);
    assert!(archive["files"].as_array().unwrap().iter().any(|f| {
        serde_json::from_value::<Option<Vec<u8>>>(f["before"].clone())
            .unwrap()
            .as_deref()
            == Some(old_wallets.as_slice())
    }));
    let _: () = conn
        .set("ethereum:assignment:new", "new owner")
        .await
        .unwrap();
    fs::write(dir.path().join("eth-state.json"), b"new payments").unwrap();
    assert!(run().output().await.unwrap().status.success());
    assert_eq!(
        fs::read(dir.path().join("eth-state.json")).unwrap(),
        b"new payments"
    );
    assert!(
        conn.exists::<_, bool>("ethereum:assignment:new")
            .await
            .unwrap()
    );
    // Delete only this test's fixtures, never FLUSHDB/FLUSHALL.
    let _: usize = conn
        .del(&[
            "base:assignment:keep",
            "solana:assignment:keep",
            "autoshop:balance:1",
            "ethereum:assignment:new",
        ])
        .await
        .unwrap();
    server.abort();
}
