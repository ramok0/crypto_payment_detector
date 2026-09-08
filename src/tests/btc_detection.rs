use super::*;
use crate::test_support::mock_server;
use axum::{Json, http::StatusCode};
use bitcoin::{
    Amount, TxOut,
    bip32::{Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use serde_json::{Value, json};

fn detector(dir: &tempfile::TempDir, chain: Chain, webhook: &str) -> ChainDetector {
    let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[7; 32]).unwrap();
    let detector = ChainDetector::new(DetectorConfig {
        chain,
        xpub: Xpub::from_priv(&Secp256k1::new(), &master).to_string(),
        webhook_url: webhook.into(),
        webhook_hmac_secret: "test".into(),
        state_file: dir.path().join("state.json").to_str().unwrap().into(),
        min_confirmations: 3,
        ..DetectorConfig::default()
    })
    .unwrap();
    detector.price_fetcher.seed_test_price(100.0);
    detector
}

fn batched_payments(detector: &ChainDetector) -> Vec<DetectedPayment> {
    let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
    let script = |index| {
        derive_address(&detector.config.xpub, index, Chain::Bitcoin)
            .unwrap()
            .parse::<bitcoin::Address<_>>()
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap()
            .script_pubkey()
    };
    block.txdata[0].output = vec![
        TxOut {
            value: Amount::from_sat(100),
            script_pubkey: script(0),
        },
        TxOut {
            value: Amount::from_sat(200),
            script_pubkey: script(0),
        },
        TxOut {
            value: Amount::from_sat(400),
            script_pubkey: script(1),
        },
    ];
    detector.scan_raw_block_parallel(&block, &detector.build_address_lookup(1).unwrap(), 100, 100)
}

#[test]
fn batched_outputs_are_summed_per_recipient_on_btc_and_ltc() {
    for chain in [Chain::Bitcoin, Chain::Litecoin] {
        let dir = tempfile::tempdir().unwrap();
        let detector = detector(&dir, chain, "http://127.0.0.1:1");
        let payments = batched_payments(&detector);
        assert_eq!(payments.len(), 2);
        let mut amounts: Vec<_> = payments.iter().map(|p| p.amount_sat).collect();
        amounts.sort();
        assert_eq!(amounts, vec![300, 400]);
        assert_ne!(payments[0].event_id, payments[1].event_id);
        assert_eq!(payments[0].txid, payments[1].txid);
    }
}

#[test]
fn restart_restores_pending_credits_and_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let first = detector(&dir, Chain::Bitcoin, "http://127.0.0.1:1");
    let payments = batched_payments(&first);
    first.enqueue_or_confirm(payments.clone()).unwrap();
    first.state.lock().unwrap().last_scanned_height = Some(100);
    first.persist_state().unwrap();
    drop(first);
    let restarted = detector(&dir, Chain::Bitcoin, "http://127.0.0.1:1");
    restarted.enqueue_or_confirm(payments).unwrap();
    let state = restarted.state.lock().unwrap();
    assert_eq!(state.last_scanned_height, Some(100));
    assert_eq!(state.pending.len(), 2);
    assert!(state.pending.iter().all(|p| !p.detected_notified));
}

#[tokio::test]
async fn concurrent_confirmation_and_restart_emit_one_credit_per_recipient() {
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = events.clone();
    let server = mock_server(move |body| {
        log.lock().unwrap().push(body);
        async { (StatusCode::OK, Json(json!({}))) }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let first = detector(&dir, Chain::Bitcoin, &server.url);
    let payments = batched_payments(&first);
    first.enqueue_or_confirm(payments.clone()).unwrap();
    // A deposit with one confirmation only sends payment_detected.
    first.process_confirmed(100).await.unwrap();
    assert_eq!(events.lock().unwrap().len(), 2);
    let (a, b) = tokio::join!(first.process_confirmed(102), first.process_confirmed(102));
    a.unwrap();
    b.unwrap();
    assert_eq!(events.lock().unwrap().len(), 4);
    assert!(first.state.lock().unwrap().pending.is_empty());
    drop(first);
    let restarted = detector(&dir, Chain::Bitcoin, &server.url);
    restarted.enqueue_or_confirm(payments).unwrap();
    restarted.process_confirmed(103).await.unwrap();
    assert_eq!(events.lock().unwrap().len(), 4);
    let events = events.lock().unwrap();
    for event in events.iter().filter(|e| e["event"] == "payment_credited") {
        assert!(event["data"]["event_id"].is_string());
        assert_eq!(event["data"]["confirmations"], 3);
    }
}

#[tokio::test]
async fn rejected_webhook_remains_pending_without_blocking_other_recipient() {
    let server = mock_server(|body| async move {
        let status = if body["data"]["derivation_index"] == 0 {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::OK
        };
        (status, Json(json!({})))
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let detector = detector(&dir, Chain::Bitcoin, &server.url);
    detector
        .enqueue_or_confirm(batched_payments(&detector))
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        detector.process_confirmed(102),
    )
    .await
    .unwrap()
    .unwrap();
    let state = crate::persistence::load_state(&detector.config.state_file).unwrap();
    assert_eq!(state.pending.len(), 1);
    assert_eq!(state.pending[0].payment.derivation_index, 0);
    assert_eq!(state.notified_confirmed.len(), 1);
}

#[test]
fn legacy_cursor_only_state_loads_without_resetting_height() {
    let state: PersistedState =
        serde_json::from_str(r#"{"last_scanned_height":100,"known_block_hashes":{}}"#).unwrap();
    assert_eq!(state.last_scanned_height, Some(100));
    assert!(state.pending.is_empty());
}

#[tokio::test]
async fn legacy_credited_txid_is_not_credited_again_after_upgrade() {
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = events.clone();
    let server = mock_server(move |body| {
        log.lock().unwrap().push(body);
        async { (StatusCode::OK, Json(json!({}))) }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let first = detector(&dir, Chain::Bitcoin, &server.url);
    let payments = batched_payments(&first);
    let legacy = json!({
        "last_scanned_height": 100,
        "known_block_hashes": {},
        "notified_confirmed": [payments[0].txid],
        "pending": [{"payment": payments[0], "block_height":100}]
    });
    std::fs::write(
        &first.config.state_file,
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();
    drop(first);
    let restarted = detector(&dir, Chain::Bitcoin, &server.url);
    restarted.enqueue_or_confirm(payments).unwrap();
    restarted.process_confirmed(103).await.unwrap();
    assert!(events.lock().unwrap().is_empty());
    assert!(restarted.state.lock().unwrap().pending.is_empty());
}
