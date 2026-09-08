use super::*;
use crate::solana_pool::shared_wallets;
use crate::test_support::{mock_server, rpc_error, rpc_ok};
use axum::{Json, http::StatusCode};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

fn detector(
    dir: &tempfile::TempDir,
    rpc: &str,
    webhook: &str,
) -> (SolanaDetector, SolanaReservation) {
    let keypair = Arc::new(Keypair::new());
    let address = keypair.pubkey().to_string();
    let detector = SolanaDetector::new(
        SolanaConfig {
            rpc_url: rpc.into(),
            wallet_pool_file: "unused.json".into(),
            secure_deposit_address: Pubkey::new_unique().to_string(),
            webhook_url: webhook.into(),
            webhook_hmac_secret: "test".into(),
            redis_url: "redis://127.0.0.1:1/".into(),
            reservation_ttl_secs: 0,
            state_file: dir.path().join("state.json").to_str().unwrap().into(),
            poll_interval_secs: 1,
            min_confirmations: 2,
            fiat_currency: "EUR".into(),
            proxy_url: None,
            max_retries: 1,
            retry_base_delay_ms: 1,
            min_deposit_fiat: 0.0,
            gas_tank_private_key: None,
            gas_tank_target_usd: 0.0,
            gas_tank_check_interval_secs: 900,
            max_fee_ratio: 0.1,
            core_api_url: None,
            internal_service_token: None,
        },
        vec![],
        shared_wallets(vec![ManagedSolanaWallet {
            index: 0,
            address: address.clone(),
            keypair,
        }]),
    )
    .unwrap();
    detector.price_fetcher.seed_test_price(100.0);
    let reservation = SolanaReservation {
        user_id: "0".into(),
        address,
        wallet_index: 0,
        reserved_at_unix: 0,
        expires_at_unix: 0,
        dormant: false,
    };
    (detector, reservation)
}

fn native_tx(owner: &str) -> Value {
    json!({"slot":100, "meta":{"err":null,"preBalances":[0],"postBalances":[10000]},
        "transaction":{"message":{"accountKeys":[owner]}}})
}

fn token_tx(owner: &str, ata: &str, mint: &str) -> Value {
    json!({"slot":100, "meta":{"err":null,"preBalances":[0],"postBalances":[0],
        "preTokenBalances":[],"postTokenBalances":[{"accountIndex":0,"mint":mint,"owner":owner,"uiTokenAmount":{"amount":"42000000"}}]},
        "transaction":{"message":{"accountKeys":[ata]}}})
}

#[tokio::test]
async fn cash_push_addresses_and_detection_use_token_2022_ata_and_usd_peg() {
    let dir = tempfile::tempdir().unwrap();
    let payload = Arc::new(Mutex::new(Value::Null));
    let value = payload.clone();
    let watched = Arc::new(Mutex::new(String::new()));
    let expected = watched.clone();
    let server = mock_server(move |request| {
        let (value, expected) = (value.clone(), expected.clone());
        async move {
            match request["method"].as_str().unwrap() {
                "getSignaturesForAddress" => {
                    assert_eq!(request["params"][0], *expected.lock().unwrap());
                    rpc_ok(&request, json!([{"signature":"cash-deposit"}]))
                }
                "getTransaction" => rpc_ok(&request, value.lock().unwrap().clone()),
                method => panic!("Unexpected RPC {method}"),
            }
        }
    })
    .await;
    let (mut detector, reservation) = detector(&dir, &server.url, &server.url);
    let cash = crate::solana_tokens::default_spl_tokens().remove(1);
    detector.tokens = vec![cash.clone()];
    let owner = Pubkey::from_str(&reservation.address).unwrap();
    let ata = detector.ata_for_wallet(&owner, &cash.mint).to_string();
    *watched.lock().unwrap() = ata.clone();
    *payload.lock().unwrap() = token_tx(&reservation.address, &ata, &cash.mint.to_string());
    assert!(detector.webhook_address_set().contains(&ata));
    let quicknode = json!({"data":[{"transaction":{"message":{"accountKeys":[{"pubkey":ata}]}}}]});
    assert!(crate::helius_webhooks::collect_candidate_addresses(&quicknode).contains(&ata));
    detector
        .process_token_for_reservation(&reservation, &owner, &cash, 102)
        .await
        .unwrap();
    detector
        .process_token_for_reservation(&reservation, &owner, &cash, 102)
        .await
        .unwrap();
    let state = detector.state.lock().unwrap();
    assert_eq!(state.pending.len(), 1);
    assert_eq!(state.pending[0].signature, "cash-deposit");
    assert_eq!(token_peg_currency("CASH"), Some("USD"));
}

#[tokio::test]
async fn unavailable_transaction_stops_cursor_before_the_gap_for_native_and_spl() {
    for spl in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let tx_payload = Arc::new(Mutex::new(Value::Null));
        let fail_oldest = Arc::new(AtomicBool::new(true));
        let requested = Arc::new(Mutex::new(Vec::<String>::new()));
        let (payload, fail, calls) = (tx_payload.clone(), fail_oldest.clone(), requested.clone());
        let server = mock_server(move |request| {
            let (payload, fail, calls) = (payload.clone(), fail.clone(), calls.clone());
            async move {
                match request["method"].as_str().unwrap() {
                    "getSignaturesForAddress" => rpc_ok(
                        &request,
                        json!([{"signature":"B"},{"signature":"A"},{"signature":"C"}]),
                    ),
                    "getTransaction" => {
                        let sig = request["params"][0].as_str().unwrap();
                        calls.lock().unwrap().push(sig.into());
                        if sig == "A" && fail.load(Ordering::SeqCst) {
                            rpc_error(&request, "temporarily unavailable")
                        } else {
                            rpc_ok(&request, payload.lock().unwrap().clone())
                        }
                    }
                    method => panic!("Unexpected RPC {method}"),
                }
            }
        })
        .await;
        let (detector, reservation) = detector(&dir, &server.url, &server.url);
        let owner = Pubkey::from_str(&reservation.address).unwrap();
        let token = SplTokenConfig {
            symbol: "USDC".into(),
            mint: Pubkey::new_unique(),
            decimals: 6,
        };
        let ata = detector.ata_for_wallet(&owner, &token.mint).to_string();
        let watched = if spl {
            ata.as_str()
        } else {
            reservation.address.as_str()
        };
        *tx_payload.lock().unwrap() = if spl {
            token_tx(&reservation.address, &ata, &token.mint.to_string())
        } else {
            native_tx(&reservation.address)
        };
        detector
            .update_last_processed_signature(watched, "C")
            .unwrap();
        let first = if spl {
            detector
                .process_token_for_reservation(&reservation, &owner, &token, 102)
                .await
        } else {
            detector
                .process_native_for_reservation(&reservation, 102, None)
                .await
        };
        assert!(first.is_err());
        assert_eq!(requested.lock().unwrap().as_slice(), &["A"]);
        assert_eq!(
            detector.state.lock().unwrap().addresses[watched]
                .last_processed_signature
                .as_deref(),
            Some("C")
        );
        fail_oldest.store(false, Ordering::SeqCst);
        if spl {
            detector
                .process_token_for_reservation(&reservation, &owner, &token, 102)
                .await
                .unwrap();
        } else {
            detector
                .process_native_for_reservation(&reservation, 102, None)
                .await
                .unwrap();
        }
        let state: SolanaState =
            crate::persistence::load_json_state(&detector.config.state_file).unwrap();
        assert_eq!(state.pending.len(), 2);
        assert_eq!(
            state.addresses[watched].last_processed_signature.as_deref(),
            Some("B")
        );
        assert_eq!(state.pending[0].signature, "A");
        assert_eq!(state.pending[1].signature, "B");
    }
}

#[tokio::test]
async fn recovering_a_later_payment_never_changes_scan_cursors() {
    let dir = tempfile::tempdir().unwrap();
    let (detector, reservation) = detector(&dir, "http://127.0.0.1:1", "http://127.0.0.1:1");
    let tx: RpcTransactionResult = serde_json::from_value(native_tx(&reservation.address)).unwrap();
    let token = SplTokenConfig {
        symbol: "USDC".into(),
        mint: Pubkey::new_unique(),
        decimals: 6,
    };
    let owner = Pubkey::from_str(&reservation.address).unwrap();
    let ata = detector.ata_for_wallet(&owner, &token.mint).to_string();
    for address in [&reservation.address, &ata] {
        detector
            .update_last_processed_signature(address, "C")
            .unwrap();
    }
    detector
        .enqueue_recovered_native(&reservation, "B", &tx, 10000)
        .await
        .unwrap();
    detector
        .enqueue_recovered_token(&reservation, "B", &tx, &token, 42000000)
        .await
        .unwrap();
    // Retrying recovery also cannot duplicate the queued payment.
    detector
        .enqueue_recovered_native(&reservation, "B", &tx, 10000)
        .await
        .unwrap();
    let state: SolanaState =
        crate::persistence::load_json_state(&detector.config.state_file).unwrap();
    assert_eq!(state.pending.len(), 2);
    for address in [&reservation.address, &ata] {
        assert_eq!(
            state.addresses[address].last_processed_signature.as_deref(),
            Some("C")
        );
    }
}

#[tokio::test]
async fn simultaneous_confirmation_ticks_emit_one_detected_and_one_credited() {
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let seen = events.clone();
    let server = mock_server(move |request| {
        let seen = seen.clone();
        async move {
            if request.get("event").is_some() {
                seen.lock().unwrap().push(request);
                tokio::time::sleep(Duration::from_millis(20)).await;
                return (StatusCode::OK, Json(json!({})));
            }
            assert_eq!(request["method"], "getBalance");
            rpc_ok(&request, json!({"value":0}))
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (detector, reservation) = detector(&dir, &server.url, &server.url);
    let tx: RpcTransactionResult = serde_json::from_value(native_tx(&reservation.address)).unwrap();
    detector
        .enqueue_recovered_native(&reservation, "B", &tx, 10000)
        .await
        .unwrap();
    let (a, b) = tokio::join!(detector.process_credits(102), detector.process_credits(102));
    a.unwrap();
    b.unwrap();
    let state: SolanaState =
        crate::persistence::load_json_state(&detector.config.state_file).unwrap();
    assert!(state.pending.is_empty());
    assert_eq!(state.credited_payments.len(), 1);
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "payment_detected");
    assert_eq!(events[1]["event"], "payment_credited");
    assert_eq!(events[0]["data"]["event_id"], events[1]["data"]["event_id"]);
}

#[tokio::test]
async fn different_addresses_scan_concurrently_but_same_address_is_serialized() {
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (active, maximum) = (inflight.clone(), peak.clone());
    let server = mock_server(move |request| {
        let (active, maximum) = (active.clone(), maximum.clone());
        async move {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(count, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(30)).await;
            active.fetch_sub(1, Ordering::SeqCst);
            rpc_ok(&request, json!([]))
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (mut detector, reservation) = detector(&dir, &server.url, &server.url);
    detector.scan_concurrency = 2;
    let reservations: Vec<_> = (0..4)
        .map(|_| SolanaReservation {
            address: Pubkey::new_unique().to_string(),
            ..reservation.clone()
        })
        .collect();
    assert_eq!(
        detector.scan_reservations(&reservations, 100, None).await,
        0
    );
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    peak.store(0, Ordering::SeqCst);
    let (a, b) = tokio::join!(
        detector.process_reservation(&reservation, 100, None),
        detector.process_reservation(&reservation, 100, None)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(peak.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_transaction_metadata_is_retryable_instead_of_zero_deposit() {
    let server = mock_server(|request| async move {
        let mut tx = native_tx("owner");
        tx["meta"] = Value::Null;
        rpc_ok(&request, tx)
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (detector, _) = detector(&dir, &server.url, &server.url);
    assert!(detector.get_transaction("A").await.is_err());
}

#[test]
fn token_delta_uses_exact_ata_among_multiple_accounts_of_same_owner() {
    let mut tx = token_tx("owner", "ata", "mint");
    tx["transaction"]["message"]["accountKeys"] = json!(["other", "ata"]);
    tx["meta"]["postTokenBalances"][0]["accountIndex"] = json!(1);
    let unrelated =
        json!({"accountIndex":0,"mint":"mint","owner":"owner","uiTokenAmount":{"amount":"7"}});
    tx["meta"]["postTokenBalances"]
        .as_array_mut()
        .unwrap()
        .insert(0, unrelated);
    let tx = serde_json::from_value(tx).unwrap();
    assert_eq!(
        SolanaDetector::extract_positive_token_amount(&tx, "owner", "mint", "ata"),
        Some(42000000)
    );
}

#[test]
fn corrupt_state_is_not_silently_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, "{broken").unwrap();
    assert!(load_solana_state(path.to_str().unwrap()).is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "{broken");
}
