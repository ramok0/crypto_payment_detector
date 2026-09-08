use super::*;
use crate::ethereum_pool::{ManagedEthereumWallet, shared_ethereum_wallets};
use crate::test_support::{mock_server, rpc_error, rpc_ok};
use axum::{Json, http::StatusCode};
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "reads historical blocks and logs from live PublicNode; no transactions or webhooks are sent"]
async fn publicnode_archive_block_can_be_scanned_through_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let detector = detector(
        &dir,
        "https://ethereum-rpc.publicnode.com",
        "http://127.0.0.1:1",
        default_erc20_tokens(),
    );
    let block = 25_771_000;
    let receipts = detector.block_receipts(block).await.unwrap();
    assert!(!receipts.is_empty());
    let transfer_topic = H256::from_slice(&keccak256("Transfer(address,address,uint256)"));
    let log = receipts
        .iter()
        .flat_map(|r| r.logs.iter())
        .find(|log| {
            log.address == detector.tokens[0].contract
                && log.topics.len() == 3
                && log.topics[0] == transfer_topic
                && log.data.len() == 32
                && !U256::from_big_endian(&log.data).is_zero()
        })
        .expect("historical block contains a mainnet USDC transfer");
    let recipient = address_from_topic(log.topics[2]);
    let lookup = HashMap::from([(
        recipient,
        EthereumReservation {
            user_id: "read-only-probe".into(),
            address: format_address(recipient),
            wallet_index: 0,
            reserved_at_unix: 0,
            expires_at_unix: 0,
        },
    )]);
    let deposits = detector
        .scan_erc20_logs(block, block, block, &lookup)
        .await
        .unwrap();
    assert!(!deposits.is_empty());
    assert!(
        deposits
            .iter()
            .all(|p| p.block_number == block && p.amount > U256::zero())
    );
    assert!(detector.state.lock().unwrap().pending.is_empty());
}

fn managed_wallet(index: u32) -> ManagedEthereumWallet {
    let wallet: LocalWallet = format!("{:064x}", index + 2).parse().unwrap();
    ManagedEthereumWallet {
        index,
        address: format_address(wallet.address()),
        eth_address: wallet.address(),
        wallet: Arc::new(wallet),
    }
}

fn reservation(index: u32) -> EthereumReservation {
    EthereumReservation {
        user_id: index.to_string(),
        address: managed_wallet(index).address,
        wallet_index: index,
        reserved_at_unix: 0,
        expires_at_unix: 0,
    }
}

fn detector(
    dir: &tempfile::TempDir,
    rpc: &str,
    webhook: &str,
    tokens: Vec<Erc20TokenConfig>,
) -> EthereumDetector {
    let mut detector = EthereumDetector::new(
        EthereumConfig {
            chain: Chain::Ethereum,
            rpc_url: rpc.into(),
            chain_id: 1,
            wallet_pool_file: "unused.json".into(),
            gas_tank_private_key: format!("{:064x}", 1),
            ledger_address: format_address(Address::from_low_u64_be(9)),
            webhook_url: webhook.into(),
            webhook_hmac_secret: "test".into(),
            redis_url: "memory://evm-reservations".into(),
            reservation_ttl_secs: 3600,
            state_file: dir.path().join("state.json").to_str().unwrap().into(),
            poll_interval_secs: 1,
            min_confirmations: 1,
            fiat_currency: "EUR".into(),
            proxy_url: None,
            max_blocks_per_cycle: 10,
            start_block: Some(100),
            gas_tank_target_usd: 0.0,
            gas_tank_check_interval_secs: 900,
            token_transfer_gas_limit: 100_000,
            gas_top_up_multiplier: 1.2,
            max_fee_ratio: 0.1,
            rpc_min_request_interval_ms: 0,
            etherscan: None,
        },
        tokens,
        shared_ethereum_wallets(vec![managed_wallet(0), managed_wallet(1)]),
    )
    .unwrap();
    detector.read_providers = vec![detector.provider.clone()];
    detector.price_fetcher.seed_test_price(1000.0);
    detector.eth_usd_fetcher.seed_test_price(1100.0);
    detector
}

fn transaction(id: u64, index: u32) -> Transaction {
    Transaction {
        hash: H256::from_low_u64_be(id),
        from: Address::from_low_u64_be(7),
        to: Some(managed_wallet(index).eth_address),
        value: U256::from(100),
        block_number: Some(100.into()),
        block_hash: Some(H256::from_low_u64_be(100)),
        ..Default::default()
    }
}

fn receipt(id: u64, success: bool, logs: Vec<Log>) -> TransactionReceipt {
    TransactionReceipt {
        transaction_hash: H256::from_low_u64_be(id),
        block_number: Some(100.into()),
        block_hash: Some(H256::from_low_u64_be(100)),
        status: Some(U64::from(u64::from(success))),
        logs,
        ..Default::default()
    }
}

fn block() -> Block<Transaction> {
    Block {
        number: Some(100.into()),
        hash: Some(H256::from_low_u64_be(100)),
        transactions: vec![transaction(1, 0)],
        ..Default::default()
    }
}

fn token() -> Erc20TokenConfig {
    Erc20TokenConfig {
        symbol: "USDC".into(),
        contract: Address::from_low_u64_be(20),
        decimals: 6,
    }
}

fn transfer_log(index: u64) -> Log {
    let mut data = [0; 32];
    U256::from(42_000_000).to_big_endian(&mut data);
    Log {
        address: token().contract,
        topics: vec![
            H256::from_slice(&keccak256("Transfer(address,address,uint256)")),
            address_to_topic(Address::from_low_u64_be(7)),
            address_to_topic(managed_wallet(0).eth_address),
        ],
        data: Bytes::from(data.to_vec()),
        block_number: Some(100.into()),
        block_hash: Some(H256::from_low_u64_be(100)),
        transaction_hash: Some(H256::from_low_u64_be(1)),
        log_index: Some(index.into()),
        ..Default::default()
    }
}

fn block_response(request: &Value) -> Value {
    if request["params"][1] == true {
        json!(block())
    } else {
        let header: Block<H256> = Block {
            number: Some(100.into()),
            hash: Some(H256::from_low_u64_be(100)),
            transactions: vec![H256::from_low_u64_be(1)],
            ..Default::default()
        };
        json!(header)
    }
}

#[tokio::test]
async fn quicknode_wakeup_scans_all_wallets_and_tokens_on_ethereum_and_base_once() {
    for chain in [Chain::Ethereum, Chain::Base] {
        let events = Arc::new(Mutex::new(Vec::<Value>::new()));
        let seen = events.clone();
        let server = mock_server(move |request| {
            let seen = seen.clone();
            async move {
                if request.get("event").is_some() {
                    seen.lock().unwrap().push(request);
                    return (StatusCode::OK, Json(json!({})));
                }
                match request["method"].as_str().unwrap() {
                    "eth_chainId" => rpc_ok(
                        &request,
                        json!(if chain == Chain::Base {
                            "0x2105"
                        } else {
                            "0x1"
                        }),
                    ),
                    "eth_blockNumber" => rpc_ok(&request, json!("0x65")),
                    "eth_getBlockByNumber" => {
                        let mut block = block();
                        block.transactions.push(transaction(2, 1));
                        rpc_ok(&request, json!(block))
                    }
                    "eth_getTransactionReceipt" => {
                        let hash: H256 =
                            serde_json::from_value(request["params"][0].clone()).unwrap();
                        let id = hash.to_low_u64_be();
                        rpc_ok(
                            &request,
                            json!(receipt(
                                id,
                                true,
                                if id == 1 {
                                    vec![transfer_log(3)]
                                } else {
                                    vec![]
                                }
                            )),
                        )
                    }
                    "eth_getTransactionByHash" => {
                        let hash: H256 =
                            serde_json::from_value(request["params"][0].clone()).unwrap();
                        let id = hash.to_low_u64_be();
                        rpc_ok(&request, json!(transaction(id, id as u32 - 1)))
                    }
                    "eth_getLogs" => rpc_ok(&request, json!([transfer_log(3)])),
                    "eth_getBalance" => rpc_ok(&request, json!("0x0")),
                    "eth_gasPrice" => rpc_ok(&request, json!("0x3b9aca00")),
                    "eth_estimateGas" => rpc_ok(&request, json!("0x186a0")),
                    "eth_call" => rpc_ok(&request, json!(format!("0x{}", "0".repeat(64)))),
                    method => panic!("Unexpected RPC {method}"),
                }
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let mut detector = detector(&dir, &server.url, &server.url, vec![token()]);
        detector.config.chain = chain;
        detector.config.chain_id = if chain == Chain::Base { 8453 } else { 1 };
        detector.config.min_confirmations = 2;
        // Defer the token sweep so this detection test never submits transactions.
        detector.config.max_fee_ratio = 0.00001;
        for index in [0, 1] {
            crate::ethereum_pool::assign_ethereum_wallet_for_user(
                chain,
                &detector.config.redis_url,
                &detector.wallets,
                "unused.json",
                &format!("quicknode-{index}"),
            )
            .await
            .unwrap();
        }
        assert_eq!(detector.webhook_address_set().len(), 2);
        let (first, duplicate) = tokio::join!(
            detector.process_webhook_now(),
            detector.process_webhook_now()
        );
        first.unwrap();
        duplicate.unwrap();
        let credited: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event["event"] == "payment_credited")
            .cloned()
            .collect();
        assert_eq!(
            credited.len(),
            3,
            "two native transfers plus one ERC-20 transfer on {chain:?}"
        );
        assert_eq!(detector.state.lock().unwrap().credited_events.len(), 3);
        crate::ethereum_pool::delete_all_ethereum_assignments(chain, &detector.config.redis_url)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn archive_log_rejection_recovers_transfers_via_receipts() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = calls.clone();
    let server = mock_server(move |request| {
        seen.lock()
            .unwrap()
            .push(request["method"].as_str().unwrap().into());
        async move {
            match request["method"].as_str().unwrap() {
                "eth_chainId" => rpc_ok(&request, json!("0x1")),
                "eth_getBlockByNumber" => rpc_ok(&request, block_response(&request)),
                "eth_getTransactionReceipt" | "eth_getBlockReceipts" => {
                    let receipt = receipt(1, true, vec![transfer_log(3), transfer_log(4)]);
                    let result = if request["method"] == "eth_getBlockReceipts" {
                        json!([receipt])
                    } else {
                        json!(receipt)
                    };
                    rpc_ok(&request, result)
                }
                "eth_getLogs" => rpc_error(&request, "Archive requests require a personal token"),
                method => panic!("Unexpected RPC {method}"),
            }
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let detector = detector(&dir, &server.url, &server.url, vec![token()]);
    detector
        .scan_new_blocks(&[reservation(0)], 100, 100)
        .await
        .unwrap();
    let state = detector.state.lock().unwrap();
    assert_eq!(state.last_scanned_block, Some(100));
    assert_eq!(state.pending.len(), 3); // native + two separate ERC-20 logs
    let tokens: Vec<_> = state
        .pending
        .iter()
        .filter(|p| p.token_contract.is_some())
        .collect();
    assert_ne!(tokens[0].event_id, tokens[1].event_id);
    for (payment, index) in tokens.iter().zip([3, 4]) {
        let webhook = detector.pending_to_webhook(payment, 100, None, U256::from(42_000_000));
        assert_eq!(webhook.event_id.as_deref(), Some(payment.event_id.as_str()));
        assert_eq!(webhook.log_index, Some(index));
    }
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "eth_getBlockReceipts")
    );
}

#[tokio::test]
async fn token_rpc_failure_does_not_roll_back_native_progress() {
    let server = mock_server(|request| async move {
        match request["method"].as_str().unwrap() {
            "eth_chainId" => rpc_ok(&request, json!("0x1")),
            "eth_getBlockByNumber" => rpc_ok(&request, block_response(&request)),
            "eth_getTransactionReceipt" => rpc_ok(&request, json!(receipt(1, true, vec![]))),
            "eth_getLogs" => rpc_error(&request, "permanent log service failure"),
            method => panic!("Unexpected RPC {method}"),
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    // Simulate the old shared cursor from before the upgrade.
    std::fs::write(
        dir.path().join("state.json"),
        r#"{"last_scanned_block":99}"#,
    )
    .unwrap();
    let detector = detector(&dir, &server.url, &server.url, vec![token()]);
    assert!(
        detector
            .scan_new_blocks(&[reservation(0)], 100, 100)
            .await
            .is_err()
    );
    let state: EthereumState =
        crate::persistence::load_json_state(&detector.config.state_file).unwrap();
    assert_eq!(state.scan_cursors.as_ref().unwrap().native, Some(100));
    assert_eq!(state.scan_cursors.as_ref().unwrap().erc20, Some(99));
    assert_eq!(state.last_scanned_block, Some(99));
    assert_eq!(state.pending.len(), 1);
}

#[tokio::test]
async fn failed_native_transaction_is_never_enqueued() {
    let server = mock_server(|request| async move {
        match request["method"].as_str().unwrap() {
            "eth_chainId" => rpc_ok(&request, json!("0x1")),
            "eth_getBlockByNumber" => rpc_ok(&request, block_response(&request)),
            "eth_getTransactionReceipt" => rpc_ok(&request, json!(receipt(1, false, vec![]))),
            method => panic!("Unexpected RPC {method}"),
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let detector = detector(&dir, &server.url, &server.url, vec![]);
    detector
        .scan_new_blocks(&[reservation(0)], 100, 100)
        .await
        .unwrap();
    assert!(detector.state.lock().unwrap().pending.is_empty());
    assert_eq!(detector.state.lock().unwrap().last_scanned_block, Some(100));
}

#[tokio::test]
async fn null_block_or_receipt_keeps_native_cursor() {
    for null_block in [true, false] {
        let server = mock_server(move |request| async move {
            match request["method"].as_str().unwrap() {
                "eth_chainId" => rpc_ok(&request, json!("0x1")),
                "eth_getBlockByNumber" => rpc_ok(
                    &request,
                    if null_block {
                        Value::Null
                    } else {
                        block_response(&request)
                    },
                ),
                "eth_getTransactionReceipt" => rpc_ok(&request, Value::Null),
                method => panic!("Unexpected RPC {method}"),
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let detector = detector(&dir, &server.url, &server.url, vec![]);
        assert!(
            detector
                .scan_new_blocks(&[reservation(0)], 100, 100)
                .await
                .is_err()
        );
        assert_eq!(
            detector
                .state
                .lock()
                .unwrap()
                .scan_cursors
                .as_ref()
                .unwrap()
                .native,
            None
        );
        assert!(detector.state.lock().unwrap().pending.is_empty());
    }
}

#[tokio::test]
async fn unsupported_batch_receipts_use_individual_receipts_and_reject_partial_sets() {
    for partial in [false, true] {
        let server = mock_server(move |request| async move {
            match request["method"].as_str().unwrap() {
                "eth_chainId" => rpc_ok(&request, json!("0x1")),
                "eth_getBlockByNumber" => rpc_ok(&request, block_response(&request)),
                "eth_getBlockReceipts" if partial => rpc_ok(&request, json!([])),
                "eth_getBlockReceipts" => rpc_error(&request, "method not found"),
                "eth_getTransactionReceipt" => {
                    rpc_ok(&request, json!(receipt(1, true, vec![transfer_log(3)])))
                }
                method => panic!("Unexpected RPC {method}"),
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let detector = detector(&dir, &server.url, &server.url, vec![token()]);
        let result = detector.block_receipts(100).await;
        assert_eq!(result.is_err(), partial);
        if !partial {
            assert_eq!(result.unwrap()[0].logs.len(), 1);
        }
    }
}

#[tokio::test]
async fn failed_sweep_does_not_block_other_payments_or_duplicate_concurrent_credits() {
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let seen = events.clone();
    let server = mock_server(move |request| {
        let seen = seen.clone();
        async move {
            if request.get("event").is_some() {
                seen.lock().unwrap().push(request);
                tokio::time::sleep(Duration::from_millis(10)).await;
                return (StatusCode::OK, Json(json!({})));
            }
            match request["method"].as_str().unwrap() {
                "eth_chainId" => rpc_ok(&request, json!("0x1")),
                "eth_getTransactionReceipt" => {
                    let hash: H256 = serde_json::from_value(request["params"][0].clone()).unwrap();
                    rpc_ok(&request, json!(receipt(hash.to_low_u64_be(), true, vec![])))
                }
                "eth_getTransactionByHash" => {
                    let hash: H256 = serde_json::from_value(request["params"][0].clone()).unwrap();
                    rpc_ok(
                        &request,
                        json!(transaction(
                            hash.to_low_u64_be(),
                            hash.to_low_u64_be() as u32 - 1
                        )),
                    )
                }
                "eth_getBalance"
                    if request["params"][0] == format_address(managed_wallet(0).eth_address) =>
                {
                    rpc_error(&request, "bad wallet balance response")
                }
                "eth_getBalance" => rpc_ok(&request, json!("0x0")),
                method => panic!("Unexpected RPC {method}"),
            }
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let detector = detector(&dir, &server.url, &server.url, vec![]);
    for index in [0, 1] {
        let tx = transaction(index as u64 + 1, index);
        detector
            .emit_detected_and_enqueue(
                DetectedEthereumPayment {
                    event_id: format!("native:{:#x}:{}", tx.hash, reservation(index).address),
                    txid: format!("{:#x}", tx.hash),
                    block_number: 100,
                    amount: tx.value,
                    asset: "ETH".into(),
                    asset_decimals: 18,
                    token_contract: None,
                    reservation: reservation(index),
                },
                100,
            )
            .await
            .unwrap();
    }
    let (a, b) = tokio::join!(detector.process_credits(100), detector.process_credits(100));
    a.unwrap();
    b.unwrap();
    let state = detector.state.lock().unwrap();
    assert_eq!(state.pending.len(), 1);
    assert_eq!(state.pending[0].wallet_index, 0);
    assert_eq!(state.credited_events.len(), 1);
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e["event"] == "payment_credited")
            .count(),
        1
    );
}

#[tokio::test]
async fn read_failover_checks_chain_before_accepting_fallback_data() {
    let primary = mock_server(|request| async move {
        if request["method"] == "eth_chainId" {
            rpc_ok(&request, json!("0x1"))
        } else {
            rpc_error(&request, "Archive requests require a personal token")
        }
    })
    .await;
    for correct_chain in [true, false] {
        let fallback = mock_server(move |request| async move {
            if request["method"] == "eth_chainId" {
                rpc_ok(
                    &request,
                    json!(if correct_chain { "0x1" } else { "0x2105" }),
                )
            } else {
                rpc_ok(&request, json!([]))
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let mut detector = detector(&dir, &primary.url, &primary.url, vec![]);
        let mut config = detector.config.clone();
        config.rpc_url = fallback.url.clone();
        detector
            .read_providers
            .push(build_ethereum_provider(&config).unwrap());
        let result: Result<Vec<Log>, _> = detector.read_rpc("eth_getLogs", json!([{}])).await;
        assert_eq!(result.is_ok(), correct_chain);
    }
}

#[test]
fn receipt_and_token_defaults_are_strict() {
    assert!(!receipt_succeeded(&receipt(1, false, vec![])).unwrap());
    let mut incomplete = receipt(1, true, vec![]);
    incomplete.status = None;
    assert!(receipt_succeeded(&incomplete).is_err());
    let base = parse_erc20_tokens_for_chain(Chain::Base, None).unwrap();
    assert_eq!(base.len(), 1);
    assert_eq!(
        format_address(base[0].contract),
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    );
    assert_ne!(base[0].contract, default_erc20_tokens()[0].contract);
    assert!(is_retryable_rpc_error(&DetectorError::ApiError(
        "unexpected end of file".into()
    )));
    assert!(!is_retryable_rpc_error(&DetectorError::ApiError(
        "Archive requests require a personal token".into()
    )));
}

#[tokio::test]
async fn unavailable_primary_receipt_uses_fallback() {
    let primary = mock_server(|request| async move {
        if request["method"] == "eth_chainId" {
            rpc_ok(&request, json!("0x1"))
        } else {
            rpc_ok(&request, Value::Null)
        }
    })
    .await;
    let fallback = mock_server(|request| async move {
        if request["method"] == "eth_chainId" {
            rpc_ok(&request, json!("0x1"))
        } else {
            rpc_ok(&request, json!(receipt(1, true, vec![])))
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut detector = detector(&dir, &primary.url, &primary.url, vec![]);
    let mut config = detector.config.clone();
    config.rpc_url = fallback.url.clone();
    detector
        .read_providers
        .push(build_ethereum_provider(&config).unwrap());
    assert!(
        receipt_succeeded(
            &detector
                .transaction_receipt(H256::from_low_u64_be(1))
                .await
                .unwrap()
        )
        .unwrap()
    );
}

#[tokio::test]
async fn null_batch_receipts_retry_then_use_individual_receipts_if_needed() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for always_null in [false, true] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let server = mock_server(move |request| {
            let calls = calls.clone();
            async move {
                match request["method"].as_str().unwrap() {
                    "eth_chainId" => rpc_ok(&request, json!("0x1")),
                    "eth_getBlockByNumber" => rpc_ok(&request, block_response(&request)),
                    "eth_getBlockReceipts" => {
                        let attempt = calls.fetch_add(1, Ordering::SeqCst);
                        rpc_ok(
                            &request,
                            if always_null || attempt == 0 {
                                Value::Null
                            } else {
                                json!([receipt(1, true, vec![])])
                            },
                        )
                    }
                    "eth_getTransactionReceipt" => {
                        rpc_ok(&request, json!(receipt(1, true, vec![])))
                    }
                    method => panic!("Unexpected RPC {method}"),
                }
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let detector = detector(&dir, &server.url, &server.url, vec![]);
        assert_eq!(detector.block_receipts(100).await.unwrap().len(), 1);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            if always_null { 3 } else { 2 }
        );
    }
}

#[tokio::test]
async fn failed_transaction_in_legacy_pending_is_removed_without_credit() {
    let server = mock_server(|request| async move {
        assert!(
            request.get("event").is_none(),
            "No webhook should be sent for a reverted deposit"
        );
        if request["method"] == "eth_chainId" {
            rpc_ok(&request, json!("0x1"))
        } else {
            rpc_ok(&request, json!(receipt(1, false, vec![])))
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let detector = detector(&dir, &server.url, &server.url, vec![]);
    let tx = transaction(1, 0);
    let key = format!("native:{:#x}:{}", tx.hash, reservation(0).address);
    detector
        .emit_detected_and_enqueue(
            DetectedEthereumPayment {
                event_id: key.clone(),
                txid: format!("{:#x}", tx.hash),
                block_number: 100,
                amount: tx.value,
                asset: "ETH".into(),
                asset_decimals: 18,
                token_contract: None,
                reservation: reservation(0),
            },
            100,
        )
        .await
        .unwrap();
    detector.process_credits(102).await.unwrap();
    let state = detector.state.lock().unwrap();
    assert!(state.pending.is_empty());
    assert!(state.credited_events.is_empty());
    assert!(state.ignored_events.contains(&key));
}

#[tokio::test]
async fn etherscan_failure_for_one_address_keeps_other_internal_deposits() {
    use axum::{Router, extract::Query, routing::get};
    let app = Router::new().route(
        "/",
        get(|Query(params): Query<HashMap<String, String>>| async move {
            if params["address"] == reservation(0).address {
                Json(json!({"status":"0", "message":"NOTOK", "result":"temporary failure"}))
            } else {
                Json(json!({"status":"1", "message":"OK", "result":[{
                    "blockNumber":"100", "hash":format!("{:#x}", H256::from_low_u64_be(1)),
                    "from":format_address(Address::from_low_u64_be(7)), "to":reservation(1).address,
                    "value":"100", "traceId":"0_1", "type":"call", "isError":"0"
                }]}))
            }
        }),
    );
    let server = crate::test_support::serve(app).await;
    let dir = tempfile::tempdir().unwrap();
    let mut detector = detector(&dir, &server.url, &server.url, vec![]);
    detector.etherscan = Some(
        EtherscanClient::new(EtherscanConfig {
            api_key: "test".into(),
            base_url: server.url.clone(),
            chain_id: 1,
            timeout_secs: 2,
            min_request_interval_ms: 0,
        })
        .unwrap(),
    );
    let reservations = detector.reservation_lookup(&[reservation(0), reservation(1)]);
    assert!(
        detector
            .scan_internal_calls(100, 100, 100, &reservations)
            .await
            .is_err()
    );
    let state = detector.state.lock().unwrap();
    assert_eq!(state.pending.len(), 1);
    assert_eq!(state.pending[0].wallet_index, 1);
    assert!(state.pending[0].event_id.starts_with("internal:"));
}
