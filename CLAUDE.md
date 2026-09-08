# CLAUDE.md

Claude-targeted notes for this repo. Read this first before exploring source files.

## What this is

Multi-chain crypto payment detector + sweep service. Polls explorers/RPCs, detects deposits to managed addresses, emits HMAC-signed webhooks (`payment_detected` / `payment_credited`), and after N confirmations sweeps funds to a configured cold-storage destination.

Supported chains/assets:

| Chain    | Native | Tokens                  | Address model              |
| -------- | ------ | ----------------------- | -------------------------- |
| Bitcoin  | BTC    | —                       | xpub-derived BIP84 (P2WPKH) |
| Litecoin | LTC    | —                       | xpub-derived BIP84 (P2WPKH, `ltc1` HRP) |
| Solana   | SOL    | USDC + custom SPL tokens | Wallet pool (per-user reservation) + per-token ATA |
| Ethereum | ETH    | USDC, USDT, custom ERC20 | Wallet pool (per-user reservation) |
| Base     | ETH    | USDC, USDT, custom ERC20 | Same `EthereumDetector` parametrized over `Chain::Base`; runs side-by-side with Ethereum mainnet in the same process |

Two binaries:
- `crypto_payment_detector` ([src/main.rs](src/main.rs)) — detector loop
- `crypto_payment_api` ([src/api.rs](src/api.rs)) — axum HTTP API for `/derive`, `/health`, `/solana/reserve`, `/ethereum/reserve`, `/base/reserve`, etc.

## Module map

- [src/lib.rs](src/lib.rs) — module declarations + public re-exports. Update both module list and `pub use` when adding modules/types.
- [src/types.rs](src/types.rs) — `Chain` enum, `DetectorConfig`, `DetectedPayment`, `WebhookEvent`. The `Chain` enum is used everywhere; adding a new chain means touching it plus every match arm in `derivation.rs`, `pricing.rs`, `bitcoin_sweep.rs`, `main.rs`, `api.rs`, etc.
- [src/error.rs](src/error.rs) — `DetectorError`. Has `From<reqwest::Error>` and `From<serde_json::Error>`.
- [src/trait_def.rs](src/trait_def.rs) — `PaymentDetector` trait (RPIT-style async fns).
- [src/persistence.rs](src/persistence.rs) — atomic JSON state file (`tmp + rename`) for BTC/LTC.
- [src/derivation.rs](src/derivation.rs) — BTC/LTC `xpub` → P2WPKH address. Handles `Ltub`→`xpub` prefix conversion via custom base58check (the bitcoin crate doesn't natively know about Litecoin extended keys).
- [src/pricing.rs](src/pricing.rs) — Kraken price fetcher with 30s cache. One `PriceFetcher` per (chain, fiat) pair.
- [src/webhook.rs](src/webhook.rs) — HMAC-SHA256 signed JSON webhook with bounded retry; durable per-chain pending queues retry failed deliveries on subsequent cycles. Also Discord webhook helper.
- [src/env_utils.rs](src/env_utils.rs) — env helpers (`chain_env_var`, `proxy_env_var`, `redact_url_credentials`).

### Chain implementations

- [src/blockstream.rs](src/blockstream.rs) — `ChainDetector` for BTC/LTC. Block-scan loop, multi-explorer fallback (Esplora + Blockchair), reorg detection by per-height block-hash cache, parallel tx scan via Rayon, optional auto-sweep via `bitcoin_sweep`.
- [src/litecoin_block.rs](src/litecoin_block.rs) — MWEB-aware raw block deserializer for Litecoin (`deserialize_litecoin_block`). `blockstream.rs` dispatches to it for `Chain::Litecoin`; BTC keeps using `bitcoin::Block::consensus_decode`.
- [src/bitcoin_sweep.rs](src/bitcoin_sweep.rs) — BTC/LTC P2WPKH sweep: `Ltpv`→`xprv` conversion, BIP32 derive secret key at index, fetch UTXOs from Esplora, build+sign+broadcast tx. Only **P2WPKH bech32** destinations are supported.
- [src/solana.rs](src/solana.rs) — `SolanaDetector`. Reservation-based: each user reserves a wallet from a pool. Per cycle, scans signatures of (a) reserved owner address for SOL, (b) each `ATA(owner, mint)` for SPL tokens. Sweeps SOL using the managed wallet as fee payer; sweeps SPL tokens using the configured `SOLANA_FEE_PAYER_PRIVATE_KEY` as fee payer + the managed wallet as token-authority signer.
- [src/solana_pool.rs](src/solana_pool.rs) — Solana wallet pool loader + Redis-backed reservations + **auto-grow** when exhausted. The pool is a `SharedSolanaWallets = Arc<RwLock<Vec<ManagedSolanaWallet>>>` shared between the detector and the API. Wallet file format: `{"wallets": [{"address": "...", "private_key": "<base58 or [byte array]>"}]}`. When `reserve_wallet_for_user` finds no free wallet, it generates a new keypair, appends it to the pool file (atomic `tmp + rename`), pushes it into the in-memory `Vec` (so the detector sees it for sweeps), and reserves it. Bound by `SOLANA_MAX_POOL_SIZE` (default 10000) to prevent runaway growth.
- [src/solana_tokens.rs](src/solana_tokens.rs) — SPL token helpers: `parse_spl_tokens` (env config parser), `derive_associated_token_address` (`Pubkey::find_program_address` over `[owner, token_program, mint]`), `spl_transfer_checked_instruction` (manually built TransferChecked, instruction tag `12`). No `spl-token` crate dep — instructions built by hand.
- [src/ethereum.rs](src/ethereum.rs) — `EthereumDetector`. Per-block scan: `eth_getBlockByNumber` for native ETH transfers, `eth_getLogs` with Transfer topic + reserved-address topic2 for ERC-20s. Sweeps to a "gas tank" address; gas tank periodically forwards to the cold ledger and tops up managed wallets that need ETH for token transfers. Has its own ignored-events bookkeeping for self-initiated gas top-ups (so they don't get treated as user deposits). **Generic over `EthereumConfig.chain`**: serves both Ethereum mainnet (`Chain::Ethereum`, chain_id 1) and Base (`Chain::Base`, chain_id 8453). Same code path; the chain field drives the log prefix (`[ETH]` vs `[BASE]`), the Redis reservation namespace, the env var prefix used by the wallet pool helpers, and the `chain` field in webhook payloads.
- [src/ethereum_pool.rs](src/ethereum_pool.rs) — EVM wallet pool (Ethereum + Base). **Auto-creates missing pool file** with N random wallets controlled by `{ETH,BASE}_WALLET_POOL_SIZE` (default 10, max 10000). **Also auto-grows on exhaustion** when `reserve_ethereum_wallet_for_user` runs out of free wallets (capped at `{ETH,BASE}_MAX_POOL_SIZE`, default 10000). Pool is `SharedEthereumWallets = Arc<RwLock<Vec<ManagedEthereumWallet>>>` shared between detector and API. Supports either Redis or in-memory reservations (`{ETH,BASE}_RESERVATION_STORE=memory`); both paths grow the pool. **Redis namespace**: `ethereum:reservation:<addr>` for mainnet, `base:reservation:<addr>` for Base — distinct prefixes so both chains can share the same Redis instance without collisions. All public functions take a `Chain` parameter to disambiguate.

## Key design patterns

### Reservation flow (SOL, ETH)
1. Bot owns a pool of N wallets (private keys local).
2. User calls `POST /solana/reserve` or `POST /ethereum/reserve` with `{user_id, ttl_secs?}`. API picks an unreserved wallet, stores `{user_id, address, wallet_index, expiry}` in Redis (key `solana:reservation:<addr>` or `ethereum:reservation:<addr>`) with TTL.
3. Detector loop loads active reservations every cycle and only watches those addresses.
4. On confirmed deposit: webhook + sweep to secure destination; reservation key continues to exist until TTL.

**TTL resolution**: per-request `ttl_secs` (capped at `MAX_RESERVATION_TTL_SECS = 30 days` in [src/api.rs](src/api.rs)) → fall back to `SOLANA_RESERVATION_TTL_SECS` / `ETH_RESERVATION_TTL_SECS` env (default 3600s = 1h). Re-calling `/reserve` with the same `user_id` and a longer `ttl_secs` extends the existing reservation's Redis TTL; calling with shorter or equal TTL returns the existing reservation unchanged.

### BTC/LTC flow (no reservations)
- xpub-derived addresses (no per-user assignment in the bot — assignment is the caller's responsibility based on the `derivation_index` exposed by `/derive`).
- Block-by-block scan in `run_block_scan_loop`, reorg-aware via per-height block hash cache.
- Sweep is **opt-in**: only enabled if `BTC_XPRIV` + `BTC_SWEEP_DESTINATION` (or LTC equivalents) are both set. Without them the detector still works as a read-only payment monitor.

### Webhook flow
- Always emit `payment_detected` first (when seen in a block, before confirmation).
- After `min_confirmations` slots/blocks: sweep, then emit `payment_credited` with sweep result populated.
- `WebhookEvent` enum is `#[serde(tag = "event", content = "data")]` — wire format is `{"event": "payment_credited", "data": {...DetectedPayment}}`.
- HMAC sent in `X-Signature-256` header (lowercase hex).

### Fee guards (deferred sweeps)

Each chain has a `max_fee_ratio` config (default 0.10 = 10%). Before broadcasting a sweep, the detector checks whether the estimated fee would exceed `max_fee_ratio × swept_amount`. If yes, the sweep is **deferred** (returns `SweepResult { deferred: true }`), the entry stays in `pending`, and the detector retries on the next cycle. This protects against ETH gas spikes, BTC mempool storms, etc.

Per-chain env vars: `ETH_MAX_FEE_RATIO`, `SOLANA_MAX_FEE_RATIO` (or `SOL_MAX_FEE_RATIO`), `BTC_MAX_FEE_RATIO`, `LTC_MAX_FEE_RATIO`. Falls back to global `MAX_FEE_RATIO`. All default to 0.10.

The ratio compares **fee value** vs **swept value** in matching units:
- BTC/LTC native: `fee_sat / total_input_sat`
- ETH native: `fee_wei / balance_wei`
- ETH ERC-20 (USD-pegged tokens only): `fee_eth × eth_usd / token_amount` (since amount is already USD-pegged)
- SOL native: `fee_lamports / balance_lamports`
- SOL SPL (USD-pegged tokens only): `fee_sol × sol_usd / token_amount` — **excludes ATA creation rent** (that's a one-time bootstrap cost amortized over future sweeps; otherwise the first sweep ever would always defer)

Non-USD-pegged tokens skip the ratio check (no price source) — falls back to "sweep regardless" behavior. This is by design: weird tokens need manual operator review anyway.

### Fee management
- **BTC/LTC**: fixed fee rate from config (`BTC_SWEEP_FEE_RATE_SATS_PER_VB`, default 5). Sweep transaction is single-output P2WPKH→P2WPKH.
- **SOL native**: managed wallet pays its own fee out of the swept SOL. The remainder lands on the **gas tank** (`SOLANA_GAS_TANK_PRIVATE_KEY` pubkey) when set, otherwise on `SOLANA_DEPOSIT_ADDRESS` (cold).
- **SOL tokens**: fee payer = `SOLANA_GAS_TANK_PRIVATE_KEY` (must be a wallet **distinct from `SOLANA_DEPOSIT_ADDRESS`**, even though using the same key works it logs a warning). Token destination is always `ATA(SOLANA_DEPOSIT_ADDRESS, mint)` — tokens never accumulate on the gas tank.
- **SOL gas tank maintenance**: same pattern as ETH gas tank. Periodically (`SOLANA_GAS_TANK_INTERVAL_SECS`, default 900s), if the gas tank holds more than `SOLANA_GAS_TANK_TARGET_USD` (default $10), excess is swept to `SOLANA_DEPOSIT_ADDRESS`. If the balance is below target, a warning is logged (the operator must top up the gas tank manually).
- **SOL orphan sweep at startup**: `SolanaDetector::sweep_orphan_balances()` runs once when the detector starts (called by `run_solana_detector` in [src/main.rs](src/main.rs) and [src/api.rs](src/api.rs)). It iterates every wallet in the pool, **skips currently reserved addresses** (those returned by `load_active_reservations`), and sweeps any leftover SOL/SPL balance to the gas tank/cold ATA. This recovers funds stuck on wallets whose reservation expired before the deposit confirmed.
- **ETH orphan sweep at startup**: `EthereumDetector::sweep_orphan_balances()` mirrors the Solana behavior. Iterates every managed wallet, skips currently reserved addresses (case-insensitive comparison since ETH addresses are sometimes mixed-case), and sweeps both native ETH and each configured ERC-20 to the gas tank. Called by `run_ethereum_detector` in both binaries. Funds recovered land on the gas tank wallet (subject to the standard fee-ratio guard, so a sweep is deferred if gas is too expensive at startup).
- **ETH native**: managed wallet pays its own fee out of the swept ETH. Remainder lands on the **gas tank** (`ETH_GAS_TANK_PRIVATE_KEY` pubkey). Excess ETH on the gas tank above `ETH_GAS_TANK_TARGET_USD` is periodically swept to `ETH_LEDGER_ADDRESS`.
- **ETH ERC-20**: fee paid in ETH from the managed wallet (gas tank tops up the managed wallet first if it has insufficient ETH). The token transfer goes **directly to `ETH_LEDGER_ADDRESS`** — it never transits through the gas tank. This avoids paying gas twice (one tx instead of two). The gas tank holds only ETH for fees, never tokens. `sweep_gas_tank_tokens_to_ledger` remains as a defensive cleanup for legacy state but no new tokens accumulate there.

### State persistence
Each chain has its own JSON state file. **Every writer goes through `persistence::write_json_atomic`** — write to `.tmp`, `fsync`, `rename`, then `fsync` the parent directory. Plain `tmp + rename` only protects readers from a half-written file; without the fsync the rename can land on disk while the data behind it has not, leaving valid-but-truncated JSON after a power loss. This also covers the SOL/EVM **wallet pool files**, which hold the only copy of an auto-generated wallet's private key. Re-parses on startup; corrupt files log a warning and start fresh.

- BTC/LTC: `last_scanned_height` + `known_block_hashes` (for reorg detection) + `pending` payments waiting for confirmations + `notified_confirmed` (credited txids). The last two were in-memory only until they were added to `PersistedState`; a restart between detection and `min_confirmations` silently dropped the deposit, because `last_scanned_height` had already moved past its block and the scan never revisits it. On startup the persisted entries are **merged** into memory rather than assigned — `run_detector` re-enters `run_block_scan_loop` after a scan error, and there the in-memory state is newer than the file.

Each chain has its own JSON state file (atomic write via `.tmp + rename`). Re-parses on startup; corrupt files fail startup without resetting the credit ledger.

- BTC/LTC: `last_scanned_height`, `known_block_hashes`, pending payments including detection delivery status, and credited event IDs. Batched outputs are aggregated by transaction and recipient.
- SOL: per-address `last_processed_signature` cursor (works for both owner and ATA addresses), pending payments, credited signatures set.
- ETH: `last_scanned_block` (lowest completed source cursor), separate native/ERC-20/internal `scan_cursors`, pending payments with detection delivery status, `credited_events` set, `ignored_events` set (gas-tank-originated transfers), `gas_tank_last_maintenance_unix`.

## Adding a new SPL token

1. Set env: `SOLANA_SPL_TOKENS=USDC:<mint>:6,USDT:<mint>:6,...` (or `default` for USDC + Phantom CASH mainnet, or `none`/`off` to disable). CASH uses Token-2022; `token_program_for_mint` selects its program for ATA derivation and transfer instructions.
2. The detector will automatically derive the ATA for each managed wallet and start monitoring.
3. The destination ATA (= ATA of `SOLANA_DEPOSIT_ADDRESS` for that mint) **must already exist** before the first sweep. The detector does not create it.

Custom tokens use `token_peg_currency(symbol)` for fiat conversion:
- USD-pegged (`USDC|USDT|DAI|BUSD|TUSD|USDP|GUSD|PYUSD`): converted via `SOL/fiat ÷ SOL/USD`.
- EUR-pegged (`EURC|EURT|AGEUR|EURE|EUROE`): converted via `SOL/fiat ÷ SOL/EUR` (using `sol_eur_fetcher` / `eth_eur_fetcher`).
- Other symbols: no fiat enrichment, ratio guard skipped (sweep proceeds without check).

Adding a new peg currency: add the symbol to `is_xxx_pegged_token`, extend `token_peg_currency`, add a price fetcher in the detector struct, and extend `sol_peg_price` / `eth_peg_price` match. Kraken supports SOL/USD, SOL/EUR, ETH/USD, ETH/EUR out of the box; for other quote currencies update [src/pricing.rs](src/pricing.rs).

## Adding a new ERC-20 token

Set env: `ETH_ERC20_TOKENS=SYMBOL:0xcontract:decimals,...` (or `default`/`none`). Same USD-pegged logic via `is_usd_pegged_token`.

## Environment variables (frequently used)

Webhook + auth (required): `WEBHOOK_URL`, `WEBHOOK_SECRET`.

Chain selection: `CHAIN=bitcoin|litecoin|solana|ethereum|both|solbtc|all`.

BTC/LTC:
- `BTC_XPUB`, `LTC_XPUB` — read-only monitoring.
- `BTC_XPRIV`, `BTC_SWEEP_DESTINATION` (and LTC equivalents) — enables sweep.
- `BTC_SWEEP_FEE_RATE_SATS_PER_VB` (default 5), `BTC_SWEEP_MIN_SAT` (default 5_000).
- `BTC_MIN_CONFIRMATIONS`, `BTC_POLL_INTERVAL`, `BTC_STATE_FILE`.
- `EXPLORER_API_URLS` (per-chain via `BTC_EXPLORER_API_URLS`/`LTC_EXPLORER_API_URLS`) — comma-separated, tried in order with automatic fallback.
- `BLOCKCHAIR_API_KEY` — optional, appended as `?key=` to Blockchair URLs.

Solana:
- `SOLANA_RPC_URL`, `SOLANA_WALLET_POOL_FILE`, `SOLANA_DEPOSIT_ADDRESS` (cold/ledger destination).
- `SOLANA_SPL_TOKENS` (default = USDC + Phantom CASH mainnet).
- `SOLANA_GAS_TANK_PRIVATE_KEY` — gas tank wallet that pays SPL fees and absorbs SOL native sweeps. Should be distinct from the deposit address. Legacy alias `SOLANA_FEE_PAYER_PRIVATE_KEY` still works but is deprecated.
- `SOLANA_GAS_TANK_TARGET_USD` (default 10) — target balance kept on the gas tank; excess auto-forwarded to the ledger.
- `SOLANA_GAS_TANK_INTERVAL_SECS` (default 900) — how often to run gas tank maintenance.
- `REDIS_URL` — required.

Ethereum:
- `ETH_RPC_URL`, `ETH_CHAIN_ID`, `ETH_WALLET_POOL_FILE`, `ETH_GAS_TANK_PRIVATE_KEY`, `ETH_LEDGER_ADDRESS`.
- `ETH_ERC20_TOKENS` (default = USDC + USDT mainnet).
- `ETH_RESERVATION_STORE=memory` to skip Redis (the wallet pool file auto-creates if missing).
- `ETH_GAS_TANK_TARGET_USD` (default 20), `ETH_GAS_TANK_INTERVAL_SECS` (default 900).

Base (mirrors the Ethereum env vars, just swap `ETH_` → `BASE_`):
- `BASE_RPC_URL` (default `https://mainnet.base.org`), `BASE_CHAIN_ID` (default 8453), `BASE_WALLET_POOL_FILE`, `BASE_GAS_TANK_PRIVATE_KEY`, `BASE_LEDGER_ADDRESS`.
- `BASE_ERC20_TOKENS` ? defaults to Base USDC only (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, 6 decimals), via `parse_erc20_tokens_for_chain`. Configure additional tokens explicitly, or use `none` for ETH-only monitoring.
- `BASE_MIN_CONFIRMATIONS` (default 5 — Base finalizes faster than mainnet thanks to ~2s blocks).
- `BASE_POLL_INTERVAL` (default 30s, override if you want faster polling — Base's tip moves quickly).
- `BASE_RESERVATION_STORE=memory` to skip Redis on Base (independent of the Ethereum setting; both can be memory or both Redis).
- `BASE_STATE_FILE` (default `base_detector_state.json`).
- `BASE_RPC_MIN_REQUEST_INTERVAL_MS` (default 200) — client-side throttle. The public `mainnet.base.org` endpoint returns `-32016 over rate limit` under burst load (orphan sweep on a 10-wallet pool fires ~40 RPC calls back-to-back). 200ms ≈ 5 req/s is safe for the public endpoint; set to 0 with a paid Base RPC.
- `ETH_RPC_MIN_REQUEST_INTERVAL_MS` (default 0) — same knob for the Ethereum mainnet detector. Default 0 because operators typically use a paid Ethereum endpoint.
- `{ETH,BASE}_ETHERSCAN_ENABLED` (default `true`) — per-chain toggle for the Etherscan internal-tx scan. The free Etherscan plan returns `Free API access is not supported for this chain` on Base; setting `BASE_ETHERSCAN_ENABLED=false` skips the etherscan client for Base only while keeping it active on Ethereum mainnet. Disabling it loses Coinbase-style internal-CALL detection but the rest of the scan (`eth_getBlockByNumber` + `eth_getLogs`) is unaffected.
- `DISABLE_BASE` (default `false`) — full killswitch. When truthy (`1`/`true`/`yes`/`on`), `Chain::Base` is filtered out of the chain list in **both** binaries before any detector spawns: no scan loop, no orphan sweep, no gas-tank maintenance, no RPC calls to `BASE_RPC_URL`, no Etherscan calls. The `/base/reserve` and `/base/active` routes stay registered but return `400 "EVM address pool is not configured"` because `base_pool` is `None`. Useful when `mainnet.base.org` is rate-limiting too aggressively or when you want to ship the rest of the system without Base. Independent of `CHAIN` — `CHAIN=all` + `DISABLE_BASE=true` runs everything except Base.

To run both Ethereum mainnet and Base in the same process: `CHAIN=ethereum,base` (comma-separated list) or `CHAIN=all`. The Redis reservation namespace differs (`ethereum:reservation:` vs `base:reservation:`), state files differ, and pool files differ — the two detectors share nothing except the webhook config and the Etherscan API key.

Etherscan internal-tx scan (optional, enables detection of ETH deposits routed through contracts e.g. Coinbase withdrawals):
- `ETHERSCAN_API_KEY` — required to enable. Same key works for **both** Ethereum and Base (V2 multichain). Free tier (5 req/s, 100k req/day) is shared across both detectors when running side-by-side. The client never goes through a proxy: the API key already authenticates the request, and most public proxies are blocked by Etherscan's WAF.
- `ETHERSCAN_BASE_URL` (default `https://api.etherscan.io/v2/api`) — V2 multichain endpoint.
- `ETHERSCAN_CHAIN_ID` is **ignored** when an EVM detector configures Etherscan: each detector pins the etherscan client's `chain_id` to its own `EthereumConfig.chain_id` (1 for Ethereum mainnet, 8453 for Base). This way two detectors sharing the same `EthereumConfig::etherscan` template still hit the right per-chain endpoint.
- `ETHERSCAN_TIMEOUT_SECS` (default `15`).
- `ETHERSCAN_MIN_REQUEST_INTERVAL_MS` (default `334`) — minimum gap between requests, enforced client-side. 334ms ≈ 3 req/s, leaves headroom under the 5 req/s free-tier ceiling for retries and concurrent callers sharing the same key. Lower values risk HTTP 429.
- API budget: per cycle the detector makes one `txlistinternal` call **per reserved wallet** (server-side filter by address). At default `ETH_POLL_INTERVAL=30` and a pool of 10 wallets that's ~28k calls/day — well within the 100k/day free quota. The 3 req/s throttle means a 10-wallet pool takes ~3.3s of wall time per cycle just for Etherscan; pools larger than ~90 wallets won't fit a 30s cycle and need a longer interval (or a paid Etherscan tier).

## Build / test

```bash
cargo build              # compile lib + both bins
cargo test --lib         # unit tests (no network); some are gated with `#[ignore = "live API"]`
cargo run --bin crypto_payment_detector
cargo run --bin crypto_payment_api
```

Live tests in `blockstream.rs` are `#[ignore]`-gated — run with `cargo test --lib -- --ignored` only when intentional.

## Pitfalls / gotchas

- **Ltub/Ltpv conversion**: the `bitcoin` crate only understands `xpub`/`xprv` prefixes. Both [src/derivation.rs](src/derivation.rs) and [src/bitcoin_sweep.rs](src/bitcoin_sweep.rs) include hand-rolled base58check helpers to swap the version bytes. Don't try to use `Xpub::from_str` directly on an `Ltub...` string — it'll fail with a base58 error.
- **Litecoin blocks are not Bitcoin blocks (MWEB)**: since the MimbleWimble activation (block 2,257,920), essentially every Litecoin block ends with an integrating transaction (the "HogEx") whose serialization flag byte is `0x08` instead of the BIP144 `0x01`. `bitcoin::Block::consensus_decode` rejects it with `unsupported segwit version: 8`, which used to abort the LTC scan loop on **every** block — the detector never advanced past the tip it was at. Raw LTC blocks must go through [src/litecoin_block.rs](src/litecoin_block.rs), which frames the per-tx MWEB payload (between the witness stack and `nLockTime`; always the null `0x00` form inside a block) and ignores the optional block-level extension block appended after the tx vector (Blockchair serves it, litecoinspace strips it). MWEB **peg-outs are regular outputs of the HogEx**, so a user withdrawing from MWEB straight to a managed `ltc1...` address is only detected once the block parses — roughly 6% of blocks carry one. Live LTC tests must target a post-activation height; the pre-existing one is pinned to height 2,000,000, which is why this never showed up in tests.
- **LTC bech32**: addresses use `ltc1...` HRP. The detector derives via the bitcoin crate (which produces `bc1...`) and then re-encodes by stripping the witness program and applying the `ltc` HRP. The `bitcoin::Address::from_str` path won't accept `ltc1...` — use `bech32::segwit::decode` for parsing LTC addresses.
- **Solana SPL transfer detection**: `getSignaturesForAddress(owner)` does **not** return token transfer signatures because the owner pubkey isn't in the account_keys for SPL transfers — only the ATA is. The detector must scan the ATA address separately.
- **Solana SPL transfer destination ATA is auto-created**: the sweep tx prepends `CreateAssociatedTokenAccountIdempotent` (data=`[1]`, program=`ATokenGPv...`) before the `TransferChecked`. If the destination ATA already exists, the instruction is a no-op; otherwise the gas tank pays the rent (~0.002 SOL) and creates it. The instruction is implemented manually in [src/solana_tokens.rs](src/solana_tokens.rs) — no `spl-associated-token-account` crate dependency.
- **Ethereum gas-tank top-ups look like deposits**: a top-up from the gas tank to a managed wallet would otherwise be detected as a payment. The detector uses `is_native_gas_tank_top_up(from, to, gas_tank)` and an `ignored_events` set to filter these. When changing the gas-tank logic, preserve this behavior.
- **`eth_getBlockByNumber` misses internal CALLs**: native ETH sent through a contract (Coinbase withdrawals, Gnosis Safe, batchers) is invisible to the standard block scan because the top-level tx's `to` is the contract, not the user. The optional `ETHERSCAN_API_KEY` path in [src/etherscan.rs](src/etherscan.rs) (called from `EthereumDetector::scan_internal_calls`) closes that gap. Idempotency uses `event_id = "internal:{tx_hash}:{trace_id}:{address}"` — distinct from the `native:...` namespace so a top-level + internal pair on the same tx hash doesn't collide. Without `ETHERSCAN_API_KEY` the scan is a no-op and Coinbase-style deposits will be missed.
- **A dead detector task must not go unnoticed**: both binaries keep their detector tasks in a `tokio::task::JoinSet` and supervise it. The scan loops are infinite, so a task that *finishes* has panicked — the process logs which one and exits non-zero so the supervisor restarts cleanly, rather than serving `/reserve` while one chain quietly stops crediting. Two traps when touching this: dropping a `JoinSet` **aborts every task still in it**, so the supervisor must own it for as long as the tasks matter; and awaiting only one handle (the old `handles.remove(0).await`) leaves every other chain unwatched.
- **Locks are poison-tolerant**: state mutexes are taken via `lock_state()` (`unwrap_or_else(|e| e.into_inner())`), never `lock().unwrap()`. A single panic under the lock would otherwise poison it and make every later lock panic too — turning one bad cycle into a permanently dead detector. The guarded state is plain data with no invariant a partial update can break. Keep new lock sites on the helper.
- **Webhook retries are infinite**: `webhook::send_webhook` retries forever with exponential backoff capped at 60s. A wedged webhook receiver will block forward progress. There is currently no "send to dead-letter and continue" path.
- **The `derive_address` trait method is overloaded for non-BIP32 chains**: for SOL, it returns `secure_deposit_address`; for ETH, it returns the gas-tank address. Don't expect it to derive distinct per-index addresses on those chains.
- **`xpub` env for `MAX_DERIVATION_INDEX`**: BTC/LTC pre-build a HashMap of `address → index` for `0..=MAX_DERIVATION_INDEX` before the scan loop. Setting this too high (e.g. 100_000) makes startup slow and memory-hungry. Default is 100, current `.env` has `1500`.
- **Atomic state writes**: state files use `path + ".tmp"` then rename. Don't write directly to the final path — partially-written files would prevent restart.
- **Don't add `spl-token` or `spl-associated-token-account` crates lightly**: they pull in a large solana toolchain. The current code builds the two SPL instructions it needs by hand. Extend [src/solana_tokens.rs](src/solana_tokens.rs) the same way unless you genuinely need more.
- **EVM RPC rate limits**: every `self.provider.*().await` call in [src/ethereum.rs](src/ethereum.rs) MUST go through `self.with_rpc_retry("op_name", || async { ... })` (or at minimum `self.acquire_rpc_slot().await` for `send_transaction` which can't safely retry). The wrapper applies a configurable minimum gap between requests (`{ETH,BASE}_RPC_MIN_REQUEST_INTERVAL_MS`) and exponential-backoff retries on transient rate-limit responses (JSON-RPC `-32016`, `-32005`, HTTP 429/502/503). Forgetting the wrapper is invisible until the orphan sweep at startup hammers a public RPC like `mainnet.base.org` and starts dropping balance reads. The rate-limit detector logic lives in `is_rpc_rate_limit_error` — extend the substring list when a new provider surfaces a different error shape.

## Code style observed in this repo

- French-language commit messages and code review (the user is francophone). Code identifiers and comments are in English.
- No emoji in code or commits.
- Errors generally bubble up as `DetectorError::ApiError(format!(...))` or `DetectorError::InvalidConfig(...)`. Avoid panicking from request handlers; do panic from `main.rs` setup if config is unrecoverable.
- Logging style: `[CHAIN_TICKER] Action — context (key=value, key=value)`. `log::info!` for milestones, `log::warn!` for recoverable issues, `log::error!` only for real failures, `log::debug!` for verbose RPC traces.
- Sweep logging always includes the destination + txid so the operator can verify on-chain.

### Detection recovery and RPC failover

- `ETH_RPC_FALLBACK_URLS` / `BASE_RPC_FALLBACK_URLS`: comma-separated read RPCs. Chain IDs are checked before accepting detection data. Sweep transactions still use the primary RPC.
- ERC-20 archive/range failures fall back to `eth_getBlockReceipts`, then individual receipts if the batch method is unavailable. Null historical responses are retried; incomplete data never advances a source cursor.
- `SOLANA_SCAN_CONCURRENCY`: default 4, clamped to 1?32. Different wallet scans may overlap; scans of the same wallet and credit processing are serialized.
- Detection is queued and persisted before sending webhooks. BTC/LTC and EVM webhooks now carry per-payment `event_id`; ERC-20 webhooks also carry `log_index`. The receiver must persist idempotency on `event_id` for crash-safe redelivery.
- `/recover-txid` on Solana must never advance the wallet or ATA scan cursor.
- Tests in `src/tests/` cover restart, batched payouts, failed/native receipts, archive fallback, missing RPC data and concurrent credits. See README for the optional read-only PublicNode regression.
