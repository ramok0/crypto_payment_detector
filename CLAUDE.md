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

Two binaries:
- `crypto_payment_detector` ([src/main.rs](src/main.rs)) — detector loop
- `crypto_payment_api` ([src/api.rs](src/api.rs)) — axum HTTP API for `/derive`, `/health`, `/solana/reserve`, `/ethereum/reserve`, etc.

## Module map

- [src/lib.rs](src/lib.rs) — module declarations + public re-exports. Update both module list and `pub use` when adding modules/types.
- [src/types.rs](src/types.rs) — `Chain` enum, `DetectorConfig`, `DetectedPayment`, `WebhookEvent`. The `Chain` enum is used everywhere; adding a new chain means touching it plus every match arm in `derivation.rs`, `pricing.rs`, `bitcoin_sweep.rs`, `main.rs`, `api.rs`, etc.
- [src/error.rs](src/error.rs) — `DetectorError`. Has `From<reqwest::Error>` and `From<serde_json::Error>`.
- [src/trait_def.rs](src/trait_def.rs) — `PaymentDetector` trait (RPIT-style async fns).
- [src/persistence.rs](src/persistence.rs) — atomic JSON state file (`tmp + rename`) for BTC/LTC.
- [src/derivation.rs](src/derivation.rs) — BTC/LTC `xpub` → P2WPKH address. Handles `Ltub`→`xpub` prefix conversion via custom base58check (the bitcoin crate doesn't natively know about Litecoin extended keys).
- [src/pricing.rs](src/pricing.rs) — Kraken price fetcher with 30s cache. One `PriceFetcher` per (chain, fiat) pair.
- [src/webhook.rs](src/webhook.rs) — HMAC-SHA256 signed JSON webhook with infinite exponential-backoff retry. Also Discord webhook helper.
- [src/env_utils.rs](src/env_utils.rs) — env helpers (`chain_env_var`, `proxy_env_var`, `redact_url_credentials`).

### Chain implementations

- [src/blockstream.rs](src/blockstream.rs) — `ChainDetector` for BTC/LTC. Block-scan loop, multi-explorer fallback (Esplora + Blockchair), reorg detection by per-height block-hash cache, parallel tx scan via Rayon, optional auto-sweep via `bitcoin_sweep`.
- [src/bitcoin_sweep.rs](src/bitcoin_sweep.rs) — BTC/LTC P2WPKH sweep: `Ltpv`→`xprv` conversion, BIP32 derive secret key at index, fetch UTXOs from Esplora, build+sign+broadcast tx. Only **P2WPKH bech32** destinations are supported.
- [src/solana.rs](src/solana.rs) — `SolanaDetector`. Reservation-based: each user reserves a wallet from a pool. Per cycle, scans signatures of (a) reserved owner address for SOL, (b) each `ATA(owner, mint)` for SPL tokens. Sweeps SOL using the managed wallet as fee payer; sweeps SPL tokens using the configured `SOLANA_FEE_PAYER_PRIVATE_KEY` as fee payer + the managed wallet as token-authority signer.
- [src/solana_pool.rs](src/solana_pool.rs) — Solana wallet pool loader + Redis-backed reservations. Wallet file format: `{"wallets": [{"address": "...", "private_key": "<base58 or [byte array]>"}]}`.
- [src/solana_tokens.rs](src/solana_tokens.rs) — SPL token helpers: `parse_spl_tokens` (env config parser), `derive_associated_token_address` (`Pubkey::find_program_address` over `[owner, token_program, mint]`), `spl_transfer_checked_instruction` (manually built TransferChecked, instruction tag `12`). No `spl-token` crate dep — instructions built by hand.
- [src/ethereum.rs](src/ethereum.rs) — `EthereumDetector`. Per-block scan: `eth_getBlockByNumber` for native ETH transfers, `eth_getLogs` with Transfer topic + reserved-address topic2 for ERC-20s. Sweeps to a "gas tank" address; gas tank periodically forwards to the cold ledger and tops up managed wallets that need ETH for token transfers. Has its own ignored-events bookkeeping for self-initiated gas top-ups (so they don't get treated as user deposits).
- [src/ethereum_pool.rs](src/ethereum_pool.rs) — Ethereum wallet pool. **Auto-creates missing pool file** with N random wallets controlled by `ETH_WALLET_POOL_SIZE` (default 10, max 10000). Supports either Redis or in-memory reservations (`ETH_RESERVATION_STORE=memory`).

## Key design patterns

### Reservation flow (SOL, ETH)
1. Bot owns a pool of N wallets (private keys local).
2. User calls `POST /solana/reserve` or `POST /ethereum/reserve` with `user_id`. API picks an unreserved wallet, stores `{user_id, address, wallet_index, expiry}` in Redis (key `solana:reservation:<addr>` or `ethereum:reservation:<addr>`) with TTL.
3. Detector loop loads active reservations every cycle and only watches those addresses.
4. On confirmed deposit: webhook + sweep to secure destination; reservation key continues to exist until TTL.

### BTC/LTC flow (no reservations)
- xpub-derived addresses (no per-user assignment in the bot — assignment is the caller's responsibility based on the `derivation_index` exposed by `/derive`).
- Block-by-block scan in `run_block_scan_loop`, reorg-aware via per-height block hash cache.
- Sweep is **opt-in**: only enabled if `BTC_XPRIV` + `BTC_SWEEP_DESTINATION` (or LTC equivalents) are both set. Without them the detector still works as a read-only payment monitor.

### Webhook flow
- Always emit `payment_detected` first (when seen in a block, before confirmation).
- After `min_confirmations` slots/blocks: sweep, then emit `payment_credited` with sweep result populated.
- `WebhookEvent` enum is `#[serde(tag = "event", content = "data")]` — wire format is `{"event": "payment_credited", "data": {...DetectedPayment}}`.
- HMAC sent in `X-Signature-256` header (lowercase hex).

### Fee management
- **BTC/LTC**: fixed fee rate from config (`BTC_SWEEP_FEE_RATE_SATS_PER_VB`, default 5). Sweep transaction is single-output P2WPKH→P2WPKH.
- **SOL native**: managed wallet pays its own fee out of the swept SOL. The remainder lands on the **gas tank** (`SOLANA_GAS_TANK_PRIVATE_KEY` pubkey) when set, otherwise on `SOLANA_DEPOSIT_ADDRESS` (cold).
- **SOL tokens**: fee payer = `SOLANA_GAS_TANK_PRIVATE_KEY` (must be a wallet **distinct from `SOLANA_DEPOSIT_ADDRESS`**, even though using the same key works it logs a warning). Token destination is always `ATA(SOLANA_DEPOSIT_ADDRESS, mint)` — tokens never accumulate on the gas tank.
- **SOL gas tank maintenance**: same pattern as ETH gas tank. Periodically (`SOLANA_GAS_TANK_INTERVAL_SECS`, default 900s), if the gas tank holds more than `SOLANA_GAS_TANK_TARGET_USD` (default $10), excess is swept to `SOLANA_DEPOSIT_ADDRESS`. If the balance is below target, a warning is logged (the operator must top up the gas tank manually).
- **SOL orphan sweep at startup**: `SolanaDetector::sweep_orphan_balances()` runs once when the detector starts (called by `run_solana_detector` in [src/main.rs](src/main.rs) and [src/api.rs](src/api.rs)). It iterates every wallet in the pool, **skips currently reserved addresses** (those returned by `load_active_reservations`), and sweeps any leftover SOL/SPL balance to the gas tank/cold ATA. This recovers funds stuck on wallets whose reservation expired before the deposit confirmed.
- **ETH native**: managed wallet pays its own fee. Excess ETH on the gas tank is periodically swept to `ETH_LEDGER_ADDRESS` keeping `~ETH_GAS_TANK_TARGET_USD` worth.
- **ETH ERC-20**: fee paid in ETH from the managed wallet itself. If the wallet has insufficient ETH, the gas tank tops it up automatically before sweeping.

### State persistence
Each chain has its own JSON state file (atomic write via `.tmp + rename`). Re-parses on startup; corrupt files log a warning and start fresh.

- BTC/LTC: `last_scanned_height` + `known_block_hashes` (for reorg detection) + pending payments waiting for confirmations.
- SOL: per-address `last_processed_signature` cursor (works for both owner and ATA addresses), pending payments, credited signatures set.
- ETH: `last_scanned_block`, pending payments, `credited_events` set, `ignored_events` set (gas-tank-originated transfers), `gas_tank_last_maintenance_unix`.

## Adding a new SPL token

1. Set env: `SOLANA_SPL_TOKENS=USDC:<mint>:6,USDT:<mint>:6,...` (or `default` for USDC mainnet, or `none`/`off` to disable).
2. The detector will automatically derive the ATA for each managed wallet and start monitoring.
3. The destination ATA (= ATA of `SOLANA_DEPOSIT_ADDRESS` for that mint) **must already exist** before the first sweep. The detector does not create it.

Custom tokens use `is_usd_pegged_token(symbol)` for fiat conversion: if the symbol matches USDC/USDT/DAI/BUSD/TUSD/USDP/GUSD/PYUSD it's treated as USD-pegged and converted via `SOL/fiat / SOL/USD`. Otherwise no fiat enrichment.

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
- `SOLANA_SPL_TOKENS` (default = USDC mainnet).
- `SOLANA_GAS_TANK_PRIVATE_KEY` — gas tank wallet that pays SPL fees and absorbs SOL native sweeps. Should be distinct from the deposit address. Legacy alias `SOLANA_FEE_PAYER_PRIVATE_KEY` still works but is deprecated.
- `SOLANA_GAS_TANK_TARGET_USD` (default 10) — target balance kept on the gas tank; excess auto-forwarded to the ledger.
- `SOLANA_GAS_TANK_INTERVAL_SECS` (default 900) — how often to run gas tank maintenance.
- `REDIS_URL` — required.

Ethereum:
- `ETH_RPC_URL`, `ETH_CHAIN_ID`, `ETH_WALLET_POOL_FILE`, `ETH_GAS_TANK_PRIVATE_KEY`, `ETH_LEDGER_ADDRESS`.
- `ETH_ERC20_TOKENS` (default = USDC + USDT mainnet).
- `ETH_RESERVATION_STORE=memory` to skip Redis (the wallet pool file auto-creates if missing).
- `ETH_GAS_TANK_TARGET_USD` (default 20), `ETH_GAS_TANK_INTERVAL_SECS` (default 900).

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
- **LTC bech32**: addresses use `ltc1...` HRP. The detector derives via the bitcoin crate (which produces `bc1...`) and then re-encodes by stripping the witness program and applying the `ltc` HRP. The `bitcoin::Address::from_str` path won't accept `ltc1...` — use `bech32::segwit::decode` for parsing LTC addresses.
- **Solana SPL transfer detection**: `getSignaturesForAddress(owner)` does **not** return token transfer signatures because the owner pubkey isn't in the account_keys for SPL transfers — only the ATA is. The detector must scan the ATA address separately.
- **Solana SPL transfer destination ATA must pre-exist**: the sweep doesn't include `createAssociatedTokenAccountIdempotent`. If `ATA(SOLANA_DEPOSIT_ADDRESS, mint)` doesn't exist on-chain yet, the first sweep will fail with `AccountNotFound`. Create it manually beforehand.
- **Ethereum gas-tank top-ups look like deposits**: a top-up from the gas tank to a managed wallet would otherwise be detected as a payment. The detector uses `is_native_gas_tank_top_up(from, to, gas_tank)` and an `ignored_events` set to filter these. When changing the gas-tank logic, preserve this behavior.
- **Webhook retries are infinite**: `webhook::send_webhook` retries forever with exponential backoff capped at 60s. A wedged webhook receiver will block forward progress. There is currently no "send to dead-letter and continue" path.
- **The `derive_address` trait method is overloaded for non-BIP32 chains**: for SOL, it returns `secure_deposit_address`; for ETH, it returns the gas-tank address. Don't expect it to derive distinct per-index addresses on those chains.
- **`xpub` env for `MAX_DERIVATION_INDEX`**: BTC/LTC pre-build a HashMap of `address → index` for `0..=MAX_DERIVATION_INDEX` before the scan loop. Setting this too high (e.g. 100_000) makes startup slow and memory-hungry. Default is 100, current `.env` has `1500`.
- **Atomic state writes**: state files use `path + ".tmp"` then rename. Don't write directly to the final path — partially-written files would prevent restart.
- **Don't add `spl-token` or `spl-associated-token-account` crates lightly**: they pull in a large solana toolchain. The current code builds the two SPL instructions it needs by hand. Extend [src/solana_tokens.rs](src/solana_tokens.rs) the same way unless you genuinely need more.

## Code style observed in this repo

- French-language commit messages and code review (the user is francophone). Code identifiers and comments are in English.
- No emoji in code or commits.
- Errors generally bubble up as `DetectorError::ApiError(format!(...))` or `DetectorError::InvalidConfig(...)`. Avoid panicking from request handlers; do panic from `main.rs` setup if config is unrecoverable.
- Logging style: `[CHAIN_TICKER] Action — context (key=value, key=value)`. `log::info!` for milestones, `log::warn!` for recoverable issues, `log::error!` only for real failures, `log::debug!` for verbose RPC traces.
- Sweep logging always includes the destination + txid so the operator can verify on-chain.
