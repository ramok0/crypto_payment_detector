# Crypto Payment Detector

Rust payment detector for **Bitcoin**, **Litecoin**, **Solana**, **Ethereum**, and **Base**.

BTC/LTC addresses are derived from an xpub / Ltub. Sweeping is optional and requires the corresponding private key and destination. Solana and EVM chains use managed wallet pools with permanent per-user address assignments. Webhooks include the user or derivation index and a stable per-payment `event_id`.

## Detection and delivery

QuickNode Webhooks are supported for Solana (SOL/SPL), Ethereum and Base
(ETH/ERC-20), alongside the existing Helius integration and polling.
See [QuickNode setup and credits endpoint](docs/quicknode.md) for configuration,
webhook URLs and authenticated `GET /quicknode/credits` usage reporting.
Solana's default token list includes USDC and Phantom CASH (Token-2022, 6 decimals).

- BTC/LTC scans aggregate transaction outputs by recipient, so batched payouts and multiple outputs to one address are credited correctly.
- SOL and SPL scans keep a cursor per wallet / ATA. A missing transaction stops that cursor for retry; `/recover-txid` queues the supplied payment without changing scan progress.
- Solana scans up to `SOLANA_SCAN_CONCURRENCY` addresses concurrently (default **4**, range **1?32**). Scans of the same address and payment confirmation workers are serialized to prevent overlapping credits.
- Ethereum/Base maintain separate cursors for native transfers, ERC-20 logs and Etherscan internal calls. Native transfers require a successful receipt. An unavailable source cannot discard progress from the other sources.
- If `eth_getLogs` rejects archive access or the requested range, the detector reads `eth_getBlockReceipts`, falling back to individual transaction receipts when the batch method is unsupported. Partial or missing receipts retain the cursor.
- All chains save pending payments before delivery. `payment_detected` precedes `payment_credited`; failed deliveries remain pending. Each webhook attempt has a 10-second timeout, with at most three attempts per delivery pass. Permanent HTTP 4xx errors (except 408/429) return immediately so other payments can continue.
- Failed or deferred sweeps remain queued. Confirmed deposits can be credited before a fee-deferred sweep completes; sweep fields are then absent from the credited webhook.
- State files preserve pending payments, delivered-event identifiers and scan cursors. Writes are serialized and atomically replaced. A corrupt state file fails startup instead of silently resetting the credit ledger.

The receiving backend must persist idempotency using `event_id`: a crash after it accepts a webhook but before the detector records the acknowledgement can still cause redelivery. BTC/LTC IDs distinguish transaction + recipient; EVM IDs distinguish native transfers, ERC-20 log indices and internal traces. Solana IDs distinguish signature + recipient + asset.

## Solana flow

1. The API assigns a permanent wallet to a user in Redis. Rotated addresses remain assigned to their original owner for late payments.
2. The detector scans the owner address for SOL and each configured token's ATA for SPL deposits.
3. A detected payment enters the durable delivery queue. After the configured confirmations, the detector attempts the sweep and sends the credit webhook.
4. Native SOL is swept to the gas tank when configured, otherwise to `SOLANA_DEPOSIT_ADDRESS`. SPL tokens go to the destination ATA; the gas tank pays fees.

## Ethereum and Base flow

1. The API assigns a permanent managed wallet to a user (Redis, or in-memory storage for local use).
2. Separate scans find native ETH, configured ERC-20 transfers and optional Etherscan internal transfers.
3. Tokens are swept directly to the ledger; the gas tank funds gas when necessary. Native ETH is swept to the gas tank.
4. Gas tank maintenance forwards excess ETH to the ledger.

Ethereum defaults to mainnet USDC and USDT. Base defaults to **Base USDC only**, at `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`. Set `BASE_ERC20_TOKENS` explicitly for additional Base tokens. Custom lists use `SYMBOL:0xcontract:decimals`.

## Restart and Ethereum archive access

Keep each chain's state file on persistent storage and run one writer per state file. Existing Ethereum state automatically initializes the separate cursors from the old `last_scanned_block`; it does not skip the backlog. `last_scanned_block` remains the lowest completed source cursor for health reporting.

If the provider denies both historical logs and receipts, configure an authorized archive endpoint in `ETH_RPC_URL` or add endpoints in `ETH_RPC_FALLBACK_URLS` (comma-separated). Base uses `BASE_RPC_FALLBACK_URLS`. The chain ID is checked before accepting detection data from an endpoint. Fallbacks apply to detection reads; sweep transactions still use the primary RPC. No additional public endpoint is contacted unless configured.

Do not delete the state file or move the cursor to the tip to fix an archive error: that would skip deposits. `ETH_START_BLOCK` applies only when there is no saved scan cursor. Old BTC/LTC versions did not persist pending payments, so payments already lost before this upgrade need explicit `/recover-txid` recovery; upgrading cannot reconstruct that missing queue from the old cursor alone. The same applies to Solana transactions already skipped by the old cursor logic.

## Tests

```bash
cargo test --all-targets --offline
```

Regression tests use local mock RPC/webhook servers and temporary state files. Live Blockchair and PublicNode tests remain ignored by default. The read-only PublicNode regression exercises the historical Ethereum block from the archive-access incident:

```bash
cargo test --lib --offline publicnode_archive_block_can_be_scanned_through_receipts -- --ignored
```

## Quick Start

### Prerequisites

- Rust 1.85+
- Redis

### Build

```bash
cargo build --release
```

### Configuration

Example `.env`:

```env
CHAIN=all

BTC_XPUB=xpub6...
LTC_XPUB=Ltub2...

SOLANA_RPC_URL=https://api.mainnet.solana.com
SOLANA_WALLET_POOL_FILE=solana_wallets.json
SOLANA_DEPOSIT_ADDRESS=...        # secure destination wallet, usually the hardware wallet receive address
REDIS_URL=redis://127.0.0.1:6379/
SOLANA_SCAN_CONCURRENCY=4       # use 1 if your RPC requires sequential polling

ETH_RPC_URL=https://ethereum-rpc.publicnode.com
ETH_CHAIN_ID=1
ETH_WALLET_POOL_FILE=ethereum_wallets.json
ETH_WALLET_POOL_SIZE=10             # optional: generated wallet count if ETH_WALLET_POOL_FILE is missing
ETH_GAS_TANK_PRIVATE_KEY=0x...    # hot wallet, used for token gas top-ups and central sweeps
ETH_LEDGER_ADDRESS=0x...          # Ledger address receiving recovered tokens and gas tank ETH excess
ETH_ERC20_TOKENS=default          # default = mainnet USDC + USDT

WEBHOOK_URL=http://localhost:8080/webhook
WEBHOOK_SECRET=your_hmac_secret

AUTH_USER=user
AUTH_PASS=pass

FIAT_CURRENCY=EUR
BTC_POLL_INTERVAL=120
LTC_POLL_INTERVAL=30
SOL_POLL_INTERVAL=20
ETH_POLL_INTERVAL=30
SOL_MIN_DEPOSIT_FIAT=0.5
SOL_MIN_CONFIRMATIONS=1
ETH_MIN_CONFIRMATIONS=12

RUST_LOG=info
```

Optional:

```env
PROXY=socks5://user:pass@host:port
SOLANA_PROXY=off                  # optional: disable global PROXY for Solana only
ETH_PROXY=off                     # optional: disable global PROXY for Ethereum only
BTC_EXPLORER_API_URL=https://blockstream.info/api
LTC_EXPLORER_API_URLS=https://litecoinspace.org/api,https://api.blockchair.com/litecoin
BLOCKCHAIR_API_KEY=optional_blockchair_key
MAX_RETRIES=5
RETRY_BASE_DELAY_MS=1000
SKIP_INITIAL_BLOCK_SYNC=false
BTC_STATE_FILE=btc_state.json
LTC_STATE_FILE=ltc_state.json
SOL_STATE_FILE=sol_state.json
ETH_STATE_FILE=eth_state.json
ETH_START_BLOCK=optional_backfill_block
ETH_MAX_BLOCKS_PER_CYCLE=250
# ETH_RPC_FALLBACK_URLS=https://your-authorized-archive-rpc.example
ETH_RESERVATION_STORE=memory        # local tests only: keep ETH reservations in process memory instead of Redis
ETH_GAS_TANK_TARGET_USD=20
ETH_GAS_TANK_INTERVAL_SECS=900
ETH_TOKEN_TRANSFER_GAS_LIMIT=100000
ETH_GAS_TOP_UP_MULTIPLIER=1.25
BTC_MIN_CONFIRMATIONS=3
LTC_MIN_CONFIRMATIONS=2
MAX_DERIVATION_INDEX=1500
API_BIND=0.0.0.0:3030
TAILSCALE_PANEL_BIND=127.0.0.1:3031 # ou l'IP Tailscale 100.x de la machine
PANEL_SOL_GAS_MINIMUM=0.01          # alerte du panel sous ce solde
PANEL_ETH_GAS_MINIMUM=0.002
PANEL_BASE_GAS_MINIMUM=0.002
```

## Panel d'opérations Tailscale

Le binaire `crypto_payment_api` expose un second serveur, indépendant de l'API
publique, avec l'état des détecteurs, les curseurs et files de paiements, les
adresses de gaz et une alerte de solde insuffisant. Il se rafraîchit toutes les
5 secondes. Par défaut il écoute uniquement `127.0.0.1:3031`, ce qui convient à
`tailscale serve http://127.0.0.1:3031`. Il peut aussi écouter directement sur
l'adresse Tailscale de la machine avec `TAILSCALE_PANEL_BIND=100.x.y.z:3031`.

Le serveur refuse au niveau applicatif toute adresse source hors loopback,
plage Tailscale IPv4 (`100.64.0.0/10`) ou préfixe Tailscale IPv6. Ne publiez pas
ce port via un reverse proxy public.

BTC/LTC explorer URLs use Esplora-compatible APIs by default. Litecoin also
falls back to Blockchair when `litecoinspace.org` is unreachable. For production
volume, prefer your own Litecoin Space/Esplora instance or set a Blockchair API
key.

## Solana Wallet Pool File

Set `SOLANA_WALLET_POOL_FILE` to a JSON file containing the bot-managed private keys.

Supported formats:

1. Array of entries
2. Object with a `wallets` field
3. Private key as base58 string or as a 64-byte array

Example:

```json
{
  "wallets": [
    {
      "address": "Fh3Y...",
      "private_key": "4UhnbpVAaXHYiQ1..."
    },
    {
      "private_key": "2j8zXJwL7n2p..."
    }
  ]
}
```

Note:

- if `address` is present, it is validated against the private key
- the private key array must contain the full 64-byte Solana keypair

## Ethereum Wallet Pool File

Set `ETH_WALLET_POOL_FILE` to a JSON file containing the bot-managed private keys.
If the file does not exist at startup, the detector creates it automatically with
generated wallets. Set `ETH_WALLET_POOL_SIZE` to control the generated count
(`10` by default). Back up the generated file securely before accepting deposits.

Supported formats:

1. Array of entries
2. Object with a `wallets` field
3. Private key as a hex string

Example:

```json
{
  "wallets": [
    {
      "address": "0x1234...",
      "private_key": "0xabcd..."
    },
    {
      "private_key": "0xbeef..."
    }
  ]
}
```

Note:

- if `address` is present, it is validated against the private key
- default ERC-20 token config is mainnet USDC/USDT; custom format is `SYMBOL:0xcontract:decimals,SYMBOL2:0xcontract:decimals`
- USD-pegged ERC-20 tokens such as USDC/USDT are valued as USD first, then converted to `FIAT_CURRENCY` for webhook `fiat_amount`
- set `ETH_RESERVATION_STORE=memory` for local testing without Redis. This only works inside one running process and reservations disappear on restart. Production should keep using Redis.

## Run

Detector only:

```bash
CHAIN=solana cargo run --release
```

```bash
CHAIN=ethereum cargo run --release
```

API + detector:

```bash
CHAIN=all cargo run --release --bin crypto_payment_api
```

## API

### Health

```http
GET /health
```

### BTC/LTC Derivation Helper

```http
GET /derive?chain=bitcoin&start=0&count=5
```

### Reserve a Solana Address

```http
POST /solana/reserve
Content-Type: application/json

{
  "user_id": "123456789"
}
```

Example response:

```json
{
  "user_id": "123456789",
  "address": "6tM5...",
  "wallet_index": 4,
  "reserved_at_unix": 1773500000,
  "expires_at_unix": 1773503600,
  "reservation_ttl_secs": 3600,
  "sweep_destination_address": "HwSecureWallet..."
}
```

If the same user already has an active reservation, the API returns the existing one.

### List Active Solana Reservations

```http
GET /solana/active
```

### Reserve an Ethereum Address

```http
POST /ethereum/reserve
Content-Type: application/json

{
  "user_id": "123456789"
}
```

### List Active Ethereum Reservations

```http
GET /ethereum/active
```

## Webhook Format

Webhooks are POST requests with:

- `Content-Type: application/json`
- `X-Signature-256` header containing the HMAC-SHA256 hex signature of the body

Example payload:

```json
{
  "event": "payment_credited",
  "data": {
    "chain": "solana",
    "ticker": "SOL",
    "txid": "5tYp...",
    "address": "6tM5...",
    "user_id": "123456789",
    "amount_sat": 1250000000,
    "amount_coin": 1.25,
    "confirmations": 1,
    "block_height": 321654987,
    "derivation_index": 4,
    "memo": null,
    "swept_to_address": "HwSecureWallet...",
    "swept_amount_sat": 1249995000,
    "swept_amount_coin": 1.249995,
    "sweep_txid": "3w9Q...",
    "fiat_amount": 148.22,
    "fiat_currency": "EUR",
    "coin_price": 118.58
  }
}
```

ETH/ERC-20 payloads also include token-safe fields:

```json
{
  "asset": "USDC",
  "asset_decimals": 6,
  "amount_base_units": "25000000",
  "swept_amount_base_units": "25000000",
  "token_contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
}
```

Important fields:

- `address`: the temporary reserved Solana address that received the payment
- `user_id`: the Redis reservation owner
- `amount_*`: what the user sent in the detected transaction
- `swept_*`: what was actually forwarded to the secure destination address

## Example Webhook Server

```bash
WEBHOOK_SECRET=your_secret cargo run --example webhook_server
```

It listens on `http://localhost:8080/webhook`.

## Architecture

```text
src/
|-- api.rs           # API server, reservation endpoints, detector orchestration
|-- blockstream.rs   # BTC/LTC block scanning
|-- derivation.rs    # BTC/LTC address derivation
|-- error.rs         # Error types
|-- lib.rs           # Public exports
|-- main.rs          # Detector-only entry point
|-- persistence.rs   # BTC/LTC state helpers
|-- pricing.rs       # Fiat pricing
|-- ethereum.rs      # Ethereum detector, ETH/ERC-20 scanning, sweep logic, gas tank
|-- ethereum_pool.rs # Ethereum wallet pool loading + Redis reservations
|-- solana.rs        # Solana detector, scanning, sweep logic
|-- solana_pool.rs   # Solana wallet pool loading + Redis reservations
|-- trait_def.rs     # Shared detector trait
|-- types.rs         # Shared webhook and payment types
`-- webhook.rs       # HMAC signing and delivery
```

## Operational Notes

- Solana sweep uses the max spendable balance on the temporary address at credit time.
- If several deposits hit the same temporary address before the sweep runs, the first credited sweep can forward more than the single transaction amount because it forwards the current spendable balance.
- Expired Redis reservations are no longer scanned for new incoming payments.
- The secure destination address should be controlled outside the bot, ideally by a hardware wallet.
- The Ethereum gas tank private key is hot. Keep it funded only for operational gas and use `ETH_LEDGER_ADDRESS` for excess ETH.
- Without `ETH_START_BLOCK`, Ethereum starts from the current safe block on first launch. Set `ETH_START_BLOCK` to backfill historical deposits.

## Verification

Current verification command:

```bash
cargo check --all-targets
```

Live Litecoin fallback checks:

```bash
cargo test blockchair_live -- --ignored --nocapture
```
