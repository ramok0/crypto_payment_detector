# Crypto Payment Detector

Rust payment detector for **Bitcoin**, **Litecoin**, and **Solana**.

BTC and LTC stay watch-only with xpub / Ltub derivation.
Solana now uses a **bot-managed wallet pool** backed by **Redis reservations**:

- the API reserves one temporary Solana address per user for 1 hour
- the detector scans only active reserved addresses from Redis
- when funds arrive, webhooks include the `user_id`
- once the payment is credited, the bot automatically sweeps the maximum spendable SOL from that temporary address to your secure destination wallet

## Features

- Multi-chain support: Bitcoin, Litecoin, Solana
- BTC/LTC watch-only address derivation from xpub / Ltub
- Solana address pool loaded from a local JSON file with private keys
- Redis-backed Solana reservation system with 1h TTL by default
- HMAC-SHA256 signed webhooks
- Automatic Solana sweep to a secure destination wallet
- Fiat enrichment via Kraken public API
- Persistent state for restart recovery

## Solana Flow

1. Your bot/API reserves a temporary address for a `user_id`.
2. The reservation is stored in Redis with a TTL.
3. The Solana detector polls only the active reserved addresses.
4. On incoming payment, it sends `payment_detected`.
5. Once confirmations are met, it sweeps the max spendable balance to `SOLANA_DEPOSIT_ADDRESS`.
6. It then sends `payment_credited` with the user id, received amount, and sweep metadata.

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
SOLANA_RESERVATION_TTL_SECS=3600

WEBHOOK_URL=http://localhost:8080/webhook
WEBHOOK_SECRET=your_hmac_secret

AUTH_USER=user
AUTH_PASS=pass

FIAT_CURRENCY=EUR
BTC_POLL_INTERVAL=120
LTC_POLL_INTERVAL=30
SOL_POLL_INTERVAL=20
SOL_MIN_DEPOSIT_FIAT=0.5
SOL_MIN_CONFIRMATIONS=1

RUST_LOG=info
```

Optional:

```env
PROXY=socks5://user:pass@host:port
EXPLORER_API_URL=https://blockstream.info/api
MAX_RETRIES=5
RETRY_BASE_DELAY_MS=1000
SKIP_INITIAL_BLOCK_SYNC=true
BTC_STATE_FILE=btc_state.json
LTC_STATE_FILE=ltc_state.json
SOL_STATE_FILE=sol_state.json
BTC_MIN_CONFIRMATIONS=3
LTC_MIN_CONFIRMATIONS=2
MAX_DERIVATION_INDEX=1500
API_BIND=0.0.0.0:3030
```

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

## Run

Detector only:

```bash
CHAIN=solana cargo run --release
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

## Verification

Current verification command:

```bash
cargo check --all-targets
```
