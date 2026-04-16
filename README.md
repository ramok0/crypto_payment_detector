# Crypto Payment Detector

A Rust-based payment detection system for **Bitcoin**, **Litecoin**, and **Solana**. Monitors blockchains in near real-time and sends HMAC-signed webhook notifications for detected and credited payments.

## Features

- **Multi-chain support** — Bitcoin, Litecoin, Solana (`CHAIN=both`, `CHAIN=solana`, or `CHAIN=all`)
- **BIP84 (P2WPKH) address derivation** from xpub / Ltub keys (watch-only, no private keys needed)
- **Raw block scanning** with parallel transaction matching via [rayon](https://github.com/rayon-rs/rayon)
- **Solana deposit watcher** via RPC `getSignaturesForAddress` + `getTransaction` with memo validation
- **HMAC-SHA256 signed webhooks** with infinite retry and exponential backoff
- **Fiat price enrichment** via Kraken public API (EUR, USD, GBP, CAD, JPY, AUD, CHF)
- **Persistence** — resumes from last scanned block on restart
- **Configurable retry**, poll intervals, and explorer API URLs per chain

## Quick Start

### Prerequisites

- Rust 1.85+

### Build

```bash
cargo build --release
```

### Configuration

Create a `.env` file:

```env
CHAIN=both                # bitcoin, litecoin, solana, btc, ltc, sol, both, all
BTC_XPUB=xpub6...        # Bitcoin extended public key
LTC_XPUB=Ltub2...        # Litecoin extended public key
SOLANA_DEPOSIT_ADDRESS=...   # Solana deposit wallet address (watch-only)
SOLANA_RPC_URL=https://api.mainnet.solana.com
DISCORD_INVALID_MEMO_WEBHOOK_URL=https://discord.com/api/webhooks/...

WEBHOOK_URL=http://localhost:8080/webhook
WEBHOOK_SECRET=your_hmac_secret

AUTH_USER=user
AUTH_PASS=pass

FIAT_CURRENCY=EUR
BTC_POLL_INTERVAL=120     # seconds between polls (BTC)
LTC_POLL_INTERVAL=30      # seconds between polls (LTC)
SOL_POLL_INTERVAL=60      # seconds between polls (SOL)
SOL_MIN_DEPOSIT_FIAT=0.5  # ignore SOL deposits below this fiat value (dust filter)

RUST_LOG=info
```

Optional:
```env
PROXY=socks5://user:pass@host:port
EXPLORER_API_URL=https://blockstream.info/api    # override default explorer
MAX_RETRIES=5
RETRY_BASE_DELAY_MS=1000
BTC_STATE_FILE=btc_state.json
LTC_STATE_FILE=ltc_state.json
BTC_MIN_CONFIRMATIONS=3
LTC_MIN_CONFIRMATIONS=2
SOL_MIN_CONFIRMATIONS=1
MAX_DERIVATION_INDEX=1500
```

### Run

```bash
# Single chain
CHAIN=bitcoin cargo run --release

# Both chains concurrently
CHAIN=both cargo run --release

# Custom derivation gap (default: 100)
cargo run --release -- 200
```

## Webhook Format

Webhooks are POST requests with:
- `Content-Type: application/json`
- `X-Signature-256` header containing the HMAC-SHA256 hex signature of the body

Payload:
```json
{
  "event": "payment_detected",
  "data": {
    "chain": "Bitcoin",
    "txid": "abc123...",
    "address": "bc1q...",
    "amount_sat": 100000,
    "confirmations": 3,
    "block_height": 840000,
    "derivation_index": 12,
    "memo": "123456",
    "fiat_amount": 52.30,
    "fiat_currency": "EUR",
    "coin_price": 52300.00
  }
}
```

### Example Webhook Server

```bash
WEBHOOK_SECRET=your_secret cargo run --example webhook_server
```

Listens on `http://localhost:8080/webhook`, verifies HMAC signatures and logs incoming payments.

## Architecture

```
src/
├── blockstream.rs   # ChainDetector: block fetching, scanning, webhook dispatch
├── derivation.rs    # BIP32/84 address derivation (BTC xpub + LTC Ltub)
├── error.rs         # Error types
├── lib.rs           # Public API
├── main.rs          # Binary entry point, multi-chain orchestration
├── persistence.rs   # State save/load (JSON, atomic write)
├── pricing.rs       # Kraken price fetcher with 30s cache
├── trait_def.rs     # PaymentDetector trait
├── types.rs         # Chain, DetectorConfig, DetectedPayment, WebhookEvent
└── webhook.rs       # HMAC signing, webhook delivery with retry
```

## Block Data Sources

| Chain    | Chain tip / Block hash       | Raw block data                |
|----------|------------------------------|-------------------------------|
| Bitcoin  | blockstream.info/api         | blockchain.info (hex)         |
| Litecoin | litecoinspace.org/api        | litecoinspace.org/api (binary)|
When confirmations threshold is reached, a second webhook is sent with event `payment_credited`.

For Solana:
- Only transactions that increase `SOLANA_DEPOSIT_ADDRESS` balance are processed.
- Memo must be numeric only (`^[0-9]+$`).
- Missing or invalid memos are sent to `DISCORD_INVALID_MEMO_WEBHOOK_URL`.
