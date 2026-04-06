# Crypto Payment Detector

A Rust-based payment detection system for **Bitcoin** and **Litecoin**. Monitors the blockchain in real-time by scanning raw blocks, derives addresses from an extended public key (xpub), and sends HMAC-signed webhook notifications when payments are detected.

## Features

- **Multi-chain support** — Bitcoin and Litecoin, runnable simultaneously (`CHAIN=both`)
- **BIP84 (P2WPKH) address derivation** from xpub / Ltub keys (watch-only, no private keys needed)
- **Raw block scanning** with parallel transaction matching via [rayon](https://github.com/rayon-rs/rayon)
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
CHAIN=both                # bitcoin, litecoin, btc, ltc, or both
BTC_XPUB=xpub6...        # Bitcoin extended public key
LTC_XPUB=Ltub2...        # Litecoin extended public key

WEBHOOK_URL=http://localhost:8080/webhook
WEBHOOK_SECRET=your_hmac_secret

AUTH_USER=user
AUTH_PASS=pass

FIAT_CURRENCY=EUR
BTC_POLL_INTERVAL=120     # seconds between polls (BTC)
LTC_POLL_INTERVAL=30      # seconds between polls (LTC)

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
  "event": "payment_confirmed",
  "data": {
    "chain": "Bitcoin",
    "txid": "abc123...",
    "address": "bc1q...",
    "amount_sat": 100000,
    "confirmations": 3,
    "block_height": 840000,
    "derivation_index": 12,
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