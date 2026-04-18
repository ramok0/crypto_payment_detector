# Solana Deposit System

This document is a handoff spec for another AI or engineer.

It describes the full Solana deposit flow implemented in this repository:

- how deposit addresses are reserved
- how reservations are stored in Redis
- how the detector scans active addresses
- how webhooks are emitted
- how received funds are swept to the secure destination wallet

The goal is to let another AI implement the reservation side, or integrate with it, without having to rediscover the system from source.

## 1. High-Level Goal

The Solana flow does not use memo fields.

Instead:

1. The bot owns a pool of Solana wallets.
2. One wallet address is temporarily reserved to one user.
3. The reservation lives for 1 hour by default.
4. The detector scans only currently reserved addresses.
5. When the user sends funds to the reserved address:
   - `payment_detected` is sent to the webhook
   - after the confirmation threshold is reached, the detector sweeps the max spendable SOL to the secure destination address
   - `payment_credited` is sent to the webhook with the `user_id` and sweep metadata

The secure destination wallet is expected to be controlled outside the bot, ideally by a hardware wallet.

## 2. Main Components

### 2.1 Wallet Pool

Source file:

- [src/solana_pool.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana_pool.rs:45)

The wallet pool is loaded from `SOLANA_WALLET_POOL_FILE`.

Each entry represents one bot-managed Solana wallet:

- it has a private key known by the bot
- it has one public address used as a temporary deposit address
- the bot can sign a sweep transaction from that wallet

### 2.2 Reservation Storage

Source file:

- [src/solana_pool.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana_pool.rs:121)

Active reservations are stored in Redis.

Each reservation is one Redis key:

```text
solana:reservation:<address>
```

The Redis value is JSON.

The Redis TTL is the real source of truth for expiration.

### 2.3 Reservation API

Source file:

- [src/api.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/api.rs:241)

The API exposes:

- `POST /solana/reserve`
- `GET /solana/active`

### 2.4 Detector

Source file:

- [src/solana.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana.rs:164)

The detector:

- loads all active reservations from Redis
- scans only the reserved addresses
- emits webhooks
- sweeps funds to `SOLANA_DEPOSIT_ADDRESS`

## 3. Required Environment Variables

These vars are required for the Solana deposit system:

```env
CHAIN=solana
SOLANA_RPC_URL=https://api.mainnet.solana.com
SOLANA_WALLET_POOL_FILE=solana_wallets.json
SOLANA_DEPOSIT_ADDRESS=<secure destination address>
REDIS_URL=redis://127.0.0.1:6379/
SOLANA_RESERVATION_TTL_SECS=3600
WEBHOOK_URL=http://localhost:8080/webhook
WEBHOOK_SECRET=<hmac secret>
```

Useful optional vars:

```env
SOL_POLL_INTERVAL=20
SOL_MIN_CONFIRMATIONS=1
SOL_MIN_DEPOSIT_FIAT=0.5
SOL_STATE_FILE=sol_state.json
FIAT_CURRENCY=EUR
MAX_RETRIES=5
RETRY_BASE_DELAY_MS=1000
PROXY=socks5://user:pass@host:port
API_BIND=0.0.0.0:3030
```

Important meanings:

- `SOLANA_WALLET_POOL_FILE`: local JSON file containing the bot-managed private keys
- `SOLANA_DEPOSIT_ADDRESS`: secure destination address that receives the sweep, not the temporary user-facing deposit address
- `REDIS_URL`: Redis used for reservation state
- `SOLANA_RESERVATION_TTL_SECS`: reservation lifetime, default `3600`

## 4. Wallet Pool File Contract

The wallet pool file can be:

1. a JSON array of wallet entries
2. a JSON object with a `wallets` field

Supported per-wallet fields:

- `address` optional
- `private_key` required

Aliases accepted for `private_key`:

- `secret_key`
- `secretKey`
- `keypair`

The private key can be:

1. a base58 string
2. a JSON array of 64 bytes

Example:

```json
{
  "wallets": [
    {
      "address": "5Xa7mJ4bWJf2...",
      "private_key": "4UhnbpVAaXHYiQ1..."
    },
    {
      "private_key": [12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78]
    }
  ]
}
```

Rules:

- if `address` is present, it must match the public key derived from the private key
- the keypair must contain the full 64-byte Solana keypair
- wallet order matters because reservation iterates in file order

## 5. Redis Contract

### 5.1 Key Pattern

```text
solana:reservation:<address>
```

Example:

```text
solana:reservation:6tM5uB2...
```

### 5.2 Value Format

JSON object:

```json
{
  "user_id": "123456789",
  "address": "6tM5uB2...",
  "wallet_index": 4,
  "reserved_at_unix": 1773500000,
  "expires_at_unix": 1773503600
}
```

Fields:

- `user_id`: the application-level user identifier
- `address`: reserved deposit address
- `wallet_index`: index of the wallet inside the pool file
- `reserved_at_unix`: UNIX timestamp when reserved
- `expires_at_unix`: UNIX timestamp expected expiration

### 5.3 TTL Behavior

The Redis TTL is set when reserving:

```text
SET solana:reservation:<address> <json> EX <ttl_secs> NX
```

Important:

- expiration is enforced by Redis TTL
- when TTL expires, the address becomes free again
- no extra cleanup job is required for the reservation itself

## 6. Reservation Algorithm

Source file:

- [src/solana_pool.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana_pool.rs:157)

Current algorithm:

1. Validate `user_id` is not empty.
2. Load all active reservations from Redis.
3. If this `user_id` already has an active reservation, return it.
4. Otherwise iterate wallet pool in order.
5. For each wallet, try:

```text
SET solana:reservation:<address> <json> EX <ttl_secs> NX
```

6. First `SET ... NX` success wins.
7. If no wallet is available, return an error.

### 6.1 Reservation Guarantees

- one Redis key per reserved address
- one active address per user in the current implementation
- one active user per address
- reservation reuse is allowed after TTL expiration

### 6.2 Recommended Client Behavior

If another AI is implementing the application-side reservation logic:

1. Call `POST /solana/reserve` with `user_id`.
2. Store:
   - `address`
   - `expires_at_unix`
   - `wallet_index`
3. Display the address to the user.
4. Treat the address as valid only until `expires_at_unix`.
5. After expiration, request a new reservation instead of reusing the old address.

## 7. API Contract

Source file:

- [src/api.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/api.rs:241)

### 7.1 POST /solana/reserve

Request:

```http
POST /solana/reserve
Content-Type: application/json
```

Body:

```json
{
  "user_id": "123456789"
}
```

Success response:

```json
{
  "user_id": "123456789",
  "address": "6tM5uB2...",
  "wallet_index": 4,
  "reserved_at_unix": 1773500000,
  "expires_at_unix": 1773503600,
  "reservation_ttl_secs": 3600,
  "sweep_destination_address": "HwSecureWallet..."
}
```

Behavior:

- if the user already has an active reservation, the existing one is returned
- otherwise a free address is reserved

Typical error cases:

- `400` if the Solana pool is not configured
- `409` if no wallet is available
- `500` for internal/Redis/config issues

### 7.2 GET /solana/active

Request:

```http
GET /solana/active
```

Response:

```json
{
  "count": 2,
  "reservations": [
    {
      "user_id": "123456789",
      "address": "6tM5uB2...",
      "wallet_index": 4,
      "reserved_at_unix": 1773500000,
      "expires_at_unix": 1773503600
    },
    {
      "user_id": "555",
      "address": "B92abc...",
      "wallet_index": 7,
      "reserved_at_unix": 1773500020,
      "expires_at_unix": 1773503620
    }
  ]
}
```

Usage:

- debugging
- admin view
- reconciliation

## 8. Detector Scan Logic

Source file:

- [src/solana.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana.rs:242)

Each cycle:

1. Load active reservations from Redis.
2. Get current slot.
3. Optionally get SOL fiat price for dust filtering.
4. For each reserved address:
   - load new signatures with `getSignaturesForAddress`
   - fetch transaction details with `getTransaction`
   - keep only transactions that increased the reserved address balance
   - emit `payment_detected`
   - push pending payment into local state
5. Process pending payments whose confirmations reached the threshold.
6. Sweep the max spendable balance from the temporary address to the secure destination.
7. Emit `payment_credited`.

### 8.1 What Counts as a Deposit

A transaction is treated as a deposit if:

- it is confirmed
- it has no transaction error
- the reserved address balance increased between `preBalances` and `postBalances`

Memo is ignored in this new system.

### 8.2 Address Cursors

The detector stores one `last_processed_signature` per address in its local state file.

That means:

- scanning is incremental per address
- restarting the process does not force rescanning from scratch

## 9. Sweep Logic

Source file:

- [src/solana.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana.rs:419)

When a pending payment is credited:

1. Load the balance of the temporary address.
2. Load a recent blockhash.
3. Estimate the transfer fee.
4. Compute:

```text
sweep_amount = balance - fee
```

5. Sign and send a transfer from the temporary wallet to `SOLANA_DEPOSIT_ADDRESS`.

The sweep sends the maximum currently spendable SOL.

### 9.1 Important Caveat

If several deposits arrive on the same temporary address before the sweep happens, the sweep may move more than the single transaction amount that triggered the credit.

This is expected with the current implementation because sweep is based on current spendable balance, not per-transaction isolation.

If another AI needs strict one-order-per-address semantics, it should:

- stop reusing the address immediately after first valid incoming payment
- or mark the reservation as consumed and prevent further customer use

## 10. Webhook Contract

Source files:

- [src/types.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/types.rs:87)
- [src/webhook.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/webhook.rs:9)

Webhooks are signed with:

- header `X-Signature-256`
- HMAC-SHA256 of the raw JSON body

### 10.1 payment_detected

Example:

```json
{
  "event": "payment_detected",
  "data": {
    "chain": "solana",
    "ticker": "SOL",
    "txid": "5tYp...",
    "address": "6tM5uB2...",
    "user_id": "123456789",
    "amount_sat": 1250000000,
    "amount_coin": 1.25,
    "confirmations": 1,
    "block_height": 321654987,
    "derivation_index": 4,
    "memo": null,
    "swept_to_address": null,
    "swept_amount_sat": null,
    "swept_amount_coin": null,
    "sweep_txid": null,
    "fiat_amount": null,
    "fiat_currency": null,
    "coin_price": null
  }
}
```

### 10.2 payment_credited

Example:

```json
{
  "event": "payment_credited",
  "data": {
    "chain": "solana",
    "ticker": "SOL",
    "txid": "5tYp...",
    "address": "6tM5uB2...",
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

Meaning of the important fields:

- `address`: temporary user-facing address
- `user_id`: the reservation owner
- `amount_*`: amount attributed to the detected inbound transaction
- `swept_*`: amount actually forwarded to the secure destination

## 11. Minimal Integration Guide For Another AI

If another AI only needs to implement the reservation side of the product, this is the minimum contract to respect:

### 11.1 To Create a Payment Request

1. Choose the application `user_id`.
2. Call `POST /solana/reserve`.
3. Save the returned address and expiration timestamp.
4. Show the address to the user.

### 11.2 To Handle Expiration

1. Compare current time to `expires_at_unix`.
2. If expired, do not reuse the address in the UI.
3. Call `POST /solana/reserve` again to obtain a fresh reservation.

### 11.3 To Reconcile Payment Completion

Use the webhook:

- `payment_detected` means incoming SOL was observed on the reserved address
- `payment_credited` means the payment passed the confirmation threshold and the bot attempted the sweep

Use `user_id` from the webhook to attach the payment to the application user/order.

## 12. If Another AI Wants To Reimplement The Reservation Logic Itself

To stay compatible with the detector, it must preserve these contracts:

1. Redis keys must use:

```text
solana:reservation:<address>
```

2. Redis values must serialize to:

```json
{
  "user_id": "...",
  "address": "...",
  "wallet_index": 0,
  "reserved_at_unix": 0,
  "expires_at_unix": 0
}
```

3. Redis TTL must be set on the key.
4. `address` must correspond to a wallet that exists in the wallet pool file.
5. `wallet_index` must match the index of that wallet in the pool file.

If these conditions are broken, the detector may:

- not find the wallet for sweeping
- send incorrect metadata
- fail to process deposits

## 13. Failure Modes And Edge Cases

### 13.1 No Free Wallet

Cause:

- all pool addresses are already reserved

Effect:

- `POST /solana/reserve` returns conflict

Fix:

- increase wallet pool size
- shorten TTL
- release reservations faster at the application layer if appropriate

### 13.2 User Pays After Reservation Expired

Cause:

- the address TTL expired before the user sent funds

Effect:

- the detector no longer scans that address if it is not reserved anymore

Important:

- this means late payments can be missed by design in the current model

If this is unacceptable, another AI should add a grace strategy such as:

- delayed untracking
- post-expiration rescue scan
- consumed-but-still-watched addresses

### 13.3 Multiple Deposits On One Reserved Address

Cause:

- same user pays twice
- third party also sends funds

Effect:

- sweep uses current spendable balance
- webhook `swept_amount_*` can be higher than the payment amount that triggered the credit event

### 13.4 Redis Is Down

Effect:

- reservation API fails
- detector cannot load active addresses

### 13.5 Wallet Pool File Is Wrong

Effect:

- startup fails

Common causes:

- invalid base58 private key
- keypair not 64 bytes
- address mismatch

## 14. Suggested Improvements

These are not required for compatibility, but another AI may want to implement them:

1. Mark an address as consumed after first valid deposit.
2. Keep expired addresses in a short rescue window.
3. Add an authenticated admin endpoint to release or inspect reservations.
4. Add `reservation_id` or `order_id` in the Redis payload and webhook.
5. Add an explicit webhook event for sweep failure.
6. Store a persistent ledger of completed sweeps instead of relying only on webhook delivery.

## 15. Code Map

Main code references:

- [src/solana_pool.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana_pool.rs:12): wallet pool parsing and Redis reservation helpers
- [src/api.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/api.rs:241): reservation endpoints
- [src/solana.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana.rs:242): scan loop, detection, pending payments
- [src/solana.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/solana.rs:419): sweep logic
- [src/types.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/src/types.rs:87): webhook payload fields
- [examples/webhook_server.rs](C:/Users/Admin/Desktop/bitcoin_payment_detector/examples/webhook_server.rs:47): simple webhook consumer example

## 16. Short Summary For Another AI

If you only remember five things, remember these:

1. Temporary deposit addresses come from a bot-managed wallet pool JSON file.
2. Active reservations live in Redis under `solana:reservation:<address>`.
3. `POST /solana/reserve` returns one address per `user_id`.
4. The detector scans only addresses that are currently reserved in Redis.
5. After credit, the bot sweeps the max spendable SOL from the temporary wallet to `SOLANA_DEPOSIT_ADDRESS`.
