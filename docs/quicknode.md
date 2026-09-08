# QuickNode Webhooks: Solana, Ethereum and Base

Run `crypto_payment_api` to receive pushes. The detector-only binary has no HTTP
listener. Existing Helius configuration and `POST /solana/webhook` continue to
work independently: enable either provider or both. Polling remains enabled as
a recovery path after missed notifications or process restarts.

## Configuration

Keep the existing wallet pools, Redis, sweep destinations and outgoing payment
webhook configuration. Add:

```env
CHAIN=solana,ethereum,base

# Platform API key (not an RPC endpoint token). Needs usage read and KV list write.
QUICKNODE_API_KEY=...
INTERNAL_SERVICE_TOKEN=...

# Enables QuickNode on the chains running in this process.
QUICKNODE_WEBHOOK_ENABLED=true

# Use a different destination security token for each chain.
QUICKNODE_SOLANA_SECURITY_TOKEN=...
QUICKNODE_ETH_SECURITY_TOKEN=...
QUICKNODE_BASE_SECURITY_TOKEN=...

# Names of existing QuickNode KV lists referenced by your webhook templates.
QUICKNODE_SOLANA_LIST_NAME=detector-solana-accounts
QUICKNODE_ETH_LIST_NAME=detector-ethereum-wallets
QUICKNODE_BASE_LIST_NAME=detector-base-wallets
QUICKNODE_ETH_TOKEN_LIST_NAME=detector-ethereum-token-contracts
QUICKNODE_BASE_TOKEN_LIST_NAME=detector-base-token-contracts

SOLANA_RPC_URL=https://your-solana-endpoint.quiknode.pro/your-token/
ETH_RPC_URL=https://your-ethereum-endpoint.quiknode.pro/your-token/
BASE_RPC_URL=https://your-base-endpoint.quiknode.pro/your-token/

SOLANA_SPL_TOKENS=default
ETH_ERC20_TOKENS=default
BASE_ERC20_TOKENS=default
```

`QUICKNODE_SOLANA_WEBHOOK_ENABLED`, `QUICKNODE_ETH_WEBHOOK_ENABLED` and
`QUICKNODE_BASE_WEBHOOK_ENABLED` override the global flag individually.
All default to disabled. `DISABLE_BASE=true` still disables the Base detector,
including its QuickNode integration.

The API key is optional for receiving signed pushes if you manage all filters
manually. It is required for automatic KV synchronization and the credits route.
Omit the corresponding `*_LIST_NAME` variables to disable automatic synchronization.
`QUICKNODE_API_BASE_URL` optionally overrides `https://api.quicknode.com` for tests.

## Configure QuickNode

Create dedicated KV lists before starting the detector, through the dashboard
or `POST https://api.quicknode.com/kv/rest/v1/lists`, with `x-api-key` authentication:

```json
{"key":"detector-solana-accounts","items":[]}
```

Repeat for the other four list names. The detector adds the wallet pool addresses
at startup and after assignments/rotations. Solana includes each wallet's ATAs
for all configured SPL tokens, including CASH's Token-2022 ATA. EVM contract lists
contain the configured ERC-20 contracts. Failed syncs retry every 60 seconds;
successful additions are cached until restart. Old addresses are retained for
late deposits, including after reservation cancellation. Use dedicated lists;
if you remove items manually, restart the detector to restore them.

Configure the following webhooks with public HTTPS destination URLs:

| Network | Template | `templateArgs` | Destination path |
| --- | --- | --- | --- |
| Solana mainnet | `solanaWalletFilter` | `{"accountsListName":"detector-solana-accounts"}` | `/solana/webhook/quicknode` |
| Ethereum mainnet | `evmWalletFilter` | `{"walletsListName":"detector-ethereum-wallets"}` | `/ethereum/webhook/quicknode` |
| Ethereum mainnet | `evmContractEvents` | `{"contractsListName":"detector-ethereum-token-contracts"}` | `/ethereum/webhook/quicknode` |
| Base mainnet | `evmWalletFilter` | `{"walletsListName":"detector-base-wallets"}` | `/base/webhook/quicknode` |
| Base mainnet | `evmContractEvents` | `{"contractsListName":"detector-base-token-contracts"}` | `/base/webhook/quicknode` |

For each webhook, set `destination_attributes.security_token` to the matching
chain's `QUICKNODE_*_SECURITY_TOKEN`. The two EVM webhooks for the same chain use
the same destination and secret. `compression` may be `none` or `gzip`.

For example, create the Solana webhook using
`POST https://api.quicknode.com/webhooks/rest/v1/webhooks/template/solanaWalletFilter`
with this body and `x-api-key` authentication:

```json
{
  "name": "Payment detector Solana",
  "network": "solana-mainnet",
  "destination_attributes": {
    "url": "https://detector.example.com/solana/webhook/quicknode",
    "security_token": "same-value-as-QUICKNODE_SOLANA_SECURITY_TOKEN",
    "compression": "none"
  },
  "templateArgs": {
    "accountsListName": "detector-solana-accounts"
  }
}
```

The EVM contract-event webhooks ensure token deposits trigger a notification
even when the top-level transaction targets a token contract instead of a
managed wallet. They can deliver activity involving other users of those
contracts; the receiver only queues scans when a managed address appears in the
payload, including padded ERC-20 log topics. Delivery charges still apply to
those matching contract blocks. Five webhooks fit Build's current ten-webhook
limit, but RPC and delivery consumption must stay within your credit budget.

The detector does not create paid webhooks or change their destination settings.
Tokens outside the configured allowlists are not credited. Internal EVM contract
payments continue to use the existing Etherscan detection path; keep it enabled
when you need those deposits.

## Delivery behavior

The receiver validates `X-QN-Nonce`, `X-QN-Timestamp` and `X-QN-Signature` using
HMAC-SHA256 over `nonce + timestamp + uncompressed body`. The signing timestamp
must be within five minutes of the server clock. The request body and decompressed
body are limited to 2 MiB each.

A valid push returns `200 {"accepted": N}`, where `N` is the number of matching
managed addresses queued. This acknowledges a scan hint, not a payment credit.
An unrelated/test JSON payload returns `accepted: 0`. Invalid signatures return
401; malformed JSON/gzip returns 400; oversized payloads return 413; unsupported
compression returns 415. Disabled chains and full/unavailable queues return 503
so QuickNode can retry.

One background worker per chain coalesces notifications. Payments are verified
through RPC, including receipts, token contracts/mints, owners and confirmations,
then use the existing durable pending queue and event identifiers. EVM pushes
run the ordinary scan for all assignments to preserve chain-wide scan cursors.
Keep the polling loops and state files: queued scan hints themselves are held
in memory, and polling recovers them after a crash. A push before the required
confirmations may only be credited on a later polling pass.

## Credits endpoint

```http
GET /quicknode/credits
X-Internal-Service-Token: <INTERNAL_SERVICE_TOKEN>
```

Example:

```json
{
  "provider": "quicknode",
  "source": "/v0/usage/rpc",
  "fetched_at_unix": 1788825600,
  "cached": false,
  "credits_used": 12000000,
  "credits_remaining": 68000000,
  "limit": 80000000,
  "overages": null,
  "start_time": 1788220800,
  "end_time": 1788825600
}
```

These are QuickNode's reported values from `GET /v0/usage/rpc`, using its default
billing-period range; they are not calculated from local request counts or a
hardcoded Build allowance. `end_time` is the end of the queried usage range,
not a promised reset date. This endpoint exposes the Admin API's RPC usage
summary; it does not synthesize a separate all-product billing ledger.
Successful responses are cached for 60 seconds and concurrent refreshes share
one provider request. `fetched_at_unix` remains the original fetch time.
Missing configuration returns 503, a missing/wrong internal token returns 401,
and upstream errors or incomplete usage data return 502, never a fake zero balance.

## CASH on Solana

Default Solana tokens are now **USDC and CASH**. CASH uses mint
`CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH`, six decimals and the Token-2022
program. Its ATA derivation, destination ATA creation and checked transfers
use that program. Fiat enrichment and the sweep fee guard treat CASH as
USD-pegged, matching the existing stablecoin behavior.

An explicit custom `SOLANA_SPL_TOKENS` list still replaces the defaults. Add
`CASH:CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH:6` to that list if needed.
`none`/`off` still disables token monitoring. Other custom mints continue to use
the legacy SPL Token program; this change specifically adds Token-2022 handling
for the verified CASH mint.

## References

- [QuickNode webhook templates](https://www.quicknode.com/docs/webhooks/rest-api/getting-started)
- [Create KV lists](https://www.quicknode.com/docs/key-value-store/rest-api/lists/create-list)
- [Update KV lists](https://www.quicknode.com/docs/key-value-store/rest-api/lists/upsert-list)
- [Validate QuickNode signatures](https://www.quicknode.com/guides/quicknode-products/streams/validating-incoming-streams-webhook-messages)
- [QuickNode usage API](https://www.quicknode.com/docs/admin-api/usage/v0-usage-rpc)
- [QuickNode pricing](https://www.quicknode.com/pricing)
- [Phantom CASH mint and decimals](https://docs.phantom.com/cash)
- [x402 CASH Token-2022 program mapping](https://github.com/x402-foundation/x402/blob/main/go/mechanisms/svm/constants.go)
