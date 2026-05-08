use serde::{Deserialize, Serialize};

use crate::types::Chain;

/// Result of an on-demand TXID recovery request. The detector returns one
/// of these statuses to the caller; the caller (backend) maps it to a
/// user-facing message and trusts the existing webhook idempotency for
/// the actual balance credit.
///
/// A `Credited` result means: the TX existed on-chain, the destination
/// address belongs to the requesting user, the detector marked it as
/// processed, and a `payment_credited` webhook was fired (and acked by
/// the backend, which dedupes via its own DB unique constraint).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RecoverStatus {
    /// New deposit successfully credited and webhook fired.
    Credited,
    /// Detector already processed this TX in a previous cycle/recovery.
    /// The backend may or may not hold the balance — caller should check.
    AlreadyCredited,
    /// Deposit was found but is queued in pending and has not yet reached
    /// `min_confirmations`. Webhook for `payment_detected` was fired;
    /// `payment_credited` will arrive once the confirmation threshold is
    /// met (the credit no longer waits for a successful sweep — funds on
    /// our managed wallet are sufficient to credit the user).
    PendingSweep,
    /// The destination address is not in our wallet pool / not derived
    /// from our xpub. The TX is not for us.
    AddressNotOwned,
    /// Address belongs to us but is reserved for a different user_id,
    /// or this user has no active reservation at all. Refuse to credit
    /// to prevent TXID-stealing across users.
    WrongUser,
    /// The TX hash is not yet visible on-chain (or never was).
    TxNotFound,
    /// TX exists but doesn't transfer a positive amount of a supported
    /// asset to the requesting user's address. Possibly an outgoing tx
    /// or zero-amount.
    NoCreditAmount,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoverResponse {
    pub chain: Chain,
    #[serde(flatten)]
    pub status: RecoverStatus,
    /// Echoed for the caller's logs.
    pub txid: String,
    pub user_id: String,
    /// Asset symbol (BTC, LTC, SOL, ETH, USDC, ...) when the recovery
    /// actually identified a transfer; `None` for negative outcomes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    /// Human-readable amount in coin units (eg. 0.012345). `None` for
    /// negative outcomes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_coin: Option<f64>,
}

impl RecoverResponse {
    pub fn new(chain: Chain, txid: String, user_id: String, status: RecoverStatus) -> Self {
        Self {
            chain,
            status,
            txid,
            user_id,
            asset: None,
            amount_coin: None,
        }
    }

    pub fn with_asset(mut self, asset: impl Into<String>, amount_coin: f64) -> Self {
        self.asset = Some(asset.into());
        self.amount_coin = Some(amount_coin);
        self
    }
}

/// Request body for `POST /<chain>/recover-txid`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecoverRequest {
    /// On-chain transaction id / signature.
    pub txid: String,
    /// User who claims the deposit. For BTC/LTC this MUST equal the
    /// xpub derivation index used to derive the user's address; for
    /// SOL/ETH/Base it's matched against the *currently active* Redis
    /// reservation. If the user's reservation has expired they must
    /// call `/<chain>/reserve` again with the same `user_id` first.
    pub user_id: String,
}
