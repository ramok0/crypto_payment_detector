//! Litecoin-aware raw block deserialization.
//!
//! Litecoin reuses the Bitcoin block/transaction serialization but adds one flag
//! bit for MimbleWimble Extension Blocks (LIP-0002 / LIP-0003):
//!
//! - `0x01` — BIP144 witness data (identical to Bitcoin)
//! - `0x08` — MWEB payload
//!
//! Every block mined since the MWEB activation ends with an integrating
//! transaction (the "HogEx") whose flag byte is `0x08`, so
//! `bitcoin::Block::consensus_decode` rejects *every* Litecoin block with
//! `unsupported segwit version: 8` and the block scan can never move forward.
//!
//! The MWEB layout differs from Bitcoin's in two places:
//!
//! 1. Per transaction, the optional MWEB payload sits between the witness stack
//!    and `nLockTime`. Inside a block it is always the null form (a single `0x00`
//!    byte) because MWEB transactions are aggregated into the block-level
//!    extension block rather than carried inline.
//! 2. After the transaction vector the block may carry the extension block
//!    itself. Explorers disagree on whether they serve it (Blockchair does,
//!    litecoinspace strips it), so anything left over is simply ignored — MWEB
//!    peg-outs already surface as regular outputs of the HogEx transaction,
//!    which is what the address scan looks at.

use bitcoin::absolute::LockTime;
use bitcoin::block::Header;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::encode::VarInt;
use bitcoin::io::BufRead;
use bitcoin::transaction::Version;
use bitcoin::{Block, Transaction, TxIn, TxOut, Witness};

use crate::error::DetectorError;

/// BIP144 marker: the transaction carries witness data.
const FLAG_WITNESS: u8 = 0x01;
/// Litecoin marker: the transaction carries a MimbleWimble payload.
const FLAG_MWEB: u8 = 0x08;

/// Cap on the transaction vector pre-allocation: the count comes straight from
/// the explorer response, so a corrupt reply must not be able to ask for
/// gigabytes up front.
const MAX_TX_PREALLOC: usize = 4096;

/// Deserialize a raw Litecoin block, tolerating the MWEB extensions.
pub fn deserialize_litecoin_block(bytes: &[u8]) -> Result<Block, DetectorError> {
    let mut reader = bytes;

    let header = Header::consensus_decode_from_finite_reader(&mut reader)
        .map_err(|e| DetectorError::ApiError(format!("Failed to parse block header: {e}")))?;

    let tx_count = VarInt::consensus_decode_from_finite_reader(&mut reader)
        .map_err(|e| DetectorError::ApiError(format!("Failed to parse tx count: {e}")))?
        .0;

    let mut txdata = Vec::with_capacity((tx_count as usize).min(MAX_TX_PREALLOC));
    for index in 0..tx_count {
        let tx = decode_transaction(&mut reader).map_err(|reason| {
            DetectorError::ApiError(format!(
                "Failed to parse Litecoin transaction {index}/{tx_count}: {reason}"
            ))
        })?;
        txdata.push(tx);
    }

    // Trailing bytes, if any, are the block-level MWEB extension block. Not needed.
    Ok(Block { header, txdata })
}

fn decode_transaction<R: BufRead + ?Sized>(reader: &mut R) -> Result<Transaction, String> {
    let version = Version::consensus_decode_from_finite_reader(reader)
        .map_err(|e| format!("version: {e}"))?;

    let mut input = Vec::<TxIn>::consensus_decode_from_finite_reader(reader)
        .map_err(|e| format!("vin: {e}"))?;

    // A non-empty vin means there was no marker byte: plain legacy transaction.
    if !input.is_empty() {
        let output = Vec::<TxOut>::consensus_decode_from_finite_reader(reader)
            .map_err(|e| format!("vout: {e}"))?;
        let lock_time = LockTime::consensus_decode_from_finite_reader(reader)
            .map_err(|e| format!("locktime: {e}"))?;
        return Ok(Transaction {
            version,
            lock_time,
            input,
            output,
        });
    }

    // The empty vin we just read was the marker byte; the flag byte follows.
    let flags =
        u8::consensus_decode_from_finite_reader(reader).map_err(|e| format!("flags: {e}"))?;
    if flags & !(FLAG_WITNESS | FLAG_MWEB) != 0 || flags == 0 {
        return Err(format!("unsupported transaction flag byte 0x{flags:02x}"));
    }

    input = Vec::<TxIn>::consensus_decode_from_finite_reader(reader)
        .map_err(|e| format!("vin: {e}"))?;
    let output = Vec::<TxOut>::consensus_decode_from_finite_reader(reader)
        .map_err(|e| format!("vout: {e}"))?;

    if flags & FLAG_WITNESS != 0 {
        for txin in input.iter_mut() {
            txin.witness = Witness::consensus_decode_from_finite_reader(reader)
                .map_err(|e| format!("witness: {e}"))?;
        }
        if !input.is_empty() && input.iter().all(|txin| txin.witness.is_empty()) {
            return Err("witness flag set but no witnesses present".to_string());
        }
    }

    if flags & FLAG_MWEB != 0 {
        skip_mweb_payload(reader)?;
    }

    let lock_time = LockTime::consensus_decode_from_finite_reader(reader)
        .map_err(|e| format!("locktime: {e}"))?;

    Ok(Transaction {
        version,
        lock_time,
        input,
        output,
    })
}

/// The per-transaction MWEB payload is serialized as an optional: a single
/// `0x00` byte when absent, `0x01` followed by a full MWEB transaction otherwise.
///
/// Only the null form occurs inside a block — the extension block holds the
/// aggregated MWEB transactions instead. Decoding the non-null form would mean
/// implementing the whole MWEB body (kernels, rangeproofs, ...), so we refuse it
/// loudly rather than silently misaligning the rest of the block.
fn skip_mweb_payload<R: BufRead + ?Sized>(reader: &mut R) -> Result<(), String> {
    let present =
        u8::consensus_decode_from_finite_reader(reader).map_err(|e| format!("mweb: {e}"))?;
    if present != 0 {
        return Err("inline MWEB payload is not supported".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Litecoin mainnet block 3153135, as served by litecoinspace's `/block/{hash}/raw`.
    /// 6 transactions, the last one being the MWEB HogEx (flag byte `0x08`).
    const LTC_BLOCK_3153135: &str = include_str!("testdata/ltc_block_3153135.hex");

    fn fixture() -> Vec<u8> {
        let hex_str: String = LTC_BLOCK_3153135
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        hex::decode(hex_str).expect("fixture is valid hex")
    }

    #[test]
    fn parses_mweb_block() {
        let block = deserialize_litecoin_block(&fixture()).expect("block should parse");

        assert_eq!(
            block.block_hash().to_string(),
            "d6881dc1acb8d346b9bef7ac3d817494b8089bc26f377be9a966d6d94d68d516"
        );
        assert_eq!(block.txdata.len(), 6);

        // The merkle root only matches if every txid was computed correctly, which
        // in turn means every transaction was framed correctly — including the HogEx
        // whose MWEB flag byte is what `bitcoin::Block::consensus_decode` chokes on.
        assert!(block.check_merkle_root());

        let hogex = block.txdata.last().unwrap();
        assert_eq!(
            hogex.compute_txid().to_string(),
            "76826ed9deb1a8053624d960a34a1bc20452aea5d8c35fed0f9eb7de713e26a3"
        );
        // Output 0 of the HogEx is the extension block balance (witness program v8).
        assert_eq!(hogex.output.len(), 1);
    }

    #[test]
    fn ignores_trailing_extension_block() {
        // Blockchair serves the block-level MWEB extension block after the tx
        // vector, litecoinspace strips it. Both must parse to the same block.
        let mut bytes = fixture();
        let expected = deserialize_litecoin_block(&bytes).expect("block should parse");
        bytes.push(0x01);
        bytes.extend_from_slice(&[0xab; 171]);

        let with_tail = deserialize_litecoin_block(&bytes).expect("trailing MWEB data is ignored");
        assert_eq!(with_tail, expected);
    }

    #[test]
    fn upstream_decoder_still_rejects_the_fixture() {
        // Guards the reason this module exists: if a future `bitcoin` release
        // learns about MWEB, this test fails and the custom parser can go away.
        let bytes = fixture();
        let err = Block::consensus_decode(&mut bytes.as_slice())
            .expect_err("bitcoin crate cannot decode MWEB blocks");
        assert!(
            err.to_string().contains("unsupported segwit version: 8"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_unknown_flag_byte() {
        let mut bytes = fixture();
        // Flip the HogEx flag byte to something neither witness nor MWEB.
        let flag_pos = bytes
            .windows(2)
            .rposition(|w| w == [0x00, 0x08])
            .expect("fixture contains the MWEB marker/flag pair")
            + 1;
        bytes[flag_pos] = 0x10;

        let err = deserialize_litecoin_block(&bytes).expect_err("unknown flag must be rejected");
        assert!(
            err.to_string()
                .contains("unsupported transaction flag byte"),
            "unexpected error: {err}"
        );
    }
}
