use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::consensus::Encodable;
use bitcoin::ecdsa;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    WPubkeyHash, Witness, absolute::LockTime,
};
use serde::Deserialize;

use crate::error::DetectorError;
use crate::types::Chain;

const LTC_XPRIV_VERSION: [u8; 4] = [0x01, 0x9D, 0x9C, 0xFE];
const BTC_XPRIV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];

const P2WPKH_INPUT_VBYTES: u64 = 68;
const TX_OVERHEAD_VBYTES: u64 = 11;
const P2WPKH_OUTPUT_VBYTES: u64 = 31;

pub const DEFAULT_SWEEP_FEE_RATE_SATS_PER_VB: u64 = 5;
pub const DEFAULT_MIN_SWEEP_SAT: u64 = 5_000;

#[derive(Debug, Clone)]
pub struct BitcoinSweepConfig {
    pub chain: Chain,
    pub xpriv: String,
    pub destination: String,
    pub fee_rate_sats_per_vb: u64,
    pub min_sweep_sat: u64,
    pub max_fee_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct BitcoinSweepResult {
    pub txid: Option<String>,
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub deferred: bool,
}

#[derive(Debug, Deserialize)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    value: u64,
}

pub fn validate_sweep_config(config: &BitcoinSweepConfig) -> Result<(), DetectorError> {
    if !matches!(config.chain, Chain::Bitcoin | Chain::Litecoin) {
        return Err(DetectorError::InvalidConfig(format!(
            "Bitcoin-style sweep is not supported for chain {}",
            config.chain
        )));
    }
    if config.xpriv.trim().is_empty() {
        return Err(DetectorError::InvalidConfig(
            "Sweep xpriv is required".into(),
        ));
    }
    if config.destination.trim().is_empty() {
        return Err(DetectorError::InvalidConfig(
            "Sweep destination is required".into(),
        ));
    }

    // Eagerly validate the inputs so bad configs fail at startup, not on first sweep.
    derive_private_key(&config.xpriv, 0, config.chain)?;
    parse_destination_script(&config.destination, config.chain)?;
    Ok(())
}

pub fn derive_private_key(
    xpriv_str: &str,
    index: u32,
    chain: Chain,
) -> Result<SecretKey, DetectorError> {
    let normalized = normalize_xpriv_to_bitcoin(xpriv_str, chain)?;
    let xpriv = Xpriv::from_str(&normalized).map_err(|e| {
        DetectorError::InvalidXpub(format!("Invalid extended private key: {e}"))
    })?;
    let secp = Secp256k1::new();

    let external_chain = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .map_err(|e| DetectorError::DerivationFailed {
            index,
            reason: e.to_string(),
        })?;

    let child = external_chain
        .derive_priv(&secp, &[ChildNumber::Normal { index }])
        .map_err(|e| DetectorError::DerivationFailed {
            index,
            reason: e.to_string(),
        })?;

    Ok(child.private_key)
}

fn normalize_xpriv_to_bitcoin(xpriv_str: &str, chain: Chain) -> Result<String, DetectorError> {
    match chain {
        Chain::Bitcoin => Ok(xpriv_str.to_string()),
        Chain::Litecoin => {
            let decoded = base58_decode_check(xpriv_str)
                .map_err(|e| DetectorError::InvalidXpub(format!("Failed to decode Ltpv: {e}")))?;
            if decoded.len() < 4 {
                return Err(DetectorError::InvalidXpub("Extended key too short".into()));
            }
            if decoded[..4] == BTC_XPRIV_VERSION {
                return Ok(xpriv_str.to_string());
            }
            if decoded[..4] != LTC_XPRIV_VERSION {
                return Err(DetectorError::InvalidXpub(format!(
                    "Expected Ltpv (019D9CFE) or xprv (0488ADE4) prefix, got {:02X}{:02X}{:02X}{:02X}",
                    decoded[0], decoded[1], decoded[2], decoded[3]
                )));
            }
            let mut converted = decoded.clone();
            converted[..4].copy_from_slice(&BTC_XPRIV_VERSION);
            Ok(base58_encode_check(&converted))
        }
        Chain::Solana | Chain::Ethereum | Chain::Base => Err(DetectorError::InvalidXpub(format!(
            "Bitcoin-style xpriv derivation is not supported for {}",
            chain
        ))),
    }
}

pub fn parse_destination_script(
    address: &str,
    chain: Chain,
) -> Result<ScriptBuf, DetectorError> {
    let trimmed = address.trim();
    let lower = trimmed.to_ascii_lowercase();

    if lower.starts_with("bc1") || lower.starts_with("ltc1") {
        let (hrp, witness_version, witness_program) = bech32::segwit::decode(trimmed)
            .map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid bech32 sweep destination '{}': {e}",
                    trimmed
                ))
            })?;
        let expected = match chain {
            Chain::Bitcoin => "bc",
            Chain::Litecoin => "ltc",
            _ => unreachable!(),
        };
        if hrp.as_str() != expected {
            return Err(DetectorError::InvalidConfig(format!(
                "Sweep destination '{}' has hrp '{}'; expected '{}'",
                trimmed,
                hrp.as_str(),
                expected
            )));
        }
        if witness_version.to_u8() != 0 || witness_program.len() != 20 {
            return Err(DetectorError::InvalidConfig(format!(
                "Sweep destination '{}' must be a P2WPKH (witness v0, 20-byte program) address",
                trimmed
            )));
        }
        let pubkey_hash = WPubkeyHash::from_slice(&witness_program).map_err(|e| {
            DetectorError::InvalidConfig(format!(
                "Invalid P2WPKH program in sweep destination '{}': {e}",
                trimmed
            ))
        })?;
        Ok(ScriptBuf::new_p2wpkh(&pubkey_hash))
    } else {
        Err(DetectorError::InvalidConfig(format!(
            "Sweep destination '{}' must be a bech32 P2WPKH address (bc1.../ltc1...)",
            trimmed
        )))
    }
}

pub async fn fetch_utxos(
    client: &reqwest::Client,
    esplora_url: &str,
    address: &str,
) -> Result<Vec<u64>, DetectorError> {
    let utxos = fetch_raw_utxos(client, esplora_url, address).await?;
    Ok(utxos.into_iter().map(|u| u.value).collect())
}

async fn fetch_raw_utxos(
    client: &reqwest::Client,
    esplora_url: &str,
    address: &str,
) -> Result<Vec<EsploraUtxo>, DetectorError> {
    let url = format!(
        "{}/address/{}/utxo",
        esplora_url.trim_end_matches('/'),
        address
    );
    let response = client.get(&url).send().await.map_err(|e| {
        DetectorError::ApiError(format!("Failed to fetch UTXOs from {url}: {e}"))
    })?;
    if !response.status().is_success() {
        return Err(DetectorError::ApiError(format!(
            "UTXO endpoint returned status {} for {address}",
            response.status()
        )));
    }
    response
        .json::<Vec<EsploraUtxo>>()
        .await
        .map_err(|e| DetectorError::ApiError(format!("Failed to parse UTXO response: {e}")))
}

async fn broadcast_tx(
    client: &reqwest::Client,
    esplora_url: &str,
    tx_hex: &str,
) -> Result<String, DetectorError> {
    let url = format!("{}/tx", esplora_url.trim_end_matches('/'));
    let response = client
        .post(&url)
        .body(tx_hex.to_string())
        .send()
        .await
        .map_err(|e| {
            DetectorError::ApiError(format!("Failed to broadcast sweep tx via {url}: {e}"))
        })?;
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| format!("<failed to read body: {e}>"));
    if !status.is_success() {
        return Err(DetectorError::ApiError(format!(
            "Broadcast endpoint returned status {status}: {body}"
        )));
    }
    Ok(body.trim().to_string())
}

pub async fn sweep_address(
    client: &reqwest::Client,
    esplora_url: &str,
    config: &BitcoinSweepConfig,
    derivation_index: u32,
    address: &str,
) -> Result<BitcoinSweepResult, DetectorError> {
    let utxos = fetch_raw_utxos(client, esplora_url, address).await?;
    if utxos.is_empty() {
        log::info!(
            "[{}] No UTXOs to sweep for {} (index {})",
            config.chain.ticker(),
            address,
            derivation_index
        );
        return Ok(BitcoinSweepResult {
            txid: None,
            amount_sat: 0,
            fee_sat: 0,
            deferred: false,
        });
    }

    let total_input: u64 = utxos.iter().map(|u| u.value).sum();
    let vsize = TX_OVERHEAD_VBYTES + (utxos.len() as u64) * P2WPKH_INPUT_VBYTES + P2WPKH_OUTPUT_VBYTES;
    let fee = vsize.saturating_mul(config.fee_rate_sats_per_vb.max(1));

    if total_input <= fee {
        log::info!(
            "[{}] Deferring sweep for {} (index {}): inputs {} sat <= fee {} sat",
            config.chain.ticker(),
            address,
            derivation_index,
            total_input,
            fee
        );
        return Ok(BitcoinSweepResult {
            txid: None,
            amount_sat: 0,
            fee_sat: 0,
            deferred: true,
        });
    }

    let amount_out = total_input - fee;
    if amount_out < config.min_sweep_sat {
        log::info!(
            "[{}] Deferring sweep for {} (index {}): net {} sat < min_sweep_sat {} sat",
            config.chain.ticker(),
            address,
            derivation_index,
            amount_out,
            config.min_sweep_sat
        );
        return Ok(BitcoinSweepResult {
            txid: None,
            amount_sat: 0,
            fee_sat: 0,
            deferred: true,
        });
    }

    if fee_ratio_too_high(fee, total_input, config.max_fee_ratio) {
        log::info!(
            "[{}] Deferring sweep for {} (index {}): fee {} sat would be {:.1}% of input {} sat (max {:.1}%) - retry when fee market drops",
            config.chain.ticker(),
            address,
            derivation_index,
            fee,
            (fee as f64 / total_input as f64) * 100.0,
            total_input,
            config.max_fee_ratio * 100.0
        );
        return Ok(BitcoinSweepResult {
            txid: None,
            amount_sat: 0,
            fee_sat: 0,
            deferred: true,
        });
    }

    let secret_key = derive_private_key(&config.xpriv, derivation_index, config.chain)?;
    let secp = Secp256k1::new();
    let public_key = secret_key.public_key(&secp);
    let compressed_pubkey =
        CompressedPublicKey::from_slice(&public_key.serialize()).map_err(|e| {
            DetectorError::ApiError(format!(
                "Failed to build compressed public key from derived secret: {e}"
            ))
        })?;
    let source_script = ScriptBuf::new_p2wpkh(&compressed_pubkey.wpubkey_hash());
    let destination_script = parse_destination_script(&config.destination, config.chain)?;

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: utxos
            .iter()
            .map(|utxo| {
                Ok(TxIn {
                    previous_output: OutPoint::new(
                        Txid::from_str(&utxo.txid).map_err(|e| {
                            DetectorError::ApiError(format!(
                                "Invalid UTXO txid '{}': {e}",
                                utxo.txid
                            ))
                        })?,
                        utxo.vout,
                    ),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
            })
            .collect::<Result<Vec<_>, DetectorError>>()?,
        output: vec![TxOut {
            value: Amount::from_sat(amount_out),
            script_pubkey: destination_script,
        }],
    };

    let mut sighasher = SighashCache::new(&mut tx);
    for (idx, utxo) in utxos.iter().enumerate() {
        let sighash = sighasher
            .p2wpkh_signature_hash(
                idx,
                &source_script,
                Amount::from_sat(utxo.value),
                EcdsaSighashType::All,
            )
            .map_err(|e| {
                DetectorError::ApiError(format!(
                    "Failed to compute p2wpkh sighash for input {idx}: {e}"
                ))
            })?;
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&message, &secret_key);
        let ecdsa_sig = ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };
        *sighasher.witness_mut(idx).ok_or_else(|| {
            DetectorError::ApiError(format!("Missing witness slot for input {idx}"))
        })? = Witness::p2wpkh(&ecdsa_sig, &public_key);
    }

    let mut serialized = Vec::with_capacity(256);
    tx.consensus_encode(&mut serialized).map_err(|e| {
        DetectorError::ApiError(format!("Failed to serialize sweep tx: {e}"))
    })?;
    let tx_hex = hex::encode(&serialized);

    let txid = broadcast_tx(client, esplora_url, &tx_hex).await?;
    log::info!(
        "[{}] Swept {} sat from {} (index {}) to {} (fee={} sat, tx={})",
        config.chain.ticker(),
        amount_out,
        address,
        derivation_index,
        config.destination,
        fee,
        txid
    );

    Ok(BitcoinSweepResult {
        txid: Some(txid),
        amount_sat: amount_out,
        fee_sat: fee,
        deferred: false,
    })
}

fn fee_ratio_too_high(fee: u64, total: u64, max_ratio: f64) -> bool {
    if total == 0 || !max_ratio.is_finite() || max_ratio <= 0.0 || max_ratio >= 1.0 {
        return false;
    }
    (fee as f64) / (total as f64) > max_ratio
}

fn base58_decode_check(input: &str) -> Result<Vec<u8>, String> {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = vec![0u8; 0];
    for &c in input.as_bytes() {
        let pos = alphabet
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| format!("Invalid base58 character: {}", c as char))?;

        let mut carry = pos;
        for byte in result.iter_mut().rev() {
            carry += (*byte as usize) * 58;
            *byte = (carry % 256) as u8;
            carry /= 256;
        }
        while carry > 0 {
            result.insert(0, (carry % 256) as u8);
            carry /= 256;
        }
    }
    for &c in input.as_bytes() {
        if c == b'1' {
            result.insert(0, 0);
        } else {
            break;
        }
    }
    if result.len() < 4 {
        return Err("Decoded data too short for checksum".into());
    }
    let payload = &result[..result.len() - 4];
    let checksum = &result[result.len() - 4..];

    use sha2::Digest;
    let hash1 = sha2::Sha256::digest(payload);
    let hash2 = sha2::Sha256::digest(&hash1);

    if checksum != &hash2[..4] {
        return Err("Checksum mismatch".into());
    }

    Ok(payload.to_vec())
}

fn base58_encode_check(payload: &[u8]) -> String {
    use sha2::Digest;
    let hash1 = sha2::Sha256::digest(payload);
    let hash2 = sha2::Sha256::digest(&hash1);

    let mut data = payload.to_vec();
    data.extend_from_slice(&hash2[..4]);

    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut num = vec![0u8; 0];
    for &byte in &data {
        let mut carry = byte as usize;
        for digit in num.iter_mut() {
            carry += (*digit as usize) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            num.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::new();
    for &byte in &data {
        if byte == 0 {
            result.push('1');
        } else {
            break;
        }
    }
    for &digit in num.iter().rev() {
        result.push(alphabet[digit as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::derive_address;
    use bitcoin::Network;
    use bitcoin::bip32::Xpub;

    fn test_master_keys() -> (String, String) {
        let seed = [0u8; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).expect("master derivation");
        let secp = Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        (xpriv.to_string(), xpub.to_string())
    }

    #[test]
    fn derives_compressed_pubkey_matching_xpub_address() {
        let (xpriv, xpub) = test_master_keys();
        let secret = derive_private_key(&xpriv, 0, Chain::Bitcoin).unwrap();
        let secp = Secp256k1::new();
        let pubkey = secret.public_key(&secp);
        let compressed = CompressedPublicKey::from_slice(&pubkey.serialize()).unwrap();
        let derived_address = bitcoin::Address::p2wpkh(&compressed, Network::Bitcoin).to_string();

        let from_xpub = derive_address(&xpub, 0, Chain::Bitcoin).unwrap();
        assert_eq!(derived_address, from_xpub);
    }

    #[test]
    fn rejects_solana_chain() {
        let (xpriv, _) = test_master_keys();
        let result = derive_private_key(&xpriv, 0, Chain::Solana);
        assert!(result.is_err());
    }

    #[test]
    fn parses_btc_p2wpkh_destination() {
        let (_, xpub) = test_master_keys();
        let address = derive_address(&xpub, 0, Chain::Bitcoin).expect("address derivation works");
        let script = parse_destination_script(&address, Chain::Bitcoin).unwrap();
        assert!(script.is_p2wpkh());
    }

    #[test]
    fn rejects_destination_with_wrong_hrp() {
        let (_, xpub) = test_master_keys();
        let address = derive_address(&xpub, 0, Chain::Bitcoin).expect("address derivation works");
        let result = parse_destination_script(&address, Chain::Litecoin);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_legacy_destination() {
        let result = parse_destination_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Chain::Bitcoin);
        assert!(result.is_err());
    }
}
