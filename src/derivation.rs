use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::CompressedPublicKey;
use bitcoin::Address;
use bitcoin::Network;
use std::str::FromStr;

use crate::error::DetectorError;
use crate::types::Chain;

const LTC_XPUB_VERSION: [u8; 4] = [0x01, 0x9D, 0xA4, 0x62]; // Ltub
const BTC_XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E]; // xpub

fn normalize_xpub_to_bitcoin(xpub_str: &str, chain: Chain) -> Result<String, DetectorError> {
    match chain {
        Chain::Bitcoin => Ok(xpub_str.to_string()),
        Chain::Litecoin => {
            let decoded = base58_decode_check(xpub_str)
                .map_err(|e| DetectorError::InvalidXpub(format!("Failed to decode Ltub: {e}")))?;

            if decoded.len() < 4 {
                return Err(DetectorError::InvalidXpub("Extended key too short".into()));
            }

            if decoded[..4] == BTC_XPUB_VERSION {
                return Ok(xpub_str.to_string());
            }

            if decoded[..4] != LTC_XPUB_VERSION {
                return Err(DetectorError::InvalidXpub(format!(
                    "Expected Ltub (019DA462) or xpub (0488B21E) prefix, got {:02X}{:02X}{:02X}{:02X}",
                    decoded[0], decoded[1], decoded[2], decoded[3]
                )));
            }

            let mut converted = decoded.clone();
            converted[..4].copy_from_slice(&BTC_XPUB_VERSION);

            Ok(base58_encode_check(&converted))
        }
    }
}

fn base58_decode_check(input: &str) -> Result<Vec<u8>, String> {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut result = vec![0u8; 0];
    for &c in input.as_bytes() {
        let pos = alphabet.iter().position(|&b| b == c)
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

pub fn derive_address(
    xpub_str: &str,
    index: u32,
    chain: Chain,
) -> Result<String, DetectorError> {
    let btc_xpub_str = normalize_xpub_to_bitcoin(xpub_str, chain)?;

    let xpub = Xpub::from_str(&btc_xpub_str)
        .map_err(|e| DetectorError::InvalidXpub(e.to_string()))?;

    let secp = bitcoin::secp256k1::Secp256k1::new();

    let external_chain = xpub
        .ckd_pub(&secp, ChildNumber::Normal { index: 0 })
        .map_err(|e| DetectorError::DerivationFailed {
            index,
            reason: e.to_string(),
        })?;

    let child = external_chain
        .ckd_pub(&secp, ChildNumber::Normal { index })
        .map_err(|e| DetectorError::DerivationFailed {
            index,
            reason: e.to_string(),
        })?;

    let pubkey = CompressedPublicKey(child.public_key);

    match chain {
        Chain::Bitcoin => {
            let address = Address::p2wpkh(&pubkey, Network::Bitcoin);
            Ok(address.to_string())
        }
        Chain::Litecoin => {
            let address = Address::p2wpkh(&pubkey, Network::Bitcoin);
            let btc_addr = address.to_string();
            btc_bech32_to_ltc_bech32(&btc_addr)
        }
    }
}

fn btc_bech32_to_ltc_bech32(btc_addr: &str) -> Result<String, DetectorError> {
    use bech32::Hrp;

    let (_hrp, witness_version, witness_program) = bech32::segwit::decode(btc_addr)
        .map_err(|e| DetectorError::DerivationFailed {
            index: 0,
            reason: format!("Failed to decode bech32 segwit address: {e}"),
        })?;

    let ltc_hrp = Hrp::parse("ltc").unwrap();
    let encoded = bech32::segwit::encode(ltc_hrp, witness_version, &witness_program)
        .map_err(|e| DetectorError::DerivationFailed {
            index: 0,
            reason: format!("Failed to encode ltc bech32 address: {e}"),
        })?;

    Ok(encoded)
}
