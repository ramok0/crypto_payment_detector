use std::str::FromStr;

use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;

use crate::error::DetectorError;

pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

pub const USDC_MAINNET_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const USDC_DEFAULT_DECIMALS: u8 = 6;

#[derive(Debug, Clone)]
pub struct SplTokenConfig {
    pub symbol: String,
    pub mint: Pubkey,
    pub decimals: u8,
}

pub fn token_program_id() -> Pubkey {
    Pubkey::from_str(TOKEN_PROGRAM_ID).expect("hardcoded SPL token program id")
}

pub fn associated_token_program_id() -> Pubkey {
    Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID)
        .expect("hardcoded SPL associated token program id")
}

pub fn system_program_id() -> Pubkey {
    Pubkey::from_str(SYSTEM_PROGRAM_ID).expect("hardcoded system program id")
}

pub fn derive_associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let token_program = token_program_id();
    let ata_program = associated_token_program_id();
    let (ata, _bump) = Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    );
    ata
}

pub fn create_associated_token_account_idempotent_instruction(
    funder: &Pubkey,
    associated_token_address: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: associated_token_program_id(),
        accounts: vec![
            AccountMeta::new(*funder, true),
            AccountMeta::new(*associated_token_address, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system_program_id(), false),
            AccountMeta::new_readonly(token_program_id(), false),
        ],
        data: vec![1u8], // CreateIdempotent discriminator
    }
}

pub fn spl_transfer_checked_instruction(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 8 + 1);
    data.push(12u8); // TransferChecked discriminator
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    Instruction {
        program_id: token_program_id(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

pub fn parse_spl_tokens(value: Option<&str>) -> Result<Vec<SplTokenConfig>, DetectorError> {
    let Some(value) = value else {
        return Ok(default_spl_tokens());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("default") {
        return Ok(default_spl_tokens());
    }
    if trimmed.eq_ignore_ascii_case("none") || trimmed.eq_ignore_ascii_case("off") {
        return Ok(Vec::new());
    }

    trimmed
        .split([',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let parts = entry.split(':').map(str::trim).collect::<Vec<_>>();
            if parts.len() != 3 {
                return Err(DetectorError::InvalidConfig(format!(
                    "Invalid SOLANA_SPL_TOKENS entry '{}'; expected SYMBOL:mint:decimals",
                    entry
                )));
            }
            let mint = Pubkey::from_str(parts[1]).map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid token mint '{}' in SOLANA_SPL_TOKENS: {e}",
                    parts[1]
                ))
            })?;
            let decimals = parts[2].parse::<u8>().map_err(|e| {
                DetectorError::InvalidConfig(format!(
                    "Invalid token decimals '{}' in SOLANA_SPL_TOKENS: {e}",
                    parts[2]
                ))
            })?;
            Ok(SplTokenConfig {
                symbol: parts[0].to_ascii_uppercase(),
                mint,
                decimals,
            })
        })
        .collect()
}

pub fn default_spl_tokens() -> Vec<SplTokenConfig> {
    vec![SplTokenConfig {
        symbol: "USDC".into(),
        mint: Pubkey::from_str(USDC_MAINNET_MINT).expect("valid USDC mainnet mint"),
        decimals: USDC_DEFAULT_DECIMALS,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ata_for_known_owner_and_mint() {
        let owner = Pubkey::from_str("4Nd1mYf6yA8WqcQq1HwRLdxx8Z3rXa9k4UjSP6mU3jWw").unwrap();
        let mint = Pubkey::from_str(USDC_MAINNET_MINT).unwrap();
        let ata = derive_associated_token_address(&owner, &mint);
        assert!(!ata.to_string().is_empty());
    }

    #[test]
    fn parse_default_token_returns_usdc() {
        let parsed = parse_spl_tokens(None).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].symbol, "USDC");
        assert_eq!(parsed[0].decimals, 6);
    }

    #[test]
    fn parse_none_disables_tokens() {
        assert!(parse_spl_tokens(Some("none")).unwrap().is_empty());
        assert!(parse_spl_tokens(Some("off")).unwrap().is_empty());
    }

    #[test]
    fn parse_custom_token_list() {
        let entries = parse_spl_tokens(Some(&format!(
            "USDT:{}:6, USDC:{}:6",
            USDC_MAINNET_MINT, USDC_MAINNET_MINT
        )))
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].symbol, "USDT");
        assert_eq!(entries[1].symbol, "USDC");
    }

    #[test]
    fn rejects_malformed_token_entries() {
        assert!(parse_spl_tokens(Some("USDC")).is_err());
        assert!(parse_spl_tokens(Some("USDC:not_a_pubkey:6")).is_err());
        assert!(parse_spl_tokens(Some(&format!("USDC:{}:bad", USDC_MAINNET_MINT))).is_err());
    }

    #[test]
    fn transfer_checked_data_layout() {
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let source = Pubkey::new_unique();
        let destination = Pubkey::new_unique();
        let instruction =
            spl_transfer_checked_instruction(&source, &mint, &destination, &owner, 1_000_000, 6);

        assert_eq!(instruction.program_id, token_program_id());
        assert_eq!(instruction.data[0], 12);
        assert_eq!(
            u64::from_le_bytes(instruction.data[1..9].try_into().unwrap()),
            1_000_000
        );
        assert_eq!(instruction.data[9], 6);
        assert_eq!(instruction.accounts.len(), 4);
        assert!(instruction.accounts[3].is_signer);
    }
}
