use crate::types::Chain;

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub fn env_bool(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    match parse_bool(&value) {
        Some(parsed) => Some(parsed),
        None => {
            log::warn!(
                "Ignoring invalid boolean env {}={:?}; expected one of 1/0, true/false, yes/no, on/off",
                name,
                value
            );
            None
        }
    }
}

pub fn chain_env_var(chain: Chain, suffix: &str) -> Option<String> {
    let chain_name = match chain {
        Chain::Bitcoin => "BTC",
        Chain::Litecoin => "LTC",
        Chain::Solana => "SOL",
    };
    let chain_var = format!("{chain_name}_{suffix}");

    std::env::var(chain_var).ok()
}

pub fn chain_env_bool(chain: Chain, suffix: &str, global_name: &str) -> bool {
    chain_env_var(chain, suffix)
        .and_then(|value| match parse_bool(&value) {
            Some(parsed) => Some(parsed),
            None => {
                let chain_name = match chain {
                    Chain::Bitcoin => "BTC",
                    Chain::Litecoin => "LTC",
                    Chain::Solana => "SOL",
                };
                log::warn!(
                    "Ignoring invalid boolean env {}_{}={:?}; expected one of 1/0, true/false, yes/no, on/off",
                    chain_name,
                    suffix,
                    value
                );
                None
            }
        })
        .or_else(|| env_bool(global_name))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::parse_bool;

    #[test]
    fn parses_truthy_values() {
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("YES"), Some(true));
        assert_eq!(parse_bool(" on "), Some(true));
    }

    #[test]
    fn parses_falsey_values() {
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("No"), Some(false));
        assert_eq!(parse_bool(" off "), Some(false));
    }

    #[test]
    fn rejects_unknown_values() {
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool(""), None);
    }
}
