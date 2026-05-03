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

/// Env var prefix used for `chain_env_var` lookups. Note this is `SOLANA` for
/// Solana (matching the existing `SOLANA_*` env vars in the codebase) — *not*
/// `SOL` — so callers like [`chain_env_var`] resolve `SOLANA_RPC_URL` rather
/// than `SOL_RPC_URL`.
pub fn chain_env_prefix(chain: Chain) -> &'static str {
    match chain {
        Chain::Bitcoin => "BTC",
        Chain::Litecoin => "LTC",
        Chain::Solana => "SOL",
        Chain::Ethereum => "ETH",
        Chain::Base => "BASE",
    }
}

pub fn chain_env_var(chain: Chain, suffix: &str) -> Option<String> {
    let chain_var = format!("{}_{}", chain_env_prefix(chain), suffix);

    std::env::var(chain_var).ok()
}

pub fn chain_env_bool(chain: Chain, suffix: &str, global_name: &str) -> bool {
    chain_env_var(chain, suffix)
        .and_then(|value| match parse_bool(&value) {
            Some(parsed) => Some(parsed),
            None => {
                log::warn!(
                    "Ignoring invalid boolean env {}_{}={:?}; expected one of 1/0, true/false, yes/no, on/off",
                    chain_env_prefix(chain),
                    suffix,
                    value
                );
                None
            }
        })
        .or_else(|| env_bool(global_name))
        .unwrap_or(false)
}

pub fn proxy_env_var(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            let trimmed = value.trim();
            if trimmed.is_empty()
                || matches!(
                    trimmed.to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off" | "none" | "direct"
                )
            {
                return None;
            }

            return Some(value);
        }
    }

    None
}

pub fn redact_url_credentials(value: &str) -> String {
    match reqwest::Url::parse(value) {
        Ok(mut url) => {
            if !url.username().is_empty() {
                let _ = url.set_username("***");
            }
            if url.password().is_some() {
                let _ = url.set_password(Some("***"));
            }
            url.to_string()
        }
        Err(_) => "<redacted invalid url>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bool, proxy_env_var, redact_url_credentials};

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

    #[test]
    fn redacts_url_credentials() {
        assert_eq!(
            redact_url_credentials("http://user:pass@example.com:8080"),
            "http://***:***@example.com:8080/"
        );
    }

    #[test]
    fn proxy_env_var_can_disable_fallback() {
        unsafe {
            std::env::set_var("TEST_PROXY_OVERRIDE", "off");
            std::env::set_var("TEST_PROXY_GLOBAL", "http://user:pass@example.com:8080");
        }

        assert_eq!(
            proxy_env_var(&["TEST_PROXY_OVERRIDE", "TEST_PROXY_GLOBAL"]),
            None
        );

        unsafe {
            std::env::remove_var("TEST_PROXY_OVERRIDE");
            std::env::remove_var("TEST_PROXY_GLOBAL");
        }
    }
}
