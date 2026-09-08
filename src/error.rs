use std::fmt;

pub enum DetectorError {
    InvalidXpub(String),
    DerivationFailed { index: u32, reason: String },
    ApiError(String),
    WebhookError(String),
    AuthenticationFailed,
    InvalidConfig(String),
    HttpError(reqwest::Error),
    SerializationError(serde_json::Error),
    RedisError(String),
    BitcoinError(String),
}

impl From<reqwest::Error> for DetectorError {
    fn from(error: reqwest::Error) -> Self {
        Self::HttpError(error)
    }
}

impl From<serde_json::Error> for DetectorError {
    fn from(error: serde_json::Error) -> Self {
        Self::SerializationError(error)
    }
}

impl fmt::Display for DetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidXpub(message) => {
                write!(formatter, "Invalid xpub key: {}", redact_urls(message))
            }
            Self::DerivationFailed { index, reason } => write!(
                formatter,
                "Address derivation failed for index {index}: {}",
                redact_urls(reason)
            ),
            Self::ApiError(message) => {
                write!(formatter, "API request failed: {}", redact_urls(message))
            }
            Self::WebhookError(message) => {
                write!(
                    formatter,
                    "Webhook delivery failed: {}",
                    redact_urls(message)
                )
            }
            Self::AuthenticationFailed => formatter.write_str("Authentication failed"),
            Self::InvalidConfig(message) => {
                write!(formatter, "Invalid configuration: {}", redact_urls(message))
            }
            Self::HttpError(error) => {
                write!(formatter, "HTTP error: {}", request_error_kind(error))
            }
            Self::SerializationError(error) => {
                write!(formatter, "Serialization error: {error}")
            }
            Self::RedisError(message) => {
                write!(formatter, "Redis error: {}", redact_urls(message))
            }
            Self::BitcoinError(message) => {
                write!(formatter, "Bitcoin key error: {}", redact_urls(message))
            }
        }
    }
}

// Debug output is deliberately as safe as Display. A future tracing field
// using ?error must not bring reqwest's stored request URL back into logs.
impl fmt::Debug for DetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for DetectorError {}

fn request_error_kind(error: &reqwest::Error) -> String {
    if let Some(status) = error.status() {
        return format!("upstream returned {status}");
    }
    if error.is_timeout() {
        return "request timed out".into();
    }
    if error.is_connect() {
        return "connection failed".into();
    }
    if error.is_decode() {
        return "response decoding failed".into();
    }
    if error.is_builder() {
        return "request construction failed".into();
    }
    "request failed".into()
}

/// Remove complete URLs from messages before they reach logs or API errors.
///
/// Provider URLs often carry an API token in the path, query, or user-info.
/// Keeping only the scheme is enough to distinguish transport families while
/// preventing those credentials from being copied into log aggregation.
fn redact_urls(message: &str) -> String {
    let mut output = String::with_capacity(message.len());
    let mut cursor = 0;

    while let Some(relative_separator) = message[cursor..].find("://") {
        let separator = cursor + relative_separator;
        let mut start = separator;
        while start > cursor {
            let byte = message.as_bytes()[start - 1];
            if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.') {
                start -= 1;
            } else {
                break;
            }
        }

        let scheme = &message[start..separator];
        if scheme.is_empty()
            || !scheme.as_bytes()[0].is_ascii_alphabetic()
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            output.push_str(&message[cursor..separator + 3]);
            cursor = separator + 3;
            continue;
        }

        output.push_str(&message[cursor..start]);
        output.push_str(scheme);
        output.push_str("://[redacted]");

        let mut end = separator + 3;
        while end < message.len() {
            let byte = message.as_bytes()[end];
            if byte.is_ascii_whitespace()
                || matches!(byte, b')' | b']' | b'}' | b'>' | b'"' | b'\'' | b',' | b';')
            {
                break;
            }
            end += 1;
        }
        cursor = end;
    }

    output.push_str(&message[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_provider_tokens_in_paths_queries_and_user_info() {
        let message = "RPC failed for https://endpoint.example/token-value/?key=secret; \
                       proxy http://user:password@proxy.example:8080/path";
        let redacted = redact_urls(message);

        assert_eq!(
            redacted,
            "RPC failed for https://[redacted]; proxy http://[redacted]"
        );
        for secret in ["token-value", "secret", "user", "password"] {
            assert!(!redacted.contains(secret));
        }
    }

    #[test]
    fn display_and_debug_never_expose_api_urls() {
        let error = DetectorError::ApiError(
            "eth_chainId failed: https://node.example/private-token/".into(),
        );

        assert_eq!(
            error.to_string(),
            "API request failed: eth_chainId failed: https://[redacted]"
        );
        assert_eq!(format!("{error:?}"), error.to_string());
    }

    #[test]
    fn leaves_messages_without_urls_unchanged() {
        assert_eq!(
            redact_urls("connection refused (os error 111)"),
            "connection refused (os error 111)"
        );
    }
}
