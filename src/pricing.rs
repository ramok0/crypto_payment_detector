use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::error::DetectorError;
use crate::types::Chain;

#[derive(Debug, Clone)]
struct PriceCache {
    price: f64,
    fetched_at: Instant,
}

#[derive(Debug, Deserialize)]
struct KrakenResponse {
    error: Vec<String>,
    result: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct PriceFetcher {
    client: reqwest::Client,
    pair: String,
    currency: String,
    chain: Chain,
    cache_ttl: Duration,
    cache: Arc<Mutex<Option<PriceCache>>>,
}

impl PriceFetcher {
    pub fn new(client: reqwest::Client, currency: &str, chain: Chain) -> Self {
        let pair = kraken_pair(chain, currency);
        Self {
            client,
            pair,
            currency: currency.to_uppercase(),
            chain,
            cache_ttl: Duration::from_secs(30),
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_price(&self) -> Result<f64, DetectorError> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(ref entry) = *cache {
                if entry.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(entry.price);
                }
            }
        }

        let price = self.fetch_from_kraken().await?;

        {
            let mut cache = self.cache.lock().unwrap();
            *cache = Some(PriceCache {
                price,
                fetched_at: Instant::now(),
            });
        }

        Ok(price)
    }

    pub async fn sats_to_fiat(&self, amount_sat: u64) -> Result<f64, DetectorError> {
        let price = self.get_price().await?;
        let coin = amount_sat as f64 / self.chain.sats_per_unit() as f64;
        Ok(coin * price)
    }

    pub fn currency(&self) -> &str {
        &self.currency
    }

    async fn fetch_from_kraken(&self) -> Result<f64, DetectorError> {
        let url = format!(
            "https://api.kraken.com/0/public/Ticker?pair={}",
            self.pair
        );

        let resp: KrakenResponse = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| DetectorError::ApiError(format!("Kraken API request failed: {e}")))?
            .json()
            .await
            .map_err(|e| DetectorError::ApiError(format!("Kraken API parse failed: {e}")))?;

        if !resp.error.is_empty() {
            return Err(DetectorError::ApiError(format!(
                "Kraken API error: {}",
                resp.error.join(", ")
            )));
        }

        let result = resp
            .result
            .ok_or_else(|| DetectorError::ApiError("Kraken API returned no result".into()))?;

        let pair_data = result
            .as_object()
            .and_then(|m| m.values().next())
            .ok_or_else(|| DetectorError::ApiError("Kraken: unexpected response format".into()))?;

        let price_str = pair_data
            .get("c")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DetectorError::ApiError("Kraken: could not extract price from response".into())
            })?;

        let price: f64 = price_str
            .parse()
            .map_err(|e| DetectorError::ApiError(format!("Kraken: failed to parse price: {e}")))?;

        log::debug!(
            "Kraken {}/{} price: {:.2}",
            self.chain.ticker(),
            self.currency,
            price
        );
        Ok(price)
    }
}

fn kraken_pair(chain: Chain, currency: &str) -> String {
    let base = match chain {
        Chain::Bitcoin => "XBT",
        Chain::Litecoin => "LTC",
    };
    let fiat = currency.to_uppercase();
    match chain {
        Chain::Bitcoin => match fiat.as_str() {
            "EUR" => "XXBTZEUR".to_string(),
            "USD" => "XXBTZUSD".to_string(),
            "GBP" => "XXBTZGBP".to_string(),
            "CAD" => "XXBTZCAD".to_string(),
            "JPY" => "XXBTZJPY".to_string(),
            "AUD" => "XXBTZAUD".to_string(),
            "CHF" => "XXBTZCHF".to_string(),
            _ => format!("X{}Z{}", base, fiat),
        },
        Chain::Litecoin => format!("LTC{}", fiat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btc_pair() {
        assert_eq!(kraken_pair(Chain::Bitcoin, "EUR"), "XXBTZEUR");
        assert_eq!(kraken_pair(Chain::Bitcoin, "usd"), "XXBTZUSD");
    }

    #[test]
    fn test_ltc_pair() {
        assert_eq!(kraken_pair(Chain::Litecoin, "EUR"), "LTCEUR");
        assert_eq!(kraken_pair(Chain::Litecoin, "usd"), "LTCUSD");
    }
}
