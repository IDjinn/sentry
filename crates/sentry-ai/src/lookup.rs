//! On-demand IP reputation lookup (F7.5).
//!
//! Complements the pull-based feeds: instead of importing a whole
//! blocklist, a single client IP is queried at a provider when the local
//! pipeline lands in the "gray band" — elevated score but not enough to
//! act, or suspicious signals — and the answer feeds back through
//! [`Pipeline::rescore_from`](sentry_core::pipeline::Pipeline::rescore_from)
//! (which can only raise the verdict).
//!
//! The trigger, caching and quota live in the daemon's fork (mirroring the
//! AI/LLM forks); this module only defines the provider contract and the
//! AbuseIPDB implementation (`GET /api/v2/check`).

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

/// Lookup outcome: the provider's confidence score (0-100).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpLookupResult {
    /// Provider confidence score, 0-100 (AbuseIPDB `abuseConfidenceScore`).
    pub score: u8,
    /// Provider name for the signal detail.
    pub provider: &'static str,
}

/// A per-IP external reputation lookup provider.
#[async_trait]
pub trait IpLookupProvider: Send + Sync {
    /// Stable provider name.
    fn name(&self) -> &'static str;

    /// Look up `ip`; errors are transport/API failures (cached negatively
    /// by the caller's quota logic, not by value).
    async fn check(&self, ip: std::net::IpAddr) -> Result<IpLookupResult, String>;
}

/// AbuseIPDB `GET /api/v2/check` implementation.
pub struct AbuseIpDbLookup {
    key: String,
    http: reqwest::Client,
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct CheckResponse {
    data: CheckData,
}

#[derive(Debug, Deserialize)]
struct CheckData {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8,
}

impl AbuseIpDbLookup {
    /// Create from an API key; `endpoint` overrides the default API base
    /// (tests / proxies).
    pub fn new(key: String, endpoint: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        Self {
            key,
            http,
            endpoint: endpoint.unwrap_or_else(|| "https://api.abuseipdb.com/api/v2".to_string()),
        }
    }
}

#[async_trait]
impl IpLookupProvider for AbuseIpDbLookup {
    fn name(&self) -> &'static str {
        "abuseipdb"
    }

    async fn check(&self, ip: std::net::IpAddr) -> Result<IpLookupResult, String> {
        // IPs (hex, dots, colons) are query-safe per RFC 3986 — no encoding.
        let url = format!(
            "{}/check?ipAddress={}&maxAgeInDays=30",
            self.endpoint.trim_end_matches('/'),
            ip
        );
        let resp = self
            .http
            .get(url)
            .header("Key", &self.key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let parsed: CheckResponse = resp.json().await.map_err(|e| e.to_string())?;
        Ok(IpLookupResult {
            score: parsed.data.abuse_confidence_score.min(100),
            provider: "abuseipdb",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The response schema parses with the documented field names.
    #[test]
    fn parses_check_response() {
        let body = r#"{"data":{"ipAddress":"198.51.100.7","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":75,"countryCode":"US","totalReports":12,"numDistinctUsers":5,"lastReportedAt":"2026-10-01T00:00:00+00:00"}}"#;
        let parsed: CheckResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.data.abuse_confidence_score, 75);
    }
}
