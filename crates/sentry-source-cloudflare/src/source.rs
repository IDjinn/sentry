//! Polling source for Cloudflare zone logs (Logpull `logs/received`).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use sentry_core::error::{CoreError, Result};
use sentry_core::event::RawEvent;
use sentry_core::source::{event_channel, send_or_log, Source};
use tokio::sync::mpsc;

use crate::parser::parse_line;

/// Cloudflare source configuration.
#[derive(Debug, Clone)]
pub struct CloudflareSourceConfig {
    /// Cloudflare zone identifier (32 hex chars).
    pub zone_id: String,
    /// API token with Logs:Read permission.
    pub api_token: String,
    /// Seconds between polls (default 30).
    pub poll_secs: u64,
    /// Pull logs starting at this instant on first poll (default: now).
    pub start_at: Option<DateTime<Utc>>,
    /// API base override (tests / on-prem proxies).
    pub api_base: String,
}

impl Default for CloudflareSourceConfig {
    fn default() -> Self {
        Self {
            zone_id: String::new(),
            api_token: String::new(),
            poll_secs: 30,
            start_at: None,
            api_base: "https://api.cloudflare.com/client/v4".to_string(),
        }
    }
}

/// Pulls Cloudflare zone logs on a fixed interval.
#[derive(Debug)]
pub struct CloudflareSource {
    cfg: CloudflareSourceConfig,
    http: reqwest::Client,
}

impl CloudflareSource {
    /// Validate config and build the source.
    pub fn new(cfg: CloudflareSourceConfig) -> Result<Self> {
        if cfg.zone_id.trim().is_empty() {
            return Err(CoreError::Config(
                "cloudflare source requires `zone_id`".into(),
            ));
        }
        if cfg.api_token.trim().is_empty() {
            return Err(CoreError::Config(
                "cloudflare source requires an API token (token_env, default SENTRY_CF_TOKEN)"
                    .into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| CoreError::Config(format!("reqwest client: {e}")))?;
        Ok(Self { cfg, http })
    }
}

/// Bounded RayID dedupe: replayed windows must not double-count requests.
#[derive(Default)]
struct RayIdDedupe {
    seen: std::collections::HashSet<String>,
    cap: usize,
}

impl RayIdDedupe {
    fn new(cap: usize) -> Self {
        Self {
            seen: Default::default(),
            cap,
        }
    }

    /// `true` when this RayID was not seen before.
    fn insert(&mut self, ray_id: &str) -> bool {
        if self.seen.len() >= self.cap {
            self.seen.clear();
        }
        self.seen.insert(ray_id.to_string())
    }
}

/// Format a timestamp the Logs API accepts (RFC3339 UTC).
fn fmt_ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[async_trait]
impl Source for CloudflareSource {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn stream(&self) -> Result<mpsc::Receiver<RawEvent>> {
        let (tx, rx) = event_channel(1024);
        let cfg = self.cfg.clone();
        let http = self.http.clone();
        tokio::spawn(async move {
            // Cursor: next poll starts where the previous ended.
            let mut cursor = cfg.start_at.unwrap_or_else(Utc::now);
            let mut dedupe = RayIdDedupe::new(100_000);
            loop {
                let end = Utc::now();
                if end > cursor {
                    let url = format!(
                        "{}/zones/{}/logs/received?start={}&end={}",
                        cfg.api_base.trim_end_matches('/'),
                        cfg.zone_id,
                        fmt_ts(cursor),
                        fmt_ts(end)
                    );
                    match http.get(&url).bearer_auth(&cfg.api_token).send().await {
                        Ok(resp) if resp.status().is_success() => match resp.text().await {
                            Ok(body) => {
                                let mut newest = cursor;
                                for line in body.lines() {
                                    let Some(line) = parse_line(line) else {
                                        continue;
                                    };
                                    if let Some(ts) = line.timestamp() {
                                        if ts > newest {
                                            newest = ts;
                                        }
                                    }
                                    let replayed = line
                                        .ray_id
                                        .as_deref()
                                        .map(|ray| !dedupe.insert(ray))
                                        .unwrap_or(false);
                                    if replayed {
                                        continue;
                                    }
                                    if let Some((_ip, evt)) = line.into_raw_event() {
                                        send_or_log(&tx, evt, "cloudflare");
                                    }
                                }
                                cursor = newest.max(end);
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "cloudflare logs body read failed");
                            }
                        },
                        Ok(resp) => {
                            tracing::warn!(
                                status = %resp.status(),
                                "cloudflare logs poll failed (Logs API requires an Enterprise entitlement)"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "cloudflare logs request failed");
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(cfg.poll_secs.max(5))).await;
            }
        });
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_admits_new_and_rejects_repeats() {
        let mut d = RayIdDedupe::new(4);
        assert!(d.insert("a"));
        assert!(!d.insert("a"));
        assert!(d.insert("b"));
    }

    #[test]
    fn dedupe_clears_at_capacity() {
        let mut d = RayIdDedupe::new(2);
        assert!(d.insert("a"));
        assert!(d.insert("b"));
        assert!(d.insert("c")); // cap hit → cleared → c admitted
        assert!(d.insert("a")); // a forgotten after clear
    }

    #[test]
    fn ts_format_is_rfc3339_utc() {
        let t = DateTime::parse_from_rfc3339("2026-09-30T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(fmt_ts(t), "2026-09-30T12:00:00Z");
    }

    #[tokio::test]
    async fn config_validation_rejects_missing_fields() {
        let err = CloudflareSource::new(CloudflareSourceConfig::default()).unwrap_err();
        assert!(err.to_string().contains("zone_id"));
        let err = CloudflareSource::new(CloudflareSourceConfig {
            zone_id: "abc123".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("token"));
    }
}
