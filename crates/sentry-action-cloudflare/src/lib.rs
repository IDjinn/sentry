//! Cloudflare action plugin.
//!
//! Executes block / challenge / rate-limit via the Cloudflare API when the
//! decider emits a matching verdict. Keeps a local in-memory cache of IPs
//! already acted on (with TTL) to avoid hammering the API.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentry_core::action::Action;
use sentry_core::analysis::Verdict;
use sentry_core::error::Result;
use sentry_core::event::Event;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Cloudflare action configuration.
#[derive(Debug, Clone)]
pub struct CloudflareActionConfig {
    /// API token (env: `SENTRY_CF_TOKEN`).
    pub token: String,
    /// Zone id (env: `SENTRY_CF_ZONE`).
    pub zone: String,
    /// Challenge mode: `block` | `js_challenge` | `managed_challenge`.
    pub mode: ChallengeMode,
    /// How long to keep an IP blocked/challenged.
    pub ttl: Duration,
}

/// Challenge mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeMode {
    Block,
    JsChallenge,
    ManagedChallenge,
}

impl ChallengeMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::JsChallenge => "js_challenge",
            Self::ManagedChallenge => "managed_challenge",
        }
    }
}

/// Cloudflare action.
pub struct CloudflareAction {
    cfg: CloudflareActionConfig,
    http: reqwest::Client,
    /// Cache of IP → expiry instant. Prevents duplicate API calls.
    cache: Arc<RwLock<HashMap<IpAddr, Instant>>>,
}

impl CloudflareAction {
    /// Create a new Cloudflare action.
    pub fn new(cfg: CloudflareActionConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        Self {
            cfg,
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns `true` if `ip` is already in the cache and not expired.
    async fn is_cached(&self, ip: IpAddr) -> bool {
        let cache = self.cache.read().await;
        cache.get(&ip).map(|t| *t > Instant::now()).unwrap_or(false)
    }

    /// Record that we acted on `ip`.
    async fn record(&self, ip: IpAddr) {
        let mut cache = self.cache.write().await;
        cache.insert(ip, Instant::now() + self.cfg.ttl);
    }

    /// Prune expired entries (called opportunistically).
    async fn prune(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, exp| *exp > now);
    }
}

#[async_trait]
impl Action for CloudflareAction {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    fn applies_to(&self, decision: &sentry_core::analysis::Decision) -> bool {
        matches!(
            decision.action,
            Verdict::Block | Verdict::Challenge | Verdict::RateLimit
        )
    }

    async fn execute(
        &self,
        evt: &Event,
        _decision: &sentry_core::analysis::Decision,
    ) -> Result<()> {
        let ip = evt.client_ip;
        if self.is_cached(ip).await {
            return Ok(());
        }

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/firewall/rules",
            self.cfg.zone
        );
        let body = serde_json::json!({
            "mode": self.cfg.mode.as_str(),
            "configuration": {
                "target": "ip",
                "value": ip.to_string(),
            },
            "ttl": self.cfg.ttl.as_secs(),
        });

        match self
            .http
            .post(&url)
            .bearer_auth(&self.cfg.token)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    info!(ip = %ip, mode = self.cfg.mode.as_str(), "cloudflare rule created");
                    self.record(ip).await;
                    self.prune().await;
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    warn!(ip = %ip, status = %status, body, "cloudflare API error");
                }
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "cloudflare request failed");
            }
        }

        Ok(())
    }
}
