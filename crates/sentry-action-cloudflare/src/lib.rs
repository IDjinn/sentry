//! Cloudflare edge-action provider.
//!
//! Implements [`sentry_core::ChallengeProvider`]: applies block / challenge /
//! rate-limit rules to a client IP via the Cloudflare **IP Access Rules** API
//! (`POST /zones/{zone}/firewall/access_rules/rules`). The legacy
//! `/firewall/rules` endpoint was deprecated on 2025-06-15 (API error 10020,
//! "firewallrules.api.maintenance_mode") and no longer accepts modifications.
//!
//! Keeps a local in-memory cache of IPs already acted on (with TTL) to avoid
//! hammering the API. Note that the access-rules API itself has no `ttl`
//! parameter — rules are permanent at the edge until manually removed; the
//! local cache only guards Sentry's own de-duplication window.
//!
//! Wired into the daemon either as `type = "cloudflare"` (backward-compatible
//! alias) or as `type = "challenge"`, `provider = "cloudflare"` (canonical
//! provider-agnostic form). See `sentry-core::challenge`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentry_core::analysis::Verdict;
use sentry_core::challenge::{ChallengeProvider, EdgeMode, EdgeOptions};
use sentry_core::error::Result;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Cloudflare provider configuration.
#[derive(Debug, Clone)]
pub struct CloudflareProviderConfig {
    /// API token (env: `SENTRY_CF_TOKEN`).
    pub token: String,
    /// Zone id (env: `SENTRY_CF_ZONE`).
    pub zone: String,
    /// Default challenge mode when the pipeline verdict is `Challenge` and
    /// no explicit mode is supplied via [`EdgeOptions`].
    pub default_mode: EdgeMode,
    /// How long to keep an IP blocked/challenged, when not overridden by
    /// [`EdgeOptions::ttl`].
    pub ttl: Duration,
}

/// Cloudflare [`ChallengeProvider`] implementation.
pub struct CloudflareProvider {
    cfg: CloudflareProviderConfig,
    http: reqwest::Client,
    /// Cache of IP → expiry instant. Prevents duplicate API calls.
    cache: Arc<RwLock<HashMap<IpAddr, Instant>>>,
}

impl CloudflareProvider {
    /// Create a new Cloudflare provider.
    pub fn new(cfg: CloudflareProviderConfig) -> Self {
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
    async fn record(&self, ip: IpAddr, ttl: Duration) {
        let mut cache = self.cache.write().await;
        cache.insert(ip, Instant::now() + ttl);
    }

    /// Prune expired entries (called opportunistically).
    async fn prune(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, exp| *exp > now);
    }

    /// Resolve the Cloudflare firewall-rule `mode` for a given verdict.
    ///
    /// - `Block` → `block` (hard block, regardless of configured mode).
    /// - `Challenge` → the configured [`EdgeOptions::mode`], falling back to
    ///   the provider's `default_mode`.
    /// - `RateLimit` → `rate_limit`.
    /// - `Allow` / `Quarantine` never reach here (filtered by
    ///   [`sentry_core::ChallengeAction`]).
    fn resolve_mode(&self, verdict: Verdict, opts: &EdgeOptions) -> EdgeMode {
        match verdict {
            Verdict::Block => EdgeMode::Block,
            Verdict::Challenge => opts.mode_or(self.cfg.default_mode),
            Verdict::RateLimit => EdgeMode::RateLimit,
            // Defensive: should never be called for these.
            Verdict::Allow | Verdict::Quarantine => opts.mode_or(self.cfg.default_mode),
        }
    }

    /// Map an [`EdgeMode`] to the Cloudflare IP Access Rules `mode` string.
    ///
    /// `Block` / `JsChallenge` / `ManagedChallenge` map directly. `RateLimit`
    /// is not supported by the access-rules API (rate limiting requires the
    /// Rulesets API); we fall back to `block` and emit a warning so the action
    /// still protects the zone.
    fn access_rule_mode(&self, mode: EdgeMode) -> &'static str {
        match mode {
            EdgeMode::Block => "block",
            EdgeMode::JsChallenge => "js_challenge",
            EdgeMode::ManagedChallenge => "managed_challenge",
            EdgeMode::RateLimit => {
                warn!(
                    "cloudflare IP Access rules do not support rate limiting; \
                     falling back to block"
                );
                "block"
            }
        }
    }

    /// Cloudflare access rules require distinct `target` values for IPv4 (`ip`)
    /// vs IPv6 (`ip6`).
    fn access_rule_target(ip: IpAddr) -> &'static str {
        match ip {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        }
    }
}

#[async_trait]
impl ChallengeProvider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn apply(&self, ip: IpAddr, verdict: Verdict, opts: &EdgeOptions) -> Result<()> {
        if self.is_cached(ip).await {
            return Ok(());
        }

        let ttl = if opts.ttl.is_zero() {
            self.cfg.ttl
        } else {
            opts.ttl
        };
        let mode = self.resolve_mode(verdict, opts);
        let cf_mode = self.access_rule_mode(mode);
        let target = Self::access_rule_target(ip);

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/firewall/access_rules/rules",
            self.cfg.zone
        );
        let body = serde_json::json!({
            "mode": cf_mode,
            "configuration": {
                "target": target,
                "value": ip.to_string(),
            },
            "notes": "sentry",
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
                    info!(ip = %ip, mode = cf_mode, "cloudflare access rule created");
                    self.record(ip, ttl).await;
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
