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
//! The provider also exposes [`CloudflareProvider::list_access_rules`],
//! [`CloudflareProvider::delete_access_rule`] and [`CloudflareProvider::verify`]
//! for the `sentry cloudflare status` / `test` CLI commands and for the
//! background reaper that removes expired rules.
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
use serde::{Deserialize, Serialize};
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

    /// Remove an IP from the cache (undo an optimistic registration when the
    /// API call failed, so a future event can retry).
    async fn evict(&self, ip: IpAddr) {
        let mut cache = self.cache.write().await;
        cache.remove(&ip);
    }

    /// Number of IPs currently tracked in the local cache (rules we believe
    /// are active at the edge within their TTL window).
    pub async fn tracked_count(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Return the IPs whose local cache entry has expired (i.e. should be
    /// reaped at the edge). Used by the daemon's background reaper.
    pub async fn expired_keys(&self) -> Vec<IpAddr> {
        let now = Instant::now();
        self.cache
            .read()
            .await
            .iter()
            .filter(|(_, exp)| **exp <= now)
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Forget an IP locally (after the reaper deleted it at the edge or the
    /// TTL expired). Does not call the API.
    pub async fn forget(&self, ip: IpAddr) {
        self.evict(ip).await;
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

    fn zones_url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/zones/{}",
            self.cfg.zone
        )
    }

    /// Verify the API token and zone. Returns `(token_valid, zone_name)`.
    ///
    /// Used by `sentry cloudflare status` / `test`.
    pub async fn verify(&self) -> Result<(bool, String)> {
        let verify_url = "https://api.cloudflare.com/client/v4/user/tokens/verify";
        let resp = self
            .http
            .get(verify_url)
            .bearer_auth(&self.cfg.token)
            .send()
            .await
            .map_err(|e| {
                sentry_core::error::CoreError::Challenge(format!("verify request: {e}"))
            })?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let token_valid = status.is_success()
            && body
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        if !token_valid {
            return Ok((false, String::new()));
        }
        let zone_url = self.zones_url();
        let zresp = self
            .http
            .get(&zone_url)
            .bearer_auth(&self.cfg.token)
            .send()
            .await
            .map_err(|e| sentry_core::error::CoreError::Challenge(format!("zone request: {e}")))?;
        let zbody: serde_json::Value = zresp.json().await.unwrap_or_default();
        let zone_name = zbody
            .get("result")
            .and_then(|r| r.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        Ok((token_valid, zone_name))
    }

    /// List IP Access Rules for the zone (paginated).
    ///
    /// Used by `sentry cloudflare status` and the reaper task.
    pub async fn list_access_rules(&self) -> Result<Vec<AccessRule>> {
        let mut all = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!(
                "{}/firewall/access_rules/rules?per_page=50&page={page}",
                self.zones_url()
            );
            let resp = match self
                .http
                .get(&url)
                .bearer_auth(&self.cfg.token)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return Err(sentry_core::error::CoreError::Challenge(format!(
                        "list access rules: {e}"
                    )))
                }
            };
            let body: AccessRulesResponse = resp.json().await.unwrap_or_default();
            let got = body.result.len();
            all.extend(body.result);
            if got < 50 || page > 50 {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    /// Delete an IP Access Rule by id.
    pub async fn delete_access_rule(&self, rule_id: &str) -> Result<()> {
        let url = format!("{}/firewall/access_rules/rules/{rule_id}", self.zones_url());
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.cfg.token)
            .send()
            .await
            .map_err(|e| {
                sentry_core::error::CoreError::Challenge(format!("delete access rule: {e}"))
            })?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(sentry_core::error::CoreError::Challenge(format!(
                "delete access rule {rule_id} failed: {body}"
            )));
        }
        info!(rule_id, "deleted cloudflare access rule");
        Ok(())
    }
}

/// A single Cloudflare IP Access Rule entry (subset of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    /// Rule id (used for deletion).
    pub id: String,
    /// Mode: `block` | `challenge` | `js_challenge` | `managed_challenge` | `whitelist`.
    #[serde(default)]
    pub mode: String,
    /// Configuration: target + value.
    #[serde(default)]
    pub configuration: AccessRuleConfig,
    /// Notes (Sentry marks rules with `"sentry"`).
    #[serde(default)]
    pub notes: Option<String>,
}

/// The `configuration` block of an access rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessRuleConfig {
    /// `ip` or `ip6`.
    #[serde(default)]
    pub target: String,
    /// The IP value.
    #[serde(default)]
    pub value: String,
}

/// Envelope for the access-rules list response.
#[derive(Debug, Default, Deserialize)]
struct AccessRulesResponse {
    #[serde(default)]
    result: Vec<AccessRule>,
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

        // Register locally BEFORE the request: this closes the dedup window
        // so concurrent events for the same IP don't all fire API calls, and
        // keeps the backend's view of "how many rules I've created" accurate
        // even if the request is slow or the response is dropped.
        self.record(ip, ttl).await;

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
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    info!(ip = %ip, mode = cf_mode, "cloudflare access rule created");
                } else if is_duplicate_rule(&body_text) {
                    // Idempotent: rule already exists for this IP — the cache
                    // entry we pre-registered is correct, nothing to undo.
                    info!(ip = %ip, mode = cf_mode, "cloudflare access rule already exists");
                } else {
                    // API rejected the rule. Evict our optimistic cache entry
                    // so a later retry can attempt the call again.
                    warn!(ip = %ip, status = %status, body = %body_text, "cloudflare API error");
                    self.evict(ip).await;
                }
            }
            Err(e) => {
                // Network failure: evict so a future event can retry within
                // the same TTL window instead of being silently skipped.
                warn!(ip = %ip, error = %e, "cloudflare request failed");
                self.evict(ip).await;
            }
        }

        self.prune().await;
        Ok(())
    }
}

/// Detect whether a Cloudflare API error body means the access rule already
/// exists (error code 9999 or a message mentioning "exists").
fn is_duplicate_rule(body: &str) -> bool {
    body.contains("\"code\":9999")
        || body.contains("already exists")
        || body.contains("Access rule already exists")
}
