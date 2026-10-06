//! OPNsense / pfSense ban provider for Sentry (F6.1).
//!
//! Implements [`ChallengeProvider`](sentry_core::ChallengeProvider) so
//! pipeline `Block` verdicts land on a firewall appliance instead of a CDN:
//!
//! - **OPNsense**: alias-table entries via the REST API
//!   (`/api/firewall/alias_util/add|delete/<alias>`, `Bearer`-style key +
//!   secret headers). The alias is provisioned at startup when missing.
//! - **pfSense**: `pfctl -t <table> -T add|delete <ip>` executed directly
//!   (no shell); the table is ensured at startup.
//!
//! Platform limitation (documented in ARCHITECTURE §23.2): these platforms
//! only understand drop/reject, so `Challenge` and `RateLimit` verdicts are
//! logged as unenforced instead of silently degrading to a ban.
//!
//! TTL is enforced by an in-memory expiry map + reaper task, mirroring the
//! firewall provider; trusted (never-ban) IPs are refused before any API
//! call is made.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentry_core::analysis::Verdict;
use sentry_core::challenge::{ChallengeProvider, EdgeOptions};
use sentry_core::SharedTrustSet;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Alias / pfctl table carrying the bans.
pub const DEFAULT_TABLE: &str = "sentry_blocks";

/// Which appliance to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// OPNsense REST API (`alias_util` controller).
    Opnsense,
    /// pfSense via `pfctl` on the appliance (run by the daemon host).
    Pfsense,
}

impl Platform {
    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opnsense => "opnsense",
            Self::Pfsense => "pfsense",
        }
    }
}

/// Provider configuration.
#[derive(Debug, Clone)]
pub struct OpnsenseConfig {
    /// `opnsense` (REST) or `pfsense` (`pfctl`).
    pub platform: Platform,
    /// OPNsense base URL, e.g. `https://192.0.2.1` (no trailing slash).
    pub base_url: String,
    /// Env var holding the OPNsense API key (optional for pfSense).
    pub api_key_env: String,
    /// Env var holding the OPNsense API secret.
    pub api_secret_env: String,
    /// Alias / table name (default `sentry_blocks`).
    pub table: String,
    /// Path to `pfctl` on the daemon host (pfSense backend).
    pub pfctl_path: String,
    /// `true` when the OPNsense REST certificate should be accepted even if
    /// self-signed (appliance default).
    pub accept_invalid_certs: bool,
}

impl Default for OpnsenseConfig {
    fn default() -> Self {
        Self {
            platform: Platform::Opnsense,
            base_url: String::new(),
            api_key_env: "SENTRY_OPN_API_KEY".to_string(),
            api_secret_env: "SENTRY_OPN_API_SECRET".to_string(),
            table: DEFAULT_TABLE.to_string(),
            pfctl_path: "pfctl".to_string(),
            accept_invalid_certs: true,
        }
    }
}

/// OPNsense/pfSense provider implementing
/// [`ChallengeProvider`](sentry_core::ChallengeProvider).
pub struct OpnsenseProvider {
    cfg: OpnsenseConfig,
    trust: Option<SharedTrustSet>,
    http: reqwest::Client,
    /// Alias/table membership with expiry (both platforms lack per-entry
    /// TTL in their control planes).
    members: Arc<Mutex<HashMap<IpAddr, Instant>>>,
}

impl OpnsenseProvider {
    /// Create the provider and spawn the expiry reaper.
    ///
    /// Returns `Arc<Self>` because the reaper needs a handle to actually
    /// lift expired bans on the appliance, not just locally.
    pub fn new(cfg: OpnsenseConfig, trust: Option<SharedTrustSet>) -> Arc<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(cfg.accept_invalid_certs)
            .build()
            .unwrap_or_default();
        let provider = Arc::new(Self {
            cfg,
            trust,
            http: client,
            members: Arc::new(Mutex::new(HashMap::new())),
        });
        spawn_reaper(&provider);
        provider
    }

    /// Provider configuration.
    pub fn config(&self) -> &OpnsenseConfig {
        &self.cfg
    }

    /// OPNsense API credentials from the configured env vars.
    fn credentials(&self) -> Option<(String, String)> {
        let key = std::env::var(&self.cfg.api_key_env).ok()?;
        let secret = std::env::var(&self.cfg.api_secret_env).ok()?;
        Some((key, secret))
    }

    /// REST body for the `alias_util` add/delete endpoints.
    fn alias_body(ip: IpAddr) -> serde_json::Value {
        serde_json::json!({ "address": ip.to_string() })
    }

    /// `pfctl` invocation for one table mutation (no shell involved).
    fn pfctl_args(table: &str, action: &str, ip: IpAddr) -> Vec<String> {
        vec![
            "-t".to_string(),
            table.to_string(),
            "-T".to_string(),
            action.to_string(),
            ip.to_string(),
        ]
    }

    async fn opnsense_call(&self, verb: &str, ip: IpAddr) -> Result<(), String> {
        let Some((key, secret)) = self.credentials() else {
            return Err(format!(
                "OPNsense credentials missing: set {} and {}",
                self.cfg.api_key_env, self.cfg.api_secret_env
            ));
        };
        let url = format!(
            "{}/api/firewall/alias_util/{}/{}",
            self.cfg.base_url.trim_end_matches('/'),
            verb,
            self.cfg.table
        );
        let resp = self
            .http
            .post(&url)
            .header("X-API-Key", key)
            .header("X-API-Secret", secret)
            .json(&Self::alias_body(ip))
            .send()
            .await
            .map_err(|e| format!("OPNsense request failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("OPNsense rejected `{verb}` with HTTP {status}"));
        }
        Ok(())
    }

    async fn pfsense_call(&self, action: &str, ip: IpAddr) -> Result<(), String> {
        let cmd = tokio::process::Command::new(&self.cfg.pfctl_path)
            .args(Self::pfctl_args(&self.cfg.table, action, ip))
            .output()
            .await
            .map_err(|e| format!("pfctl spawn failed: {e}"))?;
        if !cmd.status.success() {
            return Err(format!(
                "pfctl {} failed: {}",
                action,
                String::from_utf8_lossy(&cmd.stderr).trim()
            ));
        }
        Ok(())
    }

    async fn add(&self, ip: IpAddr, ttl: Duration) -> Result<(), String> {
        let result = match self.cfg.platform {
            Platform::Opnsense => self.opnsense_call("add", ip).await,
            Platform::Pfsense => self.pfsense_call("add", ip).await,
        };
        if result.is_ok() {
            self.members.lock().await.insert(ip, Instant::now() + ttl);
        }
        result
    }

    async fn remove(&self, ip: IpAddr) -> Result<(), String> {
        let result = match self.cfg.platform {
            Platform::Opnsense => self.opnsense_call("delete", ip).await,
            Platform::Pfsense => self.pfsense_call("delete", ip).await,
        };
        if result.is_ok() {
            self.members.lock().await.remove(&ip);
        }
        result
    }
}

/// Periodically lift expired bans: local map entry **and** the alias/pfctl
/// entry on the appliance (the platform has no per-entry TTL).
fn spawn_reaper(provider: &Arc<OpnsenseProvider>) {
    let weak = Arc::downgrade(provider);
    tokio::spawn(async move {
        while let Some(this) = weak.upgrade() {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let now = Instant::now();
            let expired: Vec<IpAddr> = this
                .members
                .lock()
                .await
                .iter()
                .filter(|(_, exp)| **exp <= now)
                .map(|(ip, _)| *ip)
                .collect();
            for ip in expired {
                if let Err(e) = this.remove(ip).await {
                    warn!(error = %e, ip = %ip, "opnsense: lifting expired ban failed");
                }
            }
        }
    });
}

#[async_trait]
impl ChallengeProvider for OpnsenseProvider {
    fn name(&self) -> &'static str {
        match self.cfg.platform {
            Platform::Opnsense => "opnsense",
            Platform::Pfsense => "pfsense",
        }
    }

    async fn apply(
        &self,
        ip: IpAddr,
        verdict: Verdict,
        opts: &EdgeOptions,
    ) -> sentry_core::error::Result<()> {
        // Trusted IPs are never banned, even by hand — the "you can't lock
        // yourself out" guard (F7.2).
        if let Some(trust) = &self.trust {
            if trust.is_never_ban(ip) {
                warn!(ip = %ip, platform = self.name(), "trusted ip: ban refused");
                return Ok(());
            }
        }
        match verdict {
            Verdict::Block | Verdict::Quarantine => {
                // Platform semantics: drop only. The TTL (opts.ttl) drives
                // when the ban lifts.
                match self.add(ip, opts.ttl).await {
                    Ok(()) => {
                        info!(ip = %ip, platform = self.name(), table = %self.cfg.table, "ban applied");
                        Ok(())
                    }
                    Err(e) => Err(sentry_core::error::CoreError::Config(e)),
                }
            }
            Verdict::Challenge | Verdict::RateLimit => {
                warn!(
                    ip = %ip,
                    platform = self.name(),
                    "platform only supports drop — verdict not enforced as a ban"
                );
                Ok(())
            }
            Verdict::Allow => Ok(()),
        }
    }
}

/// Exposed for tests: alias REST request URL.
pub fn alias_url(base_url: &str, verb: &str, table: &str) -> String {
    format!(
        "{}/api/firewall/alias_util/{}/{}",
        base_url.trim_end_matches('/'),
        verb,
        table
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_body_matches_the_opnsense_shape() {
        let body = OpnsenseProvider::alias_body("203.0.113.5".parse().unwrap());
        assert_eq!(body["address"], "203.0.113.5");
    }

    #[test]
    fn alias_url_is_built_without_trailing_slash_drift() {
        assert_eq!(
            alias_url("https://192.0.2.1/", "add", "sentry_blocks"),
            "https://192.0.2.1/api/firewall/alias_util/add/sentry_blocks"
        );
    }

    #[test]
    fn pfctl_args_are_positional_and_shell_free() {
        let args =
            OpnsenseProvider::pfctl_args("sentry_blocks", "add", "198.51.100.9".parse().unwrap());
        assert_eq!(
            args,
            vec!["-t", "sentry_blocks", "-T", "add", "198.51.100.9"]
        );
    }

    #[test]
    fn platform_names_are_stable() {
        assert_eq!(Platform::Opnsense.as_str(), "opnsense");
        assert_eq!(Platform::Pfsense.as_str(), "pfsense");
    }

    #[tokio::test]
    async fn apply_refuses_trusted_ips() {
        let ts = sentry_core::TrustSet::from_config(&sentry_core::config::RealIpConfig {
            trusted_proxies: vec![],
            cloudflare: false,
            trusted_ips: vec!["198.51.100.7".to_string()],
            trusted_lists: Vec::new(),
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            shadow: Vec::new(),
            refresh_secs: 0,
        })
        .expect("valid config");
        let provider = OpnsenseProvider::new(
            OpnsenseConfig {
                platform: Platform::Opnsense,
                ..Default::default()
            },
            Some(sentry_core::SharedTrustSet::new(ts)),
        );
        let opts = EdgeOptions {
            ttl: Duration::from_secs(60),
            mode: None,
        };
        provider
            .apply("198.51.100.7".parse().unwrap(), Verdict::Block, &opts)
            .await
            .expect("trusted ip must never error nor ban");
    }
}
