//! Reputation reporting action (F7.4): reports IPs that earned an enforcing
//! verdict to community abuse databases — [AbuseIPDB](https://www.abuseipdb.com)
//! (`POST /api/v2/report`) and [ReportedIP](https://reportedip.com)
//! (`POST /wp-json/reportedip/v2/report`).
//!
//! Sentry's own signal kinds map onto each provider's category IDs, so a
//! SQLi report carries the SQLi category, a port scan carries Port Scan,
//! and so on. Reports are deduplicated per IP for the configured window
//! (one report per IP per TTL) to respect the providers' daily quotas, and
//! the provider soft-disables itself after repeated failures (same circuit
//! breaker pattern as the Cloudflare edge provider) until restart.
//!
//! Never-ban IPs (`[real_ip] trusted_ips`) never reach an enforcing
//! verdict, so they can never be reported through this action.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentry_core::action::{Action, ActionContext};
use sentry_core::analysis::{Decision, Signal, Verdict};
use sentry_core::error::Result;
use sentry_core::event::Event;
use tracing::{debug, warn};

/// Default per-IP dedupe window: community quotas are daily.
pub const DEFAULT_DEDUPE_HOURS: u64 = 24;
/// Consecutive failures before the provider soft-disables until restart.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 5;
/// Backoff applied after an HTTP 429 (quota) response.
pub const RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(600);

/// Which reputation provider to report to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportProvider {
    /// AbuseIPDB `POST /api/v2/report` (`Key` header auth).
    AbuseIpdb,
    /// ReportedIP `POST /wp-json/reportedip/v2/report` (`X-Key` header auth).
    ReportedIp,
}

impl ReportProvider {
    /// Parse from config (`provider = "abuseipdb" | "reportedip"`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "abuseipdb" => Some(Self::AbuseIpdb),
            "reportedip" => Some(Self::ReportedIp),
            _ => None,
        }
    }

    /// Default endpoint for the provider (overridable in config).
    pub fn default_endpoint(self) -> &'static str {
        match self {
            Self::AbuseIpdb => "https://api.abuseipdb.com/api/v2/report",
            Self::ReportedIp => "https://reportedip.com/wp-json/reportedip/v2/report",
        }
    }

    /// Default env var carrying the API key.
    pub fn default_key_env(self) -> &'static str {
        match self {
            Self::AbuseIpdb => "SENTRY_ABUSEIPDB_KEY",
            Self::ReportedIp => "SENTRY_REPORTEDIP_KEY",
        }
    }
}

/// Configuration for the report action.
#[derive(Debug, Clone)]
pub struct ReportActionConfig {
    /// Provider to report to.
    pub provider: ReportProvider,
    /// API key (from the `key_env` env var; empty = provider skipped).
    pub key: String,
    /// Lowest verdict that triggers a report: `"block"` (default) reports
    /// only `Block`; `"challenge"` adds `Challenge`; `"rate_limit"` adds
    /// `RateLimit`.
    pub min_verdict: Verdict,
    /// Per-IP dedupe window (one report per IP per window).
    pub dedupe_ttl: Duration,
    /// Request timeout.
    pub timeout: Duration,
    /// Endpoint override (tests / self-hosted instances).
    pub endpoint: Option<String>,
}

impl Default for ReportActionConfig {
    fn default() -> Self {
        Self {
            provider: ReportProvider::AbuseIpdb,
            key: String::new(),
            min_verdict: Verdict::Block,
            dedupe_ttl: Duration::from_secs(DEFAULT_DEDUPE_HOURS * 3600),
            timeout: Duration::from_secs(10),
            endpoint: None,
        }
    }
}

/// A fully-built provider request (kept plain for testability).
#[derive(Debug, PartialEq, Eq)]
pub struct ReportRequest {
    /// Target URL.
    pub url: String,
    /// Request headers (name, value).
    pub headers: Vec<(String, String)>,
    /// Form-encoded body fields.
    pub form: Vec<(String, String)>,
    /// JSON body (provider-dependent; exactly one of form/json is used).
    pub json: Option<serde_json::Value>,
}

/// Build the provider-specific request for one report.
pub fn build_request(
    provider: ReportProvider,
    endpoint: &str,
    key: &str,
    ip: IpAddr,
    categories: &[u32],
    comment: &str,
) -> ReportRequest {
    match provider {
        ReportProvider::AbuseIpdb => ReportRequest {
            url: endpoint.to_string(),
            headers: vec![
                ("Key".into(), key.to_string()),
                ("Accept".into(), "application/json".into()),
            ],
            form: vec![
                ("ip".into(), ip.to_string()),
                (
                    "categories".into(),
                    categories
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("comment".into(), comment.to_string()),
            ],
            json: None,
        },
        ReportProvider::ReportedIp => ReportRequest {
            url: endpoint.to_string(),
            headers: vec![
                ("X-Key".into(), key.to_string()),
                ("Content-Type".into(), "application/json".into()),
            ],
            form: Vec::new(),
            json: Some(serde_json::json!({
                "ip": ip.to_string(),
                "categories": categories,
                "comment": comment,
            })),
        },
    }
}

/// Map the event's signals to AbuseIPDB category IDs.
///
/// Falls back to `15` (Hacking) when nothing mapped — the API requires at
/// least one category and the event did earn an enforcing verdict.
pub fn abuseipdb_categories(signals: &[Signal]) -> Vec<u32> {
    let mut out: Vec<u32> = signals
        .iter()
        .filter_map(|s| match s.kind {
            sentry_core::analysis::SignalKind::SqlInjection => Some(16), // SQL Injection
            sentry_core::analysis::SignalKind::BadCrawler
            | sentry_core::analysis::SignalKind::SuspiciousUA => Some(19), // Bad Web Bot
            sentry_core::analysis::SignalKind::ScanBehavior
            | sentry_core::analysis::SignalKind::RandomScan
            | sentry_core::analysis::SignalKind::TcpScanner
            | sentry_core::analysis::SignalKind::PromiscuousScanner
            | sentry_core::analysis::SignalKind::ScanAttackCorrelation
            | sentry_core::analysis::SignalKind::UnknownRoute => Some(14), // Port Scan
            sentry_core::analysis::SignalKind::AuthBruteForce
            | sentry_core::analysis::SignalKind::CredentialStuffing
            | sentry_core::analysis::SignalKind::DirectoryBruteForce
            | sentry_core::analysis::SignalKind::SuspiciousLoginSuccess => Some(18), // Brute-Force
            sentry_core::analysis::SignalKind::Xss
            | sentry_core::analysis::SignalKind::PathTraversal
            | sentry_core::analysis::SignalKind::Lfi
            | sentry_core::analysis::SignalKind::Log4Shell
            | sentry_core::analysis::SignalKind::Rce
            | sentry_core::analysis::SignalKind::SensitivePath
            | sentry_core::analysis::SignalKind::AnomalousPayload => Some(21), // Web App Attack
            sentry_core::analysis::SignalKind::LlmMalicious => Some(15), // Hacking
            _ => None,
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        out.push(15);
    }
    out
}

/// Map the event's signals to ReportedIP category IDs (63-category
/// taxonomy). Falls back to `15` (Hacking).
pub fn reportedip_categories(signals: &[Signal]) -> Vec<u32> {
    let mut out: Vec<u32> = signals
        .iter()
        .filter_map(|s| match s.kind {
            sentry_core::analysis::SignalKind::SqlInjection => Some(16), // SQL Injection
            sentry_core::analysis::SignalKind::BadCrawler
            | sentry_core::analysis::SignalKind::SuspiciousUA => Some(19), // Bad Web Bot
            sentry_core::analysis::SignalKind::ScanBehavior
            | sentry_core::analysis::SignalKind::RandomScan
            | sentry_core::analysis::SignalKind::TcpScanner
            | sentry_core::analysis::SignalKind::PromiscuousScanner
            | sentry_core::analysis::SignalKind::ScanAttackCorrelation
            | sentry_core::analysis::SignalKind::UnknownRoute => Some(61), // Indiscriminate Scan
            sentry_core::analysis::SignalKind::AuthBruteForce
            | sentry_core::analysis::SignalKind::CredentialStuffing
            | sentry_core::analysis::SignalKind::DirectoryBruteForce
            | sentry_core::analysis::SignalKind::SuspiciousLoginSuccess => Some(18), // Brute-Force
            sentry_core::analysis::SignalKind::Xss
            | sentry_core::analysis::SignalKind::PathTraversal
            | sentry_core::analysis::SignalKind::Lfi
            | sentry_core::analysis::SignalKind::Log4Shell
            | sentry_core::analysis::SignalKind::Rce
            | sentry_core::analysis::SignalKind::SensitivePath
            | sentry_core::analysis::SignalKind::AnomalousPayload => Some(21), // Web App Attack
            sentry_core::analysis::SignalKind::LlmMalicious => Some(15), // Hacking
            _ => None,
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        out.push(15);
    }
    out
}

/// Reputation reporting action.
pub struct ReportAction {
    cfg: ReportActionConfig,
    http: reqwest::Client,
    /// Last report instant per IP (dedupe window).
    seen: Mutex<HashMap<IpAddr, Instant>>,
    /// Backoff flag after an HTTP 429.
    backoff_until: Mutex<Option<Instant>>,
    consecutive_failures: AtomicU32,
    disabled: AtomicBool,
}

impl ReportAction {
    /// Create the action; an empty key leaves the action inert (it logs a
    /// single warning on first use instead of failing the daemon).
    pub fn new(cfg: ReportActionConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .expect("reqwest client");
        Self {
            cfg,
            http,
            seen: Mutex::new(HashMap::new()),
            backoff_until: Mutex::new(None),
            consecutive_failures: AtomicU32::new(0),
            disabled: AtomicBool::new(false),
        }
    }

    /// Whether quota/dedupe/circuit state currently allows a report for `ip`.
    pub fn should_report(&self, ip: IpAddr) -> bool {
        if self.disabled.load(Ordering::Relaxed) {
            return false;
        }
        if let Some(until) = *self.backoff_until.lock().unwrap() {
            if Instant::now() < until {
                return false;
            }
        }
        let mut seen = self.seen.lock().unwrap();
        if let Some(last) = seen.get(&ip) {
            if last.elapsed() < self.cfg.dedupe_ttl {
                return false;
            }
        }
        seen.insert(ip, Instant::now());
        seen.retain(|_, t| t.elapsed() < self.cfg.dedupe_ttl);
        true
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self, reason: &str) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= MAX_CONSECUTIVE_FAILURES {
            self.disabled.store(true, Ordering::Relaxed);
            warn!(
                provider = self.cfg.provider_debug(),
                failures, "report provider soft-disabled until restart"
            );
        } else {
            warn!(
                provider = self.cfg.provider_debug(),
                failures, reason, "reputation report failed"
            );
        }
    }

    fn record_rate_limited(&self) {
        *self.backoff_until.lock().unwrap() = Some(Instant::now() + RATE_LIMIT_BACKOFF);
        warn!(
            provider = self.cfg.provider_debug(),
            backoff_secs = RATE_LIMIT_BACKOFF.as_secs(),
            "reputation report rate-limited (429) — backing off"
        );
    }

    fn comment(&self, _evt: &Event, decision: &Decision, ctx: &ActionContext) -> String {
        let signals = decision
            .analysis
            .signals
            .iter()
            .map(|s| format!("{:?}", s.kind))
            .collect::<Vec<_>>()
            .join(",");
        match ctx.incident_id {
            Some(id) => format!(
                "sentry/{} verdict={:?} incident={} signals=[{signals}]",
                env!("CARGO_PKG_VERSION"),
                decision.action,
                id
            ),
            None => format!(
                "sentry/{} verdict={:?} signals=[{signals}]",
                env!("CARGO_PKG_VERSION"),
                decision.action
            ),
        }
    }
}

impl ReportActionConfig {
    fn provider_debug(&self) -> &'static str {
        match self.provider {
            ReportProvider::AbuseIpdb => "abuseipdb",
            ReportProvider::ReportedIp => "reportedip",
        }
    }
}

/// Parse the `min_verdict` config option (`"block"` | `"challenge"` |
/// `"rate_limit"`).
pub fn parse_min_verdict(s: &str) -> std::result::Result<Verdict, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "block" => Ok(Verdict::Block),
        "challenge" => Ok(Verdict::Challenge),
        "rate_limit" | "ratelimit" => Ok(Verdict::RateLimit),
        other => Err(format!(
            "report action: unknown min_verdict `{other}` — known: block, challenge, rate_limit"
        )),
    }
}

fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Allow => 0,
        Verdict::RateLimit => 1,
        Verdict::Quarantine => 1,
        Verdict::Challenge => 2,
        Verdict::Block => 3,
    }
}

#[async_trait]
impl Action for ReportAction {
    fn name(&self) -> &'static str {
        "report"
    }

    fn applies_to(&self, decision: &Decision) -> bool {
        verdict_rank(decision.action) >= verdict_rank(self.cfg.min_verdict)
            && decision.action != Verdict::Allow
    }

    async fn execute_with_context(
        &self,
        evt: &Event,
        decision: &Decision,
        ctx: &ActionContext,
    ) -> Result<()> {
        if !self.should_report(evt.client_ip) {
            return Ok(());
        }
        if self.cfg.key.is_empty() {
            debug!(
                provider = self.cfg.provider_debug(),
                "no API key — skipping report"
            );
            return Ok(());
        }
        let categories = match self.cfg.provider {
            ReportProvider::AbuseIpdb => abuseipdb_categories(&decision.analysis.signals),
            ReportProvider::ReportedIp => reportedip_categories(&decision.analysis.signals),
        };
        let endpoint = self
            .cfg
            .endpoint
            .as_deref()
            .unwrap_or(self.cfg.provider.default_endpoint());
        let request = build_request(
            self.cfg.provider,
            endpoint,
            &self.cfg.key,
            evt.client_ip,
            &categories,
            &self.comment(evt, decision, ctx),
        );

        let mut builder = self.http.post(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder = if let Some(json) = &request.json {
            builder.json(json)
        } else {
            builder.form(&request.form)
        };

        match builder.send().await {
            Ok(resp) if resp.status().as_u16() == 429 => {
                self.record_rate_limited();
            }
            Ok(resp) if resp.status().is_success() => {
                self.record_success();
                debug!(
                    provider = self.cfg.provider_debug(),
                    ip = %evt.client_ip,
                    "reputation report sent"
                );
            }
            Ok(resp) => {
                self.record_failure(&format!("HTTP {}", resp.status()));
            }
            Err(e) => {
                self.record_failure(&e.to_string());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::analysis::{AnalysisResult, SignalKind};

    fn signal(kind: SignalKind) -> Signal {
        Signal {
            kind,
            weight: 10,
            detail: None,
        }
    }

    #[test]
    fn abuseipdb_mapping() {
        let cats = abuseipdb_categories(&[
            signal(SignalKind::SqlInjection),
            signal(SignalKind::RandomScan),
            signal(SignalKind::AuthBruteForce),
            signal(SignalKind::BadCrawler),
        ]);
        assert_eq!(cats, vec![14, 16, 18, 19]);
    }

    #[test]
    fn abuseipdb_fallback_is_hacking() {
        assert_eq!(abuseipdb_categories(&[]), vec![15]);
        assert_eq!(
            abuseipdb_categories(&[signal(SignalKind::RuleHit)]),
            vec![15]
        );
    }

    #[test]
    fn reportedip_mapping_uses_indiscriminate_scan() {
        let cats = reportedip_categories(&[
            signal(SignalKind::TcpScanner),
            signal(SignalKind::DirectoryBruteForce),
        ]);
        assert_eq!(cats, vec![18, 61]);
    }

    #[test]
    fn request_shapes_per_provider() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let abuse = build_request(
            ReportProvider::AbuseIpdb,
            ReportProvider::AbuseIpdb.default_endpoint(),
            "k1",
            ip,
            &[16, 21],
            "c",
        );
        assert_eq!(abuse.url, "https://api.abuseipdb.com/api/v2/report");
        assert!(abuse.headers.contains(&("Key".into(), "k1".into())));
        assert!(abuse.json.is_none());
        assert!(abuse
            .form
            .iter()
            .any(|(k, v)| k == "categories" && v == "16,21"));

        let rip = build_request(
            ReportProvider::ReportedIp,
            ReportProvider::ReportedIp.default_endpoint(),
            "k2",
            ip,
            &[61],
            "c",
        );
        assert!(rip.headers.contains(&("X-Key".into(), "k2".into())));
        let json = rip.json.expect("reportedip posts json");
        assert_eq!(json["ip"], "198.51.100.7");
        assert_eq!(json["categories"][0], 61);
    }

    #[test]
    fn applies_to_respects_min_verdict() {
        let mk = |min| {
            ReportAction::new(ReportActionConfig {
                min_verdict: min,
                ..ReportActionConfig::default()
            })
        };
        let block = Decision {
            analysis: AnalysisResult::default(),
            action: Verdict::Block,
            override_reason: None,
            log_level: None,
        };
        let rate = Decision {
            analysis: AnalysisResult::default(),
            action: Verdict::RateLimit,
            override_reason: None,
            log_level: None,
        };
        let allow = Decision {
            analysis: AnalysisResult::default(),
            action: Verdict::Allow,
            override_reason: None,
            log_level: None,
        };
        assert!(mk(Verdict::Block).applies_to(&block));
        assert!(!mk(Verdict::Block).applies_to(&rate));
        assert!(!mk(Verdict::Challenge).applies_to(&rate));
        assert!(mk(Verdict::Challenge).applies_to(&block));
        assert!(mk(Verdict::RateLimit).applies_to(&rate));
        assert!(!mk(Verdict::RateLimit).applies_to(&allow));
    }

    #[tokio::test]
    async fn dedupe_reports_once_per_ttl() {
        let action = ReportAction::new(ReportActionConfig {
            dedupe_ttl: Duration::from_secs(3600),
            ..ReportActionConfig::default()
        });
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(action.should_report(ip));
        assert!(!action.should_report(ip));
        let other: IpAddr = "203.0.113.6".parse().unwrap();
        assert!(action.should_report(other));
    }

    #[tokio::test]
    async fn backoff_blocks_then_expires() {
        let action = ReportAction::new(ReportActionConfig::default());
        action.record_rate_limited();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(!action.should_report(ip));
        *action.backoff_until.lock().unwrap() = Some(Instant::now() - Duration::from_secs(1));
        // Dedupe recorded the IP on the pre-backoff check; reset manually.
        action.seen.lock().unwrap().clear();
        assert!(action.should_report(ip));
    }

    #[tokio::test]
    async fn consecutive_failures_disable_provider() {
        let action = ReportAction::new(ReportActionConfig::default());
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            action.record_failure("boom");
        }
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(!action.should_report(ip));
    }
}
