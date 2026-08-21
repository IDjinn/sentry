//! Analysis output: risk score, signals, verdict and decision.
//!
//! Produced by the scoring stage and consumed by the decider. Separating
//! `AnalysisResult` (what we found) from `Decision` (what we'll do about it)
//! keeps policy separate from detection — the same detection can map to
//! different actions depending on configuration.

use serde::{Deserialize, Serialize};

/// Discrete risk bucket derived from the numeric score.
///
/// Bucket boundaries are configurable in `sentry.toml` but the five levels
/// themselves are fixed so dashboards and alerts stay stable.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Score 0–9: ordinary traffic.
    #[default]
    Info,
    /// Score 10–29: mildly unusual.
    Low,
    /// Score 30–49: suspicious, rate-limit candidate.
    Medium,
    /// Score 50–74: clearly malicious, challenge.
    High,
    /// Score 75–100: severe, block + alert.
    Critical,
}

impl RiskLevel {
    /// Bucket a numeric score into a level using the default thresholds.
    ///
    /// Thresholds can be overridden via config, but this gives a stable
    /// reference used by tests and documentation.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=9 => Self::Info,
            10..=29 => Self::Low,
            30..=49 => Self::Medium,
            50..=74 => Self::High,
            75..=100 => Self::Critical,
            _ => Self::Critical, // scores >100 are clamped conceptually
        }
    }

    /// Human-readable label used in TUI/logs.
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MED",
            Self::High => "HIGH",
            Self::Critical => "CRIT",
        }
    }

    /// ANSI color code for terminal output.
    pub fn ansi_color(self) -> &'static str {
        match self {
            Self::Info => "\x1b[90m",       // gray
            Self::Low => "\x1b[34m",        // blue
            Self::Medium => "\x1b[33m",     // yellow
            Self::High => "\x1b[38;5;208m", // orange
            Self::Critical => "\x1b[31m",   // red
        }
    }
}

/// A single detection signal that contributed to the risk score.
///
/// Signals are the "why" behind a score: each carries a weight and an
/// optional human-readable detail so the TUI and reports can explain the
/// verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// Stable identifier of the signal kind.
    pub kind: SignalKind,
    /// Weight this signal contributed to the score (0–100).
    pub weight: u8,
    /// Free-form detail (e.g. the regex that matched, the path tried).
    pub detail: Option<String>,
}

/// Catalog of detection signal kinds.
///
/// Adding a variant here is the single place that needs updating when a new
/// detector is introduced; heuristics, the ONNX model and the LLM all emit
/// `Signal`s of these kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// SQL injection attempt.
    SqlInjection,
    /// Cross-site scripting attempt.
    Xss,
    /// Path traversal (`../`, `%2e%2f`, `..;/`).
    PathTraversal,
    /// Local file inclusion.
    Lfi,
    /// Log4Shell (`${jndi:…}`).
    Log4Shell,
    /// Remote code execution / command injection.
    Rce,
    /// Request hit a path that doesn't exist (directory brute-force).
    UnknownRoute,
    /// Method not allowed on a known route (e.g. `POST` on a GET-only route).
    MethodNotAllowed,
    /// Same IP produced many 404s in a short window.
    ScanBehavior,
    /// IP hit many distinct unknown 4xx paths in a short window
    /// (random-filename probing like `/a1b2.php`, `/.env.local`, …).
    RandomScan,
    /// IP exceeded the configured rate limit.
    AbnormalRate,
    /// Suspicious or absent User-Agent.
    SuspiciousUA,
    /// Client is a known Tor exit node.
    TorExitNode,
    /// Client IP appears in a reputation feed.
    KnownBadIp,
    /// Access to a sensitive path (`.env`, `.git/`, …).
    SensitivePath,
    /// Access from a VPN / proxy / datacenter ASN.
    VpnProxy,
    /// Blocked crawler / scanner User-Agent.
    BadCrawler,
    /// Anomaly score from the ONNX model exceeded threshold.
    AnomalousPayload,
    /// LLM classified the payload as malicious.
    LlmMalicious,
    /// A custom rule matched (the rule id is carried in `detail`).
    RuleHit,
    /// Any other signal not yet cataloged.
    Custom,
}

/// What the pipeline decided to do with the event.
///
/// `Allow` and `Block` are terminal; `Challenge` delegates verification to
/// Cloudflare; `RateLimit` applies backpressure; `Quarantine` keeps the
/// request for deeper (LLM) analysis without acting yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No action — traffic is benign.
    #[default]
    Allow,
    /// Apply rate limiting to the client.
    RateLimit,
    /// Issue a Cloudflare challenge (JS / managed / Turnstile).
    Challenge,
    /// Block the client IP.
    Block,
    /// Hold for deeper analysis (LLM), no immediate action.
    Quarantine,
}

/// Full analysis output produced by the scoring stage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Numeric risk score (0–100).
    pub risk_score: u8,
    /// Discrete bucket derived from the score.
    pub risk_level: RiskLevel,
    /// Signals that contributed to the score.
    pub signals: Vec<Signal>,
    /// Recommended verdict from the detector (pre-policy).
    pub verdict: Verdict,
}

impl AnalysisResult {
    /// Creates an empty result with zero score and `Allow` verdict.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Combines a set of signals into a score, applying the standard weights.
    ///
    /// Weights sum with a hard cap at 100. Repetition in a sliding window
    /// is applied by the scorer before calling this.
    pub fn from_signals(signals: Vec<Signal>) -> Self {
        let score = signals.iter().map(|s| s.weight).sum::<u8>().min(100);
        let level = RiskLevel::from_score(score);
        let verdict = match level {
            RiskLevel::Info | RiskLevel::Low => Verdict::Allow,
            RiskLevel::Medium => Verdict::RateLimit,
            RiskLevel::High => Verdict::Challenge,
            RiskLevel::Critical => Verdict::Block,
        };
        Self {
            risk_score: score,
            risk_level: level,
            signals,
            verdict,
        }
    }
}

/// A decision is the analysis result enriched with the final action to take,
/// after policy rules have been applied (e.g. "High + new IP → Challenge").
///
/// `AnalysisResult` is *detection*; `Decision` is *response*. Actions consume
/// `Decision`, not `AnalysisResult`, so policy can change without touching
/// detectors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Decision {
    /// The analysis that led to this decision.
    pub analysis: AnalysisResult,
    /// The final action to execute (possibly overridden by policy).
    pub action: Verdict,
    /// Optional reason explaining why policy overrode the detector, if any.
    pub override_reason: Option<String>,
}
