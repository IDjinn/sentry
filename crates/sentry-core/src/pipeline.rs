//! Pipeline: ties together rules engine, heuristics, route validator and scorer.
//!
//! The pipeline is the heart of the daemon. For each event it:
//! 1. Evaluates rules (fast path — allowlist/blocklist short-circuit)
//! 2. Runs heuristics (SQLi, XSS, path traversal, etc.)
//! 3. Validates route (unknown route → signal)
//! 4. Combines signals into a risk score
//! 5. Applies policy to produce a final decision

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::analysis::{AnalysisResult, Decision, RiskLevel, Signal, SignalKind, Verdict};
use crate::behavior::BehaviorTracker;
use crate::config::{EscalationConfig, RouteDefConfig, ScorerConfig, UploadsConfig};
use crate::correlation::{self, CorrelationScope, CorrelationTracker};
use crate::event::Event;
use crate::heuristics::HeuristicEngine;
use crate::offender::OffenderTracker;
use crate::policy::VerdictPolicy;
use crate::ratelimit::RateLimitBackend;
use crate::rules::{RuleSet, SharedRuleSet};
use crate::scan::ScanTracker;
use crate::uploads::UploadTracker;

/// Route definition for the route validator.
///
/// The `path` pattern supports three forms:
/// - exact: `/api/users`
/// - glob: `/api/*` (`*` matches any sequence, case-insensitive)
/// - template: `/users/{id}/posts/{post_id}` (`{name}` matches exactly one
///   non-empty segment; a trailing `/*` segment matches the rest)
#[derive(Debug, Clone)]
pub struct RouteDef {
    /// Path pattern (exact, glob or template).
    pub path: String,
    /// Allowed methods (empty = any).
    pub methods: Vec<String>,
}

/// Read-only view of a stored route, used by [`RouteValidator::merge`] to
/// avoid forcing callers to allocate `RouteDef`s from DB rows.
pub trait RouteLike {
    /// Path pattern.
    fn path(&self) -> &str;
    /// Allowed methods.
    fn methods(&self) -> &[String];
}

impl RouteLike for RouteDef {
    fn path(&self) -> &str {
        &self.path
    }
    fn methods(&self) -> &[String] {
        &self.methods
    }
}

impl RouteDef {
    /// Create from config.
    pub fn from_config(cfg: &RouteDefConfig) -> Self {
        Self {
            path: cfg.path.clone(),
            methods: cfg.methods.clone(),
        }
    }

    /// Whether the (lowercased) path matches this route's pattern.
    fn matches_path(&self, path_lower: &str) -> bool {
        let pat = self.path.to_ascii_lowercase();
        if pat.contains('{') {
            template_match(&pat, path_lower)
        } else if pat.contains('*') {
            glob_simple(&pat, path_lower)
        } else {
            pat == path_lower
        }
    }

    /// Whether `method` is allowed on this route (empty list = any).
    fn allows_method(&self, method: crate::event::HttpMethod) -> bool {
        self.methods.is_empty()
            || self
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method.as_str()))
    }
}

/// Route validator with a set of known routes.
#[derive(Debug, Clone, Default)]
pub struct RouteValidator {
    routes: Vec<RouteDef>,
}

impl RouteValidator {
    /// Create a validator from a list of route definitions.
    pub fn new(routes: Vec<RouteDef>) -> Self {
        Self { routes }
    }

    /// Create a validator from config.
    pub fn from_config(config: &[RouteDefConfig]) -> Self {
        Self {
            routes: config.iter().map(RouteDef::from_config).collect(),
        }
    }

    /// Iterate over known routes (for listing / merging with DB routes).
    pub fn routes(&self) -> impl Iterator<Item = &RouteDef> {
        self.routes.iter()
    }

    /// Merge config routes with DB-loaded routes (deduped by lowercased path).
    ///
    /// Config routes always win (they have a higher precedence); DB rows
    /// with the same path are skipped. Returns a fresh `RouteValidator`.
    pub fn merge(config: &[RouteDefConfig], db_rows: &[impl RouteLike]) -> Self {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut routes: Vec<RouteDef> = Vec::new();

        for cfg_route in config {
            let key = cfg_route.path.to_ascii_lowercase();
            if seen.insert(key) {
                routes.push(RouteDef::from_config(cfg_route));
            }
        }
        for row in db_rows {
            let key = row.path().to_ascii_lowercase();
            if seen.insert(key) {
                routes.push(RouteDef {
                    path: row.path().to_string(),
                    methods: row.methods().to_vec(),
                });
            }
        }
        Self { routes }
    }

    /// Check if a path matches any known route.
    pub fn is_known(&self, path: &str) -> bool {
        let path_lower = path.to_ascii_lowercase();
        self.routes.iter().any(|r| r.matches_path(&path_lower))
    }

    /// Validate an event, returning signals for unknown routes or methods.
    pub fn validate(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let path_lower = http.path.to_ascii_lowercase();
        match self.routes.iter().find(|r| r.matches_path(&path_lower)) {
            None => vec![Signal {
                kind: crate::analysis::SignalKind::UnknownRoute,
                weight: 8,
                detail: Some(http.path.clone()),
            }],
            Some(route) => {
                let method_violation = http
                    .method
                    .map(|m| !route.allows_method(m))
                    .unwrap_or(false);
                if method_violation {
                    vec![Signal {
                        kind: crate::analysis::SignalKind::MethodNotAllowed,
                        weight: 10,
                        detail: Some(format!(
                            "{} {}",
                            http.method.map(|m| m.as_str()).unwrap_or("?"),
                            http.path
                        )),
                    }]
                } else {
                    vec![]
                }
            }
        }
    }
}

/// Template matcher: `/users/{id}` matches `/users/42` but not `/users/42/posts`.
///
/// A `{name}` segment matches exactly one non-empty segment. A trailing `*`
/// segment matches zero or more remaining segments. A `*` anywhere else
/// falls back to plain glob semantics. Comparison is case-insensitive
/// (callers pass lowercased strings).
fn template_match(pattern: &str, path: &str) -> bool {
    let pat_segs: Vec<&str> = pattern.split('/').collect();
    let path_segs: Vec<&str> = path.split('/').collect();

    let wildcard_last = pat_segs.last() == Some(&"*");
    if pat_segs[..pat_segs.len() - 1].contains(&"*") {
        return glob_simple(pattern, path);
    }

    let fixed = if wildcard_last {
        &pat_segs[..pat_segs.len() - 1]
    } else {
        &pat_segs[..]
    };
    if !wildcard_last && path_segs.len() != fixed.len() {
        return false;
    }
    if wildcard_last && path_segs.len() < fixed.len() {
        return false;
    }
    for (pat, seg) in fixed.iter().zip(path_segs.iter()) {
        let is_param = pat.starts_with('{') && pat.ends_with('}') && pat.len() > 2;
        if is_param {
            if seg.is_empty() {
                return false;
            }
        } else if pat != seg {
            return false;
        }
    }
    true
}

/// Simple glob: `*` matches any sequence.
fn glob_simple(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return text == parts[0];
    }
    if !text.starts_with(parts[0]) {
        return false;
    }
    let mut pos = parts[0].len();
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    text[pos..].ends_with(parts[parts.len() - 1])
}

/// Tracks signal repetition per IP for the repetition-bonus feature.
#[derive(Debug, Default)]
pub struct RepetitionTracker {
    /// IP → list of (signal_kind, timestamp) within the window.
    history: HashMap<IpAddr, Vec<(SignalKind, Instant)>>,
    /// Window duration in seconds.
    window_secs: u64,
}

impl RepetitionTracker {
    /// Create a new tracker with the given window.
    pub fn new(window_secs: u64) -> Self {
        Self {
            history: HashMap::new(),
            window_secs,
        }
    }

    /// Record signals for an IP and return bonus weight for repetitions.
    ///
    /// Per-IP history is capped: a chatty client inside the window would
    /// otherwise grow the Vec unboundedly and make every record O(window
    /// events). The cap is far above any realistic repetition rate (F5).
    pub fn record(&mut self, ip: IpAddr, signals: &[Signal]) -> u8 {
        const MAX_ENTRIES: usize = 128;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);
        let entries = self.history.entry(ip).or_default();

        entries.retain(|(_, ts)| now.duration_since(*ts) < window);
        if entries.len() + signals.len() > MAX_ENTRIES {
            let excess = entries.len() + signals.len() - MAX_ENTRIES;
            entries.drain(..excess.min(entries.len()));
        }

        let mut bonus = 0u8;
        for s in signals {
            if entries.iter().any(|(k, _)| *k == s.kind) {
                bonus = bonus.saturating_add(5);
            }
            entries.push((s.kind, now));
        }
        bonus
    }

    /// Prune expired entries for all IPs.
    pub fn prune(&mut self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);
        for entries in self.history.values_mut() {
            entries.retain(|(_, ts)| now.duration_since(*ts) < window);
        }
    }
}

/// The analysis pipeline.
pub struct Pipeline {
    rules: SharedRuleSet,
    heuristics: HeuristicEngine,
    routes: RwLock<RouteValidator>,
    scorer: ScorerConfig,
    policy: VerdictPolicy,
    repetition: Option<RwLock<RepetitionTracker>>,
    rate_limiter: Option<Arc<dyn RateLimitBackend>>,
    offender: Option<Arc<RwLock<OffenderTracker>>>,
    escalation: EscalationConfig,
    scan: Option<Arc<RwLock<ScanTracker>>>,
    behavior: Option<Arc<RwLock<BehaviorTracker>>>,
    upload: Option<Arc<RwLock<UploadTracker>>>,
    correlation: Option<Arc<RwLock<CorrelationTracker>>>,
    trust: Option<crate::trust::SharedTrustSet>,
    bot: Option<crate::botverify::SharedBotVerifier>,
    /// Signals raised by response-phase observations (inline edge): applied
    /// to the next request from the same IP, since request-phase verdicts
    /// are decided before any response exists.
    pending: RwLock<HashMap<IpAddr, Vec<(Instant, Signal)>>>,
}

/// Queued response signals older than this are dropped, both on drain and
/// in [`Pipeline::prune_pending`] — the behavior they describe is long gone.
const PENDING_TTL: Duration = Duration::from_secs(60);
/// Per-IP cap on queued response signals (drop-oldest beyond it).
const PENDING_MAX_PER_IP: usize = 16;

/// Output of processing a single event.
#[derive(Debug, Clone)]
pub struct ProcessedEvent {
    /// The original event.
    pub event: Event,
    /// Analysis result (signals + score + level).
    pub analysis: AnalysisResult,
    /// Final decision (action to take).
    pub decision: Decision,
    /// Whether a rule short-circuited (bypassed heuristics+AI).
    pub rule_hit: Option<String>,
}

impl Pipeline {
    /// Create a new pipeline with the given rules, heuristics and routes.
    pub fn new(rules: RuleSet, routes: RouteValidator) -> Self {
        Self::with_config(
            Arc::new(RwLock::new(rules)),
            routes,
            ScorerConfig::default(),
            VerdictPolicy::default(),
        )
    }

    /// Create a pipeline with a shared ruleset (hot-reloadable), routes,
    /// scorer config and verdict policy.
    pub fn with_config(
        rules: SharedRuleSet,
        routes: RouteValidator,
        scorer: ScorerConfig,
        policy: VerdictPolicy,
    ) -> Self {
        let repetition = if scorer.repetition_bonus {
            Some(RwLock::new(RepetitionTracker::new(
                scorer.repetition_window_secs,
            )))
        } else {
            None
        };
        Self {
            rules,
            heuristics: HeuristicEngine::with_defaults(),
            routes: RwLock::new(routes),
            scorer,
            policy,
            repetition,
            rate_limiter: None,
            offender: None,
            escalation: EscalationConfig::default(),
            scan: None,
            behavior: None,
            upload: None,
            correlation: None,
            trust: None,
            bot: None,
            pending: RwLock::new(HashMap::new()),
        }
    }

    /// Arm upload inspection (F10): projects `[uploads]` onto the heuristic
    /// engine. Call once at construction; upload heuristics default to a
    /// zero-cost disabled scan.
    pub fn configure_uploads(&mut self, cfg: &UploadsConfig) -> &mut Self {
        self.heuristics = std::mem::take(&mut self.heuristics)
            .with_uploads_scan(crate::uploads::UploadsScan::from_config(cfg));
        self
    }

    /// Attach the upload-volume tracker (F10): per-IP flood window over
    /// files and bytes.
    pub fn with_upload_tracker(mut self, tracker: Arc<RwLock<UploadTracker>>) -> Self {
        self.upload = Some(tracker);
        self
    }

    /// Attach the trusted-infrastructure set (F7.2): IPs in the never-ban
    /// list short-circuit the pipeline to `Allow` (and `rescore_from`
    /// refuses to elevate them), covering daemon and inline-edge paths.
    pub fn with_trust(mut self, trust: crate::trust::SharedTrustSet) -> Self {
        self.trust = Some(trust);
        self
    }

    /// Attach a rate-limit backend (enables `RuleMatch::Rate` conditions).
    pub fn with_rate_limiter(mut self, backend: Arc<dyn RateLimitBackend>) -> Self {
        self.rate_limiter = Some(backend);
        self
    }

    /// Attach the repeat-offender tracker and its escalation policy.
    pub fn with_offender(
        mut self,
        tracker: Arc<RwLock<OffenderTracker>>,
        escalation: EscalationConfig,
    ) -> Self {
        self.offender = Some(tracker);
        self.escalation = escalation;
        self
    }

    /// Attach the behavioral scan tracker.
    pub fn with_scan_tracker(mut self, tracker: Arc<RwLock<ScanTracker>>) -> Self {
        self.scan = Some(tracker);
        self
    }

    /// Attach the behavioral attack tracker (auth brute-force, credential
    /// stuffing, directory brute-force).
    pub fn with_behavior_tracker(mut self, tracker: Arc<RwLock<BehaviorTracker>>) -> Self {
        self.behavior = Some(tracker);
        self
    }

    /// Attach the cross-IP scan→attack correlation tracker (F3.10).
    pub fn with_correlation_tracker(mut self, tracker: Arc<RwLock<CorrelationTracker>>) -> Self {
        self.correlation = Some(tracker);
        self
    }

    /// Attach the rDNS bot-verification cache (F7.7). Claimed-crawler UAs
    /// are annotated with the cached outcome before rule evaluation; misses
    /// queue a background DNS check and mark the event pending.
    pub fn with_bot_verifier(mut self, verifier: crate::botverify::SharedBotVerifier) -> Self {
        self.bot = Some(verifier);
        self
    }

    /// Process a single event through the full pipeline.
    #[tracing::instrument(skip(self, evt), fields(id = %evt.id, ip = %evt.client_ip))]
    pub fn process(&self, evt: &Event) -> ProcessedEvent {
        // Trusted IPs (F7.2 `[real_ip] trusted_ips`) are exempt from every
        // detector and verdict — the "you can't lock yourself out" guard.
        if let Some(trust) = &self.trust {
            if trust.is_never_ban(evt.client_ip) {
                return ProcessedEvent {
                    event: evt.clone(),
                    analysis: AnalysisResult {
                        risk_score: 0,
                        risk_level: RiskLevel::Info,
                        signals: Vec::new(),
                        verdict: Verdict::Allow,
                    },
                    decision: Decision {
                        analysis: AnalysisResult {
                            risk_score: 0,
                            risk_level: RiskLevel::Info,
                            signals: Vec::new(),
                            verdict: Verdict::Allow,
                        },
                        action: Verdict::Allow,
                        override_reason: Some("trusted ip".into()),
                        log_level: None,
                    },
                    rule_hit: None,
                };
            }
        }

        // Blacklisted IPs (`[real_ip] blacklist`) are denied before any
        // detector runs — the inverse of the trusted guard.
        if let Some(trust) = &self.trust {
            if trust.is_blacklisted(evt.client_ip) {
                let analysis = AnalysisResult {
                    risk_score: 100,
                    risk_level: RiskLevel::Critical,
                    signals: Vec::new(),
                    verdict: Verdict::Block,
                };
                return ProcessedEvent {
                    event: evt.clone(),
                    analysis: analysis.clone(),
                    decision: Decision {
                        analysis,
                        action: Verdict::Block,
                        override_reason: Some("blacklisted ip".into()),
                        log_level: None,
                    },
                    rule_hit: None,
                };
            }
        }

        // Bot verification (F7.7): annotate claimed-crawler UAs before rule
        // evaluation so `bot_verified` conditions (verified-only allowlists)
        // see the cached outcome. The event is cloned only when enabled.
        let mut bot_evt;
        let evt = if let Some(bot) = &self.bot {
            bot_evt = evt.clone();
            bot.annotate(&mut bot_evt);
            &bot_evt
        } else {
            evt
        };

        let ruleset = self.rules.read().unwrap();

        if let Some((rule, short_circuit)) =
            ruleset.evaluate_with(evt, self.rate_limiter.as_deref())
        {
            let action = rule.action;
            if short_circuit {
                let verdict: Verdict = action.into();
                let result = AnalysisResult {
                    risk_score: match verdict {
                        Verdict::Allow => 0,
                        Verdict::RateLimit => 30,
                        Verdict::Challenge => 50,
                        Verdict::Block => 100,
                        Verdict::Quarantine => 40,
                    },
                    risk_level: match verdict {
                        Verdict::Allow => RiskLevel::Info,
                        Verdict::RateLimit => RiskLevel::Medium,
                        Verdict::Challenge => RiskLevel::High,
                        Verdict::Block => RiskLevel::Critical,
                        Verdict::Quarantine => RiskLevel::Medium,
                    },
                    signals: vec![Signal {
                        kind: SignalKind::RuleHit,
                        weight: match verdict {
                            Verdict::Block => 100,
                            Verdict::Challenge => 50,
                            Verdict::RateLimit => 30,
                            _ => 0,
                        },
                        detail: Some(rule.id.clone()),
                    }],
                    verdict,
                };
                let decision = Decision {
                    analysis: result.clone(),
                    action: verdict,
                    override_reason: Some(format!("rule '{}' short-circuited", rule.id)),
                    log_level: rule.log_level,
                };
                return self.cap_shadow(
                    evt.client_ip,
                    ProcessedEvent {
                        event: evt.clone(),
                        analysis: result,
                        decision: self.apply_escalation(evt, decision),
                        rule_hit: Some(rule.id.clone()),
                    },
                );
            }
        }
        drop(ruleset);

        let mut signals = self.heuristics.analyze(evt);
        signals.extend(crate::reputation::reputation_signals(evt));
        if let Some(crate::botverify::BotStatus::Spoofed) = evt.bot {
            let detail = evt
                .http()
                .and_then(|h| h.user_agent.as_deref())
                .and_then(|ua| crate::botverify::claimed_engine(Some(ua)))
                .map(|e| {
                    format!(
                        "UA claims {} crawler but rDNS verification failed",
                        e.as_str()
                    )
                });
            signals.push(Signal {
                kind: SignalKind::SpoofedBot,
                weight: crate::botverify::SPOOFED_BOT_WEIGHT,
                detail,
            });
        }
        signals.extend(self.routes.read().unwrap().validate(evt));
        // Response-phase feedback (inline edge): scan/behavior trackers key
        // on the HTTP status, which only exists after a response was served —
        // signals they raised on earlier responses apply to this request.
        // Drained once, TTL-filtered so stale queues don't bite.
        if evt.http().is_some() {
            let now = Instant::now();
            let mut pending = self.pending.write().unwrap();
            if let Some(queued) = pending.remove(&evt.client_ip) {
                signals.extend(
                    queued
                        .into_iter()
                        .filter(|(ts, _)| now.duration_since(*ts) < PENDING_TTL)
                        .map(|(_, s)| s),
                );
            }
        }
        if let Some(ref scan) = self.scan {
            if let Some(http) = evt.http() {
                let mut tracker = scan.write().unwrap();
                signals.extend(tracker.record(evt.client_ip, &http.path, http.status));
            }
        }
        if let Some(ref behavior) = self.behavior {
            if let Some(http) = evt.http() {
                let mut tracker = behavior.write().unwrap();
                signals.extend(tracker.record(
                    evt.client_ip,
                    &http.path,
                    http.status,
                    http.user_agent.as_deref(),
                ));
            }
        }
        if let Some(ref upload) = self.upload {
            if let Some(uploads) = evt.http().and_then(|h| h.uploads.as_ref()) {
                if !uploads.is_empty() {
                    let mut tracker = upload.write().unwrap();
                    signals.extend(tracker.record(evt.client_ip, uploads));
                }
            }
        }
        if let Some(ref corr) = self.correlation {
            let mut tracker = corr.write().unwrap();
            for s in &signals {
                if let Some(label) = correlation::scan_label(s.kind) {
                    tracker.record_scan(evt.client_ip, evt.asn, label);
                }
            }
            if signals
                .iter()
                .any(|s| correlation::is_attack_signal(s.kind))
            {
                if let Some(hit) = tracker.correlate(evt.client_ip, evt.asn) {
                    let scope = match hit.scope {
                        CorrelationScope::Prefix => match evt.client_ip {
                            IpAddr::V4(_) => "/24",
                            IpAddr::V6(_) => "/64",
                        },
                        CorrelationScope::Asn => "ASN",
                    };
                    let weight = self
                        .scorer
                        .weights
                        .get("scan_attack_correlation")
                        .copied()
                        .unwrap_or(correlation::SCAN_ATTACK_CORRELATION_WEIGHT);
                    signals.push(Signal {
                        kind: SignalKind::ScanAttackCorrelation,
                        weight,
                        detail: Some(format!(
                            "{} from {} (same {}) {}s ago",
                            hit.label,
                            hit.scanner,
                            scope,
                            hit.age.as_secs()
                        )),
                    });
                }
            }
        }

        let bonus = if let Some(ref rep) = self.repetition {
            let mut tracker = rep.write().unwrap();
            tracker.record(evt.client_ip, &signals)
        } else {
            0
        };

        let analysis = if self.scorer.weights.is_empty() && bonus == 0 {
            AnalysisResult::from_signals(signals)
        } else {
            self.score_with_weights(signals, bonus)
        };

        let (action, override_reason) = self.policy.decide(analysis.risk_level, evt);
        let decision = Decision {
            analysis: analysis.clone(),
            action,
            override_reason,
            log_level: None,
        };

        self.cap_shadow(
            evt.client_ip,
            ProcessedEvent {
                event: evt.clone(),
                analysis,
                decision: self.apply_escalation(evt, decision),
                rule_hit: None,
            },
        )
    }

    /// Feed the response phase of an inline-edge request into the stateful
    /// trackers with the now-known response status, and queue the resulting
    /// signals for the *next* request from the same IP.
    ///
    /// The request-phase [`process`](Self::process) call runs before any
    /// response exists (`HttpData.status` is `None` on the edge), so the
    /// status-gated detectors — [`ScanTracker`](crate::scan::ScanTracker)
    /// (4xx windows) and the `BehaviorTracker` detectors — are blind at that
    /// point. This method is the feedback half: called by the edge once the
    /// response status is known (upstream status, or the edge's own
    /// 403/429/301), it performs the real tracker feed — exactly one stateful
    /// feed per request, since the request-phase call was a no-op — and
    /// enqueues the raised signals, which the next `process` call for the IP
    /// drains into scoring, policy and escalation.
    ///
    /// Returns the signals produced by this observation.
    pub fn observe_response(
        &self,
        ip: IpAddr,
        path: &str,
        status: u16,
        user_agent: Option<&str>,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();
        if let Some(ref scan) = self.scan {
            signals.extend(scan.write().unwrap().record(ip, path, Some(status)));
        }
        if let Some(ref behavior) = self.behavior {
            signals.extend(
                behavior
                    .write()
                    .unwrap()
                    .record(ip, path, Some(status), user_agent),
            );
        }
        if !signals.is_empty() {
            let now = Instant::now();
            let mut pending = self.pending.write().unwrap();
            let entry = pending.entry(ip).or_default();
            if entry.len() + signals.len() > PENDING_MAX_PER_IP {
                let overflow = entry.len() + signals.len() - PENDING_MAX_PER_IP;
                entry.drain(..overflow.min(entry.len()));
            }
            entry.extend(signals.iter().map(|s| (now, s.clone())));
        }
        signals
    }

    /// Drop expired queued response signals (daemon prune task).
    pub fn prune_pending(&self) {
        let now = Instant::now();
        let mut pending = self.pending.write().unwrap();
        pending.retain(|_, queued| {
            queued.retain(|(ts, _)| now.duration_since(*ts) < PENDING_TTL);
            !queued.is_empty()
        });
    }

    /// Shadow-list cap (F7.2 `[real_ip] shadow`): the IP is fully analyzed
    /// and logged, but never banned or blocked — `Block`/`Quarantine`
    /// downgrade to `Challenge`.
    fn cap_shadow(&self, ip: IpAddr, mut pe: ProcessedEvent) -> ProcessedEvent {
        if let Some(trust) = &self.trust {
            if trust.is_shadow(ip)
                && matches!(pe.decision.action, Verdict::Block | Verdict::Quarantine)
            {
                pe.decision.action = Verdict::Challenge;
                pe.decision.override_reason = Some("shadow ip (no ban)".into());
            }
        }
        pe
    }

    /// Record a strike for a non-Allow decision and escalate the verdict if
    /// the strike count crosses a configured threshold. `Allow` decisions
    /// pass through untouched (no ratchet against benign hits).
    fn apply_escalation(&self, evt: &Event, mut decision: Decision) -> Decision {
        if decision.action == Verdict::Allow {
            return decision;
        }
        if let Some(ref offender) = self.offender {
            let mut tracker = offender.write().unwrap();
            let (_, escalation) =
                tracker.record_and_escalate(evt.client_ip, decision.action, &self.escalation);
            if let Some((verdict, reason)) = escalation {
                decision.action = verdict;
                decision.override_reason = Some(reason);
            }
        }
        decision
    }

    /// Weight for a signal kind: config override if set, else the signal's
    /// own weight (looked up among `signals`, since kinds may repeat).
    fn weight_for(&self, kind: SignalKind, signals: &[Signal]) -> u8 {
        let key = match kind {
            SignalKind::SqlInjection => "sql_injection",
            SignalKind::Xss => "xss",
            SignalKind::PathTraversal => "path_traversal",
            SignalKind::Lfi => "lfi",
            SignalKind::Log4Shell => "log4shell",
            SignalKind::Rce => "rce",
            SignalKind::UnknownRoute => "unknown_route",
            SignalKind::MethodNotAllowed => "method_not_allowed",
            SignalKind::ScanBehavior => "scan_behavior",
            SignalKind::RandomScan => "random_scan",
            SignalKind::AuthBruteForce => "auth_brute_force",
            SignalKind::SuspiciousLoginSuccess => "suspicious_login_success",
            SignalKind::CredentialStuffing => "credential_stuffing",
            SignalKind::DirectoryBruteForce => "directory_brute_force",
            SignalKind::AbnormalRate => "abnormal_rate",
            SignalKind::SuspiciousUA => "suspicious_ua",
            SignalKind::TorExitNode => "tor_exit_node",
            SignalKind::KnownBadIp => "known_bad_ip",
            SignalKind::SensitivePath => "sensitive_path",
            SignalKind::VpnProxy => "vpn_proxy",
            SignalKind::PromiscuousScanner => "promiscuous_scanner",
            SignalKind::BadCrawler => "bad_crawler",
            SignalKind::AnomalousPayload => "anomalous_payload",
            SignalKind::TcpScanner => "tcp_scanner",
            SignalKind::ScanAttackCorrelation => "scan_attack_correlation",
            SignalKind::SpoofedBot => "spoofed_bot",
            SignalKind::LlmMalicious => "llm_malicious",
            SignalKind::ExternalReputation => "external_reputation",
            SignalKind::TlsSniMismatch => "tls_sni_mismatch",
            SignalKind::ProtocolViolation => "protocol_violation",
            SignalKind::UploadTypeMismatch => "upload_type_mismatch",
            SignalKind::UploadPolyglot => "upload_polyglot",
            SignalKind::UploadExecutable => "upload_executable",
            SignalKind::UploadFlood => "upload_flood",
            SignalKind::RuleHit => "rule_hit",
            SignalKind::Custom => "custom",
        };
        self.scorer.weights.get(key).copied().unwrap_or_else(|| {
            signals
                .iter()
                .find(|s| s.kind == kind)
                .map(|s| s.weight)
                .unwrap_or(0)
        })
    }

    /// Weight for a concrete signal: config override if set, else the
    /// signal's own weight.
    fn weight_for_signal(&self, s: &Signal) -> u8 {
        let key = match s.kind {
            SignalKind::SqlInjection => "sql_injection",
            SignalKind::Xss => "xss",
            SignalKind::PathTraversal => "path_traversal",
            SignalKind::Lfi => "lfi",
            SignalKind::Log4Shell => "log4shell",
            SignalKind::Rce => "rce",
            SignalKind::UnknownRoute => "unknown_route",
            SignalKind::MethodNotAllowed => "method_not_allowed",
            SignalKind::ScanBehavior => "scan_behavior",
            SignalKind::RandomScan => "random_scan",
            SignalKind::AuthBruteForce => "auth_brute_force",
            SignalKind::SuspiciousLoginSuccess => "suspicious_login_success",
            SignalKind::CredentialStuffing => "credential_stuffing",
            SignalKind::DirectoryBruteForce => "directory_brute_force",
            SignalKind::AbnormalRate => "abnormal_rate",
            SignalKind::SuspiciousUA => "suspicious_ua",
            SignalKind::TorExitNode => "tor_exit_node",
            SignalKind::KnownBadIp => "known_bad_ip",
            SignalKind::SensitivePath => "sensitive_path",
            SignalKind::VpnProxy => "vpn_proxy",
            SignalKind::PromiscuousScanner => "promiscuous_scanner",
            SignalKind::BadCrawler => "bad_crawler",
            SignalKind::AnomalousPayload => "anomalous_payload",
            SignalKind::TcpScanner => "tcp_scanner",
            SignalKind::ScanAttackCorrelation => "scan_attack_correlation",
            SignalKind::SpoofedBot => "spoofed_bot",
            SignalKind::LlmMalicious => "llm_malicious",
            SignalKind::ExternalReputation => "external_reputation",
            SignalKind::TlsSniMismatch => "tls_sni_mismatch",
            SignalKind::ProtocolViolation => "protocol_violation",
            SignalKind::UploadTypeMismatch => "upload_type_mismatch",
            SignalKind::UploadPolyglot => "upload_polyglot",
            SignalKind::UploadExecutable => "upload_executable",
            SignalKind::UploadFlood => "upload_flood",
            SignalKind::RuleHit => "rule_hit",
            SignalKind::Custom => "custom",
        };
        self.scorer.weights.get(key).copied().unwrap_or(s.weight)
    }

    /// Score signals using config-defined weights + repetition bonus.
    fn score_with_weights(&self, signals: Vec<Signal>, bonus: u8) -> AnalysisResult {
        let base: u8 = signals
            .iter()
            .map(|s| self.weight_for(s.kind, &signals))
            .sum();
        let score = base.saturating_add(bonus).min(100);
        let level = RiskLevel::from_score(score);
        let verdict = match level {
            RiskLevel::Info | RiskLevel::Low => Verdict::Allow,
            RiskLevel::Medium => Verdict::RateLimit,
            RiskLevel::High => Verdict::Challenge,
            RiskLevel::Critical => Verdict::Block,
        };
        AnalysisResult {
            risk_score: score,
            risk_level: level,
            signals,
            verdict,
        }
    }

    /// Swap the ruleset (hot-reload).
    pub fn swap_rules(&self, new_rules: RuleSet) {
        let mut guard = self.rules.write().unwrap();
        *guard = new_rules;
    }

    /// Swap the route validator (hot-reload of learned/imported routes).
    pub fn swap_routes(&self, new_routes: RouteValidator) {
        let mut guard = self.routes.write().unwrap();
        *guard = new_routes;
    }

    /// Rescore an event with extra signals merged in (e.g. from the ONNX
    /// model), re-applying the scorer weights and the verdict policy.
    ///
    /// Used by the daemon after async stages that run outside the sync
    /// [`process`](Self::process) path.
    pub fn rescore(&self, evt: &Event, extra_signals: Vec<Signal>) -> ProcessedEvent {
        let mut signals = self.heuristics.analyze(evt);
        signals.extend(crate::reputation::reputation_signals(evt));
        signals.extend(self.routes.read().unwrap().validate(evt));
        signals.extend(extra_signals);

        let bonus = if let Some(ref rep) = self.repetition {
            let mut tracker = rep.write().unwrap();
            tracker.record(evt.client_ip, &signals)
        } else {
            0
        };

        let analysis = if self.scorer.weights.is_empty() && bonus == 0 {
            AnalysisResult::from_signals(signals)
        } else {
            self.score_with_weights(signals, bonus)
        };

        let (action, override_reason) = self.policy.decide(analysis.risk_level, evt);
        let decision = Decision {
            analysis: analysis.clone(),
            action,
            override_reason,
            log_level: None,
        };

        ProcessedEvent {
            event: evt.clone(),
            analysis,
            decision,
            rule_hit: None,
        }
    }

    /// Re-score an already-processed event with extra signals merged in,
    /// without re-running any tracker.
    ///
    /// This is the feedback hook for async fork stages (the ML threat
    /// model): the extra signals are weighted with the configured scorer
    /// weights and added on top of the base score, so the fork can only ever
    /// *raise* the risk, never lower it. Escalation uses the IP's current
    /// strikes without recording a new one (the hot path already recorded
    /// a strike for this event when it earned a non-Allow verdict).
    pub fn rescore_from(
        &self,
        base: &ProcessedEvent,
        extra_signals: Vec<Signal>,
    ) -> ProcessedEvent {
        if extra_signals.is_empty() {
            return base.clone();
        }
        // Never elevate a trusted IP, no matter what a fork stage claims.
        if let Some(trust) = &self.trust {
            if trust.is_never_ban(base.event.client_ip) {
                return base.clone();
            }
        }
        let extra_weight: u8 = extra_signals
            .iter()
            .map(|s| self.weight_for_signal(s))
            .sum();
        let mut signals = base.analysis.signals.clone();
        signals.extend(extra_signals);
        let score = base
            .analysis
            .risk_score
            .saturating_add(extra_weight)
            .min(100);
        let level = RiskLevel::from_score(score);
        let verdict = match level {
            RiskLevel::Info | RiskLevel::Low => Verdict::Allow,
            RiskLevel::Medium => Verdict::RateLimit,
            RiskLevel::High => Verdict::Challenge,
            RiskLevel::Critical => Verdict::Block,
        };
        let analysis = AnalysisResult {
            risk_score: score,
            risk_level: level,
            signals,
            verdict,
        };
        let (action, override_reason) = self.policy.decide(level, &base.event);
        let mut decision = Decision {
            analysis: analysis.clone(),
            action,
            override_reason,
            log_level: base.decision.log_level,
        };
        if decision.action != Verdict::Allow {
            if let Some(ref offender) = self.offender {
                let tracker = offender.read().unwrap();
                if let Some((verdict, reason)) = tracker.escalate_current(
                    base.event.client_ip,
                    decision.action,
                    &self.escalation,
                ) {
                    decision.action = verdict;
                    decision.override_reason = Some(reason);
                }
            }
        }
        self.cap_shadow(
            base.event.client_ip,
            ProcessedEvent {
                event: base.event.clone(),
                analysis,
                decision,
                rule_hit: base.rule_hit.clone(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpData, ProtocolData, SourceKind};
    use crate::rules::{Rule, RuleAction, RuleMatch, RuleSet, SharedRuleSet};
    use std::net::Ipv4Addr;

    fn http_evt(path: &str) -> Event {
        Event::new(
            SourceKind::Synthetic,
            std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                ..Default::default()
            }),
        )
    }

    fn pipeline() -> Pipeline {
        Pipeline::new(RuleSet::default(), RouteValidator::default())
    }

    #[test]
    fn clean_event_gets_allow() {
        let p = pipeline();
        let evt = http_evt("/api/users");
        let result = p.process(&evt);
        assert_eq!(result.decision.action, Verdict::Allow);
    }

    #[test]
    fn sqli_gets_high_or_critical() {
        let p = pipeline();
        let evt = http_evt("/login?user='+OR+1=1--");
        let result = p.process(&evt);
        assert!(result.analysis.risk_score >= 50);
    }

    #[test]
    fn unknown_route_adds_signal() {
        let routes = RouteValidator::new(vec![RouteDef {
            path: "/api/*".into(),
            methods: vec![],
        }]);
        let p = Pipeline::new(RuleSet::default(), routes);
        let evt = http_evt("/admin/login");
        let result = p.process(&evt);
        assert!(result
            .analysis
            .signals
            .iter()
            .any(|s| { s.kind == crate::analysis::SignalKind::UnknownRoute }));
    }

    #[test]
    fn hot_reload_swaps_ruleset() {
        let p = pipeline();
        let new_rules = RuleSet::new(vec![Rule {
            id: "block-all".into(),
            name: "block all".into(),
            priority: 1,
            enabled: true,
            match_: RuleMatch::Ip {
                cidr: "0.0.0.0/0".into(),
            },
            action: RuleAction::Block,
            ttl: None,
            source: crate::rules::RuleSource::Config,
            tags: vec![],
            created_at: None,
            log_level: None,
        }]);
        p.swap_rules(new_rules);
        let evt = http_evt("/api/users");
        let result = p.process(&evt);
        assert_eq!(result.decision.action, Verdict::Block);
    }

    #[test]
    fn repetition_bonus_accumulates() {
        let scorer = ScorerConfig {
            repetition_bonus: true,
            repetition_window_secs: 60,
            ..Default::default()
        };
        let rules: SharedRuleSet = Arc::new(RwLock::new(RuleSet::default()));
        let routes = RouteValidator::default();
        let p = Pipeline::with_config(rules, routes, scorer, VerdictPolicy::default());

        let evt = http_evt("/nonexistent");
        let r1 = p.process(&evt);
        let r2 = p.process(&evt);
        assert!(r2.analysis.risk_score >= r1.analysis.risk_score);
    }

    #[test]
    fn config_driven_routes() {
        let route_configs = vec![RouteDefConfig {
            path: "/api/*".into(),
            methods: vec!["GET".into()],
        }];
        let routes = RouteValidator::from_config(&route_configs);
        assert!(routes.is_known("/api/users"));
        assert!(!routes.is_known("/admin"));
    }

    #[test]
    fn template_route_matches_single_segment() {
        let routes = RouteValidator::new(vec![RouteDef {
            path: "/users/{id}".into(),
            methods: vec![],
        }]);
        assert!(routes.is_known("/users/42"));
        assert!(routes.is_known("/Users/ABC"));
        assert!(!routes.is_known("/users"));
        assert!(!routes.is_known("/users/42/posts"));
    }

    #[test]
    fn template_route_multiple_params() {
        let routes = RouteValidator::new(vec![RouteDef {
            path: "/users/{id}/posts/{post_id}".into(),
            methods: vec![],
        }]);
        assert!(routes.is_known("/users/42/posts/7"));
        assert!(!routes.is_known("/users/42/posts"));
        assert!(!routes.is_known("/users/42/posts/7/comments"));
    }

    #[test]
    fn template_route_trailing_wildcard() {
        let routes = RouteValidator::new(vec![RouteDef {
            path: "/static/{version}/*".into(),
            methods: vec![],
        }]);
        assert!(routes.is_known("/static/v1/css/app.css"));
        assert!(routes.is_known("/static/v1"));
        assert!(!routes.is_known("/static"));
    }

    #[test]
    fn template_param_rejects_empty_segment() {
        assert!(!template_match("/users/{id}", "/users/"));
        assert!(template_match("/users/{id}", "/users/0"));
    }

    fn http_evt_method(path: &str, method: crate::event::HttpMethod) -> Event {
        Event::new(
            SourceKind::Synthetic,
            std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                method: Some(method),
                ..Default::default()
            }),
        )
    }

    #[test]
    fn method_not_allowed_on_known_route() {
        let routes = RouteValidator::new(vec![RouteDef {
            path: "/api/users".into(),
            methods: vec!["GET".into()],
        }]);
        let p = Pipeline::new(RuleSet::default(), routes);

        let get = p.process(&http_evt_method(
            "/api/users",
            crate::event::HttpMethod::Get,
        ));
        assert!(get
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::MethodNotAllowed && s.kind != SignalKind::UnknownRoute));

        let post = p.process(&http_evt_method(
            "/api/users",
            crate::event::HttpMethod::Post,
        ));
        assert!(post
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::MethodNotAllowed));
    }

    #[test]
    fn empty_methods_allows_any() {
        let routes = RouteValidator::new(vec![RouteDef {
            path: "/api/users".into(),
            methods: vec![],
        }]);
        let p = Pipeline::new(RuleSet::default(), routes);
        let res = p.process(&http_evt_method(
            "/api/users",
            crate::event::HttpMethod::Delete,
        ));
        assert!(res
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::MethodNotAllowed));
    }

    fn http_evt_status(path: &str, status: u16) -> Event {
        Event::new(
            SourceKind::Synthetic,
            std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                status: Some(status),
                method: Some(crate::event::HttpMethod::Get),
                user_agent: Some("Mozilla/5.0 (X11; Linux x86_64)".into()),
                ..Default::default()
            }),
        )
    }

    fn escalation_cfg() -> crate::config::EscalationConfig {
        crate::config::EscalationConfig {
            enabled: true,
            window_secs: 3600,
            challenge_at: 3,
            block_at: 5,
            persist: false,
        }
    }

    #[test]
    fn env_sweep_escalates_to_challenge_then_block() {
        let offender = Arc::new(RwLock::new(OffenderTracker::from_config(&escalation_cfg())));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_offender(Arc::clone(&offender), escalation_cfg());

        let paths = [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.staging",
            "/.env.test",
        ];
        let verdicts: Vec<Verdict> = paths
            .iter()
            .map(|path| p.process(&http_evt_status(path, 404)).decision.action)
            .collect();
        assert_eq!(
            &verdicts[..3],
            &[Verdict::RateLimit, Verdict::RateLimit, Verdict::Challenge]
        );
        assert_eq!(&verdicts[3..], &[Verdict::Challenge, Verdict::Block]);
    }

    #[test]
    fn allow_events_do_not_record_strikes() {
        let offender = Arc::new(RwLock::new(OffenderTracker::from_config(&escalation_cfg())));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_offender(Arc::clone(&offender), escalation_cfg());

        for _ in 0..10 {
            let r = p.process(&http_evt_status("/api/users", 200));
            assert_eq!(r.decision.action, Verdict::Allow);
        }
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(offender.read().unwrap().strikes(ip), 0);
    }

    #[test]
    fn random_scan_burst_emits_signal() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 8, 1000)));
        let p =
            Pipeline::new(RuleSet::default(), RouteValidator::default()).with_scan_tracker(scan);

        let mut last = None;
        for i in 0..8 {
            last = Some(p.process(&http_evt_status(&format!("/f{i}.php"), 404)));
        }
        let r = last.unwrap();
        assert!(r
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::RandomScan));
        assert!(r.analysis.risk_score >= 33);
        assert_eq!(r.decision.action, Verdict::RateLimit);
    }

    fn http_evt_from_ip(ip: IpAddr, path: &str) -> Event {
        Event::new(
            SourceKind::Synthetic,
            ip,
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                ..Default::default()
            }),
        )
    }

    #[test]
    fn response_observation_queues_scan_signals_for_next_request() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 8, 1000)));
        let p =
            Pipeline::new(RuleSet::default(), RouteValidator::default()).with_scan_tracker(scan);
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));

        // Request phase has no status (the edge scores before proxying), so
        // the burst alone stays LOW/Allow...
        for i in 0..8 {
            let r = p.process(&http_evt_from_ip(ip, &format!("/f{i}.php")));
            assert_eq!(r.decision.action, Verdict::Allow);
            // ...and the response phase feeds the tracker with the real 404.
            let sigs = p.observe_response(ip, &format!("/f{i}.php"), 404, None);
            if i < 7 {
                assert!(
                    sigs.iter().all(|s| s.kind != SignalKind::RandomScan),
                    "iteration {i}"
                );
            } else {
                assert!(
                    sigs.iter().any(|s| s.kind == SignalKind::RandomScan),
                    "8th distinct path must cross the threshold"
                );
            }
        }
        // The next request carries the queued signal and gets enforced.
        // 18 (UA+route) + 25 (RandomScan) + 10 repetition = 53 → High.
        let next = p.process(&http_evt_from_ip(ip, "/g.php"));
        assert!(next
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::RandomScan));
        assert_eq!(next.decision.action, Verdict::Challenge);
    }

    #[test]
    fn pending_response_signals_do_not_leak_across_ips() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 2, 1000)));
        let p =
            Pipeline::new(RuleSet::default(), RouteValidator::default()).with_scan_tracker(scan);
        let scanner = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));
        let other = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));

        assert!(p.observe_response(scanner, "/a.php", 404, None).is_empty());
        p.observe_response(scanner, "/b.php", 404, None);

        let r = p.process(&http_evt_from_ip(other, "/c.php"));
        assert!(r
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::RandomScan));
        assert_eq!(r.decision.action, Verdict::Allow);
    }

    #[test]
    fn successful_responses_leave_no_pending_signals() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 2, 2)));
        let p =
            Pipeline::new(RuleSet::default(), RouteValidator::default()).with_scan_tracker(scan);
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));

        for i in 0..10 {
            p.process(&http_evt_from_ip(ip, &format!("/api/items/{i}")));
            assert!(p
                .observe_response(ip, &format!("/api/items/{i}"), 200, None)
                .is_empty());
        }
        let r = p.process(&http_evt_from_ip(ip, "/api/items/11"));
        assert!(r
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::RandomScan && s.kind != SignalKind::ScanBehavior));
        // No state leaked: a single 404 after all the 200s starts from zero.
        assert!(p.observe_response(ip, "/first-404", 404, None).is_empty());
    }

    #[test]
    fn pending_signals_are_consumed_once() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 1, 1000)));
        let p =
            Pipeline::new(RuleSet::default(), RouteValidator::default()).with_scan_tracker(scan);
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));

        p.observe_response(ip, "/a.php", 404, None);
        let first = p.process(&http_evt_from_ip(ip, "/b.php"));
        assert!(first
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::RandomScan));
        let second = p.process(&http_evt_from_ip(ip, "/c.php"));
        assert!(second
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::RandomScan));
    }

    #[test]
    fn prune_pending_keeps_live_entries() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 1, 1000)));
        let p =
            Pipeline::new(RuleSet::default(), RouteValidator::default()).with_scan_tracker(scan);
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));

        p.observe_response(ip, "/a.php", 404, None);
        p.prune_pending();
        let r = p.process(&http_evt_from_ip(ip, "/b.php"));
        assert!(r
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::RandomScan));
    }

    #[test]
    fn response_observation_feeds_behavior_trackers() {
        let behavior = Arc::new(RwLock::new(BehaviorTracker::new(300, 3, 100, 100)));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_behavior_tracker(behavior);
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));
        let ua = "Mozilla/5.0 (X11; Linux x86_64)";

        for _ in 0..3 {
            p.process(&http_evt_from_ip(ip, "/login"));
            p.observe_response(ip, "/login", 401, Some(ua));
        }
        let next = p.process(&http_evt_from_ip(ip, "/login"));
        assert!(next
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::AuthBruteForce));
    }

    #[test]
    fn recurring_response_signals_escalate_to_block() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 8, 1000)));
        let cfg = escalation_cfg();
        let offender = Arc::new(RwLock::new(OffenderTracker::from_config(&cfg)));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_scan_tracker(scan)
            .with_offender(Arc::clone(&offender), cfg);
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));

        let mut verdicts = Vec::new();
        for i in 0..14 {
            let r = p.process(&http_evt_from_ip(ip, &format!("/f{i}.php")));
            verdicts.push(r.decision.action);
            p.observe_response(ip, &format!("/f{i}.php"), 404, None);
        }
        assert_eq!(
            &verdicts[..8],
            &[Verdict::Allow; 8],
            "no status at request phase: all allowed"
        );
        // The drained RandomScan lands at 53 (18+25+10 repetition) → High →
        // Challenge from the first violating request; strikes then carry it
        // to Block at the 5th violation.
        assert_eq!(
            &verdicts[8..12],
            &[Verdict::Challenge; 4],
            "queued scan signals + strikes climb the ladder"
        );
        assert_eq!(verdicts[12], Verdict::Block);
        assert_eq!(verdicts[13], Verdict::Block);
    }

    fn http_evt_from(ip: IpAddr, path: &str, status: u16) -> Event {
        Event::new(
            SourceKind::Synthetic,
            ip,
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                status: Some(status),
                method: Some(crate::event::HttpMethod::Get),
                user_agent: Some("Mozilla/5.0 (X11; Linux x86_64)".into()),
                ..Default::default()
            }),
        )
    }

    #[test]
    fn scan_attack_correlation_across_prefix() {
        let scanner = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 2, 1000)));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_scan_tracker(Arc::clone(&scan))
            .with_correlation_tracker(Arc::new(RwLock::new(CorrelationTracker::new(900))));

        p.process(&http_evt_from(scanner, "/a.php", 404));
        p.process(&http_evt_from(scanner, "/b.php", 404));

        let correlated = p.process(&http_evt_from(attacker, "/login?user='+OR+1=1--", 200));
        let sig = correlated
            .analysis
            .signals
            .iter()
            .find(|s| s.kind == SignalKind::ScanAttackCorrelation)
            .expect("404-burst neighbor must correlate with the SQLi");
        assert_eq!(sig.weight, 20);
        let detail = sig.detail.as_deref().unwrap();
        assert!(detail.contains("http-random-path-scan"), "detail: {detail}");
        assert!(detail.contains("198.51.100.7"), "detail: {detail}");
        assert!(detail.contains("same /24"), "detail: {detail}");

        let quiet = Pipeline::new(RuleSet::default(), RouteValidator::default());
        let base = quiet.process(&http_evt_from(attacker, "/login?user='+OR+1=1--", 200));
        assert!(correlated.analysis.risk_score > base.analysis.risk_score);
    }

    #[test]
    fn same_ip_scan_does_not_correlate() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 2, 1000)));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_scan_tracker(scan)
            .with_correlation_tracker(Arc::new(RwLock::new(CorrelationTracker::new(900))));

        p.process(&http_evt_from(ip, "/a.php", 404));
        p.process(&http_evt_from(ip, "/b.php", 404));
        let r = p.process(&http_evt_from(ip, "/login?user='+OR+1=1--", 200));
        assert!(r
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::ScanAttackCorrelation));
    }

    #[test]
    fn attack_without_prior_scan_stays_quiet() {
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_correlation_tracker(Arc::new(RwLock::new(CorrelationTracker::new(900))));
        let r = p.process(&http_evt_status("/login?user='+OR+1=1--", 200));
        assert!(r
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::ScanAttackCorrelation));
    }

    #[test]
    fn tcp_syn_scan_correlates_with_neighbor_attack() {
        let scanner = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_correlation_tracker(Arc::new(RwLock::new(CorrelationTracker::new(900))));

        let syn = Event::new(
            SourceKind::Synthetic,
            scanner,
            ProtocolData::Tcp(crate::event::TcpData {
                fingerprint: Some("65535:::".into()),
                ..Default::default()
            }),
        );
        let scanned = p.process(&syn);
        assert!(scanned
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::TcpScanner));

        let r = p.process(&http_evt_from(attacker, "/login?user='+OR+1=1--", 200));
        let sig = r
            .analysis
            .signals
            .iter()
            .find(|s| s.kind == SignalKind::ScanAttackCorrelation)
            .expect("masscan-style SYN must correlate with the SQLi");
        assert!(
            sig.detail.as_deref().unwrap().contains("tcp-syn"),
            "detail: {}",
            sig.detail.as_deref().unwrap()
        );
    }

    #[test]
    fn correlation_and_promiscuous_weights_are_configurable() {
        let scorer = ScorerConfig {
            weights: [
                ("scan_attack_correlation".to_string(), 7u8),
                ("promiscuous_scanner".to_string(), 3u8),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let p = Pipeline::with_config(
            Arc::new(RwLock::new(RuleSet::default())),
            RouteValidator::default(),
            scorer,
            VerdictPolicy::default(),
        );
        let corr = Signal {
            kind: SignalKind::ScanAttackCorrelation,
            weight: 20,
            detail: None,
        };
        let prom = Signal {
            kind: SignalKind::PromiscuousScanner,
            weight: 10,
            detail: None,
        };
        assert_eq!(p.weight_for_signal(&corr), 7);
        assert_eq!(p.weight_for_signal(&prom), 3);
        assert_eq!(p.weight_for(SignalKind::ScanAttackCorrelation, &[corr]), 7);
    }

    #[test]
    fn successful_traffic_never_triggers_scan_signals() {
        let scan = Arc::new(RwLock::new(ScanTracker::new(60, 2, 2)));
        let p =
            Pipeline::new(RuleSet::default(), RouteValidator::default()).with_scan_tracker(scan);
        for i in 0..10 {
            let r = p.process(&http_evt_status(&format!("/api/items/{i}"), 200));
            assert!(r
                .analysis
                .signals
                .iter()
                .all(|s| s.kind != SignalKind::RandomScan && s.kind != SignalKind::ScanBehavior));
        }
    }

    #[test]
    fn auth_brute_force_burst_emits_signal() {
        let behavior = Arc::new(RwLock::new(BehaviorTracker::new(300, 3, 100, 100)));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_behavior_tracker(behavior);

        let mut last = None;
        for _ in 0..3 {
            last = Some(p.process(&http_evt_status("/login", 401)));
        }
        let r = last.unwrap();
        assert!(r
            .analysis
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::AuthBruteForce));
        assert!(r.analysis.risk_score >= 35);
    }

    #[test]
    fn normal_traffic_never_triggers_behavior_signals() {
        let behavior = Arc::new(RwLock::new(BehaviorTracker::new(300, 2, 2, 2)));
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_behavior_tracker(behavior);
        for i in 0..10 {
            let r = p.process(&http_evt_status(&format!("/api/items/{i}"), 200));
            assert!(r.analysis.signals.iter().all(|s| {
                s.kind != SignalKind::AuthBruteForce
                    && s.kind != SignalKind::CredentialStuffing
                    && s.kind != SignalKind::DirectoryBruteForce
            }));
        }
    }

    fn googlebot_evt(ip: IpAddr, ua: &str) -> Event {
        Event::new(
            SourceKind::Synthetic,
            ip,
            ProtocolData::Http(HttpData {
                path: "/api/users".into(),
                method: Some(crate::event::HttpMethod::Get),
                user_agent: Some(ua.into()),
                ..Default::default()
            }),
        )
    }

    #[test]
    fn spoofed_bot_claim_emits_signal() {
        let verifier = Arc::new(crate::botverify::BotVerifier::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        ));
        let p = pipeline().with_bot_verifier(verifier.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

        // First event: pending, no signal yet.
        let first = p.process(&googlebot_evt(ip, ua));
        assert!(first
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::SpoofedBot));

        // DNS verification fails → next event carries the spoofed signal.
        verifier.insert(ip, crate::botverify::BotStatus::Spoofed);
        let second = p.process(&googlebot_evt(ip, ua));
        let sig = second
            .analysis
            .signals
            .iter()
            .find(|s| s.kind == SignalKind::SpoofedBot)
            .expect("spoofed Googlebot claim must be flagged");
        assert_eq!(sig.weight, 35);
        assert!(sig.detail.as_deref().unwrap().contains("google"));
        assert!(second.analysis.risk_score >= 35);
    }

    #[test]
    fn verified_bot_claim_never_signals() {
        let verifier = Arc::new(crate::botverify::BotVerifier::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        ));
        let p = pipeline().with_bot_verifier(verifier.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        verifier.insert(
            ip,
            crate::botverify::BotStatus::Verified(crate::botverify::BotEngine::Google),
        );
        let r = p.process(&googlebot_evt(
            ip,
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
        ));
        assert!(r
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::SpoofedBot));
        assert_eq!(r.decision.action, Verdict::Allow);
    }

    #[test]
    fn bots_ua_without_verifier_untouched() {
        let p = pipeline();
        let r = p.process(&googlebot_evt(
            IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1)),
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
        ));
        assert!(r.event.bot.is_none());
    }

    #[test]
    fn crawlers_good_allow_requires_verification_when_gated() {
        let mut packs = std::collections::HashMap::new();
        packs.insert("crawlers_good".to_string(), "enforce".to_string());
        let gated = crate::packs::build_default_ruleset_with(&packs, true);
        let ungated = crate::packs::build_default_ruleset_with(&packs, false);

        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        let ua = "Googlebot/2.1 (+http://www.google.com/bot.html)";

        // Ungated: UA alone short-circuits to Allow.
        let p = Pipeline::new(ungated, RouteValidator::default());
        let r = p.process(&googlebot_evt(ip, ua));
        assert_eq!(r.decision.action, Verdict::Allow);
        assert_eq!(r.rule_hit.as_deref(), Some("crawlers_good"));

        // Gated: claim without verification doesn't earn the rule Allow
        // (the event flows on to heuristics like any unclaimed client).
        let verifier = Arc::new(crate::botverify::BotVerifier::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        ));
        let p = Pipeline::new(gated, RouteValidator::default()).with_bot_verifier(verifier.clone());
        let res = p.process(&googlebot_evt(ip, ua));
        assert!(res.rule_hit.is_none());

        // After a verified result the Allow short-circuit applies again.
        verifier.insert(
            ip,
            crate::botverify::BotStatus::Verified(crate::botverify::BotEngine::Google),
        );
        let ok = p.process(&googlebot_evt(ip, ua));
        assert_eq!(ok.decision.action, Verdict::Allow);
        assert_eq!(
            ok.rule_hit.as_deref(),
            Some("crawlers_good_verified"),
            "rule ids: {:?}",
            ok.rule_hit
        );
    }

    #[test]
    fn dsl_bot_verified_condition_round_trip() {
        let m = crate::rules::dsl::parse("bot_verified=true").unwrap();
        assert!(matches!(m, RuleMatch::BotVerified(v) if v == "true"));
        let m = crate::rules::dsl::parse("bot_verified=google").unwrap();
        assert!(matches!(m, RuleMatch::BotVerified(v) if v == "google"));
        assert!(crate::rules::dsl::parse("bot_verified=bogus").is_err());
    }

    #[test]
    fn dsl_upload_filename_condition_matches_parts() {
        let m = crate::rules::dsl::parse(r#"upload_filename contains ".php""#).unwrap();
        assert!(matches!(m, RuleMatch::UploadFilename(_)));

        let with_upload = Event::new(
            SourceKind::Synthetic,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: "/upload".into(),
                uploads: Some(vec![crate::event::UploadInfo {
                    field_name: Some("file".into()),
                    filename: Some("shell.php".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        );
        assert!(m.matches(&with_upload));

        let clean = Event::new(
            SourceKind::Synthetic,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: "/upload".into(),
                uploads: Some(vec![crate::event::UploadInfo {
                    filename: Some("cat.png".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        );
        assert!(!m.matches(&clean));
        assert!(!m.matches(&http_evt("/upload")));
    }

    #[test]
    fn upload_flood_signal_flows_through_pipeline() {
        let mut cfg = crate::config::UploadsConfig::default();
        cfg.enabled = true;
        cfg.flood.max_uploads = 2;
        let upload_tracker = Arc::new(RwLock::new(crate::uploads::UploadTracker::from_config(
            &cfg,
        )));
        let mut p = pipeline().with_upload_tracker(upload_tracker);
        p.configure_uploads(&cfg);

        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23));
        let uploads = vec![crate::event::UploadInfo {
            filename: Some("f.bin".into()),
            size: 1024,
            ..Default::default()
        }];
        let evt_with = |uploads: Vec<crate::event::UploadInfo>| {
            Event::new(
                SourceKind::Synthetic,
                ip,
                ProtocolData::Http(HttpData {
                    path: "/upload".into(),
                    user_agent: Some("Mozilla/5.0".into()),
                    uploads: Some(uploads),
                    ..Default::default()
                }),
            )
        };
        assert!(p
            .process(&evt_with(uploads.clone()))
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != SignalKind::UploadFlood));
        let second = p.process(&evt_with(uploads));
        assert!(
            second
                .analysis
                .signals
                .iter()
                .any(|s| s.kind == SignalKind::UploadFlood && s.weight == 0),
            "shadow mode: detected at threshold but weight 0"
        );
    }

    #[test]
    fn rescore_from_adds_weight_and_escalates_without_new_strike() {
        let cfg = crate::config::EscalationConfig {
            challenge_at: 1,
            block_at: 2,
            ..escalation_cfg()
        };
        let offender = Arc::new(RwLock::new(OffenderTracker::from_config(&cfg)));
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        offender
            .write()
            .unwrap()
            .seed(ip, 2, 2, std::time::Duration::ZERO);
        let p = Pipeline::new(RuleSet::default(), RouteValidator::default())
            .with_offender(Arc::clone(&offender), cfg);

        let base = p.process(&http_evt_status("/api/users", 200));
        assert_eq!(base.decision.action, Verdict::Allow);

        let extra = vec![Signal {
            kind: SignalKind::AnomalousPayload,
            weight: 40,
            detail: None,
        }];
        let r = p.rescore_from(&base, extra);
        assert_eq!(r.analysis.risk_score, 48);
        assert_eq!(r.decision.action, Verdict::Block);
        assert!(r
            .decision
            .override_reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("offender escalation")));
        assert_eq!(offender.read().unwrap().strikes(ip), 2);
    }

    #[test]
    fn blacklisted_ip_short_circuits_to_block() {
        let mut rc = crate::config::RealIpConfig::default();
        rc.blacklist = vec!["1.2.3.0/24".into()];
        let p = pipeline().with_trust(crate::trust::SharedTrustSet::new(
            crate::trust::TrustSet::from_config(&rc).unwrap(),
        ));
        let r = p.process(&http_evt("/admin/.env"));
        assert_eq!(r.decision.action, Verdict::Block);
        assert_eq!(
            r.decision.override_reason.as_deref(),
            Some("blacklisted ip")
        );
        assert_eq!(r.analysis.risk_score, 100);
    }

    #[test]
    fn shadow_ip_is_analyzed_but_never_blocked() {
        let mut rc = crate::config::RealIpConfig::default();
        rc.shadow = vec!["1.2.3.0/24".into()];
        let p = pipeline().with_trust(crate::trust::SharedTrustSet::new(
            crate::trust::TrustSet::from_config(&rc).unwrap(),
        ));

        let base = p.process(&http_evt("/api/users"));
        assert_eq!(base.decision.action, Verdict::Allow);

        let extra = vec![Signal {
            kind: SignalKind::AnomalousPayload,
            weight: 90,
            detail: None,
        }];
        let r = p.rescore_from(&base, extra);
        // Signals were fully analyzed (Critical band) but the ban is capped
        // to a challenge.
        assert!(
            r.analysis.risk_score >= 90,
            "score was {}",
            r.analysis.risk_score
        );
        assert_eq!(r.analysis.risk_level, RiskLevel::Critical);
        assert_eq!(r.decision.action, Verdict::Challenge);
        assert_eq!(
            r.decision.override_reason.as_deref(),
            Some("shadow ip (no ban)")
        );
    }

    #[test]
    fn non_shadow_ip_still_blocks_normally() {
        let extra = vec![Signal {
            kind: SignalKind::AnomalousPayload,
            weight: 90,
            detail: None,
        }];
        let r = pipeline().rescore_from(&pipeline().process(&http_evt("/api/users")), extra);
        assert_eq!(r.decision.action, Verdict::Block);
    }
}
