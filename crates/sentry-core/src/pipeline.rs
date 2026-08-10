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
use std::time::Instant;

use crate::analysis::{AnalysisResult, Decision, RiskLevel, Signal, SignalKind, Verdict};
use crate::config::{RouteDefConfig, ScorerConfig};
use crate::event::Event;
use crate::heuristics::HeuristicEngine;
use crate::policy::VerdictPolicy;
use crate::ratelimit::RateLimitBackend;
use crate::rules::{RuleSet, SharedRuleSet};

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
    pub fn record(&mut self, ip: IpAddr, signals: &[Signal]) -> u8 {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);
        let entries = self.history.entry(ip).or_default();

        entries.retain(|(_, ts)| now.duration_since(*ts) < window);

        let mut bonus = 0u8;
        for s in signals {
            let count = entries.iter().filter(|(k, _)| *k == s.kind).count();
            if count > 0 {
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
}

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
        }
    }

    /// Attach a rate-limit backend (enables `RuleMatch::Rate` conditions).
    pub fn with_rate_limiter(mut self, backend: Arc<dyn RateLimitBackend>) -> Self {
        self.rate_limiter = Some(backend);
        self
    }

    /// Process a single event through the full pipeline.
    #[tracing::instrument(skip(self, evt), fields(id = %evt.id, ip = %evt.client_ip))]
    pub fn process(&self, evt: &Event) -> ProcessedEvent {
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
                };
                return ProcessedEvent {
                    event: evt.clone(),
                    analysis: result,
                    decision,
                    rule_hit: Some(rule.id.clone()),
                };
            }
        }
        drop(ruleset);

        let mut signals = self.heuristics.analyze(evt);
        signals.extend(self.routes.read().unwrap().validate(evt));

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
        };

        ProcessedEvent {
            event: evt.clone(),
            analysis,
            decision,
            rule_hit: None,
        }
    }

    /// Score signals using config-defined weights + repetition bonus.
    fn score_with_weights(&self, signals: Vec<Signal>, bonus: u8) -> AnalysisResult {
        let weight_for = |kind: SignalKind| -> u8 {
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
                SignalKind::AbnormalRate => "abnormal_rate",
                SignalKind::SuspiciousUA => "suspicious_ua",
                SignalKind::TorExitNode => "tor_exit_node",
                SignalKind::KnownBadIp => "known_bad_ip",
                SignalKind::SensitivePath => "sensitive_path",
                SignalKind::VpnProxy => "vpn_proxy",
                SignalKind::BadCrawler => "bad_crawler",
                SignalKind::AnomalousPayload => "anomalous_payload",
                SignalKind::LlmMalicious => "llm_malicious",
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
        };

        let base: u8 = signals.iter().map(|s| weight_for(s.kind)).sum();
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
        };

        ProcessedEvent {
            event: evt.clone(),
            analysis,
            decision,
            rule_hit: None,
        }
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
}
