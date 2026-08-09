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
use crate::rules::{RuleSet, SharedRuleSet};

/// Route definition for the route validator.
#[derive(Debug, Clone)]
pub struct RouteDef {
    /// Path pattern (exact or glob like `/api/*`).
    pub path: String,
    /// Allowed methods (empty = any).
    pub methods: Vec<String>,
}

impl RouteDef {
    /// Create from config.
    pub fn from_config(cfg: &RouteDefConfig) -> Self {
        Self {
            path: cfg.path.clone(),
            methods: cfg.methods.clone(),
        }
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

    /// Check if a path matches any known route.
    pub fn is_known(&self, path: &str) -> bool {
        let path_lower = path.to_ascii_lowercase();
        self.routes.iter().any(|r| {
            if r.path.contains('*') {
                glob_simple(&r.path.to_ascii_lowercase(), &path_lower)
            } else {
                r.path.to_ascii_lowercase() == path_lower
            }
        })
    }

    /// Validate an event, returning signals if the route is unknown.
    pub fn validate(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        if !self.is_known(&http.path) {
            vec![Signal {
                kind: crate::analysis::SignalKind::UnknownRoute,
                weight: 8,
                detail: Some(http.path.clone()),
            }]
        } else {
            vec![]
        }
    }
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
    routes: RouteValidator,
    scorer: ScorerConfig,
    repetition: Option<RwLock<RepetitionTracker>>,
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
        )
    }

    /// Create a pipeline with a shared ruleset (hot-reloadable), routes and scorer config.
    pub fn with_config(rules: SharedRuleSet, routes: RouteValidator, scorer: ScorerConfig) -> Self {
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
            routes,
            scorer,
            repetition,
        }
    }

    /// Process a single event through the full pipeline.
    #[tracing::instrument(skip(self, evt), fields(id = %evt.id, ip = %evt.client_ip))]
    pub fn process(&self, evt: &Event) -> ProcessedEvent {
        let ruleset = self.rules.read().unwrap();

        if let Some((rule, short_circuit)) = ruleset.evaluate(evt) {
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
        signals.extend(self.routes.validate(evt));

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

        let decision = Decision {
            analysis: analysis.clone(),
            action: analysis.verdict,
            override_reason: None,
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
        let p = Pipeline::with_config(rules, routes, scorer);

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
}
