//! Pipeline: ties together rules engine, heuristics, route validator and scorer.
//!
//! The pipeline is the heart of the daemon. For each event it:
//! 1. Evaluates rules (fast path — allowlist/blocklist short-circuit)
//! 2. Runs heuristics (SQLi, XSS, path traversal, etc.)
//! 3. Validates route (unknown route → signal)
//! 4. Combines signals into a risk score
//! 5. Applies policy to produce a final decision

use crate::analysis::{AnalysisResult, Decision, Signal, Verdict};
use crate::event::Event;
use crate::heuristics::HeuristicEngine;
use crate::rules::RuleSet;

/// Route definition for the route validator.
#[derive(Debug, Clone)]
pub struct RouteDef {
    /// Path pattern (exact or glob like `/api/*`).
    pub path: String,
    /// Allowed methods (empty = any).
    pub methods: Vec<String>,
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

/// The analysis pipeline.
pub struct Pipeline {
    rules: RuleSet,
    heuristics: HeuristicEngine,
    routes: RouteValidator,
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
        Self {
            rules,
            heuristics: HeuristicEngine::with_defaults(),
            routes,
        }
    }

    /// Process a single event through the full pipeline.
    pub fn process(&self, evt: &Event) -> ProcessedEvent {
        // 1. Rules engine (fast path).
        if let Some((rule, short_circuit)) = self.rules.evaluate(evt) {
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
                        Verdict::Allow => crate::analysis::RiskLevel::Info,
                        Verdict::RateLimit => crate::analysis::RiskLevel::Medium,
                        Verdict::Challenge => crate::analysis::RiskLevel::High,
                        Verdict::Block => crate::analysis::RiskLevel::Critical,
                        Verdict::Quarantine => crate::analysis::RiskLevel::Medium,
                    },
                    signals: vec![Signal {
                        kind: crate::analysis::SignalKind::RuleHit,
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
            // Log/Tag: annotate and continue.
        }

        // 2. Heuristics.
        let mut signals = self.heuristics.analyze(evt);

        // 3. Route validation.
        signals.extend(self.routes.validate(evt));

        // 4. Score.
        let analysis = AnalysisResult::from_signals(signals);

        // 5. Decision (policy is straightforward for now: trust the scorer).
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpData, ProtocolData, SourceKind};
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

    #[test]
    fn clean_event_gets_allow() {
        let pipeline = Pipeline::new(RuleSet::default(), RouteValidator::default());
        let evt = http_evt("/api/users");
        let result = pipeline.process(&evt);
        assert_eq!(result.decision.action, Verdict::Allow);
    }

    #[test]
    fn sqli_gets_high_or_critical() {
        let pipeline = Pipeline::new(RuleSet::default(), RouteValidator::default());
        let evt = http_evt("/login?user='+OR+1=1--");
        let result = pipeline.process(&evt);
        assert!(result.analysis.risk_score >= 50);
    }

    #[test]
    fn unknown_route_adds_signal() {
        let pipeline = Pipeline::new(
            RuleSet::default(),
            RouteValidator::new(vec![RouteDef {
                path: "/api/*".into(),
                methods: vec![],
            }]),
        );
        let evt = http_evt("/admin/login");
        let result = pipeline.process(&evt);
        assert!(result
            .analysis
            .signals
            .iter()
            .any(|s| { s.kind == crate::analysis::SignalKind::UnknownRoute }));
    }
}
