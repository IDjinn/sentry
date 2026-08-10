//! Verdict policy: the configurable mapping from detection to action.
//!
//! Detection ([`AnalysisResult`](crate::analysis::AnalysisResult)) says *what
//! we found*; the policy says *what to do about it*. The default policy keeps
//! the historical mapping (Info/Low → Allow, Medium → RateLimit, High →
//! Challenge, Critical → Block) but every level can be remapped in
//! `sentry.toml` and ordered `[[policy.override]]` entries (DSL match +
//! verdict) can force a verdict for specific traffic.

use crate::analysis::{RiskLevel, Verdict};
use crate::config::PolicyConfig;
use crate::error::{CoreError, Result};
use crate::event::Event;
use crate::rules::{dsl, RuleMatch};

/// Configurable verdict policy used by the decider stage.
pub struct VerdictPolicy {
    /// Verdict per risk level, indexed by [`RiskLevel`] order (Info..Critical).
    level_map: [Verdict; 5],
    /// Ordered overrides: first DSL expression matching the event wins.
    overrides: Vec<(String, RuleMatch, Verdict)>,
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self {
            level_map: [
                Verdict::Allow,
                Verdict::Allow,
                Verdict::RateLimit,
                Verdict::Challenge,
                Verdict::Block,
            ],
            overrides: Vec::new(),
        }
    }
}

impl VerdictPolicy {
    /// Build a policy from config, parsing verdict names and DSL expressions.
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self> {
        let level_map = [
            parse_verdict(&cfg.info)?,
            parse_verdict(&cfg.low)?,
            parse_verdict(&cfg.medium)?,
            parse_verdict(&cfg.high)?,
            parse_verdict(&cfg.critical)?,
        ];
        let mut overrides = Vec::with_capacity(cfg.overrides.len());
        for o in &cfg.overrides {
            let match_ = dsl::parse(&o.r#match)
                .map_err(|e| CoreError::InvalidRuleExpr(format!("policy override: {e}")))?;
            let verdict = parse_verdict(&o.verdict)?;
            overrides.push((o.r#match.clone(), match_, verdict));
        }
        Ok(Self {
            level_map,
            overrides,
        })
    }

    /// Decide the final action for an event with the given risk level.
    ///
    /// Returns the verdict plus an override reason when a `[[policy.override]]`
    /// entry fired (used in [`Decision::override_reason`](crate::analysis::Decision)).
    pub fn decide(&self, level: RiskLevel, evt: &Event) -> (Verdict, Option<String>) {
        for (expr, match_, verdict) in &self.overrides {
            if match_.matches(evt) {
                return (*verdict, Some(format!("policy override '{expr}' matched")));
            }
        }
        (self.level_map[level_index(level)], None)
    }
}

fn level_index(level: RiskLevel) -> usize {
    match level {
        RiskLevel::Info => 0,
        RiskLevel::Low => 1,
        RiskLevel::Medium => 2,
        RiskLevel::High => 3,
        RiskLevel::Critical => 4,
    }
}

fn parse_verdict(s: &str) -> Result<Verdict> {
    match s.to_ascii_lowercase().as_str() {
        "allow" => Ok(Verdict::Allow),
        "rate_limit" | "ratelimit" => Ok(Verdict::RateLimit),
        "challenge" => Ok(Verdict::Challenge),
        "block" => Ok(Verdict::Block),
        "quarantine" => Ok(Verdict::Quarantine),
        other => Err(CoreError::Config(format!("unknown verdict '{other}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyOverrideConfig;
    use crate::event::{HttpData, ProtocolData, SourceKind};
    use std::net::Ipv4Addr;

    fn evt(path: &str) -> Event {
        Event::new(
            SourceKind::Synthetic,
            std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                ..Default::default()
            }),
        )
    }

    #[test]
    fn default_policy_matches_historical_mapping() {
        let p = VerdictPolicy::default();
        let e = evt("/");
        assert_eq!(p.decide(RiskLevel::Info, &e).0, Verdict::Allow);
        assert_eq!(p.decide(RiskLevel::Low, &e).0, Verdict::Allow);
        assert_eq!(p.decide(RiskLevel::Medium, &e).0, Verdict::RateLimit);
        assert_eq!(p.decide(RiskLevel::High, &e).0, Verdict::Challenge);
        assert_eq!(p.decide(RiskLevel::Critical, &e).0, Verdict::Block);
        assert!(p.decide(RiskLevel::High, &e).1.is_none());
    }

    #[test]
    fn custom_level_map() {
        let cfg = PolicyConfig {
            medium: "block".into(),
            ..Default::default()
        };
        let p = VerdictPolicy::from_config(&cfg).unwrap();
        assert_eq!(p.decide(RiskLevel::Medium, &evt("/")).0, Verdict::Block);
        assert_eq!(p.decide(RiskLevel::High, &evt("/")).0, Verdict::Challenge);
    }

    #[test]
    fn override_fires_with_reason() {
        let cfg = PolicyConfig {
            overrides: vec![PolicyOverrideConfig {
                r#match: "path=/admin/*".into(),
                verdict: "block".into(),
            }],
            ..Default::default()
        };
        let p = VerdictPolicy::from_config(&cfg).unwrap();
        let (v, reason) = p.decide(RiskLevel::Low, &evt("/admin/users"));
        assert_eq!(v, Verdict::Block);
        assert!(reason.is_some());

        let (v2, reason2) = p.decide(RiskLevel::Low, &evt("/api"));
        assert_eq!(v2, Verdict::Allow);
        assert!(reason2.is_none());
    }

    #[test]
    fn first_override_wins() {
        let cfg = PolicyConfig {
            overrides: vec![
                PolicyOverrideConfig {
                    r#match: "path=/admin/*".into(),
                    verdict: "challenge".into(),
                },
                PolicyOverrideConfig {
                    r#match: "path=/admin/*".into(),
                    verdict: "block".into(),
                },
            ],
            ..Default::default()
        };
        let p = VerdictPolicy::from_config(&cfg).unwrap();
        assert_eq!(
            p.decide(RiskLevel::Low, &evt("/admin/x")).0,
            Verdict::Challenge
        );
    }

    #[test]
    fn invalid_verdict_errors() {
        let cfg = PolicyConfig {
            high: "explode".into(),
            ..Default::default()
        };
        assert!(VerdictPolicy::from_config(&cfg).is_err());
    }

    #[test]
    fn invalid_override_dsl_errors() {
        let cfg = PolicyConfig {
            overrides: vec![PolicyOverrideConfig {
                r#match: "this is not valid $$".into(),
                verdict: "block".into(),
            }],
            ..Default::default()
        };
        assert!(VerdictPolicy::from_config(&cfg).is_err());
    }
}
