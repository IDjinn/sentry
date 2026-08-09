//! Default rule packs: pre-built rules for common threats.
//!
//! Each pack generates [`Rule`]s that are merged into the active [`RuleSet`].
//! Packs can be in `shadow` (log only), `enforce` (act), or `off` mode.

use crate::rules::{Rule, RuleAction, RuleMatch, RuleSet, RuleSource};

/// Pack mode: `shadow` logs only, `enforce` acts, `off` disables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackMode {
    /// Log matches but don't act (shadow mode).
    Shadow,
    /// Act on matches (enforce mode).
    Enforce,
    /// Disabled.
    Off,
}

impl PackMode {
    /// Parse from a string.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "enforce" => Self::Enforce,
            "shadow" => Self::Shadow,
            _ => Self::Off,
        }
    }

    /// Whether this mode produces real actions.
    pub fn is_enforce(self) -> bool {
        self == Self::Enforce
    }
}

/// Build the default ruleset from configured pack modes.
pub fn build_default_ruleset(pack_modes: &std::collections::HashMap<String, String>) -> RuleSet {
    let mut rules = Vec::new();

    // sensitive_paths — always enforce (blocking .env/.git is always correct).
    let sp_mode = pack_modes
        .get("sensitive_paths")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Enforce);
    if sp_mode != PackMode::Off {
        rules.extend(sensitive_path_rules(sp_mode.is_enforce()));
    }

    // crawlers_bad
    let cb_mode = pack_modes
        .get("crawlers_bad")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if cb_mode != PackMode::Off {
        rules.extend(bad_crawler_rules(cb_mode.is_enforce()));
    }

    // empty_ua
    let eu_mode = pack_modes
        .get("empty_ua")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if eu_mode != PackMode::Off {
        rules.extend(empty_ua_rules(eu_mode.is_enforce()));
    }

    // http_anomaly
    let ha_mode = pack_modes
        .get("http_anomaly")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if ha_mode != PackMode::Off {
        rules.extend(http_anomaly_rules(ha_mode.is_enforce()));
    }

    RuleSet::new(rules)
}

/// Sensitive path rules — block access to `.env`, `.git/`, `.ssh/`, etc.
fn sensitive_path_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    let paths: &[&str] = &[
        r"^/\.(env|git|svn|hg|bzr|ssh|aws|gcp|azure|kube|docker|terraform|npmrc|pypirc|netrc|htpasswd|ds_store)",
        r"/(wp-admin|wp-login\.php|phpmyadmin|pma|adminer|wp-content)(?:/|$)",
        r"/server-status|/server-info|/nginx-status|/fpm-status",
        r"/actuator(/env|/heapdump|/threaddump)",
        r"\.(sql|bak|backup|old|swp|orig|save)$",
        r"/manager/html$",
    ];
    paths
        .iter()
        .enumerate()
        .map(|(i, pat)| Rule {
            id: format!("sensitive_path_{i}"),
            name: format!("block sensitive path ({i})"),
            priority: 5,
            enabled: true,
            match_: RuleMatch::Path {
                op: crate::rules::PathOp::Regex,
                pattern: format!("(?i){pat}"),
            },
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["sensitive_paths".into()],
            created_at: None,
        })
        .collect()
}

/// Bad crawler rules — block known scanner User-Agents.
fn bad_crawler_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    vec![Rule {
        id: "bad_crawler".into(),
        name: "block bad crawler/scanner UA".into(),
        priority: 10,
        enabled: true,
        match_: RuleMatch::UserAgent(crate::rules::StrOp::Regex {
            pattern: r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|nessus|acunetix|dirbuster|gobuster|wpscan|hydra|metasploit)".into(),
        }),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["crawlers_bad".into()],
        created_at: None,
    }]
}

/// Empty User-Agent rule.
fn empty_ua_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Challenge
    } else {
        RuleAction::Log
    };
    vec![Rule {
        id: "empty_ua".into(),
        name: "challenge empty User-Agent".into(),
        priority: 15,
        enabled: true,
        match_: RuleMatch::UserAgent(crate::rules::StrOp::Equals {
            value: String::new(),
        }),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["empty_ua".into()],
        created_at: None,
    }]
}

/// HTTP anomaly rules — block rare methods (TRACE, CONNECT).
fn http_anomaly_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    vec![
        Rule {
            id: "http_anomaly_trace".into(),
            name: "block TRACE method".into(),
            priority: 12,
            enabled: true,
            match_: RuleMatch::Method(crate::event::HttpMethod::Trace),
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["http_anomaly".into()],
            created_at: None,
        },
        Rule {
            id: "http_anomaly_connect".into(),
            name: "block CONNECT method".into(),
            priority: 12,
            enabled: true,
            match_: RuleMatch::Method(crate::event::HttpMethod::Connect),
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["http_anomaly".into()],
            created_at: None,
        },
    ]
}
