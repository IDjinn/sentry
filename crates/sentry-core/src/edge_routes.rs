//! nginx-like routing model for the inline edge: named upstream groups,
//! sites (`server_name`) and locations (`location` with `=`, `^~`, `~`,
//! `~*` modifiers) extended with request conditions (`match {}`), actions
//! (`proxy_pass`, `return`, `redirect`, `rewrite`), header operations and
//! per-location security overrides (`security {}`), inherited
//! `http` → site → location.
//!
//! Pure config types + validation; request-time matching lives in
//! `sentry-edge`.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{BalanceMode, EdgeConfig};

/// A named upstream group (nginx `upstream NAME {}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct UpstreamGroupConfig {
    /// Group name referenced by `proxy_pass`.
    pub name: String,
    /// Server base URLs (`http://web:3000`).
    pub servers: Vec<String>,
    /// Balancer (default: `[edge] balance`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<BalanceMode>,
    /// Passive health failures before ejection (default: `[edge] max_fails`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fails: Option<u32>,
    /// Failure window / ejection duration (default: `[edge] fail_timeout_secs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_timeout_secs: Option<u64>,
    /// Startup health-check path (default: `[edge] health_path`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,
}

/// A site (nginx `server {}` selected by `server_name`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SiteConfig {
    /// Host patterns: exact, `*.suffix`, or `~regex`. Empty = default site.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Also serve requests whose Host matches no site.
    #[serde(default)]
    pub default: bool,
    /// Certificate served for `hosts` via SNI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    /// Private key for `tls_cert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
    /// Locations in declaration order.
    #[serde(default)]
    pub locations: Vec<LocationConfig>,
    /// Header operations inherited by every location.
    #[serde(default)]
    pub headers: HeaderOps,
    /// Security overrides inherited by every location.
    #[serde(default)]
    pub security: SecurityConfig,
}

/// `location` modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocationKind {
    /// Plain prefix (`location /api/`).
    #[default]
    Prefix,
    /// Prefix that skips regex locations when it is the longest (`^~`).
    PriorityPrefix,
    /// Exact path (`=`).
    Exact,
    /// Case-sensitive regex (`~`).
    Regex,
    /// Case-insensitive regex (`~*`).
    RegexCaseless,
}

impl LocationKind {
    /// Parse an nginx modifier (`=`, `^~`, `~`, `~*`).
    pub fn from_modifier(m: &str) -> Option<Self> {
        match m {
            "=" => Some(Self::Exact),
            "^~" => Some(Self::PriorityPrefix),
            "~" => Some(Self::Regex),
            "~*" => Some(Self::RegexCaseless),
            _ => None,
        }
    }

    /// The nginx modifier (`""` for a plain prefix).
    pub fn modifier(self) -> &'static str {
        match self {
            Self::Prefix => "",
            Self::PriorityPrefix => "^~",
            Self::Exact => "=",
            Self::Regex => "~",
            Self::RegexCaseless => "~*",
        }
    }

    /// Regex location?
    pub fn is_regex(self) -> bool {
        matches!(self, Self::Regex | Self::RegexCaseless)
    }
}

/// One `location`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LocationConfig {
    /// Modifier.
    #[serde(default)]
    pub kind: LocationKind,
    /// Path prefix, exact path or regex.
    pub path: String,
    /// Extra request conditions (all must hold) — a failing location is
    /// skipped and the next candidate tried.
    #[serde(default)]
    pub conditions: Vec<MatchCondition>,
    /// Upstream group name or URL (`http://host:port[/path]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_pass: Option<String>,
    /// Answer directly (`return`/`redirect`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub respond: Option<ReturnConfig>,
    /// Path rewrites applied in order before proxying.
    #[serde(default)]
    pub rewrites: Vec<RewriteRule>,
    /// Header operations (merged over the site's).
    #[serde(default)]
    pub headers: HeaderOps,
    /// Per-request upstream timeout override (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// Response buffering override (`false` streams).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_buffering: Option<bool>,
    /// Security overrides (merged over site and http).
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Direct response: status + optional body text or redirect target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReturnConfig {
    /// HTTP status.
    pub status: u16,
    /// Body (2xx/4xx/5xx) or `Location` (3xx). `$var`s expanded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// `rewrite: regex replacement` (captures as `$1`…).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RewriteRule {
    /// Regex applied to the path.
    pub pattern: String,
    /// Replacement (`$1`, `$host`, …). A `?query` part replaces the args.
    pub replacement: String,
}

/// Header operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HeaderOps {
    /// Set (replace) request headers sent upstream.
    #[serde(default)]
    pub request_set: Vec<(String, String)>,
    /// Remove request headers before proxying.
    #[serde(default)]
    pub request_remove: Vec<String>,
    /// Set (replace) response headers sent to the client.
    #[serde(default)]
    pub response_set: Vec<(String, String)>,
    /// Remove response headers before answering.
    #[serde(default)]
    pub response_remove: Vec<String>,
}

impl HeaderOps {
    /// Parent ops followed by the child's (child wins on the same header).
    pub fn merged(&self, child: &HeaderOps) -> HeaderOps {
        let mut out = self.clone();
        out.request_set.extend(child.request_set.iter().cloned());
        out.request_remove
            .extend(child.request_remove.iter().cloned());
        out.response_set.extend(child.response_set.iter().cloned());
        out.response_remove
            .extend(child.response_remove.iter().cloned());
        out
    }

    /// No operation configured.
    pub fn is_empty(&self) -> bool {
        self.request_set.is_empty()
            && self.request_remove.is_empty()
            && self.response_set.is_empty()
            && self.response_remove.is_empty()
    }
}

/// What a condition inspects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
pub enum MatchSubject {
    /// HTTP method.
    Method,
    /// Query parameter (decoded).
    Query(String),
    /// Request header (case-insensitive name).
    Header(String),
    /// Cookie.
    Cookie(String),
    /// Host (without port).
    Host,
    /// `http` / `https`.
    Scheme,
    /// Client IP (resolved real IP).
    Ip,
    /// Raw query string.
    Args,
    /// Request path.
    Path,
}

impl MatchSubject {
    /// Parse a condition key (`method`, `query.page`, `header.x-api-key`, …).
    pub fn parse(key: &str) -> Option<Self> {
        let (head, name) = match key.split_once('.') {
            Some((h, n)) => (h, Some(n)),
            None => (key, None),
        };
        let named =
            |f: fn(String) -> Self| name.filter(|n| !n.is_empty()).map(|n| f(n.to_string()));
        match head {
            "method" if name.is_none() => Some(Self::Method),
            "query" | "arg" => named(Self::Query),
            "header" | "http" => named(|n| Self::Header(n.to_ascii_lowercase())),
            "cookie" => named(Self::Cookie),
            "host" if name.is_none() => Some(Self::Host),
            "scheme" if name.is_none() => Some(Self::Scheme),
            "ip" | "client_ip" | "remote_addr" if name.is_none() => Some(Self::Ip),
            "args" | "query_string" if name.is_none() => Some(Self::Args),
            "path" | "uri" if name.is_none() => Some(Self::Path),
            _ => None,
        }
    }

    /// The condition key (inverse of [`parse`](Self::parse)).
    pub fn key(&self) -> String {
        match self {
            Self::Method => "method".into(),
            Self::Query(n) => format!("query.{n}"),
            Self::Header(n) => format!("header.{n}"),
            Self::Cookie(n) => format!("cookie.{n}"),
            Self::Host => "host".into(),
            Self::Scheme => "scheme".into(),
            Self::Ip => "ip".into(),
            Self::Args => "args".into(),
            Self::Path => "path".into(),
        }
    }
}

/// How a condition compares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op", content = "values")]
pub enum MatchOp {
    /// Equal to any of the values (case-insensitive for method/host/scheme;
    /// CIDR containment for `ip`).
    In(Vec<String>),
    /// Equal to none of the values.
    NotIn(Vec<String>),
    /// Regex match (`~`).
    Regex(String),
    /// Case-insensitive regex (`~*`).
    RegexCaseless(String),
    /// Regex does not match (`!~`).
    NotRegex(String),
    /// Present (any value).
    Present,
    /// Absent.
    Absent,
}

/// One `match {}` condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchCondition {
    /// Inspected attribute.
    pub subject: MatchSubject,
    /// Comparison.
    pub op: MatchOp,
}

/// `security { mode }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    /// Analyze and act (default).
    #[default]
    Enforce,
    /// Analyze and record, never act (the verdict is downgraded to Allow).
    Shadow,
    /// Skip the pipeline (static assets, health checks). Hard blocks and
    /// `allow`/`deny` still apply.
    Off,
}

impl SecurityMode {
    /// Lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Shadow => "shadow",
            Self::Off => "off",
        }
    }
}

/// Per-location rate limit (`rate_limit: 100/1m`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationRateLimit {
    /// Requests allowed per window per client IP.
    pub requests: u32,
    /// Window length in seconds.
    pub window_secs: u64,
}

impl LocationRateLimit {
    /// Parse `100/1m`, `10/s`, `5/30s`.
    pub fn parse(text: &str) -> Option<Self> {
        let (n, w) = text.trim().split_once('/')?;
        let requests: u32 = n.trim().parse().ok()?;
        let w = w.trim();
        let w = if w.starts_with(|c: char| c.is_ascii_digit()) {
            w.to_string()
        } else {
            format!("1{w}")
        };
        let window_secs = crate::edge_routes::parse_secs(&w)?;
        (requests > 0 && window_secs > 0).then_some(Self {
            requests,
            window_secs,
        })
    }
}

/// Per-scope security overrides; every field is optional so `http` → site →
/// location inheritance can merge them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// enforce | shadow | off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SecurityMode>,
    /// Verdict per risk level (`info`/`low`/`medium`/`high`/`critical` →
    /// `allow`/`rate_limit`/`challenge`/`block`/`quarantine`), replacing the
    /// global level mapping for requests in scope. DSL `policy.override`
    /// entries still win.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub policy: HashMap<String, String>,
    /// Require the challenge even for clean requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_challenge: Option<bool>,
    /// Per-IP rate limit for the scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<LocationRateLimit>,
    /// Allowlist (IPs/CIDRs): anyone else gets 403.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Denylist (IPs/CIDRs) → 403.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Pack mode overrides (`sensitive_paths: off`).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub packs: HashMap<String, String>,
}

impl SecurityConfig {
    /// `self` (parent) overridden by `child`.
    pub fn merged(&self, child: &SecurityConfig) -> SecurityConfig {
        let mut policy = self.policy.clone();
        policy.extend(child.policy.clone());
        let mut packs = self.packs.clone();
        packs.extend(child.packs.clone());
        SecurityConfig {
            mode: child.mode.or(self.mode),
            policy,
            force_challenge: child.force_challenge.or(self.force_challenge),
            rate_limit: child.rate_limit.or(self.rate_limit),
            allow: if child.allow.is_empty() {
                self.allow.clone()
            } else {
                child.allow.clone()
            },
            deny: if child.deny.is_empty() {
                self.deny.clone()
            } else {
                child.deny.clone()
            },
            packs,
        }
    }

    /// Nothing configured.
    pub fn is_empty(&self) -> bool {
        *self == SecurityConfig::default()
    }
}

/// Seconds from a duration text (`30s`, `5m`, `1h`, `90` = seconds).
pub fn parse_secs(text: &str) -> Option<u64> {
    let t = text.trim().to_ascii_lowercase();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: u64 = num.parse().ok()?;
    let f = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    Some(n * f)
}

/// Normalized routing table: explicit groups/sites, or — for configs that
/// only set the legacy `upstream`/`upstreams`/`vhosts` fields (old TOML) —
/// the equivalent synthesized groups and sites.
pub fn normalized(edge: &EdgeConfig) -> (Vec<UpstreamGroupConfig>, Vec<SiteConfig>) {
    if !edge.sites.is_empty() || !edge.upstream_groups.is_empty() {
        return (edge.upstream_groups.clone(), edge.sites.clone());
    }
    let mut groups = Vec::new();
    let mut sites = Vec::new();
    let default_servers = edge.default_group_servers();
    for vhost in &edge.vhosts {
        groups.push(UpstreamGroupConfig {
            name: vhost.host.clone(),
            servers: vhost.upstreams.clone(),
            balance: vhost.balance,
            max_fails: vhost.max_fails,
            fail_timeout_secs: vhost.fail_timeout_secs,
            health_path: vhost.health_path.clone(),
        });
        sites.push(SiteConfig {
            hosts: vec![vhost.host.clone()],
            tls_cert: vhost.tls_cert.clone(),
            tls_key: vhost.tls_key.clone(),
            locations: vec![LocationConfig {
                path: "/".into(),
                proxy_pass: Some(vhost.host.clone()),
                ..Default::default()
            }],
            ..Default::default()
        });
    }
    if !default_servers.is_empty() {
        groups.insert(
            0,
            UpstreamGroupConfig {
                name: "default".into(),
                servers: default_servers,
                ..Default::default()
            },
        );
        sites.push(SiteConfig {
            locations: vec![LocationConfig {
                path: "/".into(),
                proxy_pass: Some("default".into()),
                ..Default::default()
            }],
            ..Default::default()
        });
    }
    (groups, sites)
}

fn valid_ip_spec(spec: &str) -> bool {
    let s = spec.trim();
    s.parse::<std::net::IpAddr>().is_ok() || s.parse::<ipnet::IpNet>().is_ok()
}

fn check_security(where_: &str, sec: &SecurityConfig, errors: &mut Vec<String>) {
    for (level, verdict) in &sec.policy {
        if !matches!(
            level.as_str(),
            "info" | "low" | "medium" | "high" | "critical"
        ) {
            errors.push(format!(
                "{where_}: security policy level `{level}` (expected info|low|medium|high|critical)"
            ));
        }
        if crate::policy::parse_verdict(verdict).is_err() {
            errors.push(format!(
                "{where_}: security policy verdict `{verdict}` (expected allow|rate_limit|challenge|block|quarantine)"
            ));
        }
    }
    for ip in sec.allow.iter().chain(&sec.deny) {
        if !valid_ip_spec(ip) {
            errors.push(format!("{where_}: `{ip}` is not an IP or CIDR"));
        }
    }
    for (pack, mode) in &sec.packs {
        if !crate::packs::PackMode::all_pack_names().contains(&pack.as_str()) {
            errors.push(format!("{where_}: unknown pack `{pack}`"));
        }
        if !matches!(mode.as_str(), "off" | "shadow" | "enforce") {
            errors.push(format!(
                "{where_}: pack `{pack}` mode `{mode}` (expected off|shadow|enforce)"
            ));
        }
    }
}

fn check_regex(where_: &str, pattern: &str, caseless: bool, errors: &mut Vec<String>) {
    let src = if caseless {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    if let Err(e) = regex::Regex::new(&src) {
        errors.push(format!("{where_}: invalid regex `{pattern}`: {e}"));
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Validate groups, sites and locations. Pure; returns human-readable errors.
pub fn validate(edge: &EdgeConfig) -> Vec<String> {
    let mut errors = Vec::new();
    let (groups, sites) = normalized(edge);
    let mut names: Vec<&str> = Vec::new();
    for g in &groups {
        let where_ = format!("upstream `{}`", g.name);
        if g.name.trim().is_empty() {
            errors.push("upstream: a group needs a name".into());
        }
        if names.contains(&g.name.as_str()) {
            errors.push(format!("{where_}: defined twice"));
        }
        names.push(&g.name);
        if g.servers.is_empty() {
            errors.push(format!("{where_}: needs at least one `server`"));
        }
        for s in &g.servers {
            if !is_url(s) {
                errors.push(format!(
                    "{where_}: server `{s}` must start with http:// or https://"
                ));
            }
        }
    }
    let mut defaults = 0usize;
    let mut seen_hosts: Vec<String> = Vec::new();
    for (si, site) in sites.iter().enumerate() {
        let label = if site.hosts.is_empty() {
            format!("site #{} (default)", si + 1)
        } else {
            format!("site {}", site.hosts.join(","))
        };
        if site.hosts.is_empty() || site.default {
            defaults += 1;
        }
        for h in &site.hosts {
            if let Some(re) = h.strip_prefix('~') {
                check_regex(&label, re, true, &mut errors);
            } else {
                if h != &h.to_ascii_lowercase() {
                    errors.push(format!("{label}: host `{h}` must be lowercase"));
                }
                if h.contains('*') && !(h.starts_with("*.") && h.len() > 2 && !h[1..].contains('*'))
                {
                    errors.push(format!(
                        "{label}: host `{h}`: `*` is only valid as a leading `*.` wildcard"
                    ));
                }
            }
            if seen_hosts.contains(h) {
                errors.push(format!("{label}: host `{h}` is used by another site"));
            } else {
                seen_hosts.push(h.clone());
            }
        }
        if site.tls_cert.is_some() != site.tls_key.is_some() {
            errors.push(format!(
                "{label}: tls cert and key must be configured together"
            ));
        }
        if site.tls_cert.is_some() && (edge.tls_cert.is_none() || edge.tls_key.is_none()) {
            errors.push(format!(
                "{label}: a site certificate needs the global `http {{ tls {{ cert, key }} }}` front \
                 (it is served via SNI on the same listener)"
            ));
        }
        check_security(&label, &site.security, &mut errors);
        for loc in &site.locations {
            let where_ = format!(
                "{label} › location {}{}",
                match loc.kind.modifier() {
                    "" => String::new(),
                    m => format!("{m} "),
                },
                loc.path
            );
            match loc.kind {
                LocationKind::Regex => check_regex(&where_, &loc.path, false, &mut errors),
                LocationKind::RegexCaseless => check_regex(&where_, &loc.path, true, &mut errors),
                _ => {
                    if !loc.path.starts_with('/') {
                        errors.push(format!("{where_}: path must start with `/`"));
                    }
                }
            }
            match (&loc.proxy_pass, &loc.respond) {
                (None, None) => errors.push(format!(
                    "{where_}: needs `proxy_pass`, `return` or `redirect`"
                )),
                (Some(_), Some(_)) => errors.push(format!(
                    "{where_}: `proxy_pass` and `return`/`redirect` are exclusive"
                )),
                (Some(target), None) => {
                    if !is_url(target) && !groups.iter().any(|g| &g.name == target) {
                        errors.push(format!(
                            "{where_}: proxy_pass `{target}` is neither an upstream name nor an http(s):// URL"
                        ));
                    }
                }
                (None, Some(r)) => {
                    if !(100..=599).contains(&r.status) {
                        errors.push(format!("{where_}: invalid status {}", r.status));
                    }
                    if (300..400).contains(&r.status) && r.text.is_none() {
                        errors.push(format!("{where_}: a redirect needs a target URL"));
                    }
                }
            }
            for rw in &loc.rewrites {
                check_regex(&where_, &rw.pattern, false, &mut errors);
            }
            for c in &loc.conditions {
                match &c.op {
                    MatchOp::Regex(p) | MatchOp::NotRegex(p) => {
                        check_regex(&where_, p, false, &mut errors)
                    }
                    MatchOp::RegexCaseless(p) => check_regex(&where_, p, true, &mut errors),
                    MatchOp::In(vals) | MatchOp::NotIn(vals) if c.subject == MatchSubject::Ip => {
                        for v in vals {
                            if !valid_ip_spec(v) {
                                errors
                                    .push(format!("{where_}: match ip `{v}` is not an IP or CIDR"));
                            }
                        }
                    }
                    _ => {}
                }
            }
            check_security(&where_, &loc.security, &mut errors);
        }
    }
    check_security("http", &edge.security, &mut errors);
    if defaults > 1 {
        errors.push(format!(
            "{defaults} default sites (a site without `host`, or with `default: on`) — only one is allowed"
        ));
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_shorthand() {
        assert_eq!(
            LocationRateLimit::parse("100/1m"),
            Some(LocationRateLimit {
                requests: 100,
                window_secs: 60
            })
        );
        assert_eq!(LocationRateLimit::parse("10/s").unwrap().window_secs, 1);
        assert_eq!(LocationRateLimit::parse("5/30s").unwrap().window_secs, 30);
        assert!(LocationRateLimit::parse("x/1m").is_none());
        assert!(LocationRateLimit::parse("0/1m").is_none());
    }

    #[test]
    fn subjects_parse_and_round_trip() {
        for key in [
            "method",
            "query.page",
            "header.x-api-key",
            "cookie.sid",
            "host",
            "ip",
            "args",
            "path",
        ] {
            let s = MatchSubject::parse(key).unwrap();
            assert_eq!(s.key(), key);
        }
        assert!(MatchSubject::parse("query").is_none());
        assert!(MatchSubject::parse("bogus").is_none());
        assert_eq!(
            MatchSubject::parse("header.X-Beta"),
            Some(MatchSubject::Header("x-beta".into()))
        );
    }

    #[test]
    fn security_merge_child_wins() {
        let parent = SecurityConfig {
            mode: Some(SecurityMode::Enforce),
            allow: vec!["10.0.0.0/8".into()],
            policy: HashMap::from([("high".into(), "challenge".into())]),
            ..Default::default()
        };
        let child = SecurityConfig {
            mode: Some(SecurityMode::Shadow),
            policy: HashMap::from([("medium".into(), "allow".into())]),
            ..Default::default()
        };
        let m = parent.merged(&child);
        assert_eq!(m.mode, Some(SecurityMode::Shadow));
        assert_eq!(m.allow, ["10.0.0.0/8"]);
        assert_eq!(m.policy.len(), 2);
    }

    #[test]
    fn legacy_fields_normalize_to_groups_and_sites() {
        let edge = EdgeConfig {
            upstream: "http://127.0.0.1:8080".into(),
            vhosts: vec![crate::config::EdgeVhostConfig {
                host: "app.example.com".into(),
                upstreams: vec!["http://a:1".into()],
                balance: None,
                max_fails: None,
                fail_timeout_secs: None,
                health_path: None,
                tls_cert: None,
                tls_key: None,
            }],
            ..Default::default()
        };
        let (groups, sites) = normalized(&edge);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "default");
        assert_eq!(sites.len(), 2);
        assert!(sites[1].hosts.is_empty());
        assert!(validate(&edge).is_empty(), "{:?}", validate(&edge));
    }

    #[test]
    fn validation_catches_routing_mistakes() {
        let edge = EdgeConfig {
            upstream_groups: vec![UpstreamGroupConfig {
                name: "app".into(),
                servers: vec!["127.0.0.1:1".into()],
                ..Default::default()
            }],
            sites: vec![
                SiteConfig {
                    locations: vec![
                        LocationConfig {
                            path: "/".into(),
                            proxy_pass: Some("nope".into()),
                            ..Default::default()
                        },
                        LocationConfig {
                            kind: LocationKind::Regex,
                            path: "([".into(),
                            respond: Some(ReturnConfig {
                                status: 301,
                                text: None,
                            }),
                            ..Default::default()
                        },
                    ],
                    security: SecurityConfig {
                        allow: vec!["not-an-ip".into()],
                        packs: HashMap::from([("nopack".into(), "off".into())]),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                SiteConfig::default(),
            ],
            ..Default::default()
        };
        let errors = validate(&edge).join("\n");
        for needle in [
            "must start with http://",
            "proxy_pass `nope`",
            "invalid regex",
            "redirect needs a target",
            "not an IP or CIDR",
            "unknown pack `nopack`",
            "2 default sites",
        ] {
            assert!(errors.contains(needle), "missing `{needle}` in:\n{errors}");
        }
    }
}
