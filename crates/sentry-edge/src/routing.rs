//! Request routing for the inline edge (nginx-like): Host → site
//! (`server_name`: exact > longest `*.suffix` > regex > default), then path
//! → location (nginx priority: `=` exact, longest prefix — `^~` skips the
//! regexes — `~`/`~*` regexes in order, longest plain prefix), with
//! `match {}` conditions: a location whose conditions fail is skipped and
//! the next candidate tried.
//!
//! The selected [`Route`] carries the action (upstream group or direct
//! response), path rewriting, header operations, timeouts and the merged
//! security scope (`http` → site → location).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use regex::Regex;
use sentry_core::config::BalanceMode;
use sentry_core::edge_routes::{
    HeaderOps, LocationConfig, LocationKind, LocationRateLimit, MatchOp, MatchSubject,
    ReturnConfig, SecurityConfig, SecurityMode, SiteConfig, UpstreamGroupConfig,
};
use sentry_core::RequestScope;

use crate::upstream::UpstreamGroup;

/// Group defaults applied when an `upstream {}` omits a setting.
#[derive(Debug, Clone)]
pub struct GroupDefaults {
    /// Balancer.
    pub balance: BalanceMode,
    /// Passive-health failures before ejection.
    pub max_fails: u32,
    /// Failure window / ejection seconds.
    pub fail_timeout_secs: u64,
    /// Startup health-check path.
    pub health_path: String,
}

impl Default for GroupDefaults {
    fn default() -> Self {
        Self {
            balance: BalanceMode::RoundRobin,
            max_fails: 2,
            fail_timeout_secs: 30,
            health_path: "/".into(),
        }
    }
}

/// The per-request view the router needs.
pub struct RequestView<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// Path (no query).
    pub path: &'a str,
    /// Raw query string.
    pub query: Option<&'a str>,
    /// Request headers.
    pub headers: &'a HeaderMap,
    /// Host header (may carry `:port`).
    pub host: Option<&'a str>,
    /// `http` / `https`.
    pub scheme: &'a str,
    /// Resolved client IP.
    pub client_ip: IpAddr,
}

/// Effective security for a route.
#[derive(Debug, Clone, Default)]
pub struct EffectiveSecurity {
    /// enforce | shadow | off.
    pub mode: SecurityMode,
    /// Pipeline overrides (packs, level policy).
    pub scope: RequestScope,
    /// Require the challenge for clean requests too.
    pub force_challenge: bool,
    /// Per-IP rate limit.
    pub rate_limit: Option<LocationRateLimit>,
    /// Allowlist (empty = everyone).
    pub allow: Vec<ipnet::IpNet>,
    /// Denylist.
    pub deny: Vec<ipnet::IpNet>,
}

impl EffectiveSecurity {
    fn from_config(cfg: &SecurityConfig) -> Self {
        let nets = |v: &[String]| -> Vec<ipnet::IpNet> {
            v.iter()
                .filter_map(|s| {
                    let s = s.trim();
                    s.parse::<ipnet::IpNet>()
                        .ok()
                        .or_else(|| s.parse::<IpAddr>().ok().map(ipnet::IpNet::from))
                })
                .collect()
        };
        Self {
            mode: cfg.mode.unwrap_or_default(),
            scope: RequestScope::from_maps(&cfg.packs, &cfg.policy),
            force_challenge: cfg.force_challenge.unwrap_or(false),
            rate_limit: cfg.rate_limit,
            allow: nets(&cfg.allow),
            deny: nets(&cfg.deny),
        }
    }

    /// Whether `ip` passes the allow/deny lists.
    pub fn ip_permitted(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if self.deny.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|n| n.contains(&ip))
    }
}

/// What a location does.
pub enum Target {
    /// Proxy to a group; `base_path` is the URI part of a `proxy_pass` URL
    /// (replaces the matched prefix, nginx semantics).
    Upstream {
        /// Group to balance across.
        group: Arc<UpstreamGroup>,
        /// URI path of `proxy_pass http://host/path`.
        base_path: Option<String>,
    },
    /// Answer directly.
    Respond(ReturnConfig),
}

enum Cond {
    In(Vec<String>),
    NotIn(Vec<String>),
    Cidr(Vec<ipnet::IpNet>, bool),
    Regex(Regex, bool),
    Present(bool),
}

struct CompiledCondition {
    subject: MatchSubject,
    cond: Cond,
}

/// One compiled location.
pub struct Location {
    /// Stable index (rate-limit key).
    pub id: usize,
    /// Label for logs (`example.com ~ ^/api`).
    pub label: String,
    kind: LocationKind,
    path: String,
    regex: Option<Regex>,
    conditions: Vec<CompiledCondition>,
    /// Action.
    pub target: Target,
    rewrites: Vec<(Regex, String)>,
    /// Header operations (site + location).
    pub headers: HeaderOps,
    /// Upstream timeout override.
    pub timeout: Option<Duration>,
    /// Response buffering override.
    pub response_buffering: Option<bool>,
    /// Merged security.
    pub security: EffectiveSecurity,
}

struct Site {
    locations: Vec<Location>,
    exact: Vec<usize>,
    prefixes: Vec<usize>,
    regexes: Vec<usize>,
}

/// A matched route: the location plus regex captures.
pub struct Route<'a> {
    /// The location.
    pub location: &'a Location,
    /// Captures of a regex location (`$1`…).
    pub captures: Vec<String>,
}

/// Compiled routing table.
pub struct RouteTable {
    groups: Vec<(Arc<UpstreamGroup>, String)>,
    sites: Vec<Site>,
    exact_hosts: HashMap<String, usize>,
    wildcard_hosts: Vec<(String, usize)>,
    regex_hosts: Vec<(Regex, usize)>,
    default_site: Option<usize>,
    /// Security applied to requests matching no site/location.
    pub fallback_security: EffectiveSecurity,
    limiter: LocationLimiter,
}

pub use crate::upstream::host_key;

fn split_url(url: &str) -> (String, Option<String>) {
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    match url[scheme_end..].find('/') {
        Some(i) => {
            let (base, path) = url.split_at(scheme_end + i);
            (base.to_string(), Some(path.to_string()))
        }
        None => (url.to_string(), None),
    }
}

fn compile_regex(pattern: &str, caseless: bool) -> Result<Regex, String> {
    let src = if caseless {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    Regex::new(&src).map_err(|e| format!("invalid regex `{pattern}`: {e}"))
}

fn compile_condition(subject: &MatchSubject, op: &MatchOp) -> Result<Cond, String> {
    let ci = matches!(
        subject,
        MatchSubject::Method | MatchSubject::Host | MatchSubject::Scheme
    );
    let norm = |v: &[String]| -> Vec<String> {
        v.iter()
            .map(|s| {
                if ci {
                    s.to_ascii_lowercase()
                } else {
                    s.clone()
                }
            })
            .collect()
    };
    Ok(match op {
        MatchOp::In(v) | MatchOp::NotIn(v) if *subject == MatchSubject::Ip => {
            let nets = v
                .iter()
                .map(|s| {
                    s.parse::<ipnet::IpNet>()
                        .ok()
                        .or_else(|| s.parse::<IpAddr>().ok().map(ipnet::IpNet::from))
                        .ok_or_else(|| format!("`{s}` is not an IP or CIDR"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Cond::Cidr(nets, matches!(op, MatchOp::In(_)))
        }
        MatchOp::In(v) => Cond::In(norm(v)),
        MatchOp::NotIn(v) => Cond::NotIn(norm(v)),
        MatchOp::Regex(p) => Cond::Regex(compile_regex(p, false)?, true),
        MatchOp::RegexCaseless(p) => Cond::Regex(compile_regex(p, true)?, true),
        MatchOp::NotRegex(p) => Cond::Regex(compile_regex(p, false)?, false),
        MatchOp::Present => Cond::Present(true),
        MatchOp::Absent => Cond::Present(false),
    })
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (percent_decode(k) == name).then(|| percent_decode(v))
    })
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

/// `%XX` and `+` decoding (lossy).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                    16,
                ) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

impl CompiledCondition {
    fn value(&self, req: &RequestView<'_>) -> Option<String> {
        match &self.subject {
            MatchSubject::Method => Some(req.method.to_ascii_lowercase()),
            MatchSubject::Query(name) => query_param(req.query, name),
            MatchSubject::Header(name) => req
                .headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            MatchSubject::Cookie(name) => cookie(req.headers, name),
            MatchSubject::Host => host_key(req.host),
            MatchSubject::Scheme => Some(req.scheme.to_ascii_lowercase()),
            MatchSubject::Ip => Some(req.client_ip.to_canonical().to_string()),
            MatchSubject::Args => req.query.map(str::to_string),
            MatchSubject::Path => Some(req.path.to_string()),
        }
    }

    fn holds(&self, req: &RequestView<'_>) -> bool {
        if let Cond::Cidr(nets, positive) = &self.cond {
            let ip = req.client_ip.to_canonical();
            return nets.iter().any(|n| n.contains(&ip)) == *positive;
        }
        let value = self.value(req);
        match (&self.cond, value) {
            (Cond::Present(want), v) => v.is_some() == *want,
            (Cond::In(vals), Some(v)) => vals.contains(&v),
            (Cond::In(_), None) => false,
            (Cond::NotIn(vals), Some(v)) => !vals.contains(&v),
            (Cond::NotIn(_), None) => true,
            (Cond::Regex(re, positive), Some(v)) => re.is_match(&v) == *positive,
            (Cond::Regex(_, positive), None) => !*positive,
            (Cond::Cidr(..), _) => unreachable!("handled above"),
        }
    }
}

impl Location {
    fn path_matches(&self, path: &str) -> Option<Vec<String>> {
        match self.kind {
            LocationKind::Exact => (path == self.path).then(Vec::new),
            LocationKind::Prefix | LocationKind::PriorityPrefix => {
                path.starts_with(self.path.as_str()).then(Vec::new)
            }
            LocationKind::Regex | LocationKind::RegexCaseless => {
                let caps = self.regex.as_ref()?.captures(path)?;
                Some(
                    caps.iter()
                        .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                        .collect(),
                )
            }
        }
    }

    fn conditions_hold(&self, req: &RequestView<'_>) -> bool {
        self.conditions.iter().all(|c| c.holds(req))
    }

    /// Path + query sent upstream after rewrites and the `proxy_pass` URI.
    pub fn upstream_uri(&self, req: &RequestView<'_>, captures: &[String]) -> String {
        let mut path = req.path.to_string();
        let mut query = req.query.map(str::to_string);
        let mut rewritten = false;
        for (re, replacement) in &self.rewrites {
            let Some(caps) = re.captures(&path) else {
                continue;
            };
            let caps: Vec<String> = caps
                .iter()
                .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                .collect();
            let expanded = expand_vars(replacement, req, &caps);
            match expanded.split_once('?') {
                Some((p, q)) => {
                    path = p.to_string();
                    query = match (q.is_empty(), query.take()) {
                        (true, _) => None,
                        (false, Some(orig)) if !replacement.ends_with('?') => {
                            Some(format!("{q}&{orig}"))
                        }
                        (false, _) => Some(q.to_string()),
                    };
                }
                None => path = expanded,
            }
            rewritten = true;
        }
        if !rewritten {
            if let Target::Upstream {
                base_path: Some(base),
                ..
            } = &self.target
            {
                path = match self.kind {
                    LocationKind::Exact => base.clone(),
                    LocationKind::Prefix | LocationKind::PriorityPrefix => {
                        format!("{base}{}", &path[self.path.len().min(path.len())..])
                    }
                    LocationKind::Regex | LocationKind::RegexCaseless => {
                        let _ = captures;
                        format!("{}{path}", base.trim_end_matches('/'))
                    }
                };
            }
        }
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        match query.filter(|q| !q.is_empty()) {
            Some(q) => format!("{path}?{q}"),
            None => path,
        }
    }
}

/// Expand `$host`, `$uri`, `$request_uri`, `$args`, `$scheme`,
/// `$remote_addr`, `$request_method`, `$arg_NAME`, `$http_NAME` and `$1`…`$9`.
pub fn expand_vars(template: &str, req: &RequestView<'_>, captures: &[String]) -> String {
    let mut out = String::with_capacity(template.len());
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let braced = chars.get(i + 1) == Some(&'{');
        let start = if braced { i + 2 } else { i + 1 };
        let mut end = start;
        while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
            end += 1;
            if !braced && chars[start].is_ascii_digit() {
                break;
            }
        }
        let name: String = chars[start..end].iter().collect();
        if name.is_empty() || (braced && chars.get(end) != Some(&'}')) {
            out.push('$');
            i += 1;
            continue;
        }
        let value = match name.as_str() {
            "host" => host_key(req.host).unwrap_or_default(),
            "uri" => req.path.to_string(),
            "request_uri" => match req.query {
                Some(q) if !q.is_empty() => format!("{}?{q}", req.path),
                _ => req.path.to_string(),
            },
            "args" | "query_string" => req.query.unwrap_or_default().to_string(),
            "is_args" => if req.query.is_some_and(|q| !q.is_empty()) {
                "?"
            } else {
                ""
            }
            .to_string(),
            "scheme" => req.scheme.to_string(),
            "remote_addr" => req.client_ip.to_canonical().to_string(),
            "request_method" => req.method.to_string(),
            n if n.bytes().all(|b| b.is_ascii_digit()) => n
                .parse::<usize>()
                .ok()
                .and_then(|idx| captures.get(idx).cloned())
                .unwrap_or_default(),
            n if n.starts_with("arg_") => query_param(req.query, &n[4..]).unwrap_or_default(),
            n if n.starts_with("http_") => req
                .headers
                .get(n[5..].replace('_', "-").as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            _ => {
                out.push('$');
                i += 1;
                continue;
            }
        };
        out.push_str(&value);
        i = if braced { end + 1 } else { end };
    }
    out
}

impl Site {
    fn route<'a>(&'a self, req: &RequestView<'_>) -> Option<Route<'a>> {
        let try_one = |idx: usize| -> Option<Route<'a>> {
            let loc = &self.locations[idx];
            let captures = loc.path_matches(req.path)?;
            loc.conditions_hold(req).then_some(Route {
                location: loc,
                captures,
            })
        };
        for &idx in &self.exact {
            if let Some(r) = try_one(idx) {
                return Some(r);
            }
        }
        let matching_prefixes: Vec<usize> = self
            .prefixes
            .iter()
            .copied()
            .filter(|&i| self.locations[i].path_matches(req.path).is_some())
            .collect();
        let longest_is_priority = matching_prefixes
            .first()
            .is_some_and(|&i| self.locations[i].kind == LocationKind::PriorityPrefix);
        let order: Vec<usize> = if longest_is_priority {
            matching_prefixes
                .iter()
                .copied()
                .chain(self.regexes.iter().copied())
                .collect()
        } else {
            self.regexes
                .iter()
                .copied()
                .chain(matching_prefixes.iter().copied())
                .collect()
        };
        order.into_iter().find_map(try_one)
    }
}

impl RouteTable {
    /// Compile groups, sites and the http-level security.
    pub fn build(
        groups: &[UpstreamGroupConfig],
        sites: &[SiteConfig],
        http_security: &SecurityConfig,
        defaults: &GroupDefaults,
    ) -> Result<Self, String> {
        let mut table = RouteTable {
            groups: Vec::new(),
            sites: Vec::new(),
            exact_hosts: HashMap::new(),
            wildcard_hosts: Vec::new(),
            regex_hosts: Vec::new(),
            default_site: None,
            fallback_security: EffectiveSecurity::from_config(http_security),
            limiter: LocationLimiter::default(),
        };
        let mut named: HashMap<String, Arc<UpstreamGroup>> = HashMap::new();
        for g in groups {
            let group = Arc::new(UpstreamGroup::new(
                g.name.clone(),
                &g.servers,
                g.balance.unwrap_or(defaults.balance),
                g.max_fails.unwrap_or(defaults.max_fails),
                g.fail_timeout_secs.unwrap_or(defaults.fail_timeout_secs),
            ));
            let health = g
                .health_path
                .clone()
                .unwrap_or_else(|| defaults.health_path.clone());
            table.groups.push((group.clone(), health));
            named.insert(g.name.clone(), group);
        }
        let mut anonymous: HashMap<String, Arc<UpstreamGroup>> = HashMap::new();
        let mut next_id = 0usize;
        for (si, site_cfg) in sites.iter().enumerate() {
            let site_sec = http_security.merged(&site_cfg.security);
            let site_label = site_cfg
                .hosts
                .first()
                .cloned()
                .unwrap_or_else(|| "default".to_string());
            let mut site = Site {
                locations: Vec::new(),
                exact: Vec::new(),
                prefixes: Vec::new(),
                regexes: Vec::new(),
            };
            for loc in &site_cfg.locations {
                let compiled = compile_location(
                    loc,
                    next_id,
                    &site_label,
                    &site_cfg.headers,
                    &site_sec,
                    &named,
                    &mut anonymous,
                    &mut table.groups,
                    defaults,
                )?;
                next_id += 1;
                let idx = site.locations.len();
                match compiled.kind {
                    LocationKind::Exact => site.exact.push(idx),
                    LocationKind::Prefix | LocationKind::PriorityPrefix => site.prefixes.push(idx),
                    LocationKind::Regex | LocationKind::RegexCaseless => site.regexes.push(idx),
                }
                site.locations.push(compiled);
            }
            let locs = &site.locations;
            site.prefixes
                .sort_by_key(|i| std::cmp::Reverse(locs[*i].path.len()));
            for h in &site_cfg.hosts {
                if let Some(re) = h.strip_prefix('~') {
                    table.regex_hosts.push((compile_regex(re, true)?, si));
                } else if let Some(suffix) = h.strip_prefix('*') {
                    table.wildcard_hosts.push((suffix.to_ascii_lowercase(), si));
                } else {
                    table.exact_hosts.insert(h.to_ascii_lowercase(), si);
                }
            }
            if site_cfg.hosts.is_empty() || site_cfg.default {
                table.default_site = Some(si);
            }
            table.sites.push(site);
        }
        table
            .wildcard_hosts
            .sort_by_key(|w| std::cmp::Reverse(w.0.len()));
        Ok(table)
    }

    /// A table with one catch-all location proxying to `url`.
    pub fn single(url: impl Into<String>) -> Self {
        Self::from_groups(
            UpstreamGroup::new("", &[url.into()], BalanceMode::RoundRobin, 0, 30),
            Vec::new(),
        )
    }

    /// Default group + host-routed groups (the classic vhost table).
    pub fn from_groups(default: UpstreamGroup, vhosts: Vec<(String, UpstreamGroup)>) -> Self {
        let mut table = RouteTable {
            groups: Vec::new(),
            sites: Vec::new(),
            exact_hosts: HashMap::new(),
            wildcard_hosts: Vec::new(),
            regex_hosts: Vec::new(),
            default_site: None,
            fallback_security: EffectiveSecurity::default(),
            limiter: LocationLimiter::default(),
        };
        let push = |host: Option<String>, group: UpstreamGroup, table: &mut RouteTable| {
            let group = Arc::new(group);
            table.groups.push((group.clone(), "/".into()));
            let id = table.sites.len();
            let location = Location {
                id,
                label: host.clone().unwrap_or_else(|| "default".into()),
                kind: LocationKind::Prefix,
                path: "/".into(),
                regex: None,
                conditions: Vec::new(),
                target: Target::Upstream {
                    group,
                    base_path: None,
                },
                rewrites: Vec::new(),
                headers: HeaderOps::default(),
                timeout: None,
                response_buffering: None,
                security: EffectiveSecurity::default(),
            };
            table.sites.push(Site {
                locations: vec![location],
                exact: Vec::new(),
                prefixes: vec![0],
                regexes: Vec::new(),
            });
            match host {
                None => table.default_site = Some(id),
                Some(h) => match h.strip_prefix('*') {
                    Some(suffix) => table.wildcard_hosts.push((suffix.to_string(), id)),
                    None => {
                        table.exact_hosts.insert(h.to_ascii_lowercase(), id);
                    }
                },
            }
        };
        if !default.is_empty() {
            push(None, default, &mut table);
        }
        for (host, group) in vhosts {
            push(Some(host), group, &mut table);
        }
        table
            .wildcard_hosts
            .sort_by_key(|w| std::cmp::Reverse(w.0.len()));
        table
    }

    fn site_for(&self, host: Option<&str>) -> Option<usize> {
        if let Some(key) = host_key(host) {
            if let Some(i) = self.exact_hosts.get(&key) {
                return Some(*i);
            }
            if let Some((_, i)) = self
                .wildcard_hosts
                .iter()
                .find(|(s, _)| key.ends_with(s.as_str()))
            {
                return Some(*i);
            }
            if let Some((_, i)) = self.regex_hosts.iter().find(|(re, _)| re.is_match(&key)) {
                return Some(*i);
            }
        }
        self.default_site
    }

    /// Resolve the route for a request (`None` = no site/location matches).
    pub fn route(&self, req: &RequestView<'_>) -> Option<Route<'_>> {
        let site = self.site_for(req.host)?;
        self.sites[site].route(req)
    }

    /// Every upstream group with its health-check path (startup checks).
    pub fn groups(&self) -> impl Iterator<Item = (&UpstreamGroup, &str)> {
        self.groups.iter().map(|(g, p)| (g.as_ref(), p.as_str()))
    }

    /// Count a request against a location's rate limit; `false` = over.
    pub fn rate_allow(&self, location: usize, ip: IpAddr, rule: LocationRateLimit) -> bool {
        self.limiter
            .allow(location, ip, rule, crate::upstream::now_ms())
    }

    /// Drop expired rate-limit windows (called periodically).
    pub fn prune(&self) {
        self.limiter.prune(crate::upstream::now_ms());
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_location(
    loc: &LocationConfig,
    id: usize,
    site_label: &str,
    site_headers: &HeaderOps,
    site_security: &SecurityConfig,
    named: &HashMap<String, Arc<UpstreamGroup>>,
    anonymous: &mut HashMap<String, Arc<UpstreamGroup>>,
    all_groups: &mut Vec<(Arc<UpstreamGroup>, String)>,
    defaults: &GroupDefaults,
) -> Result<Location, String> {
    let label = format!(
        "{site_label} {}{}",
        match loc.kind.modifier() {
            "" => String::new(),
            m => format!("{m} "),
        },
        loc.path
    );
    let regex = match loc.kind {
        LocationKind::Regex => Some(compile_regex(&loc.path, false)?),
        LocationKind::RegexCaseless => Some(compile_regex(&loc.path, true)?),
        _ => None,
    };
    let target = match (&loc.proxy_pass, &loc.respond) {
        (_, Some(r)) => Target::Respond(r.clone()),
        (Some(t), None) => match named.get(t) {
            Some(group) => Target::Upstream {
                group: group.clone(),
                base_path: None,
            },
            None => {
                let (base, path) = split_url(t);
                let group = anonymous
                    .entry(base.clone())
                    .or_insert_with(|| {
                        let g = Arc::new(UpstreamGroup::new(
                            base.clone(),
                            std::slice::from_ref(&base),
                            defaults.balance,
                            defaults.max_fails,
                            defaults.fail_timeout_secs,
                        ));
                        all_groups.push((g.clone(), defaults.health_path.clone()));
                        g
                    })
                    .clone();
                Target::Upstream {
                    group,
                    base_path: path,
                }
            }
        },
        (None, None) => return Err(format!("{label}: needs proxy_pass, return or redirect")),
    };
    let conditions = loc
        .conditions
        .iter()
        .map(|c| {
            compile_condition(&c.subject, &c.op)
                .map(|cond| CompiledCondition {
                    subject: c.subject.clone(),
                    cond,
                })
                .map_err(|e| format!("{label}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rewrites = loc
        .rewrites
        .iter()
        .map(|r| compile_regex(&r.pattern, false).map(|re| (re, r.replacement.clone())))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{label}: {e}"))?;
    Ok(Location {
        id,
        label,
        kind: loc.kind,
        path: loc.path.clone(),
        regex,
        conditions,
        target,
        rewrites,
        headers: site_headers.merged(&loc.headers),
        timeout: loc.timeout_secs.map(Duration::from_secs),
        response_buffering: loc.response_buffering,
        security: EffectiveSecurity::from_config(&site_security.merged(&loc.security)),
    })
}

/// Fixed-window per-(location, IP) counters.
#[derive(Default)]
struct LocationLimiter {
    windows: Mutex<HashMap<(usize, IpAddr), (u64, u32)>>,
}

const LIMITER_PRUNE_AT: usize = 65_536;

impl LocationLimiter {
    fn allow(&self, location: usize, ip: IpAddr, rule: LocationRateLimit, now_ms: u64) -> bool {
        let window_ms = rule.window_secs.max(1) * 1000;
        let mut map = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= LIMITER_PRUNE_AT {
            map.retain(|_, (start, _)| now_ms.saturating_sub(*start) < window_ms);
        }
        let entry = map.entry((location, ip)).or_insert((now_ms, 0));
        if now_ms.saturating_sub(entry.0) >= window_ms {
            *entry = (now_ms, 0);
        }
        entry.1 += 1;
        entry.1 <= rule.requests
    }

    fn prune(&self, now_ms: u64) {
        let mut map = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (start, _)| now_ms.saturating_sub(*start) < 3_600_000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::edge_routes::{MatchCondition, RewriteRule};

    fn loc(kind: LocationKind, path: &str, target: &str) -> LocationConfig {
        LocationConfig {
            kind,
            path: path.into(),
            proxy_pass: Some(target.into()),
            ..Default::default()
        }
    }

    fn table(sites: Vec<SiteConfig>) -> RouteTable {
        let groups: Vec<UpstreamGroupConfig> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|n| UpstreamGroupConfig {
                name: (*n).into(),
                servers: vec![format!("http://{n}:1")],
                ..Default::default()
            })
            .collect();
        RouteTable::build(
            &groups,
            &sites,
            &SecurityConfig::default(),
            &GroupDefaults::default(),
        )
        .unwrap()
    }

    fn view<'a>(
        headers: &'a HeaderMap,
        host: &'a str,
        path: &'a str,
        query: Option<&'a str>,
    ) -> RequestView<'a> {
        RequestView {
            method: "GET",
            path,
            query,
            headers,
            host: Some(host),
            scheme: "http",
            client_ip: "203.0.113.9".parse().unwrap(),
        }
    }

    fn target_of(t: &RouteTable, host: &str, path: &str, query: Option<&str>) -> String {
        let h = HeaderMap::new();
        match t.route(&view(&h, host, path, query)) {
            Some(r) => match &r.location.target {
                Target::Upstream { group, .. } => group.name.clone(),
                Target::Respond(ret) => format!("return {}", ret.status),
            },
            None => "none".into(),
        }
    }

    #[test]
    fn nginx_location_priority() {
        let t = table(vec![SiteConfig {
            locations: vec![
                loc(LocationKind::Prefix, "/", "a"),
                loc(LocationKind::Prefix, "/images/", "b"),
                loc(LocationKind::RegexCaseless, r"\.(gif|jpg)$", "c"),
                loc(LocationKind::PriorityPrefix, "/static/", "d"),
                loc(LocationKind::Exact, "/", "e"),
            ],
            ..Default::default()
        }]);
        assert_eq!(target_of(&t, "x", "/", None), "e", "exact wins");
        assert_eq!(target_of(&t, "x", "/index.html", None), "a");
        assert_eq!(target_of(&t, "x", "/images/a.png", None), "b");
        assert_eq!(
            target_of(&t, "x", "/images/a.JPG", None),
            "c",
            "regex beats plain prefix"
        );
        assert_eq!(
            target_of(&t, "x", "/static/a.jpg", None),
            "d",
            "^~ skips regexes"
        );
    }

    #[test]
    fn conditions_fall_through_to_the_next_candidate() {
        let mut v2 = loc(LocationKind::Prefix, "/api/", "b");
        v2.conditions = vec![MatchCondition {
            subject: MatchSubject::Query("version".into()),
            op: MatchOp::In(vec!["2".into()]),
        }];
        let t = table(vec![SiteConfig {
            locations: vec![v2, loc(LocationKind::Prefix, "/api/", "a")],
            ..Default::default()
        }]);
        assert_eq!(target_of(&t, "x", "/api/users", Some("version=2")), "b");
        assert_eq!(target_of(&t, "x", "/api/users", Some("version=1")), "a");
        assert_eq!(target_of(&t, "x", "/other", None), "none");
    }

    #[test]
    fn host_selection_exact_wildcard_regex_default() {
        let site = |hosts: &[&str], g: &str| SiteConfig {
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            locations: vec![loc(LocationKind::Prefix, "/", g)],
            ..Default::default()
        };
        let t = table(vec![
            site(&["example.com"], "a"),
            site(&["*.example.com"], "b"),
            site(&["*.api.example.com"], "c"),
            site(&[r"~^tenant-\d+\.test$"], "d"),
            site(&[], "e"),
        ]);
        assert_eq!(target_of(&t, "EXAMPLE.com:8080", "/", None), "a");
        assert_eq!(target_of(&t, "www.example.com", "/", None), "b");
        assert_eq!(
            target_of(&t, "v1.api.example.com", "/", None),
            "c",
            "longest wildcard"
        );
        assert_eq!(target_of(&t, "tenant-42.test", "/", None), "d");
        assert_eq!(target_of(&t, "other.org", "/", None), "e");
    }

    #[test]
    fn condition_kinds() {
        let mut headers = HeaderMap::new();
        headers.insert("x-beta", "1".parse().unwrap());
        headers.insert("cookie", "a=1; sid=abc".parse().unwrap());
        let req = view(&headers, "h", "/p.php", Some("id=42&q=a+b"));
        let check = |subject: MatchSubject, op: MatchOp| {
            CompiledCondition {
                cond: compile_condition(&subject, &op).unwrap(),
                subject,
            }
            .holds(&req)
        };
        assert!(check(
            MatchSubject::Header("x-beta".into()),
            MatchOp::Present
        ));
        assert!(check(
            MatchSubject::Header("x-nope".into()),
            MatchOp::Absent
        ));
        assert!(check(
            MatchSubject::Cookie("sid".into()),
            MatchOp::In(vec!["abc".into()])
        ));
        assert!(check(
            MatchSubject::Query("q".into()),
            MatchOp::In(vec!["a b".into()])
        ));
        assert!(check(
            MatchSubject::Query("id".into()),
            MatchOp::Regex("^[0-9]+$".into())
        ));
        assert!(check(
            MatchSubject::Method,
            MatchOp::In(vec!["get".into(), "POST".into()])
        ));
        assert!(check(
            MatchSubject::Ip,
            MatchOp::In(vec!["203.0.113.0/24".into()])
        ));
        assert!(!check(
            MatchSubject::Ip,
            MatchOp::NotIn(vec!["203.0.113.9".into()])
        ));
        assert!(check(
            MatchSubject::Path,
            MatchOp::NotRegex(r"\.html$".into())
        ));
        assert!(check(
            MatchSubject::Scheme,
            MatchOp::NotIn(vec!["https".into()])
        ));
    }

    #[test]
    fn upstream_uri_rewrites_and_proxy_pass_path() {
        let mut strip = loc(LocationKind::Prefix, "/api/", "http://svc:9000/v2/");
        let mut rw = loc(LocationKind::Prefix, "/old/", "a");
        rw.rewrites = vec![RewriteRule {
            pattern: "^/old/(.*)$".into(),
            replacement: "/new/$1?from=old".into(),
        }];
        strip.headers = HeaderOps::default();
        let t = table(vec![SiteConfig {
            locations: vec![strip, rw],
            ..Default::default()
        }]);
        let h = HeaderMap::new();
        let req = view(&h, "x", "/api/users/7", Some("a=1"));
        let r = t.route(&req).unwrap();
        assert_eq!(
            r.location.upstream_uri(&req, &r.captures),
            "/v2/users/7?a=1"
        );
        let Target::Upstream { group, .. } = &r.location.target else {
            panic!()
        };
        assert_eq!(
            group.url(0),
            "http://svc:9000",
            "anonymous group from the URL"
        );
        let req = view(&h, "x", "/old/page", Some("x=2"));
        let r = t.route(&req).unwrap();
        assert_eq!(
            r.location.upstream_uri(&req, &r.captures),
            "/new/page?from=old&x=2"
        );
    }

    #[test]
    fn variables_expand() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "curl".parse().unwrap());
        let req = view(&headers, "Example.com:80", "/a/b", Some("x=1"));
        let caps = vec!["/a/b".to_string(), "b".to_string()];
        assert_eq!(
            expand_vars(
                "https://$host$request_uri|$uri|$args|$1|$arg_x|$http_user_agent|${scheme}|$nope|$",
                &req,
                &caps
            ),
            "https://example.com/a/b?x=1|/a/b|x=1|b|1|curl|http|$nope|$"
        );
    }

    #[test]
    fn security_merges_and_rate_limit_counts_per_location() {
        let mut admin = loc(LocationKind::Prefix, "/admin/", "a");
        admin.security = SecurityConfig {
            allow: vec!["10.0.0.0/8".into()],
            rate_limit: LocationRateLimit::parse("2/1m"),
            ..Default::default()
        };
        let http_sec = SecurityConfig {
            mode: Some(SecurityMode::Shadow),
            ..Default::default()
        };
        let t = RouteTable::build(
            &[UpstreamGroupConfig {
                name: "a".into(),
                servers: vec!["http://a:1".into()],
                ..Default::default()
            }],
            &[SiteConfig {
                locations: vec![admin],
                ..Default::default()
            }],
            &http_sec,
            &GroupDefaults::default(),
        )
        .unwrap();
        let h = HeaderMap::new();
        let req = view(&h, "x", "/admin/x", None);
        let r = t.route(&req).unwrap();
        let sec = &r.location.security;
        assert_eq!(sec.mode, SecurityMode::Shadow, "inherited from http");
        assert!(!sec.ip_permitted("203.0.113.9".parse().unwrap()));
        assert!(sec.ip_permitted("10.1.2.3".parse().unwrap()));
        let rl = sec.rate_limit.unwrap();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(t.rate_allow(r.location.id, ip, rl));
        assert!(t.rate_allow(r.location.id, ip, rl));
        assert!(!t.rate_allow(r.location.id, ip, rl));
        assert!(
            t.rate_allow(r.location.id, "10.9.9.9".parse().unwrap(), rl),
            "per IP"
        );
    }
}
