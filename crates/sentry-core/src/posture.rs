//! Web security posture advisories (F11).
//!
//! The inline edge inspects origin response headers and reports missing or
//! weak web-security headers (CSP, HSTS, COOP, frame protection, Trusted
//! Types, nosniff, referrer policy) as weight-0 `PostureAdvisory` signals.
//! The findings describe the *protected site*, not the visitor — they are
//! advisory only and never change a score or verdict. Responding to them
//! (`enforce` header injection) is deliberately roadmap: without per-site
//! knowledge (domains, script nonces, framing needs) an injected CSP would
//! break pages.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::analysis::{Signal, SignalKind, POSTURE_ADVISORY_WEIGHT};
use crate::config::PostureConfig;

/// Check id: Content-Security-Policy missing or not restrictive against XSS.
pub const CSP: &str = "csp";
/// Check id: Strict-Transport-Security missing or weak `max-age`.
pub const HSTS: &str = "hsts";
/// Check id: Cross-Origin-Opener-Policy missing or `unsafe-none`.
pub const COOP: &str = "coop";
/// Check id: no `X-Frame-Options` and no CSP `frame-ancestors`.
pub const CLICKJACKING: &str = "clickjacking";
/// Check id: CSP without `require-trusted-types-for 'script'`.
pub const TRUSTED_TYPES: &str = "trusted_types";
/// Check id: `X-Content-Type-Options: nosniff` missing.
pub const NOSNIFF: &str = "nosniff";
/// Check id: `Referrer-Policy` missing or unsafe.
pub const REFERRER_POLICY: &str = "referrer_policy";

/// All supported check ids, in report order (`checks` config accepts these).
pub const ALL_CHECKS: [&str; 7] = [
    CSP,
    HSTS,
    COOP,
    CLICKJACKING,
    TRUSTED_TYPES,
    NOSNIFF,
    REFERRER_POLICY,
];

/// Max distinct hosts tracked — a forged `Host` header must not be able to
/// grow the table (or the `host` metric label) without bound.
pub const HOST_CAP: usize = 64;

/// One advisory about an origin response's security posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureFinding {
    /// Check id (metric label and `checks` config key).
    pub check: &'static str,
    /// Human-readable explanation, PageSpeed-style.
    pub detail: String,
}

impl PostureFinding {
    /// Shadow signal: the weight is always 0 — advisories never re-score.
    pub fn to_signal(&self) -> Signal {
        Signal {
            kind: SignalKind::PostureAdvisory,
            weight: POSTURE_ADVISORY_WEIGHT,
            detail: Some(format!("{}: {}", self.check, self.detail)),
        }
    }
}

/// Effective posture configuration, projected from `[posture]`.
#[derive(Debug, Clone)]
pub struct PostureScan {
    /// Advisories run at all (off keeps the checks zero-cost).
    pub enabled: bool,
    /// Enabled check ids.
    pub checks: HashSet<&'static str>,
    /// HSTS `max-age` below which the header counts as weak.
    pub hsts_min_max_age: u64,
    /// Host allowlist (empty = any host, subject to the tracker cap).
    pub hosts: HashSet<String>,
    /// A finding is re-reported for the same host after this idle period.
    pub ttl: Duration,
}

impl PostureScan {
    /// Project the daemon config onto the check knobs. Unknown ids in
    /// `checks` are ignored (see [`PostureConfig::unknown_checks`] for the
    /// daemon-side warning).
    pub fn from_config(cfg: &PostureConfig) -> Self {
        let checks: HashSet<&'static str> = if cfg.checks.is_empty() {
            ALL_CHECKS.into_iter().collect()
        } else {
            cfg.checks.iter().filter_map(|c| known_check(c)).collect()
        };
        Self {
            enabled: cfg.enabled,
            checks,
            hsts_min_max_age: cfg.hsts_min_max_age,
            hosts: cfg
                .hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            ttl: Duration::from_secs(cfg.dedupe_ttl_secs.max(1)),
        }
    }

    fn check_enabled(&self, id: &str) -> bool {
        self.checks.contains(id)
    }
}

impl Default for PostureScan {
    fn default() -> Self {
        Self::from_config(&PostureConfig::default())
    }
}

/// Resolve a config check id (case-insensitive) to its canonical name.
pub fn known_check(id: &str) -> Option<&'static str> {
    ALL_CHECKS
        .iter()
        .find(|k| k.eq_ignore_ascii_case(id))
        .copied()
}

/// Inspect one origin response's headers and return the advisories that
/// fire. Pure: headers are `(name, value)` pairs with lowercase names (the
/// `http` crate already normalizes them); values must be UTF-8 (the edge
/// skips non-UTF-8 header values).
///
/// HSTS is only graded on TLS connections — on plain HTTP the header is
/// ignored by browsers and the site-level `https` advisory (startup warning
/// + `sentry posture`) is the finding.
pub fn inspect_response<'a, I>(headers: I, is_tls: bool, scan: &PostureScan) -> Vec<PostureFinding>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    if !scan.enabled {
        return Vec::new();
    }
    let mut map: HashMap<String, String> = HashMap::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        let entry = map.entry(name).or_default();
        if !entry.is_empty() {
            entry.push_str("; ");
        }
        entry.push_str(value);
    }
    let mut out = Vec::new();

    let csp = non_empty(map.get("content-security-policy"));
    if scan.check_enabled(CSP) {
        match csp {
            None => out.push(finding(CSP, "missing content-security-policy")),
            Some(v) => {
                if let Some(reason) = csp_not_restrictive_reason(v) {
                    out.push(finding(CSP, format!("not restrictive ({reason})")));
                }
            }
        }
    }

    if scan.check_enabled(HSTS) && is_tls {
        match non_empty(map.get("strict-transport-security")) {
            None => out.push(finding(HSTS, "missing strict-transport-security")),
            Some(v) => match hsts_max_age(v) {
                Some(age) if age < scan.hsts_min_max_age => out.push(finding(
                    HSTS,
                    format!("max-age {age} below {}", scan.hsts_min_max_age),
                )),
                Some(_) => {}
                None => out.push(finding(
                    HSTS,
                    "strict-transport-security: unparsable max-age",
                )),
            },
        }
    }

    if scan.check_enabled(COOP) {
        match non_empty(map.get("cross-origin-opener-policy")) {
            None => out.push(finding(COOP, "missing cross-origin-opener-policy")),
            Some(v) if v.eq_ignore_ascii_case("unsafe-none") => {
                out.push(finding(COOP, "cross-origin-opener-policy: unsafe-none"))
            }
            Some(_) => {}
        }
    }

    if scan.check_enabled(CLICKJACKING) {
        let xfo = non_empty(map.get("x-frame-options"))
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let frame_ancestors = csp_directive(csp, "frame-ancestors");
        let protected = xfo.contains("deny")
            || xfo.contains("sameorigin")
            || frame_ancestors.is_some_and(|v| !v.split_whitespace().any(|t| t == "*"));
        if !protected {
            out.push(finding(
                CLICKJACKING,
                "no x-frame-options or csp frame-ancestors",
            ));
        }
    }

    if scan.check_enabled(TRUSTED_TYPES) {
        match csp {
            None => out.push(finding(
                TRUSTED_TYPES,
                "csp absent (no require-trusted-types-for)",
            )),
            Some(v) => {
                let has_tt = csp_directive(Some(v), "require-trusted-types-for")
                    .is_some_and(|v| v.to_ascii_lowercase().contains("'script'"));
                if !has_tt {
                    out.push(finding(
                        TRUSTED_TYPES,
                        "csp has no require-trusted-types-for 'script'",
                    ));
                }
            }
        }
    }

    if scan.check_enabled(NOSNIFF) {
        match non_empty(map.get("x-content-type-options")) {
            None => out.push(finding(NOSNIFF, "missing x-content-type-options")),
            Some(v) if !v.trim().eq_ignore_ascii_case("nosniff") => {
                out.push(finding(NOSNIFF, format!("x-content-type-options: {v}")))
            }
            Some(_) => {}
        }
    }

    if scan.check_enabled(REFERRER_POLICY) {
        match non_empty(map.get("referrer-policy")) {
            None => out.push(finding(REFERRER_POLICY, "missing referrer-policy")),
            Some(v)
                if v.to_ascii_lowercase().contains("unsafe-url")
                    || v.to_ascii_lowercase()
                        .contains("no-referrer-when-downgrade") =>
            {
                out.push(finding(
                    REFERRER_POLICY,
                    format!("unsafe referrer-policy ({v})"),
                ));
            }
            Some(_) => {}
        }
    }

    out
}

/// Deduplicates findings per (host, check) for a TTL so a busy site gets
/// one advisory instead of one per request. Internally locked — the edge
/// shares one tracker across workers.
#[derive(Debug)]
pub struct PostureTracker {
    scan: PostureScan,
    seen: RwLock<HashMap<String, HashMap<&'static str, Instant>>>,
}

impl PostureTracker {
    /// Build a tracker from the projected scan config.
    pub fn new(scan: PostureScan) -> Self {
        Self {
            scan,
            seen: RwLock::new(HashMap::new()),
        }
    }

    /// The projected config this tracker runs with.
    pub fn scan(&self) -> &PostureScan {
        &self.scan
    }

    /// Observe one origin response: returns only the findings that are new
    /// (or re-armed) for this host+check since the TTL.
    pub fn observe<'a, I>(&self, host: &str, headers: I, is_tls: bool) -> Vec<PostureFinding>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        if !self.scan.enabled {
            return Vec::new();
        }
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Vec::new();
        }
        if !self.scan.hosts.is_empty() && !self.scan.hosts.contains(&host) {
            return Vec::new();
        }

        let findings = inspect_response(headers, is_tls, &self.scan);
        if findings.is_empty() {
            return Vec::new();
        }

        let mut seen = self.seen.write().expect("posture tracker poisoned");
        if !seen.contains_key(&host) && seen.len() >= HOST_CAP {
            return Vec::new();
        }
        let now = Instant::now();
        let per_host = seen.entry(host).or_default();
        let mut fresh = Vec::new();
        for f in findings {
            match per_host.get(f.check) {
                Some(t) if now.duration_since(*t) < self.scan.ttl => {}
                _ => {
                    per_host.insert(f.check, now);
                    fresh.push(f);
                }
            }
        }
        fresh
    }

    /// Drop host entries whose findings all expired; returns the number of
    /// hosts removed. Driven by the daemon's 60s prune task.
    pub fn prune(&self) -> usize {
        let mut seen = self.seen.write().expect("posture tracker poisoned");
        let before = seen.len();
        seen.retain(|_, checks| checks.values().any(|t| t.elapsed() < self.scan.ttl));
        before - seen.len()
    }
}

fn finding(check: &'static str, detail: impl Into<String>) -> PostureFinding {
    PostureFinding {
        check,
        detail: detail.into(),
    }
}

fn non_empty(v: Option<&String>) -> Option<&str> {
    v.map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Why a CSP value is not restrictive against XSS (`None` = restrictive).
/// `script-src` wins over `default-src` when both are present.
fn csp_not_restrictive_reason(csp: &str) -> Option<String> {
    let mut script_src: Option<Vec<String>> = None;
    let mut default_src: Option<Vec<String>> = None;
    for directive in csp.split(';') {
        let mut tokens = directive.split_whitespace();
        let name = tokens.next().unwrap_or_default().to_ascii_lowercase();
        let values: Vec<String> = tokens.map(|t| t.to_ascii_lowercase()).collect();
        match name.as_str() {
            "script-src" if script_src.is_none() => script_src = Some(values),
            "default-src" if default_src.is_none() => default_src = Some(values),
            _ => {}
        }
    }
    if let Some(src) = script_src {
        return unsafe_inline_reason(src, "script-src");
    }
    match default_src {
        Some(src) => unsafe_inline_reason(src, "default-src"),
        None => Some("no script-src/default-src".to_string()),
    }
}

fn unsafe_inline_reason(src: Vec<String>, name: &str) -> Option<String> {
    if src.iter().any(|t| t == "'unsafe-inline'") {
        Some(format!("unsafe-inline in {name}"))
    } else {
        None
    }
}

/// Value of the first directive with the given name in a CSP header
/// (everything after the directive name, trimmed).
fn csp_directive<'c>(csp: Option<&'c str>, name: &str) -> Option<&'c str> {
    let csp = csp?;
    for directive in csp.split(';') {
        let trimmed = directive.trim_start();
        let mut parts = trimmed.split_whitespace();
        if parts.next().is_some_and(|n| n.eq_ignore_ascii_case(name)) {
            let rest = trimmed
                .find(char::is_whitespace)
                .map(|i| trimmed[i..].trim())
                .unwrap_or_default();
            if !rest.is_empty() {
                return Some(rest);
            }
            return None;
        }
    }
    None
}

/// Parse `max-age=<seconds>` out of an HSTS header value.
fn hsts_max_age(value: &str) -> Option<u64> {
    let lower = value.to_ascii_lowercase();
    let idx = lower.find("max-age=")?;
    lower[idx + 8..]
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse::<u64>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PostureConfig;

    fn scan() -> PostureScan {
        PostureScan::default()
    }

    fn h<'a>(n: &'a [(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        n.to_vec()
    }

    #[test]
    fn all_hardening_missing_fires_every_check() {
        let fs = inspect_response(h(&[("content-type", "text/html")]), true, &scan());
        let checks: Vec<_> = fs.iter().map(|f| f.check).collect();
        for id in ALL_CHECKS {
            assert!(checks.contains(&id), "missing check {id}");
        }
    }

    #[test]
    fn fully_hardened_response_is_clean() {
        let headers = h(&[
            ("content-type", "text/html"),
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'; \
                 require-trusted-types-for 'script'; object-src 'none'",
            ),
            (
                "strict-transport-security",
                "max-age=31536000; includeSubDomains",
            ),
            ("cross-origin-opener-policy", "same-origin"),
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
        ]);
        assert!(inspect_response(headers, true, &scan()).is_empty());
    }

    #[test]
    fn csp_not_restrictive_variants() {
        assert_eq!(
            csp_not_restrictive_reason("default-src 'unsafe-inline'").as_deref(),
            Some("unsafe-inline in default-src")
        );
        assert_eq!(
            csp_not_restrictive_reason("script-src 'unsafe-inline' 'self'").as_deref(),
            Some("unsafe-inline in script-src")
        );
        assert_eq!(
            csp_not_restrictive_reason("img-src *").as_deref(),
            Some("no script-src/default-src")
        );
        assert_eq!(
            csp_not_restrictive_reason("script-src 'self' 'nonce-x'").as_deref(),
            None
        );
        // script-src wins over default-src when both present.
        assert_eq!(
            csp_not_restrictive_reason("default-src 'self'; script-src 'unsafe-inline'").as_deref(),
            Some("unsafe-inline in script-src")
        );
    }

    #[test]
    fn csp_missing_vs_weak_distinct_details() {
        let missing = inspect_response(h(&[("x", "y")]), true, &scan());
        let weak = inspect_response(
            h(&[("content-security-policy", "img-src *")]),
            true,
            &scan(),
        );
        let m = missing.iter().find(|f| f.check == CSP).unwrap();
        let w = weak.iter().find(|f| f.check == CSP).unwrap();
        assert_eq!(m.detail, "missing content-security-policy");
        assert_eq!(w.detail, "not restrictive (no script-src/default-src)");
    }

    #[test]
    fn hsts_weak_and_unparsable() {
        let weak = inspect_response(
            h(&[("strict-transport-security", "max-age=86400")]),
            true,
            &scan(),
        );
        let w = weak.iter().find(|f| f.check == HSTS).unwrap();
        assert_eq!(
            w.detail,
            format!("max-age 86400 below {}", scan().hsts_min_max_age)
        );
        let bad = inspect_response(
            h(&[("strict-transport-security", "includeSubDomains")]),
            true,
            &scan(),
        );
        let b = bad.iter().find(|f| f.check == HSTS).unwrap();
        assert_eq!(b.detail, "strict-transport-security: unparsable max-age");
    }

    #[test]
    fn hsts_skipped_on_plain_http() {
        let fs = inspect_response(h(&[("content-type", "text/html")]), false, &scan());
        assert!(!fs.iter().any(|f| f.check == HSTS));
    }

    #[test]
    fn clickjacking_frame_ancestors_counts_wildcard_does_not() {
        let ok = inspect_response(
            h(&[("content-security-policy", "frame-ancestors 'self'")]),
            true,
            &scan(),
        );
        assert!(!ok.iter().any(|f| f.check == CLICKJACKING));
        let star = inspect_response(
            h(&[("content-security-policy", "frame-ancestors *")]),
            true,
            &scan(),
        );
        assert!(star.iter().any(|f| f.check == CLICKJACKING));
        let xfo = inspect_response(h(&[("x-frame-options", "SAMEORIGIN")]), true, &scan());
        assert!(!xfo.iter().any(|f| f.check == CLICKJACKING));
    }

    #[test]
    fn coop_unsafe_none_is_a_finding() {
        let fs = inspect_response(
            h(&[("cross-origin-opener-policy", "unsafe-none")]),
            true,
            &scan(),
        );
        let f = fs.iter().find(|f| f.check == COOP).unwrap();
        assert_eq!(f.detail, "cross-origin-opener-policy: unsafe-none");
    }

    #[test]
    fn nosniff_invalid_value_fires() {
        let fs = inspect_response(h(&[("x-content-type-options", "sniff")]), true, &scan());
        let f = fs.iter().find(|f| f.check == NOSNIFF).unwrap();
        assert_eq!(f.detail, "x-content-type-options: sniff");
    }

    #[test]
    fn unsafe_referrer_policy_fires() {
        let fs = inspect_response(
            h(&[("referrer-policy", "no-referrer-when-downgrade")]),
            true,
            &scan(),
        );
        let f = fs.iter().find(|f| f.check == REFERRER_POLICY).unwrap();
        assert_eq!(
            f.detail,
            "unsafe referrer-policy (no-referrer-when-downgrade)"
        );
    }

    #[test]
    fn check_toggles_limit_findings() {
        let cfg = PostureConfig {
            checks: vec![CSP.to_string()],
            ..Default::default()
        };
        let fs = inspect_response(h(&[("x", "y")]), true, &PostureScan::from_config(&cfg));
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].check, CSP);
    }

    #[test]
    fn disabled_scan_is_zero_cost() {
        let cfg = PostureConfig {
            enabled: false,
            ..Default::default()
        };
        let fs = inspect_response(h(&[("x", "y")]), true, &PostureScan::from_config(&cfg));
        assert!(fs.is_empty());
    }

    #[test]
    fn signal_is_always_weight_zero() {
        let f = finding(CSP, "missing content-security-policy");
        let s = f.to_signal();
        assert_eq!(s.kind, SignalKind::PostureAdvisory);
        assert_eq!(s.weight, 0);
        assert_eq!(
            s.detail.as_deref(),
            Some("csp: missing content-security-policy")
        );
    }

    #[test]
    fn tracker_dedupes_until_ttl_expires() {
        let t = PostureTracker::new(scan());
        let headers = h(&[("x", "y")]);
        let first = t.observe("example.com", headers.clone(), true);
        assert_eq!(first.len(), 7);
        assert!(t.observe("example.com", headers.clone(), true).is_empty());
        assert!(t.observe("EXAMPLE.com ", headers, true).is_empty());
        t.prune();
    }

    #[test]
    fn tracker_host_allowlist_blocks_others() {
        let cfg = PostureConfig {
            hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        let t = PostureTracker::new(PostureScan::from_config(&cfg));
        assert!(t.observe("other.com", h(&[("x", "y")]), true).is_empty());
        assert!(!t.observe("example.com", h(&[("x", "y")]), true).is_empty());
    }

    #[test]
    fn tracker_host_cap_bounds_table() {
        let t = PostureTracker::new(scan());
        for i in 0..HOST_CAP {
            assert!(!t
                .observe(&format!("h{i}.test"), h(&[("x", "y")]), true)
                .is_empty());
        }
        assert!(t
            .observe("overflow.test", h(&[("x", "y")]), true)
            .is_empty());
    }
}
