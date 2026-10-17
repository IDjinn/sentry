//! Browser-side signals for the fingerprint stage (F18.2).
//!
//! The inline edge serves a small first-party collector (`init.js`) that
//! reads canvas / WebGL / audio / font / screen / hardware / locale traits
//! and `POST`s them back, bound to the visitor cookie. This module owns the
//! pure part: the wire model with hard caps ([`ClientSignals`]), the stable
//! device id derived from it (`j-<16 hex>`), the bot/consistency checks
//! ([`analyze`]) and the bounded in-memory [`ClientStore`] the pipeline reads.
//!
//! Everything here is client-supplied and therefore forgeable. The checks
//! look for *inconsistency* (headless markers, header vs `navigator`
//! disagreement), never treat a value as proof, and the signals carry
//! moderate weights.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::{Signal, SignalKind};

/// Weight of `HeadlessBrowser`.
pub const HEADLESS_BROWSER_WEIGHT: u8 = 45;
/// Weight of `ClientInconsistency`.
pub const CLIENT_INCONSISTENCY_WEIGHT: u8 = 35;

/// Max bytes accepted for one collector report.
pub const MAX_REPORT_BYTES: usize = 8 * 1024;
const MAX_STR: usize = 160;
const MAX_LIST: usize = 8;
/// Same visitor may report at most once per this interval.
const MIN_REPORT_INTERVAL: Duration = Duration::from_secs(10);
/// Per-IP reports allowed per minute.
const IP_REPORTS_PER_MIN: u32 = 30;

/// One collector report. Every field is optional: a probe that throws on the
/// client is simply absent. Unknown fields are ignored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientSignals {
    /// Collector version.
    pub v: Option<u8>,
    /// `navigator.userAgent`.
    pub ua: Option<String>,
    /// `navigator.platform`.
    pub platform: Option<String>,
    /// `navigator.languages`.
    pub langs: Option<Vec<String>>,
    /// IANA time zone (`Intl.DateTimeFormat().resolvedOptions().timeZone`).
    pub tz: Option<String>,
    /// `screen.width`, `screen.height`, `screen.colorDepth`.
    pub screen: Option<[u32; 3]>,
    /// `window.devicePixelRatio`.
    pub dpr: Option<f32>,
    /// `navigator.hardwareConcurrency`.
    pub hw: Option<u32>,
    /// `navigator.deviceMemory`.
    pub mem: Option<f32>,
    /// `navigator.maxTouchPoints`.
    pub touch: Option<u32>,
    /// `navigator.plugins.length`.
    pub plugins: Option<u32>,
    /// `navigator.mimeTypes.length`.
    pub mimes: Option<u32>,
    /// `navigator.webdriver`.
    pub webdriver: Option<bool>,
    /// `typeof window.chrome === "object"`.
    pub chrome: Option<bool>,
    /// Canvas 2D render hash.
    pub canvas: Option<String>,
    /// Unmasked WebGL vendor.
    pub webgl_vendor: Option<String>,
    /// Unmasked WebGL renderer.
    pub webgl_renderer: Option<String>,
    /// Hash of WebGL limits + extension list.
    pub webgl: Option<String>,
    /// OfflineAudioContext render hash.
    pub audio: Option<String>,
    /// Hash of the installed-font probe bitmask.
    pub fonts: Option<String>,
    /// Names of probes that failed on the client.
    pub errors: Option<Vec<String>>,
}

fn cap(s: &mut Option<String>) {
    if let Some(v) = s {
        if v.len() > MAX_STR {
            let mut end = MAX_STR;
            while !v.is_char_boundary(end) {
                end -= 1;
            }
            v.truncate(end);
        }
    }
}

impl ClientSignals {
    /// Parse and sanitize a report body (size-capped, strings truncated).
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.len() > MAX_REPORT_BYTES {
            return None;
        }
        let mut s: ClientSignals = serde_json::from_slice(body).ok()?;
        for f in [
            &mut s.ua,
            &mut s.platform,
            &mut s.tz,
            &mut s.canvas,
            &mut s.webgl_vendor,
            &mut s.webgl_renderer,
            &mut s.webgl,
            &mut s.audio,
            &mut s.fonts,
        ] {
            cap(f);
        }
        for list in [&mut s.langs, &mut s.errors].into_iter().flatten() {
            list.truncate(MAX_LIST);
            for v in list.iter_mut() {
                if v.len() > 64 {
                    v.truncate(64);
                }
            }
        }
        Some(s)
    }

    /// Stable device id `j-<16 hex>` from the traits that don't change per
    /// page view. `None` when no high-entropy probe (canvas / WebGL / audio)
    /// succeeded — a constant id for everyone would be worse than none.
    pub fn id(&self) -> Option<String> {
        if self.canvas.is_none() && self.webgl.is_none() && self.audio.is_none() {
            return None;
        }
        let s = |o: &Option<String>| o.clone().unwrap_or_default();
        let n = |o: Option<u32>| o.map(|v| v.to_string()).unwrap_or_default();
        let screen = self
            .screen
            .map(|[w, h, d]| format!("{w}x{h}x{d}"))
            .unwrap_or_default();
        let langs = self.langs.as_ref().map(|l| l.join(",")).unwrap_or_default();
        let parts = [
            s(&self.canvas),
            s(&self.webgl),
            s(&self.webgl_vendor),
            s(&self.webgl_renderer),
            s(&self.audio),
            s(&self.fonts),
            screen,
            self.dpr.map(|d| format!("{d:.2}")).unwrap_or_default(),
            n(self.hw),
            self.mem.map(|m| format!("{m}")).unwrap_or_default(),
            s(&self.tz),
            s(&self.platform),
            langs,
        ];
        let mut h = Sha256::new();
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                h.update([0x1f]);
            }
            h.update(p.to_ascii_lowercase().as_bytes());
        }
        let d = h.finalize();
        let mut out = String::from("j-");
        for b in &d[..8] {
            out.push_str(&format!("{b:02x}"));
        }
        Some(out)
    }
}

fn ua_os(ua: &str) -> Option<&'static str> {
    let u = ua.to_ascii_lowercase();
    if u.contains("android") {
        Some("android")
    } else if u.contains("iphone") || u.contains("ipad") || u.contains("ipod") {
        Some("ios")
    } else if u.contains("windows") {
        Some("windows")
    } else if u.contains("cros") {
        Some("cros")
    } else if u.contains("macintosh") || u.contains("mac os x") {
        Some("mac")
    } else if u.contains("linux") || u.contains("x11") {
        Some("linux")
    } else {
        None
    }
}

fn platform_matches(os: &str, platform: &str) -> bool {
    let p = platform.to_ascii_lowercase();
    match os {
        "windows" => p.starts_with("win"),
        "mac" => p.starts_with("mac"),
        "ios" => {
            p.contains("iphone") || p.contains("ipad") || p.contains("ipod") || p.starts_with("mac")
        }
        "android" => p.contains("linux") || p.contains("android") || p.contains("arm"),
        "cros" => p.contains("cros") || p.contains("linux"),
        "linux" => p.contains("linux") || p.contains("x11") || p.contains("freebsd"),
        _ => true,
    }
}

fn primary_lang(tag: &str) -> String {
    tag.split(['-', '_', ';'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Bot / consistency findings for one report. `http_ua` and
/// `accept_language` are the request headers of the same browser.
pub fn analyze(
    sig: &ClientSignals,
    http_ua: Option<&str>,
    accept_language: Option<&str>,
) -> Vec<Signal> {
    let mut out = Vec::new();
    let ua = sig.ua.as_deref().or(http_ua).unwrap_or_default();
    let ua_l = ua.to_ascii_lowercase();
    let chrome_ua = ua_l.contains("chrome/") && !ua_l.contains("firefox");
    let renderer = sig
        .webgl_renderer
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    let mut strong: Vec<&str> = Vec::new();
    if sig.webdriver == Some(true) {
        strong.push("navigator.webdriver");
    }
    if ua_l.contains("headlesschrome") || ua_l.contains("phantomjs") {
        strong.push("headless user-agent");
    }
    if ["swiftshader", "llvmpipe", "softpipe", "software rasterizer"]
        .iter()
        .any(|m| renderer.contains(m))
    {
        strong.push("software WebGL renderer");
    }
    if sig.screen.is_some_and(|[w, h, _]| w == 0 || h == 0) {
        strong.push("zero-size screen");
    }
    let mut weak: Vec<&str> = Vec::new();
    if chrome_ua && sig.chrome == Some(false) {
        weak.push("chrome UA without window.chrome");
    }
    let mobile = ua_l.contains("mobile") || ua_l.contains("android");
    if chrome_ua && !mobile && sig.plugins == Some(0) && sig.mimes == Some(0) {
        weak.push("no plugins on desktop Chrome");
    }
    if !strong.is_empty() || weak.len() >= 2 {
        let all: Vec<_> = strong.iter().chain(weak.iter()).copied().collect();
        out.push(Signal {
            kind: SignalKind::HeadlessBrowser,
            weight: HEADLESS_BROWSER_WEIGHT,
            detail: Some(all.join(", ")),
        });
    }

    let mut hard: Vec<String> = Vec::new();
    if let (Some(client), Some(header)) = (sig.ua.as_deref(), http_ua) {
        if client.trim() != header.trim() {
            hard.push("navigator.userAgent differs from the UA header".into());
        }
    }
    if let (Some(os), Some(platform)) = (ua_os(ua), sig.platform.as_deref()) {
        if !platform.is_empty() && !platform_matches(os, platform) {
            hard.push(format!("UA says {os} but navigator.platform is {platform}"));
        }
    }
    let mut soft: Vec<String> = Vec::new();
    if ua_os(ua).is_some_and(|o| o == "android" || o == "ios") && sig.touch == Some(0) {
        soft.push("mobile UA without touch points".into());
    }
    if let (Some(first), Some(header)) = (
        sig.langs.as_ref().and_then(|l| l.first()),
        accept_language.and_then(|h| h.split(',').next()),
    ) {
        if primary_lang(first) != primary_lang(header) && !header.trim().is_empty() {
            soft.push(format!(
                "navigator.languages[0]={first} vs Accept-Language {}",
                header.trim()
            ));
        }
    }
    if !hard.is_empty() || soft.len() >= 2 {
        hard.extend(soft);
        out.push(Signal {
            kind: SignalKind::ClientInconsistency,
            weight: CLIENT_INCONSISTENCY_WEIGHT,
            detail: Some(hard.join("; ")),
        });
    }
    out
}

/// What the store remembers about one visitor's last report.
#[derive(Debug, Clone)]
pub struct ClientRecord {
    /// `j-…` id, when the report had enough entropy.
    pub id: Option<String>,
    /// Findings to attach to the visitor's requests.
    pub signals: Vec<Signal>,
}

struct Slot {
    record: ClientRecord,
    reported: Instant,
}

/// Outcome of [`ClientStore::record`].
#[derive(Debug, Clone, PartialEq)]
pub enum RecordOutcome {
    /// Stored (or refreshed); carries the derived `j-` id.
    Stored(Option<String>),
    /// Too frequent for this visitor or IP — report dropped.
    Throttled,
}

struct Inner {
    visitors: HashMap<String, Slot>,
    ips: HashMap<IpAddr, (Instant, u32)>,
}

/// Bounded, TTL'd map `visitor id → last collector report`. Per-node.
pub struct ClientStore {
    inner: RwLock<Inner>,
    ttl: Duration,
    max_entries: usize,
}

impl ClientStore {
    /// Build with a retention `ttl` and an entry cap.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(Inner {
                visitors: HashMap::new(),
                ips: HashMap::new(),
            }),
            ttl,
            max_entries: max_entries.max(1),
        }
    }

    /// Store a report for `visitor` (`v-…`), applying per-visitor and per-IP
    /// throttles.
    pub fn record(
        &self,
        visitor: &str,
        ip: IpAddr,
        sig: &ClientSignals,
        http_ua: Option<&str>,
        accept_language: Option<&str>,
    ) -> RecordOutcome {
        self.record_at(visitor, ip, sig, http_ua, accept_language, Instant::now())
    }

    fn record_at(
        &self,
        visitor: &str,
        ip: IpAddr,
        sig: &ClientSignals,
        http_ua: Option<&str>,
        accept_language: Option<&str>,
        now: Instant,
    ) -> RecordOutcome {
        let mut inner = self.inner.write().unwrap();
        let bucket = inner.ips.entry(ip).or_insert((now, 0));
        if now.duration_since(bucket.0) >= Duration::from_secs(60) {
            *bucket = (now, 0);
        }
        bucket.1 += 1;
        if bucket.1 > IP_REPORTS_PER_MIN {
            return RecordOutcome::Throttled;
        }
        if inner
            .visitors
            .get(visitor)
            .is_some_and(|s| now.duration_since(s.reported) < MIN_REPORT_INTERVAL)
        {
            return RecordOutcome::Throttled;
        }
        if !inner.visitors.contains_key(visitor) && inner.visitors.len() >= self.max_entries {
            let ttl = self.ttl;
            inner
                .visitors
                .retain(|_, s| now.duration_since(s.reported) < ttl);
            if inner.visitors.len() >= self.max_entries {
                let oldest = inner
                    .visitors
                    .iter()
                    .min_by_key(|(_, s)| s.reported)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    inner.visitors.remove(&k);
                }
            }
        }
        let record = ClientRecord {
            id: sig.id(),
            signals: analyze(sig, http_ua, accept_language),
        };
        let id = record.id.clone();
        inner.visitors.insert(
            visitor.to_string(),
            Slot {
                record,
                reported: now,
            },
        );
        RecordOutcome::Stored(id)
    }

    /// Last report for `visitor`, if still fresh.
    pub fn lookup(&self, visitor: &str) -> Option<ClientRecord> {
        let inner = self.inner.read().unwrap();
        let slot = inner.visitors.get(visitor)?;
        (slot.reported.elapsed() < self.ttl).then(|| slot.record.clone())
    }

    /// Drop expired visitors and idle IP buckets.
    pub fn prune(&self) {
        let now = Instant::now();
        let ttl = self.ttl;
        let mut inner = self.inner.write().unwrap();
        inner
            .visitors
            .retain(|_, s| now.duration_since(s.reported) < ttl);
        inner
            .ips
            .retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(120));
    }

    /// Visitors held.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().visitors.len()
    }

    /// No visitors held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        IpAddr::from([203, 0, 113, 5])
    }

    fn chrome_win() -> ClientSignals {
        ClientSignals {
            ua: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36".into()),
            platform: Some("Win32".into()),
            langs: Some(vec!["en-US".into(), "en".into()]),
            tz: Some("America/Sao_Paulo".into()),
            screen: Some([1920, 1080, 24]),
            dpr: Some(1.0),
            hw: Some(8),
            mem: Some(8.0),
            touch: Some(0),
            plugins: Some(5),
            mimes: Some(2),
            webdriver: Some(false),
            chrome: Some(true),
            canvas: Some("c4nv4s".into()),
            webgl_vendor: Some("Google Inc. (NVIDIA)".into()),
            webgl_renderer: Some("ANGLE (NVIDIA GeForce RTX 3060)".into()),
            webgl: Some("w3bgl".into()),
            audio: Some("4ud10".into()),
            fonts: Some("f0nts".into()),
            ..Default::default()
        }
    }

    const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36";

    #[test]
    fn clean_chrome_raises_nothing() {
        assert!(analyze(&chrome_win(), Some(UA), Some("en-US,en;q=0.9")).is_empty());
    }

    #[test]
    fn id_is_stable_and_ignores_window_noise() {
        let a = chrome_win();
        let mut b = chrome_win();
        b.plugins = Some(0);
        b.webdriver = Some(true);
        assert_eq!(a.id(), b.id());
        let mut c = chrome_win();
        c.canvas = Some("other".into());
        assert_ne!(a.id(), c.id());
        assert!(a.id().unwrap().starts_with("j-"));
    }

    #[test]
    fn no_entropy_no_id() {
        let s = ClientSignals {
            hw: Some(4),
            ..Default::default()
        };
        assert!(s.id().is_none());
    }

    #[test]
    fn webdriver_and_software_gl_are_headless() {
        let mut s = chrome_win();
        s.webdriver = Some(true);
        let sig = analyze(&s, Some(UA), None);
        assert_eq!(sig[0].kind, SignalKind::HeadlessBrowser);
        let mut s = chrome_win();
        s.webgl_renderer = Some("Google SwiftShader".into());
        assert_eq!(
            analyze(&s, Some(UA), None)[0].kind,
            SignalKind::HeadlessBrowser
        );
    }

    #[test]
    fn one_weak_marker_alone_is_not_enough() {
        let mut s = chrome_win();
        s.chrome = Some(false);
        assert!(analyze(&s, Some(UA), None).is_empty());
        s.plugins = Some(0);
        s.mimes = Some(0);
        assert_eq!(
            analyze(&s, Some(UA), None)[0].kind,
            SignalKind::HeadlessBrowser
        );
    }

    #[test]
    fn spoofed_ua_header_and_platform_mismatch() {
        let s = chrome_win();
        let sig = analyze(&s, Some("curl/8.0"), None);
        assert!(sig
            .iter()
            .any(|x| x.kind == SignalKind::ClientInconsistency));
        let mut s = chrome_win();
        s.platform = Some("Linux x86_64".into());
        let sig = analyze(&s, Some(UA), None);
        assert!(sig
            .iter()
            .any(|x| x.kind == SignalKind::ClientInconsistency));
    }

    #[test]
    fn language_mismatch_alone_is_soft() {
        let s = chrome_win();
        assert!(analyze(&s, Some(UA), Some("zh-CN")).is_empty());
    }

    #[test]
    fn parse_caps_and_rejects_garbage() {
        assert!(ClientSignals::parse(b"not json").is_none());
        assert!(ClientSignals::parse(&vec![b' '; MAX_REPORT_BYTES + 1]).is_none());
        let long = "x".repeat(1000);
        let body = format!(
            r#"{{"ua":"{long}","langs":["a","b","c","d","e","f","g","h","i","j"],"zzz":1}}"#
        );
        let s = ClientSignals::parse(body.as_bytes()).unwrap();
        assert_eq!(s.ua.unwrap().len(), MAX_STR);
        assert_eq!(s.langs.unwrap().len(), MAX_LIST);
    }

    #[test]
    fn store_throttles_visitor_and_ip() {
        let store = ClientStore::new(Duration::from_secs(3600), 100);
        let s = chrome_win();
        let t0 = Instant::now();
        assert!(matches!(
            store.record_at("v-a", ip(), &s, Some(UA), None, t0),
            RecordOutcome::Stored(Some(_))
        ));
        assert_eq!(
            store.record_at("v-a", ip(), &s, Some(UA), None, t0),
            RecordOutcome::Throttled
        );
        let later = t0 + Duration::from_secs(11);
        assert!(matches!(
            store.record_at("v-a", ip(), &s, Some(UA), None, later),
            RecordOutcome::Stored(_)
        ));
        let mut throttled = false;
        for n in 0..40 {
            if store.record_at(&format!("v-{n}"), ip(), &s, Some(UA), None, later)
                == RecordOutcome::Throttled
            {
                throttled = true;
            }
        }
        assert!(throttled);
        assert!(store.lookup("v-a").is_some());
    }

    #[test]
    fn store_evicts_oldest_at_cap() {
        let store = ClientStore::new(Duration::from_secs(3600), 3);
        let s = chrome_win();
        let t0 = Instant::now();
        for n in 0..6u64 {
            let ipn = IpAddr::from([10, 0, 0, n as u8]);
            store.record_at(
                &format!("v-{n}"),
                ipn,
                &s,
                Some(UA),
                None,
                t0 + Duration::from_secs(n),
            );
        }
        assert!(store.len() <= 3);
        assert!(store.lookup("v-5").is_some());
    }
}
