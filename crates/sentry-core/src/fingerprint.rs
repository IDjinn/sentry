//! Client fingerprinting (F18): recognize the same client across IPs and
//! over time, and ban it by fingerprint.
//!
//! Three ids are derived per request, none of them IP-based:
//!
//! - `t-<16 hex>` — **TLS id**: hash of the JA4 (JA3 fallback) of the
//!   connection. Identifies the TLS stack (browser build, `curl`, Go
//!   `net/http`, a headless-browser farm…). Shared by every client running it.
//! - `d-<16 hex>` — **device id**: the TLS id plus the headers that stay
//!   constant across request types (`User-Agent`, `Accept-Language`,
//!   `Accept-Encoding`, `Sec-CH-UA*`) and the negotiated ALPN. Headers that
//!   vary per resource (`Accept`, `Sec-Fetch-*`, `Referer`) stay out so one
//!   browser maps to one id. Still a population-level id, not a person.
//! - `v-<32 hex>` — **visitor id**: the first-party `sentry_vid` cookie the
//!   inline edge issues. The only id that follows one browser profile when
//!   its IP, TLS stack and headers change.
//!
//! Because passive ids are shared, [`FingerprintTracker`] never treats "many
//! IPs under one id" as bad on its own: an id earns reputation only when a
//! large share of the *other* IPs seen under it were flagged High/Critical
//! (a botnet or tool farm), not when it is simply popular (stock Chrome).
//! Bans ([`FingerprintBans`]) are explicit, and the CLI shows the id's
//! population before you commit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::{Signal, SignalKind};
use crate::config::FingerprintConfig;
use crate::event::{Event, HttpData, TlsData};

/// Name of the first-party visitor cookie issued by the inline edge.
pub const VISITOR_COOKIE: &str = "sentry_vid";

/// Weight of `FingerprintBanned` (a banned fingerprint is a block).
pub const FINGERPRINT_BANNED_WEIGHT: u8 = 100;
/// Default weight of `FingerprintReputation`.
pub const FINGERPRINT_REPUTATION_WEIGHT: u8 = 35;
/// Default weight of `VisitorDeviceChurn`.
pub const VISITOR_DEVICE_CHURN_WEIGHT: u8 = 30;

/// Share (percent) of the other IPs under an id that must be flagged for the
/// id to earn reputation — keeps popular benign ids clean.
const REPUTATION_MIN_RATIO_PCT: usize = 50;
/// Max IPs remembered per id (bounded memory; recency wins).
const MAX_IPS_PER_ID: usize = 128;
/// Max devices remembered per visitor.
const MAX_DEVICES_PER_VISITOR: usize = 32;
/// Minimum spacing between full sweeps triggered from the hot path.
const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// Fingerprint ids of one request. Absent ids are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// `d-…` device id (TLS + stable headers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// `t-…` TLS-stack id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// `v-…` visitor cookie id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visitor: Option<String>,
    /// `j-…` browser-side id (canvas/WebGL/audio/fonts/screen…), known once
    /// the visitor's collector report arrived (F18.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

impl Fingerprint {
    /// All present ids (device, tls, visitor).
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        [&self.client, &self.device, &self.tls, &self.visitor]
            .into_iter()
            .filter_map(|o| o.as_deref())
    }

    /// No id could be derived.
    pub fn is_empty(&self) -> bool {
        self.device.is_none()
            && self.tls.is_none()
            && self.visitor.is_none()
            && self.client.is_none()
    }

    /// Whether any id equals `needle` (case-insensitive).
    pub fn matches(&self, needle: &str) -> bool {
        self.ids().any(|id| id.eq_ignore_ascii_case(needle))
    }

    /// Most specific id for display: visitor, then device, then TLS.
    pub fn primary(&self) -> Option<&str> {
        self.visitor
            .as_deref()
            .or(self.device.as_deref())
            .or(self.tls.as_deref())
    }
}

fn hash_id(prefix: char, parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h.update([0x1f]);
        }
        h.update(p.as_bytes());
    }
    let digest = h.finalize();
    let mut out = String::with_capacity(18);
    out.push(prefix);
    out.push('-');
    for b in &digest[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A syntactically valid visitor cookie value: 32 hex chars.
pub fn valid_visitor(v: &str) -> bool {
    v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Mint a fresh visitor id (random, unrelated to any client data).
pub fn new_visitor_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// `Set-Cookie` value for the visitor cookie. `HttpOnly` (scripts never need
/// it), `SameSite=Lax`, `Secure` on HTTPS.
pub fn visitor_set_cookie(id: &str, max_age_secs: u64, secure: bool) -> String {
    let mut c =
        format!("{VISITOR_COOKIE}={id}; Max-Age={max_age_secs}; Path=/; HttpOnly; SameSite=Lax");
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn tls_of(evt: &Event) -> Option<&TlsData> {
    evt.tls()
        .or_else(|| evt.http().and_then(|h| h.tls.as_deref()))
}

fn device_id(h: &HttpData, tls: Option<&TlsData>) -> Option<String> {
    let ua = h
        .user_agent
        .as_deref()
        .or_else(|| h.headers.get("user-agent").map(String::as_str));
    let tls_fp = tls
        .and_then(|t| t.ja4.as_deref().or(t.ja3.as_deref()))
        .filter(|s| !s.is_empty());
    if ua.is_none() && tls_fp.is_none() {
        return None;
    }
    let hdr = |k: &str| {
        h.headers
            .get(k)
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default()
    };
    let ua = ua.unwrap_or_default().trim().to_ascii_lowercase();
    let alpn = tls
        .and_then(|t| t.alpn.as_deref())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lang = hdr("accept-language");
    let enc = hdr("accept-encoding");
    let ch = hdr("sec-ch-ua");
    let ch_mobile = hdr("sec-ch-ua-mobile");
    let ch_platform = hdr("sec-ch-ua-platform");
    Some(hash_id(
        'd',
        &[
            tls_fp.unwrap_or_default(),
            &alpn,
            &ua,
            &lang,
            &enc,
            &ch,
            &ch_mobile,
            &ch_platform,
        ],
    ))
}

/// Derive the fingerprint ids of `evt`. Pure; `None` when nothing is
/// fingerprintable (non-HTTP/TLS events, or HTTP without UA and TLS data).
pub fn compute(evt: &Event) -> Option<Fingerprint> {
    let http = evt.http();
    let tls = tls_of(evt);
    let tls_id = tls
        .and_then(|t| t.ja4.as_deref().or(t.ja3.as_deref()))
        .filter(|s| !s.is_empty())
        .map(|j| hash_id('t', &[j]));
    let device = http.and_then(|h| device_id(h, tls));
    let visitor = http
        .and_then(|h| h.cookies.as_ref())
        .and_then(|c| c.get(VISITOR_COOKIE))
        .filter(|v| valid_visitor(v))
        .map(|v| format!("v-{}", v.to_ascii_lowercase()));
    let fp = Fingerprint {
        device,
        tls: tls_id,
        visitor,
        client: None,
    };
    (!fp.is_empty()).then_some(fp)
}

#[derive(Debug)]
struct Entry {
    first: Instant,
    last: Instant,
    requests: u64,
    /// ip → (last seen, flagged High/Critical).
    ips: HashMap<IpAddr, (Instant, bool)>,
}

impl Entry {
    fn new(now: Instant) -> Self {
        Self {
            first: now,
            last: now,
            requests: 0,
            ips: HashMap::new(),
        }
    }

    fn trim(&mut self, now: Instant, window: Duration) {
        self.ips
            .retain(|_, (at, _)| now.duration_since(*at) < window);
        while self.ips.len() > MAX_IPS_PER_ID {
            let Some(oldest) = self
                .ips
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(ip, _)| *ip)
            else {
                break;
            };
            self.ips.remove(&oldest);
        }
    }

    /// `(flagged, total)` over IPs other than `ip` within the window.
    fn others(&self, ip: IpAddr, now: Instant, window: Duration) -> (usize, usize) {
        let mut flagged = 0;
        let mut total = 0;
        for (other, (at, bad)) in &self.ips {
            if *other == ip || now.duration_since(*at) >= window {
                continue;
            }
            total += 1;
            if *bad {
                flagged += 1;
            }
        }
        (flagged, total)
    }
}

/// Population stats of one id, for CLI/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdStats {
    /// Requests observed under the id (process lifetime).
    pub requests: u64,
    /// Distinct IPs inside the window.
    pub distinct_ips: usize,
    /// Distinct IPs flagged High/Critical inside the window.
    pub flagged_ips: usize,
    /// Seconds since first seen.
    pub age_secs: u64,
}

/// Sliding-window tracker behind the fingerprint signals.
#[derive(Debug)]
pub struct FingerprintTracker {
    window: Duration,
    reputation_ips: usize,
    visitor_devices: usize,
    auto_ban_ips: usize,
    max_entries: usize,
    entries: HashMap<String, Entry>,
    /// visitor id → device id → last seen.
    visitors: HashMap<String, HashMap<String, Instant>>,
    last_sweep: Instant,
}

impl FingerprintTracker {
    /// Build from `[fingerprint]`.
    pub fn from_config(cfg: &FingerprintConfig) -> Self {
        Self {
            window: Duration::from_secs(cfg.window_secs.max(1)),
            reputation_ips: cfg.reputation_ips as usize,
            visitor_devices: cfg.visitor_devices as usize,
            auto_ban_ips: cfg.auto_ban_ips as usize,
            max_entries: cfg.max_entries.max(1),
            entries: HashMap::new(),
            visitors: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Number of tracked ids.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No tracked ids.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a request and return the signals it raises.
    pub fn observe(&mut self, fp: &Fingerprint, ip: IpAddr, now: Instant) -> Vec<Signal> {
        self.maybe_sweep(now);
        let mut signals = Vec::new();
        let window = self.window;
        let mut reputation_hit = false;
        for id in fp.ids() {
            if !self.entries.contains_key(id) && self.entries.len() >= self.max_entries {
                self.sweep(now);
                if self.entries.len() >= self.max_entries {
                    self.evict_oldest();
                }
            }
            let entry = self
                .entries
                .entry(id.to_string())
                .or_insert_with(|| Entry::new(now));
            entry.last = now;
            entry.requests += 1;
            let flagged = entry.ips.get(&ip).is_some_and(|(_, bad)| *bad);
            entry.ips.insert(ip, (now, flagged));
            entry.trim(now, window);
            if self.reputation_ips > 0 && !reputation_hit {
                let (bad, total) = entry.others(ip, now, window);
                if bad >= self.reputation_ips && bad * 100 >= total * REPUTATION_MIN_RATIO_PCT {
                    reputation_hit = true;
                    signals.push(Signal {
                        kind: SignalKind::FingerprintReputation,
                        weight: FINGERPRINT_REPUTATION_WEIGHT,
                        detail: Some(format!(
                            "{id}: {bad}/{total} other IPs flagged within {}s",
                            window.as_secs()
                        )),
                    });
                }
            }
        }
        if let (Some(visitor), Some(device)) = (&fp.visitor, &fp.device) {
            if self.visitor_devices > 0 {
                if !self.visitors.contains_key(visitor) && self.visitors.len() >= self.max_entries {
                    self.visitors.retain(|_, d| !d.is_empty());
                    if self.visitors.len() >= self.max_entries {
                        if let Some(k) = self.visitors.keys().next().cloned() {
                            self.visitors.remove(&k);
                        }
                    }
                }
                let devices = self.visitors.entry(visitor.clone()).or_default();
                devices.insert(device.clone(), now);
                devices.retain(|_, at| now.duration_since(*at) < window);
                while devices.len() > MAX_DEVICES_PER_VISITOR {
                    let Some(oldest) = devices
                        .iter()
                        .min_by_key(|(_, at)| **at)
                        .map(|(d, _)| d.clone())
                    else {
                        break;
                    };
                    devices.remove(&oldest);
                }
                if devices.len() >= self.visitor_devices {
                    signals.push(Signal {
                        kind: SignalKind::VisitorDeviceChurn,
                        weight: VISITOR_DEVICE_CHURN_WEIGHT,
                        detail: Some(format!(
                            "{visitor}: {} distinct devices within {}s",
                            devices.len(),
                            window.as_secs()
                        )),
                    });
                }
            }
        }
        signals
    }

    /// Mark `ip` as flagged (High/Critical outcome) under every id of `fp`.
    /// Returns the ids that now qualify for an automatic ban.
    pub fn flag(&mut self, fp: &Fingerprint, ip: IpAddr, now: Instant) -> Vec<String> {
        let mut ban = Vec::new();
        let window = self.window;
        for id in fp.ids() {
            let Some(entry) = self.entries.get_mut(id) else {
                continue;
            };
            entry.ips.insert(ip, (now, true));
            if self.auto_ban_ips > 0 {
                let (mut bad, mut total) = entry.others(ip, now, window);
                bad += 1;
                total += 1;
                if bad >= self.auto_ban_ips && bad * 100 >= total * REPUTATION_MIN_RATIO_PCT {
                    ban.push(id.to_string());
                }
            }
        }
        ban
    }

    /// Population stats of `id` inside the window.
    pub fn stats(&self, id: &str, now: Instant) -> Option<IdStats> {
        let e = self.entries.get(id)?;
        let live: Vec<_> = e
            .ips
            .values()
            .filter(|(at, _)| now.duration_since(*at) < self.window)
            .collect();
        Some(IdStats {
            requests: e.requests,
            distinct_ips: live.len(),
            flagged_ips: live.iter().filter(|(_, bad)| *bad).count(),
            age_secs: now.duration_since(e.first).as_secs(),
        })
    }

    fn maybe_sweep(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) >= SWEEP_EVERY {
            self.sweep(now);
        }
    }

    /// Drop ids idle beyond the window.
    pub fn sweep(&mut self, now: Instant) {
        self.last_sweep = now;
        let window = self.window;
        self.entries
            .retain(|_, e| now.duration_since(e.last) < window);
        self.visitors.retain(|_, devices| {
            devices.retain(|_, at| now.duration_since(*at) < window);
            !devices.is_empty()
        });
    }

    /// Daemon prune hook.
    pub fn prune(&mut self) {
        self.sweep(Instant::now());
    }

    fn evict_oldest(&mut self) {
        let drop = (self.max_entries / 10).max(1);
        let mut by_age: Vec<_> = self
            .entries
            .iter()
            .map(|(k, e)| (e.last, k.clone()))
            .collect();
        by_age.sort();
        for (_, k) in by_age.into_iter().take(drop) {
            self.entries.remove(&k);
        }
    }
}

/// Shared in-memory fingerprint ban list with optional per-id expiry.
///
/// Ids are normalized to lowercase. Two tiers: *persistent* bans mirror the
/// `fingerprint_bans` table (written by `sentry fingerprint ban`, pre-warmed
/// and hot-reloaded by the daemon) and *automatic* bans, which live only in
/// memory and survive a table reload. Readers: the pipeline, before any
/// detector runs.
#[derive(Debug, Default)]
pub struct FingerprintBans {
    inner: RwLock<BanMaps>,
}

#[derive(Debug, Default)]
struct BanMaps {
    persistent: HashMap<String, Option<Instant>>,
    auto: HashMap<String, Instant>,
}

impl FingerprintBans {
    /// Empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ban `id` until `expires_at` (`None` = permanent).
    pub fn ban(&self, id: &str, expires_at: Option<Instant>) {
        self.inner
            .write()
            .unwrap()
            .persistent
            .insert(id.to_ascii_lowercase(), expires_at);
    }

    /// Automatic, memory-only ban expiring at `expires_at`.
    pub fn ban_auto(&self, id: &str, expires_at: Instant) {
        self.inner
            .write()
            .unwrap()
            .auto
            .insert(id.to_ascii_lowercase(), expires_at);
    }

    /// Lift a ban (either tier); whether it existed.
    pub fn unban(&self, id: &str) -> bool {
        let id = id.to_ascii_lowercase();
        let mut inner = self.inner.write().unwrap();
        let a = inner.persistent.remove(&id).is_some();
        let b = inner.auto.remove(&id).is_some();
        a || b
    }

    /// The banned id among `fp`'s ids, if any (expired entries ignored).
    pub fn banned(&self, fp: &Fingerprint) -> Option<String> {
        let inner = self.inner.read().unwrap();
        if inner.persistent.is_empty() && inner.auto.is_empty() {
            return None;
        }
        let now = Instant::now();
        fp.ids()
            .find(|id| {
                let key = id.to_ascii_lowercase();
                match inner.persistent.get(&key) {
                    Some(None) => return true,
                    Some(Some(exp)) if *exp > now => return true,
                    _ => {}
                }
                inner.auto.get(&key).is_some_and(|exp| *exp > now)
            })
            .map(str::to_string)
    }

    /// Seed a persistent entry without weakening an existing one.
    pub fn seed(&self, id: &str, expires_at: Option<Instant>) {
        let id = id.to_ascii_lowercase();
        let mut inner = self.inner.write().unwrap();
        let keep = match (inner.persistent.get(&id), expires_at) {
            (Some(None), _) => return,
            (Some(Some(old)), Some(new)) if *old >= new => return,
            _ => expires_at,
        };
        inner.persistent.insert(id, keep);
    }

    /// Replace the persistent tier with `entries` (hot-reload from the DB);
    /// automatic bans are untouched.
    pub fn reload<I: IntoIterator<Item = (String, Option<Instant>)>>(&self, entries: I) {
        let mut inner = self.inner.write().unwrap();
        inner.persistent.clear();
        inner.persistent.extend(
            entries
                .into_iter()
                .map(|(id, exp)| (id.to_ascii_lowercase(), exp)),
        );
    }

    /// Drop expired entries from both tiers.
    pub fn prune(&self) -> usize {
        let now = Instant::now();
        let mut inner = self.inner.write().unwrap();
        let before = inner.persistent.len() + inner.auto.len();
        inner
            .persistent
            .retain(|_, exp| exp.map_or(true, |e| e > now));
        inner.auto.retain(|_, exp| *exp > now);
        before - inner.persistent.len() - inner.auto.len()
    }

    /// Entries held (both tiers).
    pub fn len(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.persistent.len() + inner.auto.len()
    }

    /// No entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpMethod, ProtocolData, SourceKind};

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, n])
    }

    fn http_evt(ua: &str, ja4: Option<&str>, cookie: Option<&str>) -> Event {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), ua.to_string());
        headers.insert("accept-language".to_string(), "en-US".to_string());
        let data = HttpData {
            method: Some(HttpMethod::Get),
            path: "/".into(),
            user_agent: Some(ua.to_string()),
            headers,
            cookies: cookie.map(|c| HashMap::from([(VISITOR_COOKIE.to_string(), c.to_string())])),
            tls: ja4.map(|j| {
                Box::new(TlsData {
                    ja4: Some(j.to_string()),
                    alpn: Some("h2".into()),
                    ..Default::default()
                })
            }),
            ..Default::default()
        };
        Event::new(SourceKind::HttpProxy, ip(1), ProtocolData::Http(data))
    }

    #[test]
    fn same_client_same_ids_regardless_of_ip_and_path() {
        let mut a = http_evt("Chrome/120", Some("t13d1516h2_x"), None);
        let b = http_evt("Chrome/120", Some("t13d1516h2_x"), None);
        a.client_ip = ip(9);
        a.http_mut().unwrap().path = "/other.png".into();
        assert_eq!(compute(&a), compute(&b));
        assert!(compute(&a).unwrap().tls.is_some());
    }

    #[test]
    fn ua_or_tls_change_changes_device_but_tls_id_stays() {
        let a = compute(&http_evt("Chrome/120", Some("j"), None)).unwrap();
        let b = compute(&http_evt("curl/8", Some("j"), None)).unwrap();
        assert_ne!(a.device, b.device);
        assert_eq!(a.tls, b.tls);
        let c = compute(&http_evt("Chrome/120", Some("other"), None)).unwrap();
        assert_ne!(a.device, c.device);
        assert_ne!(a.tls, c.tls);
    }

    #[test]
    fn visitor_cookie_validated() {
        let good = "0123456789abcdef0123456789ABCDEF";
        let fp = compute(&http_evt("x", None, Some(good))).unwrap();
        assert_eq!(
            fp.visitor.as_deref(),
            Some(&*format!("v-{}", good.to_lowercase()))
        );
        let bad = compute(&http_evt("x", None, Some("not-a-visitor"))).unwrap();
        assert!(bad.visitor.is_none());
    }

    #[test]
    fn nothing_to_fingerprint_is_none() {
        let data = HttpData::default();
        let evt = Event::new(SourceKind::HttpProxy, ip(1), ProtocolData::Http(data));
        assert!(compute(&evt).is_none());
    }

    #[test]
    fn matches_is_case_insensitive_over_all_ids() {
        let fp = compute(&http_evt("x", Some("j"), None)).unwrap();
        let d = fp.device.clone().unwrap();
        assert!(fp.matches(&d.to_ascii_uppercase()));
        assert!(!fp.matches("d-0000000000000000"));
    }

    fn cfg() -> FingerprintConfig {
        FingerprintConfig {
            reputation_ips: 3,
            visitor_devices: 3,
            auto_ban_ips: 4,
            ..Default::default()
        }
    }

    fn fp_of(id: &str) -> Fingerprint {
        Fingerprint {
            device: Some(id.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn reputation_needs_flagged_majority_of_other_ips() {
        let mut t = FingerprintTracker::from_config(&cfg());
        let fp = fp_of("d-botfarm");
        let now = Instant::now();
        for n in 1..=3 {
            assert!(t.observe(&fp, ip(n), now).is_empty());
            t.flag(&fp, ip(n), now);
        }
        let sigs = t.observe(&fp, ip(50), now);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::FingerprintReputation);
    }

    #[test]
    fn popular_benign_id_never_earns_reputation() {
        let mut t = FingerprintTracker::from_config(&cfg());
        let fp = fp_of("d-chrome");
        let now = Instant::now();
        for n in 1..=100u8 {
            assert!(t.observe(&fp, ip(n), now).is_empty());
        }
        for n in 1..=3u8 {
            t.flag(&fp, ip(n), now);
        }
        assert!(t.observe(&fp, ip(200), now).is_empty());
    }

    #[test]
    fn flagged_ips_outside_window_are_forgotten() {
        let mut t = FingerprintTracker::from_config(&cfg());
        let fp = fp_of("d-old");
        let t0 = Instant::now();
        for n in 1..=3 {
            t.observe(&fp, ip(n), t0);
            t.flag(&fp, ip(n), t0);
        }
        let later = t0 + Duration::from_secs(7200);
        assert!(t.observe(&fp, ip(50), later).is_empty());
    }

    #[test]
    fn auto_ban_requires_threshold_and_majority() {
        let mut t = FingerprintTracker::from_config(&cfg());
        let fp = fp_of("d-farm");
        let now = Instant::now();
        let mut banned = Vec::new();
        for n in 1..=4 {
            t.observe(&fp, ip(n), now);
            banned = t.flag(&fp, ip(n), now);
        }
        assert_eq!(banned, vec!["d-farm".to_string()]);
    }

    #[test]
    fn visitor_with_many_devices_raises_churn() {
        let mut t = FingerprintTracker::from_config(&cfg());
        let now = Instant::now();
        let mut last = Vec::new();
        for n in 0..3 {
            let fp = Fingerprint {
                device: Some(format!("d-{n}")),
                visitor: Some("v-abc".into()),
                ..Default::default()
            };
            last = t.observe(&fp, ip(1), now);
        }
        assert!(last
            .iter()
            .any(|s| s.kind == SignalKind::VisitorDeviceChurn));
    }

    #[test]
    fn disabled_thresholds_emit_nothing() {
        let mut t = FingerprintTracker::from_config(&FingerprintConfig {
            reputation_ips: 0,
            visitor_devices: 0,
            ..Default::default()
        });
        let now = Instant::now();
        for n in 1..=10 {
            let fp = Fingerprint {
                device: Some(format!("d-{n}")),
                visitor: Some("v-abc".into()),
                ..Default::default()
            };
            assert!(t.observe(&fp, ip(n), now).is_empty());
            t.flag(&fp, ip(n), now);
        }
    }

    #[test]
    fn max_entries_evicts() {
        let mut t = FingerprintTracker::from_config(&FingerprintConfig {
            max_entries: 10,
            ..Default::default()
        });
        let now = Instant::now();
        for n in 0..50 {
            t.observe(&fp_of(&format!("d-{n}")), ip(1), now);
        }
        assert!(t.len() <= 10);
    }

    #[test]
    fn bans_match_any_id_and_expire() {
        let bans = FingerprintBans::new();
        let fp = Fingerprint {
            device: Some("d-aaaa".into()),
            tls: Some("t-bbbb".into()),
            visitor: None,
            client: None,
        };
        assert!(bans.banned(&fp).is_none());
        bans.ban("T-BBBB", None);
        assert_eq!(bans.banned(&fp).as_deref(), Some("t-bbbb"));
        assert!(bans.unban("t-bbbb"));
        bans.ban("d-aaaa", Some(Instant::now() - Duration::from_secs(1)));
        assert!(bans.banned(&fp).is_none());
        assert_eq!(bans.prune(), 1);
    }

    #[test]
    fn seed_keeps_stronger_entry() {
        let bans = FingerprintBans::new();
        bans.ban("d-x", None);
        bans.seed("d-x", Some(Instant::now() + Duration::from_secs(5)));
        let fp = fp_of("d-x");
        assert!(bans.banned(&fp).is_some());
        assert_eq!(bans.len(), 1);
    }

    #[test]
    fn reload_keeps_automatic_bans() {
        let bans = FingerprintBans::new();
        bans.ban("d-manual", None);
        bans.ban_auto("d-auto", Instant::now() + Duration::from_secs(60));
        bans.reload(Vec::new());
        assert!(bans.banned(&fp_of("d-manual")).is_none());
        assert!(bans.banned(&fp_of("d-auto")).is_some());
        assert!(bans.unban("d-auto"));
    }

    #[test]
    fn set_cookie_shape() {
        let c = visitor_set_cookie("abc", 60, true);
        assert!(c.starts_with("sentry_vid=abc;"));
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Lax") && c.ends_with("Secure"));
        assert!(!visitor_set_cookie("abc", 60, false).contains("Secure"));
        assert!(valid_visitor(&new_visitor_id()));
    }
}
