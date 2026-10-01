//! rDNS forward-confirmed bot verification (F7.7).
//!
//! Verifies crawlers that *claim* to be search-engine bots using the method
//! the engines themselves recommend: reverse-DNS the client IP, require the
//! hostname to belong to the engine's verified domain, then forward-resolve
//! that hostname and require the original IP among the answers — which
//! defeats PTR spoofing. A User-Agent alone is trivially faked; verified
//! results are cached per IP with a TTL so DNS happens once per window.
//!
//! The core stays I/O-free: DNS is injected through [`BotDnsResolver`] (the
//! daemon wires a real async resolver), the cache is in-memory, and the
//! full flow is orchestrated by [`verify_with`]. Cache misses mark the
//! event [`BotStatus::Unknown`] and queue the IP in [`BotVerifier::take_pending`]
//! for a background worker — the hot path never blocks on DNS.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::event::Event;

/// Search engines with publicly verifiable crawler networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BotEngine {
    /// Googlebot (googlebot.com / google.com).
    Google,
    /// Bingbot (search.msn.com).
    Bing,
    /// Yahoo! Slurp (yahoo.com).
    Yahoo,
    /// Baiduspider (crawl.baidu.com).
    Baidu,
    /// YandexBot (yandex.com / yandex.net / yandex.ru).
    Yandex,
}

impl BotEngine {
    /// Every engine, in DSL display order.
    pub fn all() -> &'static [Self] {
        &[
            Self::Google,
            Self::Bing,
            Self::Yahoo,
            Self::Baidu,
            Self::Yandex,
        ]
    }

    /// Lowercase stable name (config, DSL, metrics labels).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Bing => "bing",
            Self::Yahoo => "yahoo",
            Self::Baidu => "baidu",
            Self::Yandex => "yandex",
        }
    }

    /// Parse from a config/DSL name.
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.trim().to_ascii_lowercase();
        Self::all().iter().find(|e| e.as_str() == lower).copied()
    }

    /// UA substring a request must contain to claim this engine's crawler.
    pub fn ua_pattern(self) -> &'static str {
        match self {
            Self::Google => "Googlebot",
            Self::Bing => "bingbot",
            Self::Yahoo => "Slurp",
            Self::Baidu => "Baiduspider",
            Self::Yandex => "YandexBot",
        }
    }

    /// Hostname suffixes a genuine crawler's PTR record must end with.
    pub fn rdns_domains(self) -> &'static [&'static str] {
        match self {
            Self::Google => &["googlebot.com", "google.com"],
            Self::Bing => &["search.msn.com"],
            Self::Yahoo => &["yahoo.com"],
            Self::Baidu => &["crawl.baidu.com"],
            Self::Yandex => &["yandex.com", "yandex.net", "yandex.ru"],
        }
    }
}

/// Which crawler does the User-Agent claim to be? Claims are cheap and
/// spoofable — this only decides *whether* to verify, never grants trust.
pub fn claimed_engine(user_agent: Option<&str>) -> Option<BotEngine> {
    let ua = user_agent?;
    BotEngine::all()
        .iter()
        .find(|e| {
            ua.as_bytes()
                .windows(e.ua_pattern().len())
                .any(|w| w.eq_ignore_ascii_case(e.ua_pattern().as_bytes()))
        })
        .copied()
}

/// Verification outcome for one client IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BotStatus {
    /// PTR + forward-confirm succeeded for this engine.
    Verified(BotEngine),
    /// UA claims a bot but verification failed (spoofed or hijacked IP).
    Spoofed,
    /// Claimed bot, verification still pending / DNS unavailable.
    Unknown,
}

impl BotStatus {
    /// Whether the status satisfies a `bot_verified` DSL value:
    /// `true`/`verified` (any engine), `false`/`spoofed`, or an engine name
    /// (`google`, …). `Unknown` only ever fails `true` — pending never
    /// grants the allowlist bypass.
    pub fn matches_condition(&self, want: &str) -> bool {
        let lower = want.trim().to_ascii_lowercase();
        match lower.as_str() {
            "true" | "verified" | "yes" => matches!(self, Self::Verified(_)),
            "false" | "spoofed" | "no" => matches!(self, Self::Spoofed),
            engine => matches!(self, Self::Verified(e) if e.as_str() == engine),
        }
    }
}

/// Whether a PTR hostname belongs to the engine's verified domains
/// (case-insensitive suffix match on a label boundary).
pub fn hostname_matches(engine: BotEngine, hostname: &str) -> bool {
    let host = hostname.trim_end_matches('.').to_ascii_lowercase();
    engine
        .rdns_domains()
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

/// DNS query outcome. Errors are distinct from empty answers: a resolver
/// outage must never mark a genuine crawler as spoofed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOutcome<T> {
    /// The query succeeded (possibly with zero records).
    Records(Vec<T>),
    /// The query failed (network, timeout, SERVFAIL…).
    Error,
}

impl<T> DnsOutcome<T> {
    /// Records when the query succeeded, empty on error.
    pub fn records(self) -> Vec<T> {
        match self {
            Self::Records(v) => v,
            Self::Error => Vec::new(),
        }
    }
}

/// DNS lookups needed for verification. Implemented by the daemon with a
/// real resolver; tests use mocks.
#[async_trait]
pub trait BotDnsResolver: Send + Sync {
    /// Reverse-DNS hostnames for `ip` (PTR records).
    async fn ptr(&self, ip: IpAddr) -> DnsOutcome<String>;
    /// Forward A/AAAA records for `host`.
    async fn a(&self, host: String) -> DnsOutcome<IpAddr>;
}

/// Whether the forward resolution of a verified PTR hostname covers the
/// client IP (the anti-spoofing half of the check).
pub fn forward_confirms(ip: IpAddr, resolved: &[IpAddr]) -> bool {
    resolved.contains(&ip)
}

/// Full verification flow against a resolver: PTR → domain match → forward
/// confirm. Pure orchestration; all I/O goes through the trait. DNS errors
/// yield [`BotStatus::Unknown`] (retry later) instead of a spoofed verdict.
pub async fn verify_with(engine: BotEngine, ip: IpAddr, dns: &dyn BotDnsResolver) -> BotStatus {
    let DnsOutcome::Records(ptrs) = dns.ptr(ip).await else {
        return BotStatus::Unknown;
    };
    let Some(host) = ptrs.iter().find(|h| hostname_matches(engine, h)) else {
        return BotStatus::Spoofed;
    };
    let DnsOutcome::Records(resolved) = dns.a(host.clone()).await else {
        return BotStatus::Unknown;
    };
    if forward_confirms(ip, &resolved) {
        BotStatus::Verified(engine)
    } else {
        BotStatus::Spoofed
    }
}

/// Cache entry: status + insertion instant (TTL checked on read).
type Entry = (BotStatus, Instant);

/// In-memory verification cache shared between the pipeline (sync reads),
/// the edge (challenge bypass) and the daemon's background verifier.
pub struct BotVerifier {
    entries: RwLock<HashMap<IpAddr, Entry>>,
    /// (ip, claimed engine) pairs awaiting DNS; drained by the daemon task.
    pending: Mutex<Vec<(IpAddr, BotEngine)>>,
    verified_ttl: Duration,
    failed_ttl: Duration,
}

/// Shared handle.
pub type SharedBotVerifier = Arc<BotVerifier>;

impl BotVerifier {
    /// Create a cache with the given TTLs for verified and failed results.
    pub fn new(verified_ttl: Duration, failed_ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
            verified_ttl,
            failed_ttl,
        }
    }

    /// TTLs from config (`cache_ttl_secs` / `failed_ttl_secs`).
    pub fn from_config(cfg: &crate::config::BotVerificationConfig) -> Self {
        Self::new(
            Duration::from_secs(cfg.cache_ttl_secs),
            Duration::from_secs(cfg.failed_ttl_secs),
        )
    }

    /// Cached status for `ip`, honouring per-status TTLs.
    pub fn get(&self, ip: IpAddr) -> Option<BotStatus> {
        let now = Instant::now();
        let mut entries = self.entries.write().unwrap();
        match entries.get(&ip) {
            Some((status, at)) if now.duration_since(*at) < self.ttl_for(status) => Some(*status),
            Some(_) => {
                entries.remove(&ip);
                None
            }
            None => None,
        }
    }

    /// Store a verification result.
    pub fn insert(&self, ip: IpAddr, status: BotStatus) {
        self.entries
            .write()
            .unwrap()
            .insert(ip, (status, Instant::now()));
    }

    /// Number of cached entries (verified + failed, unexpired or not).
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// Set `evt.bot` from the cache; on a miss mark [`BotStatus::Unknown`]
    /// and queue the (ip, engine) claim for background verification. The
    /// hot path never awaits DNS.
    pub fn annotate(&self, evt: &mut Event) {
        let claimed = evt
            .http()
            .and_then(|h| claimed_engine(h.user_agent.as_deref()));
        let Some(engine) = claimed else {
            return;
        };
        match self.get(evt.client_ip) {
            Some(status) => evt.bot = Some(status),
            None => {
                evt.bot = Some(BotStatus::Unknown);
                self.request(evt.client_ip, engine);
            }
        }
    }

    /// Queue a claim for background verification (deduped against the cache
    /// and anything already queued).
    pub fn request(&self, ip: IpAddr, engine: BotEngine) {
        if self.get(ip).is_some() {
            return;
        }
        let mut pending = self.pending.lock().unwrap();
        if pending.iter().any(|(p, _)| *p == ip) {
            return;
        }
        pending.push((ip, engine));
    }

    /// Drain up to `max` queued claims for the background worker.
    pub fn take_pending(&self, max: usize) -> Vec<(IpAddr, BotEngine)> {
        let mut pending = self.pending.lock().unwrap();
        let take = pending.len().min(max);
        pending.drain(..take).collect()
    }

    /// Drop expired entries (daemon prune task).
    pub fn prune(&self) {
        let now = Instant::now();
        self.entries
            .write()
            .unwrap()
            .retain(|_, (status, at)| now.duration_since(*at) < self.ttl_for(status));
    }

    fn ttl_for(&self, status: &BotStatus) -> Duration {
        match status {
            BotStatus::Verified(_) => self.verified_ttl,
            _ => self.failed_ttl,
        }
    }
}

/// Default weight for [`crate::analysis::SignalKind::SpoofedBot`]: claims a
/// verified-engine UA without the rDNS to back it (High → Challenge).
pub const SPOOFED_BOT_WEIGHT: u8 = 35;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpData, ProtocolData, SourceKind};
    use std::net::Ipv4Addr;

    fn evt_with_ua(ua: Option<&str>) -> Event {
        Event::new(
            SourceKind::Synthetic,
            IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1)),
            ProtocolData::Http(HttpData {
                user_agent: ua.map(str::to_string),
                ..Default::default()
            }),
        )
    }

    struct MockDns {
        ptrs: DnsOutcome<String>,
        forward: DnsOutcome<IpAddr>,
    }

    #[async_trait]
    impl BotDnsResolver for MockDns {
        async fn ptr(&self, _ip: IpAddr) -> DnsOutcome<String> {
            self.ptrs.clone()
        }
        async fn a(&self, _host: String) -> DnsOutcome<IpAddr> {
            self.forward.clone()
        }
    }

    #[test]
    fn claimed_engine_detects_known_uas() {
        assert_eq!(
            claimed_engine(Some(
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            )),
            Some(BotEngine::Google)
        );
        assert_eq!(
            claimed_engine(Some(
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0)"
            )),
            Some(BotEngine::Bing)
        );
        assert_eq!(
            claimed_engine(Some("Mozilla/5.0 (compatible; YandexBot/3.0)")),
            Some(BotEngine::Yandex)
        );
        assert_eq!(
            claimed_engine(Some("Mozilla/5.0 (X11; Linux) Firefox")),
            None
        );
        assert_eq!(claimed_engine(None), None);
    }

    #[test]
    fn hostname_suffix_match_is_case_insensitive_and_dotted() {
        assert!(hostname_matches(
            BotEngine::Google,
            "crawl-66-249-66-1.googlebot.com"
        ));
        assert!(hostname_matches(
            BotEngine::Google,
            "CRAWL-66-249-66-1.GOOGLEBOT.COM."
        ));
        assert!(hostname_matches(
            BotEngine::Bing,
            "msnbot-157-55-39-1.search.msn.com"
        ));
        assert!(hostname_matches(
            BotEngine::Baidu,
            "baiduspider-123-125-71-96.crawl.baidu.com"
        ));
        assert!(!hostname_matches(
            BotEngine::Google,
            "evil.googlebot.com.evil.io"
        ));
        assert!(!hostname_matches(BotEngine::Google, "notgooglebot.com"));
        // The engine's own domain as a bare suffix is fine, a lookalike
        // prefix is not.
        assert!(hostname_matches(BotEngine::Google, "google.com"));
    }

    #[tokio::test]
    async fn verify_with_confirms_genuine_googlebot() {
        let dns = MockDns {
            ptrs: DnsOutcome::Records(vec!["crawl-66-249-66-1.googlebot.com".into()]),
            forward: DnsOutcome::Records(vec![IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1))]),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        assert_eq!(
            verify_with(BotEngine::Google, ip, &dns).await,
            BotStatus::Verified(BotEngine::Google)
        );
    }

    #[tokio::test]
    async fn verify_with_rejects_spoofed_ptr() {
        // PTR claims googlebot but forward resolution disagrees.
        let dns = MockDns {
            ptrs: DnsOutcome::Records(vec!["fake.googlebot.com".into()]),
            forward: DnsOutcome::Records(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        assert_eq!(
            verify_with(BotEngine::Google, ip, &dns).await,
            BotStatus::Spoofed
        );
    }

    #[tokio::test]
    async fn verify_with_rejects_missing_ptr() {
        let dns = MockDns {
            ptrs: DnsOutcome::Records(vec![]),
            forward: DnsOutcome::Records(vec![]),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        assert_eq!(
            verify_with(BotEngine::Google, ip, &dns).await,
            BotStatus::Spoofed
        );
    }

    #[tokio::test]
    async fn dns_outage_yields_unknown_not_spoofed() {
        // A resolver outage must never flag a genuine crawler.
        let dns = MockDns {
            ptrs: DnsOutcome::Error,
            forward: DnsOutcome::Error,
        };
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        assert_eq!(
            verify_with(BotEngine::Google, ip, &dns).await,
            BotStatus::Unknown
        );
    }

    #[test]
    fn bot_status_condition_matches() {
        let verified = BotStatus::Verified(BotEngine::Google);
        assert!(verified.matches_condition("true"));
        assert!(verified.matches_condition("verified"));
        assert!(verified.matches_condition("google"));
        assert!(!verified.matches_condition("bing"));
        assert!(!verified.matches_condition("false"));

        let spoofed = BotStatus::Spoofed;
        assert!(spoofed.matches_condition("false"));
        assert!(spoofed.matches_condition("spoofed"));
        assert!(!spoofed.matches_condition("true"));

        // Pending never grants the bypass.
        assert!(!BotStatus::Unknown.matches_condition("true"));
        assert!(!BotStatus::Unknown.matches_condition("false"));
    }

    #[test]
    fn verifier_annotates_from_cache_and_queues_misses() {
        let verifier = BotVerifier::new(Duration::from_secs(60), Duration::from_secs(30));
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));

        let mut evt = evt_with_ua(Some("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        verifier.annotate(&mut evt);
        assert_eq!(evt.bot, Some(BotStatus::Unknown));

        let pending = verifier.take_pending(10);
        assert_eq!(pending, vec![(ip, BotEngine::Google)]);
        // Deduped while unresolved: re-request still yields one entry.
        verifier.request(ip, BotEngine::Google);
        assert_eq!(verifier.take_pending(10).len(), 1);
        assert!(verifier.take_pending(10).is_empty());

        verifier.insert(ip, BotStatus::Verified(BotEngine::Google));
        let mut evt = evt_with_ua(Some("Googlebot"));
        verifier.annotate(&mut evt);
        assert_eq!(evt.bot, Some(BotStatus::Verified(BotEngine::Google)));
        assert!(verifier.take_pending(10).is_empty());
    }

    #[test]
    fn verifier_ignores_non_bot_and_non_http_events() {
        let verifier = BotVerifier::new(Duration::from_secs(60), Duration::from_secs(30));

        let mut evt = evt_with_ua(Some("Mozilla/5.0"));
        verifier.annotate(&mut evt);
        assert_eq!(evt.bot, None);
        assert!(verifier.take_pending(10).is_empty());

        let mut tcp_evt = Event::new(
            SourceKind::Synthetic,
            IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1)),
            ProtocolData::Tcp(crate::event::TcpData::default()),
        );
        verifier.annotate(&mut tcp_evt);
        assert_eq!(tcp_evt.bot, None);
    }

    #[test]
    fn verifier_ttl_expires_failed_results_first() {
        let verifier = BotVerifier::new(Duration::from_secs(3600), Duration::from_secs(0));
        let ip = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        verifier.insert(ip, BotStatus::Spoofed);
        assert_eq!(verifier.get(ip), None);
        assert!(verifier.is_empty());
    }

    #[test]
    fn verifier_prune_drops_expired_only() {
        let verifier = BotVerifier::new(Duration::from_secs(3600), Duration::from_secs(0));
        let keep = IpAddr::V4(Ipv4Addr::new(66, 249, 66, 1));
        let drop = IpAddr::V4(Ipv4Addr::new(157, 55, 39, 1));
        verifier.insert(keep, BotStatus::Verified(BotEngine::Google));
        verifier.insert(drop, BotStatus::Spoofed);
        verifier.prune();
        assert_eq!(
            verifier.get(keep),
            Some(BotStatus::Verified(BotEngine::Google))
        );
        assert_eq!(verifier.get(drop), None);
    }

    #[test]
    fn engine_round_trips() {
        for engine in BotEngine::all() {
            assert_eq!(BotEngine::parse(engine.as_str()), Some(*engine));
        }
        assert_eq!(BotEngine::parse("bogus"), None);
    }
}
