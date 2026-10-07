//! Overload response primitives: measured pressure → tiered degradation of
//! telemetry while detection and containment stay full-rate.
//!
//! The daemon measures pressure (queue occupancy, Postgres write latency)
//! into a shared [`OverloadState`]; under pressure, low-priority events
//! (Allow, below High) may be sampled for persistence/eventlog/print via
//! [`sample_by_ip`], repeated benign requests collapse via
//! [`BenignCoalescer`], and the inline edge skips expensive inspection.
//! Events that are security-relevant ([`must_keep`]) are never degraded.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::analysis::{RiskLevel, Verdict};
use crate::event::Event;

/// Shared pressure flag between the monitor task and its consumers (inline
/// edge runtime, ingest loop, AI/LLM forks). Clones share the same state.
#[derive(Clone, Default)]
pub struct OverloadState(Arc<AtomicU8>);

impl OverloadState {
    /// Normal (no pressure).
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
    }

    /// Flip the shared pressure flag.
    pub fn set_pressure(&self, on: bool) {
        self.0.store(u8::from(on), Ordering::Relaxed);
    }

    /// True while the daemon is under measured pressure.
    pub fn under_pressure(&self) -> bool {
        self.0.load(Ordering::Relaxed) == 1
    }
}

/// Whether an event is security-relevant enough to never be sampled, shed
/// or coalesced: any enforcing verdict, or a High/Critical risk level.
pub fn must_keep(verdict: Verdict, level: RiskLevel) -> bool {
    verdict != Verdict::Allow || matches!(level, RiskLevel::High | RiskLevel::Critical)
}

/// A request whose repetition is pure telemetry noise: an Allow verdict
/// with no signals, Info/Low, a GET that did not fail (status < 400 when
/// known) — a health-check ping, a browser refresh, a load-test loop.
pub fn benign_refresh(pe: &crate::pipeline::ProcessedEvent) -> bool {
    if pe.decision.action != Verdict::Allow || !pe.analysis.signals.is_empty() {
        return false;
    }
    if matches!(
        pe.analysis.risk_level,
        RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
    ) {
        return false;
    }
    let Some(http) = pe.event.http() else {
        return false;
    };
    if http.method != Some(crate::event::HttpMethod::Get) {
        return false;
    }
    if http.status.is_some_and(|s| s >= 400) {
        return false;
    }
    CoalesceKey::from_event(&pe.event).is_some()
}

/// Deterministic per-IP sampling: for a given `keep`, an IP is either
/// consistently in or consistently out of the sample (better for forensics
/// than per-event randomness). `keep >= 1.0` keeps everything, `<= 0.0`
/// keeps nothing.
pub fn sample_by_ip(ip: IpAddr, keep: f64) -> bool {
    if keep >= 1.0 {
        return true;
    }
    if keep <= 0.0 {
        return false;
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    (h.finish() % 10_000) as f64 / 10_000.0 < keep
}

/// Telemetry identity of a request for coalescing: source IP, method (as
/// discriminant) and path without query (truncated). Query strings from
/// cache-busting must not defeat the bucket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoalesceKey {
    ip: IpAddr,
    method: Option<u8>,
    path: String,
}

impl CoalesceKey {
    /// Build from an HTTP event; `None` for non-HTTP events (never
    /// coalesced).
    pub fn from_event(evt: &Event) -> Option<Self> {
        let http = evt.http()?;
        Some(Self {
            ip: evt.client_ip,
            method: http.method.map(|m| m as u8),
            path: http
                .path
                .split('?')
                .next()
                .unwrap_or("")
                .chars()
                .take(256)
                .collect(),
        })
    }
}

/// Outcome of admitting one benign request to a coalescing window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coalesced {
    /// First request of the window — telemetry passes through normally.
    First,
    /// Repeat inside the window — telemetry may skip it. Carries the number
    /// of repeats seen so far (1, 2, …).
    Repeat(u64),
}

/// Collapse repeated benign requests per [`CoalesceKey`]: the first hit of
/// each window passes through; repeats are counted and skipped by the
/// telemetry layers only (the pipeline already ran — detection is
/// untouched).
#[derive(Debug)]
pub struct BenignCoalescer {
    window: Duration,
    cap: usize,
    buckets: HashMap<CoalesceKey, (Instant, u64)>,
}

impl BenignCoalescer {
    /// `window` = coalescing horizon per key; `cap` = max tracked buckets
    /// (oldest window start evicted beyond it; 0 disables coalescing).
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            window,
            cap,
            buckets: HashMap::new(),
        }
    }

    /// Admit one request. Time is injected for testability.
    pub fn admit(&mut self, key: CoalesceKey, now: Instant) -> Coalesced {
        if self.cap == 0 {
            return Coalesced::First;
        }
        if let Some((start, count)) = self.buckets.get_mut(&key) {
            if now.duration_since(*start) < self.window {
                *count += 1;
                return Coalesced::Repeat(*count);
            }
            *start = now;
            *count = 0;
            return Coalesced::First;
        }
        if self.buckets.len() >= self.cap {
            self.evict_oldest();
        }
        self.buckets.insert(key, (now, 0));
        Coalesced::First
    }

    /// Number of currently tracked buckets.
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .buckets
            .iter()
            .min_by_key(|(_, (start, _))| *start)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            self.buckets.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpData, HttpMethod, ProtocolData, SourceKind};
    use std::net::Ipv4Addr;

    fn state_value(ip: IpAddr, keep: f64) -> bool {
        sample_by_ip(ip, keep)
    }

    #[test]
    fn pressure_flag_shares_across_clones() {
        let st = OverloadState::new();
        let clone = st.clone();
        assert!(!st.under_pressure());
        st.set_pressure(true);
        assert!(clone.under_pressure());
        st.set_pressure(false);
        assert!(!clone.under_pressure());
    }

    #[test]
    fn must_keep_covers_security_events() {
        assert!(must_keep(Verdict::Block, RiskLevel::Info));
        assert!(must_keep(Verdict::Allow, RiskLevel::Critical));
        assert!(must_keep(Verdict::Challenge, RiskLevel::Low));
        assert!(!must_keep(Verdict::Allow, RiskLevel::Info));
        assert!(!must_keep(Verdict::Allow, RiskLevel::Medium));
    }

    #[test]
    fn sampling_boundaries_and_determinism() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert!(sample_by_ip(ip, 1.0));
        assert!(!sample_by_ip(ip, 0.0));
        assert_eq!(state_value(ip, 0.5), state_value(ip, 0.5));
    }

    #[test]
    fn sampling_fraction_tracks_keep() {
        let total = 10_000u32;
        for keep in [0.1f64, 0.5] {
            let mut kept = 0u32;
            for i in 0..total {
                let ip = IpAddr::V4(Ipv4Addr::new(10, (i >> 8) as u8, i as u8, 1));
                if sample_by_ip(ip, keep) {
                    kept += 1;
                }
            }
            let frac = kept as f64 / total as f64;
            assert!(
                (frac - keep).abs() < 0.1,
                "keep={keep} produced fraction {frac}"
            );
        }
    }

    fn event(method: HttpMethod, path: &str) -> Event {
        Event::new(
            SourceKind::Synthetic,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ProtocolData::Http(HttpData {
                method: Some(method),
                path: path.to_string(),
                ..Default::default()
            }),
        )
    }

    #[test]
    fn coalesce_key_strips_query_and_truncates() {
        let evt = event(HttpMethod::Get, "/health?cachebust=123");
        let key = CoalesceKey::from_event(&evt).unwrap();
        assert_eq!(key.path, "/health");

        let long = "x".repeat(400);
        let evt = event(HttpMethod::Get, &format!("/{long}"));
        let key = CoalesceKey::from_event(&evt).unwrap();
        assert_eq!(key.path.len(), 256);
    }

    #[test]
    fn coalesce_key_is_none_for_non_http() {
        let evt = Event::new(
            SourceKind::Synthetic,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ProtocolData::Raw(Default::default()),
        );
        assert!(CoalesceKey::from_event(&evt).is_none());
    }

    #[test]
    fn first_passes_repeats_inside_window_count() {
        let mut c = BenignCoalescer::new(Duration::from_secs(60), 128);
        let evt = event(HttpMethod::Get, "/");
        let key = CoalesceKey::from_event(&evt).unwrap();
        let t0 = Instant::now();
        assert_eq!(c.admit(key.clone(), t0), Coalesced::First);
        assert_eq!(
            c.admit(key.clone(), t0 + Duration::from_secs(1)),
            Coalesced::Repeat(1)
        );
        assert_eq!(
            c.admit(key.clone(), t0 + Duration::from_secs(2)),
            Coalesced::Repeat(2)
        );
        assert_eq!(c.tracked(), 1);
    }

    #[test]
    fn window_expiry_admits_again() {
        let mut c = BenignCoalescer::new(Duration::from_secs(60), 128);
        let evt = event(HttpMethod::Get, "/");
        let key = CoalesceKey::from_event(&evt).unwrap();
        let t0 = Instant::now();
        assert_eq!(c.admit(key.clone(), t0), Coalesced::First);
        assert_eq!(
            c.admit(key.clone(), t0 + Duration::from_secs(61)),
            Coalesced::First
        );
    }

    #[test]
    fn different_paths_are_different_buckets() {
        let mut c = BenignCoalescer::new(Duration::from_secs(60), 128);
        let t0 = Instant::now();
        let k1 = CoalesceKey::from_event(&event(HttpMethod::Get, "/a")).unwrap();
        let k2 = CoalesceKey::from_event(&event(HttpMethod::Get, "/b")).unwrap();
        assert_eq!(c.admit(k1, t0), Coalesced::First);
        assert_eq!(c.admit(k2, t0), Coalesced::First);
        assert_eq!(c.tracked(), 2);
    }

    #[test]
    fn cap_evicts_oldest_bucket() {
        let mut c = BenignCoalescer::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        let k1 = CoalesceKey::from_event(&event(HttpMethod::Get, "/a")).unwrap();
        let k2 = CoalesceKey::from_event(&event(HttpMethod::Get, "/b")).unwrap();
        let k3 = CoalesceKey::from_event(&event(HttpMethod::Get, "/c")).unwrap();
        assert_eq!(c.admit(k1.clone(), t0), Coalesced::First);
        assert_eq!(
            c.admit(k2.clone(), t0 + Duration::from_millis(1)),
            Coalesced::First
        );
        // k3 arrives at cap: the oldest (k1) is evicted.
        assert_eq!(
            c.admit(k3.clone(), t0 + Duration::from_millis(2)),
            Coalesced::First
        );
        assert_eq!(c.tracked(), 2);
        // k1 re-admits as First — and its admission evicts k2, the new oldest.
        assert_eq!(c.admit(k1, t0 + Duration::from_millis(3)), Coalesced::First);
        // k3 was never evicted and is still inside its window.
        assert_eq!(
            c.admit(k3, t0 + Duration::from_millis(4)),
            Coalesced::Repeat(1)
        );
        assert_eq!(c.tracked(), 2);
    }

    #[test]
    fn zero_cap_disables_coalescing() {
        let mut c = BenignCoalescer::new(Duration::from_secs(60), 0);
        let key = CoalesceKey::from_event(&event(HttpMethod::Get, "/")).unwrap();
        assert_eq!(c.admit(key.clone(), Instant::now()), Coalesced::First);
        assert_eq!(c.admit(key, Instant::now()), Coalesced::First);
        assert_eq!(c.tracked(), 0);
    }

    fn processed(
        method: HttpMethod,
        path: &str,
        status: Option<u16>,
    ) -> crate::pipeline::ProcessedEvent {
        let http = HttpData {
            method: Some(method),
            path: path.to_string(),
            status,
            ..Default::default()
        };
        let evt = Event::new(
            SourceKind::Synthetic,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            ProtocolData::Http(http),
        );
        crate::pipeline::ProcessedEvent {
            event: evt,
            analysis: crate::analysis::AnalysisResult {
                risk_score: 5,
                risk_level: RiskLevel::Info,
                signals: vec![],
                verdict: Verdict::Allow,
            },
            decision: crate::analysis::Decision {
                analysis: crate::analysis::AnalysisResult::default(),
                action: Verdict::Allow,
                override_reason: None,
                log_level: None,
            },
            rule_hit: None,
            process_us: None,
        }
    }

    #[test]
    fn benign_refresh_matches_only_clean_gets() {
        assert!(benign_refresh(&processed(HttpMethod::Get, "/", Some(200))));
        assert!(benign_refresh(&processed(HttpMethod::Get, "/", None)));
        // POSTs, errors and findings are never noise.
        assert!(!benign_refresh(&processed(
            HttpMethod::Post,
            "/",
            Some(200)
        )));
        assert!(!benign_refresh(&processed(
            HttpMethod::Get,
            "/missing",
            Some(404)
        )));
        let mut noisy = processed(HttpMethod::Get, "/", Some(200));
        noisy.analysis.risk_level = RiskLevel::High;
        assert!(!benign_refresh(&noisy));
        let mut blocked = processed(HttpMethod::Get, "/", Some(200));
        blocked.decision.action = Verdict::Block;
        assert!(!benign_refresh(&blocked));
    }
}
