//! Cross-IP scan→attack correlation (F3.10).
//!
//! Honeypot telemetry keeps showing the same two-step pattern: a host scans
//! the internet from a "clean" IP, and shortly after, exploits or
//! brute-force land from a *different* IP in the same /24, /64 or ASN — the
//! scanner finds the targets, the operator (or a consumer of the published
//! scan data) knocks. See Ken Webster, "There Is No Such Thing as a Benign
//! Internet Scanner".
//!
//! [`CorrelationTracker`] keeps bounded sliding windows of recent scans
//! keyed by network prefix and ASN. When an attack-class signal fires, a
//! scan from a *different* IP in the same prefix or ASN inside the window
//! yields a `SignalKind::ScanAttackCorrelation` hit — an aggravator on top
//! of the attack's own weight, never a detector by itself.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::analysis::SignalKind;
use crate::config::CorrelationConfig;

/// Default weight of the `ScanAttackCorrelation` signal (docs §16).
pub const SCAN_ATTACK_CORRELATION_WEIGHT: u8 = 20;

/// Max remembered scans per prefix and per ASN (bounded memory, F5).
const MAX_ENTRIES_PER_KEY: usize = 64;

#[derive(Debug, Clone)]
struct ScanEntry {
    scanner: IpAddr,
    at: Instant,
    label: &'static str,
}

/// How a scan and an attack were tied together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationScope {
    /// Same /24 (IPv4) or /64 (IPv6).
    Prefix,
    /// Same autonomous system number.
    Asn,
}

/// A scan from a neighboring IP that correlates with the current attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationHit {
    /// IP the correlated scan came from (always ≠ the attacker's IP).
    pub scanner: IpAddr,
    /// Short scan label (`tcp-syn`, `http-404-sweep`, …).
    pub label: &'static str,
    /// Age of the scan observation.
    pub age: Duration,
    /// Whether the tie is by prefix or by ASN.
    pub scope: CorrelationScope,
}

/// Sliding window of recent scans keyed by prefix and ASN.
#[derive(Debug)]
pub struct CorrelationTracker {
    window: Duration,
    by_prefix: HashMap<IpAddr, Vec<ScanEntry>>,
    by_asn: HashMap<u32, Vec<ScanEntry>>,
}

impl CorrelationTracker {
    /// Create from config.
    pub fn from_config(cfg: &CorrelationConfig) -> Self {
        Self::new(cfg.window_secs)
    }

    /// Create with an explicit correlation window in seconds.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            by_prefix: HashMap::new(),
            by_asn: HashMap::new(),
        }
    }

    /// Remember a scan observed from `scanner` (same prefix and ASN keys).
    pub fn record_scan(&mut self, scanner: IpAddr, asn: Option<u32>, label: &'static str) {
        let entry = ScanEntry {
            scanner,
            at: Instant::now(),
            label,
        };
        let prefix = prefix_key(scanner);
        push_capped(self.by_prefix.entry(prefix).or_default(), entry.clone());
        if let Some(asn) = asn {
            push_capped(self.by_asn.entry(asn).or_default(), entry);
        }
    }

    /// Look for a recent scan from a *different* IP in the attacker's
    /// prefix (preferred) or ASN. `None` when nothing correlates.
    pub fn correlate(&self, attacker: IpAddr, asn: Option<u32>) -> Option<CorrelationHit> {
        let now = Instant::now();
        if let Some(entry) =
            self.recent_scan(self.by_prefix.get(&prefix_key(attacker)), attacker, now)
        {
            return Some(hit(entry, now, CorrelationScope::Prefix));
        }
        let entry = self.recent_scan(self.by_asn.get(&asn?), attacker, now)?;
        Some(hit(entry, now, CorrelationScope::Asn))
    }

    /// Drop scans whose window has gone quiet.
    pub fn prune(&mut self) {
        let now = Instant::now();
        fn retain_window<K: std::hash::Hash + Eq>(
            map: &mut HashMap<K, Vec<ScanEntry>>,
            window: Duration,
            now: Instant,
        ) {
            map.retain(|_, entries| {
                entries.retain(|e| now.duration_since(e.at) < window);
                !entries.is_empty()
            });
        }
        retain_window(&mut self.by_prefix, self.window, now);
        retain_window(&mut self.by_asn, self.window, now);
    }

    fn recent_scan<'a>(
        &self,
        entries: Option<&'a Vec<ScanEntry>>,
        attacker: IpAddr,
        now: Instant,
    ) -> Option<&'a ScanEntry> {
        entries?
            .iter()
            .rev()
            .find(|e| e.scanner != attacker && now.duration_since(e.at) < self.window)
    }
}

fn hit(entry: &ScanEntry, now: Instant, scope: CorrelationScope) -> CorrelationHit {
    CorrelationHit {
        scanner: entry.scanner,
        label: entry.label,
        age: now.duration_since(entry.at),
        scope,
    }
}

fn push_capped(entries: &mut Vec<ScanEntry>, entry: ScanEntry) {
    if entries.len() >= MAX_ENTRIES_PER_KEY {
        let overflow = entries.len() - MAX_ENTRIES_PER_KEY + 1;
        entries.drain(..overflow);
    }
    entries.push(entry);
}

/// /24 (IPv4) or /64 (IPv6) network key for an IP.
fn prefix_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & 0xffff_ff00)),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & u128::MAX << 64)),
    }
}

/// Whether `kind` marks the event as recon (recorded for correlation).
pub fn is_scan_signal(kind: SignalKind) -> bool {
    scan_label(kind).is_some()
}

/// Short label for a scan-class signal, `None` when it is not one.
pub fn scan_label(kind: SignalKind) -> Option<&'static str> {
    Some(match kind {
        SignalKind::RandomScan => "http-random-path-scan",
        SignalKind::ScanBehavior => "http-404-sweep",
        SignalKind::TcpScanner => "tcp-syn",
        _ => return None,
    })
}

/// Whether `kind` marks the event as an attack worth correlating against
/// recent recon (exploits, auth attacks, ML/LLM verdicts, sensitive-path
/// probes).
pub fn is_attack_signal(kind: SignalKind) -> bool {
    matches!(
        kind,
        SignalKind::SqlInjection
            | SignalKind::Xss
            | SignalKind::PathTraversal
            | SignalKind::Lfi
            | SignalKind::Log4Shell
            | SignalKind::Rce
            | SignalKind::SensitivePath
            | SignalKind::AuthBruteForce
            | SignalKind::SuspiciousLoginSuccess
            | SignalKind::CredentialStuffing
            | SignalKind::DirectoryBruteForce
            | SignalKind::AnomalousPayload
            | SignalKind::LlmMalicious
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn prefix_correlation_within_window() {
        let mut t = CorrelationTracker::new(900);
        t.record_scan(v4(198, 51, 100, 7), Some(65001), "tcp-syn");
        let hit = t.correlate(v4(198, 51, 100, 99), Some(65001)).unwrap();
        assert_eq!(hit.scanner, v4(198, 51, 100, 7));
        assert_eq!(hit.label, "tcp-syn");
        assert_eq!(hit.scope, CorrelationScope::Prefix);
    }

    #[test]
    fn same_ip_never_self_correlates() {
        let mut t = CorrelationTracker::new(900);
        t.record_scan(v4(198, 51, 100, 7), Some(65001), "tcp-syn");
        assert!(t.correlate(v4(198, 51, 100, 7), Some(65001)).is_none());
    }

    #[test]
    fn different_prefix_without_asn_does_not_correlate() {
        let mut t = CorrelationTracker::new(900);
        t.record_scan(v4(198, 51, 100, 7), None, "http-404-sweep");
        assert!(t.correlate(v4(203, 0, 113, 9), None).is_none());
    }

    #[test]
    fn asn_fallback_across_prefixes() {
        let mut t = CorrelationTracker::new(900);
        t.record_scan(v4(198, 51, 100, 7), Some(65001), "tcp-syn");
        let hit = t.correlate(v4(203, 0, 113, 9), Some(65001)).unwrap();
        assert_eq!(hit.scope, CorrelationScope::Asn);
        assert_eq!(hit.scanner, v4(198, 51, 100, 7));
    }

    #[test]
    fn asn_mismatch_stays_quiet() {
        let mut t = CorrelationTracker::new(900);
        t.record_scan(v4(198, 51, 100, 7), Some(65001), "tcp-syn");
        assert!(t.correlate(v4(203, 0, 113, 9), Some(65002)).is_none());
    }

    #[test]
    fn prefix_match_wins_over_asn() {
        let mut t = CorrelationTracker::new(900);
        t.record_scan(v4(198, 51, 100, 7), Some(65001), "tcp-syn");
        t.record_scan(v4(203, 0, 113, 1), Some(65001), "http-404-sweep");
        let hit = t.correlate(v4(198, 51, 100, 99), Some(65001)).unwrap();
        assert_eq!(hit.scope, CorrelationScope::Prefix);
        assert_eq!(hit.scanner, v4(198, 51, 100, 7));
    }

    #[test]
    fn zero_window_correlates_nothing() {
        let mut t = CorrelationTracker::new(0);
        t.record_scan(v4(198, 51, 100, 7), Some(65001), "tcp-syn");
        assert!(t.correlate(v4(198, 51, 100, 99), Some(65001)).is_none());
    }

    #[test]
    fn ipv6_prefix_is_64() {
        let mut t = CorrelationTracker::new(900);
        let scanner: IpAddr = "2001:db8:a::1".parse().unwrap();
        let attacker: IpAddr = "2001:db8:a::ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:b::1".parse().unwrap();
        t.record_scan(scanner, None, "tcp-syn");
        assert!(t.correlate(attacker, None).is_some());
        assert!(t.correlate(other, None).is_none());
    }

    #[test]
    fn per_key_cap_bounds_memory() {
        let mut t = CorrelationTracker::new(900);
        for i in 0..200u32 {
            let octet = (i % 254 + 1) as u8;
            t.record_scan(v4(198, 51, 100, octet), Some(65001), "tcp-syn");
        }
        let prefix = prefix_key(v4(198, 51, 100, 1));
        assert_eq!(t.by_prefix[&prefix].len(), MAX_ENTRIES_PER_KEY);
        assert_eq!(t.by_asn[&65001].len(), MAX_ENTRIES_PER_KEY);
    }

    #[test]
    fn prune_drops_quiet_keys() {
        let mut t = CorrelationTracker::new(0);
        t.record_scan(v4(198, 51, 100, 7), Some(65001), "tcp-syn");
        t.prune();
        assert!(t.by_prefix.is_empty());
        assert!(t.by_asn.is_empty());
    }

    #[test]
    fn signal_classification() {
        for kind in [
            SignalKind::RandomScan,
            SignalKind::ScanBehavior,
            SignalKind::TcpScanner,
        ] {
            assert!(is_scan_signal(kind));
            assert!(scan_label(kind).is_some());
            assert!(!is_attack_signal(kind));
        }
        for kind in [
            SignalKind::SqlInjection,
            SignalKind::Xss,
            SignalKind::PathTraversal,
            SignalKind::Lfi,
            SignalKind::Log4Shell,
            SignalKind::Rce,
            SignalKind::SensitivePath,
            SignalKind::AuthBruteForce,
            SignalKind::SuspiciousLoginSuccess,
            SignalKind::CredentialStuffing,
            SignalKind::DirectoryBruteForce,
            SignalKind::AnomalousPayload,
            SignalKind::LlmMalicious,
        ] {
            assert!(is_attack_signal(kind));
            assert!(!is_scan_signal(kind));
        }
        for kind in [
            SignalKind::UnknownRoute,
            SignalKind::MethodNotAllowed,
            SignalKind::AbnormalRate,
            SignalKind::SuspiciousUA,
            SignalKind::TorExitNode,
            SignalKind::KnownBadIp,
            SignalKind::VpnProxy,
            SignalKind::BadCrawler,
            SignalKind::RuleHit,
            SignalKind::Custom,
            SignalKind::ScanAttackCorrelation,
            SignalKind::PromiscuousScanner,
        ] {
            assert!(!is_scan_signal(kind));
            assert!(!is_attack_signal(kind));
        }
    }
}
