//! Behavioral scan detection: per-IP sliding windows over HTTP paths/status.
//!
//! Two detectors share one window per IP, counting only 4xx responses:
//!
//! - **RandomScan** — many *distinct* unknown paths (`/a1b2.php`, `/.env.local`,
//!   `/backup.sql`…) from the same IP. Random-name probing has near-infinite
//!   path cardinality, which no route template can cover, so it is detected
//!   behaviorally instead of being learned as routes (learning it would
//!   silence the `UnknownRoute` signal — an anti-poisoning rule).
//! - **ScanBehavior** — many 4xx responses total from the same IP, same path
//!   or not (generic 404 sweep).
//!
//! Both signals re-fire on every qualifying event, so the repetition bonus
//! and strike escalation keep raising the score/verdict the longer the scan
//! goes on.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::analysis::{Signal, SignalKind};
use crate::config::ScanConfig;

/// Default weight of the `RandomScan` signal (docs §16).
pub const RANDOM_SCAN_WEIGHT: u8 = 25;
/// Default weight of the `ScanBehavior` signal (docs §16).
pub const SCAN_BEHAVIOR_WEIGHT: u8 = 35;

#[derive(Debug, Clone)]
struct PathHit {
    path: String,
    ts: Instant,
}

/// Per-IP sliding window of 4xx path hits.
#[derive(Debug)]
pub struct ScanTracker {
    window: Duration,
    distinct_paths: u32,
    not_found: u32,
    max_hits: usize,
    entries: HashMap<IpAddr, Vec<PathHit>>,
}

impl ScanTracker {
    /// Create from config.
    pub fn from_config(cfg: &ScanConfig) -> Self {
        Self::new(cfg.window_secs, cfg.distinct_paths, cfg.not_found)
    }

    /// Create with explicit thresholds.
    pub fn new(window_secs: u64, distinct_paths: u32, not_found: u32) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            distinct_paths,
            not_found,
            max_hits: 128,
            entries: HashMap::new(),
        }
    }

    /// Record an HTTP observation and return the scan signals it triggered.
    ///
    /// Only 4xx responses are tracked; other statuses return no signal and
    /// leave no state behind.
    pub fn record(&mut self, ip: IpAddr, path: &str, status: Option<u16>) -> Vec<Signal> {
        let is_4xx = status.is_some_and(|s| (400..=499).contains(&s));
        if !is_4xx {
            return Vec::new();
        }
        let now = Instant::now();
        let hits = self.entries.entry(ip).or_default();
        hits.retain(|h| now.duration_since(h.ts) < self.window);
        if hits.len() >= self.max_hits {
            let overflow = hits.len() - self.max_hits + 1;
            hits.drain(..overflow);
        }
        hits.push(PathHit {
            path: path.to_string(),
            ts: now,
        });

        let mut signals = Vec::new();
        let distinct = hits.iter().map(|h| h.path.as_str()).collect::<HashSet<_>>();
        if self.distinct_paths > 0 && distinct.len() as u32 >= self.distinct_paths {
            signals.push(Signal {
                kind: SignalKind::RandomScan,
                weight: RANDOM_SCAN_WEIGHT,
                detail: Some(format!(
                    "{} distinct 4xx paths in {}s",
                    distinct.len(),
                    self.window.as_secs()
                )),
            });
        }
        if self.not_found > 0 && hits.len() as u32 >= self.not_found {
            signals.push(Signal {
                kind: SignalKind::ScanBehavior,
                weight: SCAN_BEHAVIOR_WEIGHT,
                detail: Some(format!(
                    "{} responses 4xx in {}s",
                    hits.len(),
                    self.window.as_secs()
                )),
            });
        }
        signals
    }

    /// Drop IPs whose window has gone quiet.
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, hits| {
            hits.retain(|h| now.duration_since(h.ts) < self.window);
            !hits.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23))
    }

    #[test]
    fn distinct_paths_trigger_random_scan() {
        let mut t = ScanTracker::new(60, 3, 100);
        assert!(t.record(ip(), "/a.php", Some(404)).is_empty());
        assert!(t.record(ip(), "/b.php", Some(404)).is_empty());
        let sigs = t.record(ip(), "/c.php", Some(404));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::RandomScan);
        assert_eq!(sigs[0].weight, 25);
    }

    #[test]
    fn repeated_same_path_does_not_trigger_random_scan() {
        let mut t = ScanTracker::new(60, 3, 1000);
        for _ in 0..10 {
            assert!(t
                .record(ip(), "/same.php", Some(404))
                .iter()
                .all(|s| s.kind != SignalKind::RandomScan));
        }
    }

    #[test]
    fn not_found_count_triggers_scan_behavior() {
        let mut t = ScanTracker::new(60, 1000, 3);
        assert!(t.record(ip(), "/x", Some(404)).is_empty());
        assert!(t.record(ip(), "/x", Some(404)).is_empty());
        let sigs = t.record(ip(), "/x", Some(403));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::ScanBehavior);
        assert_eq!(sigs[0].weight, 35);
    }

    #[test]
    fn success_and_server_errors_are_ignored() {
        let mut t = ScanTracker::new(60, 2, 2);
        assert!(t.record(ip(), "/ok", Some(200)).is_empty());
        assert!(t.record(ip(), "/boom", Some(502)).is_empty());
        assert!(t.record(ip(), "/none", None).is_empty());
        // Nothing was tracked, so a later single 404 starts from zero.
        assert!(t.record(ip(), "/a", Some(404)).is_empty());
    }

    #[test]
    fn zero_window_tracks_nothing() {
        // Each call sees only its own hit (window expired instantly), so
        // distinct paths never accumulate.
        let mut t = ScanTracker::new(0, 2, 2);
        assert!(t.record(ip(), "/a.php", Some(404)).is_empty());
        assert!(t.record(ip(), "/b.php", Some(404)).is_empty());
    }

    #[test]
    fn separate_ips_do_not_share_windows() {
        let mut t = ScanTracker::new(60, 2, 100);
        let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        assert!(t.record(ip(), "/a.php", Some(404)).is_empty());
        assert!(t.record(other, "/b.php", Some(404)).is_empty());
    }

    #[test]
    fn prune_drops_quiet_ips() {
        let mut t = ScanTracker::new(0, 1, 1);
        t.record(ip(), "/a.php", Some(404));
        t.prune();
        assert!(t.entries.is_empty());
    }
}
