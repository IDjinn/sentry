//! Per-IP SYN burst coalescing for the capture loop (F5.8).
//!
//! A SYN flood produces one captured segment per packet — any fixed event
//! channel saturates at line rate. Within the aggregation window, all SYNs
//! from the same source IP collapse into a single event carrying the total
//! count and the first fingerprint, so the event rate becomes a function of
//! the number of scanners, not of packets. Non-SYN segments are never
//! aggregated. Pure logic: no pcap dependency, fully unit-testable.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Aggregated SYN burst for one source IP and window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynAggregate {
    /// Total SYNs observed in the window (≥ 1).
    pub count: u32,
    /// Fingerprint of the window's first SYN (others may differ; the first
    /// is the scanner's signature).
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
struct Bucket {
    started: Instant,
    count: u32,
    fingerprint: Option<String>,
}

/// Coalesces SYN observations per source IP.
#[derive(Debug)]
pub struct SynAggregator {
    window: Duration,
    cap: usize,
    buckets: HashMap<IpAddr, Bucket>,
}

impl SynAggregator {
    /// `window` = coalescing horizon per IP (0 disables aggregation —
    /// observe passes everything through); `cap` = max simultaneously
    /// tracked IPs (oldest bucket evicted beyond it).
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            window,
            cap,
            buckets: HashMap::new(),
        }
    }

    /// Whether aggregation is armed.
    pub fn enabled(&self) -> bool {
        self.window > Duration::ZERO
    }

    /// Observe one SYN from `ip`. Returns the aggregate to emit for this
    /// window when it completes — either because the window rolled while
    /// observing (`now` past the bucket start) or because this was the
    /// first SYN of a new bucket after eviction. `None` = absorbed into the
    /// open bucket, wait for [`Self::flush_elapsed`].
    pub fn observe(
        &mut self,
        ip: IpAddr,
        fingerprint: Option<String>,
        now: Instant,
    ) -> Option<(IpAddr, SynAggregate)> {
        if !self.enabled() {
            return Some((
                ip,
                SynAggregate {
                    count: 1,
                    fingerprint,
                },
            ));
        }
        match self.buckets.get_mut(&ip) {
            Some(bucket) if now.duration_since(bucket.started) < self.window => {
                bucket.count += 1;
                if bucket.fingerprint.is_none() {
                    bucket.fingerprint = fingerprint;
                }
                None
            }
            Some(bucket) => {
                let done = SynAggregate {
                    count: std::mem::take(&mut bucket.count),
                    fingerprint: bucket.fingerprint.take(),
                };
                bucket.started = now;
                bucket.count = 1;
                bucket.fingerprint = fingerprint;
                Some((ip, done))
            }
            None => {
                if self.buckets.len() >= self.cap {
                    self.evict_oldest();
                }
                self.buckets.insert(
                    ip,
                    Bucket {
                        started: now,
                        count: 1,
                        fingerprint,
                    },
                );
                None
            }
        }
    }

    /// Emit every bucket whose window has elapsed (drain from the capture
    /// loop on a per-iteration time check). Buckets still inside their
    /// window stay open.
    pub fn flush_elapsed(&mut self, now: Instant) -> Vec<(IpAddr, SynAggregate)> {
        if !self.enabled() {
            return Vec::new();
        }
        let mut done = Vec::new();
        let mut expired: Vec<IpAddr> = self
            .buckets
            .iter()
            .filter(|(_, b)| now.duration_since(b.started) >= self.window)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in expired.drain(..) {
            if let Some(b) = self.buckets.remove(&ip) {
                done.push((
                    ip,
                    SynAggregate {
                        count: b.count,
                        fingerprint: b.fingerprint,
                    },
                ));
            }
        }
        done
    }

    /// Number of currently tracked IPs.
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.started)
            .map(|(ip, _)| *ip);
        if let Some(ip) = oldest {
            self.buckets.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip(o4: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, o4))
    }

    #[test]
    fn disabled_window_passes_every_syn_through() {
        let mut agg = SynAggregator::new(Duration::ZERO, 1024);
        assert!(!agg.enabled());
        let t0 = Instant::now();
        for i in 0..5 {
            let (ip, a) = agg.observe(test_ip(1), Some(format!("fp{i}")), t0).unwrap();
            assert_eq!(ip, test_ip(1));
            assert_eq!(a.count, 1);
            assert_eq!(a.fingerprint.as_deref(), Some(format!("fp{i}").as_str()));
        }
        assert_eq!(agg.tracked(), 0);
    }

    #[test]
    fn burst_collapses_into_one_event_per_window() {
        let mut agg = SynAggregator::new(Duration::from_millis(100), 1024);
        let t0 = Instant::now();
        assert!(agg.observe(test_ip(1), Some("fp".into()), t0).is_none());
        for _ in 0..99 {
            assert!(agg
                .observe(test_ip(1), None, t0 + Duration::from_millis(1))
                .is_none());
        }
        let flushed = agg.flush_elapsed(t0 + Duration::from_millis(101));
        assert_eq!(
            flushed,
            vec![(
                test_ip(1),
                SynAggregate {
                    count: 100,
                    fingerprint: Some("fp".into())
                }
            )]
        );
        assert_eq!(agg.tracked(), 0);
        // Next SYN after the flush starts a fresh bucket.
        assert!(agg
            .observe(test_ip(1), None, t0 + Duration::from_millis(102))
            .is_none());
    }

    #[test]
    fn observing_past_the_window_emits_the_previous_bucket() {
        let mut agg = SynAggregator::new(Duration::from_millis(100), 1024);
        let t0 = Instant::now();
        assert!(agg.observe(test_ip(2), Some("a".into()), t0).is_none());
        assert!(agg
            .observe(test_ip(2), Some("b".into()), t0 + Duration::from_millis(10))
            .is_none());
        // This SYN starts the new window and emits the completed one.
        let (ip, done) = agg
            .observe(
                test_ip(2),
                Some("c".into()),
                t0 + Duration::from_millis(150),
            )
            .unwrap();
        assert_eq!(ip, test_ip(2));
        assert_eq!(
            done,
            SynAggregate {
                count: 2,
                fingerprint: Some("a".into())
            }
        );
        // New bucket holds the third SYN.
        let flushed = agg.flush_elapsed(t0 + Duration::from_millis(251));
        assert_eq!(
            flushed,
            vec![(
                test_ip(2),
                SynAggregate {
                    count: 1,
                    fingerprint: Some("c".into())
                }
            )]
        );
    }

    #[test]
    fn different_ips_are_independent_buckets() {
        let mut agg = SynAggregator::new(Duration::from_millis(100), 1024);
        let t0 = Instant::now();
        assert!(agg.observe(test_ip(3), None, t0).is_none());
        assert!(agg.observe(test_ip(4), None, t0).is_none());
        assert_eq!(agg.tracked(), 2);
        let mut flushed = agg.flush_elapsed(t0 + Duration::from_millis(101));
        flushed.sort_by_key(|(ip, _)| *ip);
        assert_eq!(flushed.len(), 2);
        assert!(flushed.iter().all(|(_, a)| a.count == 1));
    }

    #[test]
    fn cap_evicts_oldest_and_never_grows_unbounded() {
        let mut agg = SynAggregator::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        assert!(agg.observe(test_ip(5), None, t0).is_none());
        assert!(agg
            .observe(test_ip(6), None, t0 + Duration::from_millis(1))
            .is_none());
        // Third IP evicts the oldest (ip5) bucket and opens a new one.
        assert!(agg
            .observe(test_ip(7), None, t0 + Duration::from_millis(2))
            .is_none());
        assert_eq!(agg.tracked(), 2);
        // ip5's bucket was evicted open — observing it again evicts the new
        // oldest (ip6) and starts fresh.
        assert!(agg
            .observe(test_ip(5), None, t0 + Duration::from_millis(3))
            .is_none());
        assert_eq!(agg.tracked(), 2);
        let flushed = agg.flush_elapsed(t0 + Duration::from_secs(61));
        assert_eq!(flushed.len(), 2);
        assert!(flushed.iter().all(|(_, a)| a.count == 1));
    }
}
