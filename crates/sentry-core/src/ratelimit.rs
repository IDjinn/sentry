//! Rate limiting: pluggable backend trait + in-memory sliding-window impl.
//!
//! `RuleMatch::Rate` conditions are stateful — they need a counter per scope
//! key (IP / ASN / path / global). The rules engine calls a
//! [`RateLimitBackend`] during evaluation: each check records one hit and
//! reports whether the configured threshold was exceeded within the window.
//!
//! The default backend is [`InMemoryRateLimiter`] (single-node). A Redis
//! backend for multi-node deployments lives in `sentry-cli` behind the
//! `rate-redis` feature (kept out of the core to keep it I/O-free).

use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// State backend for rate-limit evaluation.
///
/// Implementations must be cheap and non-blocking in the common path — the
/// trait is called from the sync rules evaluator on every event.
pub trait RateLimitBackend: Send + Sync + Debug {
    /// Record one hit for `key` and return `true` when the number of hits in
    /// the last `per_secs` seconds exceeds `limit`.
    fn record_and_check(&self, key: &str, limit: u32, per_secs: u64) -> bool;

    /// Human-readable backend name for logs (`memory`, `redis`).
    fn backend_name(&self) -> &'static str;
}

/// In-memory sliding-window rate limiter (default, single-node).
///
/// Keeps one timestamp deque per scope key. Memory is bounded by
/// `max_keys`; expired timestamps are removed lazily on access and via
/// [`prune`](Self::prune) (the daemon calls it periodically).
#[derive(Debug)]
pub struct InMemoryRateLimiter {
    windows: Mutex<HashMap<String, VecDeque<Instant>>>,
    max_keys: usize,
}

impl Default for InMemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRateLimiter {
    /// Create a limiter with the default key cap (100k).
    pub fn new() -> Self {
        Self::with_max_keys(100_000)
    }

    /// Create a limiter with an explicit key cap.
    pub fn with_max_keys(max_keys: usize) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_keys,
        }
    }

    /// Drop expired timestamps and empty buckets.
    pub fn prune(&self) {
        let mut map = self.windows.lock().unwrap();
        map.retain(|_, dq| {
            if let Some(back) = dq.back() {
                // Keep buckets whose newest hit is still reasonably fresh;
                // the window is at most a day for any sane rule.
                now_within(back, Duration::from_secs(86_400))
            } else {
                false
            }
        });
    }

    /// Number of tracked keys (for metrics/tests).
    pub fn tracked_keys(&self) -> usize {
        self.windows.lock().unwrap().len()
    }
}

fn now_within(ts: &Instant, window: Duration) -> bool {
    ts.elapsed() < window
}

impl RateLimitBackend for InMemoryRateLimiter {
    fn record_and_check(&self, key: &str, limit: u32, per_secs: u64) -> bool {
        let window = Duration::from_secs(per_secs);
        let now = Instant::now();
        let mut map = self.windows.lock().unwrap();

        if !map.contains_key(key) && map.len() >= self.max_keys {
            // Over capacity: drop one arbitrary bucket to make room. This is
            // a safety valve against unbounded growth under IP spoofing; in
            // practice `prune` keeps the map far below the cap.
            if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            }
        }

        let dq = map.entry(key.to_string()).or_default();
        while dq
            .front()
            .map(|ts| !now_within(ts, window))
            .unwrap_or(false)
        {
            dq.pop_front();
        }
        dq.push_back(now);
        dq.len() as u64 > u64::from(limit)
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_limit_does_not_trigger() {
        let rl = InMemoryRateLimiter::new();
        for _ in 0..10 {
            assert!(!rl.record_and_check("ip:1.2.3.4", 10, 60));
        }
    }

    #[test]
    fn over_limit_triggers() {
        let rl = InMemoryRateLimiter::new();
        let mut fired = false;
        for _ in 0..11 {
            fired = rl.record_and_check("ip:1.2.3.4", 10, 60);
        }
        assert!(fired);
    }

    #[test]
    fn window_expiry_resets_count() {
        let rl = InMemoryRateLimiter::new();
        for _ in 0..5 {
            rl.record_and_check("ip:1.2.3.4", 3, 0);
        }
        // Window of 0s: every previous hit is expired, so only the current
        // hit counts — never over a limit of 1... except that 0s window
        // expires instantly, so each call starts fresh at len 1.
        assert!(!rl.record_and_check("ip:1.2.3.4", 1, 0));
    }

    #[test]
    fn keys_are_independent() {
        let rl = InMemoryRateLimiter::new();
        for _ in 0..3 {
            rl.record_and_check("ip:1.1.1.1", 3, 60);
        }
        assert!(!rl.record_and_check("ip:2.2.2.2", 3, 60));
        assert!(rl.record_and_check("ip:1.1.1.1", 3, 60));
    }

    #[test]
    fn prune_keeps_recent_buckets() {
        let rl = InMemoryRateLimiter::new();
        rl.record_and_check("ip:8.8.8.8", 5, 60);
        rl.record_and_check("ip:9.9.9.9", 5, 60);
        rl.prune();
        // Both buckets have fresh hits (< 1 day) — prune keeps them.
        assert_eq!(rl.tracked_keys(), 2);
    }

    #[test]
    fn max_keys_cap_is_enforced() {
        let rl = InMemoryRateLimiter::with_max_keys(2);
        rl.record_and_check("a", 1, 60);
        rl.record_and_check("b", 1, 60);
        rl.record_and_check("c", 1, 60);
        assert!(rl.tracked_keys() <= 2);
    }
}
