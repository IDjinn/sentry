//! Rate-limited logging for drop events.
//!
//! Under a flood, logging one line per dropped event turns the drop itself
//! into a log flood. [`DropLogThrottle`] collapses that: the first drop logs
//! immediately, drops inside the window are counted silently, and the first
//! drop after the window reports the accumulated count so the caller can log
//! an aggregate.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

/// Aggregating throttle for "X dropped" log lines.
#[derive(Debug)]
pub struct DropLogThrottle {
    window: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl DropLogThrottle {
    /// Default aggregation window.
    pub const DEFAULT_WINDOW: Duration = Duration::from_secs(5);

    /// Create a throttle with the default 5s window.
    pub fn new() -> Self {
        Self::with_window(Self::DEFAULT_WINDOW)
    }

    /// Create a throttle with a custom window.
    pub fn with_window(window: Duration) -> Self {
        Self {
            window,
            last: None,
            suppressed: 0,
        }
    }

    /// Record one dropped item. Returns `Some(count)` when a log should be
    /// emitted — `count` is the number of drops since the last emitted log
    /// (1 on the very first drop, so a single drop is still visible).
    pub fn record(&mut self, now: Instant) -> Option<u64> {
        self.suppressed += 1;
        let window_elapsed = self
            .last
            .map_or(true, |last| now.duration_since(last) >= self.window);
        if window_elapsed {
            let count = std::mem::take(&mut self.suppressed);
            self.last = Some(now);
            Some(count)
        } else {
            None
        }
    }
}

impl Default for DropLogThrottle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_drop_logs_immediately() {
        let mut t = DropLogThrottle::new();
        let now = Instant::now();
        assert_eq!(t.record(now), Some(1));
    }

    #[test]
    fn drops_inside_window_are_counted_silently() {
        let mut t = DropLogThrottle::new();
        let now = Instant::now();
        assert_eq!(t.record(now), Some(1));
        for i in 2..=10 {
            assert_eq!(t.record(now + Duration::from_millis(100 * i as u64)), None);
        }
    }

    #[test]
    fn drop_after_window_logs_aggregate() {
        let mut t = DropLogThrottle::new();
        let now = Instant::now();
        assert_eq!(t.record(now), Some(1));
        assert_eq!(t.record(now + Duration::from_secs(1)), None);
        assert_eq!(t.record(now + Duration::from_secs(2)), None);
        let aggregate = t.record(now + DropLogThrottle::DEFAULT_WINDOW);
        assert_eq!(aggregate, Some(3));
    }

    #[test]
    fn custom_window_is_respected() {
        let mut t = DropLogThrottle::with_window(Duration::from_millis(50));
        let now = Instant::now();
        assert_eq!(t.record(now), Some(1));
        assert_eq!(t.record(now + Duration::from_millis(49)), None);
        assert_eq!(t.record(now + Duration::from_millis(50)), Some(2));
    }
}
