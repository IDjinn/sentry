//! Redis-backed rate limiter (feature `rate-redis`).
//!
//! Shares rate counters across nodes so `RuleMatch::Rate` conditions see a
//! cluster-wide view. Uses fixed-window buckets (`INCR` + `EXPIRE`) instead
//! of the in-memory sliding window — slightly coarser at window boundaries
//! but a single atomic round-trip per check.
//!
//! Note: the call is blocking (the rules evaluator is sync). With a
//! reasonably close Redis this is sub-millisecond; failures fail open
//! (the check passes, no match) and are logged.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sentry_core::ratelimit::RateLimitBackend;
use tracing::warn;

/// Fixed-window rate limiter backed by Redis.
pub struct RedisRateLimiter {
    conn: Mutex<redis::Connection>,
}

impl std::fmt::Debug for RedisRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimiter").finish_non_exhaustive()
    }
}

impl RedisRateLimiter {
    /// Connect to Redis at `url` (e.g. `redis://127.0.0.1/`).
    pub fn connect(url: &str) -> color_eyre::Result<Self> {
        let client = redis::Client::open(url)?;
        let conn = client.get_connection()?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

const INCR_EXPIRE_SCRIPT: &str = r"
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
";

impl RateLimitBackend for RedisRateLimiter {
    fn record_and_check(&self, key: &str, limit: u32, per_secs: u64) -> bool {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bucket = secs.checked_div(per_secs).unwrap_or(0);
        let redis_key = format!("sentry:rl:{key}:{bucket}");

        let result: redis::RedisResult<u64> = redis::Script::new(INCR_EXPIRE_SCRIPT)
            .key(&redis_key)
            .arg(per_secs.saturating_mul(2).max(1))
            .invoke(&mut *self.conn.lock().unwrap());

        match result {
            Ok(n) => n > u64::from(limit),
            Err(e) => {
                warn!(error = %e, key = %key, "redis rate check failed — failing open");
                false
            }
        }
    }

    fn backend_name(&self) -> &'static str {
        "redis"
    }
}
