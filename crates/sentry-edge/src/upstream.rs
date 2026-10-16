//! Upstream selection for the inline edge (F14): nginx-style upstream
//! groups — load balancing (`round_robin` / `least_conn` / `ip_hash`),
//! passive health checks (`max_fails` / `fail_timeout` semantics: eject a
//! server after enough failures inside the window, let it back in when the
//! window elapses). Host/path routing lives in [`crate::routing`].
//!
//! The state is lock-free on the selection path: `down_until` and the
//! in-flight counters are atomics; the failure timestamps only lock on
//! failures, which are the rare case.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sentry_core::config::BalanceMode;

/// Current wall-clock milliseconds (the clock every group method speaks).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// One backend inside a group: the base URL (IP or hostname — both resolve
/// through the system resolver at connect time) plus its passive-health
/// state.
pub struct UpstreamServer {
    /// Backend base URL (`http://127.0.0.1:3000`, `http://web:3000`).
    pub url: String,
    in_flight: AtomicUsize,
    /// Failure timestamps inside the `fail_timeout` window (locked —
    /// failures are rare; selection never locks).
    fails: Mutex<Vec<u64>>,
    /// Epoch ms until which this server is ejected (0 = up).
    down_until: AtomicU64,
}

impl UpstreamServer {
    fn new(url: String) -> Self {
        Self {
            url,
            in_flight: AtomicUsize::new(0),
            fails: Mutex::new(Vec::new()),
            down_until: AtomicU64::new(0),
        }
    }

    /// Whether the server accepts traffic at `now_ms` (an ejection expires
    /// by itself — the passive check gives the server another chance).
    fn is_up(&self, now_ms: u64) -> bool {
        self.down_until.load(Ordering::Relaxed) <= now_ms
    }

    /// Requests currently forwarded to this server.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Record a connection-level failure; ejects the server for
    /// `fail_timeout` once `max_fails` failures pile up inside the window.
    /// Returns `true` when this call ejected it.
    fn record_failure(&self, now_ms: u64, max_fails: u32, fail_timeout: Duration) -> bool {
        let mut fails = self.fails.lock().unwrap_or_else(|e| e.into_inner());
        let window = fail_timeout.as_millis() as u64;
        fails.retain(|ts| *ts + window > now_ms);
        fails.push(now_ms);
        if max_fails > 0 && fails.len() >= max_fails as usize {
            fails.clear();
            self.down_until
                .store(now_ms + fail_timeout.as_millis() as u64, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// A completed request clears the failure history (nginx semantics: a
    /// successful connection proves the server is back).
    fn record_success(&self) {
        self.down_until.store(0, Ordering::Relaxed);
        self.fails.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// An nginx `upstream {}` block: `max_fails`/`fail_timeout` passive health
/// checks across one or more backends with a [`BalanceMode`] strategy.
pub struct UpstreamGroup {
    /// Label for logs and metrics (`""` for the default group, the vhost
    /// host otherwise).
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub balance: BalanceMode,
    pub max_fails: u32,
    pub fail_timeout: Duration,
    next: AtomicU64,
}

impl UpstreamGroup {
    pub fn new(
        name: impl Into<String>,
        urls: &[String],
        balance: BalanceMode,
        max_fails: u32,
        fail_timeout_secs: u64,
    ) -> Self {
        Self {
            name: name.into(),
            servers: urls
                .iter()
                .map(|u| UpstreamServer::new(u.clone()))
                .collect(),
            balance,
            max_fails,
            fail_timeout: Duration::from_secs(fail_timeout_secs.max(1)),
            next: AtomicU64::new(0),
        }
    }

    /// Number of backends.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// True when the group has no backends (config gap — the daemon
    /// validates this before the edge starts).
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Whether at least one server currently accepts traffic.
    pub fn healthy(&self, now_ms: u64) -> bool {
        self.servers.iter().any(|s| s.is_up(now_ms))
    }

    /// Whether server `idx` is ejected at `now_ms`.
    pub fn is_down(&self, idx: usize, now_ms: u64) -> bool {
        !self.servers[idx].is_up(now_ms)
    }

    /// Pick the next server among the healthy, not-yet-tried ones
    /// (`exclude` = indices this request already attempted — nginx
    /// `proxy_next_upstream` tries each server at most once per request).
    /// `None` when the group is exhausted.
    pub fn pick_excluding(
        &self,
        exclude: &[usize],
        client_ip: IpAddr,
        now_ms: u64,
    ) -> Option<usize> {
        let candidates: Vec<usize> = self
            .servers
            .iter()
            .enumerate()
            .filter(|(idx, s)| s.is_up(now_ms) && !exclude.contains(idx))
            .map(|(idx, _)| idx)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let idx = match self.balance {
            BalanceMode::RoundRobin => {
                self.next.fetch_add(1, Ordering::Relaxed) % candidates.len() as u64
            }
            BalanceMode::LeastConn => {
                // Fewest in-flight requests; ties rotate with the counter so
                // idle clusters still spread evenly.
                let mut best = 0;
                let mut best_load = usize::MAX;
                for (pos, &idx) in candidates.iter().enumerate() {
                    let load = self.servers[idx].in_flight();
                    if load < best_load
                        || (load == best_load && self.next.fetch_add(1, Ordering::Relaxed) % 2 == 0)
                    {
                        best = pos;
                        best_load = load;
                    }
                }
                best as u64
            }
            BalanceMode::IpHash => {
                let mut hasher = DefaultHasher::new();
                client_ip.hash(&mut hasher);
                hasher.finish() % candidates.len() as u64
            }
        };
        candidates.get(idx as usize).copied()
    }

    /// Server base URL by index.
    pub fn url(&self, idx: usize) -> &str {
        &self.servers[idx].url
    }

    /// Label for a server (`group/server` or just the URL for the default
    /// group), used in logs.
    pub fn server_label(&self, idx: usize) -> String {
        match self.name.is_empty() {
            true => self.servers[idx].url.clone(),
            false => format!("{}/{idx}", self.name),
        }
    }

    /// Mark a request as in flight (before the hop) — drives `least_conn`.
    pub fn begin(&self, idx: usize) {
        self.servers[idx].in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Release the in-flight mark after the hop ends (success or failure).
    pub fn done(&self, idx: usize) {
        self.servers[idx].in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a retryable (connection-level) failure; returns `true` when
    /// this failure ejected the server.
    pub fn record_failure(&self, idx: usize, now_ms: u64) -> bool {
        self.servers[idx].record_failure(now_ms, self.max_fails, self.fail_timeout)
    }

    /// Record a completed request — clears the failure history.
    pub fn record_success(&self, idx: usize) {
        self.servers[idx].record_success();
    }
}

/// Normalize a raw Host header value for matching: lowercase, strip the
/// `:port` suffix, unwrap `[IPv6]:port`. `None` when there is nothing to
/// match (HTTP/1.0 without Host, or an empty header).
pub fn host_key(host: Option<&str>) -> Option<String> {
    let host = host?.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if let Some(rest) = host.strip_prefix('[') {
        // IPv6 literal: the port rides outside the closing bracket.
        return rest
            .split_once(']')
            .map(|(inner, _)| inner.to_string())
            .filter(|h| !h.is_empty());
    }
    // `host:port` — strip the port when the suffix is numeric.
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (!h.is_empty()).then(|| h.to_string())
        }
        _ => Some(host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// max_fails = 2, fail_timeout = 30s (the config defaults).
    fn group(urls: &[&str], balance: BalanceMode) -> UpstreamGroup {
        UpstreamGroup::new(
            "",
            &urls.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            balance,
            2,
            30,
        )
    }

    /// max_fails = 1: a single failure ejects immediately.
    fn fragile(urls: &[&str], balance: BalanceMode) -> UpstreamGroup {
        UpstreamGroup::new(
            "",
            &urls.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            balance,
            1,
            30,
        )
    }

    fn ip() -> IpAddr {
        "203.0.113.1".parse().unwrap()
    }

    #[test]
    fn host_key_normalizes_case_and_strips_ports() {
        assert_eq!(
            host_key(Some("App.Example.com:8443")).as_deref(),
            Some("app.example.com")
        );
        assert_eq!(
            host_key(Some("app.example.com")).as_deref(),
            Some("app.example.com")
        );
        assert_eq!(host_key(Some("[::1]:80")).as_deref(), Some("::1"));
        assert_eq!(
            host_key(Some("  WEB.local  ")).as_deref(),
            Some("web.local")
        );
        assert!(host_key(Some("")).is_none());
        assert!(host_key(None).is_none());
        assert!(host_key(Some(":8080")).is_none());
    }

    #[test]
    fn round_robin_rotates_and_skips_down_servers() {
        let g = group(
            &["http://a:1", "http://b:2", "http://c:3"],
            BalanceMode::RoundRobin,
        );
        let mut seen = Vec::new();
        for _ in 0..6 {
            let idx = g.pick_excluding(&[], ip(), now_ms()).unwrap();
            seen.push(idx);
        }
        assert_eq!(seen, vec![0, 1, 2, 0, 1, 2]);

        // Eject b (idx 1): rotation covers only a and c.
        let g2 = fragile(
            &["http://a:1", "http://b:2", "http://c:3"],
            BalanceMode::RoundRobin,
        );
        assert!(g2.record_failure(1, now_ms()));
        let mut hits = std::collections::HashSet::new();
        for _ in 0..4 {
            hits.insert(g2.pick_excluding(&[], ip(), now_ms()).unwrap());
        }
        assert_eq!(hits, [0, 2].into_iter().collect());

        // All down → exhausted.
        let g3 = fragile(&["http://a:1"], BalanceMode::RoundRobin);
        assert!(g3.record_failure(0, now_ms()));
        assert_eq!(g3.pick_excluding(&[], ip(), now_ms()), None);
        // A healthy group never exhausts.
        assert!(g.healthy(now_ms()));
    }

    #[test]
    fn failure_window_ejects_then_recovers() {
        let g = group(&["http://a:1", "http://b:2"], BalanceMode::RoundRobin);
        // max_fails = 2 inside 30s: the first failure keeps it up.
        assert!(!g.record_failure(0, 1_000));
        assert!(!g.is_down(0, 1_000));
        // Second failure inside the window ejects for 30s.
        assert!(g.record_failure(0, 2_000));
        assert!(g.is_down(0, 2_000));
        assert_eq!(g.pick_excluding(&[], ip(), 2_000), Some(1));
        // After the window the server is back.
        assert!(!g.is_down(0, 32_001));
        // Failures outside the window don't pile up.
        let g3 = group(&["http://a:1"], BalanceMode::RoundRobin);
        assert!(!g3.record_failure(0, 1_000));
        assert!(
            !g3.record_failure(0, 60_000),
            "old failure expired from the window"
        );
    }

    #[test]
    fn success_resets_failure_history() {
        let g = group(&["http://a:1"], BalanceMode::RoundRobin);
        assert!(!g.record_failure(0, 1_000));
        g.record_success(0);
        // The old failure no longer counts toward max_fails.
        assert!(!g.record_failure(0, 2_000));
    }

    #[test]
    fn least_conn_prefers_the_idle_server() {
        let g = group(&["http://a:1", "http://b:2"], BalanceMode::LeastConn);
        g.begin(0);
        for _ in 0..5 {
            assert_eq!(
                g.pick_excluding(&[], ip(), now_ms()),
                Some(1),
                "the server with zero in-flight wins"
            );
        }
    }

    #[test]
    fn ip_hash_is_sticky_per_client() {
        let g = group(
            &["http://a:1", "http://b:2", "http://c:3"],
            BalanceMode::IpHash,
        );
        let first = g.pick_excluding(&[], ip(), now_ms()).unwrap();
        for _ in 0..10 {
            assert_eq!(g.pick_excluding(&[], ip(), now_ms()), Some(first));
        }
        // A different address resolves somewhere valid.
        let other = g.pick_excluding(&[], "198.51.100.9".parse().unwrap(), now_ms());
        assert!(other.is_some());

        // Sticky still fails over: the excluded server is skipped.
        let fallback = g.pick_excluding(&[first], ip(), now_ms()).unwrap();
        assert_ne!(fallback, first);
    }

    #[test]
    fn pick_respects_exclusion_and_down_state() {
        let g = fragile(&["http://a:1", "http://b:2"], BalanceMode::RoundRobin);
        assert!(g.record_failure(1, 1_000));
        // b is down, a was tried → exhausted even though b recovers later.
        assert_eq!(g.pick_excluding(&[0], ip(), 2_000), None);
        // ...and the ejection expires.
        assert_eq!(g.pick_excluding(&[0], ip(), 31_001), Some(1));
    }
}
