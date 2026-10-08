//! Shared in-memory block table.
//!
//! The enforcement-side cache of blocked IPs. Writers: the blocklist action
//! (pipeline `Block` verdicts), the daemon (DB pre-warm and hot-reload) and
//! the dashboard/CLI (through Postgres, where `ip_state` is the source of
//! truth). Readers: the inline edge fast-path, which denies blocked IPs
//! before the pipeline runs — a block sticks even when the current request
//! alone would score as benign.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Instant;

/// Shared set of blocked IPs with optional per-IP expiry.
///
/// `None` expiry means the IP stays blocked until explicitly unblocked
/// (dashboard/CLI blocks without TTL land here).
#[derive(Debug, Default)]
pub struct BlockTable {
    inner: RwLock<HashMap<IpAddr, Option<Instant>>>,
}

impl BlockTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Block `ip` until `expires_at` (`None` = no expiry). A newer decision
    /// overwrites the previous one.
    pub fn block(&self, ip: IpAddr, expires_at: Option<Instant>) {
        self.inner
            .write()
            .unwrap()
            .insert(crate::event::Event::canonical_ip(ip), expires_at);
    }

    /// Remove a block. Returns whether the IP was blocked before.
    pub fn unblock(&self, ip: IpAddr) -> bool {
        self.inner
            .write()
            .unwrap()
            .remove(&crate::event::Event::canonical_ip(ip))
            .is_some()
    }

    /// Whether `ip` is currently blocked (an expired entry does not count).
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        match self
            .inner
            .read()
            .unwrap()
            .get(&crate::event::Event::canonical_ip(ip))
        {
            Some(None) => true,
            Some(Some(exp)) => *exp > Instant::now(),
            None => false,
        }
    }

    /// Seed from persistent state without weakening an existing entry: the
    /// longer expiry wins and a permanent block outranks a TTL one.
    pub fn seed(&self, ip: IpAddr, expires_at: Option<Instant>) {
        let ip = crate::event::Event::canonical_ip(ip);
        let mut inner = self.inner.write().unwrap();
        let keep = match (inner.get(&ip), expires_at) {
            (Some(None), _) => return,
            (Some(Some(old)), Some(new)) if *old >= new => return,
            _ => expires_at,
        };
        inner.insert(ip, keep);
    }

    /// Replace the whole table with `entries` (hot-reload from the DB).
    pub fn reload<I: IntoIterator<Item = (IpAddr, Option<Instant>)>>(&self, entries: I) {
        let mut inner = self.inner.write().unwrap();
        inner.clear();
        inner.extend(
            entries
                .into_iter()
                .map(|(ip, exp)| (crate::event::Event::canonical_ip(ip), exp)),
        );
    }

    /// Drop expired entries, returning how many were removed.
    pub fn prune(&self) -> usize {
        let now = Instant::now();
        let mut inner = self.inner.write().unwrap();
        let before = inner.len();
        inner.retain(|_, exp| exp.map_or(true, |e| e > now));
        before - inner.len()
    }

    /// Number of entries currently held (including expired, until pruned).
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Whether the table holds no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ttl(secs: u64) -> Option<Instant> {
        Some(Instant::now() + Duration::from_secs(secs))
    }

    #[test]
    fn block_then_is_blocked_until_unblock() {
        let t = BlockTable::new();
        assert!(!t.is_blocked("203.0.113.7".parse().unwrap()));
        t.block("203.0.113.7".parse().unwrap(), ttl(60));
        assert!(t.is_blocked("203.0.113.7".parse().unwrap()));
        assert!(t.unblock("203.0.113.7".parse().unwrap()));
        assert!(!t.is_blocked("203.0.113.7".parse().unwrap()));
        assert!(!t.unblock("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn permanent_block_never_expires() {
        let t = BlockTable::new();
        t.block("203.0.113.8".parse().unwrap(), None);
        assert!(t.is_blocked("203.0.113.8".parse().unwrap()));
        assert_eq!(t.prune(), 0);
        assert!(t.is_blocked("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn expired_entry_does_not_count_as_blocked() {
        let t = BlockTable::new();
        t.block("203.0.113.9".parse().unwrap(), Some(Instant::now()));
        assert!(!t.is_blocked("203.0.113.9".parse().unwrap()));
        assert_eq!(t.prune(), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn overwrite_replaces_previous_expiry() {
        let t = BlockTable::new();
        t.block("203.0.113.10".parse().unwrap(), ttl(60));
        t.block("203.0.113.10".parse().unwrap(), None);
        assert!(t.is_blocked("203.0.113.10".parse().unwrap()));
        assert_eq!(t.prune(), 0);
    }

    #[test]
    fn seed_keeps_longest_expiry_and_permanent_wins() {
        let t = BlockTable::new();
        let ip: IpAddr = "203.0.113.11".parse().unwrap();
        t.seed(ip, ttl(600));
        t.seed(ip, ttl(30));
        assert!(t.is_blocked(ip), "shorter seed must not weaken the block");
        t.seed(ip, None);
        t.seed(ip, ttl(600));
        assert_eq!(t.prune(), 0, "permanent block must survive pruning");
    }

    #[test]
    fn reload_replaces_contents() {
        let t = BlockTable::new();
        t.block("203.0.113.12".parse().unwrap(), None);
        t.reload(vec![
            ("203.0.113.13".parse().unwrap(), ttl(60)),
            ("203.0.113.14".parse().unwrap(), None),
        ]);
        assert!(!t.is_blocked("203.0.113.12".parse().unwrap()));
        assert!(t.is_blocked("203.0.113.13".parse().unwrap()));
        assert!(t.is_blocked("203.0.113.14".parse().unwrap()));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn prune_keeps_live_entries_only() {
        let t = BlockTable::new();
        t.block("203.0.113.15".parse().unwrap(), ttl(600));
        t.block("203.0.113.16".parse().unwrap(), Some(Instant::now()));
        t.block("203.0.113.17".parse().unwrap(), None);
        assert_eq!(t.prune(), 1);
        assert_eq!(t.len(), 2);
    }
}
