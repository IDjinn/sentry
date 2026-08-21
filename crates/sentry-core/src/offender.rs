//! Repeat-offender memory: per-IP strike counting with verdict escalation.
//!
//! Where [`RepetitionTracker`](crate::pipeline::RepetitionTracker) gives a
//! short-window score bonus, the offender tracker keeps a longer-lived strike
//! count per IP: every event whose final verdict is not `Allow` records a
//! strike, and strikes climb the verdict ladder (`RateLimit` → `Challenge` →
//! `Block`). The daemon mirrors strikes to the `ip_state` table so the memory
//! survives restarts and outlives edge-rule TTLs (e.g. Cloudflare access
//! rules reaped after 24h): when the offender comes back, its first violating
//! event is escalated immediately instead of starting from zero.
//!
//! Escalation only ever raises severity — a verdict already at `Block` stays
//! `Block`, and `Allow` events neither record strikes nor get escalated (no
//! ratchet against benign hits from a previously flagged IP).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::analysis::Verdict;
use crate::config::EscalationConfig;

/// Per-IP offender state.
#[derive(Debug, Clone)]
pub struct OffenderEntry {
    /// Strikes accumulated inside the current window.
    pub strikes: u32,
    /// Violations ever recorded (never decays — informational).
    pub total_violations: u64,
    /// Instant at which the strike window expires.
    pub expires_at: Instant,
}

/// Tracks per-IP strikes over a sliding window and escalates verdicts.
#[derive(Debug)]
pub struct OffenderTracker {
    window: Duration,
    entries: HashMap<IpAddr, OffenderEntry>,
}

impl OffenderTracker {
    /// Create a tracker with the given strike window.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window: Duration::from_secs(window_secs),
            entries: HashMap::new(),
        }
    }

    /// Create a tracker from config.
    pub fn from_config(cfg: &EscalationConfig) -> Self {
        Self::new(cfg.window_secs)
    }

    /// Current (non-expired) strike count for an IP.
    pub fn strikes(&self, ip: IpAddr) -> u32 {
        match self.entries.get(&ip) {
            Some(e) if e.expires_at > Instant::now() => e.strikes,
            _ => 0,
        }
    }

    /// Total violations ever recorded for an IP.
    pub fn total_violations(&self, ip: IpAddr) -> u64 {
        self.entries.get(&ip).map_or(0, |e| e.total_violations)
    }

    /// Record a strike, resetting the window. Returns the strike count
    /// including this one.
    pub fn record_strike(&mut self, ip: IpAddr) -> u32 {
        let now = Instant::now();
        let entry = self.entries.get_mut(&ip);
        let (strikes, total) = match entry {
            Some(e) if e.expires_at > now => (e.strikes + 1, e.total_violations + 1),
            Some(e) => (1, e.total_violations + 1),
            None => (1, 1),
        };
        self.entries.insert(
            ip,
            OffenderEntry {
                strikes,
                total_violations: total,
                expires_at: now + self.window,
            },
        );
        strikes
    }

    /// Record a strike (for a non-Allow verdict) and escalate the verdict if
    /// the resulting count crosses a configured threshold.
    ///
    /// Returns the new strike count and the escalated verdict, if any.
    pub fn record_and_escalate(
        &mut self,
        ip: IpAddr,
        verdict: Verdict,
        cfg: &EscalationConfig,
    ) -> (u32, Option<(Verdict, String)>) {
        let strikes = self.record_strike(ip);
        (strikes, escalate_at(strikes, verdict, cfg))
    }

    /// Escalate a verdict using the IP's current strikes without recording a
    /// new one (used by re-scoring paths such as the async AI fork).
    pub fn escalate_current(
        &self,
        ip: IpAddr,
        verdict: Verdict,
        cfg: &EscalationConfig,
    ) -> Option<(Verdict, String)> {
        escalate_at(self.strikes(ip), verdict, cfg)
    }

    /// Seed state persisted before this process started (startup pre-warm
    /// from `ip_state`). `since_last` is the time elapsed since the last
    /// violation; elapsed windows seed nothing (strikes already expired).
    pub fn seed(&mut self, ip: IpAddr, strikes: u32, total_violations: u64, since_last: Duration) {
        if strikes == 0 {
            return;
        }
        let Some(ttl) = self.window.checked_sub(since_last) else {
            return;
        };
        self.entries.insert(
            ip,
            OffenderEntry {
                strikes,
                total_violations,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// Drop entries whose window has expired.
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, e| e.expires_at > now);
    }
}

/// Escalate a verdict based on the strike count. Only ever raises severity.
pub fn escalate_at(
    strikes: u32,
    verdict: Verdict,
    cfg: &EscalationConfig,
) -> Option<(Verdict, String)> {
    if !cfg.enabled || verdict == Verdict::Allow {
        return None;
    }
    let target = if cfg.block_at > 0 && strikes >= cfg.block_at {
        Verdict::Block
    } else if cfg.challenge_at > 0 && strikes >= cfg.challenge_at {
        Verdict::Challenge
    } else {
        return None;
    };
    if severity(target) > severity(verdict) {
        Some((
            target,
            format!("offender escalation: {strikes} strikes in window"),
        ))
    } else {
        None
    }
}

fn severity(v: Verdict) -> u8 {
    match v {
        Verdict::Allow => 0,
        Verdict::Quarantine => 1,
        Verdict::RateLimit => 2,
        Verdict::Challenge => 3,
        Verdict::Block => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    fn cfg() -> EscalationConfig {
        EscalationConfig {
            enabled: true,
            window_secs: 60,
            challenge_at: 3,
            block_at: 5,
            persist: false,
        }
    }

    #[test]
    fn strikes_accumulate_and_expire() {
        let mut t = OffenderTracker::new(60);
        assert_eq!(t.record_strike(ip()), 1);
        assert_eq!(t.record_strike(ip()), 2);
        assert_eq!(t.strikes(ip()), 2);
        assert_eq!(t.total_violations(ip()), 2);
        t.prune();
        assert_eq!(t.strikes(ip()), 2);
    }

    #[test]
    fn expired_window_resets_strikes_but_keeps_total() {
        // window of 0s: every entry is expired the instant it is recorded.
        let mut t = OffenderTracker::new(0);
        assert_eq!(t.record_strike(ip()), 1);
        assert_eq!(t.record_strike(ip()), 1);
        assert_eq!(t.strikes(ip()), 0);
        assert_eq!(t.total_violations(ip()), 2);
    }

    #[test]
    fn record_and_escalate_ladder() {
        let mut t = OffenderTracker::from_config(&cfg());
        let (s, e) = t.record_and_escalate(ip(), Verdict::RateLimit, &cfg());
        assert_eq!(s, 1);
        assert!(e.is_none());

        let (_, e) = t.record_and_escalate(ip(), Verdict::RateLimit, &cfg());
        assert_eq!(e, None);

        let (s, e) = t.record_and_escalate(ip(), Verdict::RateLimit, &cfg());
        assert_eq!(s, 3);
        assert_eq!(e.map(|(v, _)| v), Some(Verdict::Challenge));

        let (s, e) = t.record_and_escalate(ip(), Verdict::RateLimit, &cfg());
        assert_eq!(s, 4);
        assert_eq!(e.map(|(v, _)| v), Some(Verdict::Challenge));

        let (s, e) = t.record_and_escalate(ip(), Verdict::RateLimit, &cfg());
        assert_eq!(s, 5);
        assert_eq!(e.map(|(v, _)| v), Some(Verdict::Block));
    }

    #[test]
    fn escalation_never_lowers_block() {
        let mut t = OffenderTracker::from_config(&cfg());
        for _ in 0..6 {
            t.record_strike(ip());
        }
        let e = escalate_at(t.strikes(ip()), Verdict::Block, &cfg());
        assert!(e.is_none());
    }

    #[test]
    fn escalation_respects_allow_semantics() {
        // Allow events are never escalated (caller must not record them);
        // a high strike count still does not escalate an Allow verdict.
        let mut t = OffenderTracker::from_config(&cfg());
        for _ in 0..6 {
            t.record_strike(ip());
        }
        assert!(escalate_at(t.strikes(ip()), Verdict::Allow, &cfg()).is_none());
    }

    #[test]
    fn disabled_escalation_is_noop() {
        let disabled = EscalationConfig {
            enabled: false,
            ..cfg()
        };
        let mut t = OffenderTracker::from_config(&disabled);
        for _ in 0..10 {
            t.record_strike(ip());
        }
        assert!(escalate_at(t.strikes(ip()), Verdict::RateLimit, &disabled).is_none());
    }

    #[test]
    fn seed_restores_and_expires() {
        let mut t = OffenderTracker::from_config(&cfg());
        t.seed(ip(), 4, 9, Duration::from_secs(10));
        assert_eq!(t.strikes(ip()), 4);
        assert_eq!(t.total_violations(ip()), 9);

        // Seeding with an elapsed time beyond the window is a no-op.
        let mut stale = OffenderTracker::from_config(&cfg());
        stale.seed(ip(), 4, 9, Duration::from_secs(600));
        assert_eq!(stale.strikes(ip()), 0);
    }
}
