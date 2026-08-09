//! Local blocklist action.
//!
//! Keeps an in-memory set of blocked IPs (with TTL) and, when a storage
//! backend is available, mirrors the state to the `ip_state` table. Used as
//! a fallback when Cloudflare isn't configured, and as the source of truth
//! for the future inline proxy mode.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentry_core::action::Action;
use sentry_core::analysis::Verdict;
use sentry_core::error::Result;
use sentry_core::event::Event;
use tokio::sync::RwLock;
use tracing::info;

/// Blocklist configuration.
#[derive(Debug, Clone)]
pub struct BlocklistActionConfig {
    /// How long an IP stays blocked.
    pub ttl: Duration,
}

/// In-memory blocklist action.
pub struct BlocklistAction {
    cfg: BlocklistActionConfig,
    blocked: Arc<RwLock<HashSet<(IpAddr, Instant)>>>,
}

impl BlocklistAction {
    /// Create a new blocklist action.
    pub fn new(cfg: BlocklistActionConfig) -> Self {
        Self {
            cfg,
            blocked: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Check whether an IP is currently blocked.
    pub async fn is_blocked(&self, ip: IpAddr) -> bool {
        let b = self.blocked.read().await;
        b.iter().any(|(i, exp)| *i == ip && *exp > Instant::now())
    }

    /// Block an IP for the configured TTL.
    pub async fn block(&self, ip: IpAddr) {
        let mut b = self.blocked.write().await;
        b.insert((ip, Instant::now() + self.cfg.ttl));
        info!(ip = %ip, ttl = ?self.cfg.ttl, "ip blocked");
    }

    /// Unblock an IP.
    pub async fn unblock(&self, ip: IpAddr) {
        let mut b = self.blocked.write().await;
        b.retain(|(i, _)| *i != ip);
    }

    /// Prune expired entries.
    pub async fn prune(&self) {
        let mut b = self.blocked.write().await;
        let now = Instant::now();
        b.retain(|(_, exp)| *exp > now);
    }
}

#[async_trait]
impl Action for BlocklistAction {
    fn name(&self) -> &'static str {
        "blocklist"
    }

    fn applies_to(&self, decision: &sentry_core::analysis::Decision) -> bool {
        decision.action == Verdict::Block
    }

    async fn execute(
        &self,
        evt: &Event,
        _decision: &sentry_core::analysis::Decision,
    ) -> Result<()> {
        self.block(evt.client_ip).await;
        self.prune().await;
        Ok(())
    }
}
