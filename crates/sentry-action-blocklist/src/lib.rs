//! Local blocklist action.
//!
//! On a pipeline `Block` verdict, records the source IP in the shared
//! [`BlockTable`] for the configured TTL. The daemon mirrors the same
//! verdicts to Postgres (`ip_state`), and the inline edge denies IPs found
//! in the table before the pipeline runs — so this action is what gives a
//! `Block` verdict teeth in inline mode.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentry_core::action::Action;
use sentry_core::analysis::Verdict;
use sentry_core::error::Result;
use sentry_core::event::Event;
use sentry_core::BlockTable;
use tracing::info;

/// Blocklist configuration.
#[derive(Debug, Clone)]
pub struct BlocklistActionConfig {
    /// How long an IP stays blocked.
    pub ttl: Duration,
}

/// In-memory blocklist action backed by a shared [`BlockTable`].
pub struct BlocklistAction {
    cfg: BlocklistActionConfig,
    table: Arc<BlockTable>,
}

impl BlocklistAction {
    /// Create a new blocklist action writing into `table`.
    pub fn new(cfg: BlocklistActionConfig, table: Arc<BlockTable>) -> Self {
        Self { cfg, table }
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
        self.table
            .block(evt.client_ip, Some(Instant::now() + self.cfg.ttl));
        self.table.prune();
        info!(ip = %evt.client_ip, ttl = ?self.cfg.ttl, "ip blocked");
        Ok(())
    }
}
