//! The [`Action`] trait: implemented by every response plugin
//! (`sentry-action-cloudflare`, `sentry-action-webhook`, …).
//!
//! An action receives the final [`Decision`](crate::analysis::Decision) and
//! executes the side effect (block IP via Cloudflare API, send a webhook,
//! insert into the local blocklist, …). Actions are invoked by the decider
//! after policy has been applied.

use async_trait::async_trait;

use crate::analysis::Decision;
use crate::error::Result;
use crate::event::Event;

/// A plugin that executes a response when a decision is reached.
///
/// Actions are infallible from the pipeline's perspective: errors are logged
/// inside the implementation (so one failing webhook doesn't kill the daemon)
/// but [`execute`](Action::execute) returns `Result` so the daemon can
/// surface persistent failures in metrics.
#[async_trait]
pub trait Action: Send + Sync {
    /// Stable, lowercase plugin name (e.g. `"cloudflare"`).
    fn name(&self) -> &'static str;

    /// Execute the action for the given event + decision.
    ///
    /// Implementations should be idempotent: the same decision may be
    /// replayed after a restart, and re-blocking an already-blocked IP
    /// should be a no-op, not an error.
    async fn execute(&self, evt: &Event, decision: &Decision) -> Result<()>;

    /// Whether this action should run for the given verdict.
    ///
    /// Most actions only care about specific verdicts (e.g. a webhook
    /// configured for `High`+`Critical`). The default impl returns `true`
    /// for non-`Allow` verdicts; override to filter.
    fn applies_to(&self, decision: &Decision) -> bool {
        decision.action != crate::analysis::Verdict::Allow
    }
}
