//! The [`Action`] trait: implemented by every response plugin
//! (`sentry-action-cloudflare`, `sentry-action-webhook`, …).
//!
//! An action receives the final [`Decision`](crate::analysis::Decision) and
//! executes the side effect (block IP via Cloudflare API, send a webhook,
//! insert into the local blocklist, …). Actions are invoked by the decider
//! after policy has been applied.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::analysis::Decision;
use crate::error::Result;
use crate::event::Event;

/// Where an action executes relative to the daemon's ingest hot path.
///
/// The hot loop must stay near-instant, so only local containment runs
/// inline; anything that performs external I/O is handed to the
/// post-processing workers. Under overload the deferred queue fills first,
/// shedding actions — never events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionDispatch {
    /// Run in the ingest hot loop. Reserved for fast, local containment
    /// (block table, kernel firewall, log lines); actions here receive an
    /// empty [`ActionContext`] because the loop never awaits on storage.
    Inline,
    /// Run on the post-processing workers (API providers, webhooks, abuse
    /// reports). This is the safe default for network-bound actions.
    #[default]
    Deferred,
}

impl ActionDispatch {
    /// Lowercase stable name used in config and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Deferred => "deferred",
        }
    }

    /// Parse from a config string. Returns `None` on unknown values so the
    /// caller can emit a precise error.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "inline" => Some(Self::Inline),
            "deferred" => Some(Self::Deferred),
            _ => None,
        }
    }
}

/// Extra dispatch context handed to actions alongside the decision.
///
/// Populated by the daemon between pipeline and dispatch; actions that don't
/// care ignore it via the [`Action::execute_with_context`] default.
#[derive(Debug, Clone, Default)]
pub struct ActionContext {
    /// Incident the event was escalated to, when storage is enabled and the
    /// risk level warranted one. Lets alerting actions reference the
    /// incident for ack/resolve round-trips (F4.5).
    pub incident_id: Option<uuid::Uuid>,
}

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
    ///
    /// Dispatch always goes through [`Action::execute_with_context`], so an
    /// implementation may override just one of the two. The default here is
    /// a no-op for actions that only implement the context variant.
    async fn execute(&self, _evt: &Event, _decision: &Decision) -> Result<()> {
        Ok(())
    }

    /// Execute with dispatch context. The default ignores `ctx` and
    /// delegates to [`Action::execute`]; override to use it.
    async fn execute_with_context(
        &self,
        evt: &Event,
        decision: &Decision,
        ctx: &ActionContext,
    ) -> Result<()> {
        let _ = ctx;
        self.execute(evt, decision).await
    }

    /// Whether this action should run for the given verdict.
    ///
    /// Most actions only care about specific verdicts (e.g. a webhook
    /// configured for `High`+`Critical`). The default impl returns `true`
    /// for non-`Allow` verdicts; override to filter.
    fn applies_to(&self, decision: &Decision) -> bool {
        decision.action != crate::analysis::Verdict::Allow
    }

    /// Where this action executes relative to the ingest hot path.
    ///
    /// Defaults to [`ActionDispatch::Deferred`] — the safe choice for
    /// network-bound side effects. Local-containment implementations
    /// override to [`ActionDispatch::Inline`] so a malicious request is
    /// contained with zero queueing latency.
    fn dispatch(&self) -> ActionDispatch {
        ActionDispatch::Deferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_defaults_to_deferred() {
        assert_eq!(ActionDispatch::default(), ActionDispatch::Deferred);
    }

    #[test]
    fn dispatch_parses_round_trip() {
        for d in [ActionDispatch::Inline, ActionDispatch::Deferred] {
            assert_eq!(ActionDispatch::parse(d.as_str()), Some(d));
        }
        assert_eq!(ActionDispatch::parse("bogus"), None);
    }

    #[test]
    fn dispatch_serde_round_trip() {
        assert_eq!(
            serde_json::from_str::<ActionDispatch>("\"inline\"").unwrap(),
            ActionDispatch::Inline
        );
        assert_eq!(
            serde_json::to_string(&ActionDispatch::Deferred).unwrap(),
            "\"deferred\""
        );
    }
}
