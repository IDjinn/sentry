//! Provider-agnostic edge-action abstraction.
//!
//! Mirrors the [`crate::LlmProvider`] pattern (ARCHITECTURE.md §10.1): the
//! daemon never calls a CDN/WAF API directly, always via the
//! [`ChallengeProvider`] trait. This lets new edge providers (AWS WAF, Fastly,
//! Bunny, Suwaye…) be added by implementing the trait + one `match` arm in
//! `daemon::build_registry`, without touching [`crate::Action`],
//! [`crate::config::ActionKind`] or verdict-filtering logic.
//!
//! [`ChallengeAction`] is the single `Action` impl that wraps a boxed
//! provider and dispatches `Block` / `Challenge` / `RateLimit` verdicts to it.
//! `Allow` and `Quarantine` are filtered out once, centrally, so providers
//! don't have to repeat that check.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::action::Action;
use crate::analysis::{Decision, Verdict};
use crate::error::Result;
use crate::event::Event;

/// Edge action flavor, as understood by CDN/WAF APIs.
///
/// Providers map this to their own vocabulary (e.g. Cloudflare's
/// `managed_challenge`, AWS WAF `CAPTCHA`, Fastly `challenge`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeMode {
    /// Hard block the IP at the edge.
    Block,
    /// JavaScript challenge (browser must execute JS).
    JsChallenge,
    /// Managed challenge (provider picks JS / Turnstile / device fingerprint).
    ManagedChallenge,
    /// Apply rate limiting instead of a hard challenge.
    RateLimit,
}

impl EdgeMode {
    /// Lowercase stable name used in config and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::JsChallenge => "js_challenge",
            Self::ManagedChallenge => "managed_challenge",
            Self::RateLimit => "rate_limit",
        }
    }

    /// Parse from a config string. Returns `None` on unknown values so the
    /// caller can emit a precise error.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "block" => Some(Self::Block),
            "js_challenge" => Some(Self::JsChallenge),
            "managed_challenge" => Some(Self::ManagedChallenge),
            "rate_limit" => Some(Self::RateLimit),
            _ => None,
        }
    }
}

/// Options passed to a [`ChallengeProvider`] on each call.
///
/// `mode` is the configured preferred challenge flavor; providers may also
/// derive the effective mode from the `verdict` argument to [`ChallengeProvider::apply`].
#[derive(Debug, Clone, Copy)]
pub struct EdgeOptions {
    /// How long to keep the IP blocked/challenged at the edge.
    pub ttl: Duration,
    /// Preferred challenge mode (when `None`, provider picks a default).
    pub mode: Option<EdgeMode>,
}

impl EdgeOptions {
    /// Effective mode, falling back to a provider-supplied default.
    pub fn mode_or(self, default: EdgeMode) -> EdgeMode {
        self.mode.unwrap_or(default)
    }
}

/// A provider that can apply an edge action (block / challenge / rate-limit)
/// to a client IP at a CDN/WAF.
///
/// Implementations are expected to be idempotent and to keep their own
/// de-duplication cache (e.g. Cloudflare's IP→expiry map) so the daemon can
/// replay decisions safely after a restart.
///
/// Errors are surfaced to the daemon via [`Result`]; transient failures
/// should be logged inside the implementation and not abort the pipeline.
#[async_trait]
pub trait ChallengeProvider: Send + Sync {
    /// Stable, lowercase provider name (e.g. `"cloudflare"`).
    fn name(&self) -> &'static str;

    /// Apply the edge action for `ip` given the pipeline `verdict`.
    ///
    /// `opts` carries TTL and the configured preferred mode; the provider may
    /// override `opts.mode` based on `verdict` (e.g. force `Block` mode when
    /// the verdict is `Block`).
    async fn apply(&self, ip: IpAddr, verdict: Verdict, opts: &EdgeOptions) -> Result<()>;
}

/// The single [`Action`] that dispatches edge verdicts to a
/// [`ChallengeProvider`].
///
/// Holds the provider and shared options; `applies_to` accepts
/// `Block` / `Challenge` / `RateLimit` (the verdicts that mean "act at the
/// edge"). `Allow` and `Quarantine` are skipped — the former is benign, the
/// latter is held for LLM analysis and shouldn't touch the edge.
pub struct ChallengeAction {
    provider: Arc<dyn ChallengeProvider>,
    opts: EdgeOptions,
}

impl ChallengeAction {
    /// Create a new challenge action wrapping a provider.
    pub fn new(provider: Arc<dyn ChallengeProvider>, opts: EdgeOptions) -> Self {
        Self { provider, opts }
    }
}

#[async_trait]
impl Action for ChallengeAction {
    fn name(&self) -> &'static str {
        self.provider.name()
    }

    fn applies_to(&self, decision: &Decision) -> bool {
        matches!(
            decision.action,
            Verdict::Block | Verdict::Challenge | Verdict::RateLimit
        )
    }

    async fn execute(&self, evt: &Event, decision: &Decision) -> Result<()> {
        self.provider
            .apply(evt.client_ip, decision.action, &self.opts)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use super::*;
    use crate::analysis::{AnalysisResult, Decision};
    use crate::event::{Event, HttpData, ProtocolData, SourceKind};

    /// Records every call so tests can assert dispatch.
    struct MockProvider {
        calls: Mutex<Vec<(IpAddr, Verdict)>>,
    }

    impl MockProvider {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<(IpAddr, Verdict)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ChallengeProvider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn apply(&self, ip: IpAddr, verdict: Verdict, _opts: &EdgeOptions) -> Result<()> {
            self.calls.lock().unwrap().push((ip, verdict));
            Ok(())
        }
    }

    fn decision(verdict: Verdict) -> Decision {
        Decision {
            analysis: AnalysisResult::empty(),
            action: verdict,
            override_reason: None,
        }
    }

    fn event() -> Event {
        Event::new(
            SourceKind::Nginx,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ProtocolData::Http(HttpData::default()),
        )
    }

    #[test]
    fn applies_to_accepts_edge_verdicts() {
        let action = ChallengeAction::new(
            Arc::new(MockProvider::new()),
            EdgeOptions {
                ttl: Duration::from_secs(60),
                mode: None,
            },
        );
        assert!(action.applies_to(&decision(Verdict::Block)));
        assert!(action.applies_to(&decision(Verdict::Challenge)));
        assert!(action.applies_to(&decision(Verdict::RateLimit)));
    }

    #[test]
    fn applies_to_rejects_allow_and_quarantine() {
        let action = ChallengeAction::new(
            Arc::new(MockProvider::new()),
            EdgeOptions {
                ttl: Duration::from_secs(60),
                mode: None,
            },
        );
        assert!(!action.applies_to(&decision(Verdict::Allow)));
        assert!(!action.applies_to(&decision(Verdict::Quarantine)));
    }

    #[tokio::test]
    async fn execute_dispatches_to_provider() {
        let mock = Arc::new(MockProvider::new());
        let weak = Arc::downgrade(&mock);
        let action = ChallengeAction::new(
            mock,
            EdgeOptions {
                ttl: Duration::from_secs(60),
                mode: Some(EdgeMode::ManagedChallenge),
            },
        );
        action
            .execute(&event(), &decision(Verdict::Challenge))
            .await
            .unwrap();
        let recorded = weak.upgrade().unwrap().calls();
        assert_eq!(
            recorded,
            vec![(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), Verdict::Challenge)]
        );
    }

    #[tokio::test]
    async fn allow_verdict_never_dispatches() {
        let mock = Arc::new(MockProvider::new());
        let weak = Arc::downgrade(&mock);
        let action = ChallengeAction::new(
            mock,
            EdgeOptions {
                ttl: Duration::from_secs(60),
                mode: None,
            },
        );
        let dec = decision(Verdict::Allow);
        if action.applies_to(&dec) {
            action.execute(&event(), &dec).await.unwrap();
        }
        assert!(weak.upgrade().unwrap().calls().is_empty());
    }

    #[test]
    fn edge_mode_round_trips() {
        for m in [
            EdgeMode::Block,
            EdgeMode::JsChallenge,
            EdgeMode::ManagedChallenge,
            EdgeMode::RateLimit,
        ] {
            assert_eq!(EdgeMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(EdgeMode::parse("bogus"), None);
    }
}
