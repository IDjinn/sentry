//! Local threat model abstraction (ONNX classifier).
//!
//! Heavy ONNX deps are gated behind the `onnx` feature; this module defines
//! the trait so the pipeline can depend on a `Box<dyn ThreatModel>` without
//! pulling `ort` into every build.

use async_trait::async_trait;

use sentry_core::analysis::Signal;
use sentry_core::event::Event;

/// A local, deterministic, no-network threat model.
///
/// Implementations wrap an ONNX session (feature `onnx`) or any other local
/// classifier. The pipeline calls [`analyze`](ThreatModel::analyze) on every
/// event whose heuristics left the verdict undecided.
#[async_trait]
pub trait ThreatModel: Send + Sync {
    /// Stable model name (`"sentry-payload-v1"`).
    fn name(&self) -> &'static str;

    /// Model version string.
    fn version(&self) -> &str;

    /// Analyze an event, returning the signals it detected and an anomaly
    /// score in 0.0–1.0.
    async fn analyze(&self, evt: &Event) -> anyhow::Result<Vec<Signal>>;
}
