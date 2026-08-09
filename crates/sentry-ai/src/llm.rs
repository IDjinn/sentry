//! LLM provider abstraction.
//!
//! The Sentry core never calls a specific LLM API directly — it goes through
//! the [`LlmProvider`] trait. Adapters (openrouter, ollama, openai, …) each
//! implement it; selection happens by config. This lets us swap models
//! without touching the pipeline, and keeps the heavy HTTP deps out of
//! `sentry-core`.
//!
//! OpenRouter is the recommended default adapter because a single endpoint
//! routes to any model (Claude, GPT, Gemini, Qwen, Llama, …), which is handy
//! for experimenting with cost vs. quality.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use sentry_core::analysis::{RiskLevel, Signal, Verdict};
use sentry_core::event::ProtocolData;

/// Request to classify a payload.
#[derive(Debug, Clone, Serialize)]
pub struct ClassifyRequest {
    /// Protocol-specific payload (Http / Tcp / Tls / …).
    pub protocol: ProtocolData,
    /// Truncated human-readable summary: method, path, key headers, payload
    /// preview. Bounded to keep token cost predictable.
    pub context: String,
    /// JSON schema the model MUST follow in its response.
    pub schema: serde_json::Value,
}

/// Structured classification response from the LLM.
#[derive(Debug, Clone, Deserialize)]
pub struct ClassifyResponse {
    /// Recommended verdict.
    pub verdict: Verdict,
    /// Risk score 0–100.
    pub risk_score: u8,
    /// Risk level (derived from score; included so the model can justify).
    pub risk_level: RiskLevel,
    /// Signal kinds the model identified (free-form strings mapped back to
    /// [`Signal`] by the caller).
    pub signals: Vec<String>,
    /// Model's confidence 0.0–1.0.
    pub confidence: f32,
    /// Optional short explanation (1–2 sentences).
    pub explanation: Option<String>,
}

/// Request for a free-form explanation of an already-classified event.
///
/// Used by the CLI (`sentry incidents show`) and by alert webhooks to produce
/// a human-readable rationale.
#[derive(Debug, Clone, Serialize)]
pub struct ExplainRequest {
    /// Event summary already classified.
    pub context: String,
    /// The signals that fired.
    pub signals: Vec<Signal>,
    /// The current verdict.
    pub verdict: Verdict,
}

/// Provider-agnostic LLM interface.
///
/// Adapters live in submodules (`openrouter`, `ollama`, `openai`, `anthropic`,
/// `mock`). The daemon constructs the configured adapter at startup and hands
/// it to the pipeline as a `Box<dyn LlmProvider>`.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Stable adapter name (`"openrouter"`, `"ollama"`, …).
    fn name(&self) -> &'static str;

    /// Model id in use (e.g. `"anthropic/claude-3.5-sonnet"`).
    fn model_id(&self) -> &str;

    /// Classify a payload.
    async fn classify(&self, req: ClassifyRequest) -> anyhow::Result<ClassifyResponse>;

    /// Explain a classification (free-form text).
    async fn explain(&self, req: ExplainRequest) -> anyhow::Result<String>;
}
