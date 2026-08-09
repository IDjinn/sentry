//! Threat models and LLM provider abstraction.
//!
//! Two layers:
//! - `ThreatModel`: local ONNX classifier (fast, deterministic, no network).
//! - `LlmProvider`: remote LLM classification (slow, costly) — provider-agnostic
//!   via OpenRouter / Ollama / OpenAI / Anthropic adapters.

#![forbid(unsafe_code)]

pub mod llm;
pub mod threat;

pub use llm::{ClassifyRequest, ClassifyResponse, ExplainRequest, LlmProvider};
pub use threat::ThreatModel;
