//! Threat models and LLM provider abstraction.
//!
//! Two layers:
//! - `ThreatModel`: local ONNX classifier (fast, deterministic, no network).
//! - `LlmProvider`: remote LLM classification (slow, costly) — provider-agnostic
//!   via OpenRouter / Ollama / OpenAI / Anthropic adapters.
//!
//! Feature extraction ([`features`]) is shared between training export and
//! inference so the model always sees the same inputs.

#![forbid(unsafe_code)]

pub mod features;
pub mod llm;
pub mod lookup;
pub mod threat;

#[cfg(feature = "onnx")]
pub mod onnx_model;

pub use features::{extract, FEATURE_NAMES};
pub use llm::{
    ClassifyRequest, ClassifyResponse, ExplainRequest, JevProvider, LlmProvider, LlmUsage,
    MockLlmProvider, OllamaProvider, OpenRouterProvider,
};
pub use lookup::{AbuseIpDbLookup, IpLookupProvider, IpLookupResult};
pub use threat::ThreatModel;
