//! Deterministic mock [`LlmProvider`] for tests and dry-runs.

use async_trait::async_trait;

use sentry_core::analysis::{RiskLevel, Verdict};

use crate::llm::{ClassifyRequest, ClassifyResponse, ExplainRequest, LlmProvider};

/// Returns a fixed classification regardless of the payload.
///
/// Defaults to a confident `block` at score 90 so pipeline wiring tests can
/// assert that LLM signals flow through `rescore_from`.
pub struct MockLlmProvider {
    /// Verdict returned by [`classify`](LlmProvider::classify).
    pub verdict: Verdict,
    /// Risk score returned by [`classify`](LlmProvider::classify).
    pub risk_score: u8,
    /// Confidence returned by [`classify`](LlmProvider::classify).
    pub confidence: f32,
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self {
            verdict: Verdict::Block,
            risk_score: 90,
            confidence: 0.9,
        }
    }
}

#[async_trait]
impl LlmProvider for MockLlmProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn model_id(&self) -> &str {
        "mock-model"
    }

    async fn classify(&self, _req: ClassifyRequest) -> anyhow::Result<ClassifyResponse> {
        Ok(ClassifyResponse {
            verdict: self.verdict,
            risk_score: self.risk_score,
            risk_level: RiskLevel::from_score(self.risk_score),
            signals: vec!["mock".to_string()],
            confidence: self.confidence,
            explanation: Some("deterministic mock verdict".to_string()),
        })
    }

    async fn explain(&self, _req: ExplainRequest) -> anyhow::Result<String> {
        Ok("mock explanation".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::event::ProtocolData;

    #[tokio::test]
    async fn classify_returns_configured_verdict() {
        let mock = MockLlmProvider::default();
        let resp = mock
            .classify(ClassifyRequest {
                protocol: ProtocolData::Raw(sentry_core::event::RawData {
                    note: String::new(),
                    bytes: vec![],
                }),
                context: String::new(),
                schema: serde_json::json!({}),
            })
            .await
            .unwrap();
        assert_eq!(resp.verdict, Verdict::Block);
        assert_eq!(resp.risk_score, 90);
        assert_eq!(resp.risk_level, RiskLevel::Critical);
        assert_eq!(mock.name(), "mock");
        assert_eq!(mock.model_id(), "mock-model");
    }

    #[tokio::test]
    async fn explain_returns_fixed_text() {
        let mock = MockLlmProvider {
            verdict: Verdict::Allow,
            risk_score: 0,
            confidence: 1.0,
        };
        let text = mock
            .explain(ExplainRequest {
                context: String::new(),
                signals: vec![],
                verdict: Verdict::Allow,
            })
            .await
            .unwrap();
        assert_eq!(text, "mock explanation");
    }
}
