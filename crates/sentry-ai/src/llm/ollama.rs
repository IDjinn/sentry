//! Ollama adapter — local, keyless [`LlmProvider`].
//!
//! Talks to a self-hosted Ollama server (default `http://localhost:11434`),
//! so no data leaves the host and there is no per-call cost. The JSON schema
//! is described in the system prompt instead of a `response_format` field
//! because `format` support varies across Ollama versions — `format: "json"`
//! plus an explicit schema instruction works everywhere.
//!
//! The recommended default for privacy-sensitive deployments (docs §17).

use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::llm::prompt;
use crate::llm::{ClassifyRequest, ClassifyResponse, ExplainRequest, LlmProvider};

/// Default Ollama base URL.
pub const DEFAULT_BASE_URL: &str = "http://localhost:11434";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Ollama provider configuration.
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    /// Model id (e.g. `"llama3.1"`).
    pub model: String,
    /// Base URL of the Ollama server (defaults to [`DEFAULT_BASE_URL`]).
    pub base_url: String,
}

/// [`LlmProvider`] backed by a local Ollama server.
pub struct OllamaProvider {
    http: reqwest::Client,
    cfg: OllamaConfig,
}

impl OllamaProvider {
    /// Build the provider with its own timed-out HTTP client.
    pub fn new(cfg: OllamaConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client"),
            cfg,
        }
    }

    async fn chat(&self, body: &Value) -> anyhow::Result<String> {
        let url = format!("{}/api/chat", self.cfg.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("ollama request failed: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let preview = &text[..text.len().min(512)];
            tracing::warn!(status = %status, body = preview, "ollama api error");
            anyhow::bail!("ollama api returned {status}");
        }
        extract_content(&text)
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn model_id(&self) -> &str {
        &self.cfg.model
    }

    async fn classify(&self, req: ClassifyRequest) -> anyhow::Result<ClassifyResponse> {
        let body = classify_body(&self.cfg.model, &req);
        let content = self.chat(&body).await?;
        prompt::parse_classify(&content)
    }

    async fn explain(&self, req: ExplainRequest) -> anyhow::Result<String> {
        let body = explain_body(&self.cfg.model, &req);
        self.chat(&body).await
    }
}

/// Build the `/api/chat` body for classification.
fn classify_body(model: &str, req: &ClassifyRequest) -> Value {
    let system = format!(
        "{}\n\nRespond ONLY with a single JSON object matching this schema \
(produce every required field, no extra fields, no prose):\n{}",
        prompt::SYSTEM_PROMPT,
        serde_json::to_string(&req.schema).unwrap_or_default()
    );
    json!({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": req.context}
        ],
        "stream": false,
        "format": "json"
    })
}

/// Build the `/api/chat` body for free-form explanations.
fn explain_body(model: &str, req: &ExplainRequest) -> Value {
    let signals = req
        .signals
        .iter()
        .map(|s| format!("{:?}", s.kind))
        .collect::<Vec<_>>()
        .join(", ");
    json!({
        "model": model,
        "messages": [
            {"role": "system", "content": "You explain WAF verdicts for operators in 2-3 sentences."},
            {"role": "user", "content": format!(
                "verdict={:?}\nsignals={}\n\n{}",
                req.verdict, signals, req.context
            )}
        ],
        "stream": false
    })
}

/// Extract `message.content` from an `/api/chat` response.
fn extract_content(body: &str) -> anyhow::Result<String> {
    let parsed: Value = serde_json::from_str(body)
        .map_err(|e| anyhow::anyhow!("ollama response is not JSON: {e}"))?;
    parsed["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("ollama response has no message content"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::analysis::Verdict;
    use sentry_core::event::ProtocolData;

    fn req() -> ClassifyRequest {
        ClassifyRequest {
            protocol: ProtocolData::Raw(sentry_core::event::RawData {
                note: "test".into(),
                bytes: vec![],
            }),
            context: "ip=1.2.3.4 path=/login".into(),
            schema: prompt::classify_schema(),
        }
    }

    #[test]
    fn classify_body_embeds_schema_and_json_format() {
        let body = classify_body("llama3.1", &req());
        assert_eq!(body["model"], "llama3.1");
        assert_eq!(body["format"], "json");
        assert_eq!(body["stream"], false);
        let system = body["messages"][0]["content"].as_str().unwrap();
        assert!(system.contains("JSON object"));
        assert!(system.contains("verdict"));
        assert_eq!(body["messages"][1]["content"], "ip=1.2.3.4 path=/login");
    }

    #[test]
    fn extract_content_reads_message() {
        let resp = r#"{"message":{"role":"assistant","content":"{\"verdict\":\"quarantine\",\"risk_score\":40,\"signals\":[],\"confidence\":0.7}"}}"#;
        let parsed = prompt::parse_classify(&extract_content(resp).unwrap()).unwrap();
        assert_eq!(parsed.verdict, Verdict::Quarantine);
    }

    #[test]
    fn extract_content_rejects_missing_message() {
        assert!(extract_content(r#"{"done":true}"#).is_err());
    }
}
