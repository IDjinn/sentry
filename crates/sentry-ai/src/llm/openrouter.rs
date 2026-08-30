//! OpenRouter adapter — the recommended default [`LlmProvider`].
//!
//! A single endpoint (`https://openrouter.ai/api/v1`) routes to any model
//! (Claude, GPT, Gemini, Qwen, Llama, …), which is handy for experimenting
//! with cost vs. quality. The API key comes from the caller (the daemon reads
//! `SENTRY_LLM_KEY`); it is never stored in config.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::llm::prompt;
use crate::llm::{ClassifyRequest, ClassifyResponse, ExplainRequest, LlmProvider};

/// Default OpenRouter API base URL.
pub const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/v1";

/// LLM calls can take a while; the fork stage tolerates the latency but not
/// forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// OpenRouter provider configuration.
#[derive(Debug, Clone)]
pub struct OpenRouterConfig {
    /// API key (`SENTRY_LLM_KEY`).
    pub api_key: String,
    /// Model id (e.g. `"anthropic/claude-3.5-sonnet"`).
    pub model: String,
    /// API base URL override (defaults to [`DEFAULT_BASE_URL`]).
    pub base_url: String,
}

/// [`LlmProvider`] backed by the OpenRouter chat-completions API.
pub struct OpenRouterProvider {
    http: reqwest::Client,
    cfg: OpenRouterConfig,
}

impl OpenRouterProvider {
    /// Build the provider with its own timed-out HTTP client.
    pub fn new(cfg: OpenRouterConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client"),
            cfg,
        }
    }

    async fn chat(&self, body: &Value) -> anyhow::Result<String> {
        let url = format!(
            "{}/chat/completions",
            self.cfg.base_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.cfg.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("openrouter request failed: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let preview = &text[..text.len().min(512)];
            tracing::warn!(status = %status, body = preview, "openrouter api error");
            anyhow::bail!("openrouter api returned {status}");
        }
        extract_content(&text)
    }
}

#[async_trait]
impl LlmProvider for OpenRouterProvider {
    fn name(&self) -> &'static str {
        "openrouter"
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

/// Build the chat-completions body with a strict JSON-schema response format.
fn classify_body(model: &str, req: &ClassifyRequest) -> Value {
    json!({
        "model": model,
        "messages": [
            {"role": "system", "content": prompt::SYSTEM_PROMPT},
            {"role": "user", "content": req.context}
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "sentry_classification",
                "strict": true,
                "schema": req.schema
            }
        }
    })
}

/// Build a free-form chat body for explanations.
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
        ]
    })
}

/// Extract `choices[0].message.content` from a chat-completions response.
fn extract_content(body: &str) -> anyhow::Result<String> {
    let parsed: Value = serde_json::from_str(body)
        .map_err(|e| anyhow::anyhow!("openrouter response is not JSON: {e}"))?;
    parsed["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("openrouter response has no message content"))
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
    fn classify_body_carries_schema_and_context() {
        let body = classify_body("m/x", &req());
        assert_eq!(body["model"], "m/x");
        assert_eq!(body["messages"][1]["content"], "ip=1.2.3.4 path=/login");
        assert_eq!(body["response_format"]["type"], "json_schema");
        assert_eq!(body["response_format"]["json_schema"]["strict"], true);
        assert_eq!(
            body["response_format"]["json_schema"]["schema"]["properties"]["verdict"]["enum"][0],
            "allow"
        );
    }

    #[test]
    fn explain_body_is_free_form() {
        let body = explain_body(
            "m/x",
            &ExplainRequest {
                context: "ctx".into(),
                signals: vec![],
                verdict: Verdict::Block,
            },
        );
        assert!(body.get("response_format").is_none());
        assert!(body["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("verdict=Block"));
    }

    #[test]
    fn extract_content_reads_first_choice() {
        let resp = r#"{"choices":[{"message":{"content":"{\"verdict\":\"allow\",\"risk_score\":5,\"signals\":[],\"confidence\":1}"}}]}"#;
        let content = extract_content(resp).unwrap();
        let parsed = prompt::parse_classify(&content).unwrap();
        assert_eq!(parsed.verdict, Verdict::Allow);
    }

    #[test]
    fn extract_content_rejects_empty_choices() {
        assert!(extract_content(r#"{"choices":[]}"#).is_err());
        assert!(extract_content("not json").is_err());
    }
}
