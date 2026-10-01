//! TypeSafe Jev adapter — a calibrated judgment API as an [`LlmProvider`].
//!
//! Jev (`https://api.typesafe.ai/v1/systemone`) is not a generative LLM: a
//! single call answers typed questions (`choice` / `score`) with calibrated
//! probabilities in a strictly structured response, so classification never
//! needs JSON repair and cannot hallucinate fields. Each event is classified
//! with one HTTP call carrying two batched questions: the recommended
//! [`Verdict`] (choice) and a 0–9 risk score mapped onto the pipeline's
//! 0–100 scale. Token/cost usage is surfaced via [`LlmUsage`].
//!
//! Jev does not generate prose, so [`LlmProvider::explain`] returns a
//! formatted breakdown (top driver + probabilities) instead of sentences.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Map, Value};

use crate::llm::prompt;
use crate::llm::{ClassifyRequest, ClassifyResponse, ExplainRequest, LlmProvider, LlmUsage};

/// Default TypeSafe Jev API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.typesafe.ai";

/// Default model id.
pub const DEFAULT_MODEL: &str = "jev-latest";

/// Judgment calls are fast (single forward pass); tolerate slow networks but
/// not hangs.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Verdict options with Sentry enforcement semantics (label → description).
const VERDICT_OPTIONS: &[(&str, &str)] = &[
    (
        "allow",
        "Ordinary benign traffic: normal browsing, API calls, good bots, \
         static assets. No attack indicators.",
    ),
    (
        "rate_limit",
        "Abusive volume or sloppy automation that deserves backpressure, \
         not a hard block.",
    ),
    (
        "challenge",
        "Suspicious automation or probing: send a human-verification \
         challenge before serving.",
    ),
    (
        "block",
        "Clear attack or abuse: SQLi, XSS, path traversal, command \
         injection, scanner probes, credential stuffing, sensitive-file \
         access.",
    ),
    (
        "quarantine",
        "Ambiguous and potentially hostile, but needs deeper analysis \
         before acting.",
    ),
];

/// 10 risk levels (index 0..=9, the API's score-level cap); the answer
/// score (which may fall between levels) maps onto the pipeline's 0–100
/// scale as `score / 9 × 100`.
const RISK_LEVELS: &[&str] = &[
    "0 — certainly benign: ordinary browsing, API traffic, good bots; no suspicious indicators",
    "1 — benign: trivial anomalies only",
    "2 — benign but slightly unusual request shape",
    "3 — mildly suspicious, probably harmless",
    "4 — suspicious, worth watching",
    "5 — suspicious, likely automated probing",
    "6 — probable attack attempt",
    "7 — likely attack attempt",
    "8 — very likely attack",
    "9 — certain attack, exploit payload present",
];

/// Map a Jev 0–9 score onto the pipeline's 0–100 risk scale.
fn score_to_risk(score: f64) -> u8 {
    (score / 9.0 * 100.0).round().clamp(0.0, 100.0) as u8
}

/// Jev provider configuration.
#[derive(Debug, Clone)]
pub struct JevConfig {
    /// API key (`SENTRY_JEV_KEY` or the TypeSafe fallbacks).
    pub api_key: String,
    /// Model id (defaults to [`DEFAULT_MODEL`]).
    pub model: String,
    /// API base URL override (defaults to [`DEFAULT_BASE_URL`]).
    pub base_url: String,
}

/// [`LlmProvider`] backed by the TypeSafe Jev judgment API.
pub struct JevProvider {
    http: reqwest::Client,
    cfg: JevConfig,
}

impl JevProvider {
    /// Build the provider with its own timed-out HTTP client.
    pub fn new(cfg: JevConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client"),
            cfg,
        }
    }

    async fn system_one(&self, body: &Value) -> anyhow::Result<String> {
        let url = format!("{}/v1/systemone", self.cfg.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.cfg.api_key)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("jev request failed: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let preview = &text[..text.len().min(512)];
            tracing::warn!(status = %status, body = preview, "jev api error");
            anyhow::bail!("jev api returned {status}");
        }
        Ok(text)
    }
}

#[async_trait]
impl LlmProvider for JevProvider {
    fn name(&self) -> &'static str {
        "jev"
    }

    fn model_id(&self) -> &str {
        &self.cfg.model
    }

    async fn classify(&self, req: ClassifyRequest) -> anyhow::Result<ClassifyResponse> {
        let body = classify_body(&self.cfg.model, &req.context);
        let text = self.system_one(&body).await?;
        let (resp, _usage) = parse_answers(&text)?;
        Ok(resp)
    }

    async fn explain(&self, req: ExplainRequest) -> anyhow::Result<String> {
        let body = explain_body(&self.cfg.model, &req);
        let text = self.system_one(&body).await?;
        parse_explain(&text)
    }
}

/// Build the systemone body: one call, two batched questions.
fn classify_body(model: &str, context: &str) -> Value {
    let criteria: Map<String, Value> = VERDICT_OPTIONS
        .iter()
        .map(|(label, desc)| (label.to_string(), json!(desc)))
        .collect();
    json!({
        "state": context,
        "model": model,
        "questions": {
            "verdict": {
                "type": "choice",
                "instructions": "You are the triage layer of a web access \
    monitor (WAF). Classify the request summarized below and recommend the \
    enforcement verdict. Ordinary traffic must be `allow`; known attack \
    patterns must be `block`.",
                "criteria": criteria,
            },
            "risk": {
                "type": "score",
                "instructions": "Rate the threat risk of this request on \
    the given 0-9 scale, where 9 is a certain attack.",
                "criteria": RISK_LEVELS,
            },
        },
    })
}

/// Build the explanation body: which observed factor drives the verdict.
fn explain_body(model: &str, req: &ExplainRequest) -> Value {
    let mut criteria: BTreeMap<String, Value> = BTreeMap::new();
    for s in &req.signals {
        let label = format!("{:?}", s.kind).to_ascii_lowercase();
        criteria
            .entry(label)
            .and_modify(|d| {
                *d = json!(format!(
                    "{} (also weight {})",
                    d.as_str().unwrap_or(""),
                    s.weight
                ));
            })
            .or_insert_with(|| json!(format!("pipeline signal with weight {}", s.weight)));
    }
    if criteria.is_empty() {
        criteria.insert("none".to_string(), json!("no pipeline signals fired"));
    }
    json!({
        "state": format!("verdict={:?}\n{}", req.verdict, req.context),
        "model": model,
        "questions": {
            "driver": {
                "type": "choice",
                "instructions": "Given this request and its verdict, which \
    factor contributes most to the decision?",
                "criteria": criteria,
            },
        },
    })
}

/// Parse a systemone response into a [`ClassifyResponse`] plus optional
/// [`LlmUsage`].
fn parse_answers(body: &str) -> anyhow::Result<(ClassifyResponse, Option<LlmUsage>)> {
    let parsed: Value =
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("jev response is not JSON: {e}"))?;
    let answers = parsed
        .get("answers")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("jev response has no answers object"))?;

    let verdict_answer = answers
        .get("verdict")
        .ok_or_else(|| anyhow::anyhow!("jev response missing `verdict` answer"))?;
    let choice = verdict_answer
        .get("choice")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("jev verdict answer has no choice"))?;
    let verdict = prompt::parse_verdict(choice)
        .ok_or_else(|| anyhow::anyhow!("unknown jev verdict label `{choice}`"))?;
    let choice_confidence = confidence_of(verdict_answer);

    let risk_answer = answers
        .get("risk")
        .ok_or_else(|| anyhow::anyhow!("jev response missing `risk` answer"))?;
    let score = risk_answer
        .get("score")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow::anyhow!("jev risk answer has no score"))?;
    let risk_score = score_to_risk(score);

    let confidence = choice_confidence
        .or_else(|| confidence_of(risk_answer))
        .unwrap_or(1.0)
        .clamp(0.0, 1.0) as f32;

    let verdict_probs = probabilities_of(verdict_answer);
    let risk_probs = probabilities_of(risk_answer);
    let explanation = format_explanation(choice, &verdict_probs, score, &risk_probs);

    let usage = parsed.get("usage").and_then(|u| {
        serde_json::from_value::<ApiUsage>(u.clone())
            .ok()
            .map(|u| LlmUsage {
                input_tokens: u.input_tokens,
                output_tokens: u.output_tokens,
                cost: u.cost,
            })
    });

    Ok((
        ClassifyResponse {
            verdict,
            risk_score,
            risk_level: sentry_core::analysis::RiskLevel::from_score(risk_score),
            signals: Vec::new(),
            confidence,
            explanation: Some(explanation),
            usage,
        },
        usage,
    ))
}

/// Parse an `explain` response into a one-line formatted summary.
fn parse_explain(body: &str) -> anyhow::Result<String> {
    let parsed: Value =
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("jev response is not JSON: {e}"))?;
    let answer = parsed
        .get("answers")
        .and_then(|a| a.get("driver"))
        .ok_or_else(|| anyhow::anyhow!("jev response missing `driver` answer"))?;
    let choice = answer
        .get("choice")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("jev driver answer has no choice"))?;
    let probs = probabilities_of(answer);
    let mut top: Vec<_> = probs.into_iter().collect();
    top.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let breakdown = top
        .iter()
        .take(3)
        .map(|(label, p)| format!("{label}={p:.2}"))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!("jev: driver={choice}; {breakdown}"))
}

/// Format the classify explanation: chosen label with its probability and the
/// risk score, plus the top verdict alternatives (calibration visibility).
fn format_explanation(
    choice: &str,
    verdict_probs: &BTreeMap<String, f64>,
    score: f64,
    risk_probs: &BTreeMap<String, f64>,
) -> String {
    let mut out = match verdict_probs.get(choice).copied() {
        Some(p) => format!("jev verdict={choice} (p={p:.2}) risk={score:.1}/10"),
        None => format!("jev verdict={choice} risk={score:.1}/10"),
    };
    let mut alts: Vec<_> = verdict_probs
        .iter()
        .filter(|(label, _)| label.as_str() != choice)
        .collect();
    alts.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    let alts = alts
        .iter()
        .take(3)
        .map(|(label, p)| format!("{label}={p:.2}"))
        .collect::<Vec<_>>()
        .join(" ");
    if !alts.is_empty() {
        out.push_str(&format!(" | p({alts})"));
    }
    let max_risk_p = risk_probs.values().copied().fold(f64::NAN, f64::max);
    if max_risk_p.is_finite() {
        out.push_str(&format!(" risk_p={max_risk_p:.2}"));
    }
    out
}

fn confidence_of(answer: &Value) -> Option<f64> {
    answer.get("confidence").and_then(Value::as_f64)
}

/// Collect the answer's probability map, tolerating both string keys
/// (choice) and numeric keys (score index).
fn probabilities_of(answer: &Value) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    if let Some(probs) = answer.get("probabilities").and_then(Value::as_object) {
        for (k, v) in probs {
            if let Some(p) = v.as_f64() {
                out.insert(k.clone(), p);
            }
        }
    }
    out
}

#[derive(serde::Deserialize)]
struct ApiUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cost: Option<f64>,
}

/// Resolve the API key the same way the `jev-mcp` adapter does:
/// `SENTRY_JEV_KEY` → `TYPESAFE_API_KEY` → `JEV_API_KEY` →
/// `~/.config/typesafe/key`. Never logged.
pub fn resolve_api_key() -> Option<String> {
    key_from_parts(
        std::env::var("SENTRY_JEV_KEY").ok(),
        std::env::var("TYPESAFE_API_KEY").ok(),
        std::env::var("JEV_API_KEY").ok(),
        key_file(),
    )
}

fn key_file() -> Option<String> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()?;
    std::fs::read_to_string(format!("{home}/.config/typesafe/key"))
        .ok()
        .map(|c| c.trim().to_string())
}

fn key_from_parts(
    a: Option<String>,
    b: Option<String>,
    c: Option<String>,
    file: Option<String>,
) -> Option<String> {
    [a, b, c, file]
        .into_iter()
        .find_map(|part| part.filter(|v| !v.trim().is_empty()))
        .map(|v| v.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::analysis::Verdict;

    fn sample_response() -> String {
        r#"{
            "model": "jev-latest",
            "answers": {
                "verdict": {
                    "type": "choice",
                    "choice": "block",
                    "confidence": 0.93,
                    "probabilities": {"allow": 0.02, "rate_limit": 0.03, "challenge": 0.02, "block": 0.93}
                },
                "risk": {
                    "type": "score",
                    "score": 8.4,
                    "confidence": 0.9,
                    "legend": {"8": "very likely attack", "9": "near-certain attack"},
                    "probabilities": {"7": 0.05, "8": 0.6, "9": 0.3, "10": 0.05}
                }
            },
            "usage": {"input_tokens": 310, "output_tokens": 24, "cost": 0.000421}
        }"#
        .to_string()
    }

    #[test]
    fn classify_body_has_two_batched_questions() {
        let body = classify_body("jev-latest", "ip=1.2.3.4 path=/login");
        assert_eq!(body["state"], "ip=1.2.3.4 path=/login");
        assert_eq!(body["model"], "jev-latest");
        assert_eq!(body["questions"]["verdict"]["type"], "choice");
        let criteria = body["questions"]["verdict"]["criteria"]
            .as_object()
            .unwrap();
        assert_eq!(criteria.len(), VERDICT_OPTIONS.len());
        assert!(criteria.contains_key("block"));
        assert_eq!(body["questions"]["risk"]["type"], "score");
        assert_eq!(
            body["questions"]["risk"]["criteria"]
                .as_array()
                .unwrap()
                .len(),
            RISK_LEVELS.len()
        );
    }

    #[test]
    fn parse_answers_maps_choice_and_score() {
        let (resp, usage) = parse_answers(&sample_response()).unwrap();
        assert_eq!(resp.verdict, Verdict::Block);
        assert_eq!(resp.risk_score, 93);
        assert_eq!(resp.risk_level, sentry_core::analysis::RiskLevel::Critical);
        assert!((resp.confidence - 0.93).abs() < 1e-6);
        let explanation = resp.explanation.unwrap();
        assert!(explanation.contains("verdict=block"));
        assert!(explanation.contains("risk=8.4/10"));
        let usage = usage.unwrap();
        assert_eq!(usage.input_tokens, 310);
        assert_eq!(usage.output_tokens, 24);
        assert_eq!(usage.cost, Some(0.000421));
        assert_eq!(resp.usage.map(|u| u.input_tokens), Some(310));
    }

    #[test]
    fn parse_answers_normalizes_verdict_label() {
        let body = r#"{"answers":{"verdict":{"choice":"Rate-Limit","confidence":0.8},"risk":{"score":3.5}}}"#;
        let (resp, _) = parse_answers(body).unwrap();
        assert_eq!(resp.verdict, Verdict::RateLimit);
        assert_eq!(resp.risk_score, 39);
    }

    #[test]
    fn parse_answers_clamps_out_of_range_score() {
        let body = r#"{"answers":{"verdict":{"choice":"allow"},"risk":{"score":12}}}"#;
        let (resp, _) = parse_answers(body).unwrap();
        assert_eq!(resp.risk_score, 100);
        assert_eq!(resp.confidence, 1.0);
    }

    #[test]
    fn parse_answers_rejects_missing_or_unknown() {
        assert!(parse_answers("{}").is_err());
        assert!(parse_answers(r#"{"answers":{}}"#).is_err());
        assert!(parse_answers(
            r#"{"answers":{"verdict":{"choice":"explode"},"risk":{"score":1}}}"#
        )
        .is_err());
        assert!(parse_answers(r#"{"answers":{"verdict":{"choice":"block"}}}"#).is_err());
        assert!(parse_answers("not json").is_err());
    }

    #[test]
    fn usage_without_cost_is_none() {
        let body = r#"{"answers":{"verdict":{"choice":"block"},"risk":{"score":9}},"usage":{"input_tokens":10,"output_tokens":2}}"#;
        let (_, usage) = parse_answers(body).unwrap();
        assert_eq!(usage.unwrap().cost, None);
        let (_, usage) =
            parse_answers(r#"{"answers":{"verdict":{"choice":"block"},"risk":{"score":9}}}"#)
                .unwrap();
        assert!(usage.is_none());
    }

    #[test]
    fn parse_explain_formats_driver() {
        let body = r#"{"answers":{"driver":{"choice":"sqli","confidence":0.9,"probabilities":{"sqli":0.75,"bad_crawler":0.15,"path_traversal":0.05}}}}"#;
        let text = parse_explain(body).unwrap();
        assert!(text.contains("driver=sqli"));
        assert!(text.contains("sqli=0.75"));
    }

    #[test]
    fn key_from_parts_skips_blank_and_keeps_precedence() {
        let key = || "k".to_string();
        assert_eq!(
            key_from_parts(Some(key()), Some("b".into()), None, Some("f".into())).as_deref(),
            Some("k")
        );
        assert_eq!(
            key_from_parts(Some("  ".into()), None, Some("c".into()), None).as_deref(),
            Some("c")
        );
        assert_eq!(
            key_from_parts(None, None, None, Some(" file-key \n".into())).as_deref(),
            Some("file-key")
        );
        assert_eq!(key_from_parts(None, None, None, None), None);
    }
}
