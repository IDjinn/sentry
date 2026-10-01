//! Shared prompt construction and response parsing for LLM adapters.
//!
//! Every adapter (OpenRouter, Ollama, …) sends the same system prompt and
//! JSON schema, and normalizes what the model answered through
//! [`parse_classify`] — so a model that answers with markdown fences or
//! capitalized enum names still produces a valid [`ClassifyResponse`].

use serde::Deserialize;
use serde_json::json;

use sentry_core::analysis::{RiskLevel, Verdict};
use sentry_core::event::{Event, ProtocolData};

use crate::llm::ClassifyResponse;

/// System prompt framing the model as a WAF triage analyst.
pub const SYSTEM_PROMPT: &str = "You are the LLM layer of an access-monitoring WAF. \
You classify HTTP/TCP/TLS observations as benign or malicious and answer \
ONLY with a single JSON object obeying the provided schema. \
Be conservative: ordinary traffic must map to verdict \"allow\" with a low \
risk_score. Known attack patterns (SQLi, XSS, path traversal, scanner \
probes, credential abuse) must map to block/challenge with a high score.";

/// Hard cap on the context summary length (token-cost predictability).
const CONTEXT_MAX_LEN: usize = 2048;

/// JSON schema the model must obey for classification responses.
///
/// Mirrors [`ClassifyResponse`]; `explanation` is optional so terse models
/// can omit it.
pub fn classify_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["allow", "rate_limit", "challenge", "block", "quarantine"]
            },
            "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
            "risk_level": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"]
            },
            "signals": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "explanation": {"type": ["string", "null"]}
        },
        "required": ["verdict", "risk_score", "signals", "confidence"],
        "additionalProperties": false
    })
}

/// Build a bounded, human-readable summary of an event for the user message.
pub fn context_from_event(evt: &Event) -> String {
    let mut ctx = format!("ip={} source={}", evt.client_ip, evt.source);
    match &evt.protocol {
        ProtocolData::Http(h) => {
            let method = h.method.map(|m| m.as_str()).unwrap_or("-");
            ctx.push_str(&format!(" method={method}"));
            ctx.push_str(&format!(" path={}", truncate(&h.path, 512)));
            if let Some(q) = &h.query {
                ctx.push_str(&format!("?{}", truncate(q, 256)));
            }
            if let Some(s) = h.status {
                ctx.push_str(&format!(" status={s}"));
            }
            if let Some(ua) = &h.user_agent {
                ctx.push_str(&format!(" ua={}", truncate(ua, 256)));
            }
            if let Some(r) = &h.referer {
                ctx.push_str(&format!(" referer={}", truncate(r, 256)));
            }
            if let Some(b) = &h.body {
                let preview = String::from_utf8_lossy(&b[..b.len().min(256)]);
                ctx.push_str(&format!(" body={}", truncate(preview.trim(), 256)));
            }
        }
        ProtocolData::TlsHandshake(t) => {
            ctx.push_str(" protocol=tls");
            if let Some(sni) = &t.sni {
                ctx.push_str(&format!(" sni={}", truncate(sni, 256)));
            }
            if let Some(ja3) = &t.ja3 {
                ctx.push_str(&format!(" ja3={ja3}"));
            }
            if let Some(ja4) = &t.ja4 {
                ctx.push_str(&format!(" ja4={ja4}"));
            }
            if let Some(v) = &t.version {
                ctx.push_str(&format!(" version={v}"));
            }
        }
        ProtocolData::Tcp(t) => {
            let payload_len = t.payload.as_ref().map(|p| p.len()).unwrap_or(0);
            ctx.push_str(&format!(
                " protocol=tcp stage={:?} payload_len={payload_len}",
                t.stage
            ));
        }
        ProtocolData::Udp(u) => {
            let payload_len = u.payload.as_ref().map(|p| p.len()).unwrap_or(0);
            ctx.push_str(&format!(" protocol=udp payload_len={payload_len}"));
            if let Some(q) = &u.dns_query {
                ctx.push_str(&format!(" dns_query={}", truncate(q, 256)));
            }
        }
        ProtocolData::Raw(r) => {
            ctx.push_str(&format!(" protocol=raw note={}", truncate(&r.note, 256)));
        }
        ProtocolData::Syslog(s) => {
            ctx.push_str(&format!(
                " protocol=syslog facility={} severity={}",
                s.facility, s.severity
            ));
            if let Some(app) = &s.app_name {
                ctx.push_str(&format!(" app={}", truncate(app, 128)));
            }
            ctx.push_str(&format!(" message={}", truncate(&s.message, 512)));
        }
    }
    truncate(&ctx, CONTEXT_MAX_LEN).to_string()
}

/// Parse a model answer into a [`ClassifyResponse`], tolerating prose around
/// the JSON object, markdown fences, capitalized enum names and out-of-range
/// numbers. `risk_level` is always re-derived from the (clamped) score.
pub fn parse_classify(raw: &str) -> anyhow::Result<ClassifyResponse> {
    let json_str = extract_json_object(raw)?;
    let parsed: RawClassify = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("llm answer is not valid JSON: {e}"))?;

    let verdict = parse_verdict(&parsed.verdict)
        .ok_or_else(|| anyhow::anyhow!("unknown verdict `{}`", parsed.verdict))?;
    let risk_score = parsed.risk_score.round().clamp(0.0, 100.0) as u8;
    Ok(ClassifyResponse {
        verdict,
        risk_score,
        risk_level: RiskLevel::from_score(risk_score),
        signals: parsed.signals.unwrap_or_default(),
        confidence: parsed.confidence.unwrap_or(1.0).clamp(0.0, 1.0) as f32,
        explanation: parsed.explanation.filter(|s| !s.is_empty()),
        usage: None,
    })
}

#[derive(Debug, Deserialize)]
struct RawClassify {
    verdict: String,
    risk_score: f64,
    #[serde(default)]
    signals: Option<Vec<String>>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    explanation: Option<String>,
}

/// Slice out the outermost JSON object, ignoring fences/prose around it.
fn extract_json_object(raw: &str) -> anyhow::Result<&str> {
    let (start, end) = match (raw.find('{'), raw.rfind('}')) {
        (Some(s), Some(e)) if s < e => (s, e + 1),
        _ => anyhow::bail!("llm answer contains no JSON object"),
    };
    Ok(&raw[start..end])
}

/// Normalize a verdict token (`deny`, `Rate-Limit`, …) to the enum.
pub(crate) fn parse_verdict(s: &str) -> Option<Verdict> {
    match normalize_token(s).as_str() {
        "allow" => Some(Verdict::Allow),
        "ratelimit" | "rate_limit" | "rate_limit_violation" => Some(Verdict::RateLimit),
        "challenge" => Some(Verdict::Challenge),
        "block" | "deny" => Some(Verdict::Block),
        "quarantine" => Some(Verdict::Quarantine),
        _ => None,
    }
}

/// Lowercase, strip `-`/`_`/spaces so `Rate-Limit`, `rateLimit` and
/// `rate_limit` all compare equal.
fn normalize_token(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_has_strict_shape() {
        let schema = classify_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(
            schema["properties"]["verdict"]["enum"][0],
            serde_json::json!("allow")
        );
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "verdict"));
    }

    #[test]
    fn parse_valid_json() {
        let raw = r#"{"verdict":"block","risk_score":87,"risk_level":"critical",
            "signals":["sql_injection"],"confidence":0.9,"explanation":"union select"}"#;
        let resp = parse_classify(raw).unwrap();
        assert_eq!(resp.verdict, Verdict::Block);
        assert_eq!(resp.risk_score, 87);
        assert_eq!(resp.risk_level, RiskLevel::Critical);
        assert_eq!(resp.signals, vec!["sql_injection".to_string()]);
        assert_eq!(resp.confidence, 0.9);
    }

    #[test]
    fn parse_strips_fences_and_prose() {
        let raw = "Here is my answer:\n```json\n{\"verdict\":\"challenge\",\"risk_score\":55,\"signals\":[],\"confidence\":0.8}\n```\nhope it helps";
        let resp = parse_classify(raw).unwrap();
        assert_eq!(resp.verdict, Verdict::Challenge);
        assert_eq!(resp.risk_score, 55);
    }

    #[test]
    fn parse_normalizes_capitalized_and_spaced_verdicts() {
        let raw = r#"{"verdict":"Rate-Limit","risk_score":30,"signals":[],"confidence":0.5}"#;
        let resp = parse_classify(raw).unwrap();
        assert_eq!(resp.verdict, Verdict::RateLimit);
        assert_eq!(resp.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn parse_clamps_and_derives_level() {
        let raw = r#"{"verdict":"allow","risk_score":250,"signals":[],"confidence":2.0}"#;
        let resp = parse_classify(raw).unwrap();
        assert_eq!(resp.risk_score, 100);
        assert_eq!(resp.risk_level, RiskLevel::Critical);
        assert_eq!(resp.confidence, 1.0);
    }

    #[test]
    fn parse_accepts_float_score_and_defaults() {
        let raw = r#"{"verdict":"allow","risk_score":8.0}"#;
        let resp = parse_classify(raw).unwrap();
        assert_eq!(resp.risk_score, 8);
        assert!(resp.signals.is_empty());
        assert_eq!(resp.confidence, 1.0);
        assert_eq!(resp.explanation, None);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_classify("no json here at all").is_err());
        assert!(parse_classify(r#"{"risk_score":10}"#).is_err());
        assert!(parse_classify(r#"{"verdict":"explode","risk_score":10}"#).is_err());
    }

    #[test]
    fn context_bounded_and_http_detailed() {
        let evt = Event::new(
            sentry_core::event::SourceKind::Synthetic,
            "1.2.3.4".parse().unwrap(),
            ProtocolData::Http(sentry_core::event::HttpData {
                method: Some(sentry_core::event::HttpMethod::Get),
                path: "/login".into(),
                query: Some("user=admin".into()),
                status: Some(401),
                user_agent: Some("curl/8.0".into()),
                ..Default::default()
            }),
        );
        let ctx = context_from_event(&evt);
        assert!(ctx.contains("method=GET"));
        assert!(ctx.contains("path=/login?user=admin"));
        assert!(ctx.contains("status=401"));

        let long = "x".repeat(10_000);
        let evt = Event::new(
            sentry_core::event::SourceKind::Synthetic,
            "1.2.3.4".parse().unwrap(),
            ProtocolData::Http(sentry_core::event::HttpData {
                path: long,
                ..Default::default()
            }),
        );
        assert!(context_from_event(&evt).len() <= CONTEXT_MAX_LEN);
    }
}
