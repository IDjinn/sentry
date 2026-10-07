//! Webhook alert action.
//!
//! Posts a JSON payload to a configured URL (Discord, Slack, Telegram, custom
//! endpoint) when a decision reaches the configured risk levels.
//!
//! Discord endpoints (`discord.com`/`discordapp.com` webhooks) reject
//! arbitrary JSON — they require at least a `content` or `embeds` field — so
//! payloads targeting them are wrapped in Discord's message format (rich
//! embed, color-coded by risk level). Every other endpoint receives the raw
//! payload verbatim.
//!
//! F4.5 bidirectional alerts: when the dispatch context carries an incident
//! id it is included in the payload (`incident_id`), so the receiving system
//! can call back `POST /api/incidents/{id}/ack|resolve`. When a webhook
//! secret is configured, requests are signed with
//! `X-Sentry-Signature: sha256=<hex hmac(secret, body)>`.

#![forbid(unsafe_code)]

use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sentry_core::action::{Action, ActionContext, ActionDispatch};
use sentry_core::analysis::{RiskLevel, Verdict};
use sentry_core::error::Result;
use sentry_core::event::Event;
use sha2::Sha256;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Webhook action configuration.
#[derive(Debug, Clone)]
pub struct WebhookActionConfig {
    /// Target URL.
    pub url: String,
    /// Risk levels that trigger the webhook (`["high", "critical"]`).
    pub on_levels: Vec<RiskLevel>,
    /// Request timeout.
    pub timeout: Duration,
    /// Shared secret for HMAC request signing (optional).
    pub secret: Option<String>,
}

/// Webhook action.
pub struct WebhookAction {
    cfg: WebhookActionConfig,
    http: reqwest::Client,
    dispatch: ActionDispatch,
}

impl WebhookAction {
    /// Create a new webhook action.
    ///
    /// Defaults to [`ActionDispatch::Deferred`]: the POST waits on external
    /// I/O and belongs on the post-processing workers.
    pub fn new(cfg: WebhookActionConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .expect("reqwest client");
        Self {
            cfg,
            http,
            dispatch: ActionDispatch::default(),
        }
    }

    /// Override where the daemon runs this action relative to the ingest
    /// hot path.
    #[must_use]
    pub fn with_dispatch(mut self, dispatch: ActionDispatch) -> Self {
        self.dispatch = dispatch;
        self
    }

    fn sign(&self, body: &str) -> Option<String> {
        let secret = self.cfg.secret.as_deref()?;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(body.as_bytes());
        Some(hex_encode(&mac.finalize().into_bytes()))
    }
}

/// True when the target URL is a Discord webhook (which requires its own
/// message format instead of the raw payload).
fn is_discord(url: &str) -> bool {
    reqwest::Url::parse(url).ok().is_some_and(|u| {
        matches!(u.host_str(), Some("discord.com") | Some("discordapp.com"))
            && u.path().starts_with("/api/webhooks/")
    })
}

/// Embed accent color per risk level (RGB).
fn discord_color(level: RiskLevel) -> u32 {
    match level {
        RiskLevel::Critical => 0xB1_2A_2A,
        RiskLevel::High => 0xE6_7E_22,
        RiskLevel::Medium => 0xF1_C4_0F,
        RiskLevel::Low | RiskLevel::Info => 0x2E_CC_71,
    }
}

/// Wrap the alert into Discord's `content` + `embeds` message format.
fn discord_payload(
    evt: &Event,
    decision: &sentry_core::analysis::Decision,
    ctx: &ActionContext,
) -> serde_json::Value {
    let level = format!("{:?}", decision.analysis.risk_level).to_lowercase();
    let verdict = format!("{:?}", decision.action).to_lowercase();
    let signals = decision
        .analysis
        .signals
        .iter()
        .map(|s| format!("{:?}", s.kind))
        .collect::<Vec<_>>()
        .join(", ");
    // Discord caps each field value at 1024 chars.
    let signals = if signals.is_empty() {
        "—".to_string()
    } else if signals.len() > 1000 {
        format!("{}…", &signals[..1000])
    } else {
        signals
    };

    let http = evt.http();
    let mut fields = vec![
        json_field("IP", format!("`{}`", evt.client_ip), true),
        json_field(
            "Score",
            format!("{} ({level})", decision.analysis.risk_score),
            true,
        ),
        json_field("Verdict", verdict.clone(), true),
    ];
    if let Some(h) = http {
        fields.push(json_field("Path", format!("`{}`", h.path), true));
        if let Some(method) = &h.method {
            fields.push(json_field(
                "Method",
                format!("{method:?}").to_uppercase(),
                true,
            ));
        }
    }
    if let Some(geo) = &evt.geo {
        if let Some(country) = &geo.country {
            fields.push(json_field("Country", country.clone(), true));
        }
    }
    if let Some(asn) = evt.asn {
        fields.push(json_field("ASN", format!("AS{asn}"), true));
    }
    fields.push(json_field("Signals", signals, false));

    let mut footer = format!("event {}", evt.id);
    if let Some(id) = ctx.incident_id {
        footer.push_str(&format!(" · incident {id}"));
    }

    serde_json::json!({
        "username": "Sentry",
        "content": format!("🚨 **{}** — {} `{}`", level.to_uppercase(), verdict, evt.client_ip),
        "embeds": [{
            "title": "Sentry detection",
            "color": discord_color(decision.analysis.risk_level),
            "timestamp": evt.timestamp.to_rfc3339(),
            "fields": fields,
            "footer": {"text": footer},
        }]
    })
}

fn json_field(name: &str, value: String, inline: bool) -> serde_json::Value {
    serde_json::json!({"name": name, "value": value, "inline": inline})
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[async_trait]
impl Action for WebhookAction {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn dispatch(&self) -> ActionDispatch {
        self.dispatch
    }

    fn applies_to(&self, decision: &sentry_core::analysis::Decision) -> bool {
        self.cfg.on_levels.contains(&decision.analysis.risk_level)
            && decision.action != Verdict::Allow
    }

    async fn execute_with_context(
        &self,
        evt: &Event,
        decision: &sentry_core::analysis::Decision,
        ctx: &ActionContext,
    ) -> Result<()> {
        let payload = if is_discord(&self.cfg.url) {
            discord_payload(evt, decision, ctx)
        } else {
            serde_json::json!({
                "event_id": evt.id,
                "incident_id": ctx.incident_id,
                "timestamp": evt.timestamp,
                "client_ip": evt.client_ip.to_string(),
                "asn": evt.asn,
                "country": evt.geo.as_ref().and_then(|g| g.country.as_ref()),
                "risk_score": decision.analysis.risk_score,
                "risk_level": format!("{:?}", decision.analysis.risk_level).to_lowercase(),
                "verdict": format!("{:?}", decision.action).to_lowercase(),
                "signals": decision.analysis.signals.iter().map(|s| &s.kind).collect::<Vec<_>>(),
                "path": evt.http().map(|h| h.path.as_str()),
                "ack_url": ctx
                    .incident_id
                    .map(|id| format!("/api/incidents/{id}/ack")),
            })
        };

        let body = serde_json::to_string(&payload).unwrap_or_default();
        let mut req = self
            .http
            .post(&self.cfg.url)
            .header("content-type", "application/json");
        if let Some(sig) = self.sign(&body) {
            req = req.header("x-sentry-signature", format!("sha256={sig}"));
        }

        match req.body(body).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => warn!(status = %resp.status(), url = &self.cfg.url, "webhook non-2xx"),
            Err(e) => warn!(error = %e, url = &self.cfg.url, "webhook request failed"),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::analysis::{AnalysisResult, Signal, SignalKind};
    use sentry_core::event::{Event, HttpData, ProtocolData, SourceKind};
    use std::net::IpAddr;
    use std::str::FromStr;

    fn sample_event() -> Event {
        Event::new(
            SourceKind::Synthetic,
            IpAddr::from_str("203.0.113.7").unwrap(),
            ProtocolData::Http(HttpData {
                path: "/admin".into(),
                ..HttpData::default()
            }),
        )
    }

    fn sample_ctx(incident: Option<uuid::Uuid>) -> ActionContext {
        ActionContext {
            incident_id: incident,
        }
    }

    fn critical_decision(verdict: Verdict) -> sentry_core::analysis::Decision {
        let analysis = AnalysisResult {
            risk_level: RiskLevel::Critical,
            risk_score: 90,
            signals: vec![Signal {
                kind: SignalKind::PathTraversal,
                weight: 25,
                detail: None,
            }],
            ..Default::default()
        };
        sentry_core::analysis::Decision {
            analysis,
            action: verdict,
            override_reason: None,
            log_level: None,
        }
    }

    #[test]
    fn is_discord_matches_only_discord_webhook_urls() {
        assert!(is_discord("https://discord.com/api/webhooks/123/abc"));
        assert!(is_discord("https://discordapp.com/api/webhooks/123/abc"));
        assert!(!is_discord("https://discord.com/api/other"));
        assert!(!is_discord("https://evil.com/api/webhooks/123/abc"));
        assert!(!is_discord("https://example.com/hook"));
        assert!(!is_discord("not a url"));
    }

    #[test]
    fn discord_payload_carries_content_embed_and_fields() {
        let evt = sample_event();
        let decision = critical_decision(Verdict::Block);
        let ctx = sample_ctx(Some(uuid::Uuid::new_v4()));
        let payload = discord_payload(&evt, &decision, &ctx);

        let content = payload["content"].as_str().unwrap();
        assert!(content.contains("CRITICAL"));
        assert!(content.contains("203.0.113.7"));

        let embed = &payload["embeds"][0];
        assert_eq!(embed["color"], discord_color(RiskLevel::Critical));
        assert!(embed["timestamp"].as_str().is_some());
        let names: Vec<&str> = embed["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"IP"));
        assert!(names.contains(&"Path"));
        assert!(names.contains(&"Signals"));
        let signals = embed["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "Signals")
            .unwrap()["value"]
            .as_str()
            .unwrap();
        assert!(signals.contains("PathTraversal"));
        assert!(embed["footer"]["text"]
            .as_str()
            .unwrap()
            .starts_with("event "));
    }

    #[test]
    fn discord_payload_omits_optional_fields_and_flags_allow() {
        let evt = Event::new(
            SourceKind::Synthetic,
            IpAddr::from_str("203.0.113.7").unwrap(),
            ProtocolData::Raw(sentry_core::event::RawData {
                note: "raw".into(),
                bytes: vec![],
            }),
        );
        let analysis = AnalysisResult {
            risk_level: RiskLevel::Low,
            risk_score: 4,
            ..Default::default()
        };
        let decision = sentry_core::analysis::Decision {
            analysis,
            action: Verdict::Allow,
            override_reason: None,
            log_level: None,
        };
        let payload = discord_payload(&evt, &decision, &sample_ctx(None));
        let names: Vec<&str> = payload["embeds"][0]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(!names.contains(&"Path"));
        assert!(!names.contains(&"Country"));
        assert_eq!(payload["embeds"][0]["color"], discord_color(RiskLevel::Low));
        assert!(!payload["embeds"][0]["footer"]["text"]
            .as_str()
            .unwrap()
            .contains("incident"));
    }

    #[test]
    fn hex_encode_matches_lowercase_hex() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[tokio::test]
    async fn executes_without_error_when_server_unreachable() {
        let action = WebhookAction::new(WebhookActionConfig {
            url: "http://127.0.0.1:9/hook".into(),
            on_levels: vec![RiskLevel::High, RiskLevel::Critical],
            timeout: Duration::from_millis(200),
            secret: Some("topsecret".into()),
        });
        let analysis = sentry_core::AnalysisResult {
            risk_level: RiskLevel::Critical,
            risk_score: 90,
            ..Default::default()
        };
        let decision = sentry_core::Decision {
            analysis,
            action: Verdict::Block,
            override_reason: None,
            log_level: None,
        };
        let evt = sample_event();
        action
            .execute_with_context(&evt, &decision, &sample_ctx(Some(uuid::Uuid::new_v4())))
            .await
            .expect("webhook failures are logged, not returned");
    }

    #[test]
    fn applies_to_filters_levels_and_allow() {
        let action = WebhookAction::new(WebhookActionConfig {
            url: "http://127.0.0.1:9/hook".into(),
            on_levels: vec![RiskLevel::Critical],
            timeout: Duration::from_secs(1),
            secret: None,
        });
        let analysis = sentry_core::AnalysisResult {
            risk_level: RiskLevel::Critical,
            ..Default::default()
        };
        let decision = sentry_core::Decision {
            analysis,
            action: Verdict::Block,
            override_reason: None,
            log_level: None,
        };
        assert!(action.applies_to(&decision));
        let mut allow = decision.clone();
        allow.action = Verdict::Allow;
        assert!(!action.applies_to(&allow));
    }
}
