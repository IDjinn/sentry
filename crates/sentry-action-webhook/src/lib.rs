//! Webhook alert action.
//!
//! Posts a JSON payload to a configured URL (Discord, Slack, Telegram, custom
//! endpoint) when a decision reaches the configured risk levels.
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
use sentry_core::action::{Action, ActionContext};
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
}

impl WebhookAction {
    /// Create a new webhook action.
    pub fn new(cfg: WebhookActionConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .expect("reqwest client");
        Self { cfg, http }
    }

    fn sign(&self, body: &str) -> Option<String> {
        let secret = self.cfg.secret.as_deref()?;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(body.as_bytes());
        Some(hex_encode(&mac.finalize().into_bytes()))
    }
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
        let payload = serde_json::json!({
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
        });

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
        let mut analysis = sentry_core::AnalysisResult::default();
        analysis.risk_level = RiskLevel::Critical;
        analysis.risk_score = 90;
        let decision = sentry_core::Decision {
            analysis,
            action: Verdict::Block,
            override_reason: None,
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
        let mut analysis = sentry_core::AnalysisResult::default();
        analysis.risk_level = RiskLevel::Critical;
        let decision = sentry_core::Decision {
            analysis,
            action: Verdict::Block,
            override_reason: None,
        };
        assert!(action.applies_to(&decision));
        let mut allow = decision.clone();
        allow.action = Verdict::Allow;
        assert!(!action.applies_to(&allow));
    }
}
