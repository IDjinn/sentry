//! Webhook alert action.
//!
//! Posts a JSON payload to a configured URL (Discord, Slack, Telegram, custom
//! endpoint) when a decision reaches the configured risk levels.

#![forbid(unsafe_code)]

use std::time::Duration;

use async_trait::async_trait;
use sentry_core::action::Action;
use sentry_core::analysis::{RiskLevel, Verdict};
use sentry_core::error::Result;
use sentry_core::event::Event;
use tracing::warn;

/// Webhook action configuration.
#[derive(Debug, Clone)]
pub struct WebhookActionConfig {
    /// Target URL.
    pub url: String,
    /// Risk levels that trigger the webhook (`["high", "critical"]`).
    pub on_levels: Vec<RiskLevel>,
    /// Request timeout.
    pub timeout: Duration,
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

    async fn execute(&self, evt: &Event, decision: &sentry_core::analysis::Decision) -> Result<()> {
        let payload = serde_json::json!({
            "event_id": evt.id,
            "timestamp": evt.timestamp,
            "client_ip": evt.client_ip.to_string(),
            "asn": evt.asn,
            "country": evt.geo.as_ref().and_then(|g| g.country.as_ref()),
            "risk_score": decision.analysis.risk_score,
            "risk_level": format!("{:?}", decision.analysis.risk_level).to_lowercase(),
            "verdict": format!("{:?}", decision.action).to_lowercase(),
            "signals": decision.analysis.signals.iter().map(|s| &s.kind).collect::<Vec<_>>(),
            "path": evt.http().map(|h| h.path.as_str()),
        });

        match self.http.post(&self.cfg.url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => warn!(status = %resp.status(), url = &self.cfg.url, "webhook non-2xx"),
            Err(e) => warn!(error = %e, url = &self.cfg.url, "webhook request failed"),
        }

        Ok(())
    }
}
