//! Recent-events log served as JSON for external dashboards (Grafana).
//!
//! The Prometheus endpoint only exposes aggregates; dashboards that want
//! per-event detail (IP, path, verdict, signals) query the ring buffer
//! below via `GET /api/events` on the same `[metrics]` HTTP server. The
//! buffer is bounded and lives in memory — persistence stays in Postgres,
//! this is a live "last N events" view for panels and triage.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use sentry_core::analysis::SignalKind;
use sentry_core::event::ProtocolKind;
use sentry_core::ProcessedEvent;
use serde::Serialize;

/// Ring buffer capacity (events). At ~500 bytes per summary this stays
/// well under 1 MiB.
const CAP: usize = 1024;

/// Label for a signal kind (snake_case, matching `[scorer.weights]` keys
/// and the `sentry_signal_kinds_total` metric label).
pub fn signal_kind_label(kind: &SignalKind) -> String {
    serde_json::to_string(kind)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// One signal condensed for the event log.
#[derive(Debug, Clone, Serialize)]
pub struct SignalSummary {
    pub kind: String,
    pub weight: u8,
    pub detail: Option<String>,
}

/// Flat per-event summary (Grafana-friendly: no nested protocol payloads).
///
/// Every field is always serialized (`null` instead of omitted): consumers
/// like the Grafana Infinity datasource infer columns from the first row,
/// so the key set must be identical across events regardless of protocol.
#[derive(Debug, Clone, Serialize)]
pub struct EventSummary {
    pub ts: String,
    pub ip: String,
    pub source: String,
    pub protocol: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub user_agent: Option<String>,
    pub verdict: String,
    pub risk_level: String,
    pub score: u8,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub rule_hit: Option<String>,
    pub signals: Vec<SignalSummary>,
}

impl EventSummary {
    /// Condense a processed event for the log.
    pub fn from_processed(pe: &ProcessedEvent) -> Self {
        let evt = &pe.event;
        let http = evt.http();
        let signals = pe
            .analysis
            .signals
            .iter()
            .take(8)
            .map(|s| SignalSummary {
                kind: signal_kind_label(&s.kind),
                weight: s.weight,
                detail: s.detail.as_deref().map(|d| truncate(d, 160)),
            })
            .collect();
        Self {
            ts: evt.timestamp.to_rfc3339(),
            ip: evt.client_ip.to_string(),
            source: evt.source.as_str().to_string(),
            protocol: protocol_label(evt.protocol_kind()),
            method: http.and_then(|h| h.method).map(|m| {
                serde_json::to_string(&m)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string()
            }),
            path: http.map(|h| truncate(&h.path, 256)),
            host: http.and_then(|h| h.host.clone()),
            status: http.and_then(|h| h.status),
            user_agent: http.and_then(|h| h.user_agent.as_deref().map(|u| truncate(u, 128))),
            verdict: serde_json::to_string(&pe.decision.action)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string(),
            risk_level: serde_json::to_string(&pe.analysis.risk_level)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string(),
            score: pe.analysis.risk_score,
            country: evt.geo.as_ref().and_then(|g| g.country.clone()),
            asn: evt.asn,
            rule_hit: pe.rule_hit.clone(),
            signals,
        }
    }
}

fn protocol_label(kind: ProtocolKind) -> String {
    match kind {
        ProtocolKind::Http => "http",
        ProtocolKind::Http3 => "http3",
        ProtocolKind::Tcp => "tcp",
        ProtocolKind::Udp => "udp",
        ProtocolKind::Tls => "tls",
        ProtocolKind::Other => "other",
    }
    .to_string()
}

/// Filters accepted by `GET /api/events`.
#[derive(Debug, Default, PartialEq)]
pub struct EventQuery {
    pub limit: usize,
    pub level: Option<String>,
    pub verdict: Option<String>,
}

/// Parse a raw query string (`limit=50&level=high&verdict=block`).
pub fn parse_event_query(query: &str) -> EventQuery {
    let mut q = EventQuery {
        limit: 100,
        ..EventQuery::default()
    };
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "limit" => {
                q.limit = value.parse().unwrap_or(100).clamp(1, CAP);
            }
            "level" => q.level = Some(value.to_ascii_lowercase()),
            "verdict" => q.verdict = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    q
}

/// Bounded in-memory log of the most recent processed events.
#[derive(Debug, Clone, Default)]
pub struct EventLog {
    inner: Arc<RwLock<VecDeque<EventSummary>>>,
}

impl EventLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a processed event, evicting the oldest when full.
    pub fn push(&self, summary: EventSummary) {
        let mut inner = self.inner.write().unwrap();
        if inner.len() >= CAP {
            inner.pop_front();
        }
        inner.push_back(summary);
    }

    /// Newest-first query with optional level/verdict filters.
    pub fn query(
        &self,
        limit: usize,
        level: Option<&str>,
        verdict: Option<&str>,
    ) -> Vec<EventSummary> {
        let inner = self.inner.read().unwrap();
        inner
            .iter()
            .rev()
            .filter(|e| {
                level.map_or(true, |l| e.risk_level == l)
                    && verdict.map_or(true, |v| e.verdict == v)
            })
            .take(limit.max(1))
            .cloned()
            .collect()
    }

    /// Number of events currently held.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Whether the log holds no events.
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::analysis::{AnalysisResult, Decision, RiskLevel, Signal, Verdict};
    use sentry_core::event::{Event, HttpData, ProtocolData, SourceKind};

    fn http_evt(ip: &str, path: &str, status: Option<u16>) -> ProcessedEvent {
        let evt = Event::new(
            SourceKind::HttpProxy,
            ip.parse().unwrap(),
            ProtocolData::Http(HttpData {
                method: Some(sentry_core::event::HttpMethod::Get),
                path: path.to_string(),
                status,
                ..Default::default()
            }),
        );
        let analysis = AnalysisResult {
            risk_score: 85,
            risk_level: RiskLevel::High,
            signals: vec![Signal {
                kind: SignalKind::SqlInjection,
                weight: 60,
                detail: None,
            }],
            verdict: Verdict::Block,
        };
        ProcessedEvent {
            event: evt,
            analysis,
            decision: Decision {
                analysis: AnalysisResult::default(),
                action: Verdict::Block,
                override_reason: None,
                log_level: None,
            },
            rule_hit: None,
        }
    }

    #[test]
    fn push_then_query_returns_newest_first() {
        let log = EventLog::new();
        log.push(EventSummary::from_processed(&http_evt(
            "10.0.0.1", "/first", None,
        )));
        log.push(EventSummary::from_processed(&http_evt(
            "10.0.0.2", "/second", None,
        )));
        let rows = log.query(10, None, None);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].path.as_deref(), Some("/second"));
        assert_eq!(rows[1].path.as_deref(), Some("/first"));
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let log = EventLog::new();
        for i in 0..(CAP + 10) {
            log.push(EventSummary::from_processed(&http_evt(
                "10.0.0.1",
                &format!("/{i}"),
                None,
            )));
        }
        assert_eq!(log.len(), CAP);
        let rows = log.query(1, None, None);
        assert_eq!(rows[0].path.as_deref(), Some(&*format!("/{}", CAP + 9)));
    }

    #[test]
    fn filters_by_level_and_verdict() {
        let log = EventLog::new();
        log.push(EventSummary::from_processed(&http_evt(
            "10.0.0.1", "/a", None,
        )));
        let rows = log.query(10, Some("high"), None);
        assert_eq!(rows.len(), 1);
        let rows = log.query(10, None, Some("block"));
        assert_eq!(rows.len(), 1);
        assert!(log.query(10, Some("critical"), None).is_empty());
        assert!(log.query(10, None, Some("allow")).is_empty());
    }

    #[test]
    fn query_parse_clamps_limit_and_lowercases_filters() {
        let q = parse_event_query("limit=99999&level=HIGH&verdict=Block&junk=1");
        assert_eq!(q.limit, CAP);
        assert_eq!(q.level.as_deref(), Some("high"));
        assert_eq!(q.verdict.as_deref(), Some("block"));
        let empty = parse_event_query("");
        assert_eq!(empty.limit, 100);
        assert_eq!(empty.level, None);
        assert_eq!(empty.verdict, None);
    }

    #[test]
    fn summary_flattens_http_fields() {
        let s = EventSummary::from_processed(&http_evt("203.0.113.9", "/admin", Some(404)));
        assert_eq!(s.ip, "203.0.113.9");
        assert_eq!(s.source, "http_proxy");
        assert_eq!(s.protocol, "http");
        assert_eq!(s.method.as_deref(), Some("GET"));
        assert_eq!(s.status, Some(404));
        assert_eq!(s.verdict, "block");
        assert_eq!(s.risk_level, "high");
        assert_eq!(s.score, 85);
        assert_eq!(s.signals[0].kind, "sql_injection");
        assert_eq!(s.signals[0].weight, 60);
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"verdict\":\"block\""));
    }

    #[test]
    fn summary_serializes_stable_key_set() {
        let keys = |s: &EventSummary| {
            let v = serde_json::to_value(s).unwrap();
            v.as_object().unwrap().keys().cloned().collect::<Vec<_>>()
        };
        let http = EventSummary::from_processed(&http_evt("203.0.113.9", "/a", Some(404)));
        let raw = EventSummary::from_processed(&ProcessedEvent {
            event: Event::new(
                SourceKind::Synthetic,
                "10.0.0.1".parse().unwrap(),
                ProtocolData::Raw(sentry_core::event::RawData {
                    note: "x".into(),
                    bytes: vec![],
                }),
            ),
            analysis: AnalysisResult::default(),
            decision: Decision {
                analysis: AnalysisResult::default(),
                action: Verdict::Allow,
                override_reason: None,
                log_level: None,
            },
            rule_hit: None,
        });
        assert_eq!(keys(&http), keys(&raw));
        let v = serde_json::to_value(&raw).unwrap();
        for k in [
            "ts",
            "ip",
            "source",
            "protocol",
            "method",
            "path",
            "host",
            "status",
            "user_agent",
            "verdict",
            "risk_level",
            "score",
            "country",
            "asn",
            "rule_hit",
            "signals",
        ] {
            assert!(v.get(k).is_some(), "missing key {k}");
        }
    }

    #[test]
    fn long_fields_are_truncated() {
        let evt = Event::new(
            SourceKind::HttpProxy,
            "10.0.0.1".parse().unwrap(),
            ProtocolData::Http(HttpData {
                path: "a".repeat(500),
                user_agent: Some("b".repeat(300)),
                ..Default::default()
            }),
        );
        let pe = ProcessedEvent {
            event: evt,
            analysis: AnalysisResult::default(),
            decision: Decision {
                analysis: AnalysisResult::default(),
                action: Verdict::Allow,
                override_reason: None,
                log_level: None,
            },
            rule_hit: None,
        };
        let s = EventSummary::from_processed(&pe);
        assert_eq!(s.path.as_ref().unwrap().chars().count(), 256);
        assert_eq!(s.user_agent.as_ref().unwrap().chars().count(), 128);
    }
}
