//! Prometheus metrics registry + `/metrics` HTTP server.
//!
//! The daemon records counters and a histogram as it processes events; the
//! server exposes them in the text exposition format at `/metrics` on the
//! configured `[metrics]` bind address (default `0.0.0.0:9100`).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use prometheus::{Encoder, Registry, TextEncoder};
use sentry_core::analysis::RiskLevel;
use sentry_core::Verdict;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::eventlog::{parse_event_query, EventLog};

/// All Prometheus metrics the daemon updates.
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    pub events_processed: prometheus::Counter,
    pub events_blocked: prometheus::Counter,
    pub dedupe_drops: prometheus::Counter,
    pub events_dropped: prometheus::CounterVec,
    pub action_queue_drops: prometheus::Counter,
    pub queue_occupancy: prometheus::GaugeVec,
    pub postgres_pressure: prometheus::Gauge,
    pub postgres_pool: prometheus::GaugeVec,
    pub persist_duration: prometheus::Histogram,
    pub overload_shed: prometheus::CounterVec,
    pub coalesced: prometheus::CounterVec,
    pub correlation_hits: prometheus::Counter,
    pub edge_block_hits: prometheus::Counter,
    pub edge_uploads_inspected: prometheus::Counter,
    pub posture_findings: prometheus::CounterVec,
    pub bot_verifications: prometheus::CounterVec,
    pub edge_challenge: prometheus::CounterVec,
    pub edge_tls_handshakes: prometheus::CounterVec,
    pub edge_tls_failures: prometheus::Counter,
    pub edge_tls_sni_mismatches: prometheus::Counter,
    pub edge_tls_cert_not_after: prometheus::Gauge,
    pub protocol_violations: prometheus::CounterVec,
    pub protocol_frames: prometheus::CounterVec,
    pub block_table_size: prometheus::Gauge,
    pub signal_kinds: prometheus::CounterVec,
    pub signals: prometheus::CounterVec,
    pub actions: prometheus::CounterVec,
    pub pipeline_duration: prometheus::Histogram,
    pub ingest_duration: prometheus::Histogram,
    pub fork_rescore_duration: prometheus::HistogramVec,
    pub action_dispatch_duration: prometheus::HistogramVec,
    pub edge_request_duration: prometheus::Histogram,
    pub feed_entries: prometheus::GaugeVec,
    pub feed_up: prometheus::GaugeVec,
    pub feed_refresh_ts: prometheus::GaugeVec,
    instance_info: prometheus::GaugeVec,
}

impl Metrics {
    /// Build a fresh registry with all sentry counters/histograms registered.
    pub fn new() -> Self {
        let registry = Arc::new(Registry::new());
        let events_processed = prometheus::Counter::new(
            "sentry_events_processed_total",
            "Total events processed by the pipeline.",
        )
        .unwrap();
        let events_blocked = prometheus::Counter::new(
            "sentry_events_blocked_total",
            "Events whose final verdict was not allow.",
        )
        .unwrap();
        let dedupe_drops = prometheus::Counter::new(
            "sentry_dedupe_drops_total",
            "Events dropped by the deduplication cache.",
        )
        .unwrap();
        let events_dropped = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_events_dropped_total",
                "Events dropped because a channel was full, by source.",
            ),
            &["source"],
        )
        .unwrap();
        let action_queue_drops = prometheus::Counter::new(
            "sentry_action_queue_drops_total",
            "Deferred actions shed because the post-processing queue was \
             full (the events themselves are still persisted and counted).",
        )
        .unwrap();
        let queue_occupancy = prometheus::GaugeVec::new(
            prometheus::Opts::new(
                "sentry_queue_occupancy",
                "Filled fraction (0-1) of each internal queue: fan_in, \
                 actions, persist — the overload pressure inputs.",
            ),
            &["queue"],
        )
        .unwrap();
        let postgres_pressure = prometheus::Gauge::new(
            "sentry_postgres_pressure",
            "1 while Postgres write latency or pool saturation trips the \
             overload pressure, 0 otherwise (hysteresis in [overload]).",
        )
        .unwrap();
        let postgres_pool = prometheus::GaugeVec::new(
            prometheus::Opts::new(
                "sentry_postgres_pool_connections",
                "Postgres pool connections by state: acquired | idle | max.",
            ),
            &["state"],
        )
        .unwrap();
        let persist_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "sentry_persist_duration_seconds",
                "Duration of one batched event persistence round-trip.",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
        )
        .unwrap();
        let overload_shed = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_overload_shed_total",
                "Low-priority telemetry dropped by the overload response, \
                 by tier (persist | eventlog | print) — security events are \
                 never shed.",
            ),
            &["tier"],
        )
        .unwrap();
        let coalesced = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_coalesced_requests_total",
                "Repeated requests collapsed by coalescing instead of being \
                 persisted individually, by kind (benign | tcp_syn).",
            ),
            &["kind"],
        )
        .unwrap();
        let correlation_hits = prometheus::Counter::new(
            "sentry_correlation_hits_total",
            "Attacks correlated with a recent scan from a neighboring IP \
             (same /24, /64 or ASN) — F3.10 shot-calling pattern.",
        )
        .unwrap();
        let edge_block_hits = prometheus::Counter::new(
            "sentry_edge_block_hits_total",
            "Connections denied by the inline edge fast-path for IPs on the \
             block table (sticky blocks enforced before the pipeline).",
        )
        .unwrap();
        let edge_uploads_inspected = prometheus::Counter::new(
            "sentry_edge_uploads_inspected_total",
            "Requests whose body went through upload inspection (F10) — \
             multipart parts parsed and upload heuristics fed.",
        )
        .unwrap();
        let posture_findings = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_posture_findings_total",
                "Web security posture advisories observed on origin responses \
                 (missing/weak CSP, HSTS, COOP, frame protection, Trusted \
                 Types, nosniff, referrer policy) — F11, advisory only.",
            ),
            &["check", "host"],
        )
        .unwrap();
        let bot_verifications = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_bot_verifications_total",
                "rDNS bot verifications performed, by result (verified | \
                 spoofed | error) — F7.7.",
            ),
            &["result"],
        )
        .unwrap();
        let edge_challenge = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_edge_challenge_total",
                "Inline-edge JS challenges, by result (served | passed | \
                 bot_bypass) — F7.8.",
            ),
            &["result"],
        )
        .unwrap();
        let edge_tls_handshakes = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_edge_tls_handshakes_total",
                "Completed TLS handshakes on the inline edge, by negotiated \
                 version (F8).",
            ),
            &["version"],
        )
        .unwrap();
        let edge_tls_failures = prometheus::Counter::new(
            "sentry_edge_tls_handshake_failures_total",
            "TLS acceptor failures: malformed records, truncated ClientHellos, \
             failed or timed-out handshakes (F8).",
        )
        .unwrap();
        let edge_tls_sni_mismatches = prometheus::Counter::new(
            "sentry_edge_tls_sni_mismatch_total",
            "Handshakes whose SNI is missing or not in [edge] \
             tls_allowed_hosts (F8).",
        )
        .unwrap();
        let edge_tls_cert_not_after = prometheus::Gauge::new(
            "sentry_edge_tls_cert_not_after",
            "Unix timestamp of the edge TLS certificate's notAfter, \
             refreshed daily (F8).",
        )
        .unwrap();
        let block_table_size = prometheus::Gauge::new(
            "sentry_block_table_size",
            "IPs currently held in the in-memory block table.",
        )
        .unwrap();
        let protocol_violations = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_protocol_violations_total",
                "Protocol schema violations, by schema and policy (F9).",
            ),
            &["schema", "policy"],
        )
        .unwrap();
        let protocol_frames = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_protocol_frames_total",
                "Frames validated against a protocol schema (F9).",
            ),
            &["schema"],
        )
        .unwrap();
        let signals = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_signals_total",
                "Events processed, by risk level (label `kind`, kept for compatibility).",
            ),
            &["kind"],
        )
        .unwrap();
        let signal_kinds = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_signal_kinds_total",
                "Pipeline signals emitted, by kind (snake_case SignalKind, \
                 same keys as [scorer.weights]).",
            ),
            &["kind"],
        )
        .unwrap();
        let actions = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_actions_total",
                "Actions executed by the registry, by name and verdict.",
            ),
            &["action", "verdict"],
        )
        .unwrap();
        let pipeline_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "sentry_pipeline_duration_seconds",
                "Time spent processing one event through the pipeline.",
            )
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]),
        )
        .unwrap();
        let ingest_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "sentry_ingest_duration_seconds",
                "End-to-end time per ingested event: dedupe, pipeline, \
                 inline AI rescoring and action dispatch.",
            )
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0,
            ]),
        )
        .unwrap();
        let fork_rescore_duration = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(
                "sentry_fork_rescore_duration_seconds",
                "Duration of async fork rescoring passes, by fork \
                 (ai | llm | ip_lookup).",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["fork"],
        )
        .unwrap();
        let action_dispatch_duration = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(
                "sentry_action_dispatch_duration_seconds",
                "Time spent dispatching one action execution, by action name.",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["action"],
        )
        .unwrap();
        let edge_request_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "sentry_edge_request_duration_seconds",
                "Time spent handling one request in the inline edge, from \
                 receipt to response (fast-path denials included).",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
        )
        .unwrap();
        let feed_entries = prometheus::GaugeVec::new(
            prometheus::Opts::new(
                "sentry_feed_entries",
                "Entries currently held per reputation feed.",
            ),
            &["feed"],
        )
        .unwrap();
        let feed_up = prometheus::GaugeVec::new(
            prometheus::Opts::new(
                "sentry_feed_up",
                "1 when the feed's last refresh succeeded, 0 when it errored.",
            ),
            &["feed"],
        )
        .unwrap();
        let feed_refresh_ts = prometheus::GaugeVec::new(
            prometheus::Opts::new(
                "sentry_feed_last_refresh_timestamp_seconds",
                "Unix timestamp of the last successful refresh per feed.",
            ),
            &["feed"],
        )
        .unwrap();
        let instance_info = prometheus::GaugeVec::new(
            prometheus::Opts::new(
                "sentry_instance_info",
                "Always 1; identifies this daemon instance (F4.7 multi-node).",
            ),
            &["instance"],
        )
        .unwrap();

        for m in [
            &events_processed,
            &events_blocked,
            &dedupe_drops,
            &action_queue_drops,
            &correlation_hits,
            &edge_block_hits,
            &edge_uploads_inspected,
        ] {
            registry.register(Box::new(m.clone())).ok();
        }
        for m in [&queue_occupancy, &postgres_pool] {
            registry
                .register(Box::new(m.clone()))
                .map_err(|e| warn!(error = %e, "register gauge vec"))
                .ok();
        }
        for m in [&overload_shed, &coalesced] {
            registry
                .register(Box::new(m.clone()))
                .map_err(|e| warn!(error = %e, "register counter vec"))
                .ok();
        }
        registry
            .register(Box::new(postgres_pressure.clone()))
            .map_err(|e| warn!(error = %e, "register postgres pressure"))
            .ok();
        registry
            .register(Box::new(events_dropped.clone()))
            .map_err(|e| warn!(error = %e, "register events dropped"))
            .ok();
        registry
            .register(Box::new(persist_duration.clone()))
            .map_err(|e| warn!(error = %e, "register persist duration"))
            .ok();
        registry.register(Box::new(block_table_size.clone())).ok();
        registry
            .register(Box::new(bot_verifications.clone()))
            .map_err(|e| warn!(error = %e, "register bot verifications"))
            .ok();
        registry
            .register(Box::new(edge_challenge.clone()))
            .map_err(|e| warn!(error = %e, "register edge challenge"))
            .ok();
        registry
            .register(Box::new(edge_tls_handshakes.clone()))
            .map_err(|e| warn!(error = %e, "register edge tls handshakes"))
            .ok();
        for m in [&edge_tls_failures, &edge_tls_sni_mismatches] {
            registry.register(Box::new(m.clone())).ok();
        }
        registry
            .register(Box::new(protocol_violations.clone()))
            .map_err(|e| warn!(error = %e, "register protocol violations"))
            .ok();
        registry
            .register(Box::new(protocol_frames.clone()))
            .map_err(|e| warn!(error = %e, "register protocol frames"))
            .ok();
        registry
            .register(Box::new(edge_tls_cert_not_after.clone()))
            .ok();
        registry
            .register(Box::new(posture_findings.clone()))
            .map_err(|e| warn!(error = %e, "register posture findings"))
            .ok();
        registry
            .register(Box::new(signals.clone()))
            .map_err(|e| warn!(error = %e, "register signals"))
            .ok();
        registry
            .register(Box::new(signal_kinds.clone()))
            .map_err(|e| warn!(error = %e, "register signal kinds"))
            .ok();
        registry
            .register(Box::new(actions.clone()))
            .map_err(|e| warn!(error = %e, "register actions"))
            .ok();
        registry
            .register(Box::new(pipeline_duration.clone()))
            .map_err(|e| warn!(error = %e, "register histogram"))
            .ok();
        for m in [&ingest_duration, &edge_request_duration] {
            registry
                .register(Box::new(m.clone()))
                .map_err(|e| warn!(error = %e, "register duration histogram"))
                .ok();
        }
        for (m, name) in [
            (&fork_rescore_duration, "fork rescore"),
            (&action_dispatch_duration, "action dispatch"),
        ] {
            registry
                .register(Box::new(m.clone()))
                .map_err(|e| warn!(error = %e, "register {name} histogram"))
                .ok();
        }
        for m in [&feed_entries, &feed_up, &feed_refresh_ts, &instance_info] {
            registry
                .register(Box::new(m.clone()))
                .map_err(|e| warn!(error = %e, "register feed metrics"))
                .ok();
        }

        Self {
            registry,
            events_processed,
            events_blocked,
            dedupe_drops,
            events_dropped,
            action_queue_drops,
            queue_occupancy,
            postgres_pressure,
            postgres_pool,
            persist_duration,
            overload_shed,
            coalesced,
            correlation_hits,
            edge_block_hits,
            edge_uploads_inspected,
            posture_findings,
            bot_verifications,
            edge_challenge,
            edge_tls_handshakes,
            edge_tls_failures,
            edge_tls_sni_mismatches,
            edge_tls_cert_not_after,
            protocol_violations,
            protocol_frames,
            block_table_size,
            signal_kinds,
            signals,
            actions,
            pipeline_duration,
            ingest_duration,
            fork_rescore_duration,
            action_dispatch_duration,
            edge_request_duration,
            feed_entries,
            feed_up,
            feed_refresh_ts,
            instance_info,
        }
    }

    /// Stamp this daemon's instance identity as a metric label (F4.7).
    pub fn set_instance(&self, instance: &str) {
        self.instance_info.with_label_values(&[instance]).set(1.0);
    }

    /// Record one processed event.
    pub fn record_event(&self, verdict: Verdict, level: RiskLevel, duration: std::time::Duration) {
        self.events_processed.inc();
        if verdict != Verdict::Allow {
            self.events_blocked.inc();
        }
        let level_str = match level {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        };
        self.signals.with_label_values(&[level_str]).inc();
        self.pipeline_duration.observe(duration.as_secs_f64());
    }

    /// Record the end-to-end ingest time for one event (dedupe → pipeline →
    /// inline AI → action dispatch).
    pub fn record_ingest(&self, duration: std::time::Duration) {
        self.ingest_duration.observe(duration.as_secs_f64());
    }

    /// Record how long an async fork took to rescore an event
    /// (`ai` | `llm` | `ip_lookup`).
    pub fn record_fork(&self, fork: &str, duration: std::time::Duration) {
        self.fork_rescore_duration
            .with_label_values(&[fork])
            .observe(duration.as_secs_f64());
    }

    /// Record how long one action dispatch took.
    pub fn record_action_dispatch(&self, action: &str, duration: std::time::Duration) {
        self.action_dispatch_duration
            .with_label_values(&[action])
            .observe(duration.as_secs_f64());
    }

    /// Render the full registry in Prometheus text exposition format.
    pub fn gather(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4096);
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buf).ok();
        buf
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

type BodyResponse = hyper::Response<Full<Bytes>>;

fn text_response(status: StatusCode, content_type: &str, body: Vec<u8>) -> BodyResponse {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Resolve one request against the routes (pure, unit-testable).
fn route(m: &Metrics, log: &EventLog, uri: &hyper::Uri) -> BodyResponse {
    match uri.path() {
        "/metrics" => text_response(StatusCode::OK, "text/plain; version=0.0.4", m.gather()),
        "/api/events" => {
            let q = parse_event_query(uri.query().unwrap_or(""));
            let rows = log.query(q.limit, q.level.as_deref(), q.verdict.as_deref());
            let body = serde_json::to_vec(&rows).unwrap_or_else(|_| b"[]".to_vec());
            text_response(StatusCode::OK, "application/json", body)
        }
        _ => text_response(StatusCode::NOT_FOUND, "text/plain", b"not found\n".to_vec()),
    }
}

/// Start the `/metrics` HTTP server on `addr`. Runs until the task is aborted.
///
/// Routes: `GET /metrics` (Prometheus text format), `GET /api/events`
/// (recent events as JSON for external dashboards — `limit`, `level`,
/// `verdict` query params), anything else → 404.
pub async fn serve(metrics: Metrics, event_log: EventLog, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!(addr = %addr, "metrics server listening on /metrics");
            l
        }
        Err(e) => {
            warn!(error = %e, addr = %addr, "failed to bind metrics server");
            return;
        }
    };

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "metrics accept failed");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let metrics = metrics.clone();
        let event_log = event_log.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let m = metrics.clone();
                let log = event_log.clone();
                async move {
                    let resp = route(&m, &log, req.uri());
                    Ok::<_, Infallible>(resp)
                }
            });
            if let Err(e) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, service)
                .await
            {
                warn!(error = %e, "metrics connection error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::EventSummary;
    use http_body_util::BodyExt;
    use sentry_core::analysis::{AnalysisResult, Decision, RiskLevel, Verdict};
    use sentry_core::event::{Event, ProtocolData, RawData, SourceKind};

    fn blocked_summary() -> EventSummary {
        EventSummary::from_processed(&sentry_core::ProcessedEvent {
            event: Event::new(
                SourceKind::Synthetic,
                "203.0.113.5".parse().unwrap(),
                ProtocolData::Raw(RawData {
                    note: "test".into(),
                    bytes: vec![],
                }),
            ),
            analysis: AnalysisResult {
                risk_score: 90,
                risk_level: RiskLevel::Critical,
                signals: vec![],
                verdict: Verdict::Block,
            },
            decision: Decision {
                analysis: AnalysisResult::default(),
                action: Verdict::Block,
                override_reason: None,
                log_level: None,
            },
            rule_hit: None,
            process_us: None,
        })
    }

    #[test]
    fn route_serves_metrics_text() {
        let resp = route(
            &Metrics::new(),
            &EventLog::new(),
            &"/metrics".parse().unwrap(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn route_serves_events_json_with_filters() {
        let log = EventLog::new();
        log.push(blocked_summary());
        let uri: hyper::Uri = "/api/events?limit=10&level=critical".parse().unwrap();
        let resp = route(&Metrics::new(), &log, &uri);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&body).unwrap().contains("203.0.113.5"));

        let uri: hyper::Uri = "/api/events?verdict=allow".parse().unwrap();
        let resp = route(&Metrics::new(), &log, &uri);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"[]");
    }

    #[test]
    fn route_unknown_path_is_404() {
        let resp = route(&Metrics::new(), &EventLog::new(), &"/nope".parse().unwrap());
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn drop_counters_are_exposed() {
        let m = Metrics::new();
        m.events_dropped.with_label_values(&["tcp"]).inc();
        m.action_queue_drops.inc();
        m.queue_occupancy.with_label_values(&["persist"]).set(0.42);
        m.postgres_pressure.set(1.0);
        m.postgres_pool.with_label_values(&["acquired"]).set(3.0);
        m.persist_duration.observe(0.012);
        m.overload_shed.with_label_values(&["persist"]).inc();
        m.coalesced.with_label_values(&["benign"]).inc();
        let text = String::from_utf8(m.gather()).unwrap();
        assert!(text.contains("sentry_events_dropped_total{source=\"tcp\"}"));
        assert!(text.contains("sentry_action_queue_drops_total"));
        assert!(text.contains("sentry_queue_occupancy{queue=\"persist\"} 0.42"));
        assert!(text.contains("sentry_postgres_pressure 1"));
        assert!(text.contains("sentry_postgres_pool_connections{state=\"acquired\"} 3"));
        assert!(text.contains("sentry_persist_duration_seconds_bucket"));
        assert!(text.contains("sentry_overload_shed_total{tier=\"persist\"}"));
        assert!(text.contains("sentry_coalesced_requests_total{kind=\"benign\"}"));
    }

    #[test]
    fn timing_histograms_are_exposed() {
        let m = Metrics::new();
        m.record_event(
            Verdict::Block,
            RiskLevel::High,
            std::time::Duration::from_micros(420),
        );
        m.record_ingest(std::time::Duration::from_micros(900));
        m.record_fork("llm", std::time::Duration::from_millis(1500));
        m.record_action_dispatch("webhook", std::time::Duration::from_millis(30));
        m.edge_request_duration.observe(0.042);
        let text = String::from_utf8(m.gather()).unwrap();
        for name in [
            "sentry_pipeline_duration_seconds_bucket",
            "sentry_ingest_duration_seconds_bucket",
            "sentry_fork_rescore_duration_seconds_bucket{fork=\"llm\",le=",
            "sentry_action_dispatch_duration_seconds_bucket{action=\"webhook\",le=",
            "sentry_edge_request_duration_seconds_bucket",
        ] {
            assert!(
                text.contains(name),
                "missing {name} in exposition:\n{}",
                text.lines()
                    .filter(|l| l.contains(name.split('{').next().unwrap()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
}
