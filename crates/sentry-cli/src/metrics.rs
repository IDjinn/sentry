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

/// All Prometheus metrics the daemon updates.
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    pub events_processed: prometheus::Counter,
    pub events_blocked: prometheus::Counter,
    pub dedupe_drops: prometheus::Counter,
    pub correlation_hits: prometheus::Counter,
    pub signals: prometheus::CounterVec,
    pub actions: prometheus::CounterVec,
    pub pipeline_duration: prometheus::Histogram,
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
        let correlation_hits = prometheus::Counter::new(
            "sentry_correlation_hits_total",
            "Attacks correlated with a recent scan from a neighboring IP \
             (same /24, /64 or ASN) — F3.10 shot-calling pattern.",
        )
        .unwrap();
        let signals = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "sentry_signals_total",
                "Signals emitted by the pipeline, by kind.",
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
            &correlation_hits,
        ] {
            registry.register(Box::new(m.clone())).ok();
        }
        registry
            .register(Box::new(signals.clone()))
            .map_err(|e| warn!(error = %e, "register signals"))
            .ok();
        registry
            .register(Box::new(actions.clone()))
            .map_err(|e| warn!(error = %e, "register actions"))
            .ok();
        registry
            .register(Box::new(pipeline_duration.clone()))
            .map_err(|e| warn!(error = %e, "register histogram"))
            .ok();
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
            correlation_hits,
            signals,
            actions,
            pipeline_duration,
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

/// Start the `/metrics` HTTP server on `addr`. Runs until the task is aborted.
pub async fn serve(metrics: Metrics, addr: SocketAddr) {
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
        tokio::spawn(async move {
            let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                let m = metrics.clone();
                async move {
                    if _req.uri().path() == "/metrics" {
                        let body = m.gather();
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain; version=0.0.4")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::from_static(b"not found\n")))
                            .unwrap())
                    }
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
