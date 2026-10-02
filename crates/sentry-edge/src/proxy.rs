//! `edge-http` — inline reverse proxy (F3.9a).
//!
//! Sentry owns the public port: every request is scored through the pipeline
//! *before* the backend sees it. Verdict mapping: `Block`/`Quarantine` → 403,
//! `RateLimit` → 429, `Challenge` → challenge page, `Allow` → proxied.
//! Decided events are pushed to `decided` so the host (daemon) can persist
//! them and fire actions exactly once — the pipeline is shared, so stateful
//! trackers never double-count.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::pages;
use crate::EdgeRuntime;
use uuid::Uuid;

/// Inline proxy configuration.
#[derive(Debug, Clone)]
pub struct EdgeProxyConfig {
    /// Listen address (`0.0.0.0:80`). An empty string disables the plain
    /// listener (HTTPS-only edge).
    pub listen: String,
    /// Protected upstream base URL (`http://127.0.0.1:8080`).
    pub upstream: String,
    /// Path used for the mandatory startup health check (default `/`).
    pub health_path: String,
    /// Health check timeout in seconds (default 5).
    pub health_timeout_secs: u64,
    /// HTTPS front (F8): `None` serves plain HTTP only.
    pub tls: Option<TlsEdgeConfig>,
}

/// HTTPS front settings (F8) — built by the daemon from `[edge] tls_*`.
#[derive(Debug, Clone, Default)]
pub struct TlsEdgeConfig {
    /// HTTPS listen address (`0.0.0.0:443`).
    pub listen: String,
    /// Certificate PEM file.
    pub cert: PathBuf,
    /// Private key PEM file.
    pub key: PathBuf,
    /// Answer plain-HTTP with a 301 to HTTPS. The redirect runs after the
    /// pipeline, so port-80 traffic keeps being monitored and enforced.
    pub redirect_https: bool,
    /// ClientHello SNI allowlist; empty disables the mismatch check.
    pub allowed_hosts: Vec<String>,
    /// Emit one `TlsHandshake` event per completed handshake.
    pub handshake_events: bool,
}

impl Default for EdgeProxyConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:80".to_string(),
            upstream: "http://127.0.0.1:8080".to_string(),
            health_path: "/".to_string(),
            health_timeout_secs: 5,
            tls: None,
        }
    }
}

/// Header pairs that must not be forwarded hop-by-hop.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// Verify the upstream answers before the edge starts accepting traffic.
///
/// Inline mode is an explicit opt-in precisely because a dead backend turns
/// the edge into an outage; this check is mandatory by design.
pub async fn health_check(cfg: &EdgeProxyConfig) -> sentry_core::error::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.health_timeout_secs.max(1)))
        .build()
        .map_err(|e| sentry_core::error::CoreError::Config(format!("edge http client: {e}")))?;
    let url = format!("{}{}", cfg.upstream.trim_end_matches('/'), cfg.health_path);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            sentry_core::error::CoreError::Config(format!(
                "edge upstream health check failed ({url}): {e} — refusing to start inline on a dead backend"
            ))
        })?;
    info!(
        url = %url,
        status = resp.status().as_u16(),
        "edge upstream healthy"
    );
    Ok(())
}

/// Serve the inline edge until the process stops.
///
/// With a TLS front (F8) the plain and HTTPS listeners run concurrently
/// on the same pipeline: port 80 and port 443 are both monitored, blocked
/// IPs are denied on both, and the SNI/JA3 telemetry flows from the TLS
/// acceptor.
pub async fn serve(
    runtime: EdgeRuntime,
    cfg: EdgeProxyConfig,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
) -> sentry_core::error::Result<()> {
    health_check(&cfg).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| sentry_core::error::CoreError::Config(format!("edge http client: {e}")))?;

    let redirect_https = cfg.tls.as_ref().is_some_and(|t| t.redirect_https);
    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(ProxyState {
            runtime: runtime.clone(),
            client,
            upstream: cfg.upstream.clone(),
            decided: decided.clone(),
            redirect_https,
        });

    match cfg.tls {
        None => serve_plain(app, cfg.listen).await,
        Some(tls_cfg) => {
            #[cfg(feature = "edge-tls")]
            {
                tokio::try_join!(
                    serve_plain(app.clone(), cfg.listen),
                    crate::tls::serve_tls(runtime, tls_cfg, app, decided)
                )?;
                Ok(())
            }
            #[cfg(not(feature = "edge-tls"))]
            {
                let _ = (tls_cfg, runtime, app, decided);
                Err(sentry_core::error::CoreError::Config(
                    "edge tls configured but sentry was built without the `edge-tls` \
                     feature — rebuild with --features sentry-cli/edge-tls"
                        .to_string(),
                ))
            }
        }
    }
}

/// Plain-HTTP listener. An empty `listen` disables it (HTTPS-only edge).
async fn serve_plain(app: Router, listen: String) -> sentry_core::error::Result<()> {
    if listen.is_empty() {
        return Ok(());
    }
    let addr: SocketAddr = listen.parse().map_err(|e| {
        sentry_core::error::CoreError::Config(format!("invalid edge listen address: {e}"))
    })?;
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        sentry_core::error::CoreError::Config(format!("edge bind on {addr} failed: {e}"))
    })?;
    info!(addr = %addr, "edge (inline) listening on http");
    // `into_make_service` + ready loop keeps ConnectInfo available for the
    // real-IP precedence chain.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| sentry_core::error::CoreError::Config(format!("edge server error: {e}")))
}

/// Shared handler state (single struct — the state tuple got unwieldy).
#[derive(Clone)]
struct ProxyState {
    runtime: EdgeRuntime,
    client: reqwest::Client,
    upstream: String,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
    /// 301 plain-HTTP requests to HTTPS (F8, TLS front only).
    redirect_https: bool,
}

async fn proxy_handler(State(state): State<ProxyState>, req: Request) -> Response {
    let start = Instant::now();
    let runtime = state.runtime.clone();
    let resp = proxy_handler_inner(State(state), req).await;
    if let Some(h) = runtime.request_duration.as_ref() {
        h.observe(start.elapsed().as_secs_f64());
    }
    resp
}

async fn proxy_handler_inner(State(state): State<ProxyState>, req: Request) -> Response {
    let ProxyState {
        runtime,
        client,
        upstream,
        decided,
        redirect_https,
    } = state;
    let (parts, body) = req.into_parts();
    // Set by the TLS acceptor (F8) — a real HTTPS connection, not a
    // spoofable header.
    let is_tls = parts.extensions.get::<crate::TlsTerminated>().is_some();
    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]));

    // Buffer the body for forwarding (≥1 MiB) and capture the first
    // `body_cap` bytes for inspection when enabled.
    let forward_cap = runtime.body_cap().max(1024 * 1024);
    let body_bytes = match axum::body::to_bytes(body, forward_cap).await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            return (
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the edge limit",
            )
                .into_response();
        }
    };
    let captured = if runtime.body_cap() > 0 {
        Some(
            body_bytes
                .get(..runtime.body_cap())
                .unwrap_or(&body_bytes)
                .to_vec(),
        )
    } else {
        None
    };

    let headers: std::collections::HashMap<String, String> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let client_ip = crate::real_client_ip_with(&parts.headers, peer, runtime.trust());

    // Sticky blocks deny before the pipeline runs — no event, no upstream.
    // No event is persisted here, so the trace id only lives in the page
    // and the log line.
    if runtime.is_hard_blocked(client_ip) {
        let trace = Uuid::new_v4();
        tracing::info!(ip = %client_ip, trace_id = %trace, "edge fast-path: blocked ip denied before pipeline (no event persisted)");
        return pages::block_page(Some(trace));
    }
    let http = sentry_core::event::HttpData {
        method: Some(sentry_core::event::HttpMethod::from_str_lossy(
            parts.method.as_str(),
        )),
        scheme: Some(parts.uri.scheme_str().unwrap_or("http").to_string()),
        host: parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        path: parts.uri.path().to_string(),
        query: parts
            .uri
            .query()
            .map(str::to_string)
            .filter(|q| !q.is_empty()),
        fragment: None,
        status: None,
        user_agent: headers.get("user-agent").cloned(),
        referer: headers.get("referer").cloned(),
        headers,
        body: captured,
        cookies: Some(crate::challenge::parse_cookies(&parts.headers)),
        upstream_time_ms: None,
    };
    let mut evt = sentry_core::event::Event::new(
        sentry_core::event::SourceKind::HttpProxy,
        client_ip,
        sentry_core::ProtocolData::Http(http),
    );
    evt.client_port = parts
        .extensions
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.port());

    let mut processed = runtime.process(evt);
    let ua = processed.event.http().and_then(|h| h.user_agent.clone());
    let path = processed
        .event
        .http()
        .map(|h| h.path.clone())
        .unwrap_or_default();

    let resp = match processed.decision.action {
        sentry_core::analysis::Verdict::Allow => {
            serve_allow(
                &parts,
                &body_bytes,
                is_tls,
                redirect_https,
                &client,
                &upstream,
            )
            .await
        }
        sentry_core::analysis::Verdict::RateLimit => {
            pages::rate_limit_page(Some(processed.event.id))
        }
        sentry_core::analysis::Verdict::Challenge => {
            match runtime.challenge_gate(&parts.headers, client_ip, Some(processed.event.id)) {
                crate::ChallengeGate::Pass => {
                    serve_allow(
                        &parts,
                        &body_bytes,
                        is_tls,
                        redirect_https,
                        &client,
                        &upstream,
                    )
                    .await
                }
                crate::ChallengeGate::Page(page) => page,
                crate::ChallengeGate::Blocked(page) => page,
                crate::ChallengeGate::Disabled => {
                    pages::challenge_required_page(Some(processed.event.id))
                }
            }
        }
        sentry_core::analysis::Verdict::Block | sentry_core::analysis::Verdict::Quarantine => {
            pages::block_page(Some(processed.event.id))
        }
    };

    // Response-phase feedback: the request-phase pipeline saw no status (the
    // response did not exist yet), so the status-keyed trackers (scan,
    // behavior) are fed here with the real code — their signals are queued
    // for the next request from this IP. The event is published only now so
    // it carries the response status it displays.
    let status = resp.status().as_u16();
    if let sentry_core::ProtocolData::Http(http) = &mut processed.event.protocol {
        http.status = Some(status);
    }
    runtime
        .pipeline()
        .observe_response(client_ip, &path, status, ua.as_deref());
    let _ = decided.try_send(processed);

    resp
}

/// Allow path (and challenge-passed requests): plain-HTTP → HTTPS redirect
/// (F8) when configured, otherwise forward to the upstream and pass its
/// response through.
async fn serve_allow(
    parts: &axum::http::request::Parts,
    body_bytes: &[u8],
    is_tls: bool,
    redirect_https: bool,
    client: &reqwest::Client,
    upstream: &str,
) -> Response {
    // Plain-HTTP → HTTPS redirect (F8): port-80 traffic stays monitored and
    // enforced; benign requests get the 301 instead of double-hitting the
    // upstream.
    if redirect_https && !is_tls {
        if let Some(host) = parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        {
            let query = match parts.uri.query() {
                Some(q) => format!("?{q}"),
                None => String::new(),
            };
            return Response::builder()
                .status(axum::http::StatusCode::MOVED_PERMANENTLY)
                .header(
                    header::LOCATION,
                    format!("https://{host}{}{query}", parts.uri.path()),
                )
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| axum::http::StatusCode::BAD_GATEWAY.into_response());
        }
    }

    // Forward to upstream.
    let path_qs = match parts.uri.query() {
        Some(q) => format!("{}?{q}", parts.uri.path()),
        None => parts.uri.path().to_string(),
    };
    let url = format!("{}{}", upstream.trim_end_matches('/'), path_qs);
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut fwd = client.request(method, &url);
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            fwd = fwd.header(name, val);
        }
    }
    if !body_bytes.is_empty() {
        fwd = fwd.body(body_bytes.to_vec());
    }

    match fwd.send().await {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let mut out = Response::builder().status(status);
            for (k, v) in resp.headers().iter() {
                let name = k.as_str();
                if HOP_BY_HOP.contains(&name) {
                    continue;
                }
                out = out.header(name, v);
            }
            match resp.bytes().await {
                Ok(bytes) => out
                    .body(axum::body::Body::from(bytes))
                    .unwrap_or_else(|_| axum::http::StatusCode::BAD_GATEWAY.into_response()),
                Err(_) => axum::http::StatusCode::BAD_GATEWAY.into_response(),
            }
        }
        Err(e) => {
            warn!(error = %e, url = %url, "edge upstream request failed");
            (axum::http::StatusCode::BAD_GATEWAY, "upstream unavailable").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_check_fails_fast_on_dead_backend() {
        let cfg = EdgeProxyConfig {
            upstream: "http://127.0.0.1:9".to_string(),
            health_timeout_secs: 1,
            ..Default::default()
        };
        let err = health_check(&cfg).await.expect_err("dead backend");
        assert!(err.to_string().contains("refusing to start inline"));
    }

    #[tokio::test]
    async fn fast_path_denies_blocked_ip_without_upstream() {
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let table = std::sync::Arc::new(sentry_core::BlockTable::new());
        table.block("127.0.0.1".parse().unwrap(), None);
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0).with_block_table(table);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(ProxyState {
                runtime,
                client: reqwest::Client::new(),
                upstream: "http://127.0.0.1:9".to_string(),
                decided: dec_tx,
                redirect_https: false,
            });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/anything")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(
            dec_rx.try_recv().is_err(),
            "fast-path denies without a decided event"
        );
    }

    #[tokio::test]
    async fn https_redirect_answers_301_and_keeps_monitoring() {
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(ProxyState {
                runtime,
                client: reqwest::Client::new(),
                upstream: "http://127.0.0.1:9".to_string(),
                decided: dec_tx,
                redirect_https: true,
            });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/some/path?q=1")
                    .header("host", "example.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("https://example.com/some/path?q=1")
        );
        // The redirect runs after the pipeline: port-80 traffic keeps
        // producing decided events (monitoring is preserved).
        assert!(
            dec_rx.try_recv().is_ok(),
            "redirected request was monitored"
        );
    }

    /// Minimal upstream answering 404 to everything (honeypot decoy).
    async fn spawn_404_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(|| async { axum::http::StatusCode::NOT_FOUND });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    #[tokio::test]
    async fn decided_events_carry_upstream_status() {
        let upstream = spawn_404_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(ProxyState {
                runtime,
                client: reqwest::Client::new(),
                upstream: format!("http://{upstream}"),
                decided: dec_tx,
                redirect_https: false,
            });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/some/missing.php")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let pe = dec_rx.try_recv().expect("decided event published");
        match &pe.event.protocol {
            sentry_core::ProtocolData::Http(h) => assert_eq!(h.status, Some(404)),
            other => panic!("expected http event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn scanner_burst_is_enforced_from_queued_response_signals() {
        let upstream = spawn_404_upstream().await;
        let scan = std::sync::Arc::new(std::sync::RwLock::new(
            sentry_core::scan::ScanTracker::from_config(&sentry_core::config::ScanConfig::default()),
        ));
        let escalation = sentry_core::config::EscalationConfig::default();
        let offender = std::sync::Arc::new(std::sync::RwLock::new(
            sentry_core::offender::OffenderTracker::from_config(&escalation),
        ));
        let pipeline = std::sync::Arc::new(
            sentry_core::pipeline::Pipeline::new(
                sentry_core::RuleSet::default(),
                sentry_core::RouteValidator::new(vec![]),
            )
            .with_scan_tracker(scan)
            .with_offender(offender, escalation),
        );
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(64);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(ProxyState {
                runtime,
                client: reqwest::Client::new(),
                upstream: format!("http://{upstream}"),
                decided: dec_tx,
                redirect_https: false,
            });

        let mut statuses = Vec::new();
        for i in 0..20 {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(format!("/scan{i}.php").as_str())
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            statuses.push(resp.status().as_u16());
        }

        // The scan window fills while the honeypot answers 404; from the 9th
        // request on the queued scan signals enforce (challenge/block pages
        // are both 403) and escalation carries the burst to a hard Block.
        assert_eq!(
            &statuses[..8],
            &[404; 8],
            "honeypot serves the burst while the window fills"
        );
        assert_eq!(statuses[8], 403, "{statuses:?}");
        assert_eq!(statuses.last(), Some(&403), "{statuses:?}");

        // Every decided event carries the response status it displayed.
        let mut saw_404 = false;
        let mut saw_403 = false;
        while let Ok(pe) = dec_rx.try_recv() {
            if let sentry_core::ProtocolData::Http(h) = &pe.event.protocol {
                assert!(h.status.is_some(), "event without response status");
                match h.status {
                    Some(404) => saw_404 = true,
                    Some(403) => saw_403 = true,
                    _ => {}
                }
            }
        }
        assert!(saw_404 && saw_403);
    }
}
