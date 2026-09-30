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
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::middleware::{block_response, challenge_response, rate_limit_response};
use crate::EdgeRuntime;

/// Inline proxy configuration.
#[derive(Debug, Clone)]
pub struct EdgeProxyConfig {
    /// Listen address (`0.0.0.0:80`).
    pub listen: String,
    /// Protected upstream base URL (`http://127.0.0.1:8080`).
    pub upstream: String,
    /// Path used for the startup health check (default `/`).
    pub health_path: String,
    /// Health check timeout in seconds (default 5).
    pub health_timeout_secs: u64,
    /// TLS certificate (feature `edge-tls`); both must be set to enable.
    pub tls_cert: Option<PathBuf>,
    /// TLS private key (feature `edge-tls`).
    pub tls_key: Option<PathBuf>,
}

impl Default for EdgeProxyConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:80".to_string(),
            upstream: "http://127.0.0.1:8080".to_string(),
            health_path: "/".to_string(),
            health_timeout_secs: 5,
            tls_cert: None,
            tls_key: None,
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
pub async fn serve(
    runtime: EdgeRuntime,
    cfg: EdgeProxyConfig,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
) -> sentry_core::error::Result<()> {
    health_check(&cfg).await?;
    let addr: SocketAddr = cfg.listen.parse().map_err(|e| {
        sentry_core::error::CoreError::Config(format!("invalid edge listen address: {e}"))
    })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| sentry_core::error::CoreError::Config(format!("edge http client: {e}")))?;

    let app = Router::new().fallback(any(proxy_handler)).with_state((
        runtime,
        client,
        cfg.upstream.clone(),
        decided,
    ));

    match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert), Some(key)) => {
            #[cfg(feature = "edge-tls")]
            {
                let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                    .await
                    .map_err(|e| {
                        sentry_core::error::CoreError::Config(format!("edge tls config: {e}"))
                    })?;
                info!(%addr, cert = %cert.display(), "edge (inline) listening on https");
                axum_server::bind_rustls(addr, tls)
                    .serve(app.into_make_service())
                    .await
                    .map_err(|e| {
                        sentry_core::error::CoreError::Config(format!("edge server error: {e}"))
                    })?;
                Ok(())
            }
            #[cfg(not(feature = "edge-tls"))]
            {
                let _ = (cert, key);
                warn!("edge tls configured but sentry was built without the `edge-tls` feature — serving plain HTTP");
                serve_plain(app, addr).await
            }
        }
        _ => {
            info!(%addr, "edge (inline) listening on http");
            serve_plain(app, addr).await
        }
    }
}

async fn serve_plain(app: Router, addr: SocketAddr) -> sentry_core::error::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        sentry_core::error::CoreError::Config(format!("edge bind on {addr} failed: {e}"))
    })?;
    // `into_make_service` + ready loop keeps ConnectInfo available for the
    // real-IP precedence chain.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| sentry_core::error::CoreError::Config(format!("edge server error: {e}")))
}

async fn proxy_handler(
    State((runtime, client, upstream, decided)): State<(
        EdgeRuntime,
        reqwest::Client,
        String,
        mpsc::Sender<sentry_core::ProcessedEvent>,
    )>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
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

    let client_ip = crate::real_client_ip(&parts.headers, peer);

    // Sticky blocks deny before the pipeline runs — no event, no upstream.
    if runtime.is_hard_blocked(client_ip) {
        return block_response();
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
        cookies: None,
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

    let processed = runtime.process(evt);
    // Hand the decided event to the daemon for persistence + actions.
    let _ = decided.try_send(processed.clone());

    match processed.decision.action {
        sentry_core::analysis::Verdict::Allow => {}
        sentry_core::analysis::Verdict::RateLimit => return rate_limit_response(),
        sentry_core::analysis::Verdict::Challenge => return challenge_response(),
        sentry_core::analysis::Verdict::Block | sentry_core::analysis::Verdict::Quarantine => {
            return block_response()
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
    let body_out = body_bytes.clone();
    if !body_out.is_empty() {
        fwd = fwd.body(body_out);
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
        let app = Router::new().fallback(any(proxy_handler)).with_state((
            runtime,
            reqwest::Client::new(),
            "http://127.0.0.1:9".to_string(),
            dec_tx,
        ));
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
}
