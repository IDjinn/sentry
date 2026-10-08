//! Reusable axum middleware (F3.1): observe or gate requests through the
//! Sentry pipeline without a proxy hop.
//!
//! Wire it into any axum `Router`:
//!
//! ```ignore
//! use axum::middleware;
//! use sentry_edge::{EdgeRuntime, middleware::{MiddlewareMode, handler}};
//!
//! let app = Router::new()
//!     .route("/", get(root))
//!     .route_layer(middleware::from_fn_with_state(runtime.clone(), handler))
//!     .with_state(runtime);
//! ```
//!
//! `MiddlewareMode::Inline` blocks/challenges/rate-limits before the
//! handler runs; `Shadow` only records the decision in the request
//! extensions (key [`DECISION`]) and never interferes.

use std::time::Instant;

use axum::extract::Request;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sentry_core::analysis::Verdict;
use sentry_core::event::{Event, HttpData, ProtocolData, SourceKind, Transport};
use uuid::Uuid;

use crate::pages;
use crate::EdgeRuntime;

/// How the middleware treats decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiddlewareMode {
    /// Enforce the verdict before the handler runs.
    Inline,
    /// Observe only: attach the decision and continue.
    Shadow,
}

/// Extension key carrying the [`ProcessedEvent`] decision (shadow mode).
pub const DECISION: &str = "sentry.decision";

impl EdgeRuntime {
    /// Middleware mode this runtime enforces.
    pub fn mode(&self) -> MiddlewareMode {
        self.mode
    }

    /// Set the middleware mode (builder-style).
    pub fn with_mode(mut self, mode: MiddlewareMode) -> Self {
        self.mode = mode;
        self
    }
}

/// The axum middleware handler — use with
/// `middleware::from_fn_with_state(runtime, sentry_edge::middleware::handler)`.
pub async fn handler(State(runtime): State<EdgeRuntime>, req: Request, next: Next) -> Response {
    let start = Instant::now();
    let resp = handler_inner(State(runtime.clone()), req, next, start).await;
    if let Some(h) = runtime.request_duration.as_ref() {
        h.observe(start.elapsed().as_secs_f64());
    }
    resp
}

async fn handler_inner(
    State(runtime): State<EdgeRuntime>,
    req: Request,
    next: Next,
    start: Instant,
) -> Response {
    let (mut parts, body) = req.into_parts();

    // Buffer the body up to the capture cap — raised to the inspection cap
    // when uploads are enabled (F10). 0 = don't buffer (unless inspection).
    // Under overload pressure the raise is skipped (cheap mode): bodies
    // still buffer to the capture cap because the handler needs them back.
    let cap = match runtime.uploads_inspection() {
        Some(insp) if !runtime.overloaded() => runtime.body_cap().max(insp.inspect_bytes),
        _ => runtime.body_cap(),
    };
    let (buffered, body) = if cap > 0 {
        match axum::body::to_bytes(body, cap).await {
            Ok(bytes) => (Some(bytes.to_vec()), axum::body::Body::from(bytes)),
            Err(_) => {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds the inspection cap",
                )
                    .into_response();
            }
        }
    } else {
        (None, body)
    };
    // Persistence keeps `body_capture_kb` semantics; the pipeline analyzes a
    // (possibly longer) inspection prefix.
    let captured = buffered.as_ref().and_then(|b| {
        if runtime.body_cap() == 0 {
            return None;
        }
        let end = b.len().min(runtime.body_cap());
        Some(b[..end].to_vec())
    });
    let (upload_meta, analysis_body) = match buffered.as_deref() {
        Some(b) => runtime.inspect_body(
            parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            b,
        ),
        None => (None, None),
    };

    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_canonical())
        .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]));
    let client_ip = crate::real_client_ip_with(&parts.headers, peer, runtime.trust());

    // Sticky blocks deny before the pipeline runs — a blocked IP stays
    // blocked even when this request alone would score as benign. No event
    // is persisted here, so the trace id only lives in the page and the
    // log line.
    if runtime.is_hard_blocked(client_ip) {
        let trace = Uuid::new_v4();
        tracing::info!(ip = %client_ip, trace_id = %trace, elapsed = ?start.elapsed(), "edge fast-path: blocked ip denied before pipeline (no event persisted)");
        return pages::block_page(Some(trace));
    }

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

    let http = HttpData {
        method: Some(sentry_core::event::HttpMethod::from_str_lossy(
            parts.method.as_str(),
        )),
        scheme: Some(parts.uri.scheme_str().unwrap_or("http").to_string()),
        host: parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        path: percent_decode(parts.uri.path()),
        query: parts
            .uri
            .query()
            .map(percent_decode)
            .filter(|q| !q.is_empty()),
        fragment: None,
        status: None,
        user_agent: headers.get("user-agent").cloned(),
        referer: headers.get("referer").cloned(),
        headers,
        body: analysis_body.clone().or_else(|| captured.clone()),
        cookies: Some(crate::challenge::parse_cookies(&parts.headers)),
        uploads: upload_meta,
        upstream_time_ms: None,
    };

    let mut evt = Event::new(SourceKind::HttpProxy, client_ip, ProtocolData::Http(http));
    evt.transport = Transport::Tcp;
    evt.client_port = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.port());

    let mut processed = runtime.process(evt);
    if let Some(http) = processed.event.http_mut() {
        http.body = captured.clone();
    }

    if runtime.mode() == MiddlewareMode::Shadow {
        parts.extensions.insert(processed);
        let req = Request::from_parts(parts, body);
        return next.run(req).await;
    }

    match processed.decision.action {
        Verdict::Allow => {
            parts.extensions.insert(processed);
            let req = Request::from_parts(parts, body);
            next.run(req).await
        }
        Verdict::RateLimit => pages::rate_limit_page(Some(processed.event.id)),
        Verdict::Challenge => {
            match runtime.challenge_gate(&parts.headers, client_ip, Some(processed.event.id)) {
                crate::ChallengeGate::Pass => {
                    parts.extensions.insert(processed);
                    let req = Request::from_parts(parts, body);
                    next.run(req).await
                }
                crate::ChallengeGate::Page(page) => page,
                crate::ChallengeGate::Blocked(page) => page,
                crate::ChallengeGate::Disabled => {
                    pages::challenge_required_page(Some(processed.event.id))
                }
            }
        }
        Verdict::Block | Verdict::Quarantine => pages::block_page(Some(processed.event.id)),
    }
}

/// Minimal percent-decode so heuristics see the attacker's intent (the same
/// normalization the nginx parser applies to `path`/`query`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use sentry_core::pipeline::Pipeline;
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn runtime(mode: MiddlewareMode) -> EdgeRuntime {
        let pipeline = std::sync::Arc::new(Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        EdgeRuntime::new(pipeline, None, 4096).with_mode(mode)
    }

    #[tokio::test]
    async fn shadow_mode_never_blocks_and_records_decision() {
        let app = Router::new()
            .route("/", get(ok_handler))
            .route_layer(axum::middleware::from_fn_with_state(
                runtime(MiddlewareMode::Shadow),
                handler,
            ))
            .with_state(runtime(MiddlewareMode::Shadow));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn inline_mode_allows_benign_requests() {
        let app = Router::new()
            .route("/", get(ok_handler))
            .route_layer(axum::middleware::from_fn_with_state(
                runtime(MiddlewareMode::Inline),
                handler,
            ))
            .with_state(runtime(MiddlewareMode::Inline));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/?health=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn inline_mode_blocks_sqli() {
        let app = Router::new()
            .route("/", get(ok_handler))
            .route_layer(axum::middleware::from_fn_with_state(
                runtime(MiddlewareMode::Inline),
                handler,
            ))
            .with_state(runtime(MiddlewareMode::Inline));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/?user=admin%27+OR+1%3D1--")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get(pages::TRACE_HEADER).is_some());
        let page = body_bytes(resp).await;
        assert!(page.contains("403 - Forbidden"), "{page}");
        assert!(
            page.contains("You are unable to access this website."),
            "{page}"
        );
        assert!(page.contains("Trace ID:"), "{page}");
    }

    #[tokio::test]
    async fn fast_path_denies_blocked_ip_before_pipeline() {
        let table = std::sync::Arc::new(sentry_core::BlockTable::new());
        table.block("127.0.0.1".parse().unwrap(), None);
        let hits = prometheus::Counter::new("edge_block_hits_test", "test").unwrap();
        let rt = runtime(MiddlewareMode::Inline)
            .with_block_table(table)
            .with_block_hits(hits.clone());
        let app = Router::new()
            .route("/", get(ok_handler))
            .route_layer(axum::middleware::from_fn_with_state(rt.clone(), handler))
            .with_state(rt);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/?health=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(hits.get(), 1.0);
        let page = body_bytes(resp).await;
        assert!(page.contains("403 - Forbidden"), "{page}");
        assert!(page.contains("Trace ID:"), "{page}");
    }

    async fn body_bytes(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn percent_decode_matches_nginx_normalization() {
        assert_eq!(percent_decode("/a%27b"), "/a'b");
        assert_eq!(percent_decode("/a%2fb"), "/a/b");
        assert_eq!(percent_decode("/plain"), "/plain");
        assert_eq!(percent_decode("/bad%zz"), "/bad%zz");
    }

    // ── Upload inspection (F10) ──────────────────────────────────────────

    fn upload_runtime(mode: MiddlewareMode, enforce: bool) -> EdgeRuntime {
        let mut cfg = sentry_core::config::UploadsConfig {
            enabled: true,
            ..Default::default()
        };
        if enforce {
            cfg.mode = sentry_core::config::UploadMode::Enforce;
        }
        let mut pipeline = Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        );
        pipeline.configure_uploads(&cfg);
        EdgeRuntime::new(std::sync::Arc::new(pipeline), None, 4096)
            .with_mode(mode)
            .with_uploads(crate::UploadsInspection {
                inspect_bytes: 64 * 1024,
                max_files: 16,
            })
    }

    fn form_app(rt: EdgeRuntime) -> Router {
        Router::new()
            .route("/", get(ok_handler).post(ok_handler))
            .route_layer(axum::middleware::from_fn_with_state(rt.clone(), handler))
            .with_state(rt)
    }

    #[tokio::test]
    async fn uploads_sqli_in_form_field_blocks_inline() {
        let app = form_app(upload_runtime(MiddlewareMode::Inline, true));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from("user=admin%27+OR+1%3D1--"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn uploads_clean_form_passes_with_body_intact() {
        let app = form_app(upload_runtime(MiddlewareMode::Inline, true));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from("user=maria&next=%2Fhome"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn uploads_decision_extension_keeps_capture_semantics() {
        // body_capture_kb = 4096 in this runtime: the handler-visible event
        // keeps the captured body, and shadow decisions carry upload metadata.
        let rt = upload_runtime(MiddlewareMode::Shadow, false);
        let counter = prometheus::Counter::new("mw_uploads_test", "test").unwrap();
        let rt = rt.with_uploads_inspected(counter.clone());
        let app = Router::new()
            .route("/", get(ok_handler).post(ok_handler))
            .route_layer(axum::middleware::from_fn_with_state(rt.clone(), handler))
            .with_state(rt);
        let gif = b"GIF89a\x00<?php eval($_POST); ?>".to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.gif\"\r\nContent-Type: image/gif\r\n\r\n");
        body.extend_from_slice(&gif);
        body.extend_from_slice(b"\r\n--B--\r\n");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "multipart/form-data; boundary=B")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "shadow never blocks");
        assert_eq!(counter.get(), 1.0, "inspected counter incremented");
    }
}
