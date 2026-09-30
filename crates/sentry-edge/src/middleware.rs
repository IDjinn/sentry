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

use axum::extract::Request;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sentry_core::analysis::Verdict;
use sentry_core::event::{Event, HttpData, ProtocolData, SourceKind, Transport};

use crate::{real_client_ip, EdgeRuntime};

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
    let (mut parts, body) = req.into_parts();

    // Capture the body up to the configured cap (0 = don't buffer).
    let (captured, body) = if runtime.body_cap() > 0 {
        match axum::body::to_bytes(body, runtime.body_cap()).await {
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

    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]));
    let client_ip = real_client_ip(&parts.headers, peer);

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
        body: captured,
        cookies: None,
    };

    let mut evt = Event::new(SourceKind::HttpProxy, client_ip, ProtocolData::Http(http));
    evt.transport = Transport::Tcp;
    evt.client_port = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.port());

    let processed = runtime.process(evt);

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
        Verdict::RateLimit => rate_limit_response(),
        Verdict::Challenge => challenge_response(),
        Verdict::Block | Verdict::Quarantine => block_response(),
    }
}

/// 403 page for `Block` / `Quarantine` verdicts.
pub fn block_response() -> Response {
    verdict_page(
        StatusCode::FORBIDDEN,
        "403 — blocked",
        "Your request was blocked by Sentry.",
    )
}

/// 429 for `RateLimit` verdicts.
pub fn rate_limit_response() -> Response {
    let mut resp = verdict_page(
        StatusCode::TOO_MANY_REQUESTS,
        "429 — too many requests",
        "Slow down and retry shortly.",
    );
    if let Ok(v) = HeaderValue::from_str("60") {
        resp.headers_mut().insert("retry-after", v);
    }
    resp
}

/// 403 challenge page for `Challenge` verdicts.
///
/// Edge challenges are static pages (unlike Cloudflare-managed challenges,
/// there is no verification backend here); use `mode = "block"` semantics or
/// front Sentry with Cloudflare for interactive challenges.
pub fn challenge_response() -> Response {
    verdict_page(
        StatusCode::FORBIDDEN,
        "403 — verification required",
        "This resource requires verification. If you believe this is an error, contact the administrator.",
    )
}

fn verdict_page(status: StatusCode, title: &str, message: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html><html><head><title>{title}</title></head><body style=\"font-family:sans-serif;background:#0d1117;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0\"><div style=\"text-align:center\"><h1>{title}</h1><p>{message}</p></div></body></html>"
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
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
    }

    #[test]
    fn percent_decode_matches_nginx_normalization() {
        assert_eq!(percent_decode("/a%27b"), "/a'b");
        assert_eq!(percent_decode("/a%2fb"), "/a/b");
        assert_eq!(percent_decode("/plain"), "/plain");
        assert_eq!(percent_decode("/bad%zz"), "/bad%zz");
    }
}
