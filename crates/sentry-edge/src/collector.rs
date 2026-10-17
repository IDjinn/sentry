//! First-party browser collector (F18.2): serves `init.js`, accepts the
//! device report it posts back and injects the `<script>` tag into HTML.
//!
//! Endpoints live under `[fingerprint] js_path` (default
//! `/challenge-sentry`) and are answered by the edge itself — they are never
//! proxied upstream, so they cannot collide with the site's own routes as
//! long as the prefix is unique.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::Response;
use sentry_core::clientsig::{ClientSignals, ClientStore, RecordOutcome, MAX_REPORT_BYTES};
use sentry_core::fingerprint::{new_visitor_id, valid_visitor, visitor_set_cookie, VISITOR_COOKIE};

const SCRIPT: &str = include_str!("../assets/collector.js");
/// HTML responses above this are served untouched.
const MAX_INJECT_BYTES: usize = 2 * 1024 * 1024;

/// Which collector endpoint a request targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorRoute {
    /// `GET <prefix>/init.js`.
    Script,
    /// `POST <prefix>/collect`.
    Collect,
}

/// Collector state shared by the proxy handlers.
pub struct Collector {
    prefix: String,
    store: Arc<ClientStore>,
    inject: bool,
    cookie_max_age: u64,
}

impl Collector {
    /// Build for `prefix` (`/challenge-sentry`), backed by `store`.
    pub fn new(prefix: &str, store: Arc<ClientStore>, inject: bool, cookie_max_age: u64) -> Self {
        Self {
            prefix: prefix.trim_end_matches('/').to_string(),
            store,
            inject,
            cookie_max_age,
        }
    }

    /// Match a request path against the collector endpoints.
    pub fn route(&self, path: &str) -> Option<CollectorRoute> {
        let rest = path.strip_prefix(self.prefix.as_str())?;
        match rest {
            "/init.js" => Some(CollectorRoute::Script),
            "/collect" => Some(CollectorRoute::Collect),
            _ => None,
        }
    }

    fn script_tag(&self) -> String {
        format!("<script src=\"{}/init.js\" defer></script>", self.prefix)
    }

    /// Serve `init.js`.
    pub fn serve_script(&self, method: &Method) -> Response {
        if method != Method::GET && method != Method::HEAD {
            return status(StatusCode::METHOD_NOT_ALLOWED);
        }
        let body = if method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(SCRIPT)
        };
        Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            )
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .header("x-content-type-options", "nosniff")
            .body(body)
            .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR))
    }

    /// Handle `POST <prefix>/collect`.
    pub async fn collect(
        &self,
        parts: &axum::http::request::Parts,
        body: Body,
        ip: IpAddr,
        is_tls: bool,
    ) -> Response {
        if parts.method != Method::POST {
            return status(StatusCode::METHOD_NOT_ALLOWED);
        }
        let Ok(bytes) = axum::body::to_bytes(body, MAX_REPORT_BYTES).await else {
            return status(StatusCode::PAYLOAD_TOO_LARGE);
        };
        let Some(sig) = ClientSignals::parse(&bytes) else {
            return status(StatusCode::BAD_REQUEST);
        };
        let cookies = crate::challenge::parse_cookies(&parts.headers);
        let (visitor_raw, minted) = match cookies.get(VISITOR_COOKIE).filter(|v| valid_visitor(v)) {
            Some(v) => (v.to_ascii_lowercase(), false),
            None => (new_visitor_id(), true),
        };
        let header_str = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        let outcome = self.store.record(
            &format!("v-{visitor_raw}"),
            ip,
            &sig,
            header_str("user-agent"),
            header_str("accept-language"),
        );
        if outcome == RecordOutcome::Throttled {
            return status(StatusCode::TOO_MANY_REQUESTS);
        }
        let mut resp = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::CACHE_CONTROL, "no-store");
        if minted {
            let secure = is_tls
                || header_str("x-forwarded-proto")
                    .and_then(|v| v.split(',').next())
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"));
            resp = resp.header(
                header::SET_COOKIE,
                visitor_set_cookie(&visitor_raw, self.cookie_max_age, secure),
            );
        }
        resp.body(Body::empty())
            .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR))
    }

    /// Insert the collector `<script>` into a successful, uncompressed,
    /// fully buffered HTML response served by the upstream. Anything else
    /// (streams, encoded bodies, non-HTML, huge pages) passes untouched.
    pub async fn inject(&self, resp: Response) -> Response {
        if !self.inject
            || resp.status() != StatusCode::OK
            || resp.headers().contains_key(header::CONTENT_ENCODING)
            || resp
                .extensions()
                .get::<crate::compression::StreamedResponse>()
                .is_some()
            || !sentry_core::security_headers::is_html(
                resp.headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
            )
        {
            return resp;
        }
        let (mut parts, body) = resp.into_parts();
        let bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
            Ok(b) => b,
            Err(_) => return status(StatusCode::BAD_GATEWAY),
        };
        let rebuilt = if bytes.len() <= MAX_INJECT_BYTES {
            insert_tag(&bytes, &self.script_tag())
        } else {
            None
        };
        let out = rebuilt.unwrap_or_else(|| bytes.to_vec());
        parts.headers.remove(header::CONTENT_LENGTH);
        if let Ok(len) = HeaderValue::from_str(&out.len().to_string()) {
            parts.headers.insert(header::CONTENT_LENGTH, len);
        }
        Response::from_parts(parts, Body::from(out))
    }
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Place `tag` before `</head>` (else before `</body>`); `None` when the
/// document has neither.
fn insert_tag(html: &[u8], tag: &str) -> Option<Vec<u8>> {
    let at = find_ci(html, b"</head>").or_else(|| find_ci(html, b"</body>"))?;
    let mut out = Vec::with_capacity(html.len() + tag.len());
    out.extend_from_slice(&html[..at]);
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&html[at..]);
    Some(out)
}

fn status(code: StatusCode) -> Response {
    Response::builder()
        .status(code)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("static response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn collector(inject: bool) -> Collector {
        Collector::new(
            "/challenge-sentry/",
            Arc::new(ClientStore::new(Duration::from_secs(60), 100)),
            inject,
            60,
        )
    }

    #[test]
    fn routes_only_exact_endpoints() {
        let c = collector(true);
        assert_eq!(
            c.route("/challenge-sentry/init.js"),
            Some(CollectorRoute::Script)
        );
        assert_eq!(
            c.route("/challenge-sentry/collect"),
            Some(CollectorRoute::Collect)
        );
        assert_eq!(c.route("/challenge-sentry/other"), None);
        assert_eq!(c.route("/challenge-sentry/init.js/x"), None);
        assert_eq!(c.route("/app/challenge-sentry/init.js"), None);
    }

    #[test]
    fn tag_goes_before_head_close_case_insensitive() {
        let out = insert_tag(
            b"<html><HEAD><title>x</title></HEAD><body></body></html>",
            "<s>",
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<s></HEAD>"), "{s}");
        let out = insert_tag(b"<body>hi</body>", "<s>").unwrap();
        assert_eq!(out, b"<body>hi<s></body>");
        assert!(insert_tag(b"plain text", "<s>").is_none());
    }

    #[tokio::test]
    async fn script_is_served_with_safe_headers() {
        let c = collector(true);
        let r = c.serve_script(&Method::GET);
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "application/javascript; charset=utf-8"
        );
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        assert!(r.headers().get(header::SET_COOKIE).is_none());
        let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains("navigator"));
        assert_eq!(
            c.serve_script(&Method::POST).status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    fn html_resp(body: &str) -> Response {
        Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn text(r: Response) -> String {
        let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        String::from_utf8(b.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn inject_rewrites_html_and_fixes_length() {
        let c = collector(true);
        let r = c
            .inject(html_resp("<html><head></head><body>ok</body></html>"))
            .await;
        let len: usize = r.headers()[header::CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let body = text(r).await;
        assert_eq!(len, body.len());
        assert!(body.contains("<script src=\"/challenge-sentry/init.js\" defer></script></head>"));
    }

    #[tokio::test]
    async fn inject_skips_encoded_non_html_errors_and_disabled() {
        let c = collector(true);
        let mut enc = html_resp("<head></head>");
        enc.headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(text(c.inject(enc).await).await, "<head></head>");
        let json = Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(text(c.inject(json).await).await, "{}");
        let mut notfound = html_resp("<head></head>");
        *notfound.status_mut() = StatusCode::NOT_FOUND;
        assert_eq!(text(c.inject(notfound).await).await, "<head></head>");
        let off = collector(false);
        assert_eq!(
            text(off.inject(html_resp("<head></head>")).await).await,
            "<head></head>"
        );
    }

    fn req(cookie: Option<&str>, body: &str) -> (axum::http::request::Parts, Body) {
        let mut b = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/challenge-sentry/collect")
            .header(header::USER_AGENT, "UA/1");
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        let (parts, _) = b.body(()).unwrap().into_parts();
        (parts, Body::from(body.to_string()))
    }

    #[tokio::test]
    async fn collect_stores_report_and_mints_cookie_when_missing() {
        let c = collector(true);
        let ip = IpAddr::from([203, 0, 113, 9]);
        let body = r#"{"ua":"UA/1","canvas":"abc","webdriver":true}"#;
        let (parts, b) = req(None, body);
        let r = c.collect(&parts, b, ip, true).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let cookie = r.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.starts_with("sentry_vid=") && cookie.ends_with("Secure"));
        assert_eq!(c.store.len(), 1);

        let visitor = new_visitor_id();
        let (parts, b) = req(Some(&format!("sentry_vid={visitor}")), body);
        let r = c
            .collect(&parts, b, IpAddr::from([203, 0, 113, 10]), false)
            .await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        assert!(r.headers().get(header::SET_COOKIE).is_none());
        let rec = c.store.lookup(&format!("v-{visitor}")).unwrap();
        assert!(rec.id.is_some());
        assert!(!rec.signals.is_empty());
    }

    #[tokio::test]
    async fn collect_rejects_garbage_and_wrong_method() {
        let c = collector(true);
        let ip = IpAddr::from([203, 0, 113, 9]);
        let (parts, b) = req(None, "nope");
        assert_eq!(
            c.collect(&parts, b, ip, false).await.status(),
            StatusCode::BAD_REQUEST
        );
        let (mut parts, b) = req(None, "{}");
        parts.method = Method::GET;
        assert_eq!(
            c.collect(&parts, b, ip, false).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}
