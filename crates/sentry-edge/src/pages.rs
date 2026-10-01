//! Static verdict pages for the inline edge — block, rate-limit and
//! challenge fallbacks, Cloudflare-style *format* (an icon, plain copy, a
//! trace id that maps back to the stored event or the fast-path log line)
//! with Sentry's own branding: nothing is imitated from any CDN. When
//! `[edge] challenge_backend = "cloudflare"` the challenge itself is
//! delegated to the Cloudflare provider via its API rules — visitors are
//! challenged by Cloudflare, not by a look-alike page.
//!
//! Status codes follow Cloudflare: blocks, challenges and challenge
//! failures are 403 (the PoW interstitial included — it already sends
//! `Cache-Control: no-store`, so caches cannot pin it), rate limits are 429.

use std::sync::LazyLock;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// Response header carrying the trace id shown on the page — the persisted
/// event id, or a fresh id on the fast-path (logged, since no event is
/// stored there).
pub const TRACE_HEADER: &str = "x-sentry-trace-id";

/// Project logo, embedded once as a `data:` URI so pages stay
/// self-contained (no CDN, no extra requests).
pub(crate) static SENTRY_ICON: LazyLock<String> = LazyLock::new(|| {
    format!(
        "data:image/png;base64,{}",
        base64(include_bytes!("../assets/sentry-icon.png"))
    )
});

/// Sentry logo as an embedded data URI (the PoW interstitial renders it
/// too — all verdict pages are Sentry pages).
pub(crate) fn sentry_icon() -> &'static str {
    SENTRY_ICON.as_str()
}

/// Shared stylesheet — the same dark theme as the PoW challenge page.
const CSS: &str = "body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}.box{text-align:center}.icon{width:56px;height:56px;margin-bottom:.75rem}h1{font-size:1.4rem;margin:0 0 .5rem}p{color:#8b949e;margin:.25rem 0;max-width:32rem}.trace{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.78rem;color:#8b949e;margin-top:1.25rem}.trace code{color:#c9d1d9;user-select:all}.footer{margin-top:2rem;font-size:.72rem;color:#6e7681}";

/// Render a verdict page: icon, title, message, optional trace id line and
/// the Sentry footer. `trace` also lands in the [`TRACE_HEADER`] response
/// header.
pub fn verdict_page(
    status: StatusCode,
    title: &str,
    message: &str,
    trace: Option<Uuid>,
) -> Response {
    let trace_html = trace
        .map(|id| format!("<div class=\"trace\">Trace ID: <code>{id}</code></div>"))
        .unwrap_or_default();
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title><style>{CSS}</style></head>\
         <body><div class=\"box\"><img class=\"icon\" src=\"{icon}\" alt=\"\">\
         <h1>{title}</h1><p>{message}</p>{trace_html}\
         <div class=\"footer\">Performance &amp; security by Sentry</div></div></body></html>",
        icon = sentry_icon(),
    );
    let mut resp = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response();
    if let Some(id) = trace {
        if let Ok(v) = HeaderValue::from_str(&id.to_string()) {
            resp.headers_mut().insert(TRACE_HEADER, v);
        }
    }
    resp
}

/// 403 page for `Block` / `Quarantine` verdicts and fast-path denials.
pub fn block_page(trace: Option<Uuid>) -> Response {
    verdict_page(
        StatusCode::FORBIDDEN,
        "403 - Forbidden",
        "You are unable to access this website.",
        trace,
    )
}

/// 429 for `RateLimit` verdicts.
pub fn rate_limit_page(trace: Option<Uuid>) -> Response {
    let mut resp = verdict_page(
        StatusCode::TOO_MANY_REQUESTS,
        "429 - Too Many Requests",
        "Slow down and retry shortly.",
        trace,
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    resp
}

/// 403 page for `Challenge` verdicts without an interactive challenge
/// configured (see `[edge.challenge]`, F7.8).
pub fn challenge_required_page(trace: Option<Uuid>) -> Response {
    verdict_page(
        StatusCode::FORBIDDEN,
        "403 - Forbidden",
        "This resource requires verification. If you believe this is an error, contact the administrator.",
        trace,
    )
}

/// Terminal 403 page for a presented challenge cookie that failed
/// verification — the client tried and failed, so no retry loop.
pub fn challenge_failed_page(trace: Option<Uuid>) -> Response {
    verdict_page(
        StatusCode::FORBIDDEN,
        "403 - Forbidden",
        "Your browser did not pass the security check. If you believe this is an error, contact the administrator.",
        trace,
    )
}

/// 403 hold page for `Challenge` verdicts when
/// `challenge_backend = "cloudflare"`: the CF provider turns the verdict
/// into a Cloudflare rule via its API and Cloudflare challenges the
/// visitor on the next hop — this page only holds the current request
/// until that happens.
pub fn delegated_challenge_page(trace: Option<Uuid>) -> Response {
    let mut resp = verdict_page(
        StatusCode::FORBIDDEN,
        "Verifying your browser...",
        "Please wait a few seconds and retry.",
        trace,
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("3"));
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    resp
}

/// Standard-alphabet base64 (with padding) — used only for the embedded
/// icon data URI, so a hand-rolled encoder beats a new dependency.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn trace() -> Uuid {
        Uuid::nil()
    }

    #[tokio::test]
    async fn block_page_carries_copy_icon_trace_and_footer() {
        let resp = block_page(Some(trace()));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get(TRACE_HEADER).unwrap().to_str().unwrap(),
            trace().to_string()
        );
        let page = body(resp).await;
        assert!(page.contains("<title>403 - Forbidden</title>"), "{page}");
        assert!(
            page.contains("You are unable to access this website."),
            "{page}"
        );
        assert!(page.contains("Trace ID:"), "{page}");
        assert!(page.contains(&trace().to_string()), "{page}");
        assert!(page.contains("data:image/png;base64,"), "{page}");
        assert!(
            page.contains("Performance &amp; security by Sentry"),
            "{page}"
        );
    }

    #[tokio::test]
    async fn block_page_without_trace_omits_the_line_and_header() {
        let resp = block_page(None);
        assert!(resp.headers().get(TRACE_HEADER).is_none());
        let page = body(resp).await;
        assert!(!page.contains("Trace ID:"), "{page}");
    }

    #[tokio::test]
    async fn rate_limit_page_is_429_with_retry_after() {
        let resp = rate_limit_page(Some(trace()));
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "60");
        let page = body(resp).await;
        assert!(page.contains("429 - Too Many Requests"), "{page}");
        assert!(page.contains("Trace ID:"), "{page}");
    }

    #[tokio::test]
    async fn challenge_fallback_and_failed_pages_are_403() {
        for resp in [
            challenge_required_page(Some(trace())),
            challenge_failed_page(Some(trace())),
        ] {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let page = body(resp).await;
            assert!(page.contains("403 - Forbidden"), "{page}");
            assert!(page.contains("Trace ID:"), "{page}");
        }
    }

    #[tokio::test]
    async fn delegated_page_is_403_with_retry_after_3() {
        let resp = delegated_challenge_page(Some(trace()));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "3");
        let page = body(resp).await;
        assert!(page.contains("Verifying your browser..."), "{page}");
        assert!(page.contains("Trace ID:"), "{page}");
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
