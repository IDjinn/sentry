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

use std::collections::HashMap;
use std::path::Path;
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

/// Per-request cap on a custom error page file — pages are static HTML;
/// anything bigger is a mistake (or an attempt to make the edge allocate).
const MAX_PAGE_BYTES: u64 = 256 * 1024;

/// Custom HTML error pages for every edge-generated response (F12).
///
/// Loaded once at startup from `[edge.error_pages] dir`: `<status>.html`
/// files (e.g. `403.html`, `413.html`) override that status, `default.html`
/// covers every other status the edge renders. Unlike the challenge
/// `template_path` (hot-read per render), these are read once — 413/502
/// responses can fire at attack rate and per-render I/O would turn the
/// error path into a disk amplifier.
///
/// Templates may use `{{SENTRY_STATUS}}`, `{{SENTRY_TITLE}}`,
/// `{{SENTRY_MESSAGE}}`, `{{SENTRY_TRACE_ID}}` (empty when absent) and
/// `{{SENTRY_ICON}}` (embedded logo data URI); substituted values are
/// HTML-escaped.
#[derive(Debug, Clone, Default)]
pub struct ErrorPages {
    pages: HashMap<u16, String>,
    default: Option<String>,
}

impl ErrorPages {
    /// Load `<status>.html` / `default.html` overrides from `dir`. Unreadable
    /// or oversized files are skipped with a warning — a broken page must
    /// never take the edge down.
    pub fn from_dir(dir: &Path) -> Self {
        let mut out = Self::default();
        let Ok(entries) = std::fs::read_dir(dir) else {
            tracing::warn!(dir = %dir.display(), "[edge.error_pages] dir unreadable — built-in pages only");
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let is_default = stem == "default";
            let status = if is_default {
                None
            } else {
                match stem.parse::<u16>() {
                    Ok(code) if (100..=599).contains(&code) => Some(code),
                    _ => continue,
                }
            };
            if path.extension().and_then(|e| e.to_str()) != Some("html") {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(file = %path.display(), error = %e, "[edge.error_pages] stat failed — skipped");
                    continue;
                }
            };
            if meta.len() > MAX_PAGE_BYTES {
                tracing::warn!(file = %path.display(), cap_kb = MAX_PAGE_BYTES / 1024, "[edge.error_pages] page too large — skipped");
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(html) => {
                    if is_default {
                        out.default = Some(html);
                    } else {
                        out.pages.insert(status.unwrap_or(0), html);
                    }
                }
                Err(e) => {
                    tracing::warn!(file = %path.display(), error = %e, "[edge.error_pages] page unreadable — skipped");
                }
            }
        }
        out
    }

    /// Number of custom pages loaded (status overrides + default).
    pub fn page_count(&self) -> usize {
        self.pages.len() + usize::from(self.default.is_some())
    }

    /// Render a custom page for `status` when one is configured; `None`
    /// means the caller falls back to the built-in page.
    pub fn render_response(
        &self,
        status: StatusCode,
        title: &str,
        message: &str,
        trace: Option<Uuid>,
    ) -> Option<Response> {
        let template = self.pages.get(&status.as_u16()).or(self.default.as_ref())?;
        let trace_html = trace.map(|id| id.to_string()).unwrap_or_default();
        let html = template
            .replace("{{SENTRY_STATUS}}", &status.as_u16().to_string())
            .replace("{{SENTRY_TITLE}}", &escape_html(title))
            .replace("{{SENTRY_MESSAGE}}", &escape_html(message))
            .replace("{{SENTRY_TRACE_ID}}", &escape_html(&trace_html))
            .replace("{{SENTRY_ICON}}", sentry_icon());
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
        Some(resp)
    }
}

/// Render through the custom map when a page exists, else the built-in.
fn page_with(
    custom: Option<&ErrorPages>,
    status: StatusCode,
    title: &str,
    message: &str,
    trace: Option<Uuid>,
) -> Response {
    if let Some(resp) = custom.and_then(|ep| ep.render_response(status, title, message, trace)) {
        return resp;
    }
    verdict_page(status, title, message, trace)
}

/// Escape interpolated values into custom templates (`&`, `<`, `>`, `"`).
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// 403 page for `Block` / `Quarantine` verdicts and fast-path denials.
pub fn block_page(custom: Option<&ErrorPages>, trace: Option<Uuid>) -> Response {
    page_with(
        custom,
        StatusCode::FORBIDDEN,
        "403 - Forbidden",
        "You are unable to access this website.",
        trace,
    )
}

/// 429 for `RateLimit` verdicts.
pub fn rate_limit_page(custom: Option<&ErrorPages>, trace: Option<Uuid>) -> Response {
    let mut resp = page_with(
        custom,
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
pub fn challenge_required_page(custom: Option<&ErrorPages>, trace: Option<Uuid>) -> Response {
    page_with(
        custom,
        StatusCode::FORBIDDEN,
        "403 - Forbidden",
        "This resource requires verification. If you believe this is an error, contact the administrator.",
        trace,
    )
}

/// Terminal 403 page for a presented challenge cookie that failed
/// verification — the client tried and failed, so no retry loop.
pub fn challenge_failed_page(custom: Option<&ErrorPages>, trace: Option<Uuid>) -> Response {
    page_with(
        custom,
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
pub fn delegated_challenge_page(custom: Option<&ErrorPages>, trace: Option<Uuid>) -> Response {
    let mut resp = page_with(
        custom,
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

/// 413 for request bodies beyond the inspection/forward caps (F10/F12).
/// No event is persisted for these, so the trace id only lives on the page
/// and the caller's log line.
pub fn payload_too_large_page(custom: Option<&ErrorPages>, trace: Option<Uuid>) -> Response {
    page_with(
        custom,
        StatusCode::PAYLOAD_TOO_LARGE,
        "413 - Payload Too Large",
        "The request body exceeds the allowed size.",
        trace,
    )
}

/// 502 when the upstream cannot be reached or its response cannot be
/// relayed.
pub fn bad_gateway_page(custom: Option<&ErrorPages>, trace: Option<Uuid>) -> Response {
    page_with(
        custom,
        StatusCode::BAD_GATEWAY,
        "502 - Bad Gateway",
        "The upstream server is unavailable.",
        trace,
    )
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
        let resp = block_page(None, Some(trace()));
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
        let resp = block_page(None, None);
        assert!(resp.headers().get(TRACE_HEADER).is_none());
        let page = body(resp).await;
        assert!(!page.contains("Trace ID:"), "{page}");
    }

    #[tokio::test]
    async fn rate_limit_page_is_429_with_retry_after() {
        let resp = rate_limit_page(None, Some(trace()));
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "60");
        let page = body(resp).await;
        assert!(page.contains("429 - Too Many Requests"), "{page}");
        assert!(page.contains("Trace ID:"), "{page}");
    }

    #[tokio::test]
    async fn challenge_fallback_and_failed_pages_are_403() {
        for resp in [
            challenge_required_page(None, Some(trace())),
            challenge_failed_page(None, Some(trace())),
        ] {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let page = body(resp).await;
            assert!(page.contains("403 - Forbidden"), "{page}");
            assert!(page.contains("Trace ID:"), "{page}");
        }
    }

    #[tokio::test]
    async fn delegated_page_is_403_with_retry_after_3() {
        let resp = delegated_challenge_page(None, Some(trace()));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "3");
        let page = body(resp).await;
        assert!(page.contains("Verifying your browser..."), "{page}");
        assert!(page.contains("Trace ID:"), "{page}");
    }

    #[tokio::test]
    async fn oversized_and_bad_gateway_pages_are_html() {
        for resp in [
            payload_too_large_page(None, Some(trace())),
            bad_gateway_page(None, Some(trace())),
        ] {
            assert_eq!(
                resp.headers()
                    .get(header::CONTENT_TYPE)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "text/html; charset=utf-8"
            );
            assert_eq!(
                resp.headers().get(TRACE_HEADER).unwrap().to_str().unwrap(),
                trace().to_string()
            );
            let page = body(resp).await;
            assert!(page.contains("<!DOCTYPE html>"), "{page}");
            assert!(page.contains("Trace ID:"), "{page}");
            assert!(page.contains(&trace().to_string()), "{page}");
            assert!(
                page.contains("Performance &amp; security by Sentry"),
                "{page}"
            );
        }
        let resp = payload_too_large_page(None, None);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(resp.headers().get(TRACE_HEADER).is_none());
        let page = body(resp).await;
        assert!(page.contains("413 - Payload Too Large"), "{page}");
    }

    #[tokio::test]
    async fn custom_pages_override_by_status_and_fall_back_to_default() {
        let tmp = std::env::temp_dir().join(format!("sentry-pages-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("413.html"),
            "<html>{{SENTRY_STATUS}}|{{SENTRY_MESSAGE}}|{{SENTRY_TRACE_ID}}</html>",
        )
        .unwrap();
        std::fs::write(
            tmp.join("default.html"),
            "<html>generic {{SENTRY_TITLE}}|{{SENTRY_TRACE_ID}}</html>",
        )
        .unwrap();
        std::fs::write(tmp.join("bogus.txt"), "ignored").unwrap();
        std::fs::write(tmp.join("999.html"), "<html>ignored</html>").unwrap();
        let ep = ErrorPages::from_dir(&tmp);
        assert_eq!(ep.page_count(), 2);

        let resp = payload_too_large_page(Some(&ep), Some(trace()));
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.headers().get(TRACE_HEADER).unwrap().to_str().unwrap(),
            trace().to_string()
        );
        let page = body(resp).await;
        assert!(
            page.contains(&format!(
                "413|The request body exceeds the allowed size.|{}",
                trace()
            )),
            "{page}"
        );

        let resp = rate_limit_page(Some(&ep), Some(trace()));
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "60");
        let page = body(resp).await;
        assert!(page.contains("generic 429 - Too Many Requests"), "{page}");
        assert!(page.contains(&trace().to_string()), "{page}");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn custom_page_values_are_html_escaped() {
        let tmp = std::env::temp_dir().join(format!("sentry-pages-esc-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("502.html"), "<html>{{SENTRY_MESSAGE}}</html>").unwrap();
        let ep = ErrorPages::from_dir(&tmp);
        let resp = bad_gateway_page(Some(&ep), None);
        let page = body(resp).await;
        assert!(
            page.contains("The upstream server is unavailable."),
            "{page}"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn unreadable_page_dir_falls_back_to_builtin() {
        let missing = std::env::temp_dir().join("sentry-pages-does-not-exist");
        let ep = ErrorPages::from_dir(&missing);
        assert_eq!(ep.page_count(), 0);
        let resp = block_page(Some(&ep), Some(trace()));
        let page = body(resp).await;
        assert!(
            page.contains("You are unable to access this website."),
            "{page}"
        );
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
