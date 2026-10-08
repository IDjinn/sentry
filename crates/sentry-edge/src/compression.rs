//! Response compression for the inline edge (F12).
//!
//! Every edge response body is already buffered in memory (upstream
//! forwarding buffers; pages are rendered strings), so compression is a
//! synchronous re-encode behind one axum middleware: negotiate the request's
//! `Accept-Encoding` (zstd > brotli > gzip), re-encode the buffered body,
//! fix `content-encoding`/`Vary`/`content-length`, and count the hit.
//!
//! Never compressed: responses that already carry a `content-encoding`,
//! range responses (206 / `content-range`), bodies under
//! `min_length`, content types outside the compressible allowlist, and —
//! under overload pressure — anything (CPU shedding; the bytes still flow).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{self, HeaderValue};
use axum::http::{HeaderValue as Hv, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::io::Write as _;

use sentry_core::config::EdgeCompressConfig;
use sentry_core::OverloadState;

/// Wire name, metric label and preference order live in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    #[cfg(feature = "edge-zstd")]
    Zstd,
    Brotli,
    Gzip,
}

impl Encoding {
    /// `content-encoding` token.
    fn token(self) -> &'static str {
        match self {
            #[cfg(feature = "edge-zstd")]
            Encoding::Zstd => "zstd",
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            #[cfg(feature = "edge-zstd")]
            "zstd" => Some(Encoding::Zstd),
            "br" | "brotli" => Some(Encoding::Brotli),
            "gzip" | "x-gzip" => Some(Encoding::Gzip),
            _ => None,
        }
    }
}

/// Preference order when several encodings share the top q-value: zstd
/// decompresses fastest, brotli compresses best at browser-relevant levels,
/// gzip is the universal fallback.
fn preference() -> &'static [Encoding] {
    &[
        #[cfg(feature = "edge-zstd")]
        Encoding::Zstd,
        Encoding::Brotli,
        Encoding::Gzip,
    ]
}

/// Parse `Accept-Encoding` into `(token, q)` pairs with `q` scaled to
/// 0..=100. Malformed q-values are treated as 1.0 (the RFC's recommendation
/// for unparseable weights).
fn accept_pairs(value: &str) -> Vec<(&str, u32)> {
    value
        .split(',')
        .filter_map(|part| {
            let mut chunk = part.split(';');
            let token = chunk.next()?.trim();
            if token.is_empty() {
                return None;
            }
            let q = chunk
                .find_map(|p| p.trim().strip_prefix("q="))
                .and_then(|v| v.trim().parse::<f32>().ok())
                .filter(|q| (0.0..=1.0).contains(q))
                .map_or(100, |q| (q * 100.0).round() as u32);
            Some((token, q))
        })
        .collect()
}

/// Pick the best encoding for an `Accept-Encoding` header value: highest
/// q-value wins; ties break toward [`preference`] order (zstd > br > gzip).
pub fn negotiate(accept: Option<&HeaderValue>) -> Option<Encoding> {
    let accept = accept?;
    let pairs = accept_pairs(accept.to_str().ok()?);
    let rank = |enc: Encoding| {
        preference()
            .iter()
            .position(|e| *e == enc)
            .unwrap_or(usize::MAX)
    };
    let mut best: Option<(u32, usize, Encoding)> = None;
    for (token, q) in pairs {
        if q == 0 {
            continue;
        }
        let ranked: Box<dyn Iterator<Item = Encoding>> = match token.to_ascii_lowercase().as_str() {
            "*" => Box::new(preference().iter().copied()),
            t => Box::new(Encoding::from_token(t).into_iter()),
        };
        for enc in ranked {
            let candidate = (q, rank(enc), enc);
            let replace = match best {
                None => true,
                Some((bq, brank, _)) => q > bq || (q == bq && candidate.1 < brank),
            };
            if replace {
                best = Some(candidate);
            }
        }
    }
    best.map(|(_, _, enc)| enc)
}

/// Compressible content-type allowlist (nginx `gzip_types` semantics):
/// text formats and known-compressible application types. Everything else
/// (images, video, archives, streams) is already compressed or binary.
/// `text/event-stream` is excluded explicitly: streaming responses must
/// not be re-encoded even though they carry a `text/` type.
fn compressible_content_type(value: &str) -> bool {
    let ct = value.split(';').next().unwrap_or_default().trim();
    let ct = ct.to_ascii_lowercase();
    if ct == "text/event-stream" {
        return false;
    }
    ct.starts_with("text/")
        || ct.ends_with("+json")
        || ct.ends_with("+xml")
        || matches!(
            ct.as_str(),
            "application/json"
                | "application/javascript"
                | "application/x-javascript"
                | "application/xml"
                | "application/rss+xml"
                | "application/atom+xml"
                | "application/xhtml+xml"
                | "application/wasm"
                | "application/x-www-form-urlencoded"
                | "image/svg+xml"
        )
        || ct.contains("javascript")
}

/// Re-encode `input` with `enc` at the configured quality (clamped to the
/// algorithm's valid range).
fn encode(enc: Encoding, input: &[u8], cfg: &EdgeCompressConfig) -> Option<Vec<u8>> {
    match enc {
        #[cfg(feature = "edge-zstd")]
        Encoding::Zstd => {
            let level = i32::from(cfg.level_zstd.clamp(1, 22));
            zstd::bulk::compress(input, level).ok()
        }
        Encoding::Brotli => {
            let quality = u32::from(cfg.level_br.clamp(0, 11));
            let mut out = Vec::with_capacity(input.len() / 4 + 64);
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, quality, 22);
            w.write_all(input).ok()?;
            w.flush().ok()?;
            drop(w);
            Some(out)
        }
        Encoding::Gzip => {
            let level = u32::from(cfg.level_gzip.clamp(0, 9));
            let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level));
            w.write_all(input).ok()?;
            w.finish().ok()
        }
    }
}

fn vary_has_accept_encoding(headers: &axum::http::HeaderMap) -> bool {
    headers.get(header::VARY).is_some_and(|v| {
        v.to_str()
            .map(|s| {
                s.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
            })
            .unwrap_or(false)
    })
}

fn add_vary(headers: &mut axum::http::HeaderMap) {
    if vary_has_accept_encoding(headers) {
        return;
    }
    match headers.get_mut(header::VARY) {
        Some(existing) => {
            if let Ok(s) = existing.to_str() {
                if let Ok(joined) = Hv::from_str(&format!("{s}, accept-encoding")) {
                    *existing = joined;
                }
            }
        }
        None => {
            headers.insert(header::VARY, Hv::from_static("accept-encoding"));
        }
    }
}

/// Shared compression decision, built once per listener by the proxy and
/// shared across requests.
#[derive(Clone)]
pub struct Compressor {
    cfg: EdgeCompressConfig,
    overload: Option<OverloadState>,
    /// `sentry_edge_compressed_total{algo}` handle, wired by the daemon.
    metrics: Option<prometheus::CounterVec>,
}

impl Compressor {
    pub fn new(
        cfg: EdgeCompressConfig,
        overload: Option<OverloadState>,
        metrics: Option<prometheus::CounterVec>,
    ) -> Self {
        Self {
            cfg,
            overload,
            metrics,
        }
    }

    fn active(&self) -> bool {
        self.cfg.enabled && !self.overloaded()
    }

    fn overloaded(&self) -> bool {
        self.overload
            .as_ref()
            .is_some_and(OverloadState::under_pressure)
    }

    /// Apply the compression decision to a finished response. `accept` is
    /// the request's `Accept-Encoding` value, taken before the handler ran.
    pub async fn compress_response(
        &self,
        accept: Option<&HeaderValue>,
        resp: Response,
    ) -> Response {
        if !self.active() {
            return resp;
        }
        let (mut parts, body) = resp.into_parts();

        // Range responses: a re-encoded body no longer matches the
        // requested byte range, so 206 / content-range passes through.
        if parts.status == StatusCode::PARTIAL_CONTENT
            || parts.headers.contains_key(header::CONTENT_RANGE)
        {
            return Response::from_parts(parts, body);
        }
        // Already encoded upstream (br/gzip/deflate/identity/…) — pass.
        if parts.headers.contains_key(header::CONTENT_ENCODING) {
            return Response::from_parts(parts, body);
        }
        // "no-transform" forbids intermediate mutation, compression included.
        if parts
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("no-transform"))
            })
        {
            return Response::from_parts(parts, body);
        }
        let Some(ct) = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        else {
            return Response::from_parts(parts, body);
        };
        if !compressible_content_type(ct) {
            return Response::from_parts(parts, body);
        }

        // Bodies are buffered end-to-end on the edge, so this read is a
        // formality — but it is still the only way to own the bytes.
        let bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(error = %e, "edge compress: body read failed, passing through");
                return Response::from_parts(parts, Body::empty());
            }
        };
        if bytes.len() < self.cfg.min_length {
            add_vary(&mut parts.headers);
            return Response::from_parts(parts, Body::from(bytes));
        }

        let Some(enc) = negotiate(accept) else {
            add_vary(&mut parts.headers);
            return Response::from_parts(parts, Body::from(bytes));
        };
        let Some(compressed) = encode(enc, &bytes, &self.cfg) else {
            tracing::debug!("edge compress: encoder failed, passing through uncompressed");
            return Response::from_parts(parts, Body::from(bytes));
        };
        if compressed.len() >= bytes.len() {
            // Nothing to save (tiny/entropy-heavy payloads) — the uncompressed
            // bytes are the better wire format.
            add_vary(&mut parts.headers);
            return Response::from_parts(parts, Body::from(bytes));
        }

        let token = enc.token();
        parts.headers.insert(
            header::CONTENT_ENCODING,
            Hv::from_str(token).expect("encoding token is a valid header value"),
        );
        add_vary(&mut parts.headers);
        if let Ok(len) = compressed.len().to_string().parse() {
            parts.headers.insert(header::CONTENT_LENGTH, len);
        }
        if let Some(m) = &self.metrics {
            m.with_label_values(&[token]).inc();
        }
        Response::from_parts(parts, Body::from(compressed))
    }
}

/// The axum middleware installed by the proxy: capture `Accept-Encoding`
/// before the handler runs, compress the response on the way out.
pub async fn compress_layer(compressor: Arc<Compressor>, req: Request, next: Next) -> Response {
    let accept = req.headers().get(header::ACCEPT_ENCODING).cloned();
    let resp = next.run(req).await;
    compressor.compress_response(accept.as_ref(), resp).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn cfg() -> EdgeCompressConfig {
        EdgeCompressConfig::default()
    }

    /// Long enough to clear the default 256-byte floor.
    const HTML: &str = concat!(
        "<html><body><h1>hello</h1>",
        "<p>sentry edge compression test page with enough text to clear the ",
        "minimum length floor so the encoder actually runs and the response ",
        "carries a content-encoding header back to the client.</p>",
        "<p>second paragraph adds a little more body for the encoder.</p>",
        "</body></html>"
    );

    #[test]
    fn negotiate_prefers_highest_q_then_order() {
        let v = |s: &str| HeaderValue::from_str(s).unwrap();
        assert_eq!(negotiate(Some(&v("gzip"))), Some(Encoding::Gzip));
        assert_eq!(negotiate(Some(&v("br, gzip"))), Some(Encoding::Brotli));
        assert_eq!(
            negotiate(Some(&v("gzip;q=1.0, br;q=0.8"))),
            Some(Encoding::Gzip)
        );
        assert_eq!(
            negotiate(Some(&v("gzip;q=0.5, br;q=0.5"))),
            Some(Encoding::Brotli),
            "tie broken by preference order"
        );
        // Wildcard resolves to the head of the preference order, which is
        // zstd when the `edge-zstd` feature is compiled, brotli otherwise.
        #[cfg(feature = "edge-zstd")]
        assert_eq!(negotiate(Some(&v("*"))), Some(Encoding::Zstd));
        #[cfg(not(feature = "edge-zstd"))]
        assert_eq!(negotiate(Some(&v("*"))), Some(Encoding::Brotli));
        assert_eq!(
            negotiate(Some(&v("gzip;q=0, br"))),
            Some(Encoding::Brotli),
            "q=0 excludes an encoding"
        );
        assert_eq!(negotiate(Some(&v("deflate"))), None, "unsupported algo");
        #[cfg(feature = "edge-zstd")]
        assert_eq!(
            negotiate(Some(&v("deflate, *;q=0.1"))),
            Some(Encoding::Zstd)
        );
        #[cfg(not(feature = "edge-zstd"))]
        assert_eq!(
            negotiate(Some(&v("deflate, *;q=0.1"))),
            Some(Encoding::Brotli)
        );
        assert_eq!(negotiate(None), None);
        assert_eq!(negotiate(Some(&v(""))), None);
    }

    #[test]
    fn content_type_allowlist_matches_nginx_gzip_types() {
        assert!(compressible_content_type("text/html; charset=utf-8"));
        assert!(compressible_content_type("application/json"));
        assert!(compressible_content_type("application/vnd.api+json"));
        assert!(compressible_content_type("application/ld+json; profile=x"));
        assert!(compressible_content_type("text/javascript"));
        assert!(compressible_content_type("application/x-javascript"));
        assert!(compressible_content_type("image/svg+xml"));
        assert!(compressible_content_type("application/wasm"));
        assert!(!compressible_content_type("image/png"));
        assert!(!compressible_content_type("video/mp4"));
        assert!(!compressible_content_type("application/zip"));
        assert!(!compressible_content_type("application/octet-stream"));
        assert!(
            !compressible_content_type("text/event-stream"),
            "streaming responses are excluded explicitly"
        );
    }

    #[tokio::test]
    async fn compresses_html_for_brotli_clients() {
        let c = Compressor::new(cfg(), None, None);
        let resp = Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(HTML))
            .unwrap();
        let accept = HeaderValue::from_static("gzip, deflate, br");
        let out = c.compress_response(Some(&accept), resp).await;
        assert_eq!(
            out.headers()
                .get(header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("br")
        );
        let vary = out
            .headers()
            .get(header::VARY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(vary.contains("accept-encoding"), "vary: {vary}");
        let bytes = axum::body::to_bytes(out.into_body(), usize::MAX)
            .await
            .unwrap();
        let raw = HTML;
        assert!(bytes.len() < raw.len(), "compressed smaller");
    }

    #[tokio::test]
    async fn gzip_fallback_and_content_length_update() {
        let c = Compressor::new(cfg(), None, None);
        let resp = Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, "99999")
            .body(Body::from(HTML))
            .unwrap();
        let accept = HeaderValue::from_static("gzip");
        let out = c.compress_response(Some(&accept), resp).await;
        assert_eq!(
            out.headers()
                .get(header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
        let len: usize = out
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("content-length refreshed");
        let bytes = axum::body::to_bytes(out.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(len, bytes.len(), "content-length matches the new body");
    }

    #[tokio::test]
    async fn skips_encoded_range_small_and_incompressible() {
        let c = Compressor::new(cfg(), None, None);
        let accept = HeaderValue::from_static("br");
        let build = |f: axum::http::response::Builder| f.body(Body::from(HTML)).unwrap();

        // Already compressed upstream.
        let resp = build(
            Response::builder()
                .header(header::CONTENT_TYPE, "text/html")
                .header(header::CONTENT_ENCODING, "br"),
        );
        let out = c.compress_response(Some(&accept), resp).await;
        assert!(out.headers().get(header::CONTENT_ENCODING).is_some());
        // Untouched: still the upstream's own br token, no double layer.
        let bytes = axum::body::to_bytes(out.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), HTML.as_bytes());

        // Range response.
        let resp = build(
            Response::builder()
                .status(206)
                .header(header::CONTENT_TYPE, "text/html")
                .header(header::CONTENT_RANGE, "bytes 0-99/500"),
        );
        let out = c.compress_response(Some(&accept), resp).await;
        assert_eq!(out.status(), 206);
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());

        // no-transform.
        let resp = build(
            Response::builder()
                .header(header::CONTENT_TYPE, "text/html")
                .header(header::CACHE_CONTROL, "private, no-transform"),
        );
        let out = c.compress_response(Some(&accept), resp).await;
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());

        // Below the size floor: vary still set for cache correctness.
        let resp = Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from("<b>ok</b>"))
            .unwrap();
        let out = c.compress_response(Some(&accept), resp).await;
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());
        assert!(out.headers().get(header::VARY).is_some());

        // Images are never re-encoded.
        let resp = build(Response::builder().header(header::CONTENT_TYPE, "image/png"));
        let out = c.compress_response(Some(&accept), resp).await;
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());

        // No accept-encoding at all.
        let resp = build(Response::builder().header(header::CONTENT_TYPE, "text/html"));
        let out = c.compress_response(None, resp).await;
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn overload_pressure_disables_compression() {
        let state = OverloadState::new();
        let c = Compressor::new(cfg(), Some(state.clone()), None);
        let resp = Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from(HTML))
            .unwrap();
        let accept = HeaderValue::from_static("br");
        state.set_pressure(true);
        let out = c.compress_response(Some(&accept), resp).await;
        assert!(
            out.headers().get(header::CONTENT_ENCODING).is_none(),
            "cheap mode sheds the compression CPU"
        );
    }

    #[tokio::test]
    async fn disabled_config_passes_everything_through() {
        let mut c = cfg();
        c.enabled = false;
        let compressor = Compressor::new(c, None, None);
        let resp = Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from(HTML))
            .unwrap();
        let accept = HeaderValue::from_static("br");
        let out = compressor.compress_response(Some(&accept), resp).await;
        assert!(out.headers().get(header::CONTENT_ENCODING).is_none());
        assert!(out.headers().get(header::VARY).is_none());
    }

    #[tokio::test]
    async fn incompressible_payload_stays_uncompressed() {
        // Hash-chain bytes look random to the encoders: no savings means
        // the passthrough rule keeps the original body.
        let noisy: Vec<u8> = (0..1024u64)
            .map(|i| {
                use std::hash::{Hash, Hasher};
                let mut h = std::hash::DefaultHasher::new();
                i.hash(&mut h);
                h.finish() as u8
            })
            .collect();
        let c = Compressor::new(cfg(), None, None);
        let resp = Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(noisy.clone()))
            .unwrap();
        let accept = HeaderValue::from_static("br");
        let out = c.compress_response(Some(&accept), resp).await;
        assert!(
            out.headers().get(header::CONTENT_ENCODING).is_none(),
            "no saving means no encoding"
        );
        let bytes = axum::body::to_bytes(out.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), noisy.as_slice());
    }
}
