//! Stateless JavaScript proof-of-work challenge for the inline edge (F7.8).
//!
//! A `Challenge` verdict normally means "hand the client to a CDN" — but an
//! inline edge has no CDN behind it, so it runs the check itself, the way
//! the nginx `js_challenge` module does: first-time visitors get a 503 page
//! whose JavaScript must find a nonce such that
//! `SHA-256(challenge_id || ":" || nonce)` has `difficulty` leading zero
//! bits, set it as a cookie and reload. Browsers solve this in well under a
//! second; clients without JS (curl, most bots) never do.
//!
//! The design is stateless and multi-node safe: `challenge_id` is derived
//! from `SHA-256(secret || ip || bucket)`, and validation recomputes the
//! PoW from the cookie contents — no server-side session, only a shared
//! secret. The bucket (a wall-clock window) rotates the challenge and
//! expires cookies; the previous bucket is honored for boundary grace.
//!
//! Cookie states are classified, Cloudflare-style: no cookie or an expired
//! one re-serves the interstitial (503); a cookie that is present but fails
//! verification (bad nonce, tampered) is a completed, failed attempt and
//! gets a plain 403 — a client without JavaScript loops on the interstitial,
//! a client that *tried and failed* does not.
//!
//! The page HTML is a template with `{{TITLE}}`, `{{ICON}}`, `{{CHALLENGE}}`,
//! `{{DIFFICULTY}}`, `{{BUCKET}}`, `{{MAX_AGE}}` and `{{SECURE}}` markers.
//! `[edge.challenge] template_path` points at a custom file; it is re-read
//! on every render (edits go live without a restart) and falls back to the
//! built-in page while missing or invalid.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

/// Cookie carrying the proof-of-work solution.
pub const COOKIE_NAME: &str = "sentry_ch";
/// Status used for the challenge interstitial (matches the nginx module:
/// 503 so caches don't pin the page as the real content).
pub const CHALLENGE_STATUS: StatusCode = StatusCode::SERVICE_UNAVAILABLE;
/// Status served when a presented cookie fails verification (the "you
/// tried and failed" terminal state, the way a CDN blocks after a
/// challenge is not solved).
pub const FAILED_STATUS: StatusCode = StatusCode::FORBIDDEN;

/// Placeholders a custom template must carry for the challenge to work at
/// all — the JS builds and validates the cookie from these.
const REQUIRED_PLACEHOLDERS: [&str; 5] = [
    "{{CHALLENGE}}",
    "{{DIFFICULTY}}",
    "{{BUCKET}}",
    "{{MAX_AGE}}",
    "{{SECURE}}",
];

/// Project logo, embedded once as a `data:` URI so pages stay
/// self-contained (no CDN, no extra requests).
static ICON_DATA_URI: LazyLock<String> = LazyLock::new(|| {
    format!(
        "data:image/png;base64,{}",
        base64(include_bytes!("../assets/sentry-icon.png"))
    )
});

/// Outcome of checking a presented `sentry_ch` cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieCheck {
    /// PoW verified — let the request through.
    Valid,
    /// Cookie is present and structurally a solve attempt, but the nonce
    /// does not verify: terminal failure.
    Failed,
    /// Cookie from a bucket outside the current/previous window: expired
    /// (or forged), worth a fresh interstitial rather than a block.
    Stale,
}

/// Rendered challenge configuration (secret resolved from the environment).
#[derive(Debug, Clone)]
pub struct JsChallenge {
    secret: Vec<u8>,
    bucket_secs: u64,
    difficulty: u8,
    title: String,
    template_path: Option<PathBuf>,
}

impl JsChallenge {
    /// Build from resolved settings. `difficulty` is clamped to `8..=28`
    /// (below 8 is pointless, above 28 starts costing seconds even for
    /// browsers). `template_path` optionally overrides the page HTML; it is
    /// re-read on every render and falls back to the built-in page when
    /// missing or missing required placeholders.
    pub fn new(
        secret: Vec<u8>,
        bucket_secs: u64,
        difficulty: u8,
        title: String,
        template_path: Option<PathBuf>,
    ) -> Self {
        Self {
            secret,
            bucket_secs: bucket_secs.max(60),
            difficulty: difficulty.clamp(8, 28),
            title,
            template_path,
        }
    }

    /// Current wall-clock bucket index.
    pub fn current_bucket(&self, now: SystemTime) -> u64 {
        now.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / self.bucket_secs)
            .unwrap_or(0)
    }

    /// Deterministic challenge for an IP within one bucket — every request
    /// from the same IP in the window sees the same puzzle.
    pub fn challenge_id(&self, ip: IpAddr, bucket: u64) -> String {
        let mut h = Sha256::new();
        h.update(&self.secret);
        h.update(ip.to_string().as_bytes());
        h.update(bucket.to_be_bytes());
        hex::encode(h.finalize())
    }

    /// Classify a `sentry_ch` cookie value (`"<bucket>:<nonce>"`) for `ip`.
    ///
    /// Accepts the current bucket and the previous one (a solve right at a
    /// boundary must not loop). Rejects future buckets outright.
    pub fn classify_cookie(&self, ip: IpAddr, value: &str, now: SystemTime) -> CookieCheck {
        let Some((bucket_raw, nonce)) = value.split_once(':') else {
            return CookieCheck::Failed;
        };
        if nonce.is_empty() || nonce.len() > 64 || bucket_raw.len() > 20 {
            return CookieCheck::Failed;
        }
        let Ok(bucket) = bucket_raw.parse::<u64>() else {
            return CookieCheck::Failed;
        };
        let current = self.current_bucket(now);
        if bucket != current && bucket + 1 != current {
            return CookieCheck::Stale;
        }
        let mut h = Sha256::new();
        h.update(self.challenge_id(ip, bucket).as_bytes());
        h.update(b":");
        h.update(nonce.as_bytes());
        if leading_zero_bits(&h.finalize()) >= self.difficulty {
            CookieCheck::Valid
        } else {
            CookieCheck::Failed
        }
    }

    /// Validate a `sentry_ch` cookie value for `ip`.
    pub fn verify_cookie(&self, ip: IpAddr, value: &str, now: SystemTime) -> bool {
        self.classify_cookie(ip, value, now) == CookieCheck::Valid
    }

    /// Render the challenge interstitial for `ip`.
    ///
    /// `https` adds the `Secure` cookie attribute (scheme plus
    /// `X-Forwarded-Proto`, for edges behind a TLS terminator).
    pub fn page_response(&self, ip: IpAddr, headers: &HeaderMap, now: SystemTime) -> Response {
        let bucket = self.current_bucket(now);
        let max_age = (self.bucket_secs * 2).min(u32::MAX as u64);
        let https = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(',').any(|p| p.trim().eq_ignore_ascii_case("https")))
            .unwrap_or(false);
        let html = self
            .load_template()
            .replace("{{TITLE}}", &self.title)
            .replace("{{ICON}}", &ICON_DATA_URI)
            .replace("{{CHALLENGE}}", &self.challenge_id(ip, bucket))
            .replace("{{DIFFICULTY}}", &self.difficulty.to_string())
            .replace("{{BUCKET}}", &bucket.to_string())
            .replace("{{MAX_AGE}}", &max_age.to_string())
            .replace("{{SECURE}}", if https { "true" } else { "false" });
        (
            CHALLENGE_STATUS,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::RETRY_AFTER, "3"),
                (header::CACHE_CONTROL, "no-store, max-age=0"),
            ],
            html,
        )
            .into_response()
    }

    /// Terminal 403 page for a cookie that failed verification.
    pub fn failed_response(&self) -> Response {
        let html = FAILED_HTML
            .replace("{{TITLE}}", &self.title)
            .replace("{{ICON}}", &ICON_DATA_URI);
        (
            FAILED_STATUS,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store, max-age=0"),
            ],
            html,
        )
            .into_response()
    }

    /// Resolve the page template: the configured file when readable and
    /// complete, the built-in page otherwise. Re-read on every call so
    /// template edits go live without a restart.
    fn load_template(&self) -> String {
        let Some(path) = &self.template_path else {
            return DEFAULT_CHALLENGE_HTML.to_string();
        };
        match std::fs::read_to_string(path) {
            Ok(t) if REQUIRED_PLACEHOLDERS.iter().all(|p| t.contains(p)) => t,
            Ok(_) => {
                tracing::warn!(
                    path = %path.display(),
                    "challenge template is missing required placeholders \
                     ({{CHALLENGE}}, {{DIFFICULTY}}, {{BUCKET}}, {{MAX_AGE}}, {{SECURE}}) — \
                     using the built-in page"
                );
                DEFAULT_CHALLENGE_HTML.to_string()
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "challenge template unreadable — using the built-in page"
                );
                DEFAULT_CHALLENGE_HTML.to_string()
            }
        }
    }
}

/// Count leading zero bits of a SHA-256 digest (the PoW measure).
pub fn leading_zero_bits(hash: &[u8]) -> u8 {
    let mut bits = 0u8;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros() as u8;
            break;
        }
    }
    bits
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

/// Extract a cookie value from a `Cookie` header (first match wins).
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Parse all cookies from a `Cookie` header (for `HttpData.cookies`).
pub fn parse_cookies(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Some(raw) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return map;
    };
    for pair in raw.split(';') {
        if let Some((k, v)) = pair.trim().split_once('=') {
            if !k.is_empty() {
                map.insert(k.to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }
    map
}

/// The self-contained challenge page: WebCrypto SHA-256 proof-of-work, dark
/// theme matching the other edge verdict pages, no external resources.
/// Editable via `[edge.challenge] template_path` — keep the five required
/// `{{…}}` markers; `{{TITLE}}` and `{{ICON}}` are optional.
const DEFAULT_CHALLENGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}
.box{text-align:center}
.icon{width:56px;height:56px;margin-bottom:.75rem}
h1{font-size:1.4rem;margin:0 0 .5rem}
p{color:#8b949e;margin:.25rem 0}
.spinner{width:28px;height:28px;margin:1.25rem auto 0;border:3px solid #21262d;border-top-color:#58a6ff;border-radius:50%;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="box">
<img class="icon" src="{{ICON}}" alt="">
<h1>{{TITLE}}</h1>
<p>This check helps block abusive automated traffic.</p>
<noscript><p>JavaScript is required to continue. Enable it and reload.</p></noscript>
<div class="spinner"></div>
</div>
<script>
(async () => {
  const enc = new TextEncoder();
  const prefix = enc.encode("{{CHALLENGE}}:");
  const difficulty = {{DIFFICULTY}};
  const meets = (d) => {
    let bits = 0;
    for (let i = 0; i < d.length; i++) {
      if (d[i] !== 0) return bits + Math.clz32(d[i]) - 24 >= difficulty;
      bits += 8;
    }
    return bits >= difficulty;
  };
  for (let n = 0; ; n++) {
    const suffix = enc.encode(String(n));
    const buf = new Uint8Array(prefix.length + suffix.length);
    buf.set(prefix);
    buf.set(suffix, prefix.length);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
    if (meets(digest)) {
      document.cookie = "sentry_ch={{BUCKET}}:" + n +
        "; Path=/; Max-Age={{MAX_AGE}}; SameSite=Lax" + ({{SECURE}} ? "; Secure" : "");
      location.reload();
      return;
    }
  }
})();
</script>
</body>
</html>
"#;

/// Terminal page for a cookie that failed verification (no retry loop —
/// the client proved it cannot or will not solve the challenge).
const FAILED_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>403 — verification failed</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}
.box{text-align:center}
.icon{width:56px;height:56px;margin-bottom:.75rem}
h1{font-size:1.4rem;margin:0 0 .5rem}
p{color:#8b949e;margin:.25rem 0}
</style>
</head>
<body>
<div class="box">
<img class="icon" src="{{ICON}}" alt="">
<h1>403 — verification failed</h1>
<p>Your browser did not pass the security check.</p>
<p>If you believe this is an error, contact the administrator.</p>
</div>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn challenge() -> JsChallenge {
        JsChallenge::new(b"test-secret".to_vec(), 3600, 12, "Verifying…".into(), None)
    }

    fn fixed_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// Reference JS-equivalent solver (same algorithm the browser runs).
    fn solve(ch: &JsChallenge, ip: IpAddr, bucket: u64) -> String {
        let id = ch.challenge_id(ip, bucket);
        for n in 0u64.. {
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            h.update(b":");
            h.update(n.to_string().as_bytes());
            if leading_zero_bits(&h.finalize()) >= ch.difficulty {
                return n.to_string();
            }
        }
        unreachable!()
    }

    #[test]
    fn leading_zero_bits_counts_across_bytes() {
        assert_eq!(leading_zero_bits(&[0, 0, 0]), 24);
        assert_eq!(leading_zero_bits(&[0b1000_0000, 0xff]), 0);
        assert_eq!(leading_zero_bits(&[0b0100_0000, 0xff]), 1);
        assert_eq!(leading_zero_bits(&[0b0000_1111, 0xff]), 4);
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

    #[test]
    fn challenge_id_is_deterministic_and_ip_bound() {
        let ch = challenge();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(ch.challenge_id(ip, 5), ch.challenge_id(ip, 5));
        assert_ne!(ch.challenge_id(ip, 5), ch.challenge_id(ip, 6));
        assert_ne!(
            ch.challenge_id(ip, 5),
            ch.challenge_id("203.0.113.8".parse().unwrap(), 5)
        );
    }

    #[test]
    fn cookie_classification_covers_all_states() {
        let ch = challenge();
        let now = fixed_now();
        let bucket = ch.current_bucket(now);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        assert_eq!(
            ch.classify_cookie(ip, &format!("{bucket}:{}", solve(&ch, ip, bucket)), now),
            CookieCheck::Valid
        );
        assert_eq!(
            ch.classify_cookie(ip, &format!("{bucket}:0"), now),
            CookieCheck::Failed
        );
        assert_eq!(
            ch.classify_cookie(ip, &format!("{bucket}:' OR '1'='1"), now),
            CookieCheck::Failed
        );
        assert_eq!(
            ch.classify_cookie(
                ip,
                &format!("{}:{}", bucket - 2, solve(&ch, ip, bucket - 2)),
                now
            ),
            CookieCheck::Stale
        );
        assert_eq!(
            ch.classify_cookie(ip, &format!("{}:{}", bucket + 5, "x"), now),
            CookieCheck::Stale
        );
        assert_eq!(ch.classify_cookie(ip, "garbage", now), CookieCheck::Failed);
        assert_eq!(ch.classify_cookie(ip, "", now), CookieCheck::Failed);

        assert_eq!(
            ch.classify_cookie(
                ip,
                &format!("{bucket}:{}", solve(&ch, ip, bucket) + "0"),
                now
            ),
            CookieCheck::Failed
        );
    }

    #[test]
    fn previous_bucket_is_grace_current_minus_two_is_not() {
        let ch = challenge();
        let now = fixed_now();
        let bucket = ch.current_bucket(now);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        let prev = format!("{}:{}", bucket - 1, solve(&ch, ip, bucket - 1));
        assert!(ch.verify_cookie(ip, &prev, now));

        let stale = format!("{}:{}", bucket - 2, solve(&ch, ip, bucket - 2));
        assert!(!ch.verify_cookie(ip, &stale, now));
    }

    #[test]
    fn page_response_embeds_challenge_icon_and_sets_503() {
        let ch = challenge();
        let now = fixed_now();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let mut headers = HeaderMap::new();
        let resp = ch.page_response(ip, &headers, now);
        assert_eq!(resp.status(), CHALLENGE_STATUS);

        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let resp = ch.page_response(ip, &headers, now);
        assert_eq!(resp.status(), CHALLENGE_STATUS);
    }

    #[tokio::test]
    async fn page_response_includes_icon_and_title() {
        let ch = challenge();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let resp = ch.page_response(ip, &HeaderMap::new(), fixed_now());
        let page = body_bytes(resp).await;
        assert!(page.contains("data:image/png;base64,"), "page: {page}");
        assert!(page.contains("Verifying…"), "page: {page}");
        assert!(!page.contains("{{CHALLENGE}}"), "page: {page}");
    }

    #[test]
    fn failed_response_is_a_plain_403_page() {
        let ch = challenge();
        let resp = ch.failed_response();
        assert_eq!(resp.status(), FAILED_STATUS);
    }

    #[tokio::test]
    async fn template_override_is_hot_read_and_validated() {
        let dir = std::env::temp_dir().join(format!("sentry-ch-tpl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("challenge.html");

        let ch = JsChallenge::new(
            b"test-secret".to_vec(),
            3600,
            12,
            "t".into(),
            Some(path.clone()),
        );
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        // Missing file → built-in page.
        let page = body_bytes(ch.page_response(ip, &HeaderMap::new(), fixed_now())).await;
        assert!(page.contains("crypto.subtle"), "page: {page}");

        // Incomplete template (no {{CHALLENGE}}) → built-in page.
        std::fs::write(&path, "<html>{{TITLE}}</html>").unwrap();
        let page = body_bytes(ch.page_response(ip, &HeaderMap::new(), fixed_now())).await;
        assert!(page.contains("crypto.subtle"), "page: {page}");

        // Complete custom template renders as-is, with placeholders filled.
        std::fs::write(
            &path,
            "<html><body data-ch=\"{{CHALLENGE}}\" data-d=\"{{DIFFICULTY}}\" \
             data-b=\"{{BUCKET}}\" data-m=\"{{MAX_AGE}}\" data-s=\"{{SECURE}}\">{{ICON}}</body></html>",
        )
        .unwrap();
        let page = body_bytes(ch.page_response(ip, &HeaderMap::new(), fixed_now())).await;
        let id = ch.challenge_id(ip, ch.current_bucket(fixed_now()));
        assert!(page.contains(&id), "page: {page}");
        assert!(page.contains("data-d=\"12\""), "page: {page}");
        assert!(page.contains("data-m=\"7200\""), "page: {page}");
        assert!(page.contains("data-s=\"false\""), "page: {page}");
        assert!(page.contains("data:image/png;base64,"), "page: {page}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cookie_value_finds_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; sentry_ch=42:abc; more=2".parse().unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, COOKIE_NAME).as_deref(),
            Some("42:abc")
        );
        assert_eq!(cookie_value(&headers, "missing"), None);

        let mut empty = HeaderMap::new();
        assert_eq!(cookie_value(&empty, COOKIE_NAME), None);
        empty.insert(header::COOKIE, "sentry_ch=7:x".parse().unwrap());
        assert_eq!(cookie_value(&empty, COOKIE_NAME).as_deref(), Some("7:x"));
    }

    #[test]
    fn parse_cookies_covers_pairs() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "A=1; b=two; ;c= ".parse().unwrap());
        let map = parse_cookies(&headers);
        assert_eq!(map.get("a").map(String::as_str), Some("1"));
        assert_eq!(map.get("b").map(String::as_str), Some("two"));
        assert_eq!(map.get("c").map(String::as_str), Some(""));
        assert!(parse_cookies(&HeaderMap::new()).is_empty());
    }

    #[test]
    fn difficulty_is_clamped() {
        let low = JsChallenge::new(vec![], 3600, 1, "t".into(), None);
        let high = JsChallenge::new(vec![], 3600, 99, "t".into(), None);
        assert_eq!(low.difficulty, 8);
        assert_eq!(high.difficulty, 28);
    }

    // ── End-to-end: EdgeRuntime gate + axum middleware ───────────────────

    fn challenge_pipeline() -> std::sync::Arc<sentry_core::Pipeline> {
        use sentry_core::rules::{Rule, RuleAction, RuleMatch, RuleSet, RuleSource};
        use sentry_core::RouteValidator;
        let rule = Rule {
            id: "challenge_locked".into(),
            name: "challenge /locked".into(),
            priority: 1,
            enabled: true,
            match_: RuleMatch::Path {
                op: sentry_core::rules::PathOp::Glob,
                pattern: "/locked*".into(),
            },
            action: RuleAction::Challenge,
            ttl: None,
            source: RuleSource::Config,
            tags: vec![],
            created_at: None,
            log_level: None,
        };
        std::sync::Arc::new(sentry_core::Pipeline::new(
            RuleSet::new(vec![rule]),
            RouteValidator::default(),
        ))
    }

    fn challenge_app(rt: crate::EdgeRuntime) -> axum::Router {
        axum::Router::new()
            .route("/locked", axum::routing::get(|| async { "ok" }))
            .route_layer(axum::middleware::from_fn_with_state(
                rt.clone(),
                crate::middleware::handler,
            ))
            .with_state(rt)
    }

    /// The middleware peer fallback (no ConnectInfo extension) is
    /// 127.0.0.1 — solve for it like the browser would.
    fn solve_now(ch: &JsChallenge, ip: IpAddr) -> String {
        let bucket = ch.current_bucket(SystemTime::now());
        solve(ch, ip, bucket)
    }

    async fn body_bytes(resp: Response) -> String {
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn middleware_serves_pow_then_accepts_solution() {
        let ch = challenge();
        let rt = crate::EdgeRuntime::new(challenge_pipeline(), None, 0)
            .with_challenge(Arc::new(ch.clone()));
        let app = challenge_app(rt);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/locked")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), CHALLENGE_STATUS);
        let page = body_bytes(resp).await;
        assert!(page.contains("crypto.subtle"), "page: {page}");
        // The embedded challenge must match what the server validates.
        let id = ch.challenge_id(ip, ch.current_bucket(SystemTime::now()));
        assert!(page.contains(&id), "page: {page}");

        let solution = solve_now(&ch, ip);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/locked")
                    .header(
                        "cookie",
                        format!(
                            "{}={}:{}",
                            COOKIE_NAME,
                            ch.current_bucket(SystemTime::now()),
                            solution
                        ),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn failed_and_stale_cookies_split_403_from_fresh_interstitial() {
        let ch = challenge();
        let rt = crate::EdgeRuntime::new(challenge_pipeline(), None, 0)
            .with_challenge(Arc::new(ch.clone()));
        let app = challenge_app(rt);

        let req = |cookie: String| {
            axum::http::Request::builder()
                .uri("/locked")
                .header("cookie", format!("{COOKIE_NAME}={cookie}"))
                .body(axum::body::Body::empty())
                .unwrap()
        };

        // Present but wrong nonce: terminal failure → 403, not a loop.
        let bucket = ch.current_bucket(SystemTime::now());
        let resp = app
            .clone()
            .oneshot(req(format!("{bucket}:0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        let page = body_bytes(resp).await;
        assert!(page.contains("verification failed"), "page: {page}");

        // Expired bucket: fresh interstitial (503), the client may retry.
        let stale_bucket = bucket.saturating_sub(10);
        let resp = app
            .clone()
            .oneshot(req(format!("{stale_bucket}:123")))
            .await
            .unwrap();
        assert_eq!(resp.status(), CHALLENGE_STATUS);

        // Garbage cookie: tamper, terminal 403.
        let resp = app.oneshot(req("garbage".into())).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn verified_bot_bypasses_and_spoofed_bot_stays_challenged() {
        let verifier = Arc::new(sentry_core::botverify::BotVerifier::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));
        let bot_ip: IpAddr = "66.249.66.1".parse().unwrap();
        let fake_ip: IpAddr = "66.249.66.2".parse().unwrap();
        verifier.insert(
            bot_ip,
            sentry_core::botverify::BotStatus::Verified(sentry_core::botverify::BotEngine::Google),
        );
        verifier.insert(fake_ip, sentry_core::botverify::BotStatus::Spoofed);

        let rt = crate::EdgeRuntime::new(challenge_pipeline(), None, 0)
            .with_challenge(Arc::new(challenge()))
            .with_bot_verifier(verifier);
        let app = challenge_app(rt);
        let req = |ip_headers: (&str, &str)| {
            axum::http::Request::builder()
                .uri("/locked")
                .header(
                    "user-agent",
                    "Googlebot/2.1 (+http://www.google.com/bot.html)",
                )
                .header("x-forwarded-for", ip_headers.1)
                .body(axum::body::Body::empty())
                .unwrap()
        };

        // Verified Googlebot passes without solving anything.
        let resp = app
            .clone()
            .oneshot(req(("ua", "66.249.66.1")))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // A spoofed claimant (JS-less) stays stuck on the PoW.
        let resp = app.oneshot(req(("ua", "66.249.66.2"))).await.unwrap();
        assert_eq!(resp.status(), CHALLENGE_STATUS);
    }

    #[tokio::test]
    async fn gate_disabled_falls_back_to_static_page() {
        let rt = crate::EdgeRuntime::new(challenge_pipeline(), None, 0);
        let app = challenge_app(rt);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/locked")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }
}
