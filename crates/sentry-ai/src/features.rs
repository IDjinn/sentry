//! Numeric feature extraction for the classic-ML threat model.
//!
//! This module is the **single source of truth** for the model input: the
//! same [`extract`] runs at inference time (daemon fork) and at training
//! time (`sentry model export` writes these vectors to CSV), so training
//! and inference can never drift apart. `tools/train_model.py` validates
//! its CSV header against [`FEATURE_NAMES`].
//!
//! All features are normalized to `0.0–1.0` so a plain logistic regression
//! over them behaves well. Non-HTTP events extract an all-zero vector
//! (fixed length, safe to feed the model).

/// Ordered feature names — must match the ONNX model input width and the
/// CSV header produced by `sentry model export`.
pub const FEATURE_NAMES: &[&str] = &[
    "path_len",
    "query_len",
    "path_depth",
    "path_digit_ratio",
    "path_special_ratio",
    "path_entropy",
    "path_encoded_count",
    "path_dot_dot",
    "path_null_byte",
    "sqli_token_score",
    "xss_token_score",
    "traversal_token_score",
    "jndi_token",
    "cmd_token_score",
    "has_file_ext",
    "ext_is_script",
    "ext_is_sensitive",
    "method_is_get",
    "method_is_post",
    "ua_len",
    "ua_is_empty",
    "ua_bot_token",
    "status_4xx",
    "status_5xx",
    "query_param_count",
];

/// Extract the feature vector for an event (length = `FEATURE_NAMES.len()`).
pub fn extract(evt: &sentry_core::Event) -> Vec<f32> {
    let Some(http) = evt.http() else {
        return vec![0.0; FEATURE_NAMES.len()];
    };

    let path = &http.path;
    let query = http.query.as_deref().unwrap_or("");
    let decoded_path = url_decode(path);
    let decoded_query = url_decode(query);
    let text = format!("{decoded_path}?{decoded_query}").to_ascii_lowercase();

    let chars = path.chars().count().max(1) as f32;
    let digits = path.chars().filter(|c| c.is_ascii_digit()).count() as f32;
    let special = path
        .chars()
        .filter(|c| !c.is_ascii_alphanumeric() && *c != '/' && *c != '-')
        .count() as f32;

    let basename = decoded_path.rsplit('/').next().unwrap_or_default();
    let segs: Vec<String> = basename
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect();

    vec![
        clamp(path.len() as f32 / 512.0),
        clamp(query.len() as f32 / 1024.0),
        clamp(path.split('/').filter(|s| !s.is_empty()).count() as f32 / 10.0),
        clamp(digits / chars),
        clamp(special / chars),
        clamp(shannon_entropy(basename) / 4.0),
        clamp(path.matches('%').count() as f32 / 10.0),
        clamp(text.matches("..").count() as f32 / 5.0),
        flag(text.contains("%00") || text.contains('\0')),
        clamp(
            count_any(
                &text,
                &[
                    "union select",
                    "or 1=1",
                    "' or '",
                    "information_schema",
                    "; drop",
                    "benchmark(",
                ],
            ) as f32
                / 5.0,
        ),
        clamp(
            count_any(
                &text,
                &[
                    "<script",
                    "javascript:",
                    "onerror=",
                    "onload=",
                    "<iframe",
                    "document.cookie",
                    "alert(",
                ],
            ) as f32
                / 5.0,
        ),
        clamp(count_any(&text, &["../", "..\\", "..;/", "/etc/passwd", "/proc/self"]) as f32 / 5.0),
        flag(text.contains("${jndi:")),
        clamp(count_any(&text, &["&&", "$(", "`", "|cat", "|ls", ";cat", ";wget"]) as f32 / 5.0),
        flag(segs.len() > 1),
        flag(segs.iter().any(|s| SCRIPT_EXTS.contains(&s.as_str()))),
        flag(segs.iter().any(|s| SENSITIVE_EXTS.contains(&s.as_str()))),
        flag(matches!(http.method, Some(sentry_core::HttpMethod::Get))),
        flag(matches!(http.method, Some(sentry_core::HttpMethod::Post))),
        clamp(http.user_agent.as_deref().map_or(0, |ua| ua.len()) as f32 / 512.0),
        flag(
            http.user_agent
                .as_deref()
                .map_or(true, |ua| ua.trim().is_empty()),
        ),
        flag(http.user_agent.as_deref().is_some_and(|ua| {
            BOT_TOKENS
                .iter()
                .any(|t| ua.to_ascii_lowercase().contains(t))
        })),
        flag(http.status.is_some_and(|s| (400..=499).contains(&s))),
        flag(http.status.is_some_and(|s| (500..=599).contains(&s))),
        clamp(query.split('&').filter(|p| !p.is_empty()).count() as f32 / 20.0),
    ]
}

const SCRIPT_EXTS: &[&str] = &[
    "php", "asp", "aspx", "jsp", "jspx", "cgi", "pl", "py", "sh", "exe", "bat", "cmd", "war",
];
const SENSITIVE_EXTS: &[&str] = &[
    "env", "git", "svn", "ssh", "bak", "backup", "old", "swp", "orig", "save", "sql", "conf",
    "yml", "yaml", "pem", "key", "htaccess", "htpasswd",
];
const BOT_TOKENS: &[&str] = &[
    "bot",
    "crawler",
    "spider",
    "scrapy",
    "curl",
    "wget",
    "python-requests",
    "go-http-client",
    "zgrab",
    "masscan",
    "nikto",
    "sqlmap",
    "scanner",
];

fn clamp(v: f32) -> f32 {
    v.clamp(0.0, 1.0)
}

fn flag(b: bool) -> f32 {
    if b {
        1.0
    } else {
        0.0
    }
}

fn count_any(haystack: &str, needles: &[&str]) -> usize {
    needles.iter().filter(|n| haystack.contains(*n)).count()
}

/// Shannon entropy (bits per character) of a string.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let len = s.len() as f32;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

/// Minimal percent-decoder (`+` → space, `%XX` → byte), shared philosophy
/// with `sentry_core::heuristics::http_text` (which is crate-private).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => 0xff,
                };
                let (h, l) = (hex(bytes[i + 1]), hex(bytes[i + 2]));
                if h != 0xff && l != 0xff {
                    out.push(h << 4 | l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
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
    use sentry_core::event::{HttpData, ProtocolData};
    use sentry_core::{Event, SourceKind};

    fn http_evt(path: &str, query: Option<&str>) -> Event {
        Event::new(
            SourceKind::Synthetic,
            "203.0.113.9".parse().unwrap(),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                query: query.map(str::to_string),
                method: Some(sentry_core::HttpMethod::Get),
                status: Some(200),
                user_agent: Some("Mozilla/5.0".into()),
                ..Default::default()
            }),
        )
    }

    fn feature(evt: &Event, name: &str) -> f32 {
        let idx = FEATURE_NAMES.iter().position(|n| *n == name).unwrap();
        extract(evt)[idx]
    }

    #[test]
    fn vector_length_matches_names() {
        let evt = http_evt("/api/users", None);
        assert_eq!(extract(&evt).len(), FEATURE_NAMES.len());
        assert!(extract(&evt).iter().all(|v| (0.0..=1.0).contains(v)));
    }

    #[test]
    fn non_http_is_all_zeros() {
        let evt = Event::new(
            SourceKind::Synthetic,
            "203.0.113.9".parse().unwrap(),
            ProtocolData::Tcp(Default::default()),
        );
        assert!(extract(&evt).iter().all(|v| *v == 0.0));
    }

    #[test]
    fn benign_path_scores_low_on_threat_tokens() {
        let evt = http_evt("/api/users/42/posts", Some("page=2&sort=asc"));
        assert_eq!(feature(&evt, "sqli_token_score"), 0.0);
        assert_eq!(feature(&evt, "traversal_token_score"), 0.0);
        assert_eq!(feature(&evt, "ua_bot_token"), 0.0);
        assert_eq!(feature(&evt, "path_digit_ratio") > 0.0, true);
    }

    #[test]
    fn encoded_sqli_is_visible_after_decode() {
        let evt = http_evt("/login", Some("user=%27+OR+1%3D1--"));
        assert!(feature(&evt, "sqli_token_score") > 0.0);
        assert!(feature(&evt, "path_encoded_count") >= 0.0);
    }

    #[test]
    fn traversal_and_jndi_detected() {
        let trav = http_evt("/%2e%2e%2fetc/passwd", None);
        assert!(feature(&trav, "traversal_token_score") > 0.0);

        let jndi = http_evt("/search", Some("q=${jndi:ldap://x}"));
        assert_eq!(feature(&jndi, "jndi_token"), 1.0);
    }

    #[test]
    fn script_extension_and_entropy_flags() {
        let evt = http_evt("/lm13.php", None);
        assert_eq!(feature(&evt, "ext_is_script"), 1.0);
        assert!(feature(&evt, "path_entropy") > 0.5);

        let env = http_evt("/.env.production", None);
        assert_eq!(feature(&env, "ext_is_sensitive"), 1.0);
    }

    #[test]
    fn status_and_ua_flags() {
        let mut evt = http_evt("/x", None);
        if let ProtocolData::Http(ref mut http) = evt.protocol {
            http.status = Some(404);
            http.user_agent = None;
        }
        assert_eq!(feature(&evt, "status_4xx"), 1.0);
        assert_eq!(feature(&evt, "ua_is_empty"), 1.0);
        assert_eq!(feature(&evt, "ua_len"), 0.0);
    }
}
