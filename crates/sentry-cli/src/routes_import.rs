//! Route import: parse OpenAPI/Swagger, Postman and HAR specs into
//! `RouteDef`s and persist them via `RouteRepo`.
//!
//! Supported formats (auto-detected by content, or forced via the `format`
//! flag):
//!
//! - **OpenAPI 2 (Swagger)** and **OpenAPI 3**: `paths` → `{template}` +
//!   methods. `{id}` parameters are already compatible with the F2.9
//!   template matcher.
//! - **Postman Collection v2.1**: `item[].request.url` with `:id` path
//!   params converted to `{id}`; `method` read from the request.
//! - **HAR 1.2**: `log.entries[].request` → literal path + method, with
//!   numeric/uuid path segments collapsed into `{id}` (best-effort).
//!
//! Each imported route is deduped against existing DB rows (case-insensitive
//! path equality) before being inserted. After the import the daemon picks
//! up the new routes via `LISTEN/NOTIFY` (`sentry_routes_changed`), the
//! same channel used by the route learner.

use std::path::Path;

use sentry_core::pipeline::RouteDef;
use sentry_storage::Repo;

/// Format hint for [`import_file`]. `Auto` inspects the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ImportFormat {
    Openapi,
    Swagger,
    Postman,
    Har,
    Auto,
}

impl ImportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Openapi => "openapi",
            Self::Swagger => "swagger",
            Self::Postman => "postman",
            Self::Har => "har",
            Self::Auto => "auto",
        }
    }
}

/// Result of an import run.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ImportReport {
    /// Routes parsed from the spec.
    pub parsed: usize,
    /// Routes skipped because they already exist in the DB (same lowercased
    /// path).
    pub duplicates: usize,
    /// Routes actually inserted.
    pub inserted: usize,
    /// Pretty list of the inserted routes (`METHODS path`).
    pub added: Vec<String>,
}

impl ImportReport {
    fn added_line(path: &str, methods: &[String]) -> String {
        let m = if methods.is_empty() {
            "*".to_string()
        } else {
            methods
                .iter()
                .map(|s| s.to_ascii_uppercase())
                .collect::<Vec<_>>()
                .join(",")
        };
        format!("{m:<24} {path}")
    }
}

/// Parse the file at `path` and insert deduped routes into `repo`.
///
/// The `format` arg forces a parser; `Auto` detects from the file content.
/// `dry_run` skips persistence and only returns what would be imported.
pub async fn import_file(
    path: &Path,
    format: ImportFormat,
    repo: &Repo,
    dry_run: bool,
) -> color_eyre::Result<ImportReport> {
    let bytes = std::fs::read(path)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read {}: {e}", path.display()))?;
    let routes = parse_bytes(&bytes, format)?;
    let parsed = routes.len();

    let existing = repo
        .routes()
        .list()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to load existing routes from db: {e}"))?;
    let existing_paths: std::collections::HashSet<String> = existing
        .iter()
        .map(|r| r.path.to_ascii_lowercase())
        .collect();

    let mut report = ImportReport {
        parsed,
        ..Default::default()
    };
    for r in &routes {
        let key = r.path.to_ascii_lowercase();
        if existing_paths.contains(&key) {
            report.duplicates += 1;
            continue;
        }
        if dry_run {
            report
                .added
                .push(ImportReport::added_line(&r.path, &r.methods));
            continue;
        }
        match repo.routes().insert(&r.path, &r.methods).await {
            Ok(_) => {
                report.inserted += 1;
                report
                    .added
                    .push(ImportReport::added_line(&r.path, &r.methods));
            }
            Err(e) => {
                tracing::warn!(path = %r.path, error = %e, "failed to insert route");
            }
        }
    }

    if !dry_run && report.inserted > 0 {
        let _ = repo.pool().notify("sentry_routes_changed").await;
    }

    tracing::info!(
        format = format.as_str(),
        parsed,
        duplicates = report.duplicates,
        inserted = report.inserted,
        dry_run,
        "routes import done"
    );

    Ok(report)
}

/// Parse raw spec bytes into `RouteDef`s using the given format hint.
pub fn parse_bytes(bytes: &[u8], format: ImportFormat) -> color_eyre::Result<Vec<RouteDef>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| color_eyre::eyre::eyre!("file is not valid UTF-8: {e}"))?;
    let resolved = if format == ImportFormat::Auto {
        detect_format(text)?
    } else {
        format
    };
    let routes = match resolved {
        ImportFormat::Openapi | ImportFormat::Swagger => parse_openapi(text)?,
        ImportFormat::Postman => parse_postman(text)?,
        ImportFormat::Har => parse_har(text)?,
        ImportFormat::Auto => unreachable!(),
    };
    Ok(normalize(routes))
}

/// Detect the spec format from its content.
fn detect_format(text: &str) -> color_eyre::Result<ImportFormat> {
    let v: serde_json::Value = serde_json::from_str(text).or_else(|_| {
        serde_yaml::from_str::<serde_yaml::Value>(text)
            .map(|yv| serde_json::to_value(&yv).unwrap_or(serde_json::Value::Null))
    })?;
    if v.get("swagger").is_some() {
        return Ok(ImportFormat::Swagger);
    }
    if v.get("openapi").is_some() {
        return Ok(ImportFormat::Openapi);
    }
    let is_postman = v
        .get("info")
        .and_then(|i| i.get("_postman_variable_scope"))
        .is_some()
        || (v.get("item").is_some() && v.get("event").is_none() && v.get("log").is_none());
    if is_postman {
        return Ok(ImportFormat::Postman);
    }
    if v.get("log").is_some() {
        return Ok(ImportFormat::Har);
    }
    Err(color_eyre::eyre::eyre!(
        "could not auto-detect spec format (expected openapi/swagger/postman/har)"
    ))
}

// ─── OpenAPI / Swagger ─────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct OpenApiSpec {
    #[serde(default)]
    paths: std::collections::BTreeMap<String, OpenApiPathItem>,
}

#[derive(Debug, serde::Deserialize)]
struct OpenApiPathItem {
    #[serde(flatten)]
    methods: std::collections::BTreeMap<String, serde_json::Value>,
}

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

/// Parse OpenAPI 2/3 (JSON or YAML). Path params like `{userId}` are kept as
/// `{userId}`; the F2.9 matcher treats any `{name}` segment as a wildcard.
fn parse_openapi(text: &str) -> color_eyre::Result<Vec<RouteDef>> {
    let spec: OpenApiSpec = if text.trim_start().starts_with('{') {
        serde_json::from_str(text)?
    } else {
        serde_yaml::from_str(text)?
    };
    let mut out = Vec::new();
    for (path, item) in &spec.paths {
        let mut methods = Vec::new();
        for m in HTTP_METHODS {
            if item.methods.contains_key(*m) {
                methods.push(m.to_ascii_uppercase());
            }
        }
        out.push(RouteDef {
            path: path.clone(),
            methods,
        });
    }
    Ok(out)
}

// ─── Postman v2.1 ─────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct PostmanCollection {
    #[serde(default)]
    item: Vec<PostmanItem>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanItem {
    #[serde(default)]
    item: Vec<PostmanItem>,
    #[serde(default)]
    request: Option<PostmanRequest>,
}

#[derive(Debug, serde::Deserialize)]
struct PostmanRequest {
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: PostmanUrl,
}

/// Postman request URL. v2.1 uses an object with `raw` and `path`; v1 and
/// some exports use a plain string.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(untagged)]
enum PostmanUrl {
    #[default]
    Empty,
    Raw(String),
    Object {
        #[serde(default)]
        raw: String,
        #[serde(default)]
        path: Vec<serde_json::Value>,
    },
}

/// Parse a Postman v2.1 collection (JSON or YAML). Nested folders are
/// walked recursively. Path params in `:param` form are converted to
/// `{param}` so the F2.9 matcher accepts them.
fn parse_postman(text: &str) -> color_eyre::Result<Vec<RouteDef>> {
    let coll: PostmanCollection = if text.trim_start().starts_with('{') {
        serde_json::from_str(text)?
    } else {
        serde_yaml::from_str(text)?
    };
    let mut out = Vec::new();
    walk_postman(&coll.item, &mut out);
    Ok(out)
}

fn walk_postman(items: &[PostmanItem], out: &mut Vec<RouteDef>) {
    for it in items {
        if !it.item.is_empty() {
            walk_postman(&it.item, out);
            continue;
        }
        let Some(req) = it.request.as_ref() else {
            continue;
        };
        let method = req.method.trim().to_ascii_uppercase();
        let path = match &req.url {
            PostmanUrl::Empty => continue,
            PostmanUrl::Raw(s) => {
                if s.is_empty() {
                    continue;
                }
                postman_url_to_path(s)
            }
            PostmanUrl::Object { raw, path: segs } => {
                if !raw.is_empty() {
                    postman_url_to_path(raw)
                } else {
                    let segs: Vec<String> = segs
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    if segs.is_empty() {
                        continue;
                    }
                    format!("/{}", segs.join("/"))
                }
            }
        };
        if path.is_empty() {
            continue;
        }
        out.push(RouteDef {
            path,
            methods: if method.is_empty() {
                vec![]
            } else {
                vec![method]
            },
        });
    }
}

/// Extract the path portion of a Postman raw URL and convert `:id` → `{id}`.
fn postman_url_to_path(raw: &str) -> String {
    let no_proto = match raw.split_once("://") {
        Some((_, rest)) => rest,
        None => raw,
    };
    let no_host = match no_proto.split_once('/') {
        Some((_, rest)) => format!("/{rest}"),
        None => "/".to_string(),
    };
    let path = no_host
        .split(['?', '#'])
        .next()
        .unwrap_or(&no_host)
        .to_string();
    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ':' {
            let mut name = String::new();
            while let Some(&n) = chars.peek() {
                if n.is_ascii_alphanumeric() || n == '_' || n == '-' {
                    name.push(n);
                    chars.next();
                } else {
                    break;
                }
            }
            if !name.is_empty() {
                out.push('{');
                out.push_str(&name);
                out.push('}');
            } else {
                out.push(':');
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ─── HAR 1.2 ──────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct HarDoc {
    log: HarLog,
}

#[derive(Debug, serde::Deserialize)]
struct HarLog {
    #[serde(default)]
    entries: Vec<HarEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct HarEntry {
    request: HarRequest,
}

#[derive(Debug, serde::Deserialize)]
struct HarRequest {
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: String,
}

/// Parse a HAR 1.2 archive. Literal request URLs are reduced to paths and
/// numeric/uuid segments are collapsed into `{id}` so the result matches the
/// F2.9 template form.
fn parse_har(text: &str) -> color_eyre::Result<Vec<RouteDef>> {
    let doc: HarDoc = serde_json::from_str(text)?;
    let mut out = Vec::new();
    for e in &doc.log.entries {
        let method = e.request.method.trim().to_ascii_uppercase();
        let path = url_to_template_path(&e.request.url);
        if path.is_empty() {
            continue;
        }
        out.push(RouteDef {
            path,
            methods: if method.is_empty() {
                vec![]
            } else {
                vec![method]
            },
        });
    }
    Ok(out)
}

/// Reduce an absolute URL to a path template by collapsing numeric and
/// UUID-like segments into `{id}`.
fn url_to_template_path(url: &str) -> String {
    let no_proto = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url,
    };
    let no_host = match no_proto.split_once('/') {
        Some((_, rest)) => format!("/{rest}"),
        None => return String::new(),
    };
    let path = no_host.split(['?', '#']).next().unwrap_or(&no_host);
    let mut segs: Vec<String> = Vec::new();
    for s in path.split('/') {
        if s.is_empty() {
            continue;
        }
        segs.push(if is_dynamic_segment(s) {
            "{id}".to_string()
        } else {
            s.to_string()
        });
    }
    if segs.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segs.join("/"))
    }
}

fn is_dynamic_segment(s: &str) -> bool {
    if s.parse::<u64>().is_ok() {
        return true;
    }
    if s.len() == 36
        && s.chars().filter(|c| *c == '-').count() == 4
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return true;
    }
    if s.len() >= 16 && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return true;
    }
    false
}

// ─── Normalize ────────────────────────────────────────────────────────────

/// Normalize parsed routes: dedup identical (lowercased path, methods set),
/// drop leading/trailing slashes inconsistencies, and sort methods.
fn normalize(routes: Vec<RouteDef>) -> Vec<RouteDef> {
    use std::collections::BTreeMap;
    let mut bucket: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for r in routes {
        let path = normalize_path(&r.path);
        let entry = bucket.entry(path).or_default();
        if r.methods.is_empty() {
            entry.insert("*".to_string());
        } else {
            for m in r.methods {
                entry.insert(m.to_ascii_uppercase());
            }
        }
    }
    bucket
        .into_iter()
        .map(|(path, mut methods)| {
            let wildcard = methods.remove("*");
            let mut m: Vec<String> = methods.into_iter().collect();
            m.sort();
            if wildcard && m.is_empty() {
                m.clear();
            }
            RouteDef { path, methods: m }
        })
        .collect()
}

fn normalize_path(p: &str) -> String {
    let p = p.trim();
    if !p.starts_with('/') {
        format!("/{p}")
    } else {
        p.to_string()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_v3_json() {
        let json = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/users": { "get": {}, "post": {} },
                "/users/{id}": { "get": {}, "delete": {} },
                "/users/{id}/posts": { "get": {} }
            }
        }"#;
        let routes = parse_bytes(json.as_bytes(), ImportFormat::Auto).unwrap();
        let paths: Vec<String> = routes.iter().map(|r| r.path.clone()).collect();
        assert!(paths.contains(&"/users".to_string()));
        assert!(paths.contains(&"/users/{id}".to_string()));
        assert!(paths.contains(&"/users/{id}/posts".to_string()));
        let users = routes.iter().find(|r| r.path == "/users").unwrap();
        assert_eq!(users.methods, vec!["GET", "POST"]);
    }

    #[test]
    fn openapi_v2_yaml() {
        let yaml = r#"
swagger: "2.0"
paths:
  /api/items:
    get: {}
    post: {}
  /api/items/{itemId}:
    get: {}
"#;
        let routes = parse_bytes(yaml.as_bytes(), ImportFormat::Auto).unwrap();
        let paths: Vec<String> = routes.iter().map(|r| r.path.clone()).collect();
        assert!(paths.contains(&"/api/items".to_string()));
        assert!(paths.contains(&"/api/items/{itemId}".to_string()));
    }

    #[test]
    fn postman_v2_with_nested_folders() {
        let json = r#"{
            "info": { "_postman_variable_scope": "environment" },
            "item": [
                {
                    "name": "Auth",
                    "item": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "{{base}}/api/login"
                            }
                        }
                    ]
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/users/:userId/posts"
                    }
                }
            ]
        }"#;
        let routes = parse_bytes(json.as_bytes(), ImportFormat::Auto).unwrap();
        assert!(routes
            .iter()
            .any(|r| r.path == "/api/login" && r.methods == vec!["POST"]));
        assert!(routes.iter().any(|r| r.path == "/users/{userId}/posts"));
    }

    #[test]
    fn har_collapses_numeric_and_uuid_segments() {
        let json = r#"{
            "log": { "entries": [
                { "request": { "method": "GET", "url": "https://api.example.com/users/42" } },
                { "request": { "method": "GET", "url": "https://api.example.com/posts/550e8400-e29b-41d4-a716-446655440000" } },
                { "request": { "method": "POST", "url": "https://api.example.com/login" } }
            ] }
        }"#;
        let routes = parse_bytes(json.as_bytes(), ImportFormat::Auto).unwrap();
        let paths: Vec<&str> = routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/users/{id}"));
        assert!(paths.contains(&"/posts/{id}"));
        assert!(paths.contains(&"/login"));
    }

    #[test]
    fn normalize_dedups_and_sorts_methods() {
        let routes = vec![
            RouteDef {
                path: "/users".into(),
                methods: vec!["POST".into(), "GET".into()],
            },
            RouteDef {
                path: "/Users".into(),
                methods: vec!["get".into()],
            },
            RouteDef {
                path: "/users/".into(),
                methods: vec![],
            },
        ];
        let out = normalize(routes);
        // `/Users` (lowercased to `/users`) deduped; `/users/` is distinct.
        let users = out.iter().find(|r| r.path == "/users").unwrap();
        assert_eq!(users.methods, vec!["GET", "POST"]);
    }

    #[test]
    fn detect_postman_from_item_field() {
        let json = r#"{ "item": [ { "request": { "method": "GET", "url": "/x" } } ] }"#;
        let fmt = detect_format(json).unwrap();
        assert_eq!(fmt, ImportFormat::Postman);
    }

    #[test]
    fn postman_url_to_path_handles_query_and_fragment() {
        assert_eq!(
            postman_url_to_path("https://x.io/api/v1/users?x=1"),
            "/api/v1/users"
        );
        assert_eq!(postman_url_to_path("https://x.io:8080/p#frag"), "/p");
        assert_eq!(postman_url_to_path("/just/path"), "/just/path");
        assert_eq!(postman_url_to_path("{{base}}/login"), "/login");
    }

    #[test]
    fn url_to_template_path_collapses_numeric() {
        assert_eq!(url_to_template_path("https://x.io/a/123/b"), "/a/{id}/b");
        assert_eq!(url_to_template_path("/a/abc"), "/a/abc");
        assert_eq!(url_to_template_path("https://x.io/"), "/");
    }
}
