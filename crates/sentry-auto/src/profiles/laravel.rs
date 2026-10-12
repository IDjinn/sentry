//! Laravel detection via `composer.json`, with regex extraction from the
//! canonical route files (`routes/web.php`, `routes/api.php`).
//!
//! Limitations (documented, best-effort by design): `Route::prefix(..)->`
//! groups are not brace-matched, so routes declared only inside a group
//! appear without the prefix; `Route::resource` expands to the 5 core REST
//! verbs (create/edit form routes are skipped).

use std::sync::LazyLock;

use regex::Regex;

use crate::{
    FoundRoute, FrameworkDetector, FrameworkProfile, PackSuggestion, RuleSuggestion, ScanContext,
};

/// Methods accepted by `Route::resource` (core REST verbs).
const RESOURCE_ROUTES: &[(&str, &[&str])] = &[
    ("", &["GET", "POST"]),
    ("/{id}", &["GET", "PUT", "PATCH", "DELETE"]),
];

pub struct LaravelDetector;

impl FrameworkDetector for LaravelDetector {
    fn name(&self) -> &'static str {
        "laravel"
    }

    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile> {
        let composer = read_composer(ctx)?;
        let version = composer
            .get("require")
            .and_then(|r| r.get("laravel/framework"))
            .or_else(|| {
                composer
                    .get("require-dev")
                    .and_then(|r| r.get("laravel/framework"))
            })
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())?;
        if ctx.files.iter().all(|f| !f.starts_with("routes/")) {
            return None;
        }

        let mut routes = Vec::new();
        let mut files: Vec<String> = ctx
            .files
            .iter()
            .filter(|f| {
                f.starts_with("routes/")
                    && f.ends_with(".php")
                    && (ctx.deep
                        || f.as_str() == "routes/web.php"
                        || f.as_str() == "routes/api.php")
            })
            .cloned()
            .collect();
        files.sort();
        for file in files {
            let Ok(content) = ctx.read(&file) else {
                continue;
            };
            let prefix = if file == "routes/api.php" { "/api" } else { "" };
            extract_routes(&content, prefix, &file, &mut routes);
        }
        if routes.is_empty() {
            return None;
        }

        Some(FrameworkProfile {
            framework: "laravel".to_string(),
            version: Some(version),
            routes: crate::normalize_found(routes),
            sensitive_paths: vec![
                "/.env".to_string(),
                "/storage/logs/".to_string(),
                "/vendor/".to_string(),
            ],
            recommended_packs: vec![
                PackSuggestion {
                    name: "sensitive_paths".to_string(),
                    mode: "enforce".to_string(),
                },
                PackSuggestion {
                    name: "crawlers_bad".to_string(),
                    mode: "enforce".to_string(),
                },
            ],
            recommended_rules: vec![RuleSuggestion {
                name: "laravel_storage_block".to_string(),
                priority: 40,
                match_expr: r#"path starts_with "/storage/""#.to_string(),
                action: "block".to_string(),
                tags: vec!["auto".to_string(), "laravel".to_string()],
            }],
            doc_roots: Vec::new(),
        })
    }
}

fn read_composer(ctx: &ScanContext) -> Option<serde_json::Value> {
    if !ctx.has("composer.json") {
        return None;
    }
    let content = ctx.read("composer.json").ok()?;
    serde_json::from_str(&content).ok()
}

/// Pull routes out of one route file: `Route::get('/x', …)`,
/// `Route::match(['GET','POST'], '/x', …)` and `Route::resource('/x', …)`.
fn extract_routes(content: &str, prefix: &str, source: &str, out: &mut Vec<FoundRoute>) {
    for caps in METHOD_RE.captures_iter(content) {
        let verb = caps.get(1).map(|m| m.as_str()).unwrap_or("any");
        let path = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        push_verb_route(path, verb, prefix, source, out);
    }
    for caps in MATCH_RE.captures_iter(content) {
        let verbs = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let path = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let methods: Vec<String> = QUOTED_RE
            .find_iter(verbs)
            .filter_map(|m| {
                let v = m
                    .as_str()
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_ascii_uppercase();
                if v == "ANY" {
                    None
                } else {
                    Some(v)
                }
            })
            .collect();
        if methods.is_empty() {
            push_verb_route(path, "any", prefix, source, out);
        } else {
            out.push(FoundRoute::new(
                join_prefix(prefix, path),
                &methods.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                source,
            ));
        }
    }
    for caps in RESOURCE_RE.captures_iter(content) {
        let path = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        let base = join_prefix(prefix, path);
        for (suffix, methods) in RESOURCE_ROUTES {
            out.push(FoundRoute::new(format!("{base}{suffix}"), methods, source));
        }
    }
}

fn push_verb_route(path: &str, verb: &str, prefix: &str, source: &str, out: &mut Vec<FoundRoute>) {
    let route_path = join_prefix(prefix, path);
    if verb == "any" {
        out.push(FoundRoute::new(route_path, &[], source));
        return;
    }
    let method = verb.to_ascii_uppercase();
    out.push(FoundRoute::new(route_path, &[&method], source));
}

fn join_prefix(prefix: &str, path: &str) -> String {
    let p = if path.is_empty() { "/" } else { path };
    let joined = sentry_core::routes_learn::normalize_route_path(&format!("{prefix}{p}"));
    if joined.len() > 1 {
        joined.trim_end_matches('/').to_string()
    } else {
        joined
    }
}

static METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bRoute::(get|post|put|patch|delete|options|head|any)\(\s*['"]([^'"]*)['"]"#)
        .expect("valid regex")
});
static MATCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bRoute::match\(\s*\[([^\]]*)\]\s*,\s*['"]([^'"]*)['"]"#)
        .expect("valid regex")
});
static RESOURCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bRoute::resource\(\s*['"]([^'"]*)['"]"#).expect("valid regex")
});
static QUOTED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"'[^']*'|"[^"]*""#).expect("valid regex"));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;

    fn ctx_with(label: &str, files: Vec<(&str, &str)>) -> ScanContext {
        let tmp = std::env::temp_dir().join(format!("sentry-auto-laravel-{label}"));
        let _ = std::fs::remove_dir_all(&tmp);
        for (rel, content) in &files {
            let path = tmp.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        ScanContext {
            root: tmp,
            deep: false,
            nginx_extra_dirs: Vec::new(),
            files: files.iter().map(|(rel, _)| rel.to_string()).collect(),
        }
    }

    const COMPOSER: &str = r#"{"require": {"php": "^8.2", "laravel/framework": "^11.0"}}"#;

    #[test]
    fn extracts_methods_and_api_prefix() {
        let ctx = ctx_with(
            "verbs",
            vec![
                ("composer.json", COMPOSER),
                (
                    "routes/web.php",
                    r#"Route::get('/users', [UserController::class, 'index']);
                   Route::post('/users', 'store');
                   Route::any('/ping', fn () => 'pong');
                   Route::match(['get', 'POST'], '/multi', 'x');
                   Route::resource('posts', PostController::class);"#,
                ),
                (
                    "routes/api.php",
                    r#"Route::get('/me', 'me'); Route::get('/{id}', 'show');"#,
                ),
            ],
        );
        let profile = LaravelDetector.detect(&ctx).unwrap();
        assert_eq!(profile.framework, "laravel");
        assert_eq!(profile.version.as_deref(), Some("^11.0"));

        let get = |path: &str| {
            profile
                .routes
                .iter()
                .find(|r| r.path == path)
                .unwrap_or_else(|| panic!("missing route {path}"))
                .methods
                .clone()
        };
        assert_eq!(get("/users"), vec!["GET", "POST"]);
        assert!(get("/ping").is_empty(), "any → any-method");
        assert_eq!(get("/multi"), vec!["GET", "POST"]);
        assert_eq!(get("/api/me"), vec!["GET"]);
        assert_eq!(get("/api/{id}"), vec!["GET"]);
        assert_eq!(get("/posts"), vec!["GET", "POST"]);
        assert_eq!(get("/posts/{id}"), vec!["DELETE", "GET", "PATCH", "PUT"]);
    }

    #[test]
    fn ignores_without_laravel_manifest() {
        let ctx = ctx_with(
            "no-laravel",
            vec![(
                "composer.json",
                r#"{"require": {"symfony/http-foundation": "^7"}}"#,
            )],
        );
        assert!(LaravelDetector.detect(&ctx).is_none());
    }

    #[test]
    fn ignores_laravel_without_route_files() {
        let ctx = ctx_with("no-routes", vec![("composer.json", COMPOSER)]);
        assert!(LaravelDetector.detect(&ctx).is_none());
    }

    #[test]
    fn normalize_trims_laravel_slashes() {
        assert_eq!(join_prefix("", "/users"), "/users");
        assert_eq!(join_prefix("/api", "/"), "/api");
        assert_eq!(join_prefix("", "/"), "/");
    }
}
