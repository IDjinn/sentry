//! Express detection via `package.json`, with regex extraction of
//! `app.get('/x', …)` / `router.route('/x')` declarations from JS/TS
//! sources (node_modules never enters the walk).
//!
//! `:param` → `{param}`; regex literals (`app.get(/re/)`) don't match and
//! are skipped.

use std::sync::LazyLock;

use regex::Regex;

use crate::{FoundRoute, FrameworkDetector, FrameworkProfile, PackSuggestion, ScanContext};

/// Source files scanned for route declarations.
const SOURCE_EXTS: &[&str] = &["js", "mjs", "cjs", "ts"];

/// Cap on scanned source files (big bundles are unlikely to declare
/// anything useful and slow the scan).
const MAX_SCANNED_FILES: usize = 800;

static VERB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|options|head|all|any|use)\s*\(\s*['"`](/[^'"`]*)['"`]"#,
    )
    .expect("valid regex")
});
static ROUTE_CHAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.\s*route\s*\(\s*['"`](/[^'"`]*)['"`]"#).expect("valid regex"));

pub struct ExpressDetector;

impl FrameworkDetector for ExpressDetector {
    fn name(&self) -> &'static str {
        "express"
    }

    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile> {
        let manifest = read_package(ctx)?;
        let version = manifest
            .get("dependencies")
            .and_then(|d| d.get("express"))
            .or_else(|| {
                manifest
                    .get("devDependencies")
                    .and_then(|d| d.get("express"))
            })
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())?;

        let mut routes = Vec::new();
        let mut scanned = 0usize;
        let mut files: Vec<String> = ctx
            .matching(|f| {
                let ext = f.rsplit('.').next().unwrap_or_default();
                SOURCE_EXTS.contains(&ext) && !f.ends_with(".d.ts")
            })
            .into_iter()
            .take(MAX_SCANNED_FILES)
            .collect();
        files.sort();
        for file in files {
            if scanned >= MAX_SCANNED_FILES {
                break;
            }
            let Ok(content) = ctx.read(&file) else {
                continue;
            };
            scanned += 1;
            extract_routes(&content, &file, &mut routes);
        }
        if routes.is_empty() {
            return None;
        }

        Some(FrameworkProfile {
            framework: "express".to_string(),
            version: Some(version),
            routes: crate::normalize_found(routes),
            sensitive_paths: vec!["/.env".to_string()],
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
            recommended_rules: Vec::new(),
            doc_roots: Vec::new(),
        })
    }
}

fn read_package(ctx: &ScanContext) -> Option<serde_json::Value> {
    if !ctx.has("package.json") {
        return None;
    }
    let content = ctx.read("package.json").ok()?;
    serde_json::from_str(&content).ok()
}

fn extract_routes(content: &str, source: &str, out: &mut Vec<FoundRoute>) {
    for caps in VERB_RE.captures_iter(content) {
        let verb = caps.get(1).map(|m| m.as_str()).unwrap_or("any");
        let raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        push(raw, verb, source, out);
    }
    for caps in ROUTE_CHAIN_RE.captures_iter(content) {
        let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        push(raw, "any", source, out);
    }
}

fn push(raw: &str, verb: &str, source: &str, out: &mut Vec<FoundRoute>) {
    let path = to_template(raw);
    if verb == "use" {
        // Mounted middleware covers everything under the path.
        let glob = if path == "/" {
            "/*".to_string()
        } else {
            format!("{path}/*")
        };
        out.push(FoundRoute::new(glob, &[], source));
        return;
    }
    if verb == "any" || verb == "all" {
        out.push(FoundRoute::new(path, &[], source));
        return;
    }
    let method = verb.to_ascii_uppercase();
    out.push(FoundRoute::new(path, &[&method], source));
}

/// Convert an Express path to the template form: `:id` → `{id}`, `*` → `*`.
fn to_template(path: &str) -> String {
    let converted: Vec<String> = path
        .split('/')
        .map(|seg| {
            if let Some(name) = seg.strip_prefix(':') {
                format!("{{{name}}}")
            } else {
                seg.to_string()
            }
        })
        .collect();
    sentry_core::routes_learn::normalize_route_path(&converted.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;

    fn ctx_with(label: &str, files: Vec<(&str, &str)>) -> ScanContext {
        let tmp = std::env::temp_dir().join(format!("sentry-auto-express-{label}"));
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

    const PKG: &str = r#"{"dependencies": {"express": "^4.21.0"}}"#;

    #[test]
    fn extracts_verbs_and_params() {
        let ctx = ctx_with(
            "verbs",
            vec![
                ("package.json", PKG),
                (
                    "server.js",
                    r#"
                app.get('/users', list);
                app.post('/users', create);
                app.delete('/users/:id', destroy);
                router.route('/items').get(x).post(y);
                app.use('/static', express.static('public'));
                app.all('/ping', p);
                app.get(/regex/, bad);
                "#,
                ),
            ],
        );
        let profile = ExpressDetector.detect(&ctx).unwrap();
        assert_eq!(profile.version.as_deref(), Some("^4.21.0"));
        let get = |path: &str| {
            profile
                .routes
                .iter()
                .find(|r| r.path == path)
                .unwrap_or_else(|| panic!("missing {path}"))
                .methods
                .clone()
        };
        assert_eq!(get("/users"), vec!["GET", "POST"]);
        assert_eq!(get("/users/{id}"), vec!["DELETE"]);
        assert!(get("/items").is_empty(), "route() chain → any method");
        assert!(get("/ping").is_empty());
        assert_eq!(get("/static/*"), Vec::<String>::new());
    }

    #[test]
    fn ignores_non_express_manifest() {
        let ctx = ctx_with(
            "non-express",
            vec![("package.json", r#"{"dependencies": {"next": "15"}}"#)],
        );
        assert!(ExpressDetector.detect(&ctx).is_none());
    }

    #[test]
    fn template_conversion() {
        assert_eq!(
            to_template("/users/:userId/posts/:postId"),
            "/users/{userId}/posts/{postId}"
        );
        assert_eq!(to_template("/"), "/");
        assert_eq!(to_template("no-slash"), "/no-slash");
    }
}
