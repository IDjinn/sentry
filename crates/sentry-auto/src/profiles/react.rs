//! React SPA detection via `package.json`, with regex extraction of
//! client-side routes from React Router declarations (`<Route path="/x">`,
//! `createBrowserRouter([{ path: "/x" }])`, framework-mode `route("x", …)`).
//!
//! Next.js projects are left to the `nextjs` profile. `:param` → `{param}`;
//! relative nested paths are emitted as top-level paths (parent prefixes are
//! not resolved), which is a safe over-approximation for an allowlist.

use std::sync::LazyLock;

use regex::Regex;

use crate::{FoundRoute, FrameworkDetector, FrameworkProfile, PackSuggestion, ScanContext};

const SOURCE_EXTS: &[&str] = &["jsx", "tsx", "js", "ts", "mjs"];

const MAX_SCANNED_FILES: usize = 800;

/// A file is only mined when it visibly talks to a router.
const ROUTER_MARKERS: &[&str] = &[
    "react-router",
    "createBrowserRouter",
    "createHashRouter",
    "createRoutesFromElements",
    "<Route",
    "@react-router/dev/routes",
];

static JSX_ROUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<Route\b[^>]*?\bpath\s*=\s*(?:\{\s*)?['"`]([^'"`]*)['"`]"#).expect("valid regex")
});
static OBJECT_ROUTE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bpath\s*:\s*['"`]([^'"`]*)['"`]"#).expect("valid regex"));
static FILE_ROUTE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\broute\s*\(\s*['"`]([^'"`]*)['"`]"#).expect("valid regex"));

pub struct ReactDetector;

impl FrameworkDetector for ReactDetector {
    fn name(&self) -> &'static str {
        "react"
    }

    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile> {
        let manifest = read_package(ctx)?;
        if dep_version(&manifest, "next").is_some() {
            return None;
        }
        let version = dep_version(&manifest, "react")?;

        let mut files: Vec<String> = ctx
            .matching(|f| {
                let ext = f.rsplit('.').next().unwrap_or_default();
                SOURCE_EXTS.contains(&ext) && !f.ends_with(".d.ts")
            })
            .into_iter()
            .take(MAX_SCANNED_FILES)
            .collect();
        files.sort();

        let mut routes = Vec::new();
        for file in files {
            let Ok(content) = ctx.read(&file) else {
                continue;
            };
            if !ROUTER_MARKERS.iter().any(|m| content.contains(m)) {
                continue;
            }
            extract_routes(&content, &file, &mut routes);
        }
        if routes.is_empty() {
            return None;
        }
        routes.extend(super::web::api_calls(ctx));
        routes.extend(super::web::public_assets(ctx));

        Some(FrameworkProfile {
            framework: "react".to_string(),
            version: Some(version),
            routes: crate::normalize_found(routes),
            sensitive_paths: vec!["/.env".to_string(), "/src/".to_string()],
            recommended_packs: vec![
                PackSuggestion {
                    name: "sensitive_paths".to_string(),
                    mode: "enforce".to_string(),
                },
                PackSuggestion {
                    name: "http_anomaly".to_string(),
                    mode: "shadow".to_string(),
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

fn dep_version(manifest: &serde_json::Value, dep: &str) -> Option<String> {
    ["dependencies", "devDependencies"]
        .iter()
        .find_map(|section| {
            manifest
                .get(section)
                .and_then(|d| d.get(dep))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn extract_routes(content: &str, source: &str, out: &mut Vec<FoundRoute>) {
    for re in [&*JSX_ROUTE_RE, &*OBJECT_ROUTE_RE, &*FILE_ROUTE_RE] {
        for caps in re.captures_iter(content) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if let Some(path) = to_template(raw) {
                out.push(FoundRoute::new(path, &[], source));
            }
        }
    }
}

/// React Router path → template. Bare `*`/empty paths (catch-all 404 and
/// index routes) carry no information and are dropped.
fn to_template(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "*" {
        return None;
    }
    let converted: Vec<String> = raw
        .split('/')
        .map(|seg| match seg.strip_prefix(':') {
            Some(name) => format!("{{{}}}", name.trim_end_matches('?')),
            None => seg.to_string(),
        })
        .collect();
    let joined = converted.join("/");
    let rooted = if joined.starts_with('/') {
        joined
    } else {
        format!("/{joined}")
    };
    Some(sentry_core::routes_learn::normalize_route_path(&rooted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;

    fn ctx_with(label: &str, files: Vec<(&str, &str)>) -> ScanContext {
        let tmp = std::env::temp_dir().join(format!("sentry-auto-react-{label}"));
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

    const PKG: &str = r#"{"dependencies": {"react": "^18.3.0", "react-router-dom": "^6"}}"#;

    #[test]
    fn jsx_and_object_routes() {
        let ctx = ctx_with(
            "jsx-object",
            vec![
                ("package.json", PKG),
                (
                    "src/App.tsx",
                    r#"
                    import { Route, Routes } from "react-router-dom";
                    <Routes>
                      <Route path="/" element={<Home />} />
                      <Route path="/users/:id" element={<User />} />
                      <Route path="*" element={<NotFound />} />
                    </Routes>
                    "#,
                ),
                (
                    "src/router.ts",
                    r#"
                    import { createBrowserRouter } from "react-router-dom";
                    export default createBrowserRouter([
                      { path: "/dashboard", element: x },
                      { path: "settings/:tab?", element: y },
                    ]);
                    "#,
                ),
                (
                    "src/vite.config.ts",
                    r#"export default { path: "/not-router" }"#,
                ),
            ],
        );
        let profile = ReactDetector.detect(&ctx).unwrap();
        assert_eq!(profile.framework, "react");
        let paths: Vec<&str> = profile.routes.iter().map(|r| r.path.as_str()).collect();
        for expected in ["/", "/users/{id}", "/dashboard", "/settings/{tab}"] {
            assert!(paths.contains(&expected), "missing {expected}: {paths:?}");
        }
        assert!(!paths.contains(&"/not-router"), "non-router file mined");
        assert!(!paths.contains(&"/*"), "bare catch-all kept");
    }

    #[test]
    fn framework_mode_route_config() {
        let ctx = ctx_with(
            "fw-mode",
            vec![
                ("package.json", PKG),
                (
                    "app/routes.ts",
                    r#"
                    import { index, route } from "@react-router/dev/routes";
                    export default [index("home.tsx"), route("about", "about.tsx"), route("posts/:slug", "post.tsx")];
                    "#,
                ),
            ],
        );
        let profile = ReactDetector.detect(&ctx).unwrap();
        let paths: Vec<&str> = profile.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/about"));
        assert!(paths.contains(&"/posts/{slug}"));
    }

    #[test]
    fn leaves_nextjs_and_non_react_alone() {
        let next = ctx_with(
            "next",
            vec![
                (
                    "package.json",
                    r#"{"dependencies": {"next": "15", "react": "19"}}"#,
                ),
                ("src/a.tsx", r#"<Route path="/x" />"#),
            ],
        );
        assert!(ReactDetector.detect(&next).is_none());
        let other = ctx_with(
            "other",
            vec![("package.json", r#"{"dependencies": {"express": "4"}}"#)],
        );
        assert!(ReactDetector.detect(&other).is_none());
    }
}
