//! Next.js detection via `package.json`, with filesystem routing: the
//! `app/` (or `src/app/`) and `pages/` directory trees define the routes.
//!
//! `[param]` → `{param}`, `(group)` segments are ignored, `[...slug]`
//! catch-alls become a `/*` glob on the parent path.

use std::collections::BTreeSet;

use crate::{FoundRoute, FrameworkDetector, FrameworkProfile, PackSuggestion, ScanContext};

/// Extensions that make a `page`/route file count.
const PAGE_EXTS: &[&str] = &["tsx", "jsx", "ts", "js", "mdx", "md"];

pub struct NextjsDetector;

impl FrameworkDetector for NextjsDetector {
    fn name(&self) -> &'static str {
        "nextjs"
    }

    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile> {
        let manifest = read_package(ctx)?;
        let version = dep_version(&manifest, "next")?;
        let mut routes = Vec::new();

        for file in ctx.matching(is_router_file) {
            if let Some(route) = file_route(&file, ctx) {
                routes.push(route);
            }
        }
        if routes.is_empty() {
            return None;
        }

        Some(FrameworkProfile {
            framework: "nextjs".to_string(),
            version: Some(version),
            routes: crate::normalize_found(routes),
            sensitive_paths: vec!["/.env".to_string(), "/.next/".to_string()],
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

/// A file that participates in Next.js routing.
fn is_router_file(rel: &str) -> bool {
    let rel = rel.strip_prefix("src/").unwrap_or(rel);
    let (dir, rest) = match rel.split_once('/') {
        Some((d, n)) => (d, n),
        None => return false,
    };
    if dir != "app" && dir != "pages" {
        return false;
    }
    let file_name = rest.rsplit('/').next().unwrap_or_default();
    let ext = file_name.rsplit('.').next().unwrap_or_default();
    if dir == "app" {
        (file_name.starts_with("page.") || file_name.starts_with("route."))
            && PAGE_EXTS.contains(&ext)
    } else {
        !file_name.starts_with('_') && !file_name.ends_with(".d.ts") && PAGE_EXTS.contains(&ext)
    }
}

/// Convert one router file into its route.
fn file_route(rel: &str, ctx: &ScanContext) -> Option<FoundRoute> {
    let rel = rel.strip_prefix("src/").unwrap_or(rel);
    let (base_dir, rest) = rel.split_once('/')?;
    let segments: Vec<&str> = rest.split('/').collect();
    // Last segment is `page.<ext>` / `route.<ext>` / the page file itself.
    let dirs: &[&str] = if base_dir == "app" {
        &segments[..segments.len() - 1]
    } else {
        // pages router: the file name is part of the path.
        match segments.split_last() {
            Some((file, dirs)) => {
                let stem = file.split('.').next().unwrap_or_default();
                if stem == "index" {
                    dirs
                } else {
                    // Keep the file stem as a final segment.
                    return page_router_route(dirs, &[stem], rel, ctx);
                }
            }
            None => return None,
        }
    };
    app_router_route(dirs, rel, ctx)
}

/// app router: `dirs` are the segments under `app/` (file already removed).
fn app_router_route(dirs: &[&str], source: &str, ctx: &ScanContext) -> Option<FoundRoute> {
    let mut path = String::new();
    let mut methods: Vec<String> = Vec::new();
    for seg in dirs {
        if seg.starts_with('(') && seg.ends_with(')') {
            continue;
        }
        if seg.starts_with('@') {
            continue;
        }
        if let Some(glob_path) = catch_all(seg) {
            path = format!("{path}/{glob_path}");
            return Some(FoundRoute::new_owned(finalize(&path), methods, source));
        }
        path = format!("{path}/{}", param_to_template(seg));
    }
    if source
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .starts_with("route.")
    {
        methods = route_handler_methods(ctx, source);
    }
    Some(FoundRoute::new_owned(finalize(&path), methods, source))
}

/// pages router: `dirs` are the segments under `pages/`, plus an optional
/// final file stem.
fn page_router_route(
    dirs: &[&str],
    last: &[&str],
    source: &str,
    _ctx: &ScanContext,
) -> Option<FoundRoute> {
    let mut path = String::new();
    for seg in dirs.iter().chain(last.iter()) {
        if let Some(glob_path) = catch_all(seg) {
            path = format!("{path}/{glob_path}");
            return Some(FoundRoute::new(finalize(&path), &[], source));
        }
        path = format!("{path}/{}", param_to_template(seg));
    }
    Some(FoundRoute::new(finalize(&path), &[], source))
}

/// `[...slug]` / `[[...slug]]` → glob tail marker (`*`).
fn catch_all(seg: &str) -> Option<String> {
    let inner = seg.trim_start_matches('[').trim_end_matches(']');
    let inner = inner.trim_start_matches('[').trim_end_matches(']');
    inner.strip_prefix("...").map(|_| "*".to_string())
}

/// `[id]` → `{id}`; plain segments pass through.
fn param_to_template(seg: &str) -> String {
    if seg.starts_with('[') && seg.ends_with(']') {
        format!("{{{}}}", &seg[1..seg.len() - 1])
    } else {
        seg.to_string()
    }
}

fn finalize(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        sentry_core::routes_learn::normalize_route_path(trimmed)
    }
}

/// API route handlers declare methods via exported functions
/// (`export async function GET …` / `export const POST = …`).
fn route_handler_methods(ctx: &ScanContext, rel: &str) -> Vec<String> {
    static HANDLER_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"export\s+(?:default\s+)?(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"#,
        )
        .expect("valid regex")
    });
    let Ok(content) = ctx.read(rel) else {
        return Vec::new();
    };
    let methods: BTreeSet<String> = HANDLER_RE
        .captures_iter(&content)
        .map(|c| c.get(1).unwrap().as_str().to_ascii_uppercase())
        .collect();
    methods.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;

    fn ctx_with(label: &str, files: Vec<(&str, &str)>) -> ScanContext {
        let tmp = std::env::temp_dir().join(format!("sentry-auto-next-{label}"));
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

    const PKG: &str = r#"{"dependencies": {"next": "15.1.0", "react": "^19"}}"#;

    #[test]
    fn app_router_pages_and_handlers() {
        let ctx = ctx_with(
            "app-router",
            vec![
                ("package.json", PKG),
                ("app/page.tsx", "export default function Home() {}"),
                ("app/about/page.tsx", ""),
                ("app/blog/[slug]/page.tsx", ""),
                ("app/(marketing)/pricing/page.tsx", ""),
                ("app/docs/[...slug]/page.tsx", ""),
                (
                    "app/api/users/route.ts",
                    "export async function GET() {}\nexport async function POST(req: Request) {}",
                ),
            ],
        );
        let profile = NextjsDetector.detect(&ctx).unwrap();
        assert_eq!(profile.version.as_deref(), Some("15.1.0"));
        let get = |path: &str| {
            profile
                .routes
                .iter()
                .find(|r| r.path == path)
                .unwrap_or_else(|| panic!("missing {path}"))
        };
        assert_eq!(get("/").path, "/");
        assert!(get("/about").methods.is_empty());
        assert_eq!(get("/blog/{slug}").path, "/blog/{slug}");
        assert_eq!(get("/pricing").path, "/pricing", "group segment ignored");
        assert_eq!(get("/docs/*").path, "/docs/*");
        let users = get("/api/users");
        assert_eq!(users.methods, vec!["GET", "POST"]);
    }

    #[test]
    fn pages_router_and_src_variant() {
        let ctx = ctx_with(
            "pages-router",
            vec![
                ("package.json", PKG),
                ("pages/index.tsx", ""),
                ("pages/about.tsx", ""),
                ("src/pages/blog/[slug].tsx", ""),
                ("src/pages/api/health.ts", ""),
            ],
        );
        let profile = NextjsDetector.detect(&ctx).unwrap();
        let paths: Vec<&str> = profile.routes.iter().map(|r| r.path.as_str()).collect();
        for expected in ["/", "/about", "/blog/{slug}", "/api/health"] {
            assert!(paths.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn ignores_non_nextjs_manifest() {
        let ctx = ctx_with(
            "non-next",
            vec![("package.json", r#"{"dependencies": {"express": "^4"}}"#)],
        );
        assert!(NextjsDetector.detect(&ctx).is_none());
    }

    #[test]
    fn catch_all_and_params_convert() {
        assert_eq!(catch_all("[...slug]"), Some("*".to_string()));
        assert_eq!(catch_all("[[...slug]]"), Some("*".to_string()));
        assert_eq!(catch_all("[slug]"), None);
        assert_eq!(param_to_template("[id]"), "{id}");
        assert_eq!(finalize(""), "/");
        assert_eq!(finalize("/docs/"), "/docs");
    }
}
