//! Route sources shared by the JS frontend profiles (`nextjs`, `react`):
//! backend calls found in client code, `next.config` rewrites/redirects and
//! static assets served from `public/`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::{FoundRoute, ScanContext};

const SOURCE_EXTS: &[&str] = &["jsx", "tsx", "js", "ts", "mjs"];
const MAX_SCANNED_FILES: usize = 800;
const CONFIG_FILES: &[&str] = &["next.config.ts", "next.config.js", "next.config.mjs"];

/// `client.post<T>("/api/x", …)` — method known.
static METHOD_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\.\s*(get|post|put|patch|delete)\s*(?:<[^()]*?>)?\(\s*(['"`])(/api/[^'"`\s]*)"#)
        .expect("valid regex")
});
/// Any other `"/api/..."` literal (fetch, template strings, constants).
static API_LITERAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"`](/api/[^'"`\s]*)"#).expect("valid regex"));
static TEMPLATE_EXPR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{[^}]*\}").expect("valid regex"));
static CONFIG_SOURCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bsource\s*:\s*['"`]([^'"`]+)['"`]"#).expect("valid regex"));
static PATH_PARAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^:(\w+)([*+?]?)(?:\(.*\))?$").expect("valid regex"));

/// Backend routes called from client source files.
pub fn api_calls(ctx: &ScanContext) -> Vec<FoundRoute> {
    let mut files: Vec<String> = ctx
        .matching(|f| {
            let ext = f.rsplit('.').next().unwrap_or_default();
            SOURCE_EXTS.contains(&ext) && !f.ends_with(".d.ts") && !is_test_file(f)
        })
        .into_iter()
        .take(MAX_SCANNED_FILES)
        .collect();
    files.sort();

    // path -> (methods, first source)
    let mut found: BTreeMap<String, (Vec<String>, String)> = BTreeMap::new();
    for file in files {
        let Ok(content) = ctx.read(&file) else {
            continue;
        };
        for caps in METHOD_CALL_RE.captures_iter(&content) {
            let method = caps[1].to_ascii_uppercase();
            if let Some(path) = clean_call_path(&caps[3]) {
                let entry = found
                    .entry(path)
                    .or_insert_with(|| (Vec::new(), file.clone()));
                if !entry.0.contains(&method) {
                    entry.0.push(method);
                }
            }
        }
        for caps in API_LITERAL_RE.captures_iter(&content) {
            if let Some(path) = clean_call_path(&caps[1]) {
                found
                    .entry(path)
                    .or_insert_with(|| (Vec::new(), file.clone()));
            }
        }
    }
    found
        .into_iter()
        .map(|(path, (methods, source))| FoundRoute::new_owned(path, methods, &source))
        .collect()
}

fn is_test_file(rel: &str) -> bool {
    rel.contains(".test.")
        || rel.contains(".spec.")
        || rel.starts_with("tests/")
        || rel.contains("/__tests__/")
}

/// `/api/people/${id}?x=1` → `/api/people/{id}`.
fn clean_call_path(raw: &str) -> Option<String> {
    if raw.contains(':') || raw.contains('*') {
        return None;
    }
    let no_query = raw.split(['?', '#']).next().unwrap_or_default();
    let mut counter = 0usize;
    let templated = TEMPLATE_EXPR_RE.replace_all(no_query, |_: &regex::Captures| {
        counter += 1;
        if counter == 1 {
            "{id}".to_string()
        } else {
            format!("{{p{counter}}}")
        }
    });
    let trimmed = templated.trim_end_matches('/');
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return None;
    }
    Some(sentry_core::routes_learn::normalize_route_path(trimmed))
}

/// `rewrites()` / `redirects()` sources in `next.config.*`.
pub fn next_config_routes(ctx: &ScanContext) -> Vec<FoundRoute> {
    let mut out = Vec::new();
    for name in CONFIG_FILES {
        if !ctx.has(name) {
            continue;
        }
        let Ok(content) = ctx.read(name) else {
            continue;
        };
        for caps in CONFIG_SOURCE_RE.captures_iter(&content) {
            if let Some(path) = config_source_to_template(&caps[1]) {
                out.push(FoundRoute::new(path, &[], *name));
            }
        }
    }
    out
}

/// `/api/:path*` → `/api/*`, `/u/:id` → `/u/{id}`; `/:path*` and other
/// all-matching sources are skipped (they would allow everything).
fn config_source_to_template(source: &str) -> Option<String> {
    let mut segments = Vec::new();
    for seg in source.split('/').filter(|s| !s.is_empty()) {
        if let Some(caps) = PATH_PARAM_RE.captures(seg) {
            match &caps[2] {
                "*" | "+" => {
                    segments.push("*".to_string());
                    break;
                }
                _ => segments.push(format!("{{{}}}", &caps[1])),
            }
        } else {
            segments.push(seg.to_string());
        }
    }
    if segments.is_empty() || segments[0] == "*" {
        return None;
    }
    Some(sentry_core::routes_learn::normalize_route_path(&format!(
        "/{}",
        segments.join("/")
    )))
}

/// Files under `public/` are served at the site root.
pub fn public_assets(ctx: &ScanContext) -> Vec<FoundRoute> {
    ctx.matching(|f| f.starts_with("public/"))
        .into_iter()
        .filter_map(|f| {
            let rel = f.strip_prefix("public/")?;
            Some(FoundRoute::new(
                sentry_core::routes_learn::normalize_route_path(&format!("/{rel}")),
                &["GET"],
                &f,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_paths_are_templated() {
        assert_eq!(
            clean_call_path("/api/people/${personId}/photos").as_deref(),
            Some("/api/people/{id}/photos")
        );
        assert_eq!(
            clean_call_path("/api/photos?${qs}").as_deref(),
            Some("/api/photos")
        );
        assert_eq!(
            clean_call_path("/api/people/suggestions/${encodeURIComponent(x)}").as_deref(),
            Some("/api/people/suggestions/{id}")
        );
    }

    #[test]
    fn config_sources_convert() {
        assert_eq!(
            config_source_to_template("/api/:path*").as_deref(),
            Some("/api/*")
        );
        assert_eq!(
            config_source_to_template("/u/:id").as_deref(),
            Some("/u/{id}")
        );
        assert_eq!(config_source_to_template("/:path*"), None);
    }
}
