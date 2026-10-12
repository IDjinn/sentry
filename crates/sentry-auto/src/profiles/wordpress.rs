//! WordPress detection: anchor files plus the fixed route/rule set of a
//! stock install (wp-login, wp-admin, xmlrpc, REST API, uploads).

use crate::{
    FoundRoute, FrameworkDetector, FrameworkProfile, PackSuggestion, RuleSuggestion, ScanContext,
};
/// WordPress routes that exist in every stock install. Globs cover the
/// subtree routes (`wp-admin` pages, REST namespaces, uploaded assets).
const STOCK_ROUTES: &[(&str, &[&str])] = &[
    ("/wp-login.php", &["GET", "POST"]),
    ("/wp-admin", &[]),
    ("/wp-admin/*", &[]),
    ("/wp-admin/admin-ajax.php", &["GET", "POST"]),
    ("/xmlrpc.php", &["POST"]),
    ("/wp-json/*", &[]),
    ("/wp-content/*", &[]),
    ("/wp-includes/*", &[]),
];

/// Files and prefixes that identify a WordPress install.
const ANCHOR_FILES: &[&str] = &[
    "wp-config.php",
    "wp-settings.php",
    "wp-mail.php",
    "xmlrpc.php",
];
const ANCHOR_PREFIXES: &[&str] = &["wp-content/", "wp-includes/", "wp-admin/"];

/// Information-disclosure paths worth knowing about (informational; the
/// `sensitive_paths` pack already blocks most).
const SENSITIVE: &[&str] = &[
    "/wp-config.php",
    "/wp-content/debug.log",
    "/readme.html",
    "/license.txt",
];

pub struct WordPressDetector;

impl FrameworkDetector for WordPressDetector {
    fn name(&self) -> &'static str {
        "wordpress"
    }

    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile> {
        let anchored = ANCHOR_FILES.iter().any(|f| ctx.has(f))
            || ctx
                .files
                .iter()
                .any(|f| ANCHOR_PREFIXES.iter().any(|p| f.starts_with(p)));
        if !anchored {
            return None;
        }
        let version = ctx
            .read("wp-includes/version.php")
            .ok()
            .and_then(|content| {
                static WP_VERSION: std::sync::LazyLock<regex::Regex> =
                    std::sync::LazyLock::new(|| {
                        regex::Regex::new(r#"\$wp_version\s*=\s*'([^']+)'"#).expect("valid regex")
                    });
                WP_VERSION
                    .captures(&content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
            });

        Some(FrameworkProfile {
            framework: "wordpress".to_string(),
            version,
            routes: STOCK_ROUTES
                .iter()
                .map(|(path, methods)| FoundRoute::new(*path, methods, "wordpress:stock"))
                .collect(),
            sensitive_paths: SENSITIVE.iter().map(|s| s.to_string()).collect(),
            recommended_packs: vec![
                PackSuggestion {
                    name: "sensitive_paths".to_string(),
                    mode: "enforce".to_string(),
                },
                PackSuggestion {
                    name: "crawlers_bad".to_string(),
                    mode: "enforce".to_string(),
                },
                PackSuggestion {
                    name: "rate_scan".to_string(),
                    mode: "enforce".to_string(),
                },
            ],
            recommended_rules: vec![
                RuleSuggestion {
                    name: "wordpress_wp_login_rate_limit".to_string(),
                    priority: 40,
                    match_expr: r#"path == "/wp-login.php""#.to_string(),
                    action: "rate_limit".to_string(),
                    tags: vec!["auto".to_string(), "wordpress".to_string()],
                },
                RuleSuggestion {
                    name: "wordpress_xmlrpc_block".to_string(),
                    priority: 40,
                    match_expr: r#"path == "/xmlrpc.php""#.to_string(),
                    action: "block".to_string(),
                    tags: vec!["auto".to_string(), "wordpress".to_string()],
                },
            ],
            doc_roots: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect;

    fn fixture_ctx() -> ScanContext {
        let root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wordpress");
        let files = detect::bounded_walk(&root, false);
        ScanContext {
            root,
            deep: false,
            nginx_extra_dirs: Vec::new(),
            files,
        }
    }

    #[test]
    fn detects_wordpress_and_emits_stock_routes() {
        let profile = WordPressDetector.detect(&fixture_ctx()).unwrap();
        assert_eq!(profile.framework, "wordpress");
        let paths: Vec<&str> = profile.routes.iter().map(|r| r.path.as_str()).collect();
        for expected in [
            "/wp-login.php",
            "/xmlrpc.php",
            "/wp-json/*",
            "/wp-content/*",
        ] {
            assert!(paths.contains(&expected), "missing {expected}");
        }
        let login = profile
            .routes
            .iter()
            .find(|r| r.path == "/wp-login.php")
            .unwrap();
        assert_eq!(login.methods, vec!["GET", "POST"]);
        assert_eq!(profile.recommended_rules.len(), 2);
    }

    #[test]
    fn ignores_non_wordpress_trees() {
        let ctx = ScanContext {
            root: std::path::PathBuf::from("."),
            deep: false,
            nginx_extra_dirs: Vec::new(),
            files: vec!["src/main.rs".to_string(), "Cargo.toml".to_string()],
        };
        assert!(WordPressDetector.detect(&ctx).is_none());
    }
}
