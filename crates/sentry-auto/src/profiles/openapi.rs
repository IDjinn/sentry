//! OpenAPI/Swagger detection: any `openapi.*` / `swagger.*` spec file in the
//! walk contributes its declared paths (and methods) as routes.

use crate::openapi::{is_spec_filename, parse_spec};
use crate::{FoundRoute, FrameworkDetector, FrameworkProfile, PackSuggestion, ScanContext};

/// Spec files are often larger than source files; allow a bigger read.
const MAX_SPEC_BYTES: u64 = 4 * 1024 * 1024;

pub struct OpenApiDetector;

impl FrameworkDetector for OpenApiDetector {
    fn name(&self) -> &'static str {
        "openapi"
    }

    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile> {
        let mut routes: Vec<FoundRoute> = Vec::new();
        for file in ctx.matching(is_spec_filename) {
            let Ok(text) = crate::read_capped(&ctx.root.join(&file), MAX_SPEC_BYTES) else {
                continue;
            };
            if let Some(found) = parse_spec(&text, &file) {
                routes.extend(found);
            }
        }
        if routes.is_empty() {
            return None;
        }
        Some(FrameworkProfile {
            framework: "openapi".to_string(),
            version: None,
            routes: crate::normalize_found(routes),
            sensitive_paths: Vec::new(),
            recommended_packs: vec![PackSuggestion {
                name: "http_anomaly".to_string(),
                mode: "shadow".to_string(),
            }],
            recommended_rules: Vec::new(),
            doc_roots: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_spec_file_in_tree() {
        let dir = std::env::temp_dir().join(format!("sentry-auto-oas-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::write(
            dir.join("docs/openapi.yaml"),
            "openapi: 3.0.0\npaths:\n  /orders/{id}:\n    get: {}\n    put: {}\n",
        )
        .unwrap();
        let files = crate::detect::bounded_walk(&dir, false);
        let ctx = crate::detect::ctx_from(dir.clone(), files, false);
        let profile = OpenApiDetector.detect(&ctx).unwrap();
        assert_eq!(profile.routes.len(), 1);
        assert_eq!(profile.routes[0].path, "/orders/{id}");
        assert_eq!(profile.routes[0].methods, vec!["GET", "PUT"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn absent_without_spec() {
        let ctx = crate::detect::ctx_from(
            std::env::temp_dir(),
            vec!["package.json".to_string()],
            false,
        );
        assert!(OpenApiDetector.detect(&ctx).is_none());
    }
}
