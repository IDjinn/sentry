//! OpenAPI 2 (Swagger) / OpenAPI 3 route extraction, shared by the disk
//! detector ([`crate::profiles::openapi`]) and the live probe in sentry-cli.
//!
//! A spec's `paths` keys become routes (`{param}` templates are already what
//! the route matcher expects). The server base path (`basePath` in Swagger 2,
//! the path of `servers[0].url` in OpenAPI 3) is prefixed so routes match
//! what clients actually request.

use crate::FoundRoute;

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

/// Cap on routes taken from one spec (a generated spec can be huge).
pub const MAX_SPEC_ROUTES: usize = 2000;

/// Parse an OpenAPI/Swagger document (JSON or YAML). `None` when the text
/// is not a spec (no `openapi`/`swagger` key) or has no paths.
pub fn parse_spec(text: &str, source: &str) -> Option<Vec<FoundRoute>> {
    let doc = parse_document(text)?;
    if doc.get("openapi").is_none() && doc.get("swagger").is_none() {
        return None;
    }
    let paths = doc.get("paths")?.as_object()?;
    let base = base_path(&doc);
    let mut out = Vec::new();
    for (path, item) in paths.iter().take(MAX_SPEC_ROUTES) {
        if !path.starts_with('/') {
            continue;
        }
        let methods: Vec<String> = HTTP_METHODS
            .iter()
            .filter(|m| item.get(**m).is_some())
            .map(|m| m.to_ascii_uppercase())
            .collect();
        out.push(FoundRoute::new_owned(
            join_base(&base, path),
            methods,
            source,
        ));
    }
    (!out.is_empty()).then_some(out)
}

fn parse_document(text: &str) -> Option<serde_json::Value> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed).ok();
    }
    serde_yaml::from_str::<serde_json::Value>(trimmed).ok()
}

/// Server base path: Swagger 2 `basePath`, else the path part of the first
/// OpenAPI 3 server URL (relative or absolute). `/` and templated
/// (`{var}`) values yield an empty prefix.
fn base_path(doc: &serde_json::Value) -> String {
    let raw = doc
        .get("basePath")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            let url = doc
                .get("servers")?
                .as_array()?
                .first()?
                .get("url")?
                .as_str()?;
            Some(crate::probe::url_path(url))
        })
        .unwrap_or_default();
    if raw.contains('{') {
        return String::new();
    }
    raw.trim_end_matches('/').to_string()
}

fn join_base(base: &str, path: &str) -> String {
    if base.is_empty() {
        return path.to_string();
    }
    let base = if base.starts_with('/') {
        base.to_string()
    } else {
        format!("/{base}")
    };
    format!("{base}{path}")
}

/// File names (case-insensitive, basename only) recognized as specs on disk.
pub fn is_spec_filename(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "openapi.json"
            | "openapi.yaml"
            | "openapi.yml"
            | "swagger.json"
            | "swagger.yaml"
            | "swagger.yml"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi3_json_with_server_base_path() {
        let spec = r#"{"openapi":"3.0.0","servers":[{"url":"https://api.x.io/v1"}],
            "paths":{"/users":{"get":{},"post":{}},"/users/{id}":{"delete":{},"parameters":[]}}}"#;
        let routes = parse_spec(spec, "t").unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path, "/v1/users");
        assert_eq!(routes[0].methods, vec!["GET", "POST"]);
        assert_eq!(routes[1].path, "/v1/users/{id}");
        assert_eq!(routes[1].methods, vec!["DELETE"]);
    }

    #[test]
    fn swagger2_yaml_base_path() {
        let spec = "swagger: '2.0'\nbasePath: /api/\npaths:\n  /ping:\n    get: {}\n";
        let routes = parse_spec(spec, "t").unwrap();
        assert_eq!(routes[0].path, "/api/ping");
    }

    #[test]
    fn templated_or_root_server_has_no_prefix() {
        let spec = r#"{"openapi":"3.0.0","servers":[{"url":"https://{host}/{v}"}],"paths":{"/a":{"get":{}}}}"#;
        assert_eq!(parse_spec(spec, "t").unwrap()[0].path, "/a");
        let spec = r#"{"openapi":"3.0.0","servers":[{"url":"/"}],"paths":{"/a":{"get":{}}}}"#;
        assert_eq!(parse_spec(spec, "t").unwrap()[0].path, "/a");
    }

    #[test]
    fn non_spec_documents_are_rejected() {
        assert!(parse_spec("<html>spa fallback</html>", "t").is_none());
        assert!(parse_spec(r#"{"name":"pkg","paths":{"/a":{}}}"#, "t").is_none());
        assert!(parse_spec(r#"{"openapi":"3.0.0","paths":{}}"#, "t").is_none());
    }

    #[test]
    fn spec_filenames() {
        assert!(is_spec_filename("docs/OpenAPI.YAML"));
        assert!(is_spec_filename("swagger.json"));
        assert!(!is_spec_filename("package.json"));
    }
}
