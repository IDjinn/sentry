//! Integration tests for the route import parsers (no DB required).

use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p
}

fn paths(routes: &[sentry_core::pipeline::RouteDef]) -> Vec<String> {
    let mut v: Vec<String> = routes.iter().map(|r| r.path.clone()).collect();
    v.sort();
    v
}

#[test]
fn openapi_json_parses_all_paths() {
    let bytes = std::fs::read(fixture("openapi.json")).unwrap();
    let routes = sentry_cli::routes_import::parse_bytes(
        &bytes,
        sentry_cli::routes_import::ImportFormat::Auto,
    )
    .unwrap();
    let p = paths(&routes);
    assert!(p.contains(&"/users".to_string()));
    assert!(p.contains(&"/users/{id}".to_string()));
    assert!(p.contains(&"/users/{id}/posts/{postId}".to_string()));

    let users = routes.iter().find(|r| r.path == "/users").unwrap();
    assert_eq!(users.methods, vec!["GET", "POST"]);
}

#[test]
fn swagger_yaml_parses_paths() {
    let bytes = std::fs::read(fixture("swagger.yaml")).unwrap();
    let routes = sentry_cli::routes_import::parse_bytes(
        &bytes,
        sentry_cli::routes_import::ImportFormat::Auto,
    )
    .unwrap();
    let p = paths(&routes);
    assert!(p.contains(&"/api/items".to_string()));
    assert!(p.contains(&"/api/items/{itemId}".to_string()));
}

#[test]
fn postman_json_handles_folders_and_colon_params() {
    let bytes = std::fs::read(fixture("postman.json")).unwrap();
    let routes = sentry_cli::routes_import::parse_bytes(
        &bytes,
        sentry_cli::routes_import::ImportFormat::Auto,
    )
    .unwrap();
    let p = paths(&routes);
    assert!(p.contains(&"/api/login".to_string()));
    assert!(p.contains(&"/api/logout".to_string()));
    assert!(p.contains(&"/users/{userId}".to_string()));
    assert!(p.contains(&"/users/{userId}/posts".to_string()));
}

#[test]
fn har_collapses_numeric_and_uuid_segments() {
    let bytes = std::fs::read(fixture("har.json")).unwrap();
    let routes = sentry_cli::routes_import::parse_bytes(
        &bytes,
        sentry_cli::routes_import::ImportFormat::Auto,
    )
    .unwrap();
    let p = paths(&routes);
    assert!(p.contains(&"/login".to_string()));
    assert!(p.contains(&"/static/app.css".to_string()));
    assert!(p.contains(&"/users/{id}".to_string()));
    let count = p.iter().filter(|x| x.as_str() == "/users/{id}").count();
    assert_eq!(count, 1, "numeric and uuid should dedup to one shape");
}
