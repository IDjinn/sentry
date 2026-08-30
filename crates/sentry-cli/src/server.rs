//! HTTP backend (F4.2) + embedded web dashboard (F4.3).
//!
//! `sentry serve` starts an axum server exposing a JSON API over the
//! Postgres repos (events, stats, incidents, blocked IPs) and serving a
//! dependency-free dashboard at `/`. The daemon and this server are separate
//! processes, so the dashboard polls the API and Postgres acts as the
//! transport.
//!
//! There is no authentication yet (F4.4): the server binds to loopback by
//! default — front it with an authenticating reverse proxy before exposing
//! it further.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use sentry_core::config::SentryConfig;
use sentry_storage::Repo;
use serde::Deserialize;
use serde_json::json;
use tracing::info;

const INDEX_HTML: &str = include_str!("../assets/dashboard/index.html");
const APP_JS: &str = include_str!("../assets/dashboard/app.js");
const STYLE_CSS: &str = include_str!("../assets/dashboard/style.css");

/// Run the dashboard server until the process is stopped.
pub async fn run(cfg: &SentryConfig) -> color_eyre::Result<()> {
    if cfg.storage.postgres.url.is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "`sentry serve` requires Postgres — set storage.postgres.url in sentry.toml or via SENTRY_STORAGE__POSTGRES__URL env"
        ));
    }
    let pool = sentry_storage::PgPool::connect(&cfg.storage.postgres)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("postgres connection failed: {e}"))?;
    let repo = Arc::new(Repo::new(pool));
    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .map_err(|e| color_eyre::eyre::eyre!("invalid server bind address: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("server bind on {addr} failed: {e}"))?;
    info!(%addr, "dashboard listening on http://{addr}");
    axum::serve(listener, router(repo))
        .await
        .map_err(|e| color_eyre::eyre::eyre!("server error: {e}"))
}

fn router(repo: Arc<Repo>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        .route("/api/health", get(health))
        .route("/api/events", get(list_events))
        .route("/api/stats", get(stats))
        .route("/api/incidents", get(list_incidents))
        .route("/api/incidents/{id}/resolve", post(resolve_incident))
        .route("/api/ips/blocked", get(list_blocked))
        .route("/api/ips/{ip}/block", post(block_ip))
        .route("/api/ips/{ip}/unblock", post(unblock_ip))
        .route("/api/ips/{ip}/forgive", post(forgive_ip))
        .with_state(repo)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLE_CSS,
    )
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    limit: Option<i64>,
    level: Option<String>,
}

async fn list_events(
    State(repo): State<Arc<Repo>>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let mut rows = repo.events().recent(limit).await.map_err(internal_error)?;
    if let Some(level) = q.level.as_deref() {
        rows.retain(|r| r.risk_level.eq_ignore_ascii_case(level));
    }
    Ok(Json(json!({ "events": rows })))
}

async fn stats(State(repo): State<Arc<Repo>>) -> Result<Json<serde_json::Value>, ApiError> {
    let since = Utc::now() - Duration::hours(24);
    let by_level = repo
        .events()
        .count_by_level_since(since)
        .await
        .map_err(internal_error)?;
    let by_verdict = repo
        .events()
        .count_by_verdict_since(since)
        .await
        .map_err(internal_error)?;
    let top_ips = repo
        .events()
        .top_ips(10, since)
        .await
        .map_err(internal_error)?;
    let top_paths = repo
        .events()
        .top_paths(10, since)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({
        "since_hours": 24,
        "by_level": named_counts(by_level),
        "by_verdict": named_counts(by_verdict),
        "top_ips": named_counts(top_ips),
        "top_paths": named_counts(top_paths),
    })))
}

fn named_counts(v: Vec<(String, i64)>) -> Vec<serde_json::Value> {
    v.into_iter()
        .map(|(name, count)| json!({"name": name, "count": count}))
        .collect()
}

async fn list_incidents(
    State(repo): State<Arc<Repo>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = repo
        .incidents()
        .unresolved(100)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({ "incidents": rows })))
}

async fn resolve_incident(
    State(repo): State<Arc<Repo>>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    repo.incidents().resolve(id).await.map_err(internal_error)?;
    Ok(Json(json!({"resolved": id})))
}

async fn list_blocked(State(repo): State<Arc<Repo>>) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = repo.ip_state().blocked(100).await.map_err(internal_error)?;
    Ok(Json(json!({ "blocked": rows })))
}

async fn block_ip(
    State(repo): State<Arc<Repo>>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, format!("invalid IP `{ip}`")))?;
    repo.ip_state()
        .block(ip, Some("dashboard"), None)
        .await
        .map_err(internal_error)?;
    let _ = repo.pool().notify("sentry_rules_changed").await;
    Ok(Json(json!({"blocked": ip})))
}

async fn unblock_ip(
    State(repo): State<Arc<Repo>>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, format!("invalid IP `{ip}`")))?;
    repo.ip_state().unblock(ip).await.map_err(internal_error)?;
    let _ = repo.pool().notify("sentry_rules_changed").await;
    Ok(Json(json!({"unblocked": ip})))
}

async fn forgive_ip(
    State(repo): State<Arc<Repo>>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, format!("invalid IP `{ip}`")))?;
    repo.ip_state()
        .reset_offender(ip)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({"forgiven": ip})))
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

fn internal_error<E: std::fmt::Display>(e: E) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// A lazy pool pointed at an unreachable address: enough to build the
    /// router and serve non-query routes without a live database.
    fn test_repo() -> Arc<Repo> {
        let pool =
            sentry_storage::PgPool::connect_lazy("postgres://nobody:nobody@127.0.0.1:1/none")
                .expect("lazy pool");
        Arc::new(Repo::new(pool))
    }

    #[tokio::test]
    async fn health_and_static_routes_respond() {
        let app = router(test_repo());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/app.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_ip_yields_bad_request() {
        let app = router(test_repo());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/ips/not-an-ip/block")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn embedded_assets_are_present() {
        assert!(INDEX_HTML.contains("Sentry"));
        assert!(APP_JS.contains("fetch"));
        assert!(STYLE_CSS.contains(":root"));
    }
}
