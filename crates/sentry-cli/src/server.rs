//! HTTP backend (F4.2) + embedded web dashboard (F4.3) + auth/RBAC (F4.4).
//!
//! `sentry serve` starts an axum server exposing a JSON API over the
//! Postgres repos (events, stats, incidents, blocked IPs) and serving a
//! dependency-free dashboard at `/`. The daemon and this server are separate
//! processes, so the dashboard polls the API and Postgres acts as the
//! transport.
//!
//! Auth (F4.4): `[server.auth]` selects `none` (loopback only), `password`
//! (Argon2 login + HMAC-signed session cookie), `token` (bearer tokens) or
//! `both`. Roles: `admin` may mutate, `viewer` is read-only.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequest, Path, Query, State};
use axum::http::header::{self, AUTHORIZATION};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use sentry_core::config::SentryConfig;
use sentry_storage::Repo;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::auth::{AuthLayer, Identity, Role};

const INDEX_HTML: &str = include_str!("../assets/dashboard/index.html");
const APP_JS: &str = include_str!("../assets/dashboard/app.js");
const STYLE_CSS: &str = include_str!("../assets/dashboard/style.css");

const SESSION_COOKIE: &str = "sentry_session";
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_FAILURES: u32 = 10;

/// Shared router state.
#[derive(Clone)]
struct AppState {
    repo: Arc<Repo>,
    auth: Arc<AuthLayer>,
    login_limiter: Arc<LoginLimiter>,
    /// Shared webhook secret (F4.5): external alert systems presenting
    /// `X-Sentry-Webhook-Secret` may ack/resolve incidents.
    webhook_secret: Option<String>,
}

/// Run the dashboard server until the process is stopped.
pub async fn run(cfg: &SentryConfig) -> color_eyre::Result<()> {
    if cfg.storage.postgres.url.is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "`sentry serve` requires Postgres — set storage.postgres.url in sentry.toml or via SENTRY_STORAGE__POSTGRES__URL env"
        ));
    }
    let auth = AuthLayer::from_config(cfg)
        .map_err(|e| color_eyre::eyre::eyre!("server auth config: {e}"))?;
    if auth.disabled() && !is_loopback(&cfg.server.host) {
        warn!(
            host = %cfg.server.host,
            "server binds off-loopback with [server.auth] mode=none — anyone who can reach this address can mutate state; set mode = \"both\" and configure users/tokens"
        );
    }
    let pool = sentry_storage::PgPool::connect(&cfg.storage.postgres)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("postgres connection failed: {e}"))?;
    let state = AppState {
        repo: Arc::new(Repo::new(pool)),
        auth: Arc::new(auth),
        login_limiter: Arc::new(LoginLimiter::new(LOGIN_MAX_FAILURES, LOGIN_WINDOW)),
        webhook_secret: std::env::var(&cfg.server.webhook_secret_env)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    };
    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .map_err(|e| color_eyre::eyre::eyre!("invalid server bind address: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("server bind on {addr} failed: {e}"))?;
    info!(%addr, "dashboard listening on http://{addr}");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| color_eyre::eyre::eyre!("server error: {e}"))
}

fn is_loopback(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(true)
}

/// Routes added before `route_layer` are public; everything after requires
/// authentication, and non-GET `/api` calls additionally require `admin`.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        .route("/api/health", get(health))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/events", get(list_events))
        .route("/api/stats", get(stats))
        .route("/api/incidents", get(list_incidents))
        .route("/api/incidents/{id}/resolve", post(resolve_incident))
        .route("/api/incidents/{id}/ack", post(ack_incident))
        .route("/api/ips/blocked", get(list_blocked))
        .route("/api/ips/{ip}/block", post(block_ip))
        .route("/api/ips/{ip}/unblock", post(unblock_ip))
        .route("/api/ips/{ip}/forgive", post(forgive_ip))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

async fn auth_middleware(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let public = matches!(
        path,
        "/" | "/app.js" | "/style.css" | "/api/health" | "/api/login" | "/api/logout" | "/api/me"
    );
    if state.auth.disabled() || public {
        return next.run(req).await;
    }

    let bearer = bearer_token(req.headers());
    let cookie = cookie_value(req.headers(), state.auth.cookie_name());
    let identity = state.auth.identify(bearer, cookie).or_else(|| {
        // External alert systems (F4.5 round-trip): a matching webhook
        // secret grants incident write access only.
        webhook_secret_identity(&state, req.headers(), path)
    });
    let is_mutation = !matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    );

    let Some(identity) = identity else {
        return unauthorized();
    };

    if is_mutation && !identity.role.allows_mutation() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let mut req = req;
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "authentication required"})),
    )
        .into_response()
}

/// Identity granted to callers presenting the shared webhook secret, scoped
/// to incident ack/resolve (the alert round-trip path). `None` elsewhere.
fn webhook_secret_identity(state: &AppState, headers: &HeaderMap, path: &str) -> Option<Identity> {
    let secret = state.webhook_secret.as_deref()?;
    let presented = headers.get("x-sentry-webhook-secret")?.to_str().ok()?;
    if !constant_time_eq(secret.as_bytes(), presented.trim().as_bytes()) {
        return None;
    }
    let is_incident_write = (path.ends_with("/ack") || path.ends_with("/resolve"))
        && path.starts_with("/api/incidents/");
    is_incident_write.then(|| Identity {
        username: "webhook".to_string(),
        role: Role::Admin,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    value.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then(|| v.trim())
    })
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
struct LoginRequest {
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

async fn login(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    if state.auth.disabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "auth is disabled (mode = none)"})),
        )
            .into_response();
    }
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    if !state.login_limiter.allowed(peer_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "too many login attempts; retry later"})),
        )
            .into_response();
    }

    let Ok(Json(req)) = Json::<LoginRequest>::from_request(req, &state).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid JSON body"})),
        )
            .into_response();
    };

    let identity = if let Some(token) = req
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        if !state.auth.token_auth_enabled() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "token auth is not enabled"})),
            )
                .into_response();
        }
        state.auth.identify(Some(token), None)
    } else {
        match (
            req.username.as_deref().map(str::trim),
            req.password.as_deref(),
        ) {
            (Some(u), Some(p)) if !u.is_empty() => {
                if !state.auth.password_login_enabled() {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "password auth is not enabled"})),
                    )
                        .into_response();
                }
                state.auth.verify_password_login(u, p).map(|role| Identity {
                    username: u.to_string(),
                    role,
                })
            }
            _ => None,
        }
    };

    let Some(identity) = identity else {
        state.login_limiter.record_failure(peer_ip);
        return unauthorized();
    };

    let Some(value) = state.auth.issue_session(&identity.username) else {
        return internal_error("session signing key unavailable").into_response();
    };
    session_response(&identity, &value, state.auth.session_ttl_secs())
}

fn session_response(identity: &Identity, value: &str, ttl_secs: u64) -> Response {
    let cookie =
        format!("{SESSION_COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={ttl_secs}");
    (
        [(header::SET_COOKIE, cookie)],
        Json(json!({
            "authenticated": true,
            "username": identity.username,
            "role": identity.role.as_str(),
        })),
    )
        .into_response()
}

async fn logout() -> Response {
    let cookie = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    (
        [(header::SET_COOKIE, cookie)],
        Json(json!({"authenticated": false})),
    )
        .into_response()
}

async fn me(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    if state.auth.disabled() {
        return Json(json!({"authenticated": true, "username": "anonymous", "role": "admin"}))
            .into_response();
    }
    let bearer = bearer_token(req.headers());
    let cookie = cookie_value(req.headers(), state.auth.cookie_name());
    match state.auth.identify(bearer, cookie) {
        Some(identity) => Json(json!({
            "authenticated": true,
            "username": identity.username,
            "role": identity.role.as_str(),
        }))
        .into_response(),
        None => Json(json!({"authenticated": false})).into_response(),
    }
}

/// Fixed-window per-IP limiter guarding the login endpoint.
struct LoginLimiter {
    attempts: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    max_failures: u32,
    window: Duration,
}

impl LoginLimiter {
    fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_failures,
            window,
        }
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        let guard = self.attempts.lock().unwrap();
        match guard.get(&ip) {
            Some((count, started)) if started.elapsed() < self.window => *count < self.max_failures,
            _ => true,
        }
    }

    fn record_failure(&self, ip: IpAddr) {
        let mut guard = self.attempts.lock().unwrap();
        let entry = guard.entry(ip);
        match entry {
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                let (count, started) = slot.get_mut();
                if started.elapsed() >= self.window {
                    *count = 1;
                    *started = Instant::now();
                } else {
                    *count += 1;
                }
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert((1, Instant::now()));
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    limit: Option<i64>,
    level: Option<String>,
}

async fn list_events(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let mut rows = state
        .repo
        .events()
        .recent(limit)
        .await
        .map_err(internal_error)?;
    if let Some(level) = q.level.as_deref() {
        rows.retain(|r| r.risk_level.eq_ignore_ascii_case(level));
    }
    Ok(Json(json!({ "events": rows })))
}

async fn stats(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let since = Utc::now() - ChronoDuration::hours(24);
    let by_level = state
        .repo
        .events()
        .count_by_level_since(since)
        .await
        .map_err(internal_error)?;
    let by_verdict = state
        .repo
        .events()
        .count_by_verdict_since(since)
        .await
        .map_err(internal_error)?;
    let top_ips = state
        .repo
        .events()
        .top_ips(10, since)
        .await
        .map_err(internal_error)?;
    let top_paths = state
        .repo
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
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = state
        .repo
        .incidents()
        .unresolved(100)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({ "incidents": rows })))
}

async fn resolve_incident(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .repo
        .incidents()
        .resolve(id)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({"resolved": id})))
}

async fn ack_incident(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .repo
        .incidents()
        .ack(id)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({"acked": id})))
}

async fn list_blocked(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = state
        .repo
        .ip_state()
        .blocked(100)
        .await
        .map_err(internal_error)?;
    Ok(Json(json!({ "blocked": rows })))
}

async fn block_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, format!("invalid IP `{ip}`")))?;
    state
        .repo
        .ip_state()
        .block(ip, Some("dashboard"), None)
        .await
        .map_err(internal_error)?;
    let _ = state.repo.pool().notify("sentry_blocks_changed").await;
    Ok(Json(json!({"blocked": ip})))
}

async fn unblock_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, format!("invalid IP `{ip}`")))?;
    state
        .repo
        .ip_state()
        .unblock(ip)
        .await
        .map_err(internal_error)?;
    let _ = state.repo.pool().notify("sentry_blocks_changed").await;
    Ok(Json(json!({"unblocked": ip})))
}

async fn forgive_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, format!("invalid IP `{ip}`")))?;
    state
        .repo
        .ip_state()
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
    use crate::auth::token_hash;
    use axum::body::Body;
    use axum::http::Request;
    use sentry_core::config::{AuthTokenConfig, AuthUserConfig, ServerAuthConfig, ServerConfig};
    use tower::ServiceExt;

    /// A lazy pool pointed at an unreachable address: enough to build the
    /// router and serve non-query routes without a live database.
    fn test_repo() -> Arc<Repo> {
        let pool =
            sentry_storage::PgPool::connect_lazy("postgres://nobody:nobody@127.0.0.1:1/none")
                .expect("lazy pool");
        Arc::new(Repo::new(pool))
    }

    fn argon_hash(password: &str) -> String {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        argon2::Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string()
    }

    fn auth_state(mode: &str) -> AppState {
        std::env::set_var(
            "SENTRY_TEST_SERVER_SECRET",
            "0123456789abcdef0123456789abcdef",
        );
        let auth = ServerAuthConfig {
            mode: mode.to_string(),
            users: vec![AuthUserConfig {
                username: "alice".to_string(),
                password_hash: argon_hash("wonder"),
                role: "admin".to_string(),
            }],
            tokens: vec![AuthTokenConfig {
                token_sha256: token_hash("viewtok"),
                token_env: String::new(),
                role: "viewer".to_string(),
            }],
            session_secret_env: "SENTRY_TEST_SERVER_SECRET".to_string(),
            session_ttl_secs: 600,
        };
        let cfg = SentryConfig {
            server: ServerConfig {
                auth,
                ..ServerConfig::default()
            },
            ..SentryConfig::default()
        };
        let layer = AuthLayer::from_config(&cfg).unwrap();
        AppState {
            repo: test_repo(),
            auth: Arc::new(layer),
            login_limiter: Arc::new(LoginLimiter::new(LOGIN_MAX_FAILURES, LOGIN_WINDOW)),
            webhook_secret: None,
        }
    }

    fn open_state() -> AppState {
        AppState {
            repo: test_repo(),
            auth: Arc::new(AuthLayer::from_config(&SentryConfig::default()).unwrap()),
            login_limiter: Arc::new(LoginLimiter::new(LOGIN_MAX_FAILURES, LOGIN_WINDOW)),
            webhook_secret: None,
        }
    }

    fn webhook_state() -> AppState {
        let mut st = auth_state("token");
        st.webhook_secret = Some("wsecret".to_string());
        st
    }

    async fn serve(app: Router, req: Request<Body>) -> Response {
        app.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn health_and_static_routes_respond() {
        let app = router(open_state());
        for uri in ["/api/health", "/", "/app.js", "/style.css"] {
            let resp = serve(
                app.clone(),
                Request::builder().uri(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
        }
    }

    #[tokio::test]
    async fn auth_disabled_allows_everything() {
        let app = router(open_state());
        let resp = serve(
            app,
            Request::builder()
                .method("POST")
                .uri("/api/ips/not-an-ip/block")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        // Reaches the handler (bad IP), not the auth layer.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn protected_routes_require_auth() {
        let app = router(auth_state("both"));
        let resp = serve(
            app.clone(),
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_bearer_token_passes_and_viewer_is_read_only() {
        let app = router(auth_state("both"));
        // Viewer GET passes auth; the method router answers 405 (no DB hit).
        let resp = serve(
            app.clone(),
            Request::builder()
                .uri("/api/incidents/00000000-0000-0000-0000-000000000000/resolve")
                .header(AUTHORIZATION, "Bearer viewtok")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // Viewer mutation is rejected with 403 before touching the DB.
        let resp = serve(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/ips/203.0.113.9/block")
                .header(AUTHORIZATION, "Bearer viewtok")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invalid_token_is_unauthorized() {
        let app = router(auth_state("token"));
        let resp = serve(
            app,
            Request::builder()
                .uri("/api/stats")
                .header(AUTHORIZATION, "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_issues_session_cookie_that_authenticates() {
        let app = router(auth_state("password"));
        let body = serde_json::to_vec(&json!({"username": "alice", "password": "wonder"})).unwrap();
        let resp = serve(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("set-cookie")
            .to_string();
        assert!(cookie.starts_with("sentry_session="));
        assert!(cookie.contains("HttpOnly"));

        let value = cookie
            .split(';')
            .next()
            .unwrap()
            .trim_start_matches("sentry_session=")
            .to_string();
        let resp = serve(
            app,
            Request::builder()
                .uri("/api/incidents/00000000-0000-0000-0000-000000000000/resolve")
                .header(header::COOKIE, format!("sentry_session={value}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        // Session accepted (middleware passed; method router answers 405).
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn login_rejects_bad_credentials() {
        let app = router(auth_state("password"));
        let body = serde_json::to_vec(&json!({"username": "alice", "password": "nope"})).unwrap();
        let resp = serve(
            app,
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_with_token_issues_session() {
        let app = router(auth_state("both"));
        let body = serde_json::to_vec(&json!({"token": "viewtok"})).unwrap();
        let resp = serve(
            app,
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["role"], "viewer");
    }

    #[tokio::test]
    async fn me_reports_identity() {
        let app = router(auth_state("both"));
        let resp = serve(
            app.clone(),
            Request::builder()
                .uri("/api/me")
                .header(AUTHORIZATION, "Bearer viewtok")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["authenticated"], true);
        assert_eq!(v["role"], "viewer");

        let resp = serve(
            app,
            Request::builder()
                .uri("/api/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["authenticated"], false);
    }

    #[tokio::test]
    async fn login_limiter_blocks_after_failures() {
        let limiter = LoginLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(limiter.allowed(ip));
        for _ in 0..3 {
            limiter.record_failure(ip);
        }
        assert!(!limiter.allowed(ip));
        // Different IP is unaffected.
        assert!(limiter.allowed("198.51.100.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn webhook_secret_grants_incident_write_only() {
        let app = router(webhook_state());
        // Correct secret on the incident path: middleware passes (the route
        // is POST-only, so a GET answers 405 — no DB involved).
        let resp = serve(
            app.clone(),
            Request::builder()
                .uri("/api/incidents/00000000-0000-0000-0000-000000000000/ack")
                .header("x-sentry-webhook-secret", "wsecret")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        // Same secret outside the incident scope: rejected.
        let resp = serve(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/ips/203.0.113.9/block")
                .header("x-sentry-webhook-secret", "wsecret")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong secret: rejected.
        let resp = serve(
            app,
            Request::builder()
                .method("POST")
                .uri("/api/incidents/00000000-0000-0000-0000-000000000000/ack")
                .header("x-sentry-webhook-secret", "wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn cookie_value_parses_pairs() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "a=1; sentry_session=xyz; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&headers, "sentry_session"), Some("xyz"));
        assert_eq!(cookie_value(&headers, "a"), Some("1"));
        assert_eq!(cookie_value(&headers, "missing"), None);
    }

    #[tokio::test]
    async fn invalid_ip_yields_bad_request() {
        let app = router(open_state());
        let resp = serve(
            app,
            Request::builder()
                .method("POST")
                .uri("/api/ips/not-an-ip/block")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn embedded_assets_are_present() {
        assert!(INDEX_HTML.contains("Sentry"));
        assert!(APP_JS.contains("fetch"));
        assert!(STYLE_CSS.contains(":root"));
    }
}
