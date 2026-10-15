//! `edge-http` — inline reverse proxy (F3.9a).
//!
//! Sentry owns the public port: every request is scored through the pipeline
//! *before* the backend sees it. Verdict mapping: `Block`/`Quarantine` → 403,
//! `RateLimit` → 429, `Challenge` → challenge page, `Allow` → proxied.
//! Decided events are pushed to `decided` so the host (daemon) can persist
//! them and fire actions exactly once — the pipeline is shared, so stateful
//! trackers never double-count.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::header;
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::pages;
use crate::EdgeRuntime;
use uuid::Uuid;

/// Inline proxy configuration (F14): the default (catch-all) upstream
/// group, optional vhost groups, and the listener/socket tuning knobs.
#[derive(Debug, Clone)]
pub struct EdgeProxyConfig {
    /// Listen address (`0.0.0.0:80`). An empty string disables the plain
    /// listener (HTTPS-only edge).
    pub listen: String,
    /// Default (catch-all) upstream base URLs — IP or hostname
    /// (`http://web:3000`), load-balanced with `balance`.
    pub upstreams: Vec<String>,
    /// Load-balancing strategy for every group without an override.
    pub balance: sentry_core::config::BalanceMode,
    /// Passive health check: failures inside `fail_timeout_secs` before a
    /// server is ejected (0 = never).
    pub max_fails: u32,
    /// Failure window and ejection duration (seconds).
    pub fail_timeout_secs: u64,
    /// Path used for the mandatory startup health check (default `/`).
    pub health_path: String,
    /// Health check timeout in seconds (default 5).
    pub health_timeout_secs: u64,
    /// HTTPS front (F8): `None` serves plain HTTP only.
    pub tls: Option<TlsEdgeConfig>,
    /// Nginx-style virtual hosts (F14): Host-header routing to per-site
    /// upstream groups.
    pub vhosts: Vec<sentry_core::config::EdgeVhostConfig>,
    /// Response compression settings (F12) — projected from
    /// `[edge.compress]`.
    pub compress: sentry_core::config::EdgeCompressConfig,
    /// Set `X-Forwarded-*`/`X-Real-IP` on forwarded requests (F12), after
    /// stripping the client's copies.
    pub forwarded_headers: bool,
    /// Stream upstream responses instead of buffering them (F14): fixes
    /// SSE/streaming payloads, at the cost of response compression.
    pub response_buffering: bool,
    /// Connect timeout for the upstream hop (seconds).
    pub upstream_connect_timeout_secs: u64,
    /// Total per-request upstream budget (seconds): connect + read + write.
    pub upstream_timeout_secs: u64,
    /// Idle keepalive connections pooled per upstream host.
    pub upstream_pool_idle: usize,
    /// Max requests served concurrently (0 = unlimited). Each in-flight
    /// request buffers body bytes, so the cap bounds edge memory under a
    /// connection flood; excess requests get an immediate 503.
    pub max_concurrent_requests: usize,
    /// Accept-loop workers sharing the port via `SO_REUSEPORT` (F14, unix).
    pub reuseport_workers: usize,
    /// Listen backlog (F14); 0 = system maximum.
    pub tcp_backlog: u32,
    /// Client-facing TCP flags (F14): nodelay, keepalive, buffers.
    pub tcp_tuning: crate::net::TcpTuning,
}

/// HTTPS front settings (F8) — built by the daemon from `[edge] tls_*`.
#[derive(Debug, Clone, Default)]
pub struct TlsEdgeConfig {
    /// HTTPS listen address (`0.0.0.0:443`).
    pub listen: String,
    /// Certificate PEM file — also the default chain for hostnames without
    /// a per-vhost cert (F14).
    pub cert: PathBuf,
    /// Private key PEM file.
    pub key: PathBuf,
    /// Answer plain-HTTP with a 301 to HTTPS. The redirect runs after the
    /// pipeline, so port-80 traffic keeps being monitored and enforced.
    pub redirect_https: bool,
    /// ClientHello SNI allowlist; empty disables the mismatch check.
    pub allowed_hosts: Vec<String>,
    /// Emit one `TlsHandshake` event per completed handshake.
    pub handshake_events: bool,
    /// Negotiate HTTP/2 via ALPN alongside HTTP/1.1 (F12).
    pub http2: bool,
    /// Per-vhost certificates (F14): SNI-selected, `cert`/`key` remain the
    /// default chain for unknown hostnames.
    pub extra_certs: Vec<VhostCert>,
}

/// One vhost TLS certificate (F14): served via SNI for `hosts` (exact
/// names or `*.wildcard` patterns).
#[derive(Debug, Clone)]
pub struct VhostCert {
    /// Hostnames this certificate answers.
    pub hosts: Vec<String>,
    /// Certificate PEM file.
    pub cert: PathBuf,
    /// Private key PEM file.
    pub key: PathBuf,
}

impl Default for EdgeProxyConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:80".to_string(),
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            balance: sentry_core::config::BalanceMode::default(),
            max_fails: 2,
            fail_timeout_secs: 30,
            health_path: "/".to_string(),
            health_timeout_secs: 5,
            tls: None,
            vhosts: Vec::new(),
            compress: sentry_core::config::EdgeCompressConfig::default(),
            forwarded_headers: true,
            response_buffering: true,
            upstream_connect_timeout_secs: 5,
            upstream_timeout_secs: 300,
            upstream_pool_idle: 32,
            max_concurrent_requests: 1024,
            reuseport_workers: 1,
            tcp_backlog: 0,
            tcp_tuning: crate::net::TcpTuning::default(),
        }
    }
}

/// Header pairs that must not be forwarded hop-by-hop.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// Client-supplied forwarding headers (F12): when `[edge]
/// forwarded_headers` is on, these are stripped before the edge sets its
/// own — a direct client cannot spoof its IP or scheme past the edge, and
/// the backend's `real_ip` module sees exactly the edge's view.
const FORWARDED_STRIP: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
];

/// Marks a response that actually came from the upstream backend, so the
/// F11 posture check only grades origin headers — edge-generated pages
/// (block/challenge/rate-limit/redirect) never carry the marker.
#[derive(Debug, Clone)]
struct UpstreamServed;

/// The reqwest client toward the upstreams. Certificates on `https://`
/// upstreams are always verified — an unverified TLS hop protects against
/// passive eavesdropping only, so backends with self-signed certificates
/// should be served over plain `http://` inside the private network
/// instead (same trust assumption, one less thing to misconfigure).
#[derive(Clone)]
pub(crate) struct UpstreamClients {
    verified: reqwest::Client,
}

impl UpstreamClients {
    fn build(cfg: &EdgeProxyConfig) -> sentry_core::error::Result<Self> {
        Ok(Self {
            verified: reqwest::Client::builder()
                .timeout(Duration::from_secs(cfg.upstream_timeout_secs.max(1)))
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(
                    cfg.upstream_connect_timeout_secs.max(1),
                ))
                .pool_idle_timeout(Duration::from_secs(90))
                .pool_max_idle_per_host(cfg.upstream_pool_idle)
                .tcp_keepalive(Duration::from_secs(60))
                .tcp_nodelay(true)
                .build()
                .map_err(|e| {
                    sentry_core::error::CoreError::Config(format!("edge http client: {e}"))
                })?,
        })
    }

    /// Single verified client (tests).
    #[cfg(test)]
    fn verified_only(client: reqwest::Client) -> Self {
        Self { verified: client }
    }
}

/// The raw h1 client used for WebSocket/h1 upgrade pass-through (F14).
/// reqwest cannot handle `101 Switching Protocols`, so upgrades bypass it.
type UpgradeClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    http_body_util::Full<bytes::Bytes>,
>;

fn default_upgrade_client() -> UpgradeClient {
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http()
}

/// Build the host-routing table (F14) from the proxy config: one default
/// (catch-all) group plus one group per vhost, each with the effective
/// balancer/health settings resolved from the globals.
fn build_vhost_router(cfg: &EdgeProxyConfig) -> crate::upstream::VhostRouter {
    use sentry_core::config::EdgeVhostConfig;
    let default = crate::upstream::UpstreamGroup::new(
        "",
        &cfg.upstreams,
        cfg.balance,
        cfg.max_fails,
        cfg.fail_timeout_secs,
    );
    let entries: Vec<(String, crate::upstream::UpstreamGroup)> = cfg
        .vhosts
        .iter()
        .map(|v: &EdgeVhostConfig| {
            (
                v.host.clone(),
                crate::upstream::UpstreamGroup::new(
                    v.host.clone(),
                    &v.upstreams,
                    v.effective_balance(cfg.balance),
                    v.effective_max_fails(cfg.max_fails),
                    v.effective_fail_timeout(cfg.fail_timeout_secs),
                ),
            )
        })
        .collect();
    crate::upstream::VhostRouter::new(default, entries)
}

/// Verify the upstreams answer before the edge starts accepting traffic.
///
/// Inline mode is an explicit opt-in precisely because a dead backend turns
/// the edge into an outage. With groups (F14) the contract is per group:
/// at least one server must answer — a down secondary is a warning (that is
/// exactly what failover exists for), a group with no healthy server is
/// fatal.
pub async fn health_check(cfg: &EdgeProxyConfig) -> sentry_core::error::Result<()> {
    let router = build_vhost_router(cfg);
    health_check_router(&router, cfg).await
}

async fn health_check_router(
    router: &crate::upstream::VhostRouter,
    cfg: &EdgeProxyConfig,
) -> sentry_core::error::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.health_timeout_secs.max(1)))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| sentry_core::error::CoreError::Config(format!("edge http client: {e}")))?;
    let checks = router.groups().map(|group| {
        let client = client.clone();
        let health_path = match group.name.is_empty() {
            true => cfg.health_path.clone(),
            false => cfg
                .vhosts
                .iter()
                .find(|v| v.host == group.name)
                .and_then(|v| v.health_path.clone())
                .unwrap_or_else(|| cfg.health_path.clone()),
        };
        async move {
            let mut failures: Vec<String> = Vec::new();
            let mut healthy = 0usize;
            for idx in 0..group.len() {
                let url = format!("{}{}", group.url(idx).trim_end_matches('/'), health_path);
                match client.get(&url).send().await {
                    Ok(_) => healthy += 1,
                    Err(e) => failures.push(format!("{}: {e}", group.url(idx))),
                }
            }
            (group.name.clone(), healthy, failures)
        }
    });
    let results = futures::future::join_all(checks).await;
    let mut errors: Vec<String> = Vec::new();
    for (name, healthy, failures) in results {
        let label = match name.is_empty() {
            true => "default".to_string(),
            false => format!("vhost {name}"),
        };
        for f in failures {
            warn!(group = %label, "edge upstream failed the startup health check: {f}");
        }
        if healthy == 0 {
            errors.push(format!(
                "edge upstream health check failed for {label} — refusing to start inline on a dead backend"
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(sentry_core::error::CoreError::Config(errors.join("; ")))
    }
}

/// Serve the inline edge until the process stops.
///
/// With a TLS front (F8) the plain and HTTPS listeners run concurrently
/// on the same pipeline: port 80 and port 443 are both monitored, blocked
/// IPs are denied on both, and the SNI/JA3 telemetry flows from the TLS
/// acceptor. Requests are routed by Host header across the upstream
/// groups (F14) with load balancing, passive health checks and failover.
pub async fn serve(
    runtime: EdgeRuntime,
    cfg: EdgeProxyConfig,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
) -> sentry_core::error::Result<()> {
    let router = Arc::new(build_vhost_router(&cfg));
    let clients = UpstreamClients::build(&cfg)?;
    health_check_router(&router, &cfg).await?;

    // Response compression (F12): one middleware around the router covers
    // upstream responses and edge-generated pages on both listeners. The
    // compressor shares the overload state, so pressure sheds the
    // compression CPU automatically.
    let compressor = Arc::new(crate::compression::Compressor::new(
        cfg.compress.clone(),
        runtime.overload_state(),
        runtime.compressed().cloned(),
    ));

    let redirect_https = cfg.tls.as_ref().is_some_and(|t| t.redirect_https);
    let listener_opts = crate::net::ListenerOptions {
        backlog: cfg.tcp_backlog,
        reuseport: cfg.reuseport_workers > 1,
        tuning: cfg.tcp_tuning,
    };
    let app = build_router(
        ProxyState {
            runtime: runtime.clone(),
            clients,
            router,
            decided: decided.clone(),
            redirect_https,
            forwarded_headers: cfg.forwarded_headers,
            response_buffering: cfg.response_buffering,
            gate: (cfg.max_concurrent_requests > 0)
                .then(|| Arc::new(tokio::sync::Semaphore::new(cfg.max_concurrent_requests))),
            failovers: runtime.upstream_failovers().cloned(),
            upgrade_client: default_upgrade_client(),
        },
        compressor,
    );

    match cfg.tls {
        None => serve_plain(app, cfg.listen, listener_opts, cfg.reuseport_workers).await,
        Some(tls_cfg) => {
            #[cfg(feature = "edge-tls")]
            {
                tokio::try_join!(
                    serve_plain(
                        app.clone(),
                        cfg.listen,
                        listener_opts,
                        cfg.reuseport_workers
                    ),
                    crate::tls::serve_tls(runtime, tls_cfg, app, decided, listener_opts)
                )?;
                Ok(())
            }
            #[cfg(not(feature = "edge-tls"))]
            {
                let _ = (tls_cfg, runtime, app, decided, listener_opts);
                Err(sentry_core::error::CoreError::Config(
                    "edge tls configured but sentry was built without the `edge-tls` \
                     feature — rebuild with --features sentry-cli/edge-tls"
                        .to_string(),
                ))
            }
        }
    }
}

/// Router shared by both listeners: the proxy handler as fallback, wrapped
/// in the response-compression middleware (F12). Extracted so tests drive
/// the exact production path.
fn build_router(state: ProxyState, compressor: Arc<crate::compression::Compressor>) -> Router {
    Router::new()
        .fallback(any(proxy_handler))
        .layer(axum::middleware::from_fn(
            move |req: Request, next: axum::middleware::Next| {
                let compressor = compressor.clone();
                crate::compression::compress_layer(compressor, req, next)
            },
        ))
        .with_state(state)
}

/// Plain-HTTP listener. An empty `listen` disables it (HTTPS-only edge).
/// With `reuseport_workers > 1` (unix) several sockets bind the same
/// address, each with its own kernel accept queue (F14).
async fn serve_plain(
    app: Router,
    listen: String,
    opts: crate::net::ListenerOptions,
    workers: usize,
) -> sentry_core::error::Result<()> {
    if listen.is_empty() {
        return Ok(());
    }
    let addr: SocketAddr = listen.parse().map_err(|e| {
        sentry_core::error::CoreError::Config(format!("invalid edge listen address: {e}"))
    })?;
    let mut workers = workers.max(1);
    #[cfg(not(unix))]
    if workers > 1 {
        workers = 1;
        warn!(
            "edge: reuseport_workers > 1 requires SO_REUSEPORT (unix) — using a single accept loop"
        );
    }
    let mut listeners = Vec::with_capacity(workers);
    for _ in 0..workers {
        listeners.push(crate::net::bind_listener(addr, opts).map_err(|e| {
            sentry_core::error::CoreError::Config(format!("edge bind on {addr} failed: {e}"))
        })?);
    }
    if workers == 1 {
        info!(addr = %addr, "edge (inline) listening on http");
    } else {
        info!(
            addr = %addr,
            workers,
            "edge (inline) listening on http with reuseport workers"
        );
    }
    let mut tasks = Vec::with_capacity(listeners.len());
    for listener in listeners {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            accept_loop(listener, app, opts.tuning).await
        }));
    }
    for task in tasks {
        task.await
            .map_err(|e| sentry_core::error::CoreError::Config(format!("edge accept task: {e}")))?
            .map_err(|e| {
                sentry_core::error::CoreError::Config(format!("edge server error: {e}"))
            })?;
    }
    Ok(())
}

/// Per-connection accept loop: tune the socket (F14 `tcp_*` flags), inject
/// `ConnectInfo` and serve it with hyper's auto builder so h1 — and
/// `serve_connection_with_upgrades` — powers WebSocket pass-through (F14).
async fn accept_loop(
    listener: tokio::net::TcpListener,
    app: Router,
    tuning: crate::net::TcpTuning,
) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        crate::net::tune_accepted(&tcp, &tuning);
        tokio::spawn({
            let app = app.clone();
            async move {
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let mut app = app.clone();
                        async move {
                            let mut req = req.map(axum::body::Body::new);
                            req.extensions_mut()
                                .insert(axum::extract::ConnectInfo(peer));
                            use tower_service::Service as _;
                            app.call(req).await
                        }
                    },
                );
                let io = hyper_util::rt::TokioIo::new(tcp);
                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection_with_upgrades(io, svc)
                .await
                {
                    tracing::debug!(error = %e, "edge connection ended");
                }
            }
        });
    }
}

/// Shared handler state (single struct — the state tuple got unwieldy).
#[derive(Clone)]
struct ProxyState {
    runtime: EdgeRuntime,
    clients: UpstreamClients,
    /// Host-header routing table (F14): default group + vhost groups with
    /// their balancers and passive-health state.
    router: Arc<crate::upstream::VhostRouter>,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
    /// 301 plain-HTTP requests to HTTPS (F8, TLS front only).
    redirect_https: bool,
    /// Set `X-Forwarded-*`/`X-Real-IP` on forwarded requests (F12).
    forwarded_headers: bool,
    /// Buffer upstream responses before forwarding (F14). `false` streams
    /// them (SSE payloads) — compression passes those through.
    response_buffering: bool,
    /// Concurrency cap: in-flight requests hold a permit; when exhausted,
    /// new requests get an immediate 503 instead of buffering another body.
    gate: Option<Arc<tokio::sync::Semaphore>>,
    /// `sentry_edge_upstream_failovers_total{vhost}` (F14).
    failovers: Option<prometheus::CounterVec>,
    /// Raw h1 client for WebSocket/h1 upgrade pass-through (F14).
    upgrade_client: UpgradeClient,
}

/// Original request host: the `Host` header, or — for HTTP/2, where the
/// host rides the `:authority` pseudo-header and no `Host` header exists
/// on the wire — the request URI authority.
fn original_host(parts: &axum::http::request::Parts) -> Option<String> {
    parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
}

#[cfg(test)]
impl ProxyState {
    fn with_gate(mut self, gate: Option<Arc<tokio::sync::Semaphore>>) -> Self {
        self.gate = gate;
        self
    }

    fn with_redirect_https(mut self, redirect: bool) -> Self {
        self.redirect_https = redirect;
        self
    }

    fn with_buffering(mut self, buffering: bool) -> Self {
        self.response_buffering = buffering;
        self
    }
}

async fn proxy_handler(State(state): State<ProxyState>, req: Request) -> Response {
    let start = Instant::now();
    let runtime = state.runtime.clone();
    let _permit = match state.gate.clone() {
        Some(gate) => match gate.try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                let trace = Some(Uuid::new_v4());
                warn!(
                    ip = %req
                        .extensions()
                        .get::<axum::extract::ConnectInfo<SocketAddr>>()
                        .map(|c| c.0.ip().to_string())
                        .unwrap_or_default(),
                    trace_id = ?trace,
                    "edge: concurrency cap reached, shedding request"
                );
                return crate::pages::page_with(
                    runtime.error_pages(),
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "503 - Service Unavailable",
                    "The server is at capacity. Please retry shortly.",
                    trace,
                );
            }
        },
        None => None,
    };
    let resp = proxy_handler_inner(State(state), req, start).await;
    if let Some(h) = runtime.request_duration.as_ref() {
        h.observe(start.elapsed().as_secs_f64());
    }
    resp
}

async fn proxy_handler_inner(
    State(state): State<ProxyState>,
    req: Request,
    start: Instant,
) -> Response {
    let (parts, body) = req.into_parts();
    // Set by the TLS acceptor (F8) — a real HTTPS connection, not a
    // spoofable header.
    let is_tls = parts.extensions.get::<crate::TlsTerminated>().is_some();
    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_canonical())
        .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]));

    // While upload inspection is armed, the inspection cap IS the body cap
    // in `reject` mode: bodies beyond it are refused outright (413), and the
    // buffered bytes are what the heuristics analyze. The declared length is
    // checked before any buffering; chunked bodies hit the cap inside
    // `to_bytes`. In `skip`/`flag` mode (F12) oversize bodies buffer to the
    // forward cap instead and bypass inspection (`inspect_body` decides).
    // Under overload pressure the inspection path is skipped (cheap mode)
    // and the legacy forward buffering runs instead.
    let declared_len = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let error_pages = state.runtime.error_pages();
    if let Some(insp) = state
        .runtime
        .uploads_inspection()
        .filter(|_| !state.runtime.overloaded())
    {
        if insp.oversize == sentry_core::config::OversizePolicy::Reject {
            if declared_len.is_some_and(|len| len > insp.inspect_bytes) {
                state.runtime.record_oversize("reject");
                let trace = Uuid::new_v4();
                tracing::info!(ip = %peer, trace_id = %trace, declared = ?declared_len, cap = insp.inspect_bytes, elapsed = ?start.elapsed(), "edge: body beyond inspection cap rejected before buffering (no event persisted)");
                return pages::payload_too_large_page(error_pages, Some(trace));
            }
            let body_bytes = match axum::body::to_bytes(body, insp.inspect_bytes).await {
                Ok(b) => b.to_vec(),
                Err(_) => {
                    state.runtime.record_oversize("reject");
                    let trace = Uuid::new_v4();
                    tracing::info!(ip = %peer, trace_id = %trace, cap = insp.inspect_bytes, elapsed = ?start.elapsed(), "edge: chunked body beyond inspection cap rejected (no event persisted)");
                    return pages::payload_too_large_page(error_pages, Some(trace));
                }
            };
            return proxy_inspected(&state, parts, body_bytes, is_tls, peer, start).await;
        }
        let forward_cap = state.runtime.body_cap().max(1024 * 1024);
        let body_bytes = match axum::body::to_bytes(body, forward_cap).await {
            Ok(b) => b.to_vec(),
            Err(_) => {
                let trace = Uuid::new_v4();
                tracing::info!(ip = %peer, trace_id = %trace, cap = forward_cap, elapsed = ?start.elapsed(), "edge: body beyond forward cap rejected (no event persisted)");
                return pages::payload_too_large_page(error_pages, Some(trace));
            }
        };
        return proxy_inspected(&state, parts, body_bytes, is_tls, peer, start).await;
    }

    // Inspection disabled: legacy behavior — buffer for forwarding (≥1 MiB)
    // and capture the first `body_cap` bytes for persistence when enabled.
    let forward_cap = state.runtime.body_cap().max(1024 * 1024);
    let body_bytes = match axum::body::to_bytes(body, forward_cap).await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            let trace = Uuid::new_v4();
            tracing::info!(ip = %peer, trace_id = %trace, cap = forward_cap, elapsed = ?start.elapsed(), "edge: body beyond forward cap rejected (no event persisted)");
            return pages::payload_too_large_page(error_pages, Some(trace));
        }
    };
    proxy_inspected(&state, parts, body_bytes, is_tls, peer, start).await
}

/// Shared tail of the proxy handler once the body is buffered: upload
/// inspection, pipeline, verdict and upstream forwarding.
async fn proxy_inspected(
    state: &ProxyState,
    parts: axum::http::request::Parts,
    body_bytes: Vec<u8>,
    is_tls: bool,
    peer: std::net::IpAddr,
    start: Instant,
) -> Response {
    let runtime = &state.runtime;
    let mut parts = parts;
    let error_pages = runtime.error_pages();
    let captured = if runtime.body_cap() > 0 {
        Some(
            body_bytes
                .get(..runtime.body_cap())
                .unwrap_or(&body_bytes)
                .to_vec(),
        )
    } else {
        None
    };
    let (upload_meta, analysis_body) = runtime.inspect_body(
        parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        &body_bytes,
    );

    let headers: std::collections::HashMap<String, String> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let client_ip = crate::real_client_ip_with(&parts.headers, peer, runtime.trust());

    // Sticky blocks deny before the pipeline runs — no event, no upstream.
    // No event is persisted here, so the trace id only lives in the page
    // and the log line.
    if runtime.is_hard_blocked(client_ip) {
        let trace = Uuid::new_v4();
        tracing::info!(ip = %client_ip, trace_id = %trace, elapsed = ?start.elapsed(), "edge fast-path: blocked ip denied before pipeline (no event persisted)");
        return pages::block_page(error_pages, Some(trace));
    }
    let http = sentry_core::event::HttpData {
        method: Some(sentry_core::event::HttpMethod::from_str_lossy(
            parts.method.as_str(),
        )),
        scheme: Some(parts.uri.scheme_str().unwrap_or("http").to_string()),
        host: original_host(&parts),
        path: parts.uri.path().to_string(),
        query: parts
            .uri
            .query()
            .map(str::to_string)
            .filter(|q| !q.is_empty()),
        fragment: None,
        status: None,
        user_agent: headers.get("user-agent").cloned(),
        referer: headers.get("referer").cloned(),
        headers,
        body: analysis_body.clone().or_else(|| captured.clone()),
        cookies: Some(crate::challenge::parse_cookies(&parts.headers)),
        uploads: upload_meta,
        upstream_time_ms: None,
    };
    let mut evt = sentry_core::event::Event::new(
        sentry_core::event::SourceKind::HttpProxy,
        client_ip,
        sentry_core::ProtocolData::Http(http),
    );
    evt.client_port = parts
        .extensions
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.port());

    let mut processed = runtime.process(evt);
    // Restore the persistence semantics of `HttpData.body` (capture cap only
    // — the analysis prefix above never lands in the published event).
    if let Some(http) = processed.event.http_mut() {
        http.body = captured.clone();
    }
    let ua = processed.event.http().and_then(|h| h.user_agent.clone());
    let path = processed
        .event
        .http()
        .map(|h| h.path.clone())
        .unwrap_or_default();

    let resp = match processed.decision.action {
        sentry_core::analysis::Verdict::Allow => {
            let client_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
            serve_allow(
                state,
                &parts,
                &body_bytes,
                is_tls,
                client_ip,
                client_upgrade,
            )
            .await
        }
        sentry_core::analysis::Verdict::RateLimit => {
            pages::rate_limit_page(error_pages, Some(processed.event.id))
        }
        sentry_core::analysis::Verdict::Challenge => {
            match runtime.challenge_gate(&parts.headers, client_ip, Some(processed.event.id)) {
                crate::ChallengeGate::Pass => {
                    let client_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
                    serve_allow(
                        state,
                        &parts,
                        &body_bytes,
                        is_tls,
                        client_ip,
                        client_upgrade,
                    )
                    .await
                }
                crate::ChallengeGate::Page(page) => page,
                crate::ChallengeGate::Blocked(page) => page,
                crate::ChallengeGate::Disabled => {
                    pages::challenge_required_page(error_pages, Some(processed.event.id))
                }
            }
        }
        sentry_core::analysis::Verdict::Block | sentry_core::analysis::Verdict::Quarantine => {
            pages::block_page(error_pages, Some(processed.event.id))
        }
    };

    // Response-phase feedback: the request-phase pipeline saw no status (the
    // response did not exist yet), so the status-keyed trackers (scan,
    // behavior) are fed here with the real code — their signals are queued
    // for the next request from this IP. The event is published only now so
    // it carries the response status it displays.
    let status = resp.status().as_u16();
    if let sentry_core::ProtocolData::Http(http) = &mut processed.event.protocol {
        http.status = Some(status);
    }
    runtime
        .pipeline()
        .observe_response(client_ip, &path, status, ua.as_deref());

    // Posture advisories (F11): grade only upstream responses (edge pages
    // and redirects are not the site's headers) on successful statuses, and
    // attach weight-0 signals — advisory only, the verdict stands.
    if resp.extensions().get::<UpstreamServed>().is_some() && status < 500 {
        if let (Some(tracker), Some(host)) = (
            runtime.posture(),
            processed.event.http().and_then(|h| h.host.clone()),
        ) {
            let header_pairs = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str(), s)));
            let findings = tracker.observe(&host, header_pairs, is_tls);
            if !findings.is_empty() {
                if let Some(counter) = runtime.posture_findings() {
                    for f in &findings {
                        counter.with_label_values(&[f.check, &host]).inc();
                    }
                }
                processed
                    .analysis
                    .signals
                    .extend(findings.iter().map(|f| f.to_signal()));
            }
        }
    }

    // Total inline request duration (request received → response ready to
    // send) — the edge analogue of nginx `$request_time`, shown on the
    // console line next to the pipeline overhead (`process_us`).
    if processed.event.duration_ms.is_none() {
        processed.event.duration_ms = Some(start.elapsed().as_millis() as u64);
    }

    if let Err(e) = state.decided.try_send(processed) {
        warn!(error = %e, "failed to publish decided event");
    }

    resp
}

/// Allow path (and challenge-passed requests): plain-HTTP → HTTPS redirect
/// (F8) when configured, otherwise resolve the Host's upstream group (F14)
/// and forward with load balancing, passive health checks and failover
/// (a connection-level failure retries the next server — nginx
/// `proxy_next_upstream error timeout`; the buffered body makes retrying
/// safe). With `forwarded_headers` (F12) the client's own
/// `X-Forwarded-*`/`X-Real-IP` are stripped and replaced with the edge's
/// resolved view: `X-Forwarded-For`/`X-Real-IP` carry the client IP,
/// `X-Forwarded-Proto` the real scheme, `X-Forwarded-Host` the requested
/// host — so backend `real_ip` modules and virtual hosts work unchanged.
/// h1 upgrade requests (WebSocket, F14) take the raw pass-through path.
async fn serve_allow(
    state: &ProxyState,
    parts: &axum::http::request::Parts,
    body_bytes: &[u8],
    is_tls: bool,
    client_ip: std::net::IpAddr,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response {
    let error_pages = state.runtime.error_pages_handle();
    // Plain-HTTP → HTTPS redirect (F8): port-80 traffic stays monitored and
    // enforced; benign requests get the 301 instead of double-hitting the
    // upstream.
    if state.redirect_https && !is_tls {
        if let Some(host) = parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        {
            let query = match parts.uri.query() {
                Some(q) => format!("?{q}"),
                None => String::new(),
            };
            return Response::builder()
                .status(axum::http::StatusCode::MOVED_PERMANENTLY)
                .header(
                    header::LOCATION,
                    format!("https://{host}{}{query}", parts.uri.path()),
                )
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| {
                    let trace = Uuid::new_v4();
                    tracing::error!(trace_id = %trace, "edge: redirect response build failed");
                    pages::bad_gateway_page(error_pages.as_deref(), Some(trace))
                });
        }
    }

    let host = original_host(parts);
    let group = state.router.resolve(host.as_deref());
    let client = &state.clients.verified;

    // WebSocket / h1 upgrade: bypass the buffered forward and pipe the two
    // upgraded connections bidirectionally (F14).
    if is_upgrade_request(parts) {
        return proxy_upgrade(state, group, parts, host.as_deref(), client_upgrade).await;
    }

    let path_qs = match parts.uri.query() {
        Some(q) => format!("{}?{q}", parts.uri.path()),
        None => parts.uri.path().to_string(),
    };
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let now = crate::upstream::now_ms();
    let mut tried: Vec<usize> = Vec::new();
    loop {
        let Some(idx) = group.pick_excluding(&tried, client_ip, now) else {
            // Every server is down or was already tried this request.
            let trace = Uuid::new_v4();
            warn!(
                vhost = %group.name,
                trace_id = %trace,
                "edge: upstream group exhausted — all servers down or failing"
            );
            return pages::bad_gateway_page(error_pages.as_deref(), Some(trace));
        };
        tried.push(idx);
        let url = format!("{}{}", group.url(idx).trim_end_matches('/'), path_qs);
        group.begin(idx);
        let hop = HopRequest {
            parts,
            body: body_bytes,
            is_tls,
            host: host.as_deref(),
            client_ip,
        };
        let outcome =
            forward_once(client, method.clone(), &url, &hop, state.forwarded_headers).await;
        group.done(idx);
        match outcome {
            Ok(resp) => {
                group.record_success(idx);
                return finalize_upstream_response(state, resp, &url).await;
            }
            Err(ForwardError::Retryable(e)) => {
                let ejected = group.record_failure(idx, crate::upstream::now_ms());
                if let Some(counter) = &state.failovers {
                    let label = match group.name.is_empty() {
                        true => "default".to_string(),
                        false => group.name.clone(),
                    };
                    counter.with_label_values(&[&label]).inc();
                }
                warn!(
                    server = %group.server_label(idx),
                    ejected,
                    error = %e,
                    url = %url,
                    "edge upstream failed — failing over to the next server"
                );
            }
            Err(ForwardError::Fatal(e)) => {
                let trace = Uuid::new_v4();
                warn!(error = %e, url = %url, trace_id = %trace, "edge upstream request failed");
                return pages::bad_gateway_page(error_pages.as_deref(), Some(trace));
            }
        }
    }
}

/// Why a forward attempt ended: a connection-level failure is retryable on
/// the next server (nginx `proxy_next_upstream error timeout`); anything
/// else aborts the request.
enum ForwardError {
    Retryable(reqwest::Error),
    Fatal(reqwest::Error),
}

/// Everything one upstream attempt needs from the original request —
/// bundled so the retry loop stays readable.
struct HopRequest<'a> {
    parts: &'a axum::http::request::Parts,
    body: &'a [u8],
    is_tls: bool,
    host: Option<&'a str>,
    client_ip: std::net::IpAddr,
}

/// One attempt against one upstream server. The request body is already in
/// memory, so a retryable failure can replay it on the next server.
async fn forward_once(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    hop: &HopRequest<'_>,
    forwarded_headers: bool,
) -> Result<reqwest::Response, ForwardError> {
    let mut fwd = client.request(method, url);
    for (k, v) in hop.parts.headers.iter() {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) {
            continue;
        }
        if forwarded_headers && FORWARDED_STRIP.contains(&name) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            fwd = fwd.header(name, val);
        }
    }
    if let Some(host) = hop.host {
        fwd = fwd.header(header::HOST, host);
    }
    if forwarded_headers {
        let proto = if hop.is_tls { "https" } else { "http" };
        fwd = fwd
            .header("x-forwarded-for", hop.client_ip.to_canonical().to_string())
            .header("x-real-ip", hop.client_ip.to_canonical().to_string())
            .header("x-forwarded-proto", proto);
        if let Some(host) = hop.host {
            fwd = fwd.header("x-forwarded-host", host);
        }
    }
    if !hop.body.is_empty() {
        fwd = fwd.body(hop.body.to_vec());
    }
    match fwd.send().await {
        Ok(resp) => Ok(resp),
        // Connect failures and timeouts are exactly the cases another
        // server can still serve; response-level errors are not retried.
        Err(e) if e.is_connect() || e.is_timeout() => Err(ForwardError::Retryable(e)),
        Err(e) => Err(ForwardError::Fatal(e)),
    }
}

/// Turn an upstream response into the client response: full buffering
/// (default — compression and posture grade the body) or streaming when
/// `response_buffering = false` or the payload is `text/event-stream`.
async fn finalize_upstream_response(
    state: &ProxyState,
    resp: reqwest::Response,
    url: &str,
) -> Response {
    let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let mut out = Response::builder().status(status).extension(UpstreamServed);
    for (k, v) in resp.headers().iter() {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) {
            continue;
        }
        out = out.header(name, v);
    }
    let streaming = !state.response_buffering
        || resp.headers().get(header::CONTENT_TYPE).is_some_and(|v| {
            v.to_str()
                .map(|ct| {
                    ct.split(';')
                        .next()
                        .map(|ct| ct.trim().eq_ignore_ascii_case("text/event-stream"))
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        });
    if streaming {
        return out
            .extension(crate::compression::StreamedResponse)
            .body(axum::body::Body::from_stream(resp.bytes_stream()))
            .unwrap_or_else(|_| {
                let trace = Uuid::new_v4();
                tracing::error!(trace_id = %trace, "edge: streaming response build failed");
                pages::bad_gateway_page(state.runtime.error_pages(), Some(trace))
            });
    }
    match resp.bytes().await {
        Ok(bytes) => out.body(axum::body::Body::from(bytes)).unwrap_or_else(|_| {
            let trace = Uuid::new_v4();
            tracing::error!(trace_id = %trace, "edge: upstream response body build failed");
            pages::bad_gateway_page(state.runtime.error_pages(), Some(trace))
        }),
        Err(_) => {
            let trace = Uuid::new_v4();
            tracing::warn!(trace_id = %trace, url = %url, "edge: upstream response body read failed");
            pages::bad_gateway_page(state.runtime.error_pages(), Some(trace))
        }
    }
}

/// True when the request asks for an h1 protocol upgrade (WebSocket and
/// friends): `Connection: upgrade` + an `Upgrade` token, HTTP/1.1 only —
/// HTTP/2 multiplexes streams instead.
fn is_upgrade_request(parts: &axum::http::request::Parts) -> bool {
    if parts.version != axum::http::Version::HTTP_11 {
        return false;
    }
    let connection = parts
        .headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        });
    connection && parts.headers.contains_key(header::UPGRADE)
}

/// Raw h1 pass-through for upgrade requests (F14): the buffered forward
/// cannot relay a `101 Switching Protocols` (reqwest has no upgrade API and
/// the hop-by-hop strip removes `Connection`/`Upgrade`), so this opens its
/// own h1 connection with a hyper legacy client, answers 101 and pipes both
/// upgraded connections bidirectionally. Upstream TLS is not supported on
/// this path yet (the raw client has no TLS connector) — a 502 explains it.
async fn proxy_upgrade(
    state: &ProxyState,
    group: &crate::upstream::UpstreamGroup,
    parts: &axum::http::request::Parts,
    host: Option<&str>,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response {
    let error_pages = state.runtime.error_pages_handle();
    let bad_gateway = |why: &str| {
        let trace = Uuid::new_v4();
        warn!(vhost = %group.name, why, trace_id = %trace, "edge: upgrade request failed");
        pages::bad_gateway_page(error_pages.as_deref(), Some(trace))
    };
    let Some(client_upgrade) = client_upgrade else {
        return bad_gateway("no client upgrade channel (not an upgradeable connection)");
    };
    if group.is_empty() {
        return bad_gateway("upstream group has no servers");
    }
    let Some(upgrade_protocol) = parts
        .headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return bad_gateway("upgrade request without an Upgrade header");
    };
    if group.url(0).trim_end_matches('/').starts_with("https://") {
        return bad_gateway(
            "WebSocket pass-through does not support https upstreams yet — use http:// behind the edge",
        );
    }

    let path_qs = match parts.uri.query() {
        Some(q) => format!("{}?{q}", parts.uri.path()),
        None => parts.uri.path().to_string(),
    };
    let uri: hyper::Uri = match format!("{}{}", group.url(0).trim_end_matches('/'), path_qs).parse()
    {
        Ok(u) => u,
        Err(e) => return bad_gateway(&format!("upstream URI build failed: {e}")),
    };
    let method: hyper::http::Method = match parts.method.as_str().parse() {
        Ok(m) => m,
        Err(_) => hyper::http::Method::GET,
    };
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .version(hyper::http::Version::HTTP_11);
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) || FORWARDED_STRIP.contains(&name) {
            // `connection`/`upgrade` are re-added explicitly below.
            continue;
        }
        if let Ok(val) = v.to_str() {
            builder = builder.header(name, val);
        }
    }
    builder = builder
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, upgrade_protocol);
    if let Some(host) = host {
        builder = builder.header(header::HOST, host);
    }
    if state.forwarded_headers {
        let proto = if parts.extensions.get::<crate::TlsTerminated>().is_some() {
            "https"
        } else {
            "http"
        };
        builder = builder
            .header("x-forwarded-proto", proto)
            .header("x-forwarded-host", host.unwrap_or(""));
    }
    let request = match builder.body(http_body_util::Full::new(bytes::Bytes::new())) {
        Ok(r) => r,
        Err(e) => return bad_gateway(&format!("upgrade request build failed: {e}")),
    };
    let upstream_resp = match state.upgrade_client.clone().request(request).await {
        Ok(r) => r,
        Err(e) => return bad_gateway(&format!("upstream upgrade failed: {e}")),
    };
    if upstream_resp.status() != hyper::http::StatusCode::SWITCHING_PROTOCOLS {
        // The backend answered normally (e.g. rejected the upgrade): pass
        // the regular response through.
        let status = axum::http::StatusCode::from_u16(upstream_resp.status().as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
        let mut out = Response::builder().status(status).extension(UpstreamServed);
        for (k, v) in upstream_resp.headers().iter() {
            let name = k.as_str();
            if HOP_BY_HOP.contains(&name) {
                continue;
            }
            out = out.header(name, v);
        }
        let bytes = http_body_util::BodyExt::collect(upstream_resp.into_body())
            .await
            .map(|b| b.to_bytes())
            .map_err(|e| {
                warn!(error = %e, "edge: upgrade rejection body read failed");
            })
            .unwrap_or_default();
        return out.body(axum::body::Body::from(bytes)).unwrap_or_else(|_| {
            let trace = Uuid::new_v4();
            pages::bad_gateway_page(error_pages.as_deref(), Some(trace))
        });
    }

    let mut out = Response::builder()
        .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
        .extension(UpstreamServed);
    for (k, v) in upstream_resp.headers().iter() {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) {
            continue;
        }
        out = out.header(name, v);
    }
    // The pipe owns BOTH sides for the whole connection lifetime: dropping
    // the upstream response body early would cancel the connection before
    // the upgrade handoff, so the response moves into the task whole and
    // `hyper::upgrade::on` extracts its upgrade channel there.
    tokio::spawn(async move {
        let (client_io, upstream_io) =
            futures::join!(client_upgrade, hyper::upgrade::on(upstream_resp));
        match (client_io, upstream_io) {
            // hyper 1 upgrades speak `hyper::rt` traits — TokioIo adapts
            // them to tokio's AsyncRead/AsyncWrite for the pipe.
            (Ok(a), Ok(b)) => {
                // hyper 1 upgrades speak `hyper::rt` traits — TokioIo adapts
                // them to tokio's AsyncRead/AsyncWrite for the pipe.
                let mut a = hyper_util::rt::TokioIo::new(a);
                let mut b = hyper_util::rt::TokioIo::new(b);
                let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
            }
            (Err(e), _) | (_, Err(e)) => {
                #[cfg(test)]
                eprintln!("DEBUG pipe: handoff failed: {e}");
                tracing::debug!(error = %e, "edge: upgraded connection handoff failed");
            }
        }
    });
    out.body(axum::body::Body::empty()).unwrap_or_else(|_| {
        let trace = Uuid::new_v4();
        pages::bad_gateway_page(error_pages.as_deref(), Some(trace))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn concurrency_gate_sheds_excess_requests_with_503() {
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let app = Router::new().fallback(any(proxy_handler)).with_state(
            proxy_state(runtime, "http://127.0.0.1:9".to_string(), dec_tx)
                .with_gate(Some(Arc::new(tokio::sync::Semaphore::new(0)))),
        );
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn health_check_fails_fast_on_dead_backend() {
        let cfg = EdgeProxyConfig {
            upstreams: vec!["http://127.0.0.1:9".to_string()],
            health_timeout_secs: 1,
            ..Default::default()
        };
        let err = health_check(&cfg).await.expect_err("dead backend");
        assert!(err.to_string().contains("refusing to start inline"));
    }

    #[tokio::test]
    async fn health_check_needs_one_healthy_server_per_group() {
        // Default group healthy, vhost group dead → the vhost kills startup.
        let cfg = EdgeProxyConfig {
            upstreams: vec!["http://127.0.0.1:9".to_string()],
            health_timeout_secs: 1,
            vhosts: vec![sentry_core::config::EdgeVhostConfig {
                host: "app.example.com".to_string(),
                upstreams: vec!["http://127.0.0.1:9".to_string()],
                balance: None,
                max_fails: None,
                fail_timeout_secs: None,
                health_path: Some("/".to_string()),
                tls_cert: None,
                tls_key: None,
            }],
            ..Default::default()
        };
        let err = health_check(&cfg).await.expect_err("dead vhost");
        assert!(err.to_string().contains("vhost app.example.com"), "{err}");
    }

    #[tokio::test]
    async fn fast_path_denies_blocked_ip_without_upstream() {
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let table = std::sync::Arc::new(sentry_core::BlockTable::new());
        table.block("127.0.0.1".parse().unwrap(), None);
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0).with_block_table(table);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(
                runtime,
                "http://127.0.0.1:9".to_string(),
                dec_tx,
            ));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/anything")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(
            dec_rx.try_recv().is_err(),
            "fast-path denies without a decided event"
        );
    }

    #[tokio::test]
    async fn https_redirect_answers_301_and_keeps_monitoring() {
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new().fallback(any(proxy_handler)).with_state(
            proxy_state(runtime, "http://127.0.0.1:9".to_string(), dec_tx)
                .with_redirect_https(true),
        );
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/some/path?q=1")
                    .header("host", "example.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("https://example.com/some/path?q=1")
        );
        // The redirect runs after the pipeline: port-80 traffic keeps
        // producing decided events (monitoring is preserved).
        assert!(
            dec_rx.try_recv().is_ok(),
            "redirected request was monitored"
        );
    }

    /// Minimal upstream answering 404 to everything (honeypot decoy).
    async fn spawn_404_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(|| async { axum::http::StatusCode::NOT_FOUND });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// Upstream echoing the forwarding headers the edge sent, pipe-separated
    /// (`xff|proto|x-real-ip|x-forwarded-host`), for F12 header tests.
    async fn spawn_forward_echo_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(|headers: axum::http::HeaderMap| async move {
            let pick = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_string()
            };
            (
                axum::http::StatusCode::OK,
                format!(
                    "{}|{}|{}|{}",
                    pick("x-forwarded-for"),
                    pick("x-forwarded-proto"),
                    pick("x-real-ip"),
                    pick("x-forwarded-host")
                ),
            )
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// Large compressible HTML upstream response (clears the 256-byte floor).
    async fn spawn_html_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = "<html><body>".to_string()
            + &"<p>compressible paragraph for the edge encoder test.</p>".repeat(10)
            + "</body></html>";
        let app = Router::new().fallback(move || {
            let body = body.clone();
            async move {
                (
                    axum::http::StatusCode::OK,
                    [("content-type", "text/html; charset=utf-8")],
                    body,
                )
            }
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// Single-upstream state baseline for the proxy tests (F14: wraps the
    /// URL in a one-server `VhostRouter`).
    fn proxy_state(
        runtime: crate::EdgeRuntime,
        upstream: String,
        dec_tx: mpsc::Sender<sentry_core::ProcessedEvent>,
    ) -> ProxyState {
        ProxyState {
            runtime,
            clients: UpstreamClients::verified_only(reqwest::Client::new()),
            router: Arc::new(crate::upstream::VhostRouter::single(upstream)),
            decided: dec_tx,
            redirect_https: false,
            forwarded_headers: true,
            response_buffering: true,
            gate: None,
            failovers: None,
            upgrade_client: default_upgrade_client(),
        }
    }

    fn test_state(
        runtime: crate::EdgeRuntime,
        upstream: String,
        forwarded_headers: bool,
        dec_tx: mpsc::Sender<sentry_core::ProcessedEvent>,
    ) -> (Router, Arc<crate::compression::Compressor>) {
        let compressor = Arc::new(crate::compression::Compressor::new(
            sentry_core::config::EdgeCompressConfig::default(),
            runtime.overload_state(),
            None,
        ));
        let mut state = proxy_state(runtime, upstream, dec_tx);
        state.forwarded_headers = forwarded_headers;
        let app = build_router(state, compressor.clone());
        (app, compressor)
    }

    // ── Response compression (F12) ───────────────────────────────────────

    #[tokio::test]
    async fn proxied_html_is_brotli_compressed_for_capable_clients() {
        let upstream = spawn_html_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let (app, _compressor) = test_state(runtime, format!("http://{upstream}"), true, dec_tx);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("accept-encoding", "gzip, deflate, br")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("br"),
            "production layer compresses the upstream body"
        );
        let vary = resp
            .headers()
            .get(axum::http::header::VARY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(vary.contains("accept-encoding"), "{vary}");
    }

    #[tokio::test]
    async fn clients_without_accept_encoding_get_plain_bytes() {
        let upstream = spawn_html_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let (app, _) = test_state(runtime, format!("http://{upstream}"), true, dec_tx);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.headers().get("content-encoding").is_none());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(bytes.starts_with(b"<html>"), "plain HTML still flows");
    }

    // ── Forwarded headers (F12) ──────────────────────────────────────────

    #[tokio::test]
    async fn forwarded_headers_replace_client_supplied_copies() {
        let upstream = spawn_forward_echo_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        // Empty `[real_ip]` trust set: the direct peer is not a trusted
        // proxy, so header-borne IPs lose and the client IP is the peer —
        // exactly what must land in the upstream's XFF.
        let trust =
            sentry_core::trust::SharedTrustSet::new(
                sentry_core::trust::TrustSet::from_config(
                    &sentry_core::config::RealIpConfig::default(),
                )
                .unwrap(),
            );
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0).with_trust(trust);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let (app, _) = test_state(runtime, format!("http://{upstream}"), true, dec_tx);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("host", "example.com")
                    // Spoofed copy: the edge must replace it with its own view.
                    .header("x-forwarded-for", "198.51.100.66")
                    .header("x-forwarded-proto", "gopher")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        // xff | proto | x-real-ip | x-forwarded-host
        let parts: Vec<&str> = body.split('|').collect();
        assert_eq!(parts.len(), 4, "{body}");
        assert_eq!(
            parts[0], "127.0.0.1",
            "XFF is the edge-resolved peer, not the client's spoof"
        );
        assert_eq!(parts[1], "http", "proto reflects the real scheme");
        assert_eq!(parts[2], "127.0.0.1", "x-real-ip mirrors the client");
        assert_eq!(parts[3], "example.com", "original host preserved");
    }

    #[tokio::test]
    async fn forwarded_headers_off_restores_passthrough() {
        let upstream = spawn_forward_echo_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let (app, _) = test_state(runtime, format!("http://{upstream}"), false, dec_tx);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("host", "example.com")
                    .header("x-forwarded-for", "198.51.100.66")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        let parts: Vec<&str> = body.split('|').collect();
        assert_eq!(parts[0], "198.51.100.66", "client XFF passes through");
        assert_eq!(parts[1], "-", "no edge-set proto");
        assert_eq!(parts[2], "-", "no edge-set x-real-ip");
        assert_eq!(parts[3], "-", "no edge-set forwarded host");
    }

    /// Upstream echoing the `Host` header it received (or `-`).
    async fn spawn_host_echo_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(|headers: axum::http::HeaderMap| async move {
            (
                axum::http::StatusCode::OK,
                headers
                    .get(axum::http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_string(),
            )
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    // ── HTTP/2 `:authority` (no Host header on the wire) ─────────────────

    #[test]
    fn original_host_falls_back_to_uri_authority() {
        let req = axum::http::Request::builder()
            .uri("http://example.com/")
            .header("host", "blog.lucas-romero.com")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(
            original_host(&parts).as_deref(),
            Some("blog.lucas-romero.com"),
            "h1: the Host header wins"
        );

        let req = axum::http::Request::builder()
            .uri("http://blog.lucas-romero.com/")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(
            original_host(&parts).as_deref(),
            Some("blog.lucas-romero.com"),
            "h2: :authority (mapped into the URI) must substitute the absent Host"
        );
    }

    #[tokio::test]
    async fn http2_authority_is_forwarded_as_upstream_host() {
        let upstream = spawn_host_echo_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let (app, _) = test_state(runtime, format!("http://{upstream}"), true, dec_tx);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("http://blog.lucas-romero.com/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "blog.lucas-romero.com",
            "upstream sees the virtual host, not the proxy address"
        );
    }

    // ── Upload inspection (F10) ──────────────────────────────────────────

    fn upload_cfg(enforce: bool, inspect_kb: usize) -> sentry_core::config::UploadsConfig {
        let mut cfg = sentry_core::config::UploadsConfig {
            enabled: true,
            inspect_kb,
            ..Default::default()
        };
        if enforce {
            cfg.mode = sentry_core::config::UploadMode::Enforce;
        }
        cfg
    }

    fn upload_pipeline(
        cfg: &sentry_core::config::UploadsConfig,
    ) -> std::sync::Arc<sentry_core::pipeline::Pipeline> {
        let mut pipeline = sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        );
        pipeline.configure_uploads(cfg);
        std::sync::Arc::new(pipeline)
    }

    fn multipart_form(parts: &[(&str, &str, &str, &[u8])]) -> (String, Vec<u8>) {
        let mut out = Vec::new();
        for (name, filename, ct, content) in parts {
            out.extend_from_slice(b"--SENTRY\r\n");
            out.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {ct}\r\n\r\n"
                )
                .as_bytes(),
            );
            out.extend_from_slice(content);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--SENTRY--\r\n");
        ("multipart/form-data; boundary=SENTRY".to_string(), out)
    }

    async fn upload_request(
        app: Router,
        content_type: &str,
        body: Vec<u8>,
    ) -> axum::http::Response<axum::body::Body> {
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/upload")
                .header("content-type", content_type)
                .header("content-length", body.len().to_string())
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn clean_upload_is_forwarded_with_metadata() {
        let upstream = spawn_404_upstream().await;
        let cfg = upload_cfg(true, 1024);
        let runtime = crate::EdgeRuntime::new(upload_pipeline(&cfg), None, 0).with_uploads(
            crate::UploadsInspection {
                inspect_bytes: cfg.inspect_kb * 1024,
                max_files: 16,
                oversize: sentry_core::config::OversizePolicy::Reject,
            },
        );
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let (ct, body) = multipart_form(&[("f", "cat.png", "image/png", b"\x89PNG\r\n\x1a\nxx")]);
        let resp = upload_request(app, &ct, body).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::NOT_FOUND,
            "forwarded"
        );
        let pe = dec_rx.try_recv().expect("decided event");
        match &pe.event.protocol {
            sentry_core::ProtocolData::Http(h) => {
                let uploads = h.uploads.as_ref().expect("upload metadata on event");
                assert_eq!(uploads.len(), 1);
                assert_eq!(uploads[0].filename.as_deref(), Some("cat.png"));
                assert_eq!(uploads[0].kind, sentry_core::event::UploadKind::Image);
                assert_eq!(h.body, None, "body_capture_kb=0 keeps nothing persisted");
            }
            other => panic!("expected http event, got {other:?}"),
        }
        assert!(
            pe.analysis
                .signals
                .iter()
                .all(|s| s.kind != sentry_core::analysis::SignalKind::UploadTypeMismatch),
            "clean png must stay quiet"
        );
    }

    #[tokio::test]
    async fn polyglot_upload_blocks_in_enforce_mode() {
        let upstream = spawn_404_upstream().await;
        let cfg = upload_cfg(true, 1024);
        let runtime = crate::EdgeRuntime::new(upload_pipeline(&cfg), None, 0).with_uploads(
            crate::UploadsInspection {
                inspect_bytes: cfg.inspect_kb * 1024,
                max_files: 16,
                oversize: sentry_core::config::OversizePolicy::Reject,
            },
        );
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(b"\x00<?php system($_GET['c']); ?>");
        let (ct, body) = multipart_form(&[("f", "avatar.gif", "image/gif", &gif)]);
        let resp = upload_request(app, &ct, body).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::FORBIDDEN,
            "blocked pre-upstream"
        );
        let pe = dec_rx.try_recv().expect("decided event");
        let sig = pe
            .analysis
            .signals
            .iter()
            .find(|s| s.kind == sentry_core::analysis::SignalKind::UploadPolyglot)
            .expect("polyglot signal");
        assert_eq!(sig.weight, 60, "enforce mode carries full weight");
    }

    #[tokio::test]
    async fn polyglot_upload_forwards_in_shadow_mode() {
        let upstream = spawn_404_upstream().await;
        let cfg = upload_cfg(false, 1024);
        let runtime = crate::EdgeRuntime::new(upload_pipeline(&cfg), None, 0).with_uploads(
            crate::UploadsInspection {
                inspect_bytes: cfg.inspect_kb * 1024,
                max_files: 16,
                oversize: sentry_core::config::OversizePolicy::Reject,
            },
        );
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(b"\x00<?php eval($_POST); ?>");
        let (ct, body) = multipart_form(&[("f", "avatar.gif", "image/gif", &gif)]);
        let resp = upload_request(app, &ct, body).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::NOT_FOUND,
            "shadow forwards"
        );
        let pe = dec_rx.try_recv().expect("decided event");
        let sig = pe
            .analysis
            .signals
            .iter()
            .find(|s| s.kind == sentry_core::analysis::SignalKind::UploadPolyglot)
            .expect("shadow still detects");
        assert_eq!(sig.weight, 0, "shadow mode zeroes the weight");
    }

    #[tokio::test]
    async fn oversized_body_rejected_while_uploads_enabled() {
        let cfg = upload_cfg(true, 1);
        let runtime = crate::EdgeRuntime::new(upload_pipeline(&cfg), None, 0).with_uploads(
            crate::UploadsInspection {
                inspect_bytes: 1024,
                max_files: 16,
                oversize: sentry_core::config::OversizePolicy::Reject,
            },
        );
        let (dec_tx, _dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(
                runtime,
                "http://127.0.0.1:9".to_string(),
                dec_tx,
            ));
        let big = vec![0x41u8; 4096];
        let (ct, body) = multipart_form(&[("f", "big.bin", "application/octet-stream", &big)]);
        let resp = upload_request(app, &ct, body).await;
        assert_eq!(resp.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/html; charset=utf-8",
            "413 must render the HTML page, not plaintext"
        );
        assert!(resp.headers().get(pages::TRACE_HEADER).is_some());
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let page = String::from_utf8_lossy(&bytes);
        assert!(page.contains("413 - Payload Too Large"), "{page}");
        assert!(page.contains("Trace ID:"), "{page}");
    }

    #[tokio::test]
    async fn oversize_skip_forwards_uninspected() {
        let upstream = spawn_404_upstream().await;
        let mut cfg = upload_cfg(true, 1);
        cfg.oversize = sentry_core::config::OversizePolicy::Skip;
        let runtime = crate::EdgeRuntime::new(upload_pipeline(&cfg), None, 0).with_uploads(
            crate::UploadsInspection {
                inspect_bytes: cfg.inspect_kb * 1024,
                max_files: 16,
                oversize: cfg.oversize,
            },
        );
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let big = vec![0x41u8; 4096];
        let (ct, body) = multipart_form(&[("f", "big.bin", "application/octet-stream", &big)]);
        let resp = upload_request(app, &ct, body).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::NOT_FOUND,
            "skip forwards the body to the upstream"
        );
        let pe = dec_rx.try_recv().expect("decided event");
        match &pe.event.protocol {
            sentry_core::ProtocolData::Http(h) => {
                assert!(h.uploads.is_none(), "skip attaches no upload metadata");
            }
            other => panic!("expected http event, got {other:?}"),
        }
        assert!(pe
            .analysis
            .signals
            .iter()
            .all(|s| s.kind != sentry_core::analysis::SignalKind::UploadOversize));
    }

    #[tokio::test]
    async fn oversize_flag_signals_and_forwards() {
        let upstream = spawn_404_upstream().await;
        let mut cfg = upload_cfg(true, 1);
        cfg.oversize = sentry_core::config::OversizePolicy::Flag;
        let runtime = crate::EdgeRuntime::new(upload_pipeline(&cfg), None, 0).with_uploads(
            crate::UploadsInspection {
                inspect_bytes: cfg.inspect_kb * 1024,
                max_files: 16,
                oversize: cfg.oversize,
            },
        );
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let big = vec![0x41u8; 4096];
        let (ct, body) = multipart_form(&[("f", "big.bin", "application/octet-stream", &big)]);
        let body_len = body.len() as u64;
        let resp = upload_request(app, &ct, body).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "flag forwards the body but the risk signal escalates the verdict"
        );
        let pe = dec_rx.try_recv().expect("decided event");
        let sig = pe
            .analysis
            .signals
            .iter()
            .find(|s| s.kind == sentry_core::analysis::SignalKind::UploadOversize)
            .expect("oversize signal on the flagged event");
        assert_eq!(sig.weight, 20, "enforce mode carries full weight");
        assert!(sig.detail.as_deref().unwrap().contains("inspected"));
        match &pe.event.protocol {
            sentry_core::ProtocolData::Http(h) => {
                let uploads = h.uploads.as_ref().expect("synthetic metadata on event");
                assert_eq!(uploads.len(), 1);
                assert_eq!(uploads[0].filename, None);
                assert_eq!(
                    uploads[0].size, body_len,
                    "synthetic entry carries the buffered body size"
                );
            }
            other => panic!("expected http event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversize_flag_volume_counts_in_flood_window() {
        let mut cfg = upload_cfg(true, 1);
        cfg.oversize = sentry_core::config::OversizePolicy::Flag;
        cfg.flood.max_uploads = 2;
        let mut pipeline = sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        );
        pipeline.configure_uploads(&cfg);
        pipeline = pipeline.with_upload_tracker(std::sync::Arc::new(std::sync::RwLock::new(
            sentry_core::uploads::UploadTracker::from_config(&cfg),
        )));
        let runtime = crate::EdgeRuntime::new(std::sync::Arc::new(pipeline), None, 0).with_uploads(
            crate::UploadsInspection {
                inspect_bytes: cfg.inspect_kb * 1024,
                max_files: 16,
                oversize: cfg.oversize,
            },
        );
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(
                runtime,
                "http://127.0.0.1:9".to_string(),
                dec_tx,
            ));
        let big = vec![0x41u8; 4096];
        let mut last = None;
        for _ in 0..2 {
            let (ct, body) = multipart_form(&[("f", "big.bin", "application/octet-stream", &big)]);
            let resp = upload_request(app.clone(), &ct, body).await;
            let _ = resp.status();
            last = dec_rx.try_recv().ok();
        }
        let pe = last.expect("second decided event");
        let kinds: Vec<_> = pe.analysis.signals.iter().map(|s| s.kind).collect();
        assert!(
            kinds.contains(&sentry_core::analysis::SignalKind::UploadOversize),
            "flag signal present: {kinds:?}"
        );
        assert!(
            kinds.contains(&sentry_core::analysis::SignalKind::UploadFlood),
            "synthetic entries feed the flood window: {kinds:?}"
        );
    }

    #[tokio::test]
    async fn uploads_inspected_counter_increments() {
        let cfg = upload_cfg(true, 1024);
        let counter = prometheus::Counter::new("uploads_inspected_test", "test").unwrap();
        let runtime = crate::EdgeRuntime::new(upload_pipeline(&cfg), None, 0)
            .with_uploads(crate::UploadsInspection {
                inspect_bytes: cfg.inspect_kb * 1024,
                max_files: 16,
                oversize: sentry_core::config::OversizePolicy::Reject,
            })
            .with_uploads_inspected(counter.clone());
        let (dec_tx, _dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(
                runtime,
                "http://127.0.0.1:9".to_string(),
                dec_tx,
            ));
        let (ct, body) = multipart_form(&[("f", "a.txt", "text/plain", b"hi")]);
        let resp = upload_request(app, &ct, body).await;
        let _ = resp.status();
        assert_eq!(counter.get(), 1.0);
    }

    #[tokio::test]
    async fn decided_events_carry_upstream_status() {
        let upstream = spawn_404_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/some/missing.php")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let pe = dec_rx.try_recv().expect("decided event published");
        match &pe.event.protocol {
            sentry_core::ProtocolData::Http(h) => assert_eq!(h.status, Some(404)),
            other => panic!("expected http event, got {other:?}"),
        }
    }

    // ── Web security posture advisories (F11) ────────────────────────────

    /// Upstream answering 200 with no security headers at all.
    async fn spawn_bare_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(|| async { (axum::http::StatusCode::OK, "ok") });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// Upstream answering 200 with a fully hardened header set.
    async fn spawn_hardened_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let headers = [
            (
                axum::http::HeaderName::from_static("content-security-policy"),
                "default-src 'self'; script-src 'self'; require-trusted-types-for 'script'",
            ),
            (
                axum::http::HeaderName::from_static("strict-transport-security"),
                "max-age=31536000",
            ),
            (
                axum::http::HeaderName::from_static("cross-origin-opener-policy"),
                "same-origin",
            ),
            (
                axum::http::HeaderName::from_static("x-frame-options"),
                "DENY",
            ),
            (
                axum::http::HeaderName::from_static("x-content-type-options"),
                "nosniff",
            ),
            (
                axum::http::HeaderName::from_static("referrer-policy"),
                "no-referrer",
            ),
        ];
        let app = Router::new().fallback(|| async move { (axum::http::StatusCode::OK, headers) });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    fn posture_signals(pe: &sentry_core::ProcessedEvent) -> Vec<&sentry_core::Signal> {
        pe.analysis
            .signals
            .iter()
            .filter(|s| s.kind == sentry_core::SignalKind::PostureAdvisory)
            .collect()
    }

    #[tokio::test]
    async fn bare_upstream_attaches_weight_zero_posture_advisories_once() {
        let upstream = spawn_bare_upstream().await;
        let tracker = std::sync::Arc::new(sentry_core::posture::PostureTracker::new(
            sentry_core::posture::PostureScan::default(),
        ));
        let counter = prometheus::CounterVec::new(
            prometheus::Opts::new("sentry_posture_findings_total", "test"),
            &["check", "host"],
        )
        .unwrap();
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0)
            .with_posture(tracker)
            .with_posture_findings(counter.clone());
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let req = || {
            axum::http::Request::builder()
                .uri("/")
                .header("host", "example.com")
                .body(axum::body::Body::empty())
                .unwrap()
        };

        let resp = app.clone().oneshot(req()).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let pe = dec_rx.try_recv().expect("decided event 1");
        let sigs = posture_signals(&pe);
        assert!(!sigs.is_empty(), "first request carries advisories");
        assert!(sigs.iter().all(|s| s.weight == 0), "advisories are shadow");
        let non_posture: u8 = pe
            .analysis
            .signals
            .iter()
            .filter(|s| s.kind != sentry_core::SignalKind::PostureAdvisory)
            .map(|s| s.weight)
            .sum();
        assert_eq!(
            pe.analysis.risk_score, non_posture,
            "posture adds nothing to the score"
        );
        let csp_hits = counter
            .get_metric_with_label_values(&["csp", "example.com"])
            .unwrap()
            .get();
        assert!(csp_hits >= 1.0, "check-level metric incremented");

        let _ = app.oneshot(req()).await.unwrap();
        let pe2 = dec_rx.try_recv().expect("decided event 2");
        assert!(
            posture_signals(&pe2).is_empty(),
            "deduplicated within the TTL"
        );
    }

    #[tokio::test]
    async fn hardened_upstream_emits_no_posture_advisories() {
        let upstream = spawn_hardened_upstream().await;
        let tracker = std::sync::Arc::new(sentry_core::posture::PostureTracker::new(
            sentry_core::posture::PostureScan::default(),
        ));
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0).with_posture(tracker);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("host", "example.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let pe = dec_rx.try_recv().expect("decided event");
        assert!(posture_signals(&pe).is_empty(), "hardened site is clean");
    }

    #[tokio::test]
    async fn edge_generated_redirect_is_not_graded_for_posture() {
        let tracker = std::sync::Arc::new(sentry_core::posture::PostureTracker::new(
            sentry_core::posture::PostureScan::default(),
        ));
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0).with_posture(tracker);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(8);
        let app = Router::new().fallback(any(proxy_handler)).with_state(
            proxy_state(runtime, "http://127.0.0.1:9".to_string(), dec_tx)
                .with_redirect_https(true),
        );
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("host", "example.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        let pe = dec_rx.try_recv().expect("redirect is monitored");
        assert!(
            posture_signals(&pe).is_empty(),
            "edge-generated 301 has no origin headers to grade"
        );
    }

    #[tokio::test]
    async fn scanner_burst_is_enforced_from_queued_response_signals() {
        let upstream = spawn_404_upstream().await;
        let scan = std::sync::Arc::new(std::sync::RwLock::new(
            sentry_core::scan::ScanTracker::from_config(&sentry_core::config::ScanConfig::default()),
        ));
        let escalation = sentry_core::config::EscalationConfig::default();
        let offender = std::sync::Arc::new(std::sync::RwLock::new(
            sentry_core::offender::OffenderTracker::from_config(&escalation),
        ));
        let pipeline = std::sync::Arc::new(
            sentry_core::pipeline::Pipeline::new(
                sentry_core::RuleSet::default(),
                sentry_core::RouteValidator::new(vec![]),
            )
            .with_scan_tracker(scan)
            .with_offender(offender, escalation),
        );
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, mut dec_rx) = tokio::sync::mpsc::channel(64);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));

        let mut statuses = Vec::new();
        for i in 0..20 {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(format!("/scan{i}.php").as_str())
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            statuses.push(resp.status().as_u16());
        }

        // The scan window fills while the honeypot answers 404; from the 9th
        // request on the queued scan signals enforce (challenge/block pages
        // are both 403) and escalation carries the burst to a hard Block.
        assert_eq!(
            &statuses[..8],
            &[404; 8],
            "honeypot serves the burst while the window fills"
        );
        assert_eq!(statuses[8], 403, "{statuses:?}");
        assert_eq!(statuses.last(), Some(&403), "{statuses:?}");

        // Every decided event carries the response status it displayed.
        let mut saw_404 = false;
        let mut saw_403 = false;
        while let Ok(pe) = dec_rx.try_recv() {
            if let sentry_core::ProtocolData::Http(h) = &pe.event.protocol {
                assert!(h.status.is_some(), "event without response status");
                match h.status {
                    Some(404) => saw_404 = true,
                    Some(403) => saw_403 = true,
                    _ => {}
                }
            }
        }
        assert!(saw_404 && saw_403);
    }

    // ── Multi-upstream: vhost routing, failover, streaming (F14) ────────

    /// Upstream answering every request with a fixed marker body — lets a
    /// test tell which backend actually served the request.
    async fn spawn_marker_upstream(marker: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(move || async move { (axum::http::StatusCode::OK, marker.to_string()) });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// `text/event-stream` upstream — the auto-stream content type.
    async fn spawn_sse_upstream() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(|| async move {
            (
                axum::http::StatusCode::OK,
                [("content-type", "text/event-stream")],
                "data: hello\n\n".to_string(),
            )
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    fn router_with_vhosts(
        default: std::net::SocketAddr,
        entries: Vec<(&'static str, std::net::SocketAddr)>,
    ) -> Arc<crate::upstream::VhostRouter> {
        use sentry_core::config::BalanceMode;
        Arc::new(crate::upstream::VhostRouter::new(
            crate::upstream::UpstreamGroup::new(
                "",
                &[format!("http://{default}")],
                BalanceMode::RoundRobin,
                0,
                30,
            ),
            entries
                .into_iter()
                .map(|(host, addr)| {
                    (
                        host.to_string(),
                        crate::upstream::UpstreamGroup::new(
                            host,
                            &[format!("http://{addr}")],
                            BalanceMode::RoundRobin,
                            0,
                            30,
                        ),
                    )
                })
                .collect(),
        ))
    }

    async fn request_with_host(app: Router, host: &str) -> axum::response::Response {
        app.oneshot(
            axum::http::Request::builder()
                .uri("/")
                .header("host", host)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[tokio::test]
    async fn vhost_routes_by_host_header_with_default_fallback() {
        let default = spawn_marker_upstream("default").await;
        let site_a = spawn_marker_upstream("a").await;
        let site_b = spawn_marker_upstream("b").await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let mut state = proxy_state(runtime, format!("http://{default}"), dec_tx);
        state.router = router_with_vhosts(default, vec![("a.test", site_a), ("*.b.test", site_b)]);
        let app = Router::new().fallback(any(proxy_handler)).with_state(state);

        let resp = request_with_host(app.clone(), "a.test").await;
        assert_eq!(body_string(resp).await, "a");
        let resp = request_with_host(app.clone(), "A.TEST:8443").await;
        assert_eq!(body_string(resp).await, "a", "case and port are normalized");
        let resp = request_with_host(app.clone(), "sub.b.test").await;
        assert_eq!(body_string(resp).await, "b", "wildcard matches subdomains");
        let resp = request_with_host(app.clone(), "b.test").await;
        assert_eq!(
            body_string(resp).await,
            "default",
            "bare domain does not match *.b.test (nginx semantics)"
        );
        let resp = request_with_host(app.clone(), "unknown.test").await;
        assert_eq!(body_string(resp).await, "default");
    }

    #[tokio::test]
    async fn connect_failure_fails_over_to_the_next_server() {
        let healthy = spawn_marker_upstream("healthy").await;
        use sentry_core::config::BalanceMode;
        let router = Arc::new(crate::upstream::VhostRouter::new(
            crate::upstream::UpstreamGroup::new(
                "",
                &[
                    "http://127.0.0.1:9".to_string(),
                    format!("http://{healthy}"),
                ],
                BalanceMode::RoundRobin,
                2,
                30,
            ),
            vec![],
        ));
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let mut state = proxy_state(runtime, "http://127.0.0.1:9".to_string(), dec_tx);
        state.router = router;
        let app = Router::new().fallback(any(proxy_handler)).with_state(state);

        // Round-robin starts on the dead server; the request must still be
        // served by the healthy one.
        for _ in 0..2 {
            let resp = request_with_host(app.clone(), "app.test").await;
            assert_eq!(resp.status(), axum::http::StatusCode::OK);
            assert_eq!(body_string(resp).await, "healthy");
        }
    }

    #[tokio::test]
    async fn exhausted_group_answers_502() {
        use sentry_core::config::BalanceMode;
        let router = Arc::new(crate::upstream::VhostRouter::new(
            crate::upstream::UpstreamGroup::new(
                "",
                &[
                    "http://127.0.0.1:9".to_string(),
                    "http://127.0.0.1:9".to_string(),
                ],
                BalanceMode::RoundRobin,
                2,
                30,
            ),
            vec![],
        ));
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let mut state = proxy_state(runtime, "http://127.0.0.1:9".to_string(), dec_tx);
        state.router = router;
        let app = Router::new().fallback(any(proxy_handler)).with_state(state);
        let resp = request_with_host(app, "app.test").await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn buffering_off_streams_and_skips_compression() {
        let upstream = spawn_html_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let state =
            proxy_state(runtime, format!("http://{upstream}"), dec_tx).with_buffering(false);
        let compressor = Arc::new(crate::compression::Compressor::new(
            sentry_core::config::EdgeCompressConfig::default(),
            None,
            None,
        ));
        let app = build_router(state, compressor);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("host", "app.test")
                    .header("accept-encoding", "gzip")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.extensions()
                .get::<crate::compression::StreamedResponse>()
                .is_some(),
            "buffering off must mark the response as streamed"
        );
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_ENCODING)
                .is_none(),
            "streamed responses skip compression"
        );
    }

    #[tokio::test]
    async fn sse_content_type_streams_even_with_buffering_on() {
        let upstream = spawn_sse_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));
        let resp = request_with_host(app, "app.test").await;
        assert!(
            resp.extensions()
                .get::<crate::compression::StreamedResponse>()
                .is_some(),
            "text/event-stream always streams"
        );
    }

    /// Raw WebSocket-style upstream: answers the h1 upgrade with 101 and
    /// echoes every byte afterwards.
    async fn spawn_raw_ws_upstream() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                head.extend_from_slice(&tmp[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: testproto\r\n\r\n",
            )
            .await
            .unwrap();
            loop {
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&tmp[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn websocket_upgrade_passes_through_bidirectionally() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let upstream = spawn_raw_ws_upstream().await;
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime = crate::EdgeRuntime::new(pipeline, None, 0);
        let (dec_tx, mut dec_rx) = mpsc::channel(8);
        let app = Router::new()
            .fallback(any(proxy_handler))
            .with_state(proxy_state(runtime, format!("http://{upstream}"), dec_tx));

        // A real listener: upgrades need hyper's connection machinery, not
        // tower oneshot.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, app, crate::net::TcpTuning::default()));

        let mut client = tokio::net::TcpStream::connect(edge_addr).await.unwrap();
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: testproto\r\n\r\n",
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            let n = client.read(&mut tmp).await.unwrap();
            head.extend_from_slice(&tmp[..n]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            head.starts_with(b"HTTP/1.1 101"),
            "expected 101 from the pass-through, got: {}",
            String::from_utf8_lossy(&head)
        );
        // Bidirectional echo over the upgraded pipe.
        client.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        // The decided event carries the 101 status.
        let pe = dec_rx.try_recv().expect("decided event");
        if let sentry_core::ProtocolData::Http(h) = &pe.event.protocol {
            assert_eq!(h.status, Some(101));
        } else {
            panic!("expected an http event");
        }
    }
}
