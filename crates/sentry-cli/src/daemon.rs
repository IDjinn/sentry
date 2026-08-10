//! Daemon entrypoint: wires up sources, pipeline, rules, actions.
//!
//! The daemon:
//! 1. Loads config and builds the plugin registry + ruleset
//! 2. Opens geo databases (graceful no-op if absent)
//! 3. Optionally connects to Postgres (storage + hot-reload)
//! 4. Starts all sources (concurrent event streams)
//! 5. Merges streams into one channel (fan-in)
//! 6. For each event: enrich (geo) → dedupe → pipeline → persist → actions
//! 7. Prints colored events to stdout and logs decisions

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sentry_core::challenge::{ChallengeAction, ChallengeProvider, EdgeMode, EdgeOptions};
use sentry_core::config::{ActionKind, SentryConfig};
use sentry_core::event::Event;
use sentry_core::packs::build_default_ruleset;
use sentry_core::pipeline::{Pipeline, RouteValidator};
use sentry_core::ratelimit::{InMemoryRateLimiter, RateLimitBackend};
use sentry_core::registry::RegistryBuilder;
use sentry_core::rules::{shared, RuleSet, SharedRuleSet};
use sentry_core::RiskLevel;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// A challenge action paired with its concrete provider handle (when the
/// provider is built locally — currently only Cloudflare).
struct ChallengeActionWithProvider {
    action: ChallengeAction,
    provider: Option<Arc<sentry_action_cloudflare::CloudflareProvider>>,
}

/// Deduplication cache: prevents processing the same event (by key) within a TTL window.
struct DedupeCache {
    entries: HashMap<String, Instant>,
    ttl: Duration,
}

impl DedupeCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Returns `true` if the key was already seen recently (i.e. should be skipped).
    fn check_and_mark(&mut self, key: &str) -> bool {
        let now = Instant::now();
        self.entries
            .retain(|_, ts| now.duration_since(*ts) < self.ttl);
        if self.entries.contains_key(key) {
            true
        } else {
            self.entries.insert(key.to_string(), now);
            false
        }
    }
}

/// Build the dedup key for an event (IP + path + method).
fn dedup_key(evt: &Event) -> String {
    let path = evt.http().map(|h| h.path.as_str()).unwrap_or("");
    let method = evt
        .http()
        .and_then(|h| h.method)
        .map(|m| format!("{m:?}"))
        .unwrap_or_default();
    format!("{}:{}:{}", evt.client_ip, method, path)
}

/// Run the daemon.
pub async fn run(cfg: SentryConfig) -> color_eyre::Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting sentry daemon"
    );

    // Build the ruleset from configured packs + custom rules.
    let pack_modes: HashMap<String, String> = cfg
        .rules
        .packs
        .iter()
        .map(|p| (p.name.clone(), p.mode.clone()))
        .collect();
    let rules = build_default_ruleset(&pack_modes);
    info!(rule_count = rules.len(), "ruleset built from default packs");

    let shared_rules: SharedRuleSet = shared(rules);

    // Open geo databases (graceful no-op if files absent).
    let geo = match sentry_geo::GeoLookup::open(&cfg.geo.city_db, &cfg.geo.asn_db) {
        Ok(g) => {
            if cfg.geo.city_db.exists() || cfg.geo.asn_db.exists() {
                info!("geo enrichment enabled");
            } else {
                info!(
                    "geo databases not found — enrichment disabled (download GeoLite2 to enable)"
                );
            }
            Some(Arc::new(g))
        }
        Err(e) => {
            warn!(error = %e, "failed to open geo databases — enrichment disabled");
            None
        }
    };

    // Optionally connect to Postgres for persistence + hot-reload.
    let repo = if !cfg.storage.postgres.url.is_empty() {
        match sentry_storage::PgPool::connect(&cfg.storage.postgres).await {
            Ok(pool) => {
                if let Err(e) = sentry_storage::migrations::run(&pool).await {
                    warn!(error = %e, "migration run failed — continuing without migrations");
                }
                let repo = sentry_storage::Repo::new(pool);
                info!("postgres storage connected");

                // Start the LISTEN/NOTIFY hot-reload task.
                let reload_rules = Arc::clone(&shared_rules);
                let reload_pool = repo.pool().clone();
                tokio::spawn(async move {
                    rules_hot_reload(reload_pool, reload_rules).await;
                });

                Some(Arc::new(repo))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "postgres connection failed — running without persistence"
                );
                None
            }
        }
    } else {
        info!("no storage.postgres.url configured — running without persistence");
        None
    };

    // Build route validator: merge config routes with DB-loaded routes.
    let db_routes = if let Some(ref repo) = repo {
        match repo.routes().list().await {
            Ok(rows) => rows,
            Err(e) => {
                warn!(error = %e, "failed to load routes from db — using config only");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let route_validator = RouteValidator::merge(&cfg.routes.known, &db_routes);
    let total_routes = route_validator.routes().count();
    if total_routes == 0 {
        warn!("no routes configured — all paths will generate UnknownRoute signals");
    } else {
        info!(
            total_routes,
            config_routes = cfg.routes.known.len(),
            db_routes = db_routes.len(),
            "routes loaded (config ∪ db)"
        );
    }

    // Build the pipeline with config-driven scorer + verdict policy.
    let policy = sentry_core::VerdictPolicy::from_config(&cfg.policy)
        .map_err(|e| color_eyre::eyre::eyre!("invalid [policy] config: {e}"))?;
    let pipeline = Arc::new(
        Pipeline::with_config(
            Arc::clone(&shared_rules),
            route_validator,
            cfg.scorer.clone(),
            policy,
        )
        .with_rate_limiter(build_rate_limiter(&cfg)?),
    );
    info!(
        weights = cfg.scorer.weights.len(),
        repetition_bonus = cfg.scorer.repetition_bonus,
        rate_backend = cfg.rate_limit.backend.as_str(),
        "pipeline built"
    );

    // Start the routes LISTEN/NOTIFY hot-reload task (only with storage).
    if let Some(ref repo) = repo {
        let reload_pool = repo.pool().clone();
        let reload_pipeline = Arc::clone(&pipeline);
        let config_routes = cfg.routes.known.clone();
        tokio::spawn(async move {
            routes_hot_reload(reload_pool, reload_pipeline, config_routes).await;
        });
    }

    // Build the plugin registry from config.
    let (registry, cf_provider) = build_registry(&cfg)?;

    if registry.source_count() == 0 {
        warn!("no sources configured — daemon will idle. Add [[source]] entries in sentry.toml");
    }

    // Spawn the Cloudflare reaper: periodically lists access rules at the
    // edge, finds the ones Sentry created (notes = "sentry"), and deletes
    // those whose local TTL has expired.
    if let Some(cf) = cf_provider.as_ref() {
        let cf = Arc::clone(cf);
        tokio::spawn(async move {
            cloudflare_reaper(cf).await;
        });
    }

    // Fan-in: merge all source streams into one channel.
    let buffer = cfg.core.channel_buffer.max(256);
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(buffer);

    // Start each source.
    for source in registry.sources() {
        let source = Arc::clone(source);
        let tx = event_tx.clone();
        let geo_clone = geo.as_ref().map(Arc::clone);
        tokio::spawn(async move {
            info!(source = source.name(), "starting source");
            match source.stream().await {
                Ok(mut rx) => {
                    while let Some(raw) = rx.recv().await {
                        let ip = raw
                            .client_ip
                            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                        let mut evt = raw.into_event(ip);
                        if let Some(ref g) = geo_clone {
                            g.enrich(&mut evt);
                        }
                        if tx.try_send(evt).is_err() {
                            warn!(source = source.name(), "event channel full, dropping event");
                        }
                    }
                    info!(source = source.name(), "source stream ended");
                }
                Err(e) => {
                    error!(source = source.name(), error = %e, "source failed to start");
                }
            }
        });
    }
    drop(event_tx);

    // Main processing loop.
    info!("pipeline ready, processing events");
    let mut dedupe = DedupeCache::new(Duration::from_secs(10));
    let mut processed_count: u64 = 0;
    let mut blocked_count: u64 = 0;
    let mut dropped_dupes: u64 = 0;

    let metrics = crate::metrics::Metrics::new();
    if cfg.metrics.enabled {
        let addr: std::net::SocketAddr = format!("{}:{}", cfg.metrics.host, cfg.metrics.port)
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("invalid metrics bind address: {e}"))?;
        let m = metrics.clone();
        tokio::spawn(async move {
            serve_metrics(m, addr).await;
        });
    }

    while let Some(evt) = event_rx.recv().await {
        let key = dedup_key(&evt);
        if dedupe.check_and_mark(&key) {
            dropped_dupes += 1;
            metrics.dedupe_drops.inc();
            continue;
        }

        let start = Instant::now();
        let result = pipeline.process(&evt);
        let duration = start.elapsed();

        print_event(
            &result.event,
            &result.analysis.risk_level,
            &result
                .analysis
                .signals
                .iter()
                .map(|s| format!("{:?}", s.kind))
                .collect::<Vec<_>>(),
        );

        if let Some(ref repo) = repo {
            let signals_json = serde_json::to_value(&result.analysis.signals).unwrap_or_default();
            let repo = Arc::clone(repo);
            let result_clone = result.clone();
            tokio::spawn(async move {
                let events = repo.events();
                if let Err(e) = events
                    .insert(
                        &result_clone.event,
                        result_clone.analysis.risk_score,
                        result_clone.analysis.risk_level,
                        result_clone.decision.action,
                        &signals_json,
                    )
                    .await
                {
                    warn!(error = %e, "failed to persist event");
                }
            });
        }

        for action in registry.actions() {
            if action.applies_to(&result.decision) {
                metrics
                    .actions
                    .with_label_values(&[action.name(), verdict_str(result.decision.action)])
                    .inc();
                if let Err(e) = action.execute(&result.event, &result.decision).await {
                    warn!(action = action.name(), error = %e, "action failed");
                }
            }
        }

        metrics.record_event(result.decision.action, result.analysis.risk_level, duration);

        processed_count += 1;
        if result.decision.action != sentry_core::Verdict::Allow {
            blocked_count += 1;
        }

        if processed_count % 100 == 0 {
            info!(
                processed = processed_count,
                acted_upon = blocked_count,
                dropped_dupes = dropped_dupes,
                "stats"
            );
        }
    }

    info!(
        processed = processed_count,
        "daemon shutting down — source streams exhausted"
    );
    Ok(())
}

/// String label for a verdict (used in Prometheus action labels).
fn verdict_str(v: sentry_core::Verdict) -> &'static str {
    match v {
        sentry_core::Verdict::Allow => "allow",
        sentry_core::Verdict::RateLimit => "rate_limit",
        sentry_core::Verdict::Challenge => "challenge",
        sentry_core::Verdict::Block => "block",
        sentry_core::Verdict::Quarantine => "quarantine",
    }
}

/// Thin wrapper so the daemon can call the metrics server without importing
/// the crate-internal module path in every call site.
async fn serve_metrics(m: crate::metrics::Metrics, addr: std::net::SocketAddr) {
    crate::metrics::serve(m, addr).await;
}

/// Background task: LISTEN for `sentry_rules_changed` notifications and hot-reload the ruleset.
///
/// On each notification, loads the fresh ruleset from Postgres and swaps it
/// into the shared `Arc<RwLock<RuleSet>>`. If the connection drops, it retries
/// with backoff.
async fn rules_hot_reload(pool: sentry_storage::PgPool, rules: SharedRuleSet) {
    const CHANNEL: &str = "sentry_rules_changed";
    loop {
        match pool.listen(CHANNEL).await {
            Ok(mut listener) => {
                info!(channel = CHANNEL, "listening for rule change notifications");
                while let Ok(_notif) = listener.recv().await {
                    let repo = sentry_storage::Repo::new(pool.clone());
                    match repo.rules().load_ruleset().await {
                        Ok(new_ruleset) => {
                            let count = new_ruleset.len();
                            {
                                let mut guard = rules.write().unwrap();
                                *guard = new_ruleset;
                            }
                            info!(rule_count = count, "ruleset hot-reloaded");
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to reload ruleset from db");
                        }
                    }
                }
                warn!("LISTEN connection closed, reconnecting in 5s…");
            }
            Err(e) => {
                warn!(error = %e, "failed to start LISTEN, retrying in 5s…");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Print a colored event line to stdout.
fn print_event(evt: &Event, level: &RiskLevel, signals: &[String]) {
    let color = level.ansi_color();
    let reset = "\x1b[0m";
    let label = level.label();

    let method = evt
        .http()
        .and_then(|h| h.method)
        .map(|m| format!("{m:?}"))
        .unwrap_or_else(|| "???".into());
    let path = evt.http().map(|h| h.path.as_str()).unwrap_or("(non-http)");
    let ip = evt.client_ip;
    let status = evt
        .http()
        .and_then(|h| h.status)
        .map(|s| s.to_string())
        .unwrap_or_else(|| " -".into());

    let signal_str = if signals.is_empty() {
        String::new()
    } else {
        format!(" [{}]", signals.join(","))
    };

    println!("{color}{label:4}{reset} {ip:15} {method:6} {path:40} {status:3}{signal_str}");
}

/// Build the plugin registry from config.
///
/// Returns the registry plus, when a Cloudflare challenge action is
/// configured, a handle to the concrete `CloudflareProvider` (used by the
/// background reaper and the CLI status commands).
fn build_registry(
    cfg: &SentryConfig,
) -> color_eyre::Result<(
    sentry_core::registry::Registry,
    Option<Arc<sentry_action_cloudflare::CloudflareProvider>>,
)> {
    let mut builder = RegistryBuilder::new();
    let mut cf_provider: Option<Arc<sentry_action_cloudflare::CloudflareProvider>> = None;

    for src in &cfg.sources {
        match src.kind.as_str() {
            "nginx" => {
                let path = src
                    .options
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/var/log/nginx/access.log")
                    .to_string();
                let format = src
                    .options
                    .get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or(
                        r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent""#,
                    )
                    .to_string();
                let ns = sentry_source_nginx::NginxSource::new(
                    sentry_source_nginx::NginxSourceConfig {
                        path: path.into(),
                        format,
                        start_from_end: true,
                    },
                )?;
                builder.register_source(ns);
            }
            other => {
                info!(
                    source = other,
                    "source plugin not yet implemented, skipping"
                );
            }
        }
    }

    let mut log_requested = false;
    for act in &cfg.actions {
        match act.kind {
            ActionKind::Log => log_requested = true,
            ActionKind::Blocklist => {
                let ttl = Duration::from_secs(parse_ttl_secs(&act.options, 86400));
                builder.register_action(sentry_action_blocklist::BlocklistAction::new(
                    sentry_action_blocklist::BlocklistActionConfig { ttl },
                ));
            }
            ActionKind::Webhook => {
                let url = act
                    .options
                    .get("url")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| color_eyre::eyre::eyre!("webhook action requires `url`"))?
                    .to_string();
                let timeout = parse_ttl_secs(&act.options, 10);
                let on_levels = act
                    .options
                    .get("on_levels")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .filter_map(parse_risk_level)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| vec![RiskLevel::High, RiskLevel::Critical]);
                builder.register_action(sentry_action_webhook::WebhookAction::new(
                    sentry_action_webhook::WebhookActionConfig {
                        url,
                        on_levels,
                        timeout: Duration::from_secs(timeout),
                    },
                ));
            }
            ActionKind::Cloudflare => {
                if let Some(built) = build_challenge_action("cloudflare", &act.options)? {
                    if cf_provider.is_none() {
                        cf_provider = built.provider;
                    }
                    builder.register_action(built.action);
                }
            }
            ActionKind::Challenge => {
                let provider = act.provider.as_deref().ok_or_else(|| {
                    color_eyre::eyre::eyre!(
                        "challenge action requires `provider` (e.g. provider = \"cloudflare\")"
                    )
                })?;
                if let Some(built) = build_challenge_action(provider, &act.options)? {
                    if cf_provider.is_none() {
                        cf_provider = built.provider;
                    }
                    builder.register_action(built.action);
                }
            }
        }
    }

    if log_requested || cfg.actions.is_empty() {
        builder.register_action(LogAction);
    }

    Ok((builder.build(), cf_provider))
}

fn parse_ttl_secs(opts: &HashMap<String, toml::Value>, default_secs: u64) -> u64 {
    opts.get("ttl_secs")
        .or_else(|| opts.get("timeout_secs"))
        .and_then(|v| v.as_integer())
        .map(|i| i.max(0) as u64)
        .unwrap_or(default_secs)
}

fn parse_edge_mode(opts: &HashMap<String, toml::Value>) -> Option<EdgeMode> {
    let raw = opts.get("mode")?.as_str()?;
    match EdgeMode::parse(raw) {
        Some(m) => Some(m),
        None => {
            warn!(
                mode = raw,
                "invalid challenge `mode` (expected block | js_challenge | managed_challenge | rate_limit), falling back to default"
            );
            None
        }
    }
}

fn build_challenge_action(
    provider_name: &str,
    options: &HashMap<String, toml::Value>,
) -> color_eyre::Result<Option<ChallengeActionWithProvider>> {
    let ttl = Duration::from_secs(parse_ttl_secs(options, 86400));
    let mode = parse_edge_mode(options);
    let opts = EdgeOptions { ttl, mode };

    let (provider, cf_concrete): (
        Arc<dyn ChallengeProvider>,
        Option<Arc<sentry_action_cloudflare::CloudflareProvider>>,
    ) = match provider_name {
        "cloudflare" => {
            let token = std::env::var("SENTRY_CF_TOKEN").unwrap_or_default();
            let zone = std::env::var("SENTRY_CF_ZONE").unwrap_or_default();
            if token.is_empty() || zone.is_empty() {
                warn!(
                    "cloudflare action configured but SENTRY_CF_TOKEN/SENTRY_CF_ZONE env unset — skipping"
                );
                return Ok(None);
            }
            let cf = Arc::new(sentry_action_cloudflare::CloudflareProvider::new(
                sentry_action_cloudflare::CloudflareProviderConfig {
                    token,
                    zone,
                    default_mode: EdgeMode::ManagedChallenge,
                    ttl,
                },
            ));
            (cf.clone(), Some(cf))
        }
        other => {
            return Err(color_eyre::eyre::eyre!(
                "unknown challenge provider `{other}` — known: cloudflare"
            ));
        }
    };

    Ok(Some(ChallengeActionWithProvider {
        action: ChallengeAction::new(provider, opts),
        provider: cf_concrete,
    }))
}

/// Background task: Cloudflare access-rule reaper.
///
/// Periodically lists access rules at the edge that Sentry created
/// (`notes = "sentry"`) and deletes those whose local TTL has expired.
/// This keeps the edge clean — the access-rules API has no TTL of its own,
/// so without reaping Sentry-created rules would accumulate forever.
async fn cloudflare_reaper(cf: Arc<sentry_action_cloudflare::CloudflareProvider>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    interval.tick().await; // skip the immediate tick
    loop {
        interval.tick().await;
        let expired = cf.expired_keys().await;
        if expired.is_empty() {
            continue;
        }
        let rules = match cf.list_access_rules().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "cloudflare reaper: list failed");
                continue;
            }
        };
        let mut reaped = 0u32;
        for rule in rules {
            // Only touch rules Sentry created.
            if rule.notes.as_deref() != Some("sentry") {
                continue;
            }
            let Ok(ip) = rule.configuration.value.parse::<IpAddr>() else {
                continue;
            };
            if expired.contains(&ip) {
                match cf.delete_access_rule(&rule.id).await {
                    Ok(_) => {
                        cf.forget(ip).await;
                        reaped += 1;
                    }
                    Err(e) => {
                        warn!(error = %e, rule_id = %rule.id, "cloudflare reaper: delete failed")
                    }
                }
            }
        }
        if reaped > 0 {
            info!(reaped, "cloudflare reaper: deleted expired access rules");
        }
    }
}

/// Background task: LISTEN for `sentry_routes_changed` notifications and
/// hot-reload the route validator (merging config + DB routes).
async fn routes_hot_reload(
    pool: sentry_storage::PgPool,
    pipeline: Arc<Pipeline>,
    config_routes: Vec<sentry_core::config::RouteDefConfig>,
) {
    const CHANNEL: &str = "sentry_routes_changed";
    loop {
        match pool.listen(CHANNEL).await {
            Ok(mut listener) => {
                info!(
                    channel = CHANNEL,
                    "listening for route change notifications"
                );
                while let Ok(_notif) = listener.recv().await {
                    let repo = sentry_storage::Repo::new(pool.clone());
                    match repo.routes().list().await {
                        Ok(rows) => {
                            let merged = RouteValidator::merge(&config_routes, &rows);
                            let count = merged.routes().count();
                            pipeline.swap_routes(merged);
                            info!(route_count = count, "routes hot-reloaded");
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to reload routes from db");
                        }
                    }
                }
                warn!("routes LISTEN connection closed, reconnecting in 5s…");
            }
            Err(e) => {
                warn!(error = %e, "failed to start routes LISTEN, retrying in 5s…");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Build the rate-limit backend from config.
///
/// For `memory` (default) the returned backend is an `InMemoryRateLimiter`
/// and a background prune task is spawned. For `redis` the CLI must be built
/// with `--features rate-redis`.
fn build_rate_limiter(cfg: &SentryConfig) -> color_eyre::Result<Arc<dyn RateLimitBackend>> {
    match cfg.rate_limit.backend.as_str() {
        "memory" | "" => {
            let limiter = Arc::new(InMemoryRateLimiter::new());
            let prune_handle = Arc::clone(&limiter);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    prune_handle.prune();
                }
            });
            Ok(limiter)
        }
        "redis" => {
            #[cfg(feature = "rate-redis")]
            {
                let limiter =
                    crate::rate_redis::RedisRateLimiter::connect(&cfg.rate_limit.redis_url)?;
                info!(url = %cfg.rate_limit.redis_url, "redis rate-limit backend connected");
                Ok(Arc::new(limiter))
            }
            #[cfg(not(feature = "rate-redis"))]
            {
                Err(color_eyre::eyre::eyre!(
                    "rate_limit.backend = \"redis\" requires building sentry-cli with --features rate-redis"
                ))
            }
        }
        other => Err(color_eyre::eyre::eyre!(
            "unknown rate_limit.backend `{other}` — expected `memory` or `redis`"
        )),
    }
}

fn parse_risk_level(s: &str) -> Option<RiskLevel> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(RiskLevel::Info),
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        "critical" => Some(RiskLevel::Critical),
        _ => None,
    }
}

struct LogAction;

#[async_trait::async_trait]
impl sentry_core::Action for LogAction {
    fn name(&self) -> &'static str {
        "log"
    }

    fn applies_to(&self, _decision: &sentry_core::Decision) -> bool {
        true
    }

    async fn execute(
        &self,
        evt: &Event,
        decision: &sentry_core::Decision,
    ) -> sentry_core::Result<()> {
        if decision.action != sentry_core::Verdict::Allow {
            info!(
                ip = %evt.client_ip,
                action = ?decision.action,
                score = decision.analysis.risk_score,
                "decision executed"
            );
        }
        Ok(())
    }
}

#[allow(dead_code)]
fn _ensure_ruleset_import() -> RuleSet {
    RuleSet::default()
}
