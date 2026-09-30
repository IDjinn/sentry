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

#[cfg(feature = "onnx")]
use sentry_ai::ThreatModel;
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

/// Deduplication cache: prevents processing the same event (by hash) within
/// a TTL window.
struct DedupeCache {
    entries: HashMap<u64, Instant>,
    ttl: Duration,
    last_sweep: Instant,
}

impl DedupeCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            last_sweep: Instant::now(),
        }
    }

    /// Returns `true` if the key was already seen recently (i.e. should be skipped).
    ///
    /// Expired entries are swept at most once per TTL, not per event — the
    /// O(n) `retain` on every check made the cache itself a hot-path cost at
    /// scale (F5). Hit path is allocation-free.
    fn check_and_mark(&mut self, key: u64) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) >= self.ttl {
            self.entries
                .retain(|_, ts| now.duration_since(*ts) < self.ttl);
            self.last_sweep = now;
        }
        match self.entries.get(&key) {
            Some(_) => true,
            None => {
                self.entries.insert(key, now);
                false
            }
        }
    }
}

/// Hash the dedup identity for an event (F5): IP + method + path for HTTP,
/// IP + hash of the raw record otherwise — the same identity the cache used
/// as a `String`, computed without intermediate allocations. Also used as
/// the cross-node `payload_hash` (F4.7), so all nodes must run the same
/// version for consistent dedupe.
fn dedup_hash(evt: &Event) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    evt.client_ip.hash(&mut h);
    match evt.http() {
        Some(http) => {
            "http".hash(&mut h);
            http.method.map(|m| m as u8).hash(&mut h);
            http.path.hash(&mut h);
        }
        None => {
            "raw".hash(&mut h);
            evt.raw.hash(&mut h);
        }
    }
    h.finish()
}

/// Resolve the instance identity for metrics (F4.7): the configured
/// `[deployment] instance_id` when set, otherwise the machine hostname.
fn instance_label(configured: &str) -> String {
    let configured = configured.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(name) = std::env::var(var) {
            let name = name.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    if let Ok(name) = std::fs::read_to_string("/etc/hostname") {
        let name = name.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    "sentry-0".to_string()
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
    let mut rules = build_default_ruleset(&pack_modes);
    // Static inline rules from `[[rules.custom]]` (config source).
    for parsed in sentry_core::rules::rules_from_config(&cfg.rules.custom) {
        match parsed {
            Ok(rule) => rules.extend(std::iter::once(rule)),
            Err(e) => warn!(error = %e, "invalid custom rule — skipped"),
        }
    }
    // Feeds with an `action` get one synthetic enforcement rule each; feeds
    // without one only enrich (the tor/vpn_proxy packs or user rules match
    // on `reputation = …` themselves).
    for feed in cfg.rules.feeds.iter().filter(|f| f.enabled) {
        match sentry_core::reputation::feed_rule(feed) {
            Ok(Some(rule)) => rules.extend(std::iter::once(rule)),
            Ok(None) => {}
            Err(e) => warn!(feed = %feed.name, error = %e, "invalid feed config — skipped"),
        }
    }
    info!(rule_count = rules.len(), "ruleset built from default packs");

    let shared_rules: SharedRuleSet = shared(rules);

    // Reputation feeds (F3.7): fetch once at startup so enrichment is live
    // before the first event, then refresh in the background. A failing
    // feed keeps its previous entries.
    let reputation = if cfg.rules.feeds.iter().any(|f| f.enabled) {
        let svc = Arc::new(sentry_reputation::ReputationService::new(&cfg.rules.feeds));
        tokio::time::timeout(Duration::from_secs(120), svc.refresh_all())
            .await
            .map_err(|_| warn!("reputation feed startup sync timed out — continuing"))
            .ok();
        svc.log_summary().await;
        svc.spawn_refresh_tasks();
        Some(svc)
    } else {
        None
    };

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

    // Behavioral scan tracker (per-IP 4xx windows → RandomScan/ScanBehavior).
    let scan_tracker = cfg.scan.enabled.then(|| {
        Arc::new(std::sync::RwLock::new(
            sentry_core::scan::ScanTracker::from_config(&cfg.scan),
        ))
    });

    // Behavioral attack tracker (auth brute-force / credential stuffing /
    // directory sweeps).
    let behavior_tracker = cfg.behavior.enabled.then(|| {
        Arc::new(std::sync::RwLock::new(
            sentry_core::behavior::BehaviorTracker::from_config(&cfg.behavior),
        ))
    });

    // Repeat-offender memory (strikes → verdict escalation ladder).
    let offender_tracker = cfg.escalation.enabled.then(|| {
        Arc::new(std::sync::RwLock::new(
            sentry_core::offender::OffenderTracker::from_config(&cfg.escalation),
        ))
    });

    let mut pipeline_builder = Pipeline::with_config(
        Arc::clone(&shared_rules),
        route_validator,
        cfg.scorer.clone(),
        policy,
    )
    .with_rate_limiter(build_rate_limiter(&cfg)?);
    if let Some(ref t) = scan_tracker {
        pipeline_builder = pipeline_builder.with_scan_tracker(Arc::clone(t));
    }
    if let Some(ref t) = behavior_tracker {
        pipeline_builder = pipeline_builder.with_behavior_tracker(Arc::clone(t));
    }
    if let Some(ref t) = offender_tracker {
        pipeline_builder = pipeline_builder.with_offender(Arc::clone(t), cfg.escalation.clone());
    }
    let pipeline = Arc::new(pipeline_builder);
    info!(
        weights = cfg.scorer.weights.len(),
        repetition_bonus = cfg.scorer.repetition_bonus,
        rate_backend = cfg.rate_limit.backend.as_str(),
        scan_detection = cfg.scan.enabled,
        behavior_detection = cfg.behavior.enabled,
        escalation = cfg.escalation.enabled,
        "pipeline built"
    );

    // Pre-warm the offender memory from persisted strikes so repeat offenders
    // are escalated immediately after a restart (and after edge-rule TTLs).
    if let (Some(ref tracker), Some(ref repo)) = (&offender_tracker, &repo) {
        if cfg.escalation.persist {
            match repo
                .ip_state()
                .recent_offenders(cfg.escalation.window_secs, 10_000)
                .await
            {
                Ok(rows) => {
                    let now = chrono::Utc::now();
                    let seeded = rows
                        .iter()
                        .filter(|r| {
                            let Some(last) = r.last_violation_at else {
                                return false;
                            };
                            let Ok(elapsed) = (now - last).to_std() else {
                                return false;
                            };
                            let Ok(ip) = r.ip.parse::<IpAddr>() else {
                                return false;
                            };
                            tracker.write().unwrap().seed(
                                ip,
                                r.strikes.max(0) as u32,
                                r.total_violations.max(0) as u64,
                                elapsed,
                            );
                            true
                        })
                        .count();
                    info!(offenders = seeded, "offender memory pre-warmed from db");
                }
                Err(e) => warn!(error = %e, "failed to pre-warm offender memory"),
            }
        }
    }

    // Prune the offender/scan windows periodically.
    if let Some(ref t) = offender_tracker {
        let t = Arc::clone(t);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                t.write().unwrap().prune();
            }
        });
    }
    if let Some(ref t) = scan_tracker {
        let t = Arc::clone(t);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                t.write().unwrap().prune();
            }
        });
    }
    if let Some(ref t) = behavior_tracker {
        let t = Arc::clone(t);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                t.write().unwrap().prune();
            }
        });
    }

    // Start the routes LISTEN/NOTIFY hot-reload task (only with storage).
    if let Some(ref repo) = repo {
        let reload_pool = repo.pool().clone();
        let reload_pipeline = Arc::clone(&pipeline);
        let config_routes = cfg.routes.known.clone();
        tokio::spawn(async move {
            routes_hot_reload(reload_pool, reload_pipeline, config_routes).await;
        });

        // Continuous route learner (auto-push via NOTIFY sentry_routes_changed).
        if cfg.route_learner.enabled {
            let learner_repo = Arc::clone(repo);
            let learner_cfg = cfg.route_learner.clone();
            tokio::spawn(async move {
                route_learner_task(learner_repo, learner_cfg).await;
            });
        }
    }

    // Build the plugin registry from config.
    let (registry, cf_provider) = build_registry(&cfg)?;

    // Local ML threat model: runs as a fork off the hot path (or inline /
    // shadow, per [ai] config) and feeds signals back via rescore_from.
    let ai_fork = build_ai_fork(&cfg);
    if let Some(ref ai) = ai_fork {
        info!(
            model = ai.model().name(),
            mode = ai.mode.as_str(),
            trigger = ai.trigger.as_str(),
            "ai threat model loaded"
        );
        // F3.6: `sentry model reload` notifies `sentry_model_changed`; the
        // daemon swaps the ONNX model in place without a restart.
        #[cfg(feature = "onnx")]
        if let Some(ref repo) = repo {
            let pool = repo.pool().clone();
            let ai_cfg = cfg.ai.clone();
            let reload_fork = Arc::clone(ai);
            tokio::spawn(model_hot_reload(pool, ai_cfg, reload_fork));
        }
    }

    // Remote LLM classifier (Layer 2): escalates suspicious or quarantined
    // events off the hot path, bounded by a semaphore and a verdict cache.
    let llm_fork = build_llm_fork(&cfg);

    if registry.source_count() == 0 {
        warn!("no sources configured — daemon will idle. Add [[source]] entries in sentry.toml");
    }

    // Cloudflare startup reconcile: verifies the token, re-adopts edge rules
    // created by previous runs (re-populating the dedup cache so restarts
    // don't hit CF duplicate-rule errors) and deletes expired ones. Disables
    // the provider when the token/zone is invalid.
    if let Some(cf) = cf_provider.as_ref() {
        let report = cf.reconcile().await;
        info!(
            token_valid = report.token_valid,
            zone = %report.zone,
            sentry_rules = report.sentry_rules,
            adopted = report.adopted,
            restamped = report.restamped,
            deleted = report.deleted,
            list_items = report.list_items,
            list_adopted = report.list_adopted,
            list_deleted = report.list_deleted,
            lists_disabled = report.lists_disabled,
            "cloudflare startup reconcile"
        );
        if cf.is_disabled() {
            warn!("cloudflare action disabled — no edge rules will be applied until restart");
        }
        if report.lists_disabled {
            warn!(
                "cloudflare ipv6 prefix list mode disabled — ipv6 blocks fall back to exact-address access rules (needs Account Filter Lists + Zone Rulesets token permissions)"
            );
        }
    }

    // Spawn the Cloudflare reaper: periodically lists access rules at the
    // edge, finds the ones Sentry created, and deletes those whose encoded
    // TTL has expired.
    if let Some(cf) = cf_provider.as_ref() {
        let cf = Arc::clone(cf);
        tokio::spawn(async move {
            cloudflare_reaper(cf).await;
        });
    }

    // Fan-in: merge all source streams into one channel.
    let buffer = cfg.core.channel_buffer.max(256);
    let (event_tx, mut event_rx) = mpsc::channel::<Incoming>(buffer);

    // Start each source.
    for source in registry.sources() {
        let source = Arc::clone(source);
        let tx = event_tx.clone();
        let geo_clone = geo.as_ref().map(Arc::clone);
        let reputation_clone = reputation.as_ref().map(Arc::clone);
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
                        if let Some(ref r) = reputation_clone {
                            r.enrich(&mut evt);
                        }
                        if tx.try_send(Incoming::Raw(Box::new(evt))).is_err() {
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

    // Inline edge (F3.9): the reverse proxy (and optional TCP front) share
    // this process's pipeline — stateful trackers count once — and hand the
    // already-decided events back through the fan-in for persistence and
    // action dispatch.
    if cfg.deployment.is_inline() {
        if cfg.edge.upstream.is_empty() {
            return Err(color_eyre::eyre::eyre!(
                "[deployment] mode = \"inline\" requires [edge] upstream"
            ));
        }
        let enricher = make_enricher(&geo, &reputation);
        let (dec_tx, mut dec_rx) = mpsc::channel::<sentry_core::ProcessedEvent>(buffer);
        let proxy_cfg = sentry_edge::proxy::EdgeProxyConfig {
            listen: cfg.edge.listen.clone(),
            upstream: cfg.edge.upstream.clone(),
            health_path: cfg.edge.health_path.clone(),
            health_timeout_secs: cfg.edge.health_timeout_secs,
            tls_cert: cfg.edge.tls_cert.clone(),
            tls_key: cfg.edge.tls_key.clone(),
        };
        let runtime = sentry_edge::EdgeRuntime::new(
            Arc::clone(&pipeline),
            enricher.clone(),
            cfg.edge.body_capture_kb.saturating_mul(1024),
        );
        let edge_pipeline = cfg.edge.upstream.clone();
        tokio::spawn(async move {
            if let Err(e) = sentry_edge::proxy::serve(runtime, proxy_cfg, dec_tx).await {
                error!(error = %e, upstream = %edge_pipeline, "edge proxy terminated");
            }
        });
        let pump_tx = event_tx.clone();
        tokio::spawn(async move {
            while let Some(pe) = dec_rx.recv().await {
                if pump_tx.try_send(Incoming::Processed(Box::new(pe))).is_err() {
                    warn!("event channel full, dropping edge event");
                }
            }
        });
        if let (Some(tcp_listen), Some(tcp_upstream)) =
            (cfg.edge.tcp_listen.clone(), cfg.edge.tcp_upstream.clone())
        {
            let tcp_runtime = sentry_edge::EdgeRuntime::new(Arc::clone(&pipeline), enricher, 0);
            let (tcp_dec_tx, mut tcp_dec_rx) = mpsc::channel::<sentry_core::ProcessedEvent>(buffer);
            let tcp_cfg = sentry_edge::tcp_listener::TcpEdgeConfig {
                listen: tcp_listen.clone(),
                upstream: tcp_upstream.clone(),
                connect_timeout_secs: cfg.edge.health_timeout_secs,
            };
            let tcp_log_listen = tcp_listen.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    sentry_edge::tcp_listener::serve_tcp(tcp_runtime, tcp_cfg, tcp_dec_tx).await
                {
                    error!(error = %e, listen = %tcp_log_listen, "edge-tcp terminated");
                }
            });
            let tcp_pump_tx = event_tx.clone();
            tokio::spawn(async move {
                while let Some(pe) = tcp_dec_rx.recv().await {
                    if tcp_pump_tx
                        .try_send(Incoming::Processed(Box::new(pe)))
                        .is_err()
                    {
                        warn!("event channel full, dropping edge-tcp event");
                    }
                }
            });
            info!(listen = %tcp_listen, upstream = %tcp_upstream, "edge-tcp front enabled");
        }
        info!(
            listen = %cfg.edge.listen,
            upstream = %cfg.edge.upstream,
            "inline edge enabled (deployment.mode = inline)"
        );
    }
    drop(event_tx);

    // Main processing loop.
    info!("pipeline ready, processing events");
    let mut dedupe = DedupeCache::new(Duration::from_secs(10));
    let mut processed_count: u64 = 0;
    let mut blocked_count: u64 = 0;
    let mut dropped_dupes: u64 = 0;

    let metrics = crate::metrics::Metrics::new();
    metrics.set_instance(&instance_label(&cfg.deployment.instance_id));
    if cfg.metrics.enabled {
        let addr: std::net::SocketAddr = format!("{}:{}", cfg.metrics.host, cfg.metrics.port)
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("invalid metrics bind address: {e}"))?;
        let m = metrics.clone();
        tokio::spawn(async move {
            serve_metrics(m, addr).await;
        });
    }

    // Mirror feed status into Prometheus gauges (entries / last refresh /
    // up=1|0) by polling the service; the fetcher itself stays metrics-free.
    if let Some(svc) = reputation.as_ref() {
        let svc = Arc::clone(svc);
        let m = metrics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                for (name, st) in svc.statuses().await {
                    m.feed_entries
                        .with_label_values(&[&name])
                        .set(st.entries as f64);
                    m.feed_up
                        .with_label_values(&[&name])
                        .set(u8::from(st.last_error.is_none()) as f64);
                    if let Some(ts) = st.last_refresh {
                        m.feed_refresh_ts
                            .with_label_values(&[&name])
                            .set(ts.timestamp() as f64);
                    }
                }
            }
        });
    }

    // Batched ingest (F5): `recv_many` drains up to 64 ready events per
    // wakeup, amortizing task/lock overhead under burst; under trickle load
    // it behaves exactly like `recv` (returns as soon as one event arrives).
    let mut batch: Vec<Incoming> = Vec::with_capacity(64);
    loop {
        let n = event_rx.recv_many(&mut batch, 64).await;
        if n == 0 {
            break; // channel closed
        }
        for incoming in batch.drain(..) {
            let start = Instant::now();
            let mut result = match incoming {
                Incoming::Raw(evt) => {
                    let evt = *evt;
                    let key = dedup_hash(&evt);
                    if dedupe.check_and_mark(key) {
                        dropped_dupes += 1;
                        metrics.dedupe_drops.inc();
                        continue;
                    }
                    pipeline.process(&evt)
                }
                // Edge decisions are final: persist + dispatch actions only.
                Incoming::Processed(pe) => *pe,
            };
            let duration = start.elapsed();

            // Inline AI mode: block before persistence/actions so the stored
            // verdict and the dispatched actions already include the model's say.
            if let Some(ref ai) = ai_fork {
                if ai.is_inline() && ai.should_run(&result) {
                    let signals = ai.evaluate(&result.event).await;
                    if !signals.is_empty() {
                        let updated = pipeline.rescore_from(&result, signals);
                        if updated.decision.action != result.decision.action {
                            info!(
                                ip = %result.event.client_ip,
                                from = ?result.decision.action,
                                to = ?updated.decision.action,
                                score = updated.analysis.risk_score,
                                "ai (inline) changed verdict"
                            );
                        }
                        result = updated;
                    }
                }
            }

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
                let signals_json =
                    serde_json::to_value(&result.analysis.signals).unwrap_or_default();
                let repo = Arc::clone(repo);
                let result_clone = result.clone();
                tokio::spawn(async move {
                    let events = repo.events();
                    if let Err(e) = events
                        .insert_with_hash(
                            &result_clone.event,
                            result_clone.analysis.risk_score,
                            result_clone.analysis.risk_level,
                            result_clone.decision.action,
                            &signals_json,
                            Some(dedup_hash(&result_clone.event) as i64),
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
                    let ctx = incident_context(&repo, &result).await;
                    if let Err(e) = action
                        .execute_with_context(&result.event, &result.decision, &ctx)
                        .await
                    {
                        warn!(action = action.name(), error = %e, "action failed");
                    }
                }
            }

            metrics.record_event(result.decision.action, result.analysis.risk_level, duration);

            // Fork AI mode: evaluate off the hot path; a changed verdict updates
            // the persisted event and re-dispatches actions.
            if let Some(ref ai) = ai_fork {
                if !ai.is_inline() && ai.should_run(&result) {
                    ai.spawn_fork(
                        result.clone(),
                        Arc::clone(&pipeline),
                        registry.clone(),
                        repo.clone(),
                    );
                }
            }

            // LLM fork (Layer 2): same contract as the AI fork, but the verdict
            // comes from the configured remote provider.
            if let Some(ref llm) = llm_fork {
                if llm.should_run(&result) {
                    llm.spawn_fork(
                        result.clone(),
                        Arc::clone(&pipeline),
                        registry.clone(),
                        repo.clone(),
                    );
                }
            }

            // Mirror offender strikes to Postgres and log escalations.
            if result.decision.action != sentry_core::Verdict::Allow {
                if let Some(ref offender) = offender_tracker {
                    let strikes = offender.read().unwrap().strikes(result.event.client_ip);
                    if let (Some(ref repo), true) = (&repo, cfg.escalation.persist) {
                        let repo = Arc::clone(repo);
                        let ip = result.event.client_ip;
                        let window = cfg.escalation.window_secs;
                        tokio::spawn(async move {
                            if let Err(e) = repo.ip_state().record_violation(ip, window).await {
                                warn!(error = %e, "failed to persist offender strike");
                            }
                        });
                    }
                    if result
                        .decision
                        .override_reason
                        .as_deref()
                        .is_some_and(|r| r.starts_with("offender escalation"))
                    {
                        info!(
                            ip = %result.event.client_ip,
                            strikes,
                            verdict = ?result.decision.action,
                            "verdict escalated (repeat offender)"
                        );
                    }
                }
            }

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

/// Fan-in item: a fresh event from a source, or an already-decided event
/// from the inline edge (the pipeline ran inside the edge process — shared
/// Arc — so it must not run again).
enum Incoming {
    Raw(Box<Event>),
    Processed(Box<sentry_core::ProcessedEvent>),
}

/// Combined geo + reputation enrichment hook for the inline edge.
fn make_enricher(
    geo: &Option<Arc<sentry_geo::GeoLookup>>,
    reputation: &Option<Arc<sentry_reputation::ReputationService>>,
) -> Option<sentry_edge::Enricher> {
    if geo.is_none() && reputation.is_none() {
        return None;
    }
    let geo = geo.clone();
    let reputation = reputation.clone();
    Some(Arc::new(move |evt: &mut Event| {
        if let Some(ref g) = geo {
            g.enrich(evt);
        }
        if let Some(ref r) = reputation {
            r.enrich(evt);
        }
    }))
}

/// Resolve the incident for a High/Critical event (F4.5).
///
/// Reuses an incident already open for the IP so bursts coalesce into one
/// ticket; otherwise creates one keyed by event id (idempotent on replay).
/// Returns an empty context for lower levels or without storage.
async fn incident_context(
    repo: &Option<Arc<sentry_storage::Repo>>,
    result: &sentry_core::ProcessedEvent,
) -> sentry_core::ActionContext {
    let mut ctx = sentry_core::ActionContext::default();
    let Some(repo) = repo else {
        return ctx;
    };
    if !matches!(
        result.analysis.risk_level,
        sentry_core::RiskLevel::High | sentry_core::RiskLevel::Critical
    ) {
        return ctx;
    }
    match repo
        .incidents()
        .open_incident_for_ip(result.event.client_ip)
        .await
    {
        Ok(Some(id)) => ctx.incident_id = Some(id),
        Ok(None) => {
            match repo
                .incidents()
                .get_or_create_for_event(
                    result.event.id,
                    result.event.client_ip,
                    result.analysis.risk_level,
                    result.decision.action,
                    None,
                )
                .await
            {
                Ok(id) => ctx.incident_id = Some(id),
                Err(e) => warn!(error = %e, "failed to create incident"),
            }
        }
        Err(e) => warn!(error = %e, "failed to look up open incident"),
    }
    ctx
}

/// Cached model verdict keyed by payload hash: (inserted_at, signals).
type AiCache = Arc<std::sync::RwLock<HashMap<u64, (Instant, Vec<sentry_core::Signal>)>>>;

/// Cache key shared by the AI and LLM fork stages: client identity plus the
/// HTTP payload shape (path/query/UA).
fn payload_hash(evt: &Event) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    evt.client_ip.hash(&mut hasher);
    if let Some(http) = evt.http() {
        http.path.hash(&mut hasher);
        http.query.hash(&mut hasher);
        http.user_agent.hash(&mut hasher);
    }
    hasher.finish()
}

/// Local ML threat model running beside the hot path.
///
/// The hot path (rules → heuristics → routes → scan → score → policy →
/// escalation) stays synchronous; the model runs off to the side and only
/// feeds back through [`Pipeline::rescore_from`], which can raise (never
/// lower) the risk score. Modes:
///
/// - `fork` (default): async, non-blocking, bounded by a semaphore;
/// - `inline`: awaited before persistence/actions;
/// - `shadow`: evaluates and logs, never acts.
struct AiFork {
    /// Loaded model, swappable at runtime via `NOTIFY sentry_model_changed`
    /// (F3.6 retraining loop: `sentry model reload`).
    model: Arc<std::sync::RwLock<Arc<dyn sentry_ai::ThreatModel>>>,
    mode: String,
    trigger: String,
    min_score: u8,
    cache_ttl: Duration,
    semaphore: Arc<tokio::sync::Semaphore>,
    cache: AiCache,
}

impl AiFork {
    fn model(&self) -> Arc<dyn sentry_ai::ThreatModel> {
        self.model.read().unwrap().clone()
    }

    #[cfg(feature = "onnx")]
    fn swap_model(&self, model: Arc<dyn sentry_ai::ThreatModel>) {
        *self.model.write().unwrap() = model;
    }

    fn is_inline(&self) -> bool {
        self.mode == "inline"
    }

    /// Whether the hot-path result should be evaluated by the model.
    fn should_run(&self, r: &sentry_core::ProcessedEvent) -> bool {
        match self.trigger.as_str() {
            "always" => true,
            "quarantine_only" => r.decision.action == sentry_core::Verdict::Quarantine,
            // "above_score" (default)
            _ => r.analysis.risk_score >= self.min_score,
        }
    }

    fn payload_hash(evt: &Event) -> u64 {
        payload_hash(evt)
    }

    /// Evaluate the model with a TTL cache keyed by payload hash.
    async fn evaluate(&self, evt: &Event) -> Vec<sentry_core::Signal> {
        let key = Self::payload_hash(evt);
        if let Some((ts, cached)) = self.cache.read().unwrap().get(&key) {
            if ts.elapsed() < self.cache_ttl {
                return cached.clone();
            }
        }
        let _permit = self.semaphore.acquire().await;
        match self.model().analyze(evt).await {
            Ok(signals) => {
                let mut cache = self.cache.write().unwrap();
                cache.retain(|_, (ts, _)| ts.elapsed() < self.cache_ttl);
                cache.insert(key, (Instant::now(), signals.clone()));
                signals
            }
            Err(e) => {
                warn!(error = %e, "ai threat model inference failed");
                Vec::new()
            }
        }
    }

    /// Spawn the fork evaluation for a processed event.
    fn spawn_fork(
        self: &Arc<Self>,
        base: sentry_core::ProcessedEvent,
        pipeline: Arc<Pipeline>,
        registry: sentry_core::registry::Registry,
        repo: Option<Arc<sentry_storage::Repo>>,
    ) {
        let fork = Arc::clone(self);
        tokio::spawn(async move {
            let signals = fork.evaluate(&base.event).await;
            if signals.is_empty() {
                return;
            }
            let updated = pipeline.rescore_from(&base, signals);
            if updated.decision.action == base.decision.action {
                return;
            }
            let ip = base.event.client_ip;
            if fork.mode == "shadow" {
                info!(
                    ip = %ip,
                    would = ?updated.decision.action,
                    score = updated.analysis.risk_score,
                    "ai (shadow) would change verdict"
                );
                return;
            }
            info!(
                ip = %ip,
                from = ?base.decision.action,
                to = ?updated.decision.action,
                score = updated.analysis.risk_score,
                "ai fork changed verdict"
            );
            if let Some(ref repo) = repo {
                if let Err(e) = repo
                    .events()
                    .update_verdict(
                        base.event.id,
                        updated.decision.action,
                        updated.analysis.risk_score,
                        updated.analysis.risk_level,
                    )
                    .await
                {
                    warn!(error = %e, "ai fork: failed to update event verdict");
                }
            }
            for action in registry.actions() {
                if action.applies_to(&updated.decision) {
                    let ctx = incident_context(&repo, &updated).await;
                    if let Err(e) = action
                        .execute_with_context(&updated.event, &updated.decision, &ctx)
                        .await
                    {
                        warn!(action = action.name(), error = %e, "ai fork action failed");
                    }
                }
            }
        });
    }
}

/// Build the AI fork from config when `[ai] enabled = true`.
fn build_ai_fork(cfg: &SentryConfig) -> Option<Arc<AiFork>> {
    if !cfg.ai.enabled {
        return None;
    }
    #[cfg(feature = "onnx")]
    {
        let model = match sentry_ai::onnx_model::OnnxThreatModel::load(
            &cfg.ai.model_path,
            sentry_ai::onnx_model::OnnxThreatModelConfig {
                threshold: cfg.ai.threshold,
                signal_weight: cfg.ai.signal_weight,
            },
        ) {
            Ok(m) => {
                info!(model = m.name(), describe = %m.describe(), "onnx model loaded");
                Arc::new(m) as Arc<dyn sentry_ai::ThreatModel>
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %cfg.ai.model_path.display(),
                    "failed to load ai model — ai stage disabled for this run"
                );
                return None;
            }
        };
        Some(Arc::new(AiFork {
            model: Arc::new(std::sync::RwLock::new(
                model as Arc<dyn sentry_ai::ThreatModel>,
            )),
            mode: cfg.ai.mode.clone(),
            trigger: cfg.ai.trigger.clone(),
            min_score: cfg.ai.min_score,
            cache_ttl: Duration::from_secs(cfg.ai.cache_ttl_secs),
            semaphore: Arc::new(tokio::sync::Semaphore::new(cfg.ai.concurrency.max(1))),
            cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }))
    }
    #[cfg(not(feature = "onnx"))]
    {
        warn!("ai.enabled = true but sentry-cli was built without --features onnx — ai stage disabled");
        None
    }
}

/// Remote LLM classifier running beside the hot path (Layer 2).
///
/// Mirrors [`AiFork`] but calls the configured [`sentry_ai::LlmProvider`].
/// Only suspicious or quarantined events are escalated (cost control), and
/// verdicts re-enter through [`Pipeline::rescore_from`], which can only
/// raise the risk score. `shadow` mode logs what the LLM would decide
/// without ever acting.
struct LlmFork {
    provider: Arc<dyn sentry_ai::LlmProvider>,
    mode: String,
    only_above: u8,
    cache_ttl: Duration,
    semaphore: Arc<tokio::sync::Semaphore>,
    cache: AiCache,
}

impl LlmFork {
    /// Whether the hot-path result should be escalated to the LLM.
    fn should_run(&self, r: &sentry_core::ProcessedEvent) -> bool {
        r.decision.action == sentry_core::Verdict::Quarantine
            || r.analysis.risk_score >= self.only_above
    }

    /// Classify the event with a TTL cache keyed by payload hash.
    async fn evaluate(&self, evt: &Event) -> Vec<sentry_core::Signal> {
        let key = payload_hash(evt);
        if let Some((ts, cached)) = self.cache.read().unwrap().get(&key) {
            if ts.elapsed() < self.cache_ttl {
                return cached.clone();
            }
        }
        let _permit = self.semaphore.acquire().await;
        let req = sentry_ai::ClassifyRequest {
            protocol: evt.protocol.clone(),
            context: sentry_ai::llm::prompt::context_from_event(evt),
            schema: sentry_ai::llm::prompt::classify_schema(),
        };
        match self.provider.classify(req).await {
            Ok(resp) => {
                let signals = llm_signals(&resp);
                let mut cache = self.cache.write().unwrap();
                cache.retain(|_, (ts, _)| ts.elapsed() < self.cache_ttl);
                cache.insert(key, (Instant::now(), signals.clone()));
                signals
            }
            Err(e) => {
                warn!(
                    error = %e,
                    provider = self.provider.name(),
                    "llm classify failed"
                );
                Vec::new()
            }
        }
    }

    /// Spawn the fork evaluation for a processed event.
    fn spawn_fork(
        self: &Arc<Self>,
        base: sentry_core::ProcessedEvent,
        pipeline: Arc<Pipeline>,
        registry: sentry_core::registry::Registry,
        repo: Option<Arc<sentry_storage::Repo>>,
    ) {
        let fork = Arc::clone(self);
        tokio::spawn(async move {
            let signals = fork.evaluate(&base.event).await;
            if signals.is_empty() {
                return;
            }
            let updated = pipeline.rescore_from(&base, signals);
            if updated.decision.action == base.decision.action {
                return;
            }
            let ip = base.event.client_ip;
            if fork.mode == "shadow" {
                info!(
                    ip = %ip,
                    would = ?updated.decision.action,
                    score = updated.analysis.risk_score,
                    "llm (shadow) would change verdict"
                );
                return;
            }
            info!(
                ip = %ip,
                from = ?base.decision.action,
                to = ?updated.decision.action,
                score = updated.analysis.risk_score,
                "llm fork changed verdict"
            );
            if let Some(ref repo) = repo {
                if let Err(e) = repo
                    .events()
                    .update_verdict(
                        base.event.id,
                        updated.decision.action,
                        updated.analysis.risk_score,
                        updated.analysis.risk_level,
                    )
                    .await
                {
                    warn!(error = %e, "llm fork: failed to update event verdict");
                }
            }
            for action in registry.actions() {
                if action.applies_to(&updated.decision) {
                    let ctx = incident_context(&repo, &updated).await;
                    if let Err(e) = action
                        .execute_with_context(&updated.event, &updated.decision, &ctx)
                        .await
                    {
                        warn!(action = action.name(), error = %e, "llm fork action failed");
                    }
                }
            }
        });
    }
}

/// Map an LLM classification to pipeline signals.
///
/// Benign answers produce no signal (the fork can only raise risk, so a
/// zero-weight signal would be noise); malicious ones emit `LlmMalicious`
/// weighted by `risk_score * confidence`.
fn llm_signals(resp: &sentry_ai::ClassifyResponse) -> Vec<sentry_core::Signal> {
    let benign = resp.verdict == sentry_core::Verdict::Allow && resp.risk_score < 20;
    if benign {
        return Vec::new();
    }
    let confidence = resp.confidence.clamp(0.0, 1.0);
    let weight = (resp.risk_score as f32 * confidence).round() as u8;
    if weight == 0 {
        return Vec::new();
    }
    let detail = resp
        .explanation
        .clone()
        .or_else(|| (!resp.signals.is_empty()).then(|| resp.signals.join(", ")));
    vec![sentry_core::Signal {
        kind: sentry_core::SignalKind::LlmMalicious,
        weight,
        detail,
    }]
}

/// Build the LLM fork from `[llm]` config when `provider != "none"`.
fn build_llm_fork(cfg: &SentryConfig) -> Option<Arc<LlmFork>> {
    if cfg.llm.provider.is_empty() || cfg.llm.provider == "none" {
        return None;
    }
    let provider: Arc<dyn sentry_ai::LlmProvider> = match cfg.llm.provider.as_str() {
        "openrouter" => {
            let key = std::env::var("SENTRY_LLM_KEY").unwrap_or_default();
            if key.is_empty() {
                warn!("llm.provider = \"openrouter\" but SENTRY_LLM_KEY env unset — llm stage disabled for this run");
                return None;
            }
            Arc::new(sentry_ai::OpenRouterProvider::new(
                sentry_ai::llm::openrouter::OpenRouterConfig {
                    api_key: key,
                    model: non_empty_or(&cfg.llm.model, "openai/gpt-4o-mini"),
                    base_url: non_empty_or(
                        cfg.llm.base_url.as_deref().unwrap_or(""),
                        sentry_ai::llm::openrouter::DEFAULT_BASE_URL,
                    ),
                },
            ))
        }
        "ollama" => Arc::new(sentry_ai::OllamaProvider::new(
            sentry_ai::llm::ollama::OllamaConfig {
                model: non_empty_or(&cfg.llm.model, "llama3.1"),
                base_url: non_empty_or(
                    cfg.llm.base_url.as_deref().unwrap_or(""),
                    sentry_ai::llm::ollama::DEFAULT_BASE_URL,
                ),
            },
        )),
        "mock" => Arc::new(sentry_ai::MockLlmProvider::default()),
        other => {
            warn!(
                provider = other,
                "unknown llm.provider — known: openrouter | ollama | mock"
            );
            return None;
        }
    };
    let mode = match cfg.llm.mode.as_str() {
        "shadow" => "shadow",
        _ => "fork",
    };
    info!(
        provider = provider.name(),
        model = provider.model_id(),
        mode,
        only_above = cfg.llm.only_above,
        "llm provider loaded"
    );
    Some(Arc::new(LlmFork {
        provider,
        mode: mode.to_string(),
        only_above: cfg.llm.only_above,
        cache_ttl: Duration::from_secs(cfg.llm.cache_ttl_secs),
        semaphore: Arc::new(tokio::sync::Semaphore::new(cfg.llm.concurrency.max(1))),
        cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
    }))
}

fn non_empty_or(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.trim().to_string()
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

/// F3.6 retraining loop endpoint: on `NOTIFY sentry_model_changed`, reload
/// the ONNX model from disk and swap it into the running fork. A failed load
/// keeps the previous model running.
#[cfg(feature = "onnx")]
async fn model_hot_reload(
    pool: sentry_storage::PgPool,
    ai_cfg: sentry_core::config::AiConfig,
    fork: Arc<AiFork>,
) {
    const CHANNEL: &str = "sentry_model_changed";
    loop {
        match pool.listen(CHANNEL).await {
            Ok(mut listener) => {
                info!(
                    channel = CHANNEL,
                    "listening for model change notifications"
                );
                while listener.recv().await.is_ok() {
                    match sentry_ai::onnx_model::OnnxThreatModel::load(
                        &ai_cfg.model_path,
                        sentry_ai::onnx_model::OnnxThreatModelConfig {
                            threshold: ai_cfg.threshold,
                            signal_weight: ai_cfg.signal_weight,
                        },
                    ) {
                        Ok(m) => {
                            fork.swap_model(Arc::new(m));
                            info!(
                                path = %ai_cfg.model_path.display(),
                                "onnx model hot-reloaded"
                            );
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                path = %ai_cfg.model_path.display(),
                                "model reload failed — keeping previous model"
                            );
                        }
                    }
                }
                warn!("LISTEN connection closed, reconnecting in 5s…");
            }
            Err(e) => {
                warn!(error = %e, "failed to start model LISTEN, retrying in 5s…");
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
            "syslog" => {
                let bind = src
                    .options
                    .get("bind")
                    .and_then(|v| v.as_str())
                    .unwrap_or(sentry_source_syslog::DEFAULT_BIND)
                    .to_string();
                let transport = src
                    .options
                    .get("transport")
                    .and_then(|v| v.as_str())
                    .unwrap_or("udp");
                let transport: sentry_source_syslog::SyslogTransport = transport
                    .parse()
                    .map_err(|e| color_eyre::eyre::eyre!("source `syslog`: {e}"))?;
                let ss = sentry_source_syslog::SyslogSource::new(
                    sentry_source_syslog::SyslogSourceConfig {
                        bind_addr: bind,
                        transport,
                    },
                )?;
                builder.register_source(ss);
            }
            "cloudflare" => {
                let zone_id = src
                    .options
                    .get("zone_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        color_eyre::eyre::eyre!("source `cloudflare` requires `zone_id`")
                    })?;
                let token_env = src
                    .options
                    .get("token_env")
                    .and_then(|v| v.as_str())
                    .unwrap_or("SENTRY_CF_TOKEN")
                    .to_string();
                let api_token = std::env::var(&token_env).unwrap_or_default();
                let poll_secs = parse_ttl_secs(&src.options, 30);
                let start_at = src
                    .options
                    .get("start")
                    .and_then(|v| v.as_str())
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&chrono::Utc));
                let cfs = sentry_source_cloudflare::CloudflareSource::new(
                    sentry_source_cloudflare::CloudflareSourceConfig {
                        zone_id,
                        api_token,
                        poll_secs,
                        start_at,
                        api_base: src
                            .options
                            .get("api_base")
                            .and_then(|v| v.as_str())
                            .unwrap_or("https://api.cloudflare.com/client/v4")
                            .to_string(),
                    },
                )?;
                builder.register_source(cfs);
            }
            "tcp" => {
                let interface = src
                    .options
                    .get("interface")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| color_eyre::eyre::eyre!("source `tcp` requires `interface`"))?;
                let ports = src
                    .options
                    .get("ports")
                    .and_then(|v| v.as_str())
                    .map(|csv| {
                        csv.split(',')
                            .filter_map(|p| p.trim().parse::<u16>().ok())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let payload_cap = parse_ttl_secs(&src.options, 8192) as usize;
                let flow_cap = parse_ttl_secs(&src.options, 65_536) as usize;
                let ts =
                    sentry_source_tcp::TcpCaptureSource::new(sentry_source_tcp::TcpSourceConfig {
                        interface,
                        ports,
                        payload_cap,
                        flow_cap,
                    })?;
                builder.register_source(ts);
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
                let secret_env = act
                    .options
                    .get("secret_env")
                    .and_then(|v| v.as_str())
                    .unwrap_or("SENTRY_WEBHOOK_SECRET")
                    .to_string();
                let secret = std::env::var(&secret_env)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                builder.register_action(sentry_action_webhook::WebhookAction::new(
                    sentry_action_webhook::WebhookActionConfig {
                        url,
                        on_levels,
                        timeout: Duration::from_secs(timeout),
                        secret,
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

fn parse_max_failures(opts: &HashMap<String, toml::Value>) -> u32 {
    match opts
        .get("max_failures")
        .and_then(|v| v.as_integer())
        .and_then(|i| u32::try_from(i).ok())
    {
        Some(n) if n > 0 => n,
        _ => 3,
    }
}

/// Parse the opt-in `ipv6_prefix` option (F2.14): block/rate-limit verdicts
/// for IPv6 clients go to a /<prefix> Cloudflare IP List item instead of an
/// exact /128 access rule. 128 (exact) is the default and disables it.
fn parse_ipv6_prefix(opts: &HashMap<String, toml::Value>) -> Option<u8> {
    let raw = opts.get("ipv6_prefix")?.as_integer()?;
    match u8::try_from(raw) {
        Ok(p) if (1..128).contains(&p) => Some(p),
        Ok(128) => None,
        _ => {
            warn!(raw, "invalid ipv6_prefix (expected 1..=128) — ignoring");
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
            // Optional override; otherwise the account id is derived from
            // the zone lookup at reconcile time.
            let account = std::env::var("SENTRY_CF_ACCOUNT")
                .ok()
                .filter(|s| !s.is_empty());
            let cf = Arc::new(sentry_action_cloudflare::CloudflareProvider::new(
                sentry_action_cloudflare::CloudflareProviderConfig {
                    token,
                    zone,
                    default_mode: EdgeMode::ManagedChallenge,
                    ttl,
                    max_failures: parse_max_failures(options),
                    ipv6_prefix: parse_ipv6_prefix(options),
                    list_name: options
                        .get("list_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("sentry_blocks")
                        .to_string(),
                    account,
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
/// Periodically deletes edge rules created by Sentry whose note-encoded TTL
/// (`sentry:<created_unix>:<ttl_secs>`) has lapsed. Unlike the provider's
/// in-memory cache, the encoded expiry survives restarts. No-op while the
/// provider is disabled (invalid token or tripped circuit breaker).
async fn cloudflare_reaper(cf: Arc<sentry_action_cloudflare::CloudflareProvider>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    interval.tick().await; // skip the immediate tick
    loop {
        interval.tick().await;
        match cf.reap_expired().await {
            Ok(reaped) if reaped > 0 => {
                info!(reaped, "cloudflare reaper: deleted expired access rules");
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "cloudflare reaper: list failed"),
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

/// Convert a stored `EventRow` back into a domain `Event`.
///
/// Shared by the `routes learn` CLI handler and the background learner task.
pub(crate) fn event_row_to_event(row: &sentry_storage::EventRow) -> Option<Event> {
    let proto = serde_json::from_value::<sentry_core::ProtocolData>(row.protocol.clone()).ok()?;
    let ip: IpAddr = row.client_ip.parse().ok()?;
    Some(Event::new(sentry_core::SourceKind::Synthetic, ip, proto))
}

/// Background task: continuous route learner.
///
/// Every `interval_secs`, scans events from the last `window_secs`, infers
/// stable route shapes, dedups against the DB, inserts new routes, and
/// notifies the daemon to hot-reload them.
async fn route_learner_task(
    repo: Arc<sentry_storage::Repo>,
    cfg: sentry_core::config::RouteLearnerConfig,
) {
    let interval = Duration::from_secs(cfg.interval_secs.max(30));
    let window = chrono::Duration::seconds(cfg.window_secs as i64);
    let opts = sentry_core::routes_learn::LearnOptions {
        min_hits: cfg.min_hits,
        min_ips: cfg.min_ips,
    };
    info!(
        interval_secs = cfg.interval_secs,
        window_secs = cfg.window_secs,
        min_hits = cfg.min_hits,
        min_ips = cfg.min_ips,
        "route learner task started"
    );
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;
    loop {
        tick.tick().await;
        let since = chrono::Utc::now() - window;
        let rows = match repo.events().recent_since(since).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "route learner: failed to fetch events");
                continue;
            }
        };
        if rows.is_empty() {
            continue;
        }
        let events: Vec<Event> = rows.iter().filter_map(event_row_to_event).collect();
        if events.is_empty() {
            continue;
        }
        let learned = sentry_core::routes_learn::learn(&events, &opts);
        if learned.is_empty() {
            continue;
        }
        let existing = match repo.routes().list().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "route learner: failed to list existing routes");
                continue;
            }
        };
        let existing_paths: std::collections::HashSet<String> = existing
            .iter()
            .map(|r| r.path.to_ascii_lowercase())
            .collect();
        let mut inserted = 0u32;
        for r in &learned {
            if existing_paths.contains(&r.path.to_ascii_lowercase()) {
                continue;
            }
            match repo.routes().insert(&r.path, &r.methods).await {
                Ok(_) => {
                    inserted += 1;
                    info!(path = %r.path, "route learner: discovered new route");
                }
                Err(e) => warn!(error = %e, path = %r.path, "route learner: insert failed"),
            }
        }
        if inserted > 0 {
            info!(inserted, "route learner: auto-pushed new routes");
            let _ = repo.pool().notify("sentry_routes_changed").await;
        }
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

#[cfg(test)]
mod tests {
    use super::instance_label;

    #[test]
    fn configured_instance_id_wins() {
        assert_eq!(instance_label("node-b"), "node-b");
        assert_eq!(instance_label("  node-c  "), "node-c");
    }

    #[test]
    fn falls_back_when_unconfigured() {
        let label = instance_label("");
        assert!(!label.is_empty());
        assert!(!label.contains(char::is_whitespace));
    }
}
