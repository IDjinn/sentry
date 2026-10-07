//! Daemon entrypoint: wires up sources, pipeline, rules, actions.
//!
//! The daemon:
//! 1. Loads config and builds the plugin registry + ruleset
//! 2. Opens geo databases (graceful no-op if absent)
//! 3. Optionally connects to Postgres (storage + hot-reload)
//! 4. Starts all sources (concurrent event streams)
//! 5. Merges streams into one channel (fan-in)
//! 6. For each event: enrich (geo) → dedupe → pipeline → persist → inline
//!    containment actions; deferred (network-bound) actions go to
//!    post-processing workers
//! 7. Prints colored events to stdout and logs decisions

use notify::Watcher;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "onnx")]
use sentry_ai::ThreatModel;
use sentry_core::challenge::{ChallengeAction, ChallengeProvider, EdgeMode, EdgeOptions};
use sentry_core::config::{ActionKind, ChallengeBackend, SentryConfig};
use sentry_core::event::{Event, ProtocolData};
use sentry_core::packs::build_default_ruleset_with;
use sentry_core::pipeline::{Pipeline, RouteValidator};
use sentry_core::ratelimit::{InMemoryRateLimiter, RateLimitBackend};
use sentry_core::registry::RegistryBuilder;
use sentry_core::rules::{shared, RuleSet, SharedRuleSet};
use sentry_core::throttle::DropLogThrottle;
use sentry_core::{ActionDispatch, RiskLevel, RuleLogLevel, Signal};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// A challenge action paired with its concrete provider handles (when the
/// providers are built locally — Cloudflare edge rules, local firewall,
/// nginx includes).
struct ChallengeActionWithProvider {
    action: ChallengeAction,
    provider: Option<Arc<sentry_action_cloudflare::CloudflareProvider>>,
    firewall: Option<Arc<sentry_action_firewall::FirewallProvider>>,
    nginx: Option<Arc<sentry_action_nginx::NginxProvider>>,
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

    // Build the ruleset from configured packs + custom rules. Pack params
    // flatten into `<pack>__<param>` keys (e.g. `host_allowlist__domains`);
    // without this the param-driven packs silently never saw their params.
    let pack_modes: HashMap<String, String> = cfg
        .rules
        .packs
        .iter()
        .flat_map(|p| {
            let mut entries = vec![(p.name.clone(), p.mode.clone())];
            for (key, value) in &p.params {
                let rendered = match value {
                    toml::Value::String(s) => Some(s.clone()),
                    toml::Value::Array(arr) => Some(
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                    _ => None,
                };
                if let Some(s) = rendered {
                    entries.push((format!("{}__{}", p.name, key), s));
                }
            }
            entries
        })
        .collect();

    // Reputation feeds (F3.7) + datasets (F7.6): fetch once at startup so
    // enrichment is live and dataset rules have content before the ruleset
    // is shared, then refresh in the background. A failing feed keeps its
    // previous entries.
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

    let mut rules = build_default_ruleset_with(&pack_modes, cfg.bot_verification.enabled);
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
    // Dataset feeds (`kind = "user_agent" | "path"`, F7.6): one synthetic
    // rule per dataset from the content fetched above. The rule carries the
    // startup snapshot; a later background refresh updates the service's
    // copy but not the rule (a restart or rules hot-reload picks it up).
    if let Some(ref svc) = reputation {
        for feed in cfg.rules.feeds.iter().filter(|f| f.enabled) {
            if matches!(
                feed.kind,
                sentry_core::config::FeedKind::UserAgent | sentry_core::config::FeedKind::Path
            ) {
                match svc.dataset(&feed.name).await {
                    Some(entries) => match sentry_core::reputation::dataset_rule(feed, &entries) {
                        Ok(Some(rule)) => {
                            info!(
                                feed = %feed.name,
                                entries = entries.len(),
                                "dataset rule built"
                            );
                            rules.extend(std::iter::once(rule));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(feed = %feed.name, error = %e, "invalid dataset rule — skipped")
                        }
                    },
                    None => {
                        warn!(feed = %feed.name, "dataset feed has no fetched content — skipped")
                    }
                }
            }
        }
    }
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

    // Shared block table: the blocklist action, the DB pre-warm/hot-reload
    // and the block mirror below write it; the inline edge fast-path reads
    // it to deny blocked IPs before the pipeline runs.
    let block_table = Arc::new(sentry_core::BlockTable::new());
    let block_ttl = Duration::from_secs(blocklist_ttl_secs(&cfg));

    let metrics = crate::metrics::Metrics::new();
    metrics.set_instance(&instance_label(&cfg.deployment.instance_id));
    let event_log = crate::eventlog::EventLog::new();

    // Protocol schema validation (F9): compile schemas at startup and keep
    // a hot-swappable engine; an fs watcher recompiles on add/modify/remove.
    let protocol_engine: Option<Arc<sentry_protocol::ProtocolEngine>> = if cfg.protocol.enabled {
        match crate::protocol_cmd::compile_dir(&cfg.protocol.dir, cfg.protocol.max_schemas) {
            Ok((compiled, errors)) if errors.is_empty() => {
                let n = compiled.protocols.len();
                info!(
                    schemas = n,
                    dir = %cfg.protocol.dir.display(),
                    "protocol schemas compiled"
                );
                Some(Arc::new(sentry_protocol::ProtocolEngine::new(compiled)))
            }
            Ok((_, errors)) => {
                for e in &errors {
                    warn!(error = %e, "protocol schema failed to compile");
                }
                warn!("protocol validation disabled for this run (compile errors)");
                None
            }
            Err(e) => {
                warn!(error = %e, "protocol dir scan failed; validation disabled");
                None
            }
        }
    } else {
        None
    };
    if let Some(ref engine) = protocol_engine {
        let watcher_cfg = cfg.protocol.clone();
        let watcher_engine = Arc::clone(engine);
        tokio::spawn(async move {
            protocol_watcher(watcher_cfg, watcher_engine).await;
        });
    }

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

                let reload_blocks = Arc::clone(&block_table);
                let blocks_pool = repo.pool().clone();
                tokio::spawn(async move {
                    blocks_hot_reload(blocks_pool, reload_blocks).await;
                });

                // DB datasets (F7.7): synthetic rules + dynamic prefilter
                // literals, applied at startup and hot-reloaded on NOTIFY.
                match db_dataset_rules(&repo).await {
                    Ok((fresh, uas, paths)) => {
                        let n = {
                            let mut guard = shared_rules.write().unwrap();
                            guard.replace_by_prefix("dataset:", fresh)
                        };
                        sentry_core::heuristics::reload_dataset_lists(&uas, &paths);
                        info!(rule_count = n, "db datasets applied");
                    }
                    Err(e) => warn!(error = %e, "failed to load db datasets"),
                }
                let reload_datasets_pool = repo.pool().clone();
                let reload_datasets_rules = Arc::clone(&shared_rules);
                tokio::spawn(async move {
                    datasets_hot_reload(reload_datasets_pool, reload_datasets_rules).await;
                });

                // Pre-warm the block table from persisted blocks so the
                // inline edge denies them immediately after a restart.
                match repo.ip_state().blocked(10_000).await {
                    Ok(rows) => {
                        let now = chrono::Utc::now();
                        let seeded = rows
                            .iter()
                            .filter_map(|r| {
                                let ip = r.ip.parse::<IpAddr>().ok()?;
                                let exp = match r.expires_at {
                                    None => None,
                                    Some(ts) => {
                                        let Ok(remaining) = (ts - now).to_std() else {
                                            return None;
                                        };
                                        Some(std::time::Instant::now() + remaining)
                                    }
                                };
                                block_table.seed(ip, exp);
                                Some(())
                            })
                            .count();
                        info!(blocked = seeded, "block table pre-warmed from db");
                    }
                    Err(e) => warn!(error = %e, "failed to pre-warm block table"),
                }

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

    // Upload-volume tracker (F10): per-IP flood window over files/bytes.
    let upload_tracker = cfg.uploads.enabled.then(|| {
        Arc::new(std::sync::RwLock::new(
            sentry_core::uploads::UploadTracker::from_config(&cfg.uploads),
        ))
    });
    if cfg.uploads.enabled && !cfg.deployment.is_inline() {
        warn!(
            "[uploads] enabled but [deployment] mode is not \"inline\" — request \
             bodies never reach passive sources (log tails), so upload inspection \
             has nothing to analyze; switch to inline to enforce it"
        );
    }

    // Web security posture advisories (F11): shadow-only header inspection
    // of origin responses. `enforce` is reserved for header injection
    // (roadmap) and is rejected here so the config never lies.
    if cfg.posture.mode.is_enforce() {
        return Err(color_eyre::eyre::eyre!(
            "[posture] mode = \"enforce\" is not implemented yet — header \
             injection without per-site knowledge would break pages; use \
             \"shadow\" (roadmap: BACKLOG.md §5.4)"
        ));
    }
    if cfg.posture.enabled {
        for id in cfg.posture.unknown_checks() {
            warn!(check = %id, "unknown [posture] checks id — ignoring");
        }
        if !cfg.deployment.is_inline() {
            warn!(
                "[posture] enabled but [deployment] mode is not \"inline\" — \
                 origin responses never reach passive sources, so no security \
                 header is ever observed; advisory checks stay silent"
            );
        }
    }
    let posture_tracker = cfg.posture.enabled.then(|| {
        Arc::new(sentry_core::posture::PostureTracker::new(
            sentry_core::posture::PostureScan::from_config(&cfg.posture),
        ))
    });

    // Cross-IP scan→attack correlation (F3.10 shot-calling pattern).
    let correlation_tracker = cfg.correlation.enabled.then(|| {
        Arc::new(std::sync::RwLock::new(
            sentry_core::correlation::CorrelationTracker::from_config(&cfg.correlation),
        ))
    });

    // Repeat-offender memory (strikes → verdict escalation ladder).
    let offender_tracker = cfg.escalation.enabled.then(|| {
        Arc::new(std::sync::RwLock::new(
            sentry_core::offender::OffenderTracker::from_config(&cfg.escalation),
        ))
    });

    // Trusted infrastructure (F7.2): proxies allowed to set header-borne
    // client IPs (Cloudflare ranges + `[real_ip] trusted_proxies`) and
    // never-ban clients (`[real_ip] trusted_ips`).
    let shared_trust = sentry_core::SharedTrustSet::new(
        sentry_core::TrustSet::from_config(&cfg.real_ip)
            .map_err(|e| color_eyre::eyre::eyre!("[real_ip] {e}"))?,
    );
    if cfg.real_ip.cloudflare && cfg.real_ip.refresh_secs > 0 {
        spawn_cloudflare_refresh(cfg.real_ip.clone(), shared_trust.clone());
    }
    if !cfg.real_ip.trusted_lists.is_empty() {
        let lists = &cfg.real_ip.trusted_lists;
        let total: usize = lists
            .iter()
            .filter_map(|n| sentry_core::trusted_lists::preset_nets(n))
            .map(|nets| nets.len())
            .sum();
        info!(
            lists = %lists.join(", "),
            ranges = total,
            "trusted IP presets approved (never-ban)"
        );
    }

    // rDNS bot verification (F7.7): claimed-crawler UAs are checked off the
    // hot path by the background worker; pipeline + edge read the cache.
    let bot_verifier = if cfg.bot_verification.enabled {
        match crate::botdns::HickoryDns::new(Duration::from_millis(cfg.bot_verification.timeout_ms))
        {
            Ok(dns) => {
                let verifier = Arc::new(sentry_core::botverify::BotVerifier::from_config(
                    &cfg.bot_verification,
                ));
                tokio::spawn(crate::botdns::bot_verify_worker(
                    verifier.clone(),
                    Arc::new(dns),
                    Duration::from_millis(cfg.bot_verification.timeout_ms),
                    cfg.bot_verification.batch_size,
                    metrics.clone(),
                ));
                info!("bot verification enabled (rDNS forward-confirm)");
                Some(verifier)
            }
            Err(e) => {
                warn!(error = %e, "failed to build bot-verification resolver — disabled");
                None
            }
        }
    } else {
        None
    };

    let mut pipeline_builder = Pipeline::with_config(
        Arc::clone(&shared_rules),
        route_validator,
        cfg.scorer.clone(),
        policy,
    )
    .with_rate_limiter(build_rate_limiter(&cfg)?)
    .with_trust(shared_trust.clone());
    pipeline_builder.configure_uploads(&cfg.uploads);
    if let Some(ref v) = bot_verifier {
        pipeline_builder = pipeline_builder.with_bot_verifier(Arc::clone(v));
    }
    if let Some(ref t) = scan_tracker {
        pipeline_builder = pipeline_builder.with_scan_tracker(Arc::clone(t));
    }
    if let Some(ref t) = behavior_tracker {
        pipeline_builder = pipeline_builder.with_behavior_tracker(Arc::clone(t));
    }
    if let Some(ref t) = upload_tracker {
        pipeline_builder = pipeline_builder.with_upload_tracker(Arc::clone(t));
    }
    if let Some(ref t) = correlation_tracker {
        pipeline_builder = pipeline_builder.with_correlation_tracker(Arc::clone(t));
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
        correlation = cfg.correlation.enabled,
        escalation = cfg.escalation.enabled,
        bot_verification = cfg.bot_verification.enabled,
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
    if let Some(ref t) = upload_tracker {
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
    if let Some(ref t) = correlation_tracker {
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
    if let Some(ref t) = posture_tracker {
        let t = Arc::clone(t);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                t.prune();
            }
        });
    }
    {
        let pipeline = Arc::clone(&pipeline);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                pipeline.prune_pending();
            }
        });
    }
    {
        let table = Arc::clone(&block_table);
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                table.prune();
                metrics.block_table_size.set(table.len() as f64);
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
    let RegistryBundle {
        registry,
        cf_provider,
        fw_provider,
        nginx_provider,
    } = build_registry(&cfg, Arc::clone(&block_table), &shared_trust)?;

    // nginx include reconcile (F7.8): `ip_state` is the source of truth for
    // deny entries — re-seed them after a restart and keep converging with
    // manual unblocks from other nodes. Challenge-map entries are ephemeral.
    if let (Some(ref ng), Some(ref repo)) = (&nginx_provider, &repo) {
        let rows = repo.ip_state().blocked(10_000).await.unwrap_or_default();
        let expected = expected_firewall_entries(&rows);
        let (added, removed) = ng.sync_denies(&expected).await;
        info!(added, removed, "nginx denies synced with ip_state");
        let ng_task = Arc::clone(ng);
        let repo_task = Arc::clone(repo);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await; // skip the immediate tick (startup sync above)
            loop {
                interval.tick().await;
                let rows = repo_task
                    .ip_state()
                    .blocked(10_000)
                    .await
                    .unwrap_or_default();
                let expected = expected_firewall_entries(&rows);
                let (added, removed) = ng_task.sync_denies(&expected).await;
                if added > 0 || removed > 0 {
                    info!(added, removed, "nginx deny reconcile applied changes");
                }
            }
        });
    }

    // Firewall reconcile (F7.3): the DB (`ip_state`) is the source of
    // truth — provision the sets, re-seed persisted bans after a restart,
    // and keep the live sets converging in the background (manual
    // unblocks from CLI/dashboard/other nodes, expired entries).
    if let (Some(ref fw), Some(ref repo)) = (&fw_provider, &repo) {
        let rows = repo.ip_state().blocked(10_000).await.unwrap_or_default();
        let expected = expected_firewall_entries(&rows);
        match fw.sync(&expected).await {
            Ok((added, removed)) => {
                info!(
                    backend = fw.resolved_backend().map(|b| b.as_str()).unwrap_or("?"),
                    added, removed, "firewall synced with ip_state"
                );
            }
            Err(e) => warn!(error = %e, "firewall initial sync failed"),
        }
        let fw_task = Arc::clone(fw);
        let repo_task = Arc::clone(repo);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await; // skip the immediate tick (startup sync above)
            loop {
                interval.tick().await;
                let rows = repo_task
                    .ip_state()
                    .blocked(10_000)
                    .await
                    .unwrap_or_default();
                let expected = expected_firewall_entries(&rows);
                match fw_task.sync(&expected).await {
                    Ok((added, removed)) if added > 0 || removed > 0 => {
                        info!(added, removed, "firewall reconcile applied changes");
                    }
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "firewall reconcile failed"),
                }
            }
        });
    }

    // Local ML threat model: runs as a fork off the hot path (or inline /
    // shadow, per [ai] config) and feeds signals back via rescore_from.
    let ai_fork = build_ai_fork(&cfg, &metrics);
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
    let llm_fork = build_llm_fork(&cfg, &metrics);
    let ip_lookup_fork = build_ip_lookup_fork(&cfg, &metrics);

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
        let trust_clone = shared_trust.clone();
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            info!(source = source.name(), "starting source");
            let mut throttle = DropLogThrottle::new();
            match source.stream().await {
                Ok(mut rx) => {
                    while let Some(raw) = rx.recv().await {
                        let ip = raw
                            .client_ip
                            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                        let mut evt = raw.into_event(ip);
                        mark_trusted(&mut evt, &trust_clone);
                        if let Some(ref g) = geo_clone {
                            g.enrich(&mut evt);
                        }
                        if let Some(ref r) = reputation_clone {
                            r.enrich(&mut evt);
                        }
                        match tx.try_send(Incoming::Raw(Box::new(evt))) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                metrics_clone
                                    .events_dropped
                                    .with_label_values(&[source.name()])
                                    .inc();
                                if let Some(count) = throttle.record(Instant::now()) {
                                    warn!(
                                        source = source.name(),
                                        dropped = count,
                                        "event channel full, dropped events in the last 5s"
                                    );
                                }
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                warn!(source = source.name(), "fan-in closed, stopping forwarder");
                                break;
                            }
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
        let enricher = make_enricher(&geo, &reputation, &shared_trust);
        let (dec_tx, mut dec_rx) = mpsc::channel::<sentry_core::ProcessedEvent>(buffer);
        let tls_cfg = match (&cfg.edge.tls_cert, &cfg.edge.tls_key) {
            (Some(cert), Some(key)) => Some(sentry_edge::proxy::TlsEdgeConfig {
                listen: cfg
                    .edge
                    .tls_listen
                    .clone()
                    .unwrap_or_else(|| "0.0.0.0:443".to_string()),
                cert: cert.clone(),
                key: key.clone(),
                redirect_https: cfg.edge.tls_redirect_https,
                allowed_hosts: cfg.edge.tls_allowed_hosts.clone(),
                handshake_events: cfg.edge.tls_handshake_events,
            }),
            (None, None) => None,
            _ => {
                return Err(color_eyre::eyre::eyre!(
                    "[edge] tls_cert and tls_key must be configured together"
                ));
            }
        };
        // Site-level posture advisories (F11): these two warn about exactly
        // what browser security checklists flag on the protected origin.
        match &tls_cfg {
            None => {
                warn!(
                    "[edge] no tls_cert configured — the site is served over plain \
                     HTTP and browsers flag it as \"not using HTTPS\"; see [edge] \
                     tls_cert/tls_key (F8)"
                );
            }
            Some(tls) if !tls.redirect_https => {
                warn!(
                    "[edge] tls_redirect_https = false — HTTP traffic is not \
                     redirected to HTTPS; browsers report \"HTTP traffic is not \
                     redirected\" and first visits stay cleartext"
                );
            }
            Some(_) => {}
        }
        let proxy_cfg = sentry_edge::proxy::EdgeProxyConfig {
            listen: cfg.edge.listen.clone(),
            upstream: cfg.edge.upstream.clone(),
            health_path: cfg.edge.health_path.clone(),
            health_timeout_secs: cfg.edge.health_timeout_secs,
            tls: tls_cfg.clone(),
        };
        let runtime = sentry_edge::EdgeRuntime::new(
            Arc::clone(&pipeline),
            enricher.clone(),
            cfg.edge.body_capture_kb.saturating_mul(1024),
        )
        .with_challenge_backend(cfg.edge.challenge_backend)
        .with_trust(shared_trust.clone())
        .with_block_table(Arc::clone(&block_table))
        .with_block_hits(metrics.edge_block_hits.clone())
        .with_request_duration(metrics.edge_request_duration.clone())
        .with_challenge_metrics(metrics.edge_challenge.clone())
        .with_tls_metrics(sentry_edge::TlsMetrics {
            handshakes: metrics.edge_tls_handshakes.clone(),
            failures: metrics.edge_tls_failures.clone(),
            sni_mismatches: metrics.edge_tls_sni_mismatches.clone(),
        });
        let runtime = if cfg.uploads.enabled {
            let inspect_bytes = cfg
                .uploads
                .inspect_kb
                .saturating_mul(1024)
                .clamp(64 * 1024, 64 * 1024 * 1024);
            info!(
                mode = cfg.uploads.mode.as_str(),
                inspect_kb = cfg.uploads.inspect_kb,
                max_files = cfg.uploads.max_files,
                "upload inspection enabled (F10)"
            );
            runtime
                .with_uploads(sentry_edge::UploadsInspection {
                    inspect_bytes,
                    max_files: cfg.uploads.max_files.clamp(1, 256),
                })
                .with_uploads_inspected(metrics.edge_uploads_inspected.clone())
        } else {
            runtime
        };
        let runtime = if let Some(ref tracker) = posture_tracker {
            info!(
                mode = cfg.posture.mode.as_str(),
                ttl_secs = cfg.posture.dedupe_ttl_secs,
                "web security posture advisories enabled (F11, shadow)"
            );
            runtime
                .with_posture(Arc::clone(tracker))
                .with_posture_findings(metrics.posture_findings.clone())
        } else {
            runtime
        };
        let runtime = match &protocol_engine {
            Some(eng) => runtime.with_protocol(Arc::clone(eng), protocol_metrics_handles(&metrics)),
            None => runtime,
        };
        let runtime = if let Some(ref v) = bot_verifier {
            runtime.with_bot_verifier(Arc::clone(v))
        } else {
            runtime
        };
        let runtime = if cfg.edge.challenge.enabled
            && cfg.edge.challenge_backend == ChallengeBackend::Sentry
        {
            let secret = std::env::var(&cfg.edge.challenge.secret_env)
                .map_err(|_| {
                    color_eyre::eyre::eyre!(
                        "[edge.challenge] enabled but env `{}` is not set (generate one with `openssl rand -hex 32`)",
                        cfg.edge.challenge.secret_env
                    )
                })?;
            if secret.len() < 16 {
                return Err(color_eyre::eyre::eyre!(
                    "[edge.challenge] secret in `{}` is too short (use 32+ random bytes)",
                    cfg.edge.challenge.secret_env
                ));
            }
            let ch = Arc::new(sentry_edge::challenge::JsChallenge::new(
                secret.into_bytes(),
                cfg.edge.challenge.bucket_secs,
                cfg.edge.challenge.difficulty,
                cfg.edge.challenge.title.clone(),
                cfg.edge.challenge.template_path.clone(),
            ));
            info!(
                bucket_secs = cfg.edge.challenge.bucket_secs,
                difficulty = cfg.edge.challenge.difficulty,
                template = ?cfg.edge.challenge.template_path,
                "edge JS challenge enabled (F7.8)"
            );
            runtime.with_challenge(ch)
        } else {
            runtime
        };
        if cfg.edge.challenge_backend == ChallengeBackend::Cloudflare {
            if cf_provider.is_some() {
                info!(
                    backend = "cloudflare",
                    "edge challenges delegated to the Cloudflare provider — \
                     verdicts become CF rules via the CF API"
                );
            } else {
                warn!(
                    "[edge] challenge_backend = \"cloudflare\" but no [[action]] with provider \
                     = \"cloudflare\" is configured — Challenge verdicts will be held with a \
                     403 retry page instead of becoming Cloudflare rules"
                );
            }
        }
        let edge_pipeline = cfg.edge.upstream.clone();
        tokio::spawn(async move {
            if let Err(e) = sentry_edge::proxy::serve(runtime, proxy_cfg, dec_tx).await {
                error!(error = %e, upstream = %edge_pipeline, "edge proxy terminated");
            }
        });
        let pump_tx = event_tx.clone();
        let pump_metrics = metrics.clone();
        tokio::spawn(async move {
            let mut throttle = DropLogThrottle::new();
            while let Some(pe) = dec_rx.recv().await {
                match pump_tx.try_send(Incoming::Processed(Box::new(pe))) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        pump_metrics
                            .events_dropped
                            .with_label_values(&["edge"])
                            .inc();
                        if let Some(count) = throttle.record(Instant::now()) {
                            warn!(
                                dropped = count,
                                "event channel full, dropped edge events in the last 5s"
                            );
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        });
        // Certificate expiry gauge + daily refresh (F8): operators see the
        // runway in `/metrics` long before browsers start warning.
        #[cfg(feature = "edge-tls")]
        if let Some(ref tls_cfg) = tls_cfg {
            let gauge = metrics.edge_tls_cert_not_after.clone();
            let cert_path = tls_cfg.cert.clone();
            if let Some(not_after) = sentry_edge::tls::cert_not_after(&cert_path) {
                let ts = not_after
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                gauge.set(ts as f64);
                let days_left = not_after
                    .duration_since(std::time::SystemTime::now())
                    .map(|d| d.as_secs() / 86_400)
                    .unwrap_or(0);
                if days_left < 14 {
                    warn!(
                        days_left,
                        cert = %cert_path.display(),
                        "edge tls certificate expires soon"
                    );
                }
            } else {
                warn!(
                    cert = %cert_path.display(),
                    "edge tls certificate expiry could not be parsed"
                );
            }
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                    if let Some(not_after) = sentry_edge::tls::cert_not_after(&cert_path) {
                        let ts = not_after
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        gauge.set(ts as f64);
                    }
                }
            });
        }
        if let (Some(tcp_listen), Some(tcp_upstream)) =
            (cfg.edge.tcp_listen.clone(), cfg.edge.tcp_upstream.clone())
        {
            let tcp_runtime = sentry_edge::EdgeRuntime::new(Arc::clone(&pipeline), enricher, 0)
                .with_challenge_backend(cfg.edge.challenge_backend)
                .with_trust(shared_trust.clone())
                .with_block_table(Arc::clone(&block_table))
                .with_block_hits(metrics.edge_block_hits.clone());
            let tcp_runtime = match &protocol_engine {
                Some(eng) => {
                    tcp_runtime.with_protocol(Arc::clone(eng), protocol_metrics_handles(&metrics))
                }
                None => tcp_runtime,
            };
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
            let tcp_pump_metrics = metrics.clone();
            tokio::spawn(async move {
                let mut throttle = DropLogThrottle::new();
                while let Some(pe) = tcp_dec_rx.recv().await {
                    match tcp_pump_tx.try_send(Incoming::Processed(Box::new(pe))) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tcp_pump_metrics
                                .events_dropped
                                .with_label_values(&["edge-tcp"])
                                .inc();
                            if let Some(count) = throttle.record(Instant::now()) {
                                warn!(
                                    dropped = count,
                                    "event channel full, dropped edge-tcp events in the last 5s"
                                );
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
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

    if cfg.metrics.enabled {
        let addr: std::net::SocketAddr = format!("{}:{}", cfg.metrics.host, cfg.metrics.port)
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("invalid metrics bind address: {e}"))?;
        let m = metrics.clone();
        let log = event_log.clone();
        tokio::spawn(async move {
            serve_metrics(m, log, addr).await;
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

    // Deferred action dispatch (post-processing): network-bound actions
    // (Cloudflare/OPNsense/nginx APIs, webhooks, abuse reports) run on
    // dedicated workers so the ingest hot loop never awaits external I/O.
    // `action_workers = 1` (default) keeps strict ordering; incident
    // resolution is serialized across workers regardless, preserving the
    // one-open-incident-per-IP coalescing (F4.5).
    let action_buffer = cfg.core.action_buffer.max(256);
    let action_workers = cfg.core.action_workers.clamp(1, 32);
    let (deferred_tx, deferred_rx) =
        mpsc::channel::<Arc<sentry_core::ProcessedEvent>>(action_buffer);
    {
        let deferred_rx = Arc::new(tokio::sync::Mutex::new(deferred_rx));
        let incident_gate = Arc::new(tokio::sync::Mutex::new(()));
        for _ in 0..action_workers {
            let rx = Arc::clone(&deferred_rx);
            let registry = registry.clone();
            let repo = repo.clone();
            let metrics = metrics.clone();
            let gate = Arc::clone(&incident_gate);
            tokio::spawn(async move {
                loop {
                    // Holding the lock across recv hands each queued event to
                    // exactly one worker; the rest queue on the mutex.
                    let next = rx.lock().await.recv().await;
                    let Some(result) = next else { break };
                    dispatch_deferred(&result, &registry, &repo, &metrics, &gate).await;
                }
            });
        }
    }

    // Console printing moves off the hot loop too: a blocked terminal can
    // stall the ingest path for milliseconds per event.
    let (print_tx, mut print_rx) =
        mpsc::channel::<(Arc<sentry_core::ProcessedEvent>, Option<Duration>)>(1024);
    tokio::spawn(async move {
        while let Some((result, process)) = print_rx.recv().await {
            print_event(
                &result.event,
                &result.analysis.risk_level,
                &result.analysis.signals,
                result.decision.log_level,
                process,
            );
        }
    });

    // Batched ingest (F5): `recv_many` drains up to 64 ready events per
    // wakeup, amortizing task/lock overhead under burst; under trickle load
    // it behaves exactly like `recv` (returns as soon as one event arrives).
    let mut deferred_throttle = DropLogThrottle::new();
    let mut batch: Vec<Incoming> = Vec::with_capacity(64);
    loop {
        let n = event_rx.recv_many(&mut batch, 64).await;
        if n == 0 {
            break; // channel closed
        }
        for incoming in batch.drain(..) {
            let start = Instant::now();
            let from_edge = matches!(incoming, Incoming::Processed(_));
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
            // The pipeline only runs for raw sources; edge-decided events
            // arrive with the verdict already applied (process_us stays None
            // and the edge latency lives in sentry_edge_request_duration_seconds).
            let process_us = (!from_edge).then_some(duration.as_micros() as u64);

            // Inline AI mode: block before persistence/actions so the stored
            // verdict and the dispatched actions already include the model's say.
            if let Some(ref ai) = ai_fork {
                if ai.is_inline() && ai.should_run(&result) {
                    let signals = ai.evaluate(&result.event).await;
                    let reason = signals
                        .iter()
                        .find_map(|s| s.detail.clone())
                        .unwrap_or_else(|| "-".into());
                    if !signals.is_empty() {
                        let updated = pipeline.rescore_from(&result, signals);
                        if updated.decision.action != result.decision.action {
                            info!(
                                ip = %result.event.client_ip,
                                from = ?result.decision.action,
                                to = ?updated.decision.action,
                                score = updated.analysis.risk_score,
                                reason = %reason,
                                "ai (inline) changed verdict"
                            );
                        }
                        result = updated;
                    }
                }
            }

            // From here the event is shared with the deferred lanes (console
            // printer, persistence spawn, post-processing workers) — an Arc
            // instead of a deep clone per consumer.
            let result = Arc::new(result);

            if print_tx
                .try_send((Arc::clone(&result), (!from_edge).then_some(duration)))
                .is_err()
            {
                if let Some(count) = deferred_throttle.record(Instant::now()) {
                    warn!(
                        dropped = count,
                        "console backlog full, dropping event lines"
                    );
                }
            }

            if let Some(ref repo) = repo {
                let signals_json =
                    serde_json::to_value(&result.analysis.signals).unwrap_or_default();
                let repo = Arc::clone(repo);
                let result_clone = Arc::clone(&result);
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
                            process_us,
                        )
                        .await
                    {
                        warn!(error = %e, "failed to persist event");
                    }
                });
            }

            // Mirror block verdicts into the block table + Postgres so the
            // inline edge denies the IP before the pipeline, the block
            // survives restarts and sibling nodes pick it up via NOTIFY.
            // The is_blocked guard keeps repeat offenders from rewriting the
            // row on every violating event.
            if result.decision.action == sentry_core::Verdict::Block
                && !block_table.is_blocked(result.event.client_ip)
            {
                let expires = std::time::Instant::now() + block_ttl;
                block_table.block(result.event.client_ip, Some(expires));
                if let Some(ref repo) = repo {
                    let repo = Arc::clone(repo);
                    let ip = result.event.client_ip;
                    let reason = result
                        .analysis
                        .signals
                        .first()
                        .map(|s| crate::eventlog::signal_kind_label(&s.kind))
                        .unwrap_or_else(|| "pipeline".to_string());
                    let expires_db = chrono::Utc::now()
                        + chrono::Duration::from_std(block_ttl).unwrap_or_default();
                    let table = Arc::clone(&block_table);
                    tokio::spawn(async move {
                        if let Err(e) = repo
                            .ip_state()
                            .block(ip, Some(&reason), Some(expires_db))
                            .await
                        {
                            warn!(error = %e, "failed to mirror block to db");
                            return;
                        }
                        table.block(ip, Some(expires));
                        if let Err(e) = repo.pool().notify("sentry_blocks_changed").await {
                            warn!(error = %e, "failed to notify block change");
                        }
                    });
                }
            }

            // Two-lane dispatch: local containment (blocklist, log, kernel
            // firewall) runs inline so a hostile request is contained with
            // zero queueing latency — inline actions receive an empty
            // ActionContext because the hot loop never awaits on storage.
            // Network side effects are handed to the post-processing
            // workers; when their queue fills under overload, actions are
            // shed (counted) — the event itself is still persisted above.
            let mut needs_deferred = false;
            for action in registry.actions() {
                if !action.applies_to(&result.decision) {
                    continue;
                }
                if action.dispatch() == ActionDispatch::Deferred {
                    needs_deferred = true;
                    continue;
                }
                metrics
                    .actions
                    .with_label_values(&[action.name(), verdict_str(result.decision.action)])
                    .inc();
                let action_start = Instant::now();
                let executed = action
                    .execute_with_context(
                        &result.event,
                        &result.decision,
                        &sentry_core::ActionContext::default(),
                    )
                    .await;
                metrics.record_action_dispatch(action.name(), action_start.elapsed());
                if let Err(e) = executed {
                    warn!(action = action.name(), error = %e, "action failed");
                }
            }
            if needs_deferred && deferred_tx.try_send(Arc::clone(&result)).is_err() {
                metrics.action_queue_drops.inc();
                if let Some(count) = deferred_throttle.record(Instant::now()) {
                    warn!(
                        dropped = count,
                        "deferred action queue full, shedding actions"
                    );
                }
            }

            if result
                .analysis
                .signals
                .iter()
                .any(|s| s.kind == sentry_core::SignalKind::ScanAttackCorrelation)
            {
                metrics.correlation_hits.inc();
            }
            for signal in &result.analysis.signals {
                metrics
                    .signal_kinds
                    .with_label_values(&[&crate::eventlog::signal_kind_label(&signal.kind)])
                    .inc();
            }
            event_log.push(crate::eventlog::EventSummary::from_processed_with_timing(
                &result,
                (!from_edge).then_some(duration),
            ));
            metrics.record_event(result.decision.action, result.analysis.risk_level, duration);
            metrics.record_ingest(start.elapsed());

            // Fork AI mode: evaluate off the hot path; a changed verdict updates
            // the persisted event and re-dispatches actions.
            if let Some(ref ai) = ai_fork {
                if !ai.is_inline() && ai.should_run(&result) {
                    ai.spawn_fork(
                        (*result).clone(),
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
                        (*result).clone(),
                        Arc::clone(&pipeline),
                        registry.clone(),
                        repo.clone(),
                    );
                }
            }

            // IP lookup fork (F7.5): external reputation check for gray-band
            // IPs, after the AI/LLM forks so a post-LLM score counts toward
            // the trigger band.
            if let Some(ref lookup) = ip_lookup_fork {
                if lookup.should_run(&result) {
                    lookup.spawn_fork(
                        (*result).clone(),
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
///
/// Trusted IPs (`[real_ip] trusted_ips`) are tagged `Authorized` before the
/// feed enrichment runs (which only fills when still unset) so they never
/// inherit a malicious tier from a feed.
fn make_enricher(
    geo: &Option<Arc<sentry_geo::GeoLookup>>,
    reputation: &Option<Arc<sentry_reputation::ReputationService>>,
    trust: &sentry_core::SharedTrustSet,
) -> Option<sentry_edge::Enricher> {
    if geo.is_none() && reputation.is_none() {
        return None;
    }
    let geo = geo.clone();
    let reputation = reputation.clone();
    let trust = trust.clone();
    Some(Arc::new(move |evt: &mut Event| {
        mark_trusted(evt, &trust);
        if let Some(ref g) = geo {
            g.enrich(evt);
        }
        if let Some(ref r) = reputation {
            r.enrich(evt);
        }
    }))
}

/// Tag a never-ban IP as reputation `Authorized` (idempotent; feeds only
/// fill an unset reputation).
fn mark_trusted(evt: &mut Event, trust: &sentry_core::SharedTrustSet) {
    if evt.reputation.is_none() && trust.is_never_ban(evt.client_ip) {
        let presets = sentry_core::trusted_lists::matching_presets(evt.client_ip);
        let source = if presets.is_empty() {
            "trusted_ips".to_string()
        } else {
            format!("trusted_lists:{}", presets.join(","))
        };
        evt.reputation = Some(sentry_core::ReputationInfo {
            tier: sentry_core::rules::ReputationTier::Authorized,
            source,
        });
    }
}

/// Background task: refresh the Cloudflare ranges (`[real_ip] cloudflare`,
/// F7.2) and swap them into the shared trust set. A failed or empty refresh
/// keeps the previous ranges (the bundled constants at bootstrap).
fn spawn_cloudflare_refresh(cfg: sentry_core::RealIpConfig, trust: sentry_core::SharedTrustSet) {
    let secs = cfg.refresh_secs.max(60);
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "cloudflare ranges: http client build failed");
                return;
            }
        };
        let mut interval = tokio::time::interval(Duration::from_secs(secs));
        loop {
            interval.tick().await; // first tick fires immediately
            let mut fetched = Vec::new();
            for url in [
                "https://www.cloudflare.com/ips-v4",
                "https://www.cloudflare.com/ips-v6",
            ] {
                match client.get(url).send().await {
                    Ok(resp) if resp.status().is_success() => match resp.text().await {
                        Ok(text) => {
                            fetched.extend(sentry_core::trust::parse_range_list(&text));
                        }
                        Err(e) => {
                            warn!(url, error = %e, "cloudflare ranges: body read failed")
                        }
                    },
                    Ok(resp) => {
                        warn!(url, status = %resp.status(), "cloudflare ranges refresh failed")
                    }
                    Err(e) => warn!(url, error = %e, "cloudflare ranges refresh failed"),
                }
            }
            if fetched.is_empty() {
                warn!("cloudflare ranges refresh came back empty — keeping previous ranges");
                continue;
            }
            // Config proxies + never-ban entries were validated at startup;
            // rebuild the set with cloudflare = false and layer the fetched
            // ranges on top.
            let base_cfg = sentry_core::RealIpConfig {
                cloudflare: false,
                ..cfg.clone()
            };
            let mut next = sentry_core::TrustSet::from_config(&base_cfg)
                .expect("real_ip entries were validated at startup");
            next.add_proxies(fetched);
            let proxies = next.proxy_count();
            trust.update(next);
            info!(trusted_ranges = proxies, "cloudflare ranges refreshed");
        }
    });
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

/// Run every deferred action that applies to `result` — the post-processing
/// worker body. Incident resolution is serialized through `gate` so parallel
/// workers keep the one-open-incident-per-IP coalescing; the context is
/// computed lazily, once per event (previously once per action).
async fn dispatch_deferred(
    result: &sentry_core::ProcessedEvent,
    registry: &sentry_core::registry::Registry,
    repo: &Option<Arc<sentry_storage::Repo>>,
    metrics: &crate::metrics::Metrics,
    gate: &tokio::sync::Mutex<()>,
) {
    let mut ctx: Option<sentry_core::ActionContext> = None;
    for action in registry.actions() {
        if action.dispatch() != ActionDispatch::Deferred || !action.applies_to(&result.decision) {
            continue;
        }
        metrics
            .actions
            .with_label_values(&[action.name(), verdict_str(result.decision.action)])
            .inc();
        if ctx.is_none() {
            let _guard = gate.lock().await;
            ctx = Some(incident_context(repo, result).await);
        }
        let action_start = Instant::now();
        if let Err(e) = action
            .execute_with_context(&result.event, &result.decision, ctx.as_ref().unwrap())
            .await
        {
            warn!(action = action.name(), error = %e, "action failed");
        }
        metrics.record_action_dispatch(action.name(), action_start.elapsed());
    }
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
    metrics: crate::metrics::Metrics,
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
            let started = Instant::now();
            let signals = fork.evaluate(&base.event).await;
            fork.metrics.record_fork("ai", started.elapsed());
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
fn build_ai_fork(cfg: &SentryConfig, metrics: &crate::metrics::Metrics) -> Option<Arc<AiFork>> {
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
            metrics: metrics.clone(),
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
    metrics: crate::metrics::Metrics,
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
            let started = Instant::now();
            let signals = fork.evaluate(&base.event).await;
            fork.metrics.record_fork("llm", started.elapsed());
            if signals.is_empty() {
                return;
            }
            let reason = signals
                .iter()
                .find(|s| s.kind == sentry_core::SignalKind::LlmMalicious)
                .and_then(|s| s.detail.clone());
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
                    reason = reason.as_deref().unwrap_or("-"),
                    "llm (shadow) would change verdict"
                );
                return;
            }
            info!(
                ip = %ip,
                from = ?base.decision.action,
                to = ?updated.decision.action,
                score = updated.analysis.risk_score,
                reason = reason.as_deref().unwrap_or("-"),
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

/// Construct a provider by name from `[llm]` config. Returns `None` (with a
/// warning) when the name is unknown or a required env key is missing —
/// shared by the daemon and `sentry bench llm`.
pub(crate) fn make_llm_provider(
    provider: &str,
    llm: &sentry_core::config::LlmConfig,
) -> Option<Arc<dyn sentry_ai::LlmProvider>> {
    match provider {
        "openrouter" => {
            let key = std::env::var("SENTRY_LLM_KEY").unwrap_or_default();
            if key.is_empty() {
                warn!("llm.provider = \"openrouter\" but SENTRY_LLM_KEY env unset — llm stage disabled for this run");
                return None;
            }
            Some(Arc::new(sentry_ai::OpenRouterProvider::new(
                sentry_ai::llm::openrouter::OpenRouterConfig {
                    api_key: key,
                    model: non_empty_or(&llm.model, "openai/gpt-4o-mini"),
                    base_url: non_empty_or(
                        llm.base_url.as_deref().unwrap_or(""),
                        sentry_ai::llm::openrouter::DEFAULT_BASE_URL,
                    ),
                },
            )))
        }
        "openai" => Some(Arc::new(sentry_ai::OpenRouterProvider::new(
            sentry_ai::llm::openrouter::OpenRouterConfig {
                // OpenAI-compatible local servers (LM Studio, vLLM,
                // llama.cpp server…) need no key; SENTRY_LLM_KEY is sent as
                // bearer when set, and base_url points at the server.
                api_key: std::env::var("SENTRY_LLM_KEY").unwrap_or_default(),
                model: non_empty_or(&llm.model, "local-model"),
                base_url: non_empty_or(
                    llm.base_url.as_deref().unwrap_or(""),
                    "http://localhost:1234/v1",
                ),
            },
        ))),
        "ollama" => Some(Arc::new(sentry_ai::OllamaProvider::new(
            sentry_ai::llm::ollama::OllamaConfig {
                model: non_empty_or(&llm.model, "llama3.1"),
                base_url: non_empty_or(
                    llm.base_url.as_deref().unwrap_or(""),
                    sentry_ai::llm::ollama::DEFAULT_BASE_URL,
                ),
            },
        ))),
        "jev" => {
            let Some(key) = sentry_ai::llm::jev::resolve_api_key() else {
                warn!(
                    "llm.provider = \"jev\" but no API key (SENTRY_JEV_KEY / TYPESAFE_API_KEY / JEV_API_KEY / ~/.config/typesafe/key) — llm stage disabled for this run"
                );
                return None;
            };
            Some(Arc::new(sentry_ai::JevProvider::new(
                sentry_ai::llm::jev::JevConfig {
                    api_key: key,
                    model: non_empty_or(&llm.model, sentry_ai::llm::jev::DEFAULT_MODEL),
                    base_url: non_empty_or(
                        llm.base_url.as_deref().unwrap_or(""),
                        sentry_ai::llm::jev::DEFAULT_BASE_URL,
                    ),
                },
            )))
        }
        "mock" => Some(Arc::new(sentry_ai::MockLlmProvider::default())),
        other => {
            warn!(
                provider = other,
                "unknown llm.provider — known: openrouter | openai | ollama | jev | mock"
            );
            None
        }
    }
}

/// Build the LLM fork from `[llm]` config when `provider != "none"`.
fn build_llm_fork(cfg: &SentryConfig, metrics: &crate::metrics::Metrics) -> Option<Arc<LlmFork>> {
    if cfg.llm.provider.is_empty() || cfg.llm.provider == "none" {
        return None;
    }
    let provider = make_llm_provider(&cfg.llm.provider, &cfg.llm)?;
    let mode = match cfg.llm.mode.as_str() {
        "shadow" => "shadow",
        _ => "fork",
    };
    info!(
        provider = provider.name(),
        provider_kind = %cfg.llm.provider,
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
        metrics: metrics.clone(),
    }))
}

fn non_empty_or(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.trim().to_string()
    }
}

/// External IP-reputation lookup fork (F7.5): checks "gray-band" IPs —
/// local score elevated but not yet acted on, or carrying a configured
/// suspicious signal — against the provider (AbuseIPDB `/check`) and feeds
/// the confidence score back through [`Pipeline::rescore_from`], which can
/// only raise the verdict. Runs after the AI/LLM forks so an elevated
/// post-LLM score counts toward the trigger band. TTL cache per IP + a
/// rolling-hour quota guard protect the provider's daily limits.
struct IpLookupFork {
    provider: Arc<dyn sentry_ai::IpLookupProvider>,
    trigger_above: u8,
    cache_ttl: Duration,
    max_per_hour: u32,
    semaphore: Arc<tokio::sync::Semaphore>,
    cache: std::sync::Mutex<HashMap<IpAddr, (Instant, u8)>>,
    quota: std::sync::Mutex<(Instant, u32)>,
    on_signals: Vec<sentry_core::analysis::SignalKind>,
    metrics: crate::metrics::Metrics,
}

impl IpLookupFork {
    /// Whether the result qualifies for a lookup (band, signals, quota).
    fn should_run(&self, r: &sentry_core::ProcessedEvent) -> bool {
        // Block already acted; the lookup can only raise, so spend no quota.
        if r.decision.action == sentry_core::Verdict::Block {
            return false;
        }
        let band = r.analysis.risk_score >= self.trigger_above;
        let signal_hit = !self.on_signals.is_empty()
            && r.analysis
                .signals
                .iter()
                .any(|s| self.on_signals.contains(&s.kind));
        if !band && !signal_hit {
            return false;
        }
        if let Some((ts, _)) = self.cache.lock().unwrap().get(&r.event.client_ip) {
            if ts.elapsed() < self.cache_ttl {
                return false;
            }
        }
        let mut quota = self.quota.lock().unwrap();
        if quota.0.elapsed() >= Duration::from_secs(3600) {
            *quota = (Instant::now(), 0);
        }
        if quota.1 >= self.max_per_hour {
            return false;
        }
        quota.1 += 1;
        true
    }

    /// Check the IP (cache-aware).
    async fn evaluate(&self, ip: IpAddr) -> Option<u8> {
        if let Some((ts, score)) = self.cache.lock().unwrap().get(&ip) {
            if ts.elapsed() < self.cache_ttl {
                return Some(*score);
            }
        }
        let _permit = self.semaphore.acquire().await;
        match self.provider.check(ip).await {
            Ok(res) => {
                let mut cache = self.cache.lock().unwrap();
                cache.retain(|_, (ts, _)| ts.elapsed() < self.cache_ttl);
                cache.insert(ip, (Instant::now(), res.score));
                Some(res.score)
            }
            Err(e) => {
                warn!(provider = self.provider.name(), ip = %ip, error = %e, "ip lookup failed");
                None
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
            let started = Instant::now();
            let Some(score) = fork.evaluate(base.event.client_ip).await else {
                return;
            };
            fork.metrics.record_fork("ip_lookup", started.elapsed());
            // Provider confidence scales the weight: 25% ≈ +10, 100% ≈ +40.
            let weight = ((u16::from(score) * 40) / 100).min(40) as u8;
            if weight == 0 {
                return;
            }
            let signals = vec![sentry_core::Signal {
                kind: sentry_core::SignalKind::ExternalReputation,
                weight,
                detail: Some(format!("{} confidence_score={score}", fork.provider.name())),
            }];
            let updated = pipeline.rescore_from(&base, signals);
            if updated.decision.action == base.decision.action {
                return;
            }
            info!(
                ip = %base.event.client_ip,
                from = ?base.decision.action,
                to = ?updated.decision.action,
                score = updated.analysis.risk_score,
                "ip lookup changed verdict"
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
                    warn!(error = %e, "ip lookup fork: failed to update event verdict");
                }
            }
            for action in registry.actions() {
                if action.applies_to(&updated.decision) {
                    let ctx = incident_context(&repo, &updated).await;
                    if let Err(e) = action
                        .execute_with_context(&updated.event, &updated.decision, &ctx)
                        .await
                    {
                        warn!(action = action.name(), error = %e, "ip lookup fork action failed");
                    }
                }
            }
        });
    }
}

/// Build the IP lookup fork from `[ip_lookup]` config when enabled.
fn build_ip_lookup_fork(
    cfg: &SentryConfig,
    metrics: &crate::metrics::Metrics,
) -> Option<Arc<IpLookupFork>> {
    let ilc = &cfg.ip_lookup;
    if !ilc.enabled {
        return None;
    }
    if ilc.provider != "abuseipdb" {
        warn!(provider = %ilc.provider, "unknown ip_lookup provider — fork disabled");
        return None;
    }
    let key = std::env::var(&ilc.key_env)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(key) = key else {
        warn!(env = %ilc.key_env, "ip_lookup key unset — fork disabled");
        return None;
    };
    let on_signals = ilc
        .on_signals
        .iter()
        .filter_map(|name| {
            serde_json::from_value::<sentry_core::analysis::SignalKind>(serde_json::Value::String(
                name.clone(),
            ))
            .map_err(|_| warn!(signal = %name, "unknown ip_lookup on_signals kind — skipped"))
            .ok()
        })
        .collect();
    info!(
        provider = "abuseipdb",
        trigger_above = ilc.trigger_above,
        max_per_hour = ilc.max_per_hour,
        "ip lookup fork enabled"
    );
    Some(Arc::new(IpLookupFork {
        provider: Arc::new(sentry_ai::AbuseIpDbLookup::new(key, None)),
        trigger_above: ilc.trigger_above,
        cache_ttl: Duration::from_secs(ilc.cache_ttl_secs),
        max_per_hour: ilc.max_per_hour.max(1),
        semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
        cache: std::sync::Mutex::new(HashMap::new()),
        quota: std::sync::Mutex::new((Instant::now(), 0)),
        on_signals,
        metrics: metrics.clone(),
    }))
}

/// Thin wrapper so the daemon can call the metrics server without importing
/// the crate-internal module path in every call site.
async fn serve_metrics(
    m: crate::metrics::Metrics,
    log: crate::eventlog::EventLog,
    addr: std::net::SocketAddr,
) {
    crate::metrics::serve(m, log, addr).await;
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

/// Load every enabled DB dataset (F7.7) and build its synthetic rule.
///
/// Returns the rules plus the user-agent/path literals that feed the
/// dynamic prefilter.
async fn db_dataset_rules(
    repo: &sentry_storage::Repo,
) -> color_eyre::Result<(Vec<sentry_core::rules::Rule>, Vec<String>, Vec<String>)> {
    let rows = repo.datasets().list().await?;
    let mut out = Vec::new();
    let mut user_agents = Vec::new();
    let mut paths = Vec::new();
    for ds in rows.iter().filter(|d| d.enabled) {
        let entries = repo.datasets().entries(&ds.name).await.unwrap_or_default();
        let kind = match ds.kind.as_str() {
            "user_agent" => sentry_core::config::FeedKind::UserAgent,
            "ja3" => sentry_core::config::FeedKind::Ja3,
            _ => sentry_core::config::FeedKind::Path,
        };
        let feed = sentry_core::config::FeedConfig {
            name: ds.name.clone(),
            kind,
            action: ds.action.clone(),
            ..Default::default()
        };
        match sentry_core::reputation::dataset_rule(&feed, &entries) {
            Ok(Some(mut rule)) => {
                rule.id = format!("dataset:{}", ds.name);
                rule.name = format!("dataset `{}` ({} entries)", ds.name, entries.len());
                match kind {
                    sentry_core::config::FeedKind::UserAgent => {
                        user_agents.extend(entries.iter().cloned())
                    }
                    sentry_core::config::FeedKind::Path => paths.extend(entries.iter().cloned()),
                    _ => {}
                }
                out.push(rule);
            }
            Ok(None) => {}
            Err(e) => warn!(dataset = %ds.name, error = %e, "invalid dataset rule — skipped"),
        }
    }
    Ok((out, user_agents, paths))
}

/// Background task: LISTEN for `sentry_datasets_changed` notifications (F7.7)
/// and hot-reload the synthetic dataset rules + prefilter literals.
///
/// The CLI `sentry datasets …` commands and the nightly re-fetch emit the
/// notification; the shared ruleset is updated in place (rules with the
/// `dataset:` id prefix are replaced atomically).
async fn datasets_hot_reload(pool: sentry_storage::PgPool, rules: SharedRuleSet) {
    const CHANNEL: &str = "sentry_datasets_changed";
    loop {
        match pool.listen(CHANNEL).await {
            Ok(mut listener) => {
                info!(
                    channel = CHANNEL,
                    "listening for dataset change notifications"
                );
                while listener.recv().await.is_ok() {
                    let repo = sentry_storage::Repo::new(pool.clone());
                    match db_dataset_rules(&repo).await {
                        Ok((fresh, uas, paths)) => {
                            let n = {
                                let mut guard = rules.write().unwrap();
                                guard.replace_by_prefix("dataset:", fresh)
                            };
                            sentry_core::heuristics::reload_dataset_lists(&uas, &paths);
                            info!(rule_count = n, "dataset rules + prefilter hot-reloaded");
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to reload datasets from db");
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

/// Background task: LISTEN for `sentry_blocks_changed` notifications and
/// hot-reload the block table from `ip_state`.
///
/// The dashboard/CLI block endpoints and the daemon's own block mirror emit
/// the notification; `ip_state` stays the source of truth, the table is its
/// in-memory cache.
async fn blocks_hot_reload(pool: sentry_storage::PgPool, table: Arc<sentry_core::BlockTable>) {
    const CHANNEL: &str = "sentry_blocks_changed";
    loop {
        match pool.listen(CHANNEL).await {
            Ok(mut listener) => {
                info!(
                    channel = CHANNEL,
                    "listening for block change notifications"
                );
                while let Ok(_notif) = listener.recv().await {
                    let repo = sentry_storage::Repo::new(pool.clone());
                    match repo.ip_state().blocked(10_000).await {
                        Ok(rows) => {
                            let now = chrono::Utc::now();
                            let entries: Vec<(IpAddr, Option<std::time::Instant>)> = rows
                                .iter()
                                .filter_map(|r| {
                                    let ip = r.ip.parse::<IpAddr>().ok()?;
                                    let exp = match r.expires_at {
                                        None => None,
                                        Some(ts) => {
                                            let Ok(remaining) = (ts - now).to_std() else {
                                                return None;
                                            };
                                            Some(std::time::Instant::now() + remaining)
                                        }
                                    };
                                    Some((ip, exp))
                                })
                                .collect();
                            let count = entries.len();
                            table.reload(entries);
                            info!(blocked = count, "block table hot-reloaded from db");
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to reload block table from db");
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

/// Well-known port → service name, for non-HTTP event lines.
fn port_service(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        465 | 587 => "smtps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => "",
    }
}

/// Human summary of the protocol payload for non-HTTP events:
/// service/port when known (e.g. `tcp/ssh`), app-name for syslog,
/// SNI for TLS, otherwise the protocol name.
fn protocol_summary(evt: &Event) -> String {
    match &evt.protocol {
        ProtocolData::Http(_) => String::new(),
        ProtocolData::Tcp(_) => match evt.server_port {
            Some(p) => {
                let svc = port_service(p);
                if svc.is_empty() {
                    format!("tcp/{p}")
                } else {
                    format!("tcp/{svc}")
                }
            }
            None => "tcp".into(),
        },
        ProtocolData::Udp(d) => match (&d.dns_query, evt.server_port) {
            (Some(q), _) => format!("udp/dns {q}"),
            (None, Some(p)) => format!("udp/{p}"),
            (None, None) => "udp".into(),
        },
        ProtocolData::TlsHandshake(d) => match &d.sni {
            Some(sni) => format!("tls {sni}"),
            None => "tls".into(),
        },
        ProtocolData::Syslog(d) => match &d.app_name {
            Some(app) => format!("syslog {app}"),
            None => "syslog".into(),
        },
        ProtocolData::Raw(d) if !d.note.is_empty() => format!("raw {}", d.note),
        ProtocolData::Raw(_) => "raw".into(),
    }
}

/// Format a signal for the event line: `RuleHit(rule_id)` when there is a
/// detail, bare kind name otherwise. Details are truncated to keep the
/// console line readable.
fn format_signal(s: &Signal) -> String {
    const MAX_DETAIL: usize = 48;
    match &s.detail {
        Some(d) if !d.is_empty() => {
            let short: String = d.chars().take(MAX_DETAIL).collect();
            let ellipsis = if d.chars().count() > MAX_DETAIL {
                "…"
            } else {
                ""
            };
            format!("{:?}({short}{ellipsis})", s.kind)
        }
        _ => format!("{:?}", s.kind),
    }
}

/// Print (or suppress) the event console line according to the matching
/// rule's `log_level`: `silent` drops the line entirely (the event is still
/// persisted and dispatched to actions), `warn`/`error` route the line
/// through tracing at that level, `info`/absent prints the colored line.
fn print_event(
    evt: &Event,
    level: &RiskLevel,
    signals: &[Signal],
    log_level: Option<RuleLogLevel>,
    process: Option<Duration>,
) {
    if matches!(log_level, Some(RuleLogLevel::Silent)) {
        return;
    }
    let label = level.label();

    let source = evt.source.as_str();
    let (method, path, status) = if let Some(h) = evt.http() {
        (
            h.method
                .map(|m| format!("{m:?}"))
                .unwrap_or_else(|| "???".into()),
            h.path.clone(),
            h.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
        )
    } else {
        (String::new(), protocol_summary(evt), "-".into())
    };
    let ip = evt.client_ip;

    let signal_str = if signals.is_empty() {
        String::new()
    } else {
        format!(
            " [{}]",
            signals
                .iter()
                .map(format_signal)
                .collect::<Vec<_>>()
                .join(",")
        )
    };

    let mut timing = String::new();
    if let Some(ms) = evt.duration_ms {
        timing.push_str(&format!(" {ms}ms"));
    }
    if let Some(d) = process {
        timing.push_str(&format!(" ({})", fmt_duration(d)));
    }

    let line = format!(
        "{label:4} {ip:15} [{source:8}] {method:6} {path:40} {status:3}{timing}{signal_str}"
    );
    match log_level {
        Some(RuleLogLevel::Warn) => warn!("{line}"),
        Some(RuleLogLevel::Error) => error!("{line}"),
        _ => {
            let color = level.ansi_color();
            println!("{color}{line}\x1b[0m");
        }
    }
}

/// Human-friendly duration for the console line (`823µs`, `1.2ms`, `3.4s`).
fn fmt_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros < 1_000 {
        format!("{micros}µs")
    } else if micros < 1_000_000 {
        format!("{:.1}ms", micros as f64 / 1_000.0)
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

/// Resolve the dispatch lane for one `[[action]]` config entry.
///
/// Defaults by kind/provider — local containment (blocklist, log, kernel
/// firewall) runs inline in the ingest hot loop; network side effects
/// (Cloudflare/nginx/OPNsense APIs, webhooks, abuse reports) defer to the
/// post-processing workers. An explicit `dispatch = "inline"|"deferred"` in
/// the config always wins.
fn resolve_dispatch(
    act: &sentry_core::config::ActionConfig,
    provider: Option<&str>,
) -> ActionDispatch {
    let default = match act.kind {
        ActionKind::Blocklist | ActionKind::Log => ActionDispatch::Inline,
        ActionKind::Cloudflare
        | ActionKind::Webhook
        | ActionKind::Report
        | ActionKind::Challenge => match provider {
            Some("firewall") => ActionDispatch::Inline,
            _ => ActionDispatch::Deferred,
        },
    };
    act.dispatch.unwrap_or(default)
}

/// Build the plugin registry from config.
///
/// Returns the registry plus, when configured, handles to the concrete
/// local providers (`CloudflareProvider` for the background reaper and CLI
/// status commands; `FirewallProvider` for the DB reconcile loop).
fn build_registry(
    cfg: &SentryConfig,
    block_table: Arc<sentry_core::BlockTable>,
    trust: &sentry_core::SharedTrustSet,
) -> color_eyre::Result<RegistryBundle> {
    let mut builder = RegistryBuilder::new();
    let mut cf_provider: Option<Arc<sentry_action_cloudflare::CloudflareProvider>> = None;
    let mut fw_provider: Option<Arc<sentry_action_firewall::FirewallProvider>> = None;
    let mut nginx_provider: Option<Arc<sentry_action_nginx::NginxProvider>> = None;

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
                        trust: Some(trust.clone()),
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
                let channel_buffer = src
                    .options
                    .get("channel_buffer")
                    .and_then(|v| v.as_integer())
                    .map(|v| v.max(64) as usize)
                    .unwrap_or(sentry_source_tcp::DEFAULT_CHANNEL_BUFFER);
                let ts =
                    sentry_source_tcp::TcpCaptureSource::new(sentry_source_tcp::TcpSourceConfig {
                        interface,
                        ports,
                        payload_cap,
                        flow_cap,
                        channel_buffer,
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
                let ttl = Duration::from_secs(blocklist_ttl_secs(cfg));
                builder.register_action(
                    sentry_action_blocklist::BlocklistAction::new(
                        sentry_action_blocklist::BlocklistActionConfig { ttl },
                        block_table.clone(),
                    )
                    .with_dispatch(resolve_dispatch(act, None)),
                );
            }
            ActionKind::Report => {
                // Community abuse-database reporting (F7.4): `provider` picks
                // abuseipdb | reportedip; the API key comes from `key_env`.
                // An unset key skips the action with a warning — reporting is
                // opt-in per deployment.
                let provider_name = act.provider.as_deref().unwrap_or("abuseipdb").to_string();
                let Some(provider) = sentry_action_report::ReportProvider::parse(&provider_name)
                else {
                    return Err(color_eyre::eyre::eyre!(
                        "report action: unknown provider `{provider_name}` — known: abuseipdb, reportedip"
                    ));
                };
                let key_env = act
                    .options
                    .get("key_env")
                    .and_then(|v| v.as_str())
                    .unwrap_or(provider.default_key_env())
                    .to_string();
                let key = std::env::var(&key_env)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let Some(key) = key else {
                    warn!(
                        env = key_env,
                        "report provider key unset — report action skipped"
                    );
                    continue;
                };
                let min_verdict = match act.options.get("min_verdict").and_then(|v| v.as_str()) {
                    Some(s) => sentry_action_report::parse_min_verdict(s)
                        .map_err(|e| color_eyre::eyre::eyre!("{e}"))?,
                    None => sentry_core::analysis::Verdict::Block,
                };
                let dedupe_hours = parse_ttl_secs(&act.options, 24).max(1);
                let timeout = parse_ttl_secs(&act.options, 10).max(1);
                let endpoint = act
                    .options
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                builder.register_action(
                    sentry_action_report::ReportAction::new(
                        sentry_action_report::ReportActionConfig {
                            provider,
                            key,
                            min_verdict,
                            dedupe_ttl: Duration::from_secs(dedupe_hours * 3600),
                            timeout: Duration::from_secs(timeout),
                            endpoint,
                        },
                    )
                    .with_dispatch(resolve_dispatch(act, None)),
                );
            }
            ActionKind::Webhook => {
                // The target URL is a credential for hosted chat webhooks
                // (Discord etc.); `url_env` keeps it out of the config file.
                // An unset url_env skips the action with a warning instead of
                // failing the daemon — the alert channel is optional.
                let url = match act.options.get("url_env").and_then(|v| v.as_str()) {
                    Some(env_name) => match std::env::var(env_name)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                    {
                        Some(url) => url,
                        None => {
                            warn!(
                                env = env_name,
                                "webhook url_env unset or empty — webhook action skipped"
                            );
                            continue;
                        }
                    },
                    None => act
                        .options
                        .get("url")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            color_eyre::eyre::eyre!("webhook action requires `url` or `url_env`")
                        })?
                        .to_string(),
                };
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
                builder.register_action(
                    sentry_action_webhook::WebhookAction::new(
                        sentry_action_webhook::WebhookActionConfig {
                            url,
                            on_levels,
                            timeout: Duration::from_secs(timeout),
                            secret,
                        },
                    )
                    .with_dispatch(resolve_dispatch(act, None)),
                );
            }
            ActionKind::Cloudflare => {
                if let Some(built) = build_challenge_action(
                    "cloudflare",
                    &act.options,
                    trust,
                    resolve_dispatch(act, Some("cloudflare")),
                )? {
                    if cf_provider.is_none() {
                        cf_provider = built.provider;
                    }
                    if fw_provider.is_none() {
                        fw_provider = built.firewall;
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
                if let Some(built) = build_challenge_action(
                    provider,
                    &act.options,
                    trust,
                    resolve_dispatch(act, Some(provider)),
                )? {
                    if cf_provider.is_none() {
                        cf_provider = built.provider;
                    }
                    if fw_provider.is_none() {
                        fw_provider = built.firewall;
                    }
                    if nginx_provider.is_none() {
                        nginx_provider = built.nginx;
                    }
                    builder.register_action(built.action);
                }
            }
        }
    }

    if log_requested || cfg.actions.is_empty() {
        builder.register_action(LogAction);
    }

    Ok(RegistryBundle {
        registry: builder.build(),
        cf_provider,
        fw_provider,
        nginx_provider,
    })
}

/// Effective blocklist TTL: `ttl_secs` of the first `[[action]]
/// type = "blocklist"`, else the 24 h default. Shared by the action, the
/// DB mirror and the pre-warm so all three agree on how long a block lasts.
fn blocklist_ttl_secs(cfg: &SentryConfig) -> u64 {
    cfg.actions
        .iter()
        .find(|a| a.kind == ActionKind::Blocklist)
        .map(|a| parse_ttl_secs(&a.options, 86_400))
        .unwrap_or(86_400)
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

/// Build the firewall reconcile map from `ip_state` rows: IP → remaining
/// ban TTL in seconds (`None` = permanent).
fn expected_firewall_entries(
    rows: &[sentry_storage::repo::IpStateRow],
) -> HashMap<IpAddr, Option<u64>> {
    let now = chrono::Utc::now();
    rows.iter()
        .filter_map(|r| {
            let ip = r.ip.parse::<IpAddr>().ok()?;
            let ttl = r
                .expires_at
                .map(|ts| (ts - now).num_seconds().max(1) as u64);
            Some((ip, ttl))
        })
        .collect()
}

/// Locally-constructed provider handles returned alongside the registry.
struct RegistryBundle {
    registry: sentry_core::registry::Registry,
    cf_provider: Option<Arc<sentry_action_cloudflare::CloudflareProvider>>,
    fw_provider: Option<Arc<sentry_action_firewall::FirewallProvider>>,
    nginx_provider: Option<Arc<sentry_action_nginx::NginxProvider>>,
}

type ProviderHandles = (
    Arc<dyn ChallengeProvider>,
    Option<Arc<sentry_action_cloudflare::CloudflareProvider>>,
    Option<Arc<sentry_action_firewall::FirewallProvider>>,
    Option<Arc<sentry_action_nginx::NginxProvider>>,
);

fn build_challenge_action(
    provider_name: &str,
    options: &HashMap<String, toml::Value>,
    trust: &sentry_core::SharedTrustSet,
    dispatch: ActionDispatch,
) -> color_eyre::Result<Option<ChallengeActionWithProvider>> {
    let ttl = Duration::from_secs(parse_ttl_secs(options, 86400));
    let mode = parse_edge_mode(options);
    let opts = EdgeOptions { ttl, mode };

    let (provider, cf_concrete, fw_concrete, nginx_concrete): ProviderHandles = match provider_name
    {
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
            (cf.clone(), Some(cf), None, None)
        }
        "firewall" => {
            // Local kernel-level enforcement (F7.3): nftables/ipset/
            // firewalld. Linux-only; needs CAP_NET_ADMIN (see deploy docs).
            if !cfg!(target_os = "linux") {
                warn!("firewall provider is Linux-only — skipping");
                return Ok(None);
            }
            let backend = match options.get("backend").and_then(|v| v.as_str()) {
                Some(s) => sentry_action_firewall::FirewallBackend::parse(s)
                    .ok_or_else(|| {
                        color_eyre::eyre::eyre!(
                            "firewall action: unknown backend `{s}` — known: auto, nftables, ipset, firewalld"
                        )
                    })?,
                None => None,
            };
            let rate_limit_ttl = Duration::from_secs(parse_ttl_secs(options, 600));
            let fw = Arc::new(sentry_action_firewall::FirewallProvider::new(
                sentry_action_firewall::FirewallConfig {
                    backend,
                    ttl,
                    rate_limit_ttl,
                    table: options
                        .get("table")
                        .and_then(|v| v.as_str())
                        .unwrap_or("sentry")
                        .to_string(),
                    set_prefix: options
                        .get("set_prefix")
                        .and_then(|v| v.as_str())
                        .unwrap_or("sentry_blocks")
                        .to_string(),
                },
                Some(trust.clone()),
            ));
            (fw.clone(), None, Some(fw), None)
        }
        "nginx" => {
            // Config-generation provider (F7.8): deny-list + JS-challenge
            // geo map includes for a co-located nginx (getpagespeed
            // modules on the host), with a debounced validate/reload.
            let conf_dir = options
                .get("conf_dir")
                .and_then(|v| v.as_str())
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/etc/nginx/conf.d/sentry"));
            let reload_cmd = options
                .get("reload_cmd")
                .and_then(|v| v.as_str())
                .unwrap_or("nginx -s reload")
                .to_string();
            let validate = options
                .get("validate")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let rate_limit_deny = options
                .get("rate_limit_deny")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let provision_bots = options
                .get("provision_bots")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let geo_var = options
                .get("geo_var")
                .and_then(|v| v.as_str())
                .unwrap_or("$sentry_challenge_ip")
                .to_string();
            let ng = sentry_action_nginx::NginxProvider::new(
                sentry_action_nginx::NginxConfig {
                    conf_dir,
                    reload_cmd,
                    validate,
                    ttl,
                    rate_limit_deny,
                    ipv6_prefix: parse_ipv6_prefix(options),
                    geo_var,
                    provision_bots,
                },
                Some(trust.clone()),
            );
            info!(
                conf_dir = %ng.config().conf_dir.display(),
                "nginx provider enabled (deny + challenge includes)"
            );
            (ng.clone(), None, None, Some(ng))
        }
        "opnsense" | "pfsense" => {
            // Firewall-appliance enforcement (F6.1): OPNsense alias_util
            // REST or pfSense pfctl table. Drop-only platform: Challenge/
            // RateLimit verdicts are logged as unenforced.
            let platform = if provider_name == "opnsense" {
                sentry_action_opnsense::Platform::Opnsense
            } else {
                sentry_action_opnsense::Platform::Pfsense
            };
            let opt_str = |key: &str, default: &str| {
                options
                    .get(key)
                    .and_then(|v| v.as_str())
                    .unwrap_or(default)
                    .to_string()
            };
            let opn = sentry_action_opnsense::OpnsenseProvider::new(
                sentry_action_opnsense::OpnsenseConfig {
                    platform,
                    base_url: opt_str("base_url", ""),
                    api_key_env: opt_str("api_key_env", "SENTRY_OPN_API_KEY"),
                    api_secret_env: opt_str("api_secret_env", "SENTRY_OPN_API_SECRET"),
                    table: opt_str("table", "sentry_blocks"),
                    pfctl_path: opt_str("pfctl_path", "pfctl"),
                    accept_invalid_certs: options
                        .get("accept_invalid_certs")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                },
                Some(trust.clone()),
            );
            if platform == sentry_action_opnsense::Platform::Opnsense
                && opn.config().base_url.is_empty()
            {
                return Err(color_eyre::eyre::eyre!(
                    "opnsense action requires [action.options] base_url (e.g. \"https://192.0.2.10\")"
                ));
            }
            (opn, None, None, None)
        }
        other => {
            return Err(color_eyre::eyre::eyre!(
                "unknown challenge provider `{other}` — known: cloudflare, firewall, opnsense, pfsense, nginx"
            ));
        }
    };

    Ok(Some(ChallengeActionWithProvider {
        action: ChallengeAction::new(provider, opts).with_dispatch(dispatch),
        provider: cf_concrete,
        firewall: fw_concrete,
        nginx: nginx_concrete,
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

    fn dispatch(&self) -> ActionDispatch {
        // A tracing line is local and instant — hot-path work.
        ActionDispatch::Inline
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

/// Metrics handles for the protocol validator (F9).
fn protocol_metrics_handles(
    metrics: &crate::metrics::Metrics,
) -> Option<sentry_edge::protocol::ProtocolMetrics> {
    Some(sentry_edge::protocol::ProtocolMetrics {
        violations: metrics.protocol_violations.clone(),
        frames: metrics.protocol_frames.clone(),
    })
}

/// Watches the schema directory and hot-swaps the compiled set on
/// add/modify/remove. `notify` events coalesce through a debounce window;
/// a safety poll catches lost events. A failed compile keeps the previous
/// set (all-or-nothing).
async fn protocol_watcher(
    cfg: sentry_core::config::ProtocolConfig,
    engine: Arc<sentry_protocol::ProtocolEngine>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(64);
    let watch_dir = cfg.dir.clone();
    let watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
        if res.is_ok() {
            let _ = tx.try_send(());
        }
    });
    let mut watcher = match watcher {
        Ok(w) => {
            let mut w = w;
            match w.watch(&watch_dir, notify::RecursiveMode::NonRecursive) {
                Ok(()) => Some(w),
                Err(e) => {
                    warn!(error = %e, dir = %watch_dir.display(), "protocol watch failed; using safety poll only");
                    None
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "protocol watcher unavailable; using safety poll only");
            None
        }
    };
    let _ = &mut watcher; // dropping the watcher stops the watch

    let debounce = Duration::from_millis(cfg.debounce_ms.max(100));
    let safety = Duration::from_secs(cfg.safety_poll_secs.max(10));
    let mut fingerprint = dir_fingerprint(&cfg.dir);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(safety) => {}
            _ = rx.recv() => {
                // Coalesce bursts of fs events within the debounce window.
                while matches!(
                    tokio::time::timeout(debounce, rx.recv()).await,
                    Ok(Some(()))
                ) {}
            }
        }
        let fresh = dir_fingerprint(&cfg.dir);
        if fresh == fingerprint {
            continue;
        }
        fingerprint = fresh;
        match crate::protocol_cmd::compile_dir(&cfg.dir, cfg.max_schemas) {
            Ok((compiled, errors)) if errors.is_empty() => {
                let n = compiled.protocols.len();
                engine.swap(compiled);
                info!(schemas = n, "protocol schemas hot-reloaded");
            }
            Ok((_, errors)) => {
                for e in &errors {
                    warn!(error = %e, "protocol reload skipped: schema error");
                }
            }
            Err(e) => warn!(error = %e, "protocol reload scan failed"),
        }
    }
}

/// Stable fingerprint of a schema directory: file set + mtime + size.
fn dir_fingerprint(dir: &std::path::Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut entries: Vec<(u64, u64)> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .filter_map(|m| {
                    Some((
                        m.modified()
                            .ok()?
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()?
                            .as_nanos() as u64,
                        m.len(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    for (t, l) in &entries {
        (t, l).hash(&mut h);
    }
    let count = entries.len() as u64;
    count.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::instance_label;
    use super::IpLookupFork;
    use sentry_core::analysis::{AnalysisResult, Decision, Signal, SignalKind, Verdict};
    use sentry_core::event::{HttpData, ProtocolData, SourceKind};
    use sentry_core::pipeline::ProcessedEvent;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;

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

    struct NoopLookup;

    #[async_trait::async_trait]
    impl sentry_ai::IpLookupProvider for NoopLookup {
        fn name(&self) -> &'static str {
            "noop"
        }
        async fn check(&self, _ip: IpAddr) -> Result<sentry_ai::IpLookupResult, String> {
            Ok(sentry_ai::IpLookupResult {
                score: 80,
                provider: "noop",
            })
        }
    }

    fn fork(trigger_above: u8, on_signals: Vec<SignalKind>, max_per_hour: u32) -> IpLookupFork {
        IpLookupFork {
            provider: Arc::new(NoopLookup),
            trigger_above,
            cache_ttl: Duration::from_secs(3600),
            max_per_hour,
            semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            quota: std::sync::Mutex::new((std::time::Instant::now(), 0)),
            on_signals,
            metrics: crate::metrics::Metrics::new(),
        }
    }

    fn processed(ip: IpAddr, score: u8, signals: Vec<Signal>) -> ProcessedEvent {
        let analysis = AnalysisResult {
            risk_score: score,
            signals,
            ..AnalysisResult::default()
        };
        let evt = sentry_core::Event::new(
            SourceKind::Synthetic,
            ip,
            ProtocolData::Http(HttpData::default()),
        );
        ProcessedEvent {
            event: evt,
            decision: Decision {
                analysis: analysis.clone(),
                action: Verdict::Allow,
                override_reason: None,
                log_level: None,
            },
            analysis,
            rule_hit: None,
        }
    }

    #[test]
    fn gray_band_triggers_block_does_not() {
        let f = fork(25, Vec::new(), 100);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(f.should_run(&processed(ip, 30, Vec::new())));
        assert!(!f.should_run(&processed(ip, 10, Vec::new())));
        let blocked = processed(ip, 100, Vec::new());
        // A Block verdict already acted — no quota spent.
        assert!(!f.should_run(&ProcessedEvent {
            decision: Decision {
                analysis: blocked.analysis.clone(),
                action: Verdict::Block,
                override_reason: None,
                log_level: None,
            },
            ..blocked
        }));
    }

    #[test]
    fn signal_trigger_beats_low_score() {
        let f = fork(25, vec![SignalKind::SensitivePath], 100);
        let ip: IpAddr = "203.0.113.6".parse().unwrap();
        let hit = processed(
            ip,
            5,
            vec![Signal {
                kind: SignalKind::SensitivePath,
                weight: 30,
                detail: None,
            }],
        );
        assert!(f.should_run(&hit));
    }

    #[test]
    fn quota_is_per_rolling_hour() {
        let f = fork(25, Vec::new(), 2);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(f.should_run(&processed(ip, 30, Vec::new())));
        assert!(f.should_run(&processed(ip, 31, Vec::new())));
        assert!(!f.should_run(&processed(ip, 32, Vec::new())));
    }

    #[tokio::test]
    async fn evaluate_caches_per_ip() {
        let f = fork(25, Vec::new(), 100);
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        assert_eq!(f.evaluate(ip).await, Some(80));
        assert_eq!(f.evaluate(ip).await, Some(80));
        assert_eq!(f.cache.lock().unwrap().len(), 1);
    }
}
