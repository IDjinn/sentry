//! Live config reload (F17): the daemon re-reads `sentry.conf` when a
//! config file changes (or on `SIGHUP`) and applies the sections that can be
//! swapped without dropping traffic — rule packs and custom rules, known
//! routes, and the inline edge's routing table (sites, locations, upstream
//! groups, location security). Everything else keeps running with its
//! startup value and is reported as "restart required".
//!
//! A reload is all-or-nothing per section: a config that fails to load or
//! validate is rejected and the running state stays as it was.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use sentry_core::config::{RouteDefConfig, SentryConfig};
use sentry_core::rules::{Rule, RuleSource, SharedRuleSet};
use sentry_core::{Pipeline, RouteValidator};
use sentry_edge::proxy::{EdgeProxyConfig, RouteReloader};
use serde::Serialize;
use tracing::{info, warn};

/// How often the config files are checked for changes.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Wait after a detected change so editors that write in several steps
/// (truncate, write, rename) settle before the file is parsed.
const DEBOUNCE: Duration = Duration::from_millis(400);

/// What a config change touches.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReloadPlan {
    /// `rules.pack` / `rules.custom` changed.
    pub rules: bool,
    /// `routes.known` changed.
    pub routes: bool,
    /// The inline edge routing (sites, upstreams, location security) changed.
    pub edge_routing: bool,
    /// Sections that changed but only take effect after a restart.
    pub restart: Vec<String>,
}

impl ReloadPlan {
    /// Nothing changed at all.
    pub fn is_empty(&self) -> bool {
        !self.rules && !self.routes && !self.edge_routing && self.restart.is_empty()
    }

    /// Names of the sections applied live.
    pub fn live(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.rules {
            out.push("rules");
        }
        if self.routes {
            out.push("routes");
        }
        if self.edge_routing {
            out.push("http routing");
        }
        out
    }
}

fn differs<T: Serialize>(a: &T, b: &T) -> bool {
    serde_json::to_value(a).ok() != serde_json::to_value(b).ok()
}

fn section_label(key: &str) -> String {
    match key {
        "edge" => "http".to_string(),
        other => other.to_string(),
    }
}

/// Keys of `a` and `b` (JSON objects) whose values differ.
fn differing_keys(a: &serde_json::Value, b: &serde_json::Value) -> Vec<String> {
    let (Some(ao), Some(bo)) = (a.as_object(), b.as_object()) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = ao.keys().chain(bo.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| ao.get(*k) != bo.get(*k))
        .cloned()
        .collect()
}

/// Compare the running config with a freshly loaded one.
pub fn plan(running: &SentryConfig, new: &SentryConfig) -> ReloadPlan {
    let mut plan = ReloadPlan::default();
    let (Ok(old_v), Ok(new_v)) = (serde_json::to_value(running), serde_json::to_value(new)) else {
        plan.restart.push("config (not comparable)".into());
        return plan;
    };

    for key in differing_keys(&old_v, &new_v) {
        match key.as_str() {
            "rules" => {
                if differs(&running.rules.packs, &new.rules.packs)
                    || differs(&running.rules.custom, &new.rules.custom)
                {
                    plan.rules = true;
                }
                if differs(&running.rules.feeds, &new.rules.feeds)
                    || differs(&running.rules.feed_presets, &new.rules.feed_presets)
                {
                    plan.restart.push("rules.feeds".into());
                }
            }
            "routes" => plan.routes = true,
            "edge" => plan_edge(running, new, &mut plan),
            other => plan.restart.push(section_label(other)),
        }
    }
    plan
}

fn plan_edge(running: &SentryConfig, new: &SentryConfig, plan: &mut ReloadPlan) {
    let (old, nw) = (&running.edge, &new.edge);
    let routing_changed = differs(&old.upstream, &nw.upstream)
        || differs(&old.upstreams, &nw.upstreams)
        || differs(&old.balance, &nw.balance)
        || differs(&old.max_fails, &nw.max_fails)
        || differs(&old.fail_timeout_secs, &nw.fail_timeout_secs)
        || differs(&old.vhosts, &nw.vhosts)
        || differs(&old.upstream_groups, &nw.upstream_groups)
        || differs(&old.sites, &nw.sites)
        || differs(&old.security, &nw.security)
        || differs(&old.health_path, &nw.health_path)
        || differs(&old.health_timeout_secs, &nw.health_timeout_secs);

    let mut masked = nw.clone();
    masked.upstream = old.upstream.clone();
    masked.upstreams = old.upstreams.clone();
    masked.balance = old.balance;
    masked.max_fails = old.max_fails;
    masked.fail_timeout_secs = old.fail_timeout_secs;
    masked.vhosts = old.vhosts.clone();
    masked.upstream_groups = old.upstream_groups.clone();
    masked.sites = old.sites.clone();
    masked.security = old.security.clone();
    masked.health_path = old.health_path.clone();
    masked.health_timeout_secs = old.health_timeout_secs;
    if let (Ok(a), Ok(b)) = (serde_json::to_value(old), serde_json::to_value(&masked)) {
        for key in differing_keys(&a, &b) {
            plan.restart.push(format!("http.{key}"));
        }
    }

    if !routing_changed {
        return;
    }
    if !running.deployment.is_inline() {
        return;
    }
    let certs = |c: &SentryConfig| {
        sentry_core::edge_routes::normalized(&c.edge)
            .1
            .iter()
            .map(|s| (s.hosts.clone(), s.tls_cert.clone(), s.tls_key.clone()))
            .collect::<Vec<_>>()
    };
    if certs(running) != certs(new) {
        plan.restart.push("http site TLS certificates".into());
    }
    plan.edge_routing = true;
}

/// The running config after applying the live sections of `new` on top of
/// `running` — what the next reload should compare against, so sections
/// that need a restart keep being reported until one happens.
pub fn merge_live(running: &SentryConfig, new: &SentryConfig, plan: &ReloadPlan) -> SentryConfig {
    let mut out = running.clone();
    if plan.rules {
        out.rules.packs = new.rules.packs.clone();
        out.rules.custom = new.rules.custom.clone();
    }
    if plan.routes {
        out.routes = new.routes.clone();
    }
    if plan.edge_routing {
        let (o, n) = (&mut out.edge, &new.edge);
        o.upstream = n.upstream.clone();
        o.upstreams = n.upstreams.clone();
        o.balance = n.balance;
        o.max_fails = n.max_fails;
        o.fail_timeout_secs = n.fail_timeout_secs;
        o.vhosts = n.vhosts.clone();
        o.upstream_groups = n.upstream_groups.clone();
        o.sites = n.sites.clone();
        o.security = n.security.clone();
        o.health_path = n.health_path.clone();
        o.health_timeout_secs = n.health_timeout_secs;
    }
    out
}

/// Inline edge handles needed to swap its routing table.
pub struct EdgeHandle {
    /// Swaps the running table.
    pub reloader: RouteReloader,
    /// Proxy config the edge started with; routing fields are overridden on
    /// each reload.
    pub base: EdgeProxyConfig,
}

/// Everything a reload swaps into.
pub struct Handles {
    /// Live ruleset.
    pub shared_rules: SharedRuleSet,
    /// Pipeline owning the route validator.
    pub pipeline: Arc<Pipeline>,
    /// Storage (for the DB half of the route merge).
    pub repo: Option<Arc<sentry_storage::Repo>>,
    /// Config routes shared with the routes LISTEN task.
    pub config_routes: Arc<RwLock<Vec<RouteDefConfig>>>,
    /// Inline edge, when running.
    pub edge: Option<EdgeHandle>,
    /// Whether rDNS bot verification is on (changes the default packs).
    pub bot_verify_enabled: bool,
}

/// Every file whose change should trigger a reload.
fn watched_files(path: Option<&Path>) -> Vec<PathBuf> {
    let Ok(resolved) = crate::config::resolve(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in &resolved.files {
        out.push(f.clone());
        out.extend(crate::cmd::included_files(f));
    }
    if let Some(dir) = &resolved.dir {
        out.push(dir.join(crate::config::AUTO_FILE));
        out.push(dir.join(".env"));
        out.push(dir.join(crate::config::CONF_DIR));
    }
    out
}

type Fingerprint = Vec<(PathBuf, Option<(SystemTime, u64)>)>;

fn fingerprint(files: &[PathBuf]) -> Fingerprint {
    files
        .iter()
        .map(|p| {
            let meta = std::fs::metadata(p)
                .ok()
                .and_then(|m| Some((m.modified().ok()?, m.len())));
            (p.clone(), meta)
        })
        .collect()
}

/// Rules derived from `cfg`: default packs + custom rules, plus whatever
/// the live set holds that does not come from the config (DB rules, feed and
/// dataset rules).
fn rebuild_rules(cfg: &SentryConfig, current: &SharedRuleSet, bot_verify: bool) -> usize {
    let mut fresh = sentry_core::packs::build_default_ruleset_with(
        &crate::daemon::pack_modes_of(cfg),
        bot_verify,
    );
    for parsed in sentry_core::rules::rules_from_config(&cfg.rules.custom) {
        match parsed {
            Ok(rule) => fresh.extend(std::iter::once(rule)),
            Err(e) => warn!(error = %e, "invalid custom rule — skipped"),
        }
    }
    let carried: Vec<Rule> = current
        .read()
        .unwrap()
        .iter()
        .filter(|r| {
            r.id.starts_with("feed:")
                || r.id.starts_with("dataset:")
                || !matches!(r.source, RuleSource::DefaultPack | RuleSource::Config)
        })
        .cloned()
        .collect();
    fresh.extend(carried);
    let n = fresh.len();
    *current.write().unwrap() = fresh;
    n
}

fn edge_proxy_cfg(base: &EdgeProxyConfig, cfg: &SentryConfig) -> EdgeProxyConfig {
    let (groups, sites) = sentry_core::edge_routes::normalized(&cfg.edge);
    EdgeProxyConfig {
        groups,
        sites,
        security: cfg.edge.security.clone(),
        balance: cfg.edge.balance,
        max_fails: cfg.edge.max_fails,
        fail_timeout_secs: cfg.edge.fail_timeout_secs,
        health_path: cfg.edge.health_path.clone(),
        health_timeout_secs: cfg.edge.health_timeout_secs,
        ..base.clone()
    }
}

/// Apply `plan` for `new`. Returns the plan with sections that failed to
/// apply cleared, so the caller keeps them out of the running config.
async fn apply(plan: &mut ReloadPlan, new: &SentryConfig, h: &mut Handles) {
    if plan.rules {
        let n = rebuild_rules(new, &h.shared_rules, h.bot_verify_enabled);
        info!(rule_count = n, "config reload: rules applied");
    }
    if plan.routes {
        let rows = match &h.repo {
            Some(repo) => repo.routes().list().await.unwrap_or_else(|e| {
                warn!(error = %e, "config reload: failed to read DB routes — using file routes only");
                Vec::new()
            }),
            None => Vec::new(),
        };
        *h.config_routes.write().unwrap() = new.routes.known.clone();
        let merged = RouteValidator::merge(&new.routes.known, &rows);
        let count = merged.routes().count();
        h.pipeline.swap_routes(merged);
        info!(route_count = count, "config reload: routes applied");
    }
    if plan.edge_routing {
        match &mut h.edge {
            None => plan.edge_routing = false,
            Some(edge) => {
                let errors = new.edge.validate();
                if !errors.is_empty() || !new.edge.has_routes() {
                    warn!(
                        errors = %errors.join("; "),
                        "config reload: http routing rejected — keeping the running table"
                    );
                    plan.edge_routing = false;
                    return;
                }
                let proxy_cfg = edge_proxy_cfg(&edge.base, new);
                match edge.reloader.reload(&proxy_cfg).await {
                    Ok(groups) => {
                        edge.base = proxy_cfg;
                        info!(
                            upstream_groups = groups,
                            "config reload: http routing applied"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "config reload: http routing rejected — keeping the running table");
                        plan.edge_routing = false;
                    }
                }
            }
        }
    }
}

/// Spawn the reload task: polls the config files and listens for `SIGHUP`.
pub fn spawn(config_path: Option<PathBuf>, initial: SentryConfig, mut handles: Handles) {
    tokio::spawn(async move {
        let path = config_path.as_deref();
        let mut running = initial;
        let mut seen = fingerprint(&watched_files(path));
        let hup = Arc::new(tokio::sync::Notify::new());
        #[cfg(unix)]
        {
            let hup = Arc::clone(&hup);
            tokio::spawn(async move {
                let Ok(mut sig) =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                else {
                    return;
                };
                while sig.recv().await.is_some() {
                    hup.notify_one();
                }
            });
        }
        let mut last_restart_note: Vec<String> = Vec::new();
        loop {
            let forced = tokio::select! {
                () = tokio::time::sleep(POLL_INTERVAL) => false,
                () = hup.notified() => true,
            };
            let now = fingerprint(&watched_files(path));
            if !forced && now == seen {
                continue;
            }
            tokio::time::sleep(DEBOUNCE).await;
            seen = fingerprint(&watched_files(path));

            let new = match crate::config::load(path).and_then(|c| {
                crate::config::validate(&c)?;
                Ok(c)
            }) {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "config reload rejected — keeping the running config");
                    continue;
                }
            };
            let mut p = plan(&running, &new);
            if p.is_empty() {
                info!("config reload: no effective change");
                continue;
            }
            apply(&mut p, &new, &mut handles).await;
            running = merge_live(&running, &new, &p);
            if !p.restart.is_empty() && p.restart != last_restart_note {
                warn!(
                    sections = %p.restart.join(", "),
                    "config changed but these sections only take effect after a restart"
                );
            }
            last_restart_note = p.restart.clone();
            if p.live().is_empty() && p.restart.is_empty() {
                info!("config reload: no effective change");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(src: &str) -> SentryConfig {
        sentry_core::conf::from_str(src, "t.conf").unwrap()
    }

    #[test]
    fn identical_configs_plan_nothing() {
        let a = cfg("sentry { mode: passive }\n");
        assert!(plan(&a, &a.clone()).is_empty());
    }

    #[test]
    fn rule_and_route_changes_are_live() {
        let a = cfg("rules { pack sensitive_paths { mode: shadow } }\n");
        let b = cfg("rules { pack sensitive_paths { mode: enforce } }\nroutes { \"/x\": GET }\n");
        let p = plan(&a, &b);
        assert!(p.rules, "{p:?}");
        assert!(p.routes, "{p:?}");
        assert!(!p.edge_routing && p.restart.is_empty(), "{p:?}");
    }

    #[test]
    fn unrelated_sections_need_restart() {
        let a = cfg("metrics { enabled: on }\n");
        let b = cfg("metrics { enabled: off }\n");
        let p = plan(&a, &b);
        assert!(!p.rules && !p.routes && !p.edge_routing);
        assert_eq!(p.restart, ["metrics"]);
    }

    #[test]
    fn merge_live_keeps_restart_only_sections_at_running_values() {
        let a = cfg("metrics { enabled: on }\nrules { pack sensitive_paths { mode: shadow } }\n");
        let b = cfg("metrics { enabled: off }\nrules { pack sensitive_paths { mode: enforce } }\n");
        let p = plan(&a, &b);
        let merged = merge_live(&a, &b, &p);
        assert_eq!(merged.metrics.enabled, a.metrics.enabled);
        assert_eq!(merged.rules.packs[0].mode, "enforce");
        assert_eq!(plan(&merged, &b).restart, ["metrics"]);
    }

    #[test]
    fn edge_routing_is_live_only_when_inline() {
        let passive_a = cfg("http { proxy_pass: http://127.0.0.1:1 }\n");
        let passive_b = cfg("http { proxy_pass: http://127.0.0.1:2 }\n");
        assert!(!plan(&passive_a, &passive_b).edge_routing);

        let a = cfg("sentry { mode: inline }\nhttp { proxy_pass: http://127.0.0.1:1 }\n");
        let b = cfg("sentry { mode: inline }\nhttp { proxy_pass: http://127.0.0.1:2 }\n");
        let p = plan(&a, &b);
        assert!(p.edge_routing, "{p:?}");
        assert!(p.restart.is_empty(), "{p:?}");

        let c = cfg(
            "sentry { mode: inline }\nhttp { proxy_pass: http://127.0.0.1:1\n listen: 0.0.0.0:8081 }\n",
        );
        let p = plan(&a, &c);
        assert!(!p.edge_routing);
        assert_eq!(p.restart, ["http.listen"]);
    }

    #[test]
    fn fingerprint_changes_with_content() {
        let dir = std::env::temp_dir().join(format!("sentry_reload_fp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.conf");
        std::fs::write(&f, "a: 1\n").unwrap();
        let before = fingerprint(std::slice::from_ref(&f));
        std::fs::write(&f, "a: 22\n").unwrap();
        assert_ne!(before, fingerprint(std::slice::from_ref(&f)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
