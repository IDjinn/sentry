//! `ConfFile` ⇄ [`SentryConfig`]: lowering (load) and raising (`config
//! show`, `config migrate`, `sentry auto`).

use std::collections::HashMap;

use sentry_conf::{Bytes, ConfValue, Millis, OneOrMany, OrderedMap, RawBlock, Secs};

use super::schema::*;
use crate::config::*;
use crate::edge_routes::{
    HeaderOps, LocationConfig, LocationKind, LocationRateLimit, MatchCondition, MatchOp,
    MatchSubject, ReturnConfig, RewriteRule, SecurityConfig, SiteConfig, UpstreamGroupConfig,
};

fn set<T>(dst: &mut T, v: Option<T>) {
    if let Some(v) = v {
        *dst = v;
    }
}

fn secs(v: Option<Secs>) -> Option<u64> {
    v.map(|s| s.0)
}

fn millis(v: Option<Millis>) -> Option<u64> {
    v.map(|m| m.0)
}

fn kib(v: Option<Bytes>) -> Option<usize> {
    v.map(|b| (b.0 / 1024) as usize)
}

fn list(v: Option<OneOrMany<String>>) -> Option<Vec<String>> {
    v.map(OneOrMany::into_vec)
}

fn some_list(v: &[String]) -> Option<OneOrMany<String>> {
    Some(OneOrMany(v.to_vec()))
}

/// Split `host:port`, `:port`, `[v6]:port` or a bare port.
pub fn split_listen(text: &str) -> Result<(String, u16), String> {
    let t = text.trim();
    let (host, port) = match t.rsplit_once(':') {
        Some((h, p)) => (h.trim_start_matches('[').trim_end_matches(']'), p),
        None => ("", t),
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("listen `{text}`: expected host:port"))?;
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    Ok((host.to_string(), port))
}

fn join_listen(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `ConfValue` → JSON (options maps). `on/off/yes/no` become booleans and
/// `key: 24h` also yields `key_secs: 86400` when the key has no unit suffix.
pub fn conf_to_json(v: &ConfValue) -> serde_json::Value {
    match v {
        ConfValue::Bool(b) => serde_json::Value::Bool(*b),
        ConfValue::Int(i) => serde_json::Value::from(*i),
        ConfValue::Float(f) => serde_json::Value::from(*f),
        ConfValue::Str(s) => match sentry_conf::de::parse_bool_word(s) {
            Some(b) if !matches!(s.as_str(), "enabled" | "disabled") => serde_json::Value::Bool(b),
            _ => serde_json::Value::String(s.clone()),
        },
        ConfValue::List(items) => {
            serde_json::Value::Array(items.iter().map(conf_to_json).collect())
        }
        ConfValue::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), conf_to_json(v)))
                .collect(),
        ),
    }
}

/// JSON → `ConfValue` (raising options maps).
pub fn json_to_conf(v: &serde_json::Value) -> ConfValue {
    match v {
        serde_json::Value::Null => ConfValue::List(Vec::new()),
        serde_json::Value::Bool(b) => ConfValue::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => ConfValue::Int(i),
            None => ConfValue::Float(n.as_f64().unwrap_or_default()),
        },
        serde_json::Value::String(s) => ConfValue::Str(s.clone()),
        serde_json::Value::Array(items) => {
            ConfValue::List(items.iter().map(json_to_conf).collect())
        }
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, ConfValue)> = map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_conf(v)))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            ConfValue::Map(entries)
        }
    }
}

fn is_duration_literal(s: &str) -> bool {
    let unit_start = s.find(|c: char| !(c.is_ascii_digit() || c == '.'));
    match unit_start {
        Some(i) if i > 0 => matches!(&s[i..], "ms" | "s" | "m" | "h" | "d" | "w"),
        _ => false,
    }
}

fn options_from(entries: &[(String, ConfValue)]) -> HashMap<String, serde_json::Value> {
    let mut out = HashMap::new();
    for (k, v) in entries {
        if let ConfValue::Str(s) = v {
            if !k.ends_with("_secs") && !k.ends_with("_ms") && is_duration_literal(s) {
                if let Some(ms) = sentry_conf::values::parse_duration_ms(s) {
                    out.insert(
                        format!("{k}_secs"),
                        serde_json::Value::from(ms.div_ceil(1000)),
                    );
                    continue;
                }
            }
        }
        out.insert(k.clone(), conf_to_json(v));
    }
    out
}

fn options_to(options: &HashMap<String, serde_json::Value>) -> Vec<(String, ConfValue)> {
    let mut entries: Vec<(String, ConfValue)> = options
        .iter()
        .map(|(k, v)| match (k.strip_suffix("_secs"), v.as_u64()) {
            // `ttl_secs: 86400` reads back as `ttl: 1d` (lowered to the same).
            (Some(base), Some(secs)) if !base.is_empty() && !options.contains_key(base) => (
                base.to_string(),
                ConfValue::Str(sentry_conf::values::format_duration_ms(secs * 1000)),
            ),
            _ => (k.clone(), json_to_conf(v)),
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

fn conf_text(v: &ConfValue) -> Option<String> {
    v.as_text()
}

/// Lower a parsed file set onto the runtime config.
pub fn lower(file: ConfFile) -> Result<SentryConfig, Vec<String>> {
    let mut cfg = SentryConfig::default();
    let mut errors: Vec<String> = Vec::new();

    if let Some(s) = file.sentry {
        set(&mut cfg.deployment.mode, s.mode);
        set(&mut cfg.deployment.instance_id, s.instance_id);
        if let Some(r) = s.runtime {
            set(&mut cfg.runtime.worker_threads, r.worker_threads);
            set(
                &mut cfg.runtime.pin_cores,
                r.pin_cores.map(OneOrMany::into_vec),
            );
            set(&mut cfg.runtime.thread_priority, r.priority);
        }
        if let Some(u) = s.update {
            set(&mut cfg.update.enabled, u.enabled);
            set(&mut cfg.update.interval_secs, secs(u.interval));
            set(&mut cfg.update.repo, u.repo);
            set(&mut cfg.update.auto_restart, u.auto_restart);
        }
        if let Some(a) = s.auto {
            set(&mut cfg.auto.sensitive.skip, list(a.skip));
            set(&mut cfg.auto.sensitive.enable, list(a.enable));
        }
    }

    if let Some(s) = file.server {
        set(&mut cfg.core.data_dir, s.data_directory);
        set(&mut cfg.core.channel_buffer, s.channel_buffer);
        set(&mut cfg.core.action_buffer, s.action_buffer);
        set(&mut cfg.core.action_workers, s.action_workers);
        set(&mut cfg.core.persist_buffer, s.persist_buffer);
        set(&mut cfg.core.dedupe_ttl_secs, secs(s.dedupe_ttl));
        if let Some(g) = s.geo {
            set(&mut cfg.geo.city_db, g.city_db);
            set(&mut cfg.geo.asn_db, g.asn_db);
        }
        if let Some(p) = s.policy {
            set(&mut cfg.policy.info, p.info);
            set(&mut cfg.policy.low, p.low);
            set(&mut cfg.policy.medium, p.medium);
            set(&mut cfg.policy.high, p.high);
            set(&mut cfg.policy.critical, p.critical);
            for o in p.overrides {
                let expr = o.match_.or_else(|| o.labels.first().cloned());
                match (expr, o.verdict) {
                    (Some(expr), Some(verdict)) => cfg.policy.overrides.push(PolicyOverrideConfig {
                        r#match: expr,
                        verdict,
                    }),
                    _ => errors.push(
                        "server › policy › override: needs a DSL expression (label or `match:`) and `verdict:`"
                            .into(),
                    ),
                }
            }
        }
        if let Some(sc) = s.scorer {
            set(&mut cfg.scorer.repetition_bonus, sc.repetition_bonus);
            set(
                &mut cfg.scorer.repetition_window_secs,
                secs(sc.repetition_window),
            );
            if let Some(w) = sc.weights {
                cfg.scorer.weights = w.0.into_iter().collect();
            }
        }
        if let Some(e) = s.escalation {
            set(&mut cfg.escalation.enabled, e.enabled);
            set(&mut cfg.escalation.window_secs, secs(e.window));
            set(&mut cfg.escalation.challenge_at, e.challenge_at);
            set(&mut cfg.escalation.block_at, e.block_at);
            set(&mut cfg.escalation.persist, e.persist);
        }
        if let Some(o) = s.overload {
            set(&mut cfg.overload.enabled, o.enabled);
            set(&mut cfg.overload.queue_pressure, o.queue_pressure);
            set(&mut cfg.overload.release_pressure, o.release_pressure);
            set(&mut cfg.overload.release_secs, secs(o.release));
            set(
                &mut cfg.overload.pg_insert_budget_ms,
                millis(o.pg_insert_budget),
            );
            set(&mut cfg.overload.sample_keep, o.sample_keep);
            set(&mut cfg.overload.coalesce_benign, o.coalesce_benign);
            set(
                &mut cfg.overload.coalesce_window_secs,
                secs(o.coalesce_window),
            );
            set(&mut cfg.overload.coalesce_cap, o.coalesce_cap);
        }
    }

    if let Some(s) = file.storage {
        let pg = &mut cfg.storage.postgres;
        set(&mut pg.url, s.url);
        set(&mut pg.max_connections, s.max_connections);
        set(&mut pg.acquire_timeout_secs, secs(s.acquire_timeout));
        set(&mut pg.statement_timeout_secs, secs(s.statement_timeout));
    }

    if let Some(d) = file.detect {
        lower_detect(d, &mut cfg);
    }

    if let Some(t) = file.trust {
        let r = &mut cfg.real_ip;
        set(&mut r.trusted_proxies, list(t.proxies));
        set(&mut r.cloudflare, t.cloudflare);
        set(&mut r.trusted_ips, list(t.trusted_ips));
        set(&mut r.trusted_lists, list(t.trusted_lists));
        set(&mut r.whitelist, list(t.whitelist));
        set(&mut r.blacklist, list(t.blacklist));
        set(&mut r.shadow, list(t.shadow));
        set(&mut r.refresh_secs, secs(t.refresh));
    }

    if let Some(r) = file.rules {
        lower_rules(r, &mut cfg, &mut errors);
    }

    if let Some(routes) = file.routes {
        for (path, methods) in routes.0 {
            let methods: Vec<String> = methods
                .into_vec()
                .into_iter()
                .filter(|m| !matches!(m.to_ascii_lowercase().as_str(), "any" | "*"))
                .map(|m| m.to_ascii_uppercase())
                .collect();
            cfg.routes.known.push(RouteDefConfig { path, methods });
        }
    }

    for src in file.source {
        let mut entries = src.entries.clone();
        let kind = src
            .labels
            .first()
            .cloned()
            .or_else(|| take_entry(&mut entries, "type"));
        match kind {
            Some(kind) => cfg.sources.push(SourceConfig {
                kind,
                options: options_from(&entries),
            }),
            None => errors.push("source: needs a type label (e.g. `source nginx { … }`)".into()),
        }
    }

    for act in file.action {
        match lower_action(act) {
            Ok(a) => cfg.actions.push(a),
            Err(e) => errors.push(e),
        }
    }

    if let Some(d) = file.dashboard {
        if let Some(l) = d.listen {
            match split_listen(&l) {
                Ok((h, p)) => {
                    cfg.server.host = h;
                    cfg.server.port = p;
                }
                Err(e) => errors.push(format!("dashboard: {e}")),
            }
        }
        set(&mut cfg.server.webhook_secret_env, d.webhook_secret_env);
        if let Some(a) = d.auth {
            let auth = &mut cfg.server.auth;
            set(&mut auth.mode, a.mode);
            set(&mut auth.session_secret_env, a.session_secret_env);
            set(&mut auth.session_ttl_secs, secs(a.session_ttl));
            for u in a.user {
                match (u.labels.first(), u.password_hash) {
                    (Some(name), Some(hash)) => auth.users.push(AuthUserConfig {
                        username: name.clone(),
                        password_hash: hash,
                        role: u.role.unwrap_or_else(|| "viewer".into()),
                    }),
                    _ => errors.push(
                        "dashboard › auth › user: needs a name label and `password_hash:`".into(),
                    ),
                }
            }
            for t in a.token {
                auth.tokens.push(AuthTokenConfig {
                    token_sha256: t.token_sha256.unwrap_or_default(),
                    token_env: t.token_env.unwrap_or_default(),
                    role: t.role.unwrap_or_else(|| "viewer".into()),
                });
            }
        }
    }

    if let Some(m) = file.metrics {
        set(&mut cfg.metrics.enabled, m.enabled);
        if let Some(l) = m.listen {
            match split_listen(&l) {
                Ok((h, p)) => {
                    cfg.metrics.host = h;
                    cfg.metrics.port = p;
                }
                Err(e) => errors.push(format!("metrics: {e}")),
            }
        }
    }

    if let Some(h) = file.http {
        lower_http(h, &mut cfg.edge, &mut errors);
    }

    if let Some(t) = file.tcp {
        cfg.edge.tcp_listen = t.listen;
        cfg.edge.tcp_upstream = t.proxy_pass;
    }

    if errors.is_empty() {
        Ok(cfg)
    } else {
        Err(errors)
    }
}

fn take_entry(entries: &mut Vec<(String, ConfValue)>, key: &str) -> Option<String> {
    let idx = entries.iter().position(|(k, _)| k == key)?;
    conf_text(&entries.remove(idx).1)
}

fn lower_action(block: RawBlock) -> Result<ActionConfig, String> {
    let mut entries = block.entries;
    let kind = block
        .labels
        .first()
        .cloned()
        .or_else(|| take_entry(&mut entries, "type"))
        .ok_or("action: needs a type label (e.g. `action webhook { … }`)")?;
    let kind: ActionKind = serde_json::from_value(serde_json::Value::String(kind.clone()))
        .map_err(|_| {
            format!(
                "action `{kind}`: unknown type (expected blocklist | challenge | webhook | report | log | cloudflare)"
            )
        })?;
    let provider = block
        .labels
        .get(1)
        .cloned()
        .or_else(|| take_entry(&mut entries, "provider"));
    let dispatch = match take_entry(&mut entries, "dispatch") {
        None => None,
        Some(d) => Some(
            serde_json::from_value(serde_json::Value::String(d.clone())).map_err(|_| {
                format!("action {kind}: dispatch `{d}` (expected inline | deferred)")
            })?,
        ),
    };
    if block.labels.len() > 2 {
        return Err(format!(
            "action {kind}: takes at most a type and a provider label"
        ));
    }
    Ok(ActionConfig {
        kind,
        provider,
        dispatch,
        options: options_from(&entries),
    })
}

fn lower_detect(d: DetectBlock, cfg: &mut SentryConfig) {
    if let Some(s) = d.scan {
        set(&mut cfg.scan.enabled, s.enabled);
        set(&mut cfg.scan.window_secs, secs(s.window));
        set(&mut cfg.scan.distinct_paths, s.distinct_paths);
        set(&mut cfg.scan.not_found, s.not_found);
    }
    if let Some(b) = d.behavior {
        let k = &mut cfg.behavior;
        set(&mut k.enabled, b.enabled);
        set(&mut k.window_secs, secs(b.window));
        set(&mut k.auth_failures, b.auth_failures);
        set(&mut k.distinct_uas, b.distinct_uas);
        set(&mut k.wordlist_hits, b.wordlist_hits);
        set(
            &mut k.suspicious_success_min_failures,
            b.suspicious_success_min_failures,
        );
        set(&mut k.login_patterns, list(b.login_patterns));
        set(&mut k.wordlist_paths, list(b.wordlist_paths));
    }
    if let Some(c) = d.correlation {
        set(&mut cfg.correlation.enabled, c.enabled);
        set(&mut cfg.correlation.window_secs, secs(c.window));
    }
    if let Some(b) = d.bot_verification {
        let k = &mut cfg.bot_verification;
        set(&mut k.enabled, b.enabled);
        set(&mut k.cache_ttl_secs, secs(b.cache_ttl));
        set(&mut k.failed_ttl_secs, secs(b.failed_ttl));
        set(&mut k.timeout_ms, millis(b.timeout));
        set(&mut k.batch_size, b.batch_size);
    }
    if let Some(u) = d.uploads {
        let k = &mut cfg.uploads;
        set(&mut k.enabled, u.enabled);
        set(&mut k.mode, u.mode);
        set(&mut k.inspect_kb, kib(u.inspect));
        set(&mut k.max_files, u.max_files);
        set(&mut k.scan_json, u.scan_json);
        set(&mut k.oversize, u.oversize);
        set(&mut k.blocked_extensions, list(u.blocked_extensions));
        set(&mut k.allowed_extensions, list(u.allowed_extensions));
        set(&mut k.allowed_content_types, list(u.allowed_content_types));
        set(&mut k.methods, list(u.methods));
        set(&mut k.allowed_paths, list(u.allowed_paths));
        set(&mut k.allow_extensionless, u.allow_extensionless);
        if let Some(f) = u.flood {
            set(&mut k.flood.window_secs, secs(f.window));
            set(&mut k.flood.max_uploads, f.max_uploads);
            set(
                &mut k.flood.max_total_mb,
                f.max_total.map(|b| (b.0 / (1024 * 1024)) as u32),
            );
        }
    }
    if let Some(p) = d.posture {
        let k = &mut cfg.posture;
        set(&mut k.enabled, p.enabled);
        set(&mut k.mode, p.mode);
        set(&mut k.dedupe_ttl_secs, secs(p.dedupe_ttl));
        set(&mut k.hsts_min_max_age, p.hsts_min_max_age);
        set(&mut k.checks, list(p.checks));
        set(&mut k.hosts, list(p.hosts));
    }
    if let Some(p) = d.protocol {
        let k = &mut cfg.protocol;
        set(&mut k.enabled, p.enabled);
        set(&mut k.dir, p.dir);
        set(&mut k.safety_poll_secs, secs(p.safety_poll));
        set(&mut k.debounce_ms, millis(p.debounce));
        set(&mut k.max_schemas, p.max_schemas);
    }
    if let Some(r) = d.route_learner {
        let k = &mut cfg.route_learner;
        set(&mut k.enabled, r.enabled);
        set(&mut k.interval_secs, secs(r.interval));
        set(&mut k.window_secs, secs(r.window));
        set(&mut k.min_hits, r.min_hits);
        set(&mut k.min_ips, r.min_ips);
    }
    if let Some(a) = d.ai {
        let k = &mut cfg.ai;
        set(&mut k.enabled, a.enabled);
        set(&mut k.model_path, a.model_path);
        set(&mut k.threshold, a.threshold);
        set(&mut k.signal_weight, a.signal_weight);
        set(&mut k.mode, a.mode);
        set(&mut k.trigger, a.trigger);
        set(&mut k.min_score, a.min_score);
        set(&mut k.concurrency, a.concurrency);
        set(&mut k.cache_ttl_secs, secs(a.cache_ttl));
    }
    if let Some(l) = d.llm {
        let k = &mut cfg.llm;
        set(&mut k.provider, l.provider);
        set(&mut k.model, l.model);
        if l.base_url.is_some() {
            k.base_url = l.base_url.filter(|u| !u.is_empty());
        }
        set(&mut k.mode, l.mode);
        set(&mut k.only_above, l.only_above);
        set(&mut k.concurrency, l.concurrency);
        set(&mut k.cache_ttl_secs, secs(l.cache_ttl));
    }
    if let Some(i) = d.ip_lookup {
        let k = &mut cfg.ip_lookup;
        set(&mut k.enabled, i.enabled);
        set(&mut k.provider, i.provider);
        set(&mut k.key_env, i.key_env);
        set(&mut k.trigger_above, i.trigger_above);
        set(&mut k.on_signals, list(i.on_signals));
        set(&mut k.cache_ttl_secs, secs(i.cache_ttl));
        set(&mut k.max_per_hour, i.max_per_hour);
        set(&mut k.timeout_secs, secs(i.timeout));
    }
}

fn lower_rules(r: RulesBlock, cfg: &mut SentryConfig, errors: &mut Vec<String>) {
    let packs = &mut cfg.rules.packs;
    if let Some(map) = r.packs {
        for (name, mode) in map.0 {
            packs.push(RulePackConfig {
                name,
                mode,
                params: HashMap::new(),
            });
        }
    }
    for p in r.pack {
        let Some(name) = p.labels.first().cloned() else {
            errors.push("rules › pack: needs a name (e.g. `pack country_blocklist { … }`)".into());
            continue;
        };
        let mut params = HashMap::new();
        if let Some(c) = p.countries {
            params.insert("countries".to_string(), serde_json::json!(c.into_vec()));
        }
        if let Some(d) = p.domains {
            params.insert("domains".to_string(), serde_json::json!(d.into_vec()));
        }
        match packs.iter_mut().find(|e| e.name == name) {
            Some(existing) => {
                if let Some(m) = p.mode {
                    existing.mode = m;
                }
                existing.params.extend(params);
            }
            None => packs.push(RulePackConfig {
                name,
                mode: p.mode.unwrap_or_else(|| "shadow".into()),
                params,
            }),
        }
    }
    for rule in r.rule {
        let name = rule.labels.first().cloned();
        match (name, rule.match_, rule.action) {
            (Some(name), Some(m), Some(action)) => cfg.rules.custom.push(RuleDefConfig {
                name,
                priority: rule.priority.unwrap_or_default(),
                r#match: m,
                action,
                tags: list(rule.tags).unwrap_or_default(),
                log_level: rule.log,
            }),
            (name, _, _) => errors.push(format!(
                "rules › rule {}: needs a name label, `match:` and `action:`",
                name.unwrap_or_default()
            )),
        }
    }
    set(&mut cfg.rules.feed_presets, list(r.feed_presets));
    for f in r.feed {
        let (Some(name), Some(url)) = (f.labels.first().cloned(), f.url) else {
            errors.push("rules › feed: needs a name label and `url:`".into());
            continue;
        };
        let refresh_hours = f
            .refresh_hours
            .or_else(|| f.refresh.map(|s| (s.0.div_ceil(3600)).max(1) as u32))
            .unwrap_or(24);
        let mut feed = FeedConfig {
            name,
            url,
            refresh_hours,
            ..Default::default()
        };
        set(&mut feed.kind, f.kind);
        set(&mut feed.tier, f.tier);
        set(&mut feed.action, f.action);
        set(&mut feed.enabled, f.enabled);
        if let Some(h) = f.headers_env {
            feed.headers_env = h.0.into_iter().collect();
        }
        cfg.rules.feeds.push(feed);
    }
    if let Some(rl) = r.rate_limit {
        set(&mut cfg.rate_limit.backend, rl.backend);
        set(&mut cfg.rate_limit.redis_url, rl.redis_url);
    }
}

fn lower_security(
    b: Option<SecurityBlock>,
    where_: &str,
    errors: &mut Vec<String>,
) -> SecurityConfig {
    let Some(b) = b else {
        return SecurityConfig::default();
    };
    let mut policy = HashMap::new();
    if let Some(p) = b.policy {
        for (level, v) in [
            ("info", p.info),
            ("low", p.low),
            ("medium", p.medium),
            ("high", p.high),
            ("critical", p.critical),
        ] {
            if let Some(v) = v {
                policy.insert(level.to_string(), v);
            }
        }
    }
    let force_challenge = match b.challenge.as_deref().map(str::to_ascii_lowercase) {
        None => None,
        Some(c) if matches!(c.as_str(), "always" | "on" | "true" | "yes") => Some(true),
        Some(c) if matches!(c.as_str(), "off" | "never" | "false" | "no" | "auto") => Some(false),
        Some(c) => {
            errors.push(format!(
                "{where_} › security: challenge `{c}` (expected always | off)"
            ));
            None
        }
    };
    let rate_limit = match b.rate_limit {
        None => None,
        Some(ConfValue::Map(entries)) => {
            let get = |k: &str| {
                entries
                    .iter()
                    .find(|(key, _)| key == k)
                    .and_then(|(_, v)| conf_text(v))
            };
            let requests = get("requests").and_then(|r| r.parse::<u32>().ok());
            let window = get("window")
                .and_then(|w| sentry_conf::values::parse_duration_ms(&w))
                .map(|ms| ms.div_ceil(1000));
            match (requests, window) {
                (Some(requests), Some(window_secs)) if requests > 0 && window_secs > 0 => {
                    Some(LocationRateLimit {
                        requests,
                        window_secs,
                    })
                }
                _ => {
                    errors.push(format!(
                        "{where_} › security › rate_limit: needs `requests:` and `window:` (or the `100/1m` form)"
                    ));
                    None
                }
            }
        }
        Some(v) => {
            let text = conf_text(&v).unwrap_or_default();
            match LocationRateLimit::parse(&text) {
                Some(rl) => Some(rl),
                None => {
                    errors.push(format!(
                        "{where_} › security: rate_limit `{text}` (expected e.g. 100/1m, 10/s)"
                    ));
                    None
                }
            }
        }
    };
    SecurityConfig {
        mode: b.mode,
        policy,
        force_challenge,
        rate_limit,
        allow: list(b.allow).unwrap_or_default(),
        deny: list(b.deny).unwrap_or_default(),
        packs: b
            .packs
            .map(|p| p.0.into_iter().collect())
            .unwrap_or_default(),
    }
}

fn lower_return(
    values: Vec<ConfValue>,
    redirect: bool,
    where_: &str,
) -> Result<ReturnConfig, String> {
    let texts: Vec<String> = values.iter().filter_map(conf_text).collect();
    let parse_status = |s: &str| s.parse::<u16>().ok();
    match (redirect, texts.as_slice()) {
        (true, [url]) => Ok(ReturnConfig {
            status: 301,
            text: Some(url.clone()),
        }),
        (true, [code, url]) => Ok(ReturnConfig {
            status: parse_status(code)
                .filter(|c| (300..400).contains(c))
                .ok_or_else(|| {
                    format!("{where_}: redirect code `{code}` (expected 301, 302, 307 or 308)")
                })?,
            text: Some(url.clone()),
        }),
        (false, [code]) => Ok(ReturnConfig {
            status: parse_status(code)
                .ok_or_else(|| format!("{where_}: return status `{code}`"))?,
            text: None,
        }),
        (false, [code, text]) => Ok(ReturnConfig {
            status: parse_status(code)
                .ok_or_else(|| format!("{where_}: return status `{code}`"))?,
            text: Some(text.clone()),
        }),
        (true, _) => Err(format!("{where_}: `redirect: [code] \"url\"`")),
        (false, _) => Err(format!("{where_}: `return: status [\"text\"]`")),
    }
}

fn match_op(subject: &MatchSubject, v: &ConfValue) -> Result<MatchOp, String> {
    let texts =
        |items: &[ConfValue]| -> Vec<String> { items.iter().filter_map(conf_text).collect() };
    match v {
        ConfValue::Map(_) => Err(format!("match {}: expected a value", subject.key())),
        ConfValue::List(items) => {
            let t = texts(items);
            match t.first().map(String::as_str) {
                Some(op @ ("~" | "~*" | "!~" | "!=" | "not")) => {
                    let rest = t[1..].to_vec();
                    if rest.is_empty() {
                        return Err(format!("match {}: `{op}` needs a value", subject.key()));
                    }
                    Ok(match op {
                        "~" => MatchOp::Regex(rest.join(" ")),
                        "~*" => MatchOp::RegexCaseless(rest.join(" ")),
                        "!~" => MatchOp::NotRegex(rest.join(" ")),
                        _ => MatchOp::NotIn(rest),
                    })
                }
                _ => Ok(MatchOp::In(t)),
            }
        }
        scalar => {
            let t = conf_text(scalar).unwrap_or_default();
            Ok(match t.as_str() {
                "present" => MatchOp::Present,
                "absent" => MatchOp::Absent,
                _ => MatchOp::In(vec![t]),
            })
        }
    }
}

fn header_ops(
    set_req: Vec<(String, String)>,
    rm_req: Option<OneOrMany<String>>,
    set_resp: Vec<(String, String)>,
    rm_resp: Option<OneOrMany<String>>,
) -> HeaderOps {
    HeaderOps {
        request_set: set_req,
        request_remove: list(rm_req).unwrap_or_default(),
        response_set: set_resp,
        response_remove: list(rm_resp).unwrap_or_default(),
    }
}

fn lower_location(
    l: LocationBlock,
    site: &str,
    errors: &mut Vec<String>,
) -> Option<LocationConfig> {
    let (kind, path) = match l.labels.as_slice() {
        [path] => (LocationKind::Prefix, path.clone()),
        [m, path] => match LocationKind::from_modifier(m) {
            Some(k) => (k, path.clone()),
            None => {
                errors.push(format!(
                    "{site} › location {m} {path}: unknown modifier `{m}` (expected =, ^~, ~ or ~*)"
                ));
                return None;
            }
        },
        _ => {
            errors.push(format!(
                "{site} › location: write `location [=|^~|~|~*] \"/path\" {{ … }}`"
            ));
            return None;
        }
    };
    let where_ = format!("{site} › location {path}");
    let mut conditions = Vec::new();
    if let Some(m) = l.match_ {
        for (key, value) in m.0 {
            let Some(subject) = MatchSubject::parse(&key) else {
                errors.push(format!(
                    "{where_} › match: unknown key `{key}` (method, query.NAME, header.NAME, cookie.NAME, host, scheme, ip, args, path)"
                ));
                continue;
            };
            match match_op(&subject, &value) {
                Ok(op) => conditions.push(MatchCondition { subject, op }),
                Err(e) => errors.push(format!("{where_}: {e}")),
            }
        }
    }
    let respond = match (l.return_, l.redirect) {
        (Some(_), Some(_)) => {
            errors.push(format!("{where_}: `return` and `redirect` are exclusive"));
            None
        }
        (Some(r), None) => lower_return(r.into_vec(), false, &where_)
            .map_err(|e| errors.push(e))
            .ok(),
        (None, Some(r)) => lower_return(r.into_vec(), true, &where_)
            .map_err(|e| errors.push(e))
            .ok(),
        (None, None) => None,
    };
    Some(LocationConfig {
        kind,
        path,
        conditions,
        proxy_pass: l.proxy_pass,
        respond,
        rewrites: l
            .rewrite
            .into_iter()
            .map(|(pattern, replacement)| RewriteRule {
                pattern,
                replacement,
            })
            .collect(),
        headers: header_ops(
            l.set_request_header,
            l.remove_request_header,
            l.set_response_header,
            l.remove_response_header,
        ),
        timeout_secs: secs(l.timeout),
        response_buffering: l.response_buffering,
        security: lower_security(l.security, &where_, errors),
    })
}

fn fallback_location(
    proxy_pass: Option<String>,
    ret: Option<OneOrMany<ConfValue>>,
    redirect: Option<OneOrMany<ConfValue>>,
    where_: &str,
    errors: &mut Vec<String>,
) -> Option<LocationConfig> {
    let respond = match (ret, redirect) {
        (Some(r), _) => lower_return(r.into_vec(), false, where_)
            .map_err(|e| errors.push(e))
            .ok(),
        (None, Some(r)) => lower_return(r.into_vec(), true, where_)
            .map_err(|e| errors.push(e))
            .ok(),
        (None, None) => None,
    };
    if proxy_pass.is_none() && respond.is_none() {
        return None;
    }
    Some(LocationConfig {
        path: "/".into(),
        proxy_pass,
        respond,
        ..Default::default()
    })
}

fn lower_http(h: HttpBlock, e: &mut EdgeConfig, errors: &mut Vec<String>) {
    set(&mut e.listen, h.listen);
    if let Some(t) = h.tls {
        set(&mut e.tls_listen, t.listen.map(Some));
        e.tls_cert = t.cert.or(e.tls_cert.take());
        e.tls_key = t.key.or(e.tls_key.take());
        set(&mut e.tls_redirect_https, t.redirect_https);
        set(&mut e.http2, t.http2);
        set(&mut e.tls_handshake_events, t.handshake_events);
        set(&mut e.tls_allowed_hosts, list(t.allowed_hosts));
    }
    set(&mut e.forwarded_headers, h.forwarded_headers);
    set(&mut e.response_buffering, h.response_buffering);
    set(&mut e.body_capture_kb, kib(h.body_capture));
    set(&mut e.max_concurrent_requests, h.max_concurrent_requests);
    set(&mut e.upstream_timeout_secs, secs(h.upstream_timeout));
    set(
        &mut e.upstream_connect_timeout_secs,
        secs(h.upstream_connect_timeout),
    );
    set(&mut e.upstream_pool_idle, h.upstream_pool_idle);
    set(&mut e.health_timeout_secs, secs(h.health_timeout));
    set(&mut e.health_path, h.health_path);
    set(&mut e.balance, h.balance);
    set(&mut e.max_fails, h.max_fails);
    set(&mut e.fail_timeout_secs, secs(h.fail_timeout));
    if let Some(s) = h.socket {
        set(&mut e.reuseport_workers, s.reuseport_workers);
        set(&mut e.tcp_backlog, s.backlog);
        set(&mut e.tcp_nodelay, s.nodelay);
        set(&mut e.tcp_keepalive_secs, secs(s.keepalive));
        set(
            &mut e.tcp_send_buffer_kb,
            s.send_buffer.map(|b| (b.0 / 1024) as u32),
        );
        set(
            &mut e.tcp_recv_buffer_kb,
            s.recv_buffer.map(|b| (b.0 / 1024) as u32),
        );
    }
    if let Some(c) = h.compress {
        set(&mut e.compress.enabled, c.enabled);
        set(&mut e.compress.min_length, c.min_length);
        set(&mut e.compress.level_br, c.level_br);
        set(&mut e.compress.level_gzip, c.level_gzip);
        set(&mut e.compress.level_zstd, c.level_zstd);
    }
    if let Some(c) = h.challenge {
        set(&mut e.challenge_backend, c.backend);
        set(&mut e.challenge.enabled, c.enabled);
        set(&mut e.challenge.secret_env, c.secret_env);
        set(&mut e.challenge.bucket_secs, secs(c.bucket));
        set(&mut e.challenge.difficulty, c.difficulty);
        set(&mut e.challenge.title, c.title);
        if c.template.is_some() {
            e.challenge.template_path = c.template;
        }
    }
    if h.error_pages.is_some() {
        e.error_pages.dir = h.error_pages;
    }
    for u in h.upstream {
        let Some(name) = u.labels.first().cloned() else {
            errors.push("http › upstream: needs a name (e.g. `upstream app { … }`)".into());
            continue;
        };
        e.upstream_groups.push(UpstreamGroupConfig {
            name,
            servers: list(u.server).unwrap_or_default(),
            balance: u.balance,
            max_fails: u.max_fails,
            fail_timeout_secs: secs(u.fail_timeout),
            health_path: u.health_path,
        });
    }
    e.security = lower_security(h.security, "http", errors);
    for s in h.site {
        let hosts: Vec<String> = list(s.host)
            .unwrap_or_default()
            .into_iter()
            .map(|h| {
                if h.starts_with('~') {
                    h
                } else {
                    h.to_ascii_lowercase()
                }
            })
            .collect();
        let label = if hosts.is_empty() {
            "site (default)".to_string()
        } else {
            format!("site {}", hosts.join(","))
        };
        let mut locations: Vec<LocationConfig> = s
            .location
            .into_iter()
            .filter_map(|l| lower_location(l, &label, errors))
            .collect();
        if let Some(f) = fallback_location(s.proxy_pass, s.return_, s.redirect, &label, errors) {
            locations.push(f);
        }
        let (tls_cert, tls_key) = match s.tls {
            Some(t) => (t.cert, t.key),
            None => (None, None),
        };
        e.sites.push(SiteConfig {
            hosts,
            default: s.default.unwrap_or(false),
            tls_cert,
            tls_key,
            locations,
            headers: header_ops(
                s.set_request_header,
                s.remove_request_header,
                s.set_response_header,
                s.remove_response_header,
            ),
            security: lower_security(s.security, &label, errors),
        });
    }
    let mut implicit: Vec<LocationConfig> = h
        .location
        .into_iter()
        .filter_map(|l| lower_location(l, "http", errors))
        .collect();
    if let Some(f) = fallback_location(h.proxy_pass, None, None, "http", errors) {
        implicit.push(f);
    }
    if !implicit.is_empty() {
        e.sites.push(SiteConfig {
            locations: implicit,
            ..Default::default()
        });
    }
}

// ── Raising: SentryConfig → ConfFile ───────────────────────────────────────

fn raise_security(s: &SecurityConfig) -> Option<SecurityBlock> {
    if s.is_empty() {
        return None;
    }
    let level = |k: &str| s.policy.get(k).cloned();
    let policy = (!s.policy.is_empty()).then(|| LevelPolicyBlock {
        info: level("info"),
        low: level("low"),
        medium: level("medium"),
        high: level("high"),
        critical: level("critical"),
    });
    let mut packs: Vec<(String, String)> = s
        .packs
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    packs.sort();
    Some(SecurityBlock {
        mode: s.mode,
        policy,
        challenge: s.force_challenge.map(|f| {
            if f {
                "always".to_string()
            } else {
                "off".to_string()
            }
        }),
        rate_limit: s.rate_limit.map(|r| {
            ConfValue::Str(format!(
                "{}/{}",
                r.requests,
                sentry_conf::values::format_duration_ms(r.window_secs * 1000)
            ))
        }),
        allow: (!s.allow.is_empty()).then(|| OneOrMany(s.allow.clone())),
        deny: (!s.deny.is_empty()).then(|| OneOrMany(s.deny.clone())),
        packs: (!packs.is_empty()).then_some(OrderedMap(packs)),
    })
}

fn raise_return(r: &ReturnConfig) -> (Option<OneOrMany<ConfValue>>, Option<OneOrMany<ConfValue>>) {
    let mut values = vec![ConfValue::Int(i64::from(r.status))];
    if let Some(t) = &r.text {
        values.push(ConfValue::Str(t.clone()));
    }
    if (300..400).contains(&r.status) {
        (None, Some(OneOrMany(values)))
    } else {
        (Some(OneOrMany(values)), None)
    }
}

fn raise_match_value(op: &MatchOp) -> ConfValue {
    let strs = |v: &[String]| {
        v.iter()
            .map(|s| ConfValue::Str(s.clone()))
            .collect::<Vec<_>>()
    };
    match op {
        MatchOp::In(v) if v.len() == 1 => ConfValue::Str(v[0].clone()),
        MatchOp::In(v) => ConfValue::List(strs(v)),
        MatchOp::NotIn(v) => {
            let mut items = vec![ConfValue::Str("!=".into())];
            items.extend(strs(v));
            ConfValue::List(items)
        }
        MatchOp::Regex(p) => {
            ConfValue::List(vec![ConfValue::Str("~".into()), ConfValue::Str(p.clone())])
        }
        MatchOp::RegexCaseless(p) => {
            ConfValue::List(vec![ConfValue::Str("~*".into()), ConfValue::Str(p.clone())])
        }
        MatchOp::NotRegex(p) => {
            ConfValue::List(vec![ConfValue::Str("!~".into()), ConfValue::Str(p.clone())])
        }
        MatchOp::Present => ConfValue::Str("present".into()),
        MatchOp::Absent => ConfValue::Str("absent".into()),
    }
}

fn non_empty(v: &[String]) -> Option<OneOrMany<String>> {
    (!v.is_empty()).then(|| OneOrMany(v.to_vec()))
}

fn raise_location(l: &LocationConfig) -> LocationBlock {
    let mut labels = Vec::new();
    if l.kind != LocationKind::Prefix {
        labels.push(l.kind.modifier().to_string());
    }
    labels.push(l.path.clone());
    let (return_, redirect) = match &l.respond {
        Some(r) => raise_return(r),
        None => (None, None),
    };
    LocationBlock {
        labels,
        match_: (!l.conditions.is_empty()).then(|| {
            OrderedMap(
                l.conditions
                    .iter()
                    .map(|c| (c.subject.key(), raise_match_value(&c.op)))
                    .collect(),
            )
        }),
        proxy_pass: l.proxy_pass.clone(),
        return_,
        redirect,
        rewrite: l
            .rewrites
            .iter()
            .map(|r| (r.pattern.clone(), r.replacement.clone()))
            .collect(),
        set_request_header: l.headers.request_set.clone(),
        remove_request_header: non_empty(&l.headers.request_remove),
        set_response_header: l.headers.response_set.clone(),
        remove_response_header: non_empty(&l.headers.response_remove),
        timeout: l.timeout_secs.map(Secs),
        response_buffering: l.response_buffering,
        security: raise_security(&l.security),
    }
}

fn raise_http(e: &EdgeConfig) -> HttpBlock {
    let (groups, sites) = crate::edge_routes::normalized(e);
    HttpBlock {
        listen: Some(e.listen.clone()),
        tls: Some(TlsBlock {
            listen: Some(e.tls_listen.clone().unwrap_or_else(|| "0.0.0.0:443".into())),
            cert: e.tls_cert.clone(),
            key: e.tls_key.clone(),
            redirect_https: Some(e.tls_redirect_https),
            http2: Some(e.http2),
            handshake_events: Some(e.tls_handshake_events),
            allowed_hosts: some_list(&e.tls_allowed_hosts),
        }),
        forwarded_headers: Some(e.forwarded_headers),
        response_buffering: Some(e.response_buffering),
        body_capture: Some(Bytes(e.body_capture_kb as u64 * 1024)),
        max_concurrent_requests: Some(e.max_concurrent_requests),
        upstream_timeout: Some(Secs(e.upstream_timeout_secs)),
        upstream_connect_timeout: Some(Secs(e.upstream_connect_timeout_secs)),
        upstream_pool_idle: Some(e.upstream_pool_idle),
        health_timeout: Some(Secs(e.health_timeout_secs)),
        health_path: Some(e.health_path.clone()),
        balance: Some(e.balance),
        max_fails: Some(e.max_fails),
        fail_timeout: Some(Secs(e.fail_timeout_secs)),
        socket: Some(SocketBlock {
            reuseport_workers: Some(e.reuseport_workers),
            backlog: Some(e.tcp_backlog),
            nodelay: Some(e.tcp_nodelay),
            keepalive: Some(Secs(e.tcp_keepalive_secs)),
            send_buffer: Some(Bytes(u64::from(e.tcp_send_buffer_kb) * 1024)),
            recv_buffer: Some(Bytes(u64::from(e.tcp_recv_buffer_kb) * 1024)),
        }),
        compress: Some(CompressBlock {
            enabled: Some(e.compress.enabled),
            min_length: Some(e.compress.min_length),
            level_br: Some(e.compress.level_br),
            level_gzip: Some(e.compress.level_gzip),
            level_zstd: Some(e.compress.level_zstd),
        }),
        challenge: Some(ChallengeBlock {
            backend: Some(e.challenge_backend),
            enabled: Some(e.challenge.enabled),
            secret_env: Some(e.challenge.secret_env.clone()),
            bucket: Some(Secs(e.challenge.bucket_secs)),
            difficulty: Some(e.challenge.difficulty),
            title: Some(e.challenge.title.clone()),
            template: e.challenge.template_path.clone(),
        }),
        error_pages: e.error_pages.dir.clone(),
        upstream: groups
            .iter()
            .map(|g| UpstreamBlock {
                labels: vec![g.name.clone()],
                server: Some(OneOrMany(g.servers.clone())),
                balance: g.balance,
                max_fails: g.max_fails,
                fail_timeout: g.fail_timeout_secs.map(Secs),
                health_path: g.health_path.clone(),
            })
            .collect(),
        security: raise_security(&e.security),
        site: sites
            .iter()
            .map(|s| {
                let tls = (s.tls_cert.is_some() || s.tls_key.is_some()).then(|| SiteTlsBlock {
                    cert: s.tls_cert.clone(),
                    key: s.tls_key.clone(),
                });
                SiteBlock {
                    host: non_empty(&s.hosts),
                    default: s.default.then_some(true),
                    tls,
                    location: s.locations.iter().map(raise_location).collect(),
                    set_request_header: s.headers.request_set.clone(),
                    remove_request_header: non_empty(&s.headers.request_remove),
                    set_response_header: s.headers.response_set.clone(),
                    remove_response_header: non_empty(&s.headers.response_remove),
                    security: raise_security(&s.security),
                    ..Default::default()
                }
            })
            .collect(),
        location: Vec::new(),
        proxy_pass: None,
    }
}

/// Full `ConfFile` view of a runtime config (every value set; prune against
/// `raise(&SentryConfig::default())` to keep only changes).
pub fn raise(c: &SentryConfig) -> ConfFile {
    let mut packs_simple: Vec<(String, String)> = Vec::new();
    let mut pack_blocks: Vec<PackBlock> = Vec::new();
    for p in &c.rules.packs {
        if p.params.is_empty() {
            packs_simple.push((p.name.clone(), p.mode.clone()));
        } else {
            let strings = |k: &str| {
                p.params.get(k).and_then(|v| v.as_array()).map(|a| {
                    OneOrMany(
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect(),
                    )
                })
            };
            pack_blocks.push(PackBlock {
                labels: vec![p.name.clone()],
                mode: Some(p.mode.clone()),
                countries: strings("countries"),
                domains: strings("domains"),
            });
        }
    }
    let mut weights: Vec<(String, u8)> = c
        .scorer
        .weights
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    weights.sort();
    ConfFile {
        sentry: Some(SentryBlock {
            mode: Some(c.deployment.mode.clone()),
            instance_id: Some(c.deployment.instance_id.clone()),
            runtime: Some(RuntimeBlock {
                worker_threads: Some(c.runtime.worker_threads),
                pin_cores: Some(OneOrMany(c.runtime.pin_cores.clone())),
                priority: Some(c.runtime.thread_priority),
            }),
            update: Some(UpdateBlock {
                enabled: Some(c.update.enabled),
                interval: Some(Secs(c.update.interval_secs)),
                repo: Some(c.update.repo.clone()),
                auto_restart: Some(c.update.auto_restart),
            }),
            auto: Some(AutoBlock {
                skip: some_list(&c.auto.sensitive.skip),
                enable: some_list(&c.auto.sensitive.enable),
            }),
        }),
        server: Some(ServerBlock {
            data_directory: Some(c.core.data_dir.clone()),
            channel_buffer: Some(c.core.channel_buffer),
            action_buffer: Some(c.core.action_buffer),
            action_workers: Some(c.core.action_workers),
            persist_buffer: Some(c.core.persist_buffer),
            dedupe_ttl: Some(Secs(c.core.dedupe_ttl_secs)),
            geo: Some(GeoBlock {
                city_db: Some(c.geo.city_db.clone()),
                asn_db: Some(c.geo.asn_db.clone()),
            }),
            policy: Some(PolicyBlock {
                info: Some(c.policy.info.clone()),
                low: Some(c.policy.low.clone()),
                medium: Some(c.policy.medium.clone()),
                high: Some(c.policy.high.clone()),
                critical: Some(c.policy.critical.clone()),
                overrides: c
                    .policy
                    .overrides
                    .iter()
                    .map(|o| OverrideBlock {
                        labels: vec![o.r#match.clone()],
                        match_: None,
                        verdict: Some(o.verdict.clone()),
                    })
                    .collect(),
            }),
            scorer: Some(ScorerBlock {
                repetition_bonus: Some(c.scorer.repetition_bonus),
                repetition_window: Some(Secs(c.scorer.repetition_window_secs)),
                weights: Some(OrderedMap(weights)),
            }),
            escalation: Some(EscalationBlock {
                enabled: Some(c.escalation.enabled),
                window: Some(Secs(c.escalation.window_secs)),
                challenge_at: Some(c.escalation.challenge_at),
                block_at: Some(c.escalation.block_at),
                persist: Some(c.escalation.persist),
            }),
            overload: Some(OverloadBlock {
                enabled: Some(c.overload.enabled),
                queue_pressure: Some(c.overload.queue_pressure),
                release_pressure: Some(c.overload.release_pressure),
                release: Some(Secs(c.overload.release_secs)),
                pg_insert_budget: Some(Millis(c.overload.pg_insert_budget_ms)),
                sample_keep: Some(c.overload.sample_keep),
                coalesce_benign: Some(c.overload.coalesce_benign),
                coalesce_window: Some(Secs(c.overload.coalesce_window_secs)),
                coalesce_cap: Some(c.overload.coalesce_cap),
            }),
        }),
        storage: Some(StorageBlock {
            url: Some(c.storage.postgres.url.clone()),
            max_connections: Some(c.storage.postgres.max_connections),
            acquire_timeout: Some(Secs(c.storage.postgres.acquire_timeout_secs)),
            statement_timeout: Some(Secs(c.storage.postgres.statement_timeout_secs)),
        }),
        detect: Some(raise_detect(c)),
        trust: Some(TrustBlock {
            proxies: some_list(&c.real_ip.trusted_proxies),
            cloudflare: Some(c.real_ip.cloudflare),
            trusted_ips: some_list(&c.real_ip.trusted_ips),
            trusted_lists: some_list(&c.real_ip.trusted_lists),
            whitelist: some_list(&c.real_ip.whitelist),
            blacklist: some_list(&c.real_ip.blacklist),
            shadow: some_list(&c.real_ip.shadow),
            refresh: Some(Secs(c.real_ip.refresh_secs)),
        }),
        rules: Some(RulesBlock {
            packs: Some(OrderedMap(packs_simple)),
            pack: pack_blocks,
            rule: c
                .rules
                .custom
                .iter()
                .map(|r| RuleBlock {
                    labels: vec![r.name.clone()],
                    priority: (r.priority != 0).then_some(r.priority),
                    match_: Some(r.r#match.clone()),
                    action: Some(r.action.clone()),
                    tags: non_empty(&r.tags),
                    log: r.log_level.clone(),
                })
                .collect(),
            feed_presets: some_list(&c.rules.feed_presets),
            feed: c
                .rules
                .feeds
                .iter()
                .map(|f| {
                    let mut headers: Vec<(String, String)> = f
                        .headers_env
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    headers.sort();
                    let defaults = FeedConfig::default();
                    FeedBlock {
                        labels: vec![f.name.clone()],
                        url: Some(f.url.clone()),
                        kind: (f.kind != defaults.kind).then_some(f.kind),
                        refresh: (f.refresh_hours != defaults.refresh_hours)
                            .then(|| Secs(u64::from(f.refresh_hours) * 3600)),
                        refresh_hours: None,
                        tier: (f.tier != defaults.tier).then(|| f.tier.clone()),
                        action: (!f.action.is_empty()).then(|| f.action.clone()),
                        enabled: (!f.enabled).then_some(false),
                        headers_env: (!headers.is_empty()).then_some(OrderedMap(headers)),
                    }
                })
                .collect(),
            rate_limit: Some(RateLimitBlock {
                backend: Some(c.rate_limit.backend.clone()),
                redis_url: Some(c.rate_limit.redis_url.clone()),
            }),
        }),
        routes: Some(OrderedMap(
            c.routes
                .known
                .iter()
                .map(|r| {
                    let methods = if r.methods.is_empty() {
                        vec!["any".to_string()]
                    } else {
                        r.methods.clone()
                    };
                    (r.path.clone(), OneOrMany(methods))
                })
                .collect(),
        )),
        source: c
            .sources
            .iter()
            .map(|s| RawBlock {
                labels: vec![s.kind.clone()],
                entries: options_to(&s.options),
            })
            .collect(),
        action: c
            .actions
            .iter()
            .map(|a| {
                let mut labels = vec![a.kind.as_str().to_string()];
                if let Some(p) = &a.provider {
                    labels.push(p.clone());
                }
                let mut entries = Vec::new();
                if let Some(d) = a.dispatch {
                    if let Ok(serde_json::Value::String(s)) = serde_json::to_value(d) {
                        entries.push(("dispatch".to_string(), ConfValue::Str(s)));
                    }
                }
                entries.extend(options_to(&a.options));
                RawBlock { labels, entries }
            })
            .collect(),
        dashboard: Some(DashboardBlock {
            listen: Some(join_listen(&c.server.host, c.server.port)),
            webhook_secret_env: Some(c.server.webhook_secret_env.clone()),
            auth: Some(AuthBlock {
                mode: Some(c.server.auth.mode.clone()),
                session_secret_env: Some(c.server.auth.session_secret_env.clone()),
                session_ttl: Some(Secs(c.server.auth.session_ttl_secs)),
                user: c
                    .server
                    .auth
                    .users
                    .iter()
                    .map(|u| UserBlock {
                        labels: vec![u.username.clone()],
                        password_hash: Some(u.password_hash.clone()),
                        role: Some(u.role.clone()),
                    })
                    .collect(),
                token: c
                    .server
                    .auth
                    .tokens
                    .iter()
                    .map(|t| TokenBlock {
                        labels: Vec::new(),
                        token_sha256: (!t.token_sha256.is_empty()).then(|| t.token_sha256.clone()),
                        token_env: (!t.token_env.is_empty()).then(|| t.token_env.clone()),
                        role: Some(t.role.clone()),
                    })
                    .collect(),
            }),
        }),
        metrics: Some(MetricsBlock {
            enabled: Some(c.metrics.enabled),
            listen: Some(join_listen(&c.metrics.host, c.metrics.port)),
        }),
        http: Some(raise_http(&c.edge)),
        tcp: Some(TcpBlock {
            listen: c.edge.tcp_listen.clone(),
            proxy_pass: c.edge.tcp_upstream.clone(),
        }),
    }
}

fn raise_detect(c: &SentryConfig) -> DetectBlock {
    DetectBlock {
        scan: Some(ScanBlock {
            enabled: Some(c.scan.enabled),
            window: Some(Secs(c.scan.window_secs)),
            distinct_paths: Some(c.scan.distinct_paths),
            not_found: Some(c.scan.not_found),
        }),
        behavior: Some(BehaviorBlock {
            enabled: Some(c.behavior.enabled),
            window: Some(Secs(c.behavior.window_secs)),
            auth_failures: Some(c.behavior.auth_failures),
            distinct_uas: Some(c.behavior.distinct_uas),
            wordlist_hits: Some(c.behavior.wordlist_hits),
            suspicious_success_min_failures: Some(c.behavior.suspicious_success_min_failures),
            login_patterns: some_list(&c.behavior.login_patterns),
            wordlist_paths: some_list(&c.behavior.wordlist_paths),
        }),
        correlation: Some(CorrelationBlock {
            enabled: Some(c.correlation.enabled),
            window: Some(Secs(c.correlation.window_secs)),
        }),
        bot_verification: Some(BotVerificationBlock {
            enabled: Some(c.bot_verification.enabled),
            cache_ttl: Some(Secs(c.bot_verification.cache_ttl_secs)),
            failed_ttl: Some(Secs(c.bot_verification.failed_ttl_secs)),
            timeout: Some(Millis(c.bot_verification.timeout_ms)),
            batch_size: Some(c.bot_verification.batch_size),
        }),
        uploads: Some(UploadsBlock {
            enabled: Some(c.uploads.enabled),
            mode: Some(c.uploads.mode),
            inspect: Some(Bytes(c.uploads.inspect_kb as u64 * 1024)),
            max_files: Some(c.uploads.max_files),
            scan_json: Some(c.uploads.scan_json),
            oversize: Some(c.uploads.oversize),
            blocked_extensions: some_list(&c.uploads.blocked_extensions),
            allowed_extensions: some_list(&c.uploads.allowed_extensions),
            allowed_content_types: some_list(&c.uploads.allowed_content_types),
            methods: some_list(&c.uploads.methods),
            allowed_paths: some_list(&c.uploads.allowed_paths),
            allow_extensionless: Some(c.uploads.allow_extensionless),
            flood: Some(UploadFloodBlock {
                window: Some(Secs(c.uploads.flood.window_secs)),
                max_uploads: Some(c.uploads.flood.max_uploads),
                max_total: Some(Bytes(u64::from(c.uploads.flood.max_total_mb) * 1024 * 1024)),
            }),
        }),
        posture: Some(PostureBlock {
            enabled: Some(c.posture.enabled),
            mode: Some(c.posture.mode),
            dedupe_ttl: Some(Secs(c.posture.dedupe_ttl_secs)),
            hsts_min_max_age: Some(c.posture.hsts_min_max_age),
            checks: some_list(&c.posture.checks),
            hosts: some_list(&c.posture.hosts),
        }),
        protocol: Some(ProtocolBlock {
            enabled: Some(c.protocol.enabled),
            dir: Some(c.protocol.dir.clone()),
            safety_poll: Some(Secs(c.protocol.safety_poll_secs)),
            debounce: Some(Millis(c.protocol.debounce_ms)),
            max_schemas: Some(c.protocol.max_schemas),
        }),
        route_learner: Some(RouteLearnerBlock {
            enabled: Some(c.route_learner.enabled),
            interval: Some(Secs(c.route_learner.interval_secs)),
            window: Some(Secs(c.route_learner.window_secs)),
            min_hits: Some(c.route_learner.min_hits),
            min_ips: Some(c.route_learner.min_ips),
        }),
        ai: Some(AiBlock {
            enabled: Some(c.ai.enabled),
            model_path: Some(c.ai.model_path.clone()),
            threshold: Some(c.ai.threshold),
            signal_weight: Some(c.ai.signal_weight),
            mode: Some(c.ai.mode.clone()),
            trigger: Some(c.ai.trigger.clone()),
            min_score: Some(c.ai.min_score),
            concurrency: Some(c.ai.concurrency),
            cache_ttl: Some(Secs(c.ai.cache_ttl_secs)),
        }),
        llm: Some(LlmBlock {
            provider: Some(c.llm.provider.clone()),
            model: Some(c.llm.model.clone()),
            base_url: c.llm.base_url.clone().filter(|u| !u.is_empty()),
            mode: Some(c.llm.mode.clone()),
            only_above: Some(c.llm.only_above),
            concurrency: Some(c.llm.concurrency),
            cache_ttl: Some(Secs(c.llm.cache_ttl_secs)),
        }),
        ip_lookup: Some(IpLookupBlock {
            enabled: Some(c.ip_lookup.enabled),
            provider: Some(c.ip_lookup.provider.clone()),
            key_env: Some(c.ip_lookup.key_env.clone()),
            trigger_above: Some(c.ip_lookup.trigger_above),
            on_signals: some_list(&c.ip_lookup.on_signals),
            cache_ttl: Some(Secs(c.ip_lookup.cache_ttl_secs)),
            max_per_hour: Some(c.ip_lookup.max_per_hour),
            timeout: Some(Secs(c.ip_lookup.timeout_secs)),
        }),
    }
}
