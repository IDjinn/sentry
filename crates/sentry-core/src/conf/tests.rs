use super::*;
use crate::edge_routes::{LocationKind, MatchOp, MatchSubject, SecurityMode};

const EXAMPLE: &str = include_str!("../../../../config/sentry.example.conf");

fn json(cfg: &SentryConfig) -> serde_json::Value {
    serde_json::to_value(cfg).unwrap()
}

fn load(src: &str) -> SentryConfig {
    from_str(src, "t.conf").unwrap_or_else(|e| panic!("{e}"))
}

fn load_err(src: &str) -> String {
    from_str(src, "t.conf").unwrap_err().to_string()
}

#[test]
fn example_file_loads_and_maps_every_section() {
    std::env::remove_var("SENTRY_DATABASE_URL");
    let cfg = load(EXAMPLE);
    assert_eq!(cfg.deployment.mode, "passive");
    assert_eq!(cfg.core.data_dir.to_str(), Some("/var/lib/sentry"));
    assert_eq!(cfg.core.dedupe_ttl_secs, 10);
    assert_eq!(cfg.update.interval_secs, 86_400);
    assert_eq!(
        cfg.storage.postgres.url,
        "postgres://sentry:changeme@localhost:5432/sentry"
    );
    assert_eq!(cfg.escalation.window_secs, 604_800);
    assert_eq!(cfg.overload.pg_insert_budget_ms, 250);
    assert_eq!(cfg.behavior.window_secs, 300);
    assert_eq!(cfg.correlation.window_secs, 900);
    assert_eq!(cfg.bot_verification.timeout_ms, 2000);
    assert_eq!(cfg.uploads.inspect_kb, 4096);
    assert_eq!(cfg.uploads.flood.max_total_mb, 50);
    assert_eq!(cfg.protocol.debounce_ms, 500);
    assert!(cfg.real_ip.cloudflare);
    assert_eq!(
        cfg.rules
            .packs
            .iter()
            .find(|p| p.name == "sensitive_paths")
            .unwrap()
            .mode,
        "enforce"
    );
    assert!(cfg
        .rules
        .packs
        .iter()
        .any(|p| p.name == "country_blocklist" && p.mode == "off"));
    assert_eq!(cfg.rules.custom.len(), 2);
    assert_eq!(cfg.rules.custom[0].log_level.as_deref(), Some("silent"));
    assert_eq!(cfg.routes.known.len(), 4);
    assert_eq!(
        cfg.routes.known[2].methods,
        ["GET", "POST", "PATCH", "DELETE"]
    );
    assert_eq!(cfg.sources[0].kind, "nginx");
    assert!(cfg.sources[0].options["format"]
        .as_str()
        .unwrap()
        .contains("$remote_addr"));
    let blocklist = &cfg.actions[0];
    assert_eq!(blocklist.kind, ActionKind::Blocklist);
    assert_eq!(blocklist.options["ttl_secs"], 86_400);
    let cf = &cfg.actions[1];
    assert_eq!(cf.kind, ActionKind::Challenge);
    assert_eq!(cf.provider.as_deref(), Some("cloudflare"));
    assert_eq!(cf.options["mode"], "managed_challenge");
    assert_eq!(cfg.server.port, 8080);
    assert_eq!(cfg.metrics.port, 9100);
    assert_eq!(cfg.edge.listen, "0.0.0.0:80");
    assert_eq!(cfg.edge.upstream_groups[0].name, "app");
    assert_eq!(cfg.edge.sites.len(), 1);
    assert_eq!(
        cfg.edge.sites[0].locations[0].proxy_pass.as_deref(),
        Some("app")
    );
    assert!(cfg.edge.validate().is_empty(), "{:?}", cfg.edge.validate());
}

use crate::config::ActionKind;

#[test]
fn commented_example_sites_load_too() {
    let start = EXAMPLE
        .find("    # site {\n    #     host:")
        .expect("commented site example");
    let mut block = String::new();
    for line in EXAMPLE[start..].lines() {
        let stripped = line
            .strip_prefix("    # ")
            .or_else(|| line.strip_prefix("    #"))
            .unwrap_or(line);
        block.push_str(stripped);
        block.push('\n');
        if line == "    # }" {
            break;
        }
    }
    let src = format!(
        "http {{\n upstream app {{ server: http://127.0.0.1:1 }}\n upstream api {{ server: http://127.0.0.1:2 }}\n tls {{ cert: /c, key: /k }}\n{block}\n}}\n"
    );
    let cfg = load(&src);
    let site = &cfg.edge.sites[0];
    assert_eq!(site.hosts, ["example.com", "www.example.com"]);
    let kinds: Vec<(LocationKind, &str)> = site
        .locations
        .iter()
        .map(|l| (l.kind, l.path.as_str()))
        .collect();
    assert!(kinds.contains(&(LocationKind::Exact, "/health")));
    assert!(kinds.contains(&(LocationKind::PriorityPrefix, "/static/")));
    assert!(kinds.contains(&(LocationKind::RegexCaseless, r"\.(php|asp|aspx)$")));
    let v2 = &site.locations[3];
    assert_eq!(
        v2.conditions[0].subject,
        MatchSubject::Query("version".into())
    );
    assert_eq!(v2.conditions[0].op, MatchOp::In(vec!["2".into()]));
    let api = &site.locations[4];
    assert_eq!(api.rewrites[0].replacement, "/$1");
    assert_eq!(
        api.headers.request_set,
        [("X-Tenant".to_string(), "acme".to_string())]
    );
    assert_eq!(api.headers.response_remove, ["Server", "X-Powered-By"]);
    assert_eq!(api.timeout_secs, Some(30));
    assert_eq!(api.security.rate_limit.unwrap().requests, 100);
    let admin = &site.locations[5];
    assert_eq!(admin.security.force_challenge, Some(true));
    assert_eq!(admin.security.allow.len(), 2);
    let health = &site.locations[0];
    assert_eq!(health.security.mode, Some(SecurityMode::Off));
    assert_eq!(health.respond.as_ref().unwrap().status, 200);
    let old = site
        .locations
        .iter()
        .find(|l| l.path == "/old-blog/")
        .unwrap();
    assert_eq!(old.respond.as_ref().unwrap().status, 301);
    let beta = site
        .locations
        .iter()
        .rev()
        .find(|l| l.path == "/" && !l.conditions.is_empty())
        .unwrap();
    assert_eq!(beta.conditions[0].op, MatchOp::Present);
    assert_eq!(
        site.locations.last().unwrap().proxy_pass.as_deref(),
        Some("app"),
        "site-level fallback"
    );
    assert!(cfg.edge.validate().is_empty(), "{:?}", cfg.edge.validate());
}

#[test]
fn text_round_trips_through_the_runtime_model() {
    let cfg = load(EXAMPLE);
    let text = to_text(&cfg);
    let back = load(&text);
    assert_eq!(json(&back), json(&cfg), "rendered:\n{text}");
}

#[test]
fn defaults_render_to_nothing() {
    assert_eq!(to_text(&SentryConfig::default()).trim(), "");
}

#[test]
fn blocks_split_across_files_merge() {
    let dir = std::env::temp_dir().join(format!("sentry_conf_merge_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sites")).unwrap();
    std::fs::write(
        dir.join("sentry.conf"),
        "include: detect.conf\nserver { channel_buffer: 1 }\nhttp {\n listen: 0.0.0.0:8080\n upstream app { server: http://a:1 }\n include: \"sites/*.conf\"\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("detect.conf"),
        "detect { scan { window: 2m } }\nserver { action_workers: 3 }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("sites/a.conf"),
        "site { host: a.com\n location \"/\" { proxy_pass: app } }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("sites/b.conf"),
        "site { host: b.com\n proxy_pass: app }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("extra.conf"),
        "detect { behavior { auth_failures: 4 } }\n",
    )
    .unwrap();
    let mut body = sentry_conf::Loader::default()
        .load_file(&dir.join("sentry.conf"))
        .unwrap();
    body.extend(
        sentry_conf::Loader::default()
            .load_file(&dir.join("extra.conf"))
            .unwrap(),
    );
    let cfg = from_body(&body).unwrap();
    assert_eq!(cfg.core.channel_buffer, 1);
    assert_eq!(cfg.core.action_workers, 3);
    assert_eq!(cfg.scan.window_secs, 120);
    assert_eq!(cfg.behavior.auth_failures, 4);
    assert_eq!(cfg.edge.listen, "0.0.0.0:8080");
    assert_eq!(cfg.edge.sites.len(), 2);
    assert_eq!(cfg.edge.sites[1].hosts, ["b.com"]);

    std::fs::write(dir.join("dup.conf"), "server { channel_buffer: 2 }\n").unwrap();
    body.extend(
        sentry_conf::Loader::default()
            .load_file(&dir.join("dup.conf"))
            .unwrap(),
    );
    let err = from_body(&body).unwrap_err().to_string();
    assert!(err.contains("`channel_buffer` is given 2 times"), "{err}");
    assert!(
        err.contains("sentry.conf:2:10") && err.contains("dup.conf:1:10"),
        "{err}"
    );
}

#[test]
fn errors_point_at_the_mistake() {
    let e = load_err("detect {\n  scan { windw: 1m }\n}");
    assert_eq!(e, "config error: t.conf:2:10: detect › scan: unknown directive `windw` — did you mean `window`?");
    let e = load_err("server { dedupe_ttl: soon }");
    assert!(e.contains("invalid duration `soon`"), "{e}");
    let e = load_err("http { site { location \"/\" { proxy_pass: app, match { query: x } } } }");
    assert!(e.contains("unknown key `query`"), "{e}");
    let e = load_err("http { location ?? \"/\" { proxy_pass: app } }");
    assert!(e.contains("unknown modifier `??`"), "{e}");
    let e = load_err("action { url: x }");
    assert!(e.contains("action: needs a type"), "{e}");
    let e = load_err("action fly {}");
    assert!(e.contains("unknown type"), "{e}");
    let e = load_err("http { site { location \"/\" { security { rate_limit: lots } } } }");
    assert!(e.contains("rate_limit `lots`"), "{e}");
}

#[test]
fn shorthand_http_without_sites_builds_a_default_site() {
    let cfg = load("http { proxy_pass: http://127.0.0.1:3000 }");
    assert_eq!(cfg.edge.sites.len(), 1);
    assert!(cfg.edge.sites[0].hosts.is_empty());
    assert_eq!(cfg.edge.sites[0].locations[0].path, "/");
    assert!(cfg.edge.validate().is_empty());
}

#[test]
fn match_operators_parse() {
    let cfg = load(
        "http { location \"/\" {\n match {\n  query.id: ~ '^[0-9]+$'\n  header.x-env: != prod staging\n  ip: [10.0.0.0/8]\n  cookie.sid: absent\n  path: !~ '\\.php$'\n }\n proxy_pass: http://a:1\n} }",
    );
    let c = &cfg.edge.sites[0].locations[0].conditions;
    assert_eq!(c[0].op, MatchOp::Regex("^[0-9]+$".into()));
    assert_eq!(
        c[1].op,
        MatchOp::NotIn(vec!["prod".into(), "staging".into()])
    );
    assert_eq!(c[2].op, MatchOp::In(vec!["10.0.0.0/8".into()]));
    assert_eq!(c[3].op, MatchOp::Absent);
    assert_eq!(c[4].op, MatchOp::NotRegex(r"\.php$".into()));
}

#[test]
fn legacy_toml_migrates_to_conf() {
    let legacy: SentryConfig = toml::from_str(
        "[core]\nchannel_buffer = 8192\n[edge]\nupstream = \"http://127.0.0.1:8080\"\n[[edge.vhosts]]\nhost = \"app.example.com\"\nupstreams = [\"http://a:1\"]\n[[action]]\ntype = \"blocklist\"\n[action.options]\nttl_secs = 3600\n",
    )
    .unwrap();
    let text = to_text(&legacy);
    assert!(text.contains("upstream default {"), "{text}");
    assert!(text.contains("host: app.example.com"), "{text}");
    let back = load(&text);
    assert_eq!(back.core.channel_buffer, 8192);
    assert_eq!(back.edge.sites.len(), 2);
    assert_eq!(back.actions[0].options["ttl_secs"], 3600);
}
