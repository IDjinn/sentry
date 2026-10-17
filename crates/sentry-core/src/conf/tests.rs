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
    assert_eq!(cfg.edge.sites.len(), 1);
    assert_eq!(
        cfg.edge.sites[0].locations[0].proxy_pass.as_deref(),
        Some("http://127.0.0.1:8080")
    );
    assert!(cfg.edge.validate().is_empty(), "{:?}", cfg.edge.validate());
}

use crate::config::ActionKind;

#[test]
fn commented_example_sites_load_too() {
    let start = EXAMPLE
        .find("    # site example.com")
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
    let src = format!("http {{\n tls {{ cert: /c, key: /k }}\n{block}\n}}\n");
    let cfg = load(&src);
    let site = &cfg.edge.sites[0];
    assert_eq!(site.hosts, ["example.com", "www.example.com"]);
    assert_eq!(
        site.tls_cert.as_deref(),
        Some(std::path::Path::new("/etc/sentry/example.crt"))
    );
    let at = |path: &str| site.locations.iter().find(|l| l.path == path).unwrap();
    assert_eq!(at("/").proxy_pass.as_deref(), Some("http://app:8080"));
    let api_group = at("/api/").proxy_pass.clone().unwrap();
    let group = cfg
        .edge
        .upstream_groups
        .iter()
        .find(|g| g.name == api_group)
        .unwrap();
    assert_eq!(
        group.servers.len(),
        2,
        "a list of URLs becomes a balanced group"
    );
    assert_eq!(at("/old-blog/").respond.as_ref().unwrap().status, 301);
    let health = at("/health");
    assert_eq!(health.kind, LocationKind::Exact);
    assert_eq!(health.respond.as_ref().unwrap().text.as_deref(), Some("ok"));
    assert_eq!(health.security.mode, Some(SecurityMode::Off));
    assert_eq!(at(r"\.(php|aspx?)$").kind, LocationKind::RegexCaseless);
    let admin = at("/admin/");
    assert_eq!(admin.security.force_challenge, Some(true));
    assert_eq!(admin.security.allow, ["10.0.0.0/8"]);
    let v2 = site
        .locations
        .iter()
        .find(|l| l.path == "/api/" && !l.conditions.is_empty())
        .unwrap();
    assert_eq!(
        v2.conditions[0].subject,
        MatchSubject::Query("version".into())
    );
    let stat = at("/static/");
    assert_eq!(stat.headers.response_remove, ["Server"]);
    assert_eq!(stat.headers.response_set[0].0, "Cache-Control");
    assert_eq!(at("/events").response_buffering, Some(false));
    assert!(cfg.edge.validate().is_empty(), "{:?}", cfg.edge.validate());
}

#[test]
fn proxy_shorthands() {
    let cfg = load(
        "http {\n upstream api { server: http://api:1 }\n site a.test *.a.test {\n  \"/\": api\n  \"/x/\": http://x:1/v2/\n  \"/up\": 204\n  \"/go\": redirect 302 \"https://b.test$uri\"\n  location /admin/ { proxy_pass: api, inspect: shadow, rate_limit: 5/s, request_headers { X-A: one, Cookie: off } }\n }\n site { \"/\": [http://d1:1, http://d2:1] }\n}",
    );
    let site = &cfg.edge.sites[0];
    assert_eq!(site.hosts, ["a.test", "*.a.test"]);
    let paths: Vec<&str> = site.locations.iter().map(|l| l.path.as_str()).collect();
    assert_eq!(paths, ["/", "/x/", "/up", "/go", "/admin/"]);
    let admin = &site.locations[4];
    assert_eq!(admin.security.mode, Some(SecurityMode::Shadow));
    assert_eq!(admin.security.rate_limit.unwrap().window_secs, 1);
    assert_eq!(
        admin.headers.request_set,
        [("X-A".to_string(), "one".to_string())]
    );
    assert_eq!(admin.headers.request_remove, ["Cookie"]);
    assert_eq!(site.locations[2].respond.as_ref().unwrap().status, 204);
    let go = site.locations[3].respond.as_ref().unwrap();
    assert_eq!(
        (go.status, go.text.as_deref()),
        (302, Some("https://b.test$uri"))
    );
    let default = &cfg.edge.sites[1];
    let group = default.locations[0].proxy_pass.clone().unwrap();
    assert!(cfg
        .edge
        .upstream_groups
        .iter()
        .any(|g| g.name == group && g.servers.len() == 2));
    assert!(cfg.edge.validate().is_empty(), "{:?}", cfg.edge.validate());

    let back = load(&to_text(&cfg));
    assert_eq!(json(&back), json(&cfg));
    let text = to_text(&cfg);
    assert!(text.contains("site a.test *.a.test {"), "{text}");
    assert!(text.contains("\"/\": api"), "{text}");
    assert!(text.contains("\"/up\": 204"), "{text}");
    assert!(text.contains("\"/go\": redirect 302"), "{text}");
    assert!(
        text.contains("site { proxy_pass: [http://d1:1, http://d2:1] }"),
        "{text}"
    );
    assert!(!text.contains("upstream default/"), "{text}");
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
    let e = load_err("http { site { location / { proxy_pass: http://a:1, rate_limit: lots } } }");
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
    assert!(
        text.contains("site app.example.com { proxy_pass: app.example.com }"),
        "{text}"
    );
    let back = load(&text);
    assert_eq!(back.core.channel_buffer, 8192);
    assert_eq!(back.edge.sites.len(), 2);
    assert_eq!(back.actions[0].options["ttl_secs"], 3600);
}

#[test]
fn security_headers_and_tls_min_version_parse_with_safe_defaults() {
    let defaults = load("http { proxy_pass: http://127.0.0.1:8080 }");
    assert!(defaults.edge.security_headers.enabled);
    assert_eq!(defaults.edge.tls_min_version, "1.3");
    assert_eq!(
        defaults.edge.tls_min().unwrap(),
        crate::config::TlsMinVersion::V13
    );

    let c = load(
        "http {\n  proxy_pass: http://127.0.0.1:8080\n  tls { cert: /a.crt, key: /a.key, min_version: \"1.2\" }\n  security_headers { x_frame_options: DENY, coep: credentialless, strip: [Server] }\n}",
    );
    assert_eq!(c.edge.tls_min().unwrap(), crate::config::TlsMinVersion::V12);
    assert_eq!(c.edge.security_headers.x_frame_options, "DENY");
    assert_eq!(
        c.edge.security_headers.cross_origin_embedder_policy,
        "credentialless"
    );
    assert_eq!(c.edge.security_headers.strip, vec!["Server".to_string()]);

    let bad = load("http { proxy_pass: http://127.0.0.1:8080\n tls { cert: /a, key: /b, min_version: \"1.1\" } }");
    assert!(bad
        .edge
        .validate()
        .iter()
        .any(|e| e.contains("tls_min_version")));
}
