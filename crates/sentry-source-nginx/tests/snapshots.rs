//! Snapshot tests: parse each fixture log line, run it through the
//! analysis pipeline, and snapshot the verdict + signals.
//!
//! Regenerate snapshots with `INSTA_UPDATE=1 cargo test -p sentry-source-nginx`
//! or `cargo insta review` after intentional heuristic changes.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

use sentry_core::packs::build_default_ruleset;
use sentry_core::pipeline::{Pipeline, RouteValidator};
use sentry_core::rules::RuleSet;
use sentry_source_nginx::LogFormat;

const COMBINED: &str = r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent""#;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

#[test]
fn snapshots_for_all_fixtures() {
    let fmt = LogFormat::compile(COMBINED).expect("combined format compiles");
    let rules: RuleSet = build_default_ruleset(&Default::default());
    let pipeline = Pipeline::new(rules, RouteValidator::default());

    let mut entries: Vec<_> = fs::read_dir(fixtures_dir())
        .expect("fixtures dir exists")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("log"))
        .collect();
    entries.sort();

    for path in entries {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let line = fs::read_to_string(&path)
            .unwrap()
            .trim_end_matches(['\n', '\r'])
            .to_string();
        let raw = fmt
            .parse_line(&line)
            .unwrap_or_else(|e| panic!("failed to parse fixture {name}: {e}\nline: {line:?}"));
        let ip = raw
            .client_ip
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let evt = raw.into_event(ip);
        let result = pipeline.process(&evt);

        let http = evt.http().expect("http event");
        let mut signal_kinds: Vec<&str> = result
            .analysis
            .signals
            .iter()
            .map(|s| signal_label(s.kind))
            .collect();
        signal_kinds.sort();
        signal_kinds.dedup();

        let summary = format!(
            "fixture: {name}\n\
             line:    {line}\n\
             method:  {method:?}\n\
             path:    {path}\n\
             query:   {query}\n\
             status:  {status}\n\
             ua:      {ua}\n\
             score:   {score}\n\
             level:   {level}\n\
             verdict: {verdict:?}\n\
             rule:    {rule}\n\
             signals: [{sig}]",
            method = http.method,
            path = http.path,
            query = http.query.as_deref().unwrap_or("-"),
            status = http
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            ua = http.user_agent.as_deref().unwrap_or("-"),
            score = result.analysis.risk_score,
            level = result.analysis.risk_level.label(),
            verdict = result.decision.action,
            rule = result.rule_hit.as_deref().unwrap_or("-"),
            sig = signal_kinds.join(", "),
        );

        insta::assert_snapshot!(name, summary);
    }
}

fn signal_label(k: sentry_core::SignalKind) -> &'static str {
    use sentry_core::SignalKind::*;
    match k {
        SqlInjection => "sql_injection",
        Xss => "xss",
        PathTraversal => "path_traversal",
        Lfi => "lfi",
        Log4Shell => "log4shell",
        Rce => "rce",
        UnknownRoute => "unknown_route",
        MethodNotAllowed => "method_not_allowed",
        ScanBehavior => "scan_behavior",
        AbnormalRate => "abnormal_rate",
        SuspiciousUA => "suspicious_ua",
        TorExitNode => "tor_exit_node",
        KnownBadIp => "known_bad_ip",
        SensitivePath => "sensitive_path",
        VpnProxy => "vpn_proxy",
        BadCrawler => "bad_crawler",
        AnomalousPayload => "anomalous_payload",
        LlmMalicious => "llm_malicious",
        RuleHit => "rule_hit",
        Custom => "custom",
    }
}
