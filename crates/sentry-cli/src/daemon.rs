//! Daemon entrypoint: wires up sources, pipeline, rules, actions.
//!
//! The daemon:
//! 1. Loads config and builds the plugin registry + ruleset
//! 2. Starts all sources (concurrent event streams)
//! 3. Merges streams into one channel (fan-in)
//! 4. For each event: enrich (geo) → pipeline (rules → heuristics → score) → actions
//! 5. Prints colored events to stdout and logs decisions

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sentry_core::config::{ActionKind, SentryConfig};
use sentry_core::event::Event;
use sentry_core::packs::build_default_ruleset;
use sentry_core::pipeline::{Pipeline, RouteDef, RouteValidator};
use sentry_core::registry::RegistryBuilder;
use sentry_core::RiskLevel;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Run the daemon.
pub async fn run(cfg: SentryConfig) -> color_eyre::Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting sentry daemon"
    );

    // Build the ruleset from configured packs.
    let pack_modes: HashMap<String, String> = cfg
        .rules
        .packs
        .iter()
        .map(|p| (p.name.clone(), p.mode.clone()))
        .collect();
    let rules = build_default_ruleset(&pack_modes);
    info!(rule_count = rules.len(), "ruleset built");

    // Build route validator (empty for now — routes come from config later).
    let route_validator = RouteValidator::new(vec![
        RouteDef {
            path: "/".into(),
            methods: vec!["GET".into()],
        },
        RouteDef {
            path: "/api/*".into(),
            methods: vec!["GET".into(), "POST".into()],
        },
        RouteDef {
            path: "/static/*".into(),
            methods: vec!["GET".into()],
        },
    ]);

    // Build the pipeline.
    let pipeline = Arc::new(Pipeline::new(rules, route_validator));

    // Build the plugin registry from config.
    let registry = build_registry(&cfg)?;

    if registry.source_count() == 0 {
        warn!("no sources configured — daemon will idle. Add [[source]] entries in sentry.toml");
    }

    // Fan-in: merge all source streams into one channel.
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(8192);

    // Start each source.
    for source in registry.sources() {
        let source = Arc::clone(source);
        let tx = event_tx.clone();
        tokio::spawn(async move {
            info!(source = source.name(), "starting source");
            match source.stream().await {
                Ok(mut rx) => {
                    while let Some(raw) = rx.recv().await {
                        let ip = raw
                            .client_ip
                            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                        let evt = raw.into_event(ip);
                        // Enrichment (geo/asn) would go here.
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
    let mut processed_count: u64 = 0;
    let mut blocked_count: u64 = 0;

    while let Some(evt) = event_rx.recv().await {
        let result = pipeline.process(&evt);

        // Print colored event line.
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

        // Execute applicable actions.
        for action in registry.actions() {
            if action.applies_to(&result.decision) {
                if let Err(e) = action.execute(&result.event, &result.decision).await {
                    warn!(action = action.name(), error = %e, "action failed");
                }
            }
        }

        processed_count += 1;
        if result.decision.action != sentry_core::Verdict::Allow {
            blocked_count += 1;
        }

        // Log stats periodically.
        if processed_count % 100 == 0 {
            info!(
                processed = processed_count,
                acted_upon = blocked_count,
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
fn build_registry(cfg: &SentryConfig) -> color_eyre::Result<sentry_core::registry::Registry> {
    let mut builder = RegistryBuilder::new();

    for src in &cfg.sources {
        match src.kind.as_str() {
            "nginx" => {
                let path = src
                    .options
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/var/log/nginx/access.log")
                    .to_string();
                let format = src.options.get("format").and_then(|v| v.as_str()).unwrap_or(r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent""#).to_string();
                let ns = sentry_source_nginx::NginxSource::new(
                    sentry_source_nginx::NginxSourceConfig {
                        path: path.into(),
                        format,
                        start_from_end: true,
                    },
                )?;
                builder.register_source(ns);
            }
            other => info!(
                source = other,
                "source plugin not yet implemented, skipping"
            ),
        }
    }

    // Build actions from config, dispatching on the type-safe ActionKind.
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
                let token = std::env::var("SENTRY_CF_TOKEN").unwrap_or_default();
                let zone = std::env::var("SENTRY_CF_ZONE").unwrap_or_default();
                if token.is_empty() || zone.is_empty() {
                    warn!("cloudflare action configured but SENTRY_CF_TOKEN/SENTRY_CF_ZONE env unset — skipping");
                    continue;
                }
                let mode = act
                    .options
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("managed_challenge");
                let mode = match mode {
                    "block" => sentry_action_cloudflare::ChallengeMode::Block,
                    "js_challenge" => sentry_action_cloudflare::ChallengeMode::JsChallenge,
                    _ => sentry_action_cloudflare::ChallengeMode::ManagedChallenge,
                };
                let ttl = parse_ttl_secs(&act.options, 86400);
                builder.register_action(sentry_action_cloudflare::CloudflareAction::new(
                    sentry_action_cloudflare::CloudflareActionConfig {
                        token,
                        zone,
                        mode,
                        ttl: Duration::from_secs(ttl),
                    },
                ));
            }
        }
    }

    // The log action is always present — it's the sink of last resort.
    if log_requested || cfg.actions.is_empty() {
        builder.register_action(LogAction);
    }

    Ok(builder.build())
}

/// Read `ttl_secs` (or `timeout_secs`) from a config options map, falling
/// back to `default_secs`. Returns the value in seconds.
fn parse_ttl_secs(opts: &HashMap<String, toml::Value>, default_secs: u64) -> u64 {
    opts.get("ttl_secs")
        .or_else(|| opts.get("timeout_secs"))
        .and_then(|v| v.as_integer())
        .map(|i| i.max(0) as u64)
        .unwrap_or(default_secs)
}

/// Parse a risk level name from config (`"high"` → `RiskLevel::High`).
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

/// Simple log action — prints decisions to stdout (always present).
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
            info!(ip = %evt.client_ip, action = ?decision.action, score = decision.analysis.risk_score, "decision executed");
        }
        Ok(())
    }
}
