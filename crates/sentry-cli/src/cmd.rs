//! Subcommand handlers.
//!
//! Commands that need Postgres connect from the loaded config's
//! `storage.postgres.url`. If no URL is configured, they print a helpful
//! message instead of crashing.

use crate::cli::*;
use sentry_core::config::SentryConfig;

/// Dispatch a parsed CLI invocation with a possibly-loaded config.
pub async fn dispatch_with_config(cli: Cli, cfg: Option<SentryConfig>) -> color_eyre::Result<()> {
    match cli.command {
        Command::Run => {
            let cfg = cfg.ok_or_else(|| color_eyre::eyre::eyre!("config required for `run`"))?;
            crate::daemon::run(cfg).await?;
        }
        Command::Tail { stream, .. } => {
            if stream {
                tail_stream().await?;
            } else {
                crate::tui::run(cfg.as_ref())
                    .await
                    .map_err(color_eyre::Report::from)?;
            }
        }
        Command::Incidents { action } => match action {
            IncidentsCmd::List => {
                let cfg = require_config(&cfg)?;
                let repo = connect_storage(cfg).await?;
                let incidents = repo
                    .incidents()
                    .unresolved(50)
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                if incidents.is_empty() {
                    println!("No unresolved incidents.");
                } else {
                    println!(
                        "{:<38} {:<20} {:<10} {:<8} NOTES",
                        "ID", "CREATED", "LEVEL", "ACTION"
                    );
                    for i in &incidents {
                        println!(
                            "{:<38} {:<20} {:<10} {:<8} {}",
                            i.id,
                            i.created_at.format("%Y-%m-%d %H:%M"),
                            i.risk_level,
                            i.action,
                            i.notes.as_deref().unwrap_or("-"),
                        );
                    }
                }
            }
            IncidentsCmd::Show { id } => {
                let cfg = require_config(&cfg)?;
                let repo = connect_storage(cfg).await?;
                let incidents = repo
                    .incidents()
                    .unresolved(1000)
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                let id_parsed = id
                    .parse::<uuid::Uuid>()
                    .map_err(|e| color_eyre::eyre::eyre!("invalid UUID: {e}"))?;
                let found = incidents.iter().find(|i| i.id == id_parsed);
                match found {
                    Some(i) => {
                        println!("ID:       {}", i.id);
                        println!(
                            "Event:    {}",
                            i.event_id.map(|u| u.to_string()).unwrap_or("-".into())
                        );
                        println!("Created:  {}", i.created_at);
                        println!("Level:    {}", i.risk_level);
                        println!("Action:   {}", i.action);
                        println!("Resolved: {}", i.resolved);
                        println!("Notes:    {}", i.notes.as_deref().unwrap_or("-"));
                    }
                    None => println!("Incident {id} not found (or already resolved)."),
                }
            }
        },
        Command::Ip { ip, action } => {
            let cfg = require_config(&cfg)?;
            let repo = connect_storage(cfg).await?;
            let ip_addr: std::net::IpAddr = ip
                .parse()
                .map_err(|e| color_eyre::eyre::eyre!("invalid IP: {e}"))?;
            match action {
                Some(IpCmd::Block { ttl, note }) => {
                    let expires_at = ttl
                        .as_deref()
                        .map(parse_duration)
                        .transpose()?
                        .map(|d| chrono::Utc::now() + d);
                    repo.ip_state()
                        .block(ip_addr, note.as_deref(), expires_at)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("block failed: {e}"))?;
                    println!(
                        "Blocked {ip} (expires: {})",
                        expires_at.map(|t| t.to_string()).unwrap_or("never".into())
                    );
                    notify_rules_changed(&repo).await;
                }
                Some(IpCmd::Unblock) => {
                    repo.ip_state()
                        .unblock(ip_addr)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("unblock failed: {e}"))?;
                    println!("Unblocked {ip}");
                    notify_rules_changed(&repo).await;
                }
                Some(IpCmd::Info) | None => {
                    let is_blocked = repo
                        .ip_state()
                        .is_blocked(ip_addr)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                    println!("IP:       {ip}");
                    println!("Blocked:  {is_blocked}");
                    let blocked_list = repo
                        .ip_state()
                        .blocked(1000)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                    if let Some(row) = blocked_list.iter().find(|r| r.ip == ip) {
                        println!("Reason:   {}", row.reason.as_deref().unwrap_or("-"));
                        println!(
                            "Expires:  {}",
                            row.expires_at
                                .map(|t| t.to_string())
                                .unwrap_or("never".into())
                        );
                        println!("Updated:  {}", row.updated_at);
                    }
                }
            }
        }
        Command::Routes { action } => match action {
            RoutesCmd::List => {
                let cfg = require_config(&cfg)?;
                let repo = connect_storage(cfg).await?;
                let routes = repo
                    .routes()
                    .list()
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                if routes.is_empty() {
                    println!("No routes in database. Config routes:");
                    for r in &cfg.routes.known {
                        println!("  (config) {} [{}]", r.path, r.methods.join(","));
                    }
                } else {
                    println!("{:<5} {:<30} METHODS", "ID", "PATH");
                    for r in &routes {
                        println!("{:<5} {:<30} {}", r.id, r.path, r.methods.join(","));
                    }
                }
            }
            RoutesCmd::Learn => {
                println!("Route learning mode not yet implemented (F2).");
                println!("Add routes manually via the database or sentry.toml [[routes.known]].");
            }
        },
        Command::Rules { action } => {
            match action {
                RulesCmd::List => {
                    let cfg = require_config(&cfg)?;
                    if let Ok(repo) = connect_storage(cfg).await {
                        let rules = repo
                            .rules()
                            .list()
                            .await
                            .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                        if rules.is_empty() {
                            println!("No rules in database.");
                        } else {
                            println!(
                                "{:<20} {:<25} {:<8} {:<7} {:<10} MATCH",
                                "ID", "NAME", "PRIORITY", "ENABLED", "ACTION"
                            );
                            for r in &rules {
                                println!(
                                    "{:<20} {:<25} {:<8} {:<7} {:<10} {}",
                                    r.id, r.name, r.priority, r.enabled, r.action, r.match_expr
                                );
                            }
                        }
                    }
                    println!("\nConfig packs:");
                    for p in &cfg.rules.packs {
                        println!("  {} = {}", p.name, p.mode);
                    }
                }
                RulesCmd::Show { id } => {
                    let cfg = require_config(&cfg)?;
                    let repo = connect_storage(cfg).await?;
                    let rules = repo
                        .rules()
                        .list()
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                    match rules.iter().find(|r| r.id == id) {
                        Some(r) => {
                            println!("ID:       {}", r.id);
                            println!("Name:     {}", r.name);
                            println!("Priority: {}", r.priority);
                            println!("Enabled:  {}", r.enabled);
                            println!("Action:   {}", r.action);
                            println!("Match:    {}", r.match_expr);
                            println!("TTL:      {:?}", r.ttl_secs);
                            println!("Source:   {}", r.source);
                            println!("Tags:     {}", r.tags.join(", "));
                            println!("Created:  {}", r.created_at);
                        }
                        None => println!("Rule '{id}' not found."),
                    }
                }
                RulesCmd::Add {
                    name,
                    r#match,
                    action,
                    priority,
                } => {
                    let cfg = require_config(&cfg)?;
                    let repo = connect_storage(cfg).await?;
                    let id = name.to_lowercase().replace(' ', "-");
                    repo.rules()
                        .upsert(&id, &name, priority, true, &r#match, &action, None, &[])
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("upsert failed: {e}"))?;
                    println!("Added rule '{id}' (match: {match}, action: {action}, priority: {priority})");
                    notify_rules_changed(&repo).await;
                }
                RulesCmd::Allow { ip, ttl, note } => {
                    let cfg = require_config(&cfg)?;
                    let repo = connect_storage(cfg).await?;
                    let id = format!("allow-{ip}");
                    let match_expr = format!("ip={ip}");
                    repo.rules()
                        .upsert(
                            &id,
                            &format!("Allow {ip}"),
                            1,
                            true,
                            &match_expr,
                            "allow",
                            None,
                            &[],
                        )
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("upsert failed: {e}"))?;
                    println!(
                        "Allowlisted {ip}{}",
                        ttl_or_note(ttl.as_deref(), note.as_deref())
                    );
                    notify_rules_changed(&repo).await;
                }
                RulesCmd::Block { ip, ttl, note } => {
                    let cfg = require_config(&cfg)?;
                    let repo = connect_storage(cfg).await?;
                    let id = format!("block-{ip}");
                    let match_expr = format!("ip={ip}");
                    let ttl_secs = ttl
                        .as_deref()
                        .and_then(|s| parse_duration(s).ok().map(|d| d.num_seconds() as i32));
                    repo.rules()
                        .upsert(
                            &id,
                            &format!("Block {ip}"),
                            1,
                            true,
                            &match_expr,
                            "block",
                            ttl_secs,
                            &[],
                        )
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("upsert failed: {e}"))?;
                    println!(
                        "Blocked {ip}{}",
                        ttl_or_note(ttl.as_deref(), note.as_deref())
                    );
                    notify_rules_changed(&repo).await;
                }
                RulesCmd::Enable { id } => {
                    let cfg = require_config(&cfg)?;
                    let repo = connect_storage(cfg).await?;
                    repo.rules()
                        .set_enabled(&id, true)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("update failed: {e}"))?;
                    println!("Enabled rule '{id}'");
                    notify_rules_changed(&repo).await;
                }
                RulesCmd::Disable { id } => {
                    let cfg = require_config(&cfg)?;
                    let repo = connect_storage(cfg).await?;
                    repo.rules()
                        .set_enabled(&id, false)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("update failed: {e}"))?;
                    println!("Disabled rule '{id}'");
                    notify_rules_changed(&repo).await;
                }
                RulesCmd::Delete { id } => {
                    let cfg = require_config(&cfg)?;
                    let repo = connect_storage(cfg).await?;
                    repo.rules()
                        .delete(&id)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("delete failed: {e}"))?;
                    println!("Deleted rule '{id}'");
                    notify_rules_changed(&repo).await;
                }
                RulesCmd::Packs => {
                    let cfg = require_config(&cfg)?;
                    println!("{:<20} {:<10}", "PACK", "MODE");
                    for p in &cfg.rules.packs {
                        println!("{:<20} {:<10}", p.name, p.mode);
                    }
                    println!("\nAvailable default packs:");
                    for name in sentry_core::packs::PackMode::all_pack_names() {
                        let mode = cfg
                            .rules
                            .packs
                            .iter()
                            .find(|p| p.name == *name)
                            .map(|p| p.mode.as_str())
                            .unwrap_or("off");
                        println!("  {name:<20} {mode}");
                    }
                }
                RulesCmd::Test {
                    path,
                    method,
                    ip,
                    ua,
                } => {
                    test_rules(&cfg, &path, &method, &ip, &ua)?;
                }
            }
        }
        Command::Report { from, export } => {
            let cfg = require_config(&cfg)?;
            let repo = connect_storage(cfg).await?;
            let counts = repo
                .events()
                .count_by_level()
                .await
                .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
            println!("Report (last {from}):");
            if counts.is_empty() {
                println!("  No events recorded.");
            } else {
                for (level, count) in &counts {
                    println!("  {level:<10} {count}");
                }
            }
            if let Some(fmt) = export {
                eprintln!("Export format '{fmt}' not yet implemented.");
            }
        }
        Command::Config { action } => match action {
            ConfigCmd::Validate => {
                let cfg = require_config(&cfg)?;
                println!("config OK");
                println!("  sources:   {}", cfg.sources.len());
                println!("  actions:   {}", cfg.actions.len());
                println!("  routes:    {}", cfg.routes.known.len());
                println!("  packs:     {}", cfg.rules.packs.len());
                println!(
                    "  storage:   {}",
                    if cfg.storage.postgres.url.is_empty() {
                        "disabled"
                    } else {
                        "enabled"
                    }
                );
            }
            ConfigCmd::Show => {
                let cfg = require_config(&cfg)?;
                println!("{}", toml::to_string_pretty(&cfg)?);
            }
        },
        Command::Model { action } => match action {
            ModelCmd::Status => {
                println!("Model: ONNX threat model (F2 — not yet loaded)");
                println!(
                    "Provider: {}",
                    cfg.as_ref()
                        .map(|c| c.llm.provider.as_str())
                        .unwrap_or("none")
                );
            }
            ModelCmd::Reload => {
                println!("Model reload not yet implemented (F2).");
            }
        },
        Command::Cloudflare { action } => match action {
            CloudflareCmd::Status => {
                let token = std::env::var("SENTRY_CF_TOKEN").unwrap_or_default();
                let zone = std::env::var("SENTRY_CF_ZONE").unwrap_or_default();
                println!(
                    "Cloudflare token: {}",
                    if token.is_empty() { "NOT SET" } else { "set" }
                );
                println!(
                    "Cloudflare zone:  {}",
                    if zone.is_empty() { "NOT SET" } else { "set" }
                );
            }
            CloudflareCmd::Pull => {
                println!("Cloudflare log pull not yet implemented (F2).");
            }
        },
        Command::Test {
            payload,
            path,
            method,
        } => {
            test_payload(&payload, &path, &method)?;
        }
        Command::Auto {
            root,
            profile,
            dry_run,
            merge,
            deep,
        } => {
            println!("(stub) auto root={root:?} profile={profile:?} dry_run={dry_run} merge={merge} deep={deep}");
        }
    }
    Ok(())
}

fn require_config(cfg: &Option<SentryConfig>) -> color_eyre::Result<&SentryConfig> {
    cfg.as_ref().ok_or_else(|| {
        color_eyre::eyre::eyre!("config required — pass --config or create sentry.toml")
    })
}

async fn connect_storage(cfg: &SentryConfig) -> color_eyre::Result<sentry_storage::Repo> {
    if cfg.storage.postgres.url.is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "storage.postgres.url is not configured — set it in sentry.toml or via SENTRY_STORAGE__POSTGRES__URL env"
        ));
    }
    let pool = sentry_storage::PgPool::connect(&cfg.storage.postgres)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("postgres connection failed: {e}"))?;
    Ok(sentry_storage::Repo::new(pool))
}

async fn notify_rules_changed(repo: &sentry_storage::Repo) {
    let _ = repo.pool().notify("sentry_rules_changed").await;
}

fn parse_duration(s: &str) -> color_eyre::Result<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(color_eyre::eyre::eyre!("empty duration"));
    }
    let (num_str, unit) = s
        .find(|c: char| !c.is_ascii_digit())
        .map(|pos| s.split_at(pos))
        .unwrap_or((s, ""));
    let num: i64 = num_str
        .parse()
        .map_err(|e| color_eyre::eyre::eyre!("invalid duration number: {e}"))?;
    let secs = match unit {
        "s" | "" => num,
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        "w" => num * 86400 * 7,
        _ => {
            return Err(color_eyre::eyre::eyre!(
                "unknown duration unit '{unit}' (use s/m/h/d/w)"
            ))
        }
    };
    chrono::Duration::try_seconds(secs)
        .ok_or_else(|| color_eyre::eyre::eyre!("duration out of range"))
}

fn ttl_or_note(ttl: Option<&str>, note: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(t) = ttl {
        parts.push(format!(" (ttl: {t})"));
    }
    if let Some(n) = note {
        parts.push(format!(" (note: {n})"));
    }
    parts.join("")
}

fn test_rules(
    cfg: &Option<SentryConfig>,
    path: &str,
    method: &str,
    ip: &Option<String>,
    ua: &Option<String>,
) -> color_eyre::Result<()> {
    use sentry_core::event::{Event, HttpData, HttpMethod, ProtocolData, SourceKind};
    use sentry_core::packs::build_default_ruleset;
    use sentry_core::pipeline::{Pipeline, RouteValidator};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    let pack_modes: HashMap<String, String> = cfg
        .as_ref()
        .map(|c| {
            c.rules
                .packs
                .iter()
                .map(|p| (p.name.clone(), p.mode.clone()))
                .collect()
        })
        .unwrap_or_default();
    let rules = build_default_ruleset(&pack_modes);
    let routes = cfg
        .as_ref()
        .map(|c| RouteValidator::from_config(&c.routes.known))
        .unwrap_or_default();
    let scorer = cfg.as_ref().map(|c| c.scorer.clone()).unwrap_or_default();
    let pipeline = Pipeline::with_config(
        std::sync::Arc::new(std::sync::RwLock::new(rules)),
        routes,
        scorer,
    );

    let client_ip: std::net::IpAddr = ip
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

    let mut http = HttpData {
        method: Some(HttpMethod::from_str_lossy(method)),
        path: path.to_string(),
        ..Default::default()
    };
    if let Some((p, q)) = path.split_once('?') {
        http.path = p.to_string();
        http.query = Some(q.to_string());
    }
    if let Some(ua_str) = ua {
        http.user_agent = Some(ua_str.clone());
    }

    let evt = Event::new(SourceKind::Synthetic, client_ip, ProtocolData::Http(http));
    let result = pipeline.process(&evt);

    println!("┌─ Rule Test ────────────────────────────────────────────");
    println!("│ Path:     {path}");
    println!("│ Method:   {method}");
    println!("│ IP:       {client_ip}");
    if let Some(ua) = ua {
        println!("│ UA:       {ua}");
    }
    println!("│");
    println!("│ Score:    {}/100", result.analysis.risk_score);
    println!("│ Level:    {:?}", result.analysis.risk_level);
    println!("│ Verdict:  {:?}", result.decision.action);
    if let Some(rule_id) = &result.rule_hit {
        println!("│ Rule:     {rule_id} (short-circuit)");
    }
    if !result.analysis.signals.is_empty() {
        println!("│ Signals:");
        for s in &result.analysis.signals {
            println!(
                "│   - {:?} (weight {}): {}",
                s.kind,
                s.weight,
                s.detail.as_deref().unwrap_or("")
            );
        }
    } else {
        println!("│ Signals:  (none)");
    }
    println!("└────────────────────────────────────────────────────────");

    Ok(())
}

/// Run the pipeline on a single synthetic payload and print the result.
fn test_payload(payload: &str, path: &str, method: &str) -> color_eyre::Result<()> {
    use sentry_core::event::{Event, HttpData, HttpMethod, ProtocolData, SourceKind};
    use sentry_core::packs::build_default_ruleset;
    use sentry_core::pipeline::{Pipeline, RouteValidator};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    let rules = build_default_ruleset(&HashMap::new());
    let routes = RouteValidator::default();
    let pipeline = Pipeline::new(rules, routes);

    let mut http = HttpData {
        method: Some(HttpMethod::from_str_lossy(method)),
        path: path.to_string(),
        ..Default::default()
    };
    if let Some((p, q)) = path.split_once('?') {
        http.path = p.to_string();
        http.query = Some(q.to_string());
    }
    if http.query.is_none() && !payload.is_empty() {
        http.query = Some(payload.to_string());
    }
    if payload.starts_with('/') {
        http.path = format!("{path}{payload}");
    }

    let evt = Event::new(
        SourceKind::Synthetic,
        std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        ProtocolData::Http(http),
    );

    let result = pipeline.process(&evt);

    println!("┌─ Analysis Result ──────────────────────────────────────");
    println!("│ IP:       {}", evt.client_ip);
    println!(
        "│ Path:     {}",
        evt.http().map(|h| h.path.as_str()).unwrap_or("(none)")
    );
    println!("│ Method:   {method}");
    println!("│ Payload:  {payload}");
    println!("│");
    println!("│ Score:    {}/100", result.analysis.risk_score);
    println!("│ Level:    {:?}", result.analysis.risk_level);
    println!("│ Verdict:  {:?}", result.decision.action);
    if let Some(rule_id) = &result.rule_hit {
        println!("│ Rule:     {} (short-circuit)", rule_id);
    }
    if !result.analysis.signals.is_empty() {
        println!("│ Signals:");
        for s in &result.analysis.signals {
            println!(
                "│   - {:?} (weight {}): {}",
                s.kind,
                s.weight,
                s.detail.as_deref().unwrap_or("")
            );
        }
    } else {
        println!("│ Signals:  (none)");
    }
    println!("└────────────────────────────────────────────────────────");

    Ok(())
}

/// Stream events to stdout, one per line.
async fn tail_stream() -> color_eyre::Result<()> {
    println!("tail stream — connect to a running daemon (F2).");
    println!("For now, use `sentry run` to process events live.");
    Ok(())
}
