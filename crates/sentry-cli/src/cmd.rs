//! Subcommand handlers. Most are stubs for F0; fleshed out per phase.

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
                crate::tui::run().await.map_err(color_eyre::Report::from)?;
            }
        }
        Command::Incidents { action } => match action {
            IncidentsCmd::List => println!("(stub) listing incidents"),
            IncidentsCmd::Show { id } => println!("(stub) incident {id}"),
        },
        Command::Ip { ip, action } => match action {
            Some(IpCmd::Block { ttl, note }) => {
                println!("(stub) block {ip} ttl={ttl:?} note={note:?}")
            }
            Some(IpCmd::Unblock) => println!("(stub) unblock {ip}"),
            Some(IpCmd::Info) | None => println!("(stub) info {ip}"),
        },
        Command::Routes { action } => match action {
            RoutesCmd::List => println!("(stub) routes list"),
            RoutesCmd::Learn => println!("(stub) routes learn"),
        },
        Command::Rules { action } => match action {
            RulesCmd::List => println!("(stub) rules list"),
            RulesCmd::Show { id } => println!("(stub) rule {id}"),
            RulesCmd::Add {
                name,
                r#match,
                action,
                priority,
            } => {
                println!("(stub) add rule {name} match={match} action={action} priority={priority}")
            }
            RulesCmd::Allow { ip, ttl, note } => {
                println!("(stub) allow {ip} ttl={ttl:?} note={note:?}")
            }
            RulesCmd::Block { ip, ttl, note } => {
                println!("(stub) block {ip} ttl={ttl:?} note={note:?}")
            }
            RulesCmd::Enable { id } => println!("(stub) enable {id}"),
            RulesCmd::Disable { id } => println!("(stub) disable {id}"),
            RulesCmd::Delete { id } => println!("(stub) delete {id}"),
            RulesCmd::Packs => println!("(stub) packs list"),
            RulesCmd::Test {
                path,
                method,
                ip,
                ua,
            } => println!("(stub) test path={path} method={method} ip={ip:?} ua={ua:?}"),
        },
        Command::Report { from, export } => println!("(stub) report from={from} export={export:?}"),
        Command::Config { action } => match action {
            ConfigCmd::Validate => {
                let _ = cfg.ok_or_else(|| color_eyre::eyre::eyre!("config required"))?;
                println!("config OK");
            }
            ConfigCmd::Show => {
                let cfg = cfg.ok_or_else(|| color_eyre::eyre::eyre!("config required"))?;
                println!("{}", toml::to_string_pretty(&cfg)?);
            }
        },
        Command::Model { action } => match action {
            ModelCmd::Status => println!("(stub) model status"),
            ModelCmd::Reload => println!("(stub) model reload"),
        },
        Command::Cloudflare { action } => match action {
            CloudflareCmd::Status => println!("(stub) cloudflare status"),
            CloudflareCmd::Pull => println!("(stub) cloudflare pull"),
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
    // If path contains query, split it.
    if let Some((p, q)) = path.split_once('?') {
        http.path = p.to_string();
        http.query = Some(q.to_string());
    }
    // Also put the payload in query for detection.
    if http.query.is_none() && !payload.is_empty() {
        http.query = Some(payload.to_string());
    }
    // If payload looks like a path, append to path.
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

/// Stream events to stdout, one per line. Stub until the pipeline exists.
async fn tail_stream() -> color_eyre::Result<()> {
    println!("(stub) tail stream — pipeline not yet wired (F1.8)");
    Ok(())
}
