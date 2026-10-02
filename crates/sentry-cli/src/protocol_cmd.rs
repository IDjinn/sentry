//! Protocol schema CLI helpers (F9): compile/inspect/test schemas.

use std::path::Path;

use sentry_protocol::compile::{CompileOptions, Compiled};
use sentry_protocol::{ConnectionState, ProtocolEngine, ProtocolSchema};

/// Loads and compiles every `*.protocol.yaml` in `dir` into one set.
pub fn compile_dir(dir: &Path, max: usize) -> color_eyre::Result<(Compiled, Vec<String>)> {
    let mut compiled = Compiled::default();
    let mut errors = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|x| x == "yaml" || x == "yml")
                .unwrap_or(false)
        })
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().ends_with(".protocol.yaml"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    if files.len() > max {
        color_eyre::eyre::bail!(
            "protocol dir {} holds {} schemas; max is {max}",
            dir.display(),
            files.len()
        );
    }
    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|t| ProtocolSchema::from_yaml(&t).map_err(|e| e.to_string()))
        {
            Ok(schema) => {
                if let Err(e) = compiled.add(schema, &CompileOptions::default()) {
                    errors.push(format!("{name}: {e}"));
                }
            }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }
    Ok((compiled, errors))
}

fn resolve_dir(cfg: &sentry_core::SentryConfig, dir: Option<String>) -> std::path::PathBuf {
    dir.map(std::path::PathBuf::from)
        .unwrap_or_else(|| cfg.protocol.dir.clone())
}

/// `sentry protocol validate [dir]`.
pub fn protocol_validate(
    cfg: &sentry_core::SentryConfig,
    dir: Option<String>,
) -> color_eyre::Result<()> {
    let dir = resolve_dir(cfg, dir);
    let (compiled, errors) = compile_dir(&dir, cfg.protocol.max_schemas)?;
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("invalid schema: {e}");
        }
        color_eyre::eyre::bail!(
            "protocol INVALID: {} schema(s) failed to compile",
            errors.len()
        );
    }
    println!(
        "protocol OK ({} schema(s) in {})",
        compiled.protocols.len(),
        dir.display()
    );
    for p in &compiled.protocols {
        println!(
            "  {}: {} message(s), ports {:?}",
            p.schema_id,
            p.messages.len(),
            p.ports
        );
    }
    Ok(())
}

/// `sentry protocol list [dir]`.
pub fn protocol_list(
    cfg: &sentry_core::SentryConfig,
    dir: Option<String>,
) -> color_eyre::Result<()> {
    let dir = resolve_dir(cfg, dir);
    let (compiled, errors) = compile_dir(&dir, cfg.protocol.max_schemas)?;
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("invalid schema: {e}");
        }
    }
    for p in &compiled.protocols {
        println!("{} v? (ports {:?})", p.schema_id, p.ports);
        for (name, policy) in p.policies.iter() {
            println!("  policy {name}: weight {}", policy.weight);
        }
        for m in &p.messages {
            println!("  message {}: policy {}", m.name, m.policy);
        }
    }
    Ok(())
}

/// `sentry protocol check <schema> --hex <bytes>`.
pub fn protocol_check(schema_path: &str, hex: &str) -> color_eyre::Result<()> {
    let text = std::fs::read_to_string(schema_path)?;
    let schema = ProtocolSchema::from_yaml(&text)?;
    let mut compiled = Compiled::default();
    compiled.add(schema, &CompileOptions::default())?;

    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        color_eyre::eyre::bail!("hex input must have an even number of digits");
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for pair in clean.as_bytes().chunks(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }

    let engine = ProtocolEngine::new(compiled);
    let snapshot = engine.current();
    let proto = &snapshot.protocols[0];
    let mut state = ConnectionState::new();
    match engine.feed(proto, &mut state, &bytes) {
        Ok(info) => {
            println!("OK: message {}", info.message);
            if info.keepalive {
                println!("  (keepalive refreshed)");
            }
        }
        Err(violations) => {
            for v in &violations {
                println!(
                    "VIOLATION policy={} message={} escalated={} : {}",
                    v.policy, v.message, v.escalated, v.reason
                );
            }
            color_eyre::eyre::bail!("frame rejected with {} violation(s)", violations.len());
        }
    }
    Ok(())
}
