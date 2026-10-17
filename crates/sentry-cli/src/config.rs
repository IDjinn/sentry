//! Config loading: `sentry.conf` (nginx-like format, see
//! [`sentry_core::conf`]) plus the env overlay.
//!
//! Files, in load order:
//! 1. the main config — `--config`/`SENTRY_CONFIG` (a file, or a directory:
//!    every `*.conf` in it, sorted), else `./sentry.conf`, else
//!    `/etc/sentry/sentry.conf`;
//! 2. `conf.d/*.conf` next to the main file (sorted) — split configs such
//!    as `detect.conf`, `sites/…` work the same through `include:`;
//! 3. `sentry.auto.conf` next to it (written by `sentry auto`): its routes
//!    and rules are appended and deduped, existing entries win;
//! 4. `.env` next to the config (dotenv-style, never overrides real env
//!    vars), then the `SENTRY_*` env overlay: nested keys separated by `__`
//!    (`SENTRY_STORAGE__POSTGRES__URL`) override single fields of the
//!    runtime model and leave their siblings untouched.
//!
//! The same unlabeled block may appear in several files (`detect {}` in
//! `detect.conf`); its contents merge, and a scalar set twice is an error
//! naming both places. A legacy `sentry.toml` is rejected with a pointer to
//! `sentry config migrate`.

use std::path::{Path, PathBuf};

use figment::providers::Env;
use figment::Provider;
use sentry_core::config::SentryConfig;

/// Main config file name.
pub const MAIN_FILE: &str = "sentry.conf";

/// Generated config cascaded into every load (routes/rules are appended,
/// never replaced).
pub const AUTO_FILE: &str = "sentry.auto.conf";

/// Directory of extra config files loaded after the main file.
pub const CONF_DIR: &str = "conf.d";

/// Secrets file looked up next to the resolved config (systemd
/// `EnvironmentFile` companion); fed into the env overlay, non-override.
const ENV_FILE: &str = ".env";

/// The config files a load resolves to.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    /// Main file or directory (`None` = defaults only).
    pub main: Option<PathBuf>,
    /// Directory holding the main config (auto file, `.env`, `conf.d`).
    pub dir: Option<PathBuf>,
    /// Files parsed, in order (auto file excluded).
    pub files: Vec<PathBuf>,
}

fn is_legacy_toml(p: &Path) -> bool {
    p.extension().is_some_and(|e| e == "toml")
}

/// Resolve which files a load reads.
pub fn resolve(path: Option<&Path>) -> color_eyre::Result<Resolved> {
    let main = match path {
        Some(p) => Some(PathBuf::from(p)),
        None => [
            PathBuf::from(MAIN_FILE),
            PathBuf::from("/etc/sentry").join(MAIN_FILE),
        ]
        .into_iter()
        .find(|p| p.exists()),
    };
    let Some(main) = main else {
        if path.is_none() {
            for legacy in ["sentry.toml", "/etc/sentry/sentry.toml"] {
                if Path::new(legacy).exists() {
                    color_eyre::eyre::bail!(
                        "found legacy {legacy} but no sentry.conf — convert it with \
                         `sentry config migrate {legacy} --out sentry.conf`"
                    );
                }
            }
        }
        return Ok(Resolved::default());
    };
    if !main.exists() {
        return Ok(Resolved::default());
    }
    if is_legacy_toml(&main) {
        color_eyre::eyre::bail!(
            "{} is a legacy TOML config — sentry now reads sentry.conf; convert it with \
             `sentry config migrate {} --out sentry.conf`",
            main.display(),
            main.display()
        );
    }
    let (dir, mut files) = if main.is_dir() {
        let files: Vec<PathBuf> = sentry_conf::conf_files_in(&main)
            .into_iter()
            .filter(|f| f.file_name().is_some_and(|n| n != AUTO_FILE))
            .collect();
        (main.clone(), files)
    } else {
        let dir = main
            .parent()
            .map(Path::to_path_buf)
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("."));
        (dir, vec![main.clone()])
    };
    files.extend(sentry_conf::conf_files_in(&dir.join(CONF_DIR)));
    Ok(Resolved {
        main: Some(main),
        dir: Some(dir),
        files,
    })
}

/// Load config from the default search path, merging files + env.
pub fn load(path: Option<&Path>) -> color_eyre::Result<SentryConfig> {
    let resolved = resolve(path)?;
    let loader = sentry_conf::Loader::default();
    let body = loader
        .load_files(&resolved.files)
        .map_err(|e| color_eyre::eyre::eyre!("config error: {e}"))?;
    let mut cfg =
        sentry_core::conf::from_body(&body).map_err(|e| color_eyre::eyre::eyre!("{e}"))?;

    if let Some(dir) = &resolved.dir {
        let auto_path = dir.join(AUTO_FILE);
        if auto_path.exists() {
            merge_auto_file(&mut cfg, &auto_path)?;
        }
        load_env_file(dir);
    }

    let mut cfg = apply_env_overlay(cfg, Env::prefixed("SENTRY_").split("__"))?;
    for unknown in cfg.resolve_feed_presets() {
        eprintln!("warning: unknown feed preset `{unknown}` (see `sentry feeds list`)");
    }
    Ok(cfg)
}

/// Semantic checks the schema cannot express: custom rules compile,
/// routing/runtime/update/protocol sections are coherent. Prints each
/// problem to stderr and fails with a one-line summary. Shared by
/// `sentry config validate`, `config set` and the daemon's live reload.
pub fn validate(cfg: &SentryConfig) -> color_eyre::Result<()> {
    let mut errors: Vec<String> = Vec::new();
    for parsed in sentry_core::rules::rules_from_config(&cfg.rules.custom) {
        if let Err(e) = parsed {
            errors.push(e);
        }
    }
    if let Err(e) = sentry_core::sensitive_files::Filter::from_names(
        &cfg.auto.sensitive.enable,
        &cfg.auto.sensitive.skip,
    ) {
        color_eyre::eyre::bail!("config INVALID: sentry › auto: {e}");
    }
    if let Err(e) = cfg.update.validate() {
        color_eyre::eyre::bail!("config INVALID: {e}");
    }
    let edge_errors = cfg.edge.validate();
    if !edge_errors.is_empty() {
        for e in &edge_errors {
            eprintln!("invalid http config: {e}");
        }
        color_eyre::eyre::bail!(
            "config INVALID: {} http/routing error(s)",
            edge_errors.len()
        );
    }
    if let Some(e) = cfg.runtime.validate().first() {
        color_eyre::eyre::bail!("config INVALID: {e}");
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("invalid custom rule: {e}");
        }
        color_eyre::eyre::bail!(
            "config INVALID: {} custom rule(s) failed to compile",
            errors.len()
        );
    }
    if cfg.protocol.enabled {
        let dir = &cfg.protocol.dir;
        match crate::protocol_cmd::compile_dir(dir, cfg.protocol.max_schemas) {
            Ok((_, es)) if es.is_empty() => {
                println!("  protocol:  OK ({})", dir.display());
            }
            Ok((_, es)) => {
                for e in &es {
                    eprintln!("invalid protocol schema: {e}");
                }
                color_eyre::eyre::bail!(
                    "config INVALID: {} protocol schema(s) failed to compile",
                    es.len()
                );
            }
            Err(e) => {
                color_eyre::eyre::bail!("config INVALID: protocol dir: {e}");
            }
        }
    }
    if cfg.posture.mode.is_enforce() {
        color_eyre::eyre::bail!(
            "config INVALID: detect › posture › mode: enforce is not implemented \
                 yet — header injection without per-site knowledge would break \
                 pages; use shadow (roadmap: BACKLOG.md §5.4)"
        );
    }
    Ok(())
}

/// Parse a legacy `sentry.toml` (for `sentry config migrate`).
pub fn load_legacy_toml(path: &Path) -> color_eyre::Result<SentryConfig> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| color_eyre::eyre::eyre!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| color_eyre::eyre::eyre!("{}: {e}", path.display()))
}

/// Load `<dir>/.env` into the process environment, dotenv-style: vars that
/// are already set (shell export, systemd unit, …) are never overridden.
/// A missing or unreadable file is silently ignored.
fn load_env_file(dir: &Path) {
    let Ok(content) = std::fs::read_to_string(dir.join(ENV_FILE)) else {
        return;
    };
    for (key, value) in parse_env_file(&content) {
        if std::env::var_os(&key).is_none() {
            std::env::set_var(&key, value);
        }
    }
}

/// Parse the systemd `EnvironmentFile` subset: `KEY=VALUE` lines, `#`/`;`
/// comments, blank lines, surrounding whitespace trimmed, optional
/// single/double quotes stripped. Malformed lines are skipped.
fn parse_env_file(content: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        let mut value = value.trim();
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = &value[1..value.len() - 1];
        }
        pairs.push((key.to_string(), value.to_string()));
    }
    pairs
}

/// Top-level blocks the auto config may contribute to.
const AUTO_SECTIONS: &[&str] = &["routes", "rules"];

/// Merge `sentry.auto.conf`: `routes`, rule packs and custom rules are
/// appended and deduped (existing entries win); any other block is warned
/// about and ignored.
fn merge_auto_file(cfg: &mut SentryConfig, path: &Path) -> color_eyre::Result<()> {
    let body = sentry_conf::Loader::default()
        .load_file(path)
        .map_err(|e| color_eyre::eyre::eyre!("config error: {e}"))?;
    let (kept, ignored): (Vec<_>, Vec<_>) = body
        .into_iter()
        .partition(|stmt| AUTO_SECTIONS.contains(&stmt.name()));
    for stmt in ignored {
        eprintln!(
            "warning: ignoring `{}` in {} — only {} are merged",
            stmt.name(),
            path.display(),
            AUTO_SECTIONS.join("/")
        );
    }
    let auto = sentry_core::conf::from_body(&kept).map_err(|e| color_eyre::eyre::eyre!("{e}"))?;
    merge_auto(cfg, auto);
    Ok(())
}

/// Append the auto config's routes/packs/custom rules, skipping entries
/// whose path/name (case-insensitive) already exists.
fn merge_auto(cfg: &mut SentryConfig, auto: SentryConfig) {
    for route in auto.routes.known {
        if !cfg
            .routes
            .known
            .iter()
            .any(|r| r.path.eq_ignore_ascii_case(&route.path))
        {
            cfg.routes.known.push(route);
        }
    }
    for pack in auto.rules.packs {
        if !cfg
            .rules
            .packs
            .iter()
            .any(|p| p.name.eq_ignore_ascii_case(&pack.name))
        {
            cfg.rules.packs.push(pack);
        }
    }
    for rule in auto.rules.custom {
        if !cfg
            .rules
            .custom
            .iter()
            .any(|r| r.name.eq_ignore_ascii_case(&rule.name))
        {
            cfg.rules.custom.push(rule);
        }
    }
}

/// Apply the env overlay field by field: the config is flattened to JSON,
/// env keys are merged leaf-by-leaf (a single `SENTRY_SERVER__HOST` never
/// wipes the rest of `server`), and the result is deserialized back.
fn apply_env_overlay(cfg: SentryConfig, env: Env) -> color_eyre::Result<SentryConfig> {
    let mut merged =
        serde_json::to_value(&cfg).map_err(|e| color_eyre::eyre::eyre!("config data: {e}"))?;
    let env_data = env
        .data()
        .map_err(|e| color_eyre::eyre::eyre!("env overlay: {e}"))?;
    let mut touched = false;
    for (_profile, dict) in env_data {
        if dict.is_empty() {
            continue;
        }
        let overlay =
            serde_json::to_value(&dict).map_err(|e| color_eyre::eyre::eyre!("env overlay: {e}"))?;
        merge_json(&mut merged, overlay);
        touched = true;
    }
    if !touched {
        return Ok(cfg);
    }
    serde_json::from_value(merged).map_err(|e| color_eyre::eyre::eyre!("env overlay: {e}"))
}

fn merge_json(base: &mut serde_json::Value, overlay: serde_json::Value) {
    match (base, overlay) {
        (serde_json::Value::Object(base), serde_json::Value::Object(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(slot) if slot.is_object() && value.is_object() => {
                        merge_json(slot, value);
                    }
                    _ => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate the process environment or call
    /// `load()` (which reads it): the overlay reads `SENTRY_*` vars at load
    /// time, so parallel tests race on `set_var`/`remove_var` windows.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sentry_cfg_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn merge_json_overrides_leaf_and_keeps_siblings() {
        let mut base = serde_json::json!({
            "server": {
                "host": "127.0.0.1",
                "auth": { "mode": "password", "users": [{ "username": "admin" }] },
            }
        });
        let overlay = serde_json::json!({ "server": { "host": "0.0.0.0" } });
        merge_json(&mut base, overlay);

        assert_eq!(base["server"]["host"], "0.0.0.0");
        assert_eq!(base["server"]["auth"]["mode"], "password");
        assert_eq!(base["server"]["auth"]["users"][0]["username"], "admin");
    }

    #[test]
    fn env_override_is_field_level() {
        let _env = env_lock();
        std::env::set_var("SENTRY_METRICS__PORT", "9999");
        // Explicit (absent) path skips the cwd//etc search — defaults only.
        let cfg = load(Some(Path::new("/nonexistent/sentry.conf"))).unwrap();
        std::env::remove_var("SENTRY_METRICS__PORT");
        assert_eq!(cfg.metrics.port, 9999);
        // Sibling keys of metrics survive the override.
        assert!(cfg.metrics.enabled);
    }

    #[test]
    fn env_override_keeps_file_auth_section() {
        let _env = env_lock();
        let dir = tmp("env_auth");
        let path = dir.join(MAIN_FILE);
        std::fs::write(
            &path,
            "dashboard {\n  listen: 127.0.0.1:8080\n  auth {\n    mode: password\n    user admin {\n      password_hash: \"argon2-here\"\n      role: admin\n    }\n  }\n}\n",
        )
        .unwrap();
        std::env::set_var("SENTRY_SERVER__HOST", "0.0.0.0");
        let cfg = load(Some(&path)).unwrap();
        std::env::remove_var("SENTRY_SERVER__HOST");
        assert_eq!(cfg.server.host, "0.0.0.0");
        assert_eq!(cfg.server.auth.mode, "password");
        assert_eq!(cfg.server.auth.users.len(), 1);
        assert_eq!(cfg.server.auth.users[0].username, "admin");
    }

    #[test]
    fn parse_env_file_covers_environmentfile_subset() {
        let pairs = parse_env_file(
            "# comment\n\
             ; also a comment\n\
             \n\
             SENTRY_STORAGE__POSTGRES__URL=postgres://u:p@localhost/db\n\
             SENTRY_JEV_KEY=\"abc=123\"\n\
             SENTRY_QUOTED='single'\n\
             SPACED =  spaced value \n\
             NO_EQUALS_LINE\n\
             = novalue\n",
        );
        assert_eq!(
            pairs,
            vec![
                (
                    "SENTRY_STORAGE__POSTGRES__URL".to_string(),
                    "postgres://u:p@localhost/db".to_string()
                ),
                ("SENTRY_JEV_KEY".to_string(), "abc=123".to_string()),
                ("SENTRY_QUOTED".to_string(), "single".to_string()),
                ("SPACED".to_string(), "spaced value".to_string()),
            ]
        );
    }

    #[test]
    fn env_file_next_to_config_feeds_overlay() {
        let _env = env_lock();
        let dir = tmp("dotenv");
        let main_path = dir.join(MAIN_FILE);
        std::fs::write(&main_path, "").unwrap();
        std::fs::write(
            dir.join(ENV_FILE),
            "SENTRY_STORAGE__POSTGRES__URL=postgres://fromfile/db\n",
        )
        .unwrap();

        let cfg = load(Some(&main_path)).unwrap();
        assert_eq!(cfg.storage.postgres.url, "postgres://fromfile/db");

        std::env::set_var("SENTRY_STORAGE__POSTGRES__URL", "postgres://fromenv/db");
        let cfg = load(Some(&main_path)).unwrap();
        std::env::remove_var("SENTRY_STORAGE__POSTGRES__URL");
        assert_eq!(
            cfg.storage.postgres.url, "postgres://fromenv/db",
            "real env wins over the .env file"
        );
    }

    #[test]
    fn split_files_conf_d_and_directory_loading() {
        let _env = env_lock();
        let dir = tmp("split");
        std::fs::create_dir_all(dir.join(CONF_DIR)).unwrap();
        std::fs::create_dir_all(dir.join("sites")).unwrap();
        std::fs::write(
            dir.join(MAIN_FILE),
            "sentry { mode: inline }\ninclude: detect.conf\nhttp {\n  upstream app { server: http://127.0.0.1:1 }\n  include: \"sites/*.conf\"\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("detect.conf"), "detect { scan { window: 2m } }\n").unwrap();
        std::fs::write(
            dir.join("sites/a.conf"),
            "site { host: a.test, proxy_pass: app }\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(CONF_DIR).join("storage.conf"),
            "storage { max_connections: 3 }\n",
        )
        .unwrap();
        let cfg = load(Some(&dir.join(MAIN_FILE))).unwrap();
        assert!(cfg.deployment.is_inline());
        assert_eq!(cfg.scan.window_secs, 120);
        assert_eq!(cfg.edge.sites[0].hosts, ["a.test"]);
        assert_eq!(cfg.storage.postgres.max_connections, 3, "conf.d loaded");

        let flat = tmp("flatdir");
        std::fs::write(
            flat.join("10-server.conf"),
            "server { channel_buffer: 7 }\n",
        )
        .unwrap();
        std::fs::write(
            flat.join("20-detect.conf"),
            "detect { scan { enabled: off } }\n",
        )
        .unwrap();
        let cfg = load(Some(&flat)).unwrap();
        assert_eq!(cfg.core.channel_buffer, 7);
        assert!(!cfg.scan.enabled);
    }

    #[test]
    fn legacy_toml_is_rejected_with_migration_hint() {
        let dir = tmp("legacy");
        let path = dir.join("sentry.toml");
        std::fs::write(&path, "[core]\nchannel_buffer = 1\n").unwrap();
        let err = load(Some(&path)).unwrap_err().to_string();
        assert!(err.contains("sentry config migrate"), "{err}");
        let cfg = load_legacy_toml(&path).unwrap();
        assert_eq!(cfg.core.channel_buffer, 1);
    }

    #[test]
    fn auto_config_appends_and_dedupes() {
        let _env = env_lock();
        let dir = tmp("auto");
        let main_path = dir.join(MAIN_FILE);
        std::fs::write(
            &main_path,
            "routes { \"/Mine\": GET }\nrules { packs { tor: shadow } }\n",
        )
        .unwrap();
        std::fs::write(
            dir.join(AUTO_FILE),
            "routes {\n  \"/mine\": POST\n  \"/api/*\": any\n}\n\
             rules {\n  packs { TOR: enforce, rate_scan: enforce }\n  rule auto_rule { priority: 40, match: 'path == \"/x\"', action: block }\n}\n\
             dashboard { listen: 9.9.9.9:1 }\n",
        )
        .unwrap();
        let cfg = load(Some(&main_path)).unwrap();
        let paths: Vec<&str> = cfg.routes.known.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            ["/Mine", "/api/*"],
            "existing path wins, new appended"
        );
        assert_eq!(cfg.routes.known[0].methods, ["GET"]);
        let packs: Vec<(&str, &str)> = cfg
            .rules
            .packs
            .iter()
            .map(|p| (p.name.as_str(), p.mode.as_str()))
            .collect();
        assert_eq!(packs, [("tor", "shadow"), ("rate_scan", "enforce")]);
        assert_eq!(cfg.rules.custom[0].name, "auto_rule");
        assert_eq!(
            cfg.server.host, "127.0.0.1",
            "auto file cannot touch dashboard"
        );
    }
}
