//! Config loading: figment (TOML + env overlay).
//!
//! Env vars override config values using the `SENTRY_` prefix with nested
//! keys separated by `__` (e.g. `SENTRY_STORAGE__POSTGRES__URL`). Overrides
//! are field-level: setting `SENTRY_SERVER__HOST` replaces `server.host` and
//! leaves the rest of `[server]` (auth, users, …) untouched.

use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Serialized, Toml};
use figment::{Figment, Provider};
use sentry_core::config::SentryConfig;

/// Generated config cascaded into every load (routes/rules are appended,
/// never replaced).
pub const AUTO_FILE: &str = "sentry.auto.toml";

/// Load config from the default search path, merging TOML + env.
pub fn load(path: Option<&Path>) -> color_eyre::Result<SentryConfig> {
    let figment = Figment::from(Serialized::defaults(SentryConfig::default()));

    // Try explicit path, then cwd, then /etc/sentry/sentry.toml.
    let main_path = match path {
        Some(p) => Some(PathBuf::from(p)),
        None => {
            let cwd = PathBuf::from("sentry.toml");
            let etc = PathBuf::from("/etc/sentry/sentry.toml");
            if cwd.exists() {
                Some(cwd)
            } else if etc.exists() {
                Some(etc)
            } else {
                None
            }
        }
    };
    let figment = match &main_path {
        Some(p) => figment.merge(Toml::file(p)),
        None => figment,
    };

    // Cascade: sentry.auto.toml sits next to the main config (`sentry auto`
    // writes it); its routes/rules are appended to the user's own values.
    let auto_path = main_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|dir| dir.join(AUTO_FILE))
        .unwrap_or_else(|| PathBuf::from(AUTO_FILE));
    let figment = if auto_path.exists() {
        merge_auto_file(figment, &auto_path)?
    } else {
        figment
    };

    // Env overlay: SENTRY_STORAGE__POSTGRES__URL=...
    let figment = deep_merge_env(figment, Env::prefixed("SENTRY_").split("__"))?;

    let mut cfg: SentryConfig = figment
        .extract()
        .map_err(|e| color_eyre::eyre::eyre!("config load error: {}", e))?;

    for unknown in cfg.resolve_feed_presets() {
        eprintln!("warning: unknown feed preset `{unknown}` (see `sentry feeds list`)");
    }

    Ok(cfg)
}

/// Top-level sections the auto config may contribute to.
const AUTO_SECTIONS: &[&str] = &["routes", "rules"];

/// Merge `sentry.auto.toml` into the figment: `routes.known`,
/// `rules.pack` and `rules.custom` are appended and deduped (existing
/// entries win); anything else in the file is warned about and ignored.
fn merge_auto_file(figment: Figment, path: &Path) -> color_eyre::Result<Figment> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| color_eyre::eyre::eyre!("{}: {e}", path.display()))?;
    let auto: toml::Value =
        toml::from_str(&content).map_err(|e| color_eyre::eyre::eyre!("{}: {e}", path.display()))?;
    let auto_json = serde_json::to_value(auto)
        .map_err(|e| color_eyre::eyre::eyre!("{}: {e}", path.display()))?;

    let mut merged: serde_json::Value = figment
        .extract()
        .map_err(|e| color_eyre::eyre::eyre!("config data: {e}"))?;
    let ignored = merge_auto_json(&mut merged, auto_json);
    for section in ignored {
        eprintln!(
            "warning: ignoring `{section}` in {} — only {} are merged",
            path.display(),
            AUTO_SECTIONS.join("/")
        );
    }

    Ok(Figment::from(JsonOverlay(
        merged,
        "sentry.auto.toml (cascade)",
    )))
}

/// Append the auto config's routes/rules onto the merged config. Returns
/// the ignored top-level sections.
fn merge_auto_json(base: &mut serde_json::Value, auto: serde_json::Value) -> Vec<String> {
    let mut ignored = Vec::new();
    let serde_json::Value::Object(auto) = auto else {
        return ignored;
    };
    for (key, value) in auto {
        match key.as_str() {
            "routes" => merge_auto_arrays(base, "routes", "known", &["path"], &value),
            "rules" => {
                merge_auto_arrays(base, "rules", "pack", &["name"], &value);
                merge_auto_arrays(base, "rules", "custom", &["name"], &value);
            }
            other => ignored.push(other.to_string()),
        }
    }
    ignored
}

/// Append `auto[section][array_key]` entries onto
/// `base[section][array_key]`, skipping entries whose `dedupe_keys` values
/// already exist (case-insensitive). Other keys inside the section are
/// skipped.
fn merge_auto_arrays(
    base: &mut serde_json::Value,
    section: &str,
    array_key: &str,
    dedupe_keys: &[&str],
    auto_section: &serde_json::Value,
) {
    let Some(entries) = auto_section.get(array_key).and_then(|v| v.as_array()) else {
        return;
    };
    let entry = base
        .as_object_mut()
        .expect("merged config is an object")
        .entry(section.to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !entry.is_object() {
        *entry = serde_json::json!({});
    }
    let list = entry
        .as_object_mut()
        .expect("section is an object")
        .entry(array_key.to_string())
        .or_insert_with(|| serde_json::json!([]));
    if !list.is_array() {
        *list = serde_json::json!([]);
    }
    let arr = list.as_array_mut().expect("array key is an array");
    for item in entries {
        if entry_key(item, dedupe_keys).is_some_and(|key| {
            arr.iter()
                .any(|e| entry_key(e, dedupe_keys).as_deref() == Some(key.as_str()))
        }) {
            continue;
        }
        arr.push(item.clone());
    }
}

/// Lowercased composite key of an entry over `keys` (dedupe identity).
fn entry_key(entry: &serde_json::Value, keys: &[&str]) -> Option<String> {
    let mut key = String::new();
    for k in keys {
        let value = entry.get(*k)?.as_str()?.to_ascii_lowercase();
        key.push_str(&value);
        key.push('\u{1}');
    }
    Some(key)
}

/// Deep-merge an env provider into `figment`.
///
/// `Figment::merge` replaces a collided top-level key wholesale, so a single
/// `SENTRY_SERVER__HOST` would silently wipe the rest of the `[server]` table
/// (auth included). Both layers are flattened to JSON, merged field-by-field,
/// and the result is served back as a default-profile provider: only the
/// referenced leaf is overridden.
fn deep_merge_env(figment: Figment, env: Env) -> color_eyre::Result<Figment> {
    let mut merged: serde_json::Value = figment
        .extract()
        .map_err(|e| color_eyre::eyre::eyre!("config data: {e}"))?;

    let env_data = env
        .data()
        .map_err(|e| color_eyre::eyre::eyre!("env overlay: {e}"))?;
    for (_profile, dict) in env_data {
        let overlay =
            serde_json::to_value(&dict).map_err(|e| color_eyre::eyre::eyre!("env overlay: {e}"))?;
        merge_json(&mut merged, overlay);
    }

    Ok(Figment::from(JsonOverlay(merged, "env overlay (deep)")))
}

/// Provider serving a whole resolved config under the default profile
/// (used by the env deep-merge and the `sentry.auto.toml` cascade).
struct JsonOverlay(serde_json::Value, &'static str);

impl figment::Provider for JsonOverlay {
    fn metadata(&self) -> figment::Metadata {
        figment::Metadata::named(self.1)
    }

    fn data(
        &self,
    ) -> Result<figment::value::Map<figment::Profile, figment::value::Dict>, figment::Error> {
        let dict = figment::value::Value::serialize(&self.0)?
            .into_dict()
            .ok_or_else(|| figment::Error::from("env overlay: expected a dictionary"))?;
        Ok(figment::Profile::Default.collect(dict))
    }
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
        std::env::set_var("SENTRY_METRICS__PORT", "9999");
        // Explicit (absent) path skips the cwd//etc search — defaults only.
        let cfg = load(Some(Path::new("/nonexistent/sentry.toml"))).unwrap();
        std::env::remove_var("SENTRY_METRICS__PORT");
        assert_eq!(cfg.metrics.port, 9999);
        // Sibling keys of [metrics] survive the override.
        assert!(cfg.metrics.enabled);
    }

    #[test]
    fn env_override_keeps_file_auth_section() {
        let path = std::env::temp_dir().join("sentry_cfg_env_test.toml");
        std::fs::write(
            &path,
            "[server]\n\
             host = \"127.0.0.1\"\n\
             port = 8080\n\
             \n\
             [server.auth]\n\
             mode = \"password\"\n\
             \n\
             [[server.auth.users]]\n\
             username = \"admin\"\n\
             password_hash = \"argon2-here\"\n\
             role = \"admin\"\n",
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

    fn write_config(dir: &Path, main: &str, auto: Option<&str>) -> PathBuf {
        let main_path = dir.join("sentry.toml");
        std::fs::write(&main_path, main).unwrap();
        if let Some(auto) = auto {
            std::fs::write(dir.join(AUTO_FILE), auto).unwrap();
        }
        main_path
    }

    #[test]
    fn auto_config_appends_routes_and_packs() {
        let dir = std::env::temp_dir().join(format!("sentry_cfg_auto_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = write_config(
            &dir,
            "[[routes.known]]\npath = \"/mine\"\nmethods = [\"GET\"]\n",
            Some(
                "[[routes.known]]\npath = \"/api/*\"\n\n\
                 [[rules.pack]]\nname = \"rate_scan\"\nmode = \"enforce\"\n\n\
                 [[rules.custom]]\nname = \"auto_rule\"\npriority = 40\nmatch = 'path == \"/x\"'\naction = \"block\"\n",
            ),
        );
        let cfg = load(Some(&main_path)).unwrap();
        let paths: Vec<&str> = cfg.routes.known.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["/mine", "/api/*"],
            "main route kept, auto appended"
        );
        assert_eq!(cfg.rules.packs[0].name, "rate_scan");
        assert_eq!(cfg.rules.custom[0].name, "auto_rule");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn auto_config_dedupes_by_path_and_name() {
        let dir =
            std::env::temp_dir().join(format!("sentry_cfg_auto_dedupe_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = write_config(
            &dir,
            "[[routes.known]]\npath = \"/Mine\"\nmethods = [\"GET\"]\n\n\
             [[rules.pack]]\nname = \"tor\"\nmode = \"shadow\"\n",
            Some(
                "[[routes.known]]\npath = \"/mine\"\nmethods = [\"POST\"]\n\n\
                 [[rules.pack]]\nname = \"TOR\"\nmode = \"enforce\"\n",
            ),
        );
        let cfg = load(Some(&main_path)).unwrap();
        assert_eq!(cfg.routes.known.len(), 1, "existing path wins over auto");
        assert_eq!(cfg.routes.known[0].methods, vec!["GET"]);
        assert_eq!(cfg.rules.packs.len(), 1);
        assert_eq!(cfg.rules.packs[0].mode, "shadow");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn auto_config_ignores_unknown_sections() {
        let dir =
            std::env::temp_dir().join(format!("sentry_cfg_auto_unknown_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = write_config(
            &dir,
            "",
            Some("[[routes.known]]\npath = \"/a\"\n\n[server]\nhost = \"9.9.9.9\"\n"),
        );
        let cfg = load(Some(&main_path)).unwrap();
        assert_eq!(cfg.routes.known.len(), 1);
        assert_eq!(
            cfg.server.host, "127.0.0.1",
            "auto file cannot touch server"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merge_auto_arrays_appends_and_dedupes() {
        let mut base =
            serde_json::json!({"routes": {"known": [{"path": "/a", "methods": ["GET"]}]}});
        merge_auto_arrays(
            &mut base,
            "routes",
            "known",
            &["path"],
            &serde_json::json!({
                "known": [
                    {"path": "/A", "methods": ["POST"]},
                    {"path": "/b"},
                ]
            }),
        );
        let known = base["routes"]["known"].as_array().unwrap();
        assert_eq!(known.len(), 2);
        assert_eq!(known[0]["methods"][0], "GET", "existing entry untouched");
        assert_eq!(known[1]["path"], "/b");
    }
}
