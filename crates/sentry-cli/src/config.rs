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

/// Load config from the default search path, merging TOML + env.
pub fn load(path: Option<&Path>) -> color_eyre::Result<SentryConfig> {
    let figment = Figment::from(Serialized::defaults(SentryConfig::default()));

    // Try explicit path, then cwd, then /etc/sentry/sentry.toml.
    let figment = if let Some(p) = path {
        figment.merge(Toml::file(p))
    } else {
        let cwd = PathBuf::from("sentry.toml");
        let etc = PathBuf::from("/etc/sentry/sentry.toml");
        let figment = if cwd.exists() {
            figment.merge(Toml::file(&cwd))
        } else {
            figment
        };
        if etc.exists() {
            figment.merge(Toml::file(&etc))
        } else {
            figment
        }
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

    Ok(Figment::from(EnvOverlay(merged)))
}

/// Provider serving a whole resolved config under the default profile.
struct EnvOverlay(serde_json::Value);

impl figment::Provider for EnvOverlay {
    fn metadata(&self) -> figment::Metadata {
        figment::Metadata::named("env overlay (deep)")
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
}
