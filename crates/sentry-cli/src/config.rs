//! Config loading: figment (TOML + env overlay).
//!
//! Env vars override config values using the `SENTRY_` prefix with nested
//! keys separated by `__` (e.g. `SENTRY_STORAGE__POSTGRES__URL`).

use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
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
    let figment = figment.merge(Env::prefixed("SENTRY_").split("__"));

    let cfg: SentryConfig = figment
        .extract()
        .map_err(|e| color_eyre::eyre::eyre!("config load error: {}", e))?;

    Ok(cfg)
}
