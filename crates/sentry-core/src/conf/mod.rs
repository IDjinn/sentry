//! `sentry.conf` support: the nginx-like file format (parsed by
//! `sentry-conf`) mapped onto the runtime [`SentryConfig`].
//!
//! - [`from_body`]: parsed (and include-expanded) statements → config;
//! - [`to_text`]: config → `.conf` text with only non-default values
//!   (`sentry config show`, `sentry config migrate`, `sentry auto`).
//!
//! The same top-level block may appear in several files (`detect {}` in
//! `detect.conf`, `http {}` split into `sites/*.conf`): unlabeled blocks
//! are merged, labeled ones accumulate.

pub mod lower;
pub mod schema;

use crate::config::SentryConfig;
use crate::error::{CoreError, Result};

pub use lower::split_listen;

/// Lower parsed statements onto a [`SentryConfig`].
pub fn from_body(body: &sentry_conf::Body) -> Result<SentryConfig> {
    let file: schema::ConfFile =
        sentry_conf::from_body(body).map_err(|e| CoreError::Config(e.to_string()))?;
    lower::lower(file).map_err(|errors| CoreError::Config(errors.join("\n")))
}

/// Parse and lower an in-memory source (no includes).
pub fn from_str(src: &str, name: &str) -> Result<SentryConfig> {
    let body = sentry_conf::parse_str(src, name).map_err(|e| CoreError::Config(e.to_string()))?;
    from_body(&body)
}

/// Render the non-default part of a config as `.conf` text.
pub fn to_text(cfg: &SentryConfig) -> String {
    let base = lower::raise(&SentryConfig::default());
    sentry_conf::ser::to_string_diff(&lower::raise(cfg), &base).unwrap_or_default()
}

/// Render every value (defaults included).
pub fn to_text_full(cfg: &SentryConfig) -> String {
    sentry_conf::ser::to_string(&lower::raise(cfg)).unwrap_or_default()
}

#[cfg(test)]
mod tests;
