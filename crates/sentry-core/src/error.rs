//! Error types shared across the Sentry core.

use thiserror::Error;

/// Top-level error returned by core operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A plugin (source/action) failed during streaming or execution.
    #[error("plugin `{plugin}` failed: {message}")]
    Plugin {
        /// Name of the offending plugin.
        plugin: &'static str,
        /// Human-readable message.
        message: String,
    },

    /// A rule expression could not be parsed.
    #[error("invalid rule match expression: {0}")]
    InvalidRuleExpr(String),

    /// Configuration value is missing or invalid.
    #[error("config error: {0}")]
    Config(String),

    /// Storage layer error, wrapped lossy.
    #[error("storage error: {0}")]
    Storage(String),

    /// Catch-all for errors that don't fit a more specific variant.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Convenience `Result` alias used throughout the core.
pub type Result<T> = std::result::Result<T, CoreError>;
