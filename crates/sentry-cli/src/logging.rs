//! Tracing/logging initialization.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialize `tracing` with the requested verbosity.
pub fn init(verbose: u8) {
    let filter = match verbose {
        0 => "warn,sentry=info",
        1 => "info,sentry=debug",
        2 => "debug,sentry=trace",
        _ => "trace",
    };
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));
    fmt().with_env_filter(env).with_target(false).init();
}
