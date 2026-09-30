//! Sentry — access monitor with AI-powered threat detection.
//!
//! Multi-platform CLI. Reads `sentry.toml` (or env overrides), wires up
//! sources, the pipeline, rules engine and actions, then streams events.

#![forbid(unsafe_code)]

pub mod auth;
pub mod cli;
pub mod cmd;
pub mod config;
mod daemon;
pub mod logging;
pub mod metrics;
#[cfg(feature = "rate-redis")]
pub mod rate_redis;
pub mod routes_import;
pub mod server;
pub mod service;
pub mod siem;
mod tui;

pub use cli::Cli;
