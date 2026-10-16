//! Sentry — access monitor with AI-powered threat detection.
//!
//! Multi-platform CLI. Reads `sentry.conf` (nginx-like, split files allowed; env overrides on top), wires up
//! sources, the pipeline, rules engine and actions, then streams events.

#![forbid(unsafe_code)]

pub mod auth;
pub mod auto;
pub mod bench_llm;
pub mod botdns;
pub mod cli;
pub mod cmd;
pub mod config;
mod daemon;
pub mod datasets;
pub mod eventlog;
pub mod logging;
pub mod metrics;
pub mod protocol_cmd;
#[cfg(feature = "rate-redis")]
pub mod rate_redis;
pub mod routes_import;
pub mod runtime;
pub mod server;
pub mod service;
pub mod siem;
mod tui;
pub mod update;

pub use cli::Cli;
