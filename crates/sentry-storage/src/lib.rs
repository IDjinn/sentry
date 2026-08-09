//! Postgres persistence for Sentry.
//!
//! Owns the connection pool and the migrations. Exposes typed repositories
//! (events, incidents, rules, ip_state, routes) that the daemon and CLI use.

#![forbid(unsafe_code)]

pub mod error;
pub mod migrations;
pub mod pool;
pub mod repo;

pub use error::{Result, StorageError};
pub use pool::PgPool;
pub use repo::{
    EventRepo, EventRow, IncidentRepo, IncidentRow, IpStateRepo, IpStateRow, Repo, RouteRepo,
    RouteRow, RuleRepo, RuleRow,
};
