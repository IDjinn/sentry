//! Built-in framework detectors.
//!
//! Each profile anchors on manifest/config files and extracts the routes
//! the framework declares. Parsers are tolerant: a malformed file is
//! skipped, never a hard error — `sentry auto` is best-effort by design.

pub mod express;
pub mod laravel;
pub mod nextjs;
pub mod nginx;
pub mod openapi;
pub mod react;
pub mod web;
pub mod wordpress;
