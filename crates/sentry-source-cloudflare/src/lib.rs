//! Cloudflare logs pull source (F3.3).
//!
//! Polls the zone [Logs API](https://developers.cloudflare.com/logs/logpull/)
//! (`GET /zones/{zone_id}/logs/received`, NDJSON) and feeds the same pipeline
//! as the nginx tail. Requires an Enterprise plan entitlement for
//! `logs/received`; the parser is fixture-tested so CI never calls the API.

#![forbid(unsafe_code)]

mod parser;
mod source;

pub use parser::{parse_line, CfLogLine};
pub use source::{CloudflareSource, CloudflareSourceConfig};
