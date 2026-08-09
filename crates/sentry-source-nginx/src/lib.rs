//! Nginx access log source plugin.
//!
//! Tails an nginx `access.log` file, parses each line according to a
//! configurable `$var` format string, and emits [`RawEvent`]s into a tokio
//! channel. Parsing is best-effort: malformed lines are logged and skipped
//! rather than killing the stream.

#![forbid(unsafe_code)]

mod parser;
mod source;

pub use parser::LogFormat;
pub use source::{NginxSource, NginxSourceConfig};
