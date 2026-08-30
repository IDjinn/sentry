//! Syslog receiver source: listens on UDP or TCP and turns each message into
//! a [`RawEvent`](sentry_core::event::RawEvent) with a
//! `ProtocolData::Syslog` payload.
//!
//! Parses RFC 5424 (with an RFC 3164 legacy fallback); the peer address
//! becomes the client IP. TCP connections support both newline framing and
//! RFC 6587 octet-counting. Typical use: network equipment, firewalls and
//! services that ship access/security logs via syslog.

#![forbid(unsafe_code)]

mod parser;
mod source;

pub use parser::{parse_syslog, SyslogParseError};
pub use source::{SyslogSource, SyslogSourceConfig, SyslogTransport, DEFAULT_BIND};
