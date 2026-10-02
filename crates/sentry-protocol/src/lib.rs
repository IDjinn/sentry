//! Protocol schema DSL for Sentry (F9).
//!
//! Compiles YAML wire-protocol descriptions into instruction-table
//! validators. A schema describes a binary or text protocol (framing,
//! message dispatch by header, per-field read macros and constraints,
//! keepalive semantics) and is compiled once into a [`Compiled`] program
//! executed by a small register VM — no regex on the default path.
//!
//! The crate is intentionally pure: no I/O, no async, no dependency on
//! other Sentry crates. The host (daemon/edge) owns file loading,
//! hot-reload watchers and converts [`Violation`]s into pipeline signals.
//!
//! Macros are customized per protocol: the crate ships only universal
//! atoms (fixed/prefixed/terminated reads, infix bit arithmetic, bounded
//! `while` loops, `if` blocks); protocol formats like variable-length
//! integers are defined in the schema itself and inlined at compile time.
//!
//! # Example
//!
//! ```yaml
//! transport: {protocol: tcp, ports: [14901]}
//! on_message:
//!   run: check_len! | parse_header!
//! types:
//!   LPStr: {prefix: u16, decode: utf8}
//!   VLInt:
//!     body:
//!       - b0: "read u8"
//!       - n: "(b0 and 0x38) >> 3"
//!       - acc: "b0 and 0x03"
//!       - while min!(n, 4):
//!           - bi: "read u8"
//!           - check_mask!(bi, 0xC0, 0x40)
//!           - acc: "(acc << 6) or (bi and 0x3F)"
//!       - if (b0 and 0x04):
//!           - acc: "-acc"
//!       - return acc
//! policies:
//!   default: {weight: 20}
//! messages:
//!   sso_ticket_event:
//!     when: {header: 400}
//!     validate:
//!       - sso_ticket: LPStr >16 <56 regex 'GAME-[a-zA-Z0-9]+-3324'
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod compile;
pub mod engine;
pub mod error;
pub mod expr;
pub mod instr;
pub mod macros;
pub mod ops;
pub mod schema;
pub mod steps;

pub use compile::{Compiled, CompiledProtocol};
pub use engine::{feed_on, ConnectionState, FrameInfo, ProtocolEngine};
pub use error::{ProtocolError, Result};
pub use instr::{Instr, Value};
pub use schema::{ProtocolSchema, Transport};

use std::sync::Arc;

/// A single protocol-validation failure, ready for the host to map into a
/// pipeline signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Schema (`id`) that produced the violation.
    pub schema: Arc<str>,
    /// Policy name cited by the violated rule (severity comes from here).
    pub policy: Arc<str>,
    /// Message label when known (empty for framing/unknown-header hits).
    pub message: Arc<str>,
    /// Human-readable reason (stable enough for logs/metrics labels).
    pub reason: String,
    /// Set when the policy's `on_repeat` escalation window was reached.
    pub escalated: bool,
}

/// Max nesting depth when expanding custom types into other custom types.
pub(crate) const MAX_TYPE_DEPTH: usize = 8;

/// Cap on instructions per compiled message (compiler DoS guard).
pub(crate) const MAX_INSTRS_PER_MESSAGE: usize = 512;
