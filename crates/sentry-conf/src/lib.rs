//! `sentry-conf` — the nginx-like configuration language used by
//! `sentry.conf`.
//!
//! - [`parser`]: lexer + parser into a positioned syntax tree ([`ast`]);
//! - [`load`]: multi-file loading (`include:` globs, directories);
//! - [`de`]: serde `Deserializer` over the tree, with errors that point at
//!   `file:line:col` and the block path;
//! - [`ser`]: emitter from any `Serialize` value back to text;
//! - [`values`]: durations, sizes, one-or-many lists, untyped values.
//!
//! The crate knows nothing about Sentry's schema: `sentry-core` maps the
//! tree onto its runtime config.

#![forbid(unsafe_code)]

pub mod ast;
pub mod de;
pub mod edit;
pub mod error;
pub mod load;
pub mod parser;
pub mod ser;
pub mod values;

pub use ast::{Block, Body, Directive, Node, Span, Stmt, Value};
pub use de::{from_body, from_node, LABELS_KEY};
pub use error::{Error, Result};
pub use load::{conf_files_in, Loader};
pub use parser::{parse, parse_str};
pub use values::{Bytes, ConfValue, Millis, OneOrMany, OrderedMap, RawBlock, Secs};
