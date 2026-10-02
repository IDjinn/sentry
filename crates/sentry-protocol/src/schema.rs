//! Typed model of the protocol-schema DSL (v3).
//!
//! One YAML file describes one protocol. Macros are customized per
//! protocol in the `types:` block — either as one-line sugar (the loader
//! desugars it to steps) or as an explicit register-machine body for
//! exotic encodings (variable-length integers, for example). The crate
//! ships only universal atoms; protocol formats live in the schema file.
//!
//! ```yaml
//! id: game-relay
//! transport: {protocol: tcp, ports: [14901]}
//! on_message:
//!   run: check_len! | parse_header!
//! types:
//!   LPStr: {prefix: u16, decode: utf8, max_len: 4096}
//!   VLInt:
//!     body:
//!       - b0: "read u8"
//!       - acc: "b0 and 0x03"
//!       - while min!(n, 4):
//!           - bi: "read u8"
//!           - check_mask!(bi, 0xC0, 0x40)
//!       - return acc
//! policies:
//!   default: {weight: 20}
//! messages:
//!   sso_ticket_event:
//!     when: {header: 400}
//!     validate:
//!       - sso_ticket: LPStr >16 <56 regex 'GAME-[a-zA-Z0-9]+-3324'
//! ```

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::ProtocolError;
use crate::ops::{self, FieldLine};

/// Root of a parsed protocol schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSchema {
    /// Optional `$schema` URL (accepted for editor tooling, ignored).
    #[serde(rename = "$schema", default)]
    pub schema_url: Option<String>,
    /// Optional `$id` URL (accepted for editor tooling, ignored).
    #[serde(rename = "$id", default)]
    pub id_url: Option<String>,
    /// Unique schema identifier; becomes the label on metrics/signals.
    pub id: String,
    /// Free-form version string, informational.
    #[serde(default)]
    pub version: Option<String>,
    /// Free-form description, informational.
    #[serde(default)]
    pub description: Option<String>,
    /// Enforcement posture: `shadow` (default) only signals, `enforce`
    /// lets the host close the connection on violations.
    #[serde(default)]
    pub mode: Mode,
    /// Listener binding: protocol kind, ports, socket flags.
    pub transport: Transport,
    /// Pipeline of pipeline-atoms run on every message before dispatch.
    #[serde(default)]
    pub on_message: Option<OnMessage>,
    /// Custom read macros, by name. Primitives (`i16`, `u32`, …) are
    /// built in; everything here is protocol-specific and defined here.
    #[serde(default)]
    pub types: BTreeMap<String, TypeDef>,
    /// Named severity policies; `default` is mandatory.
    #[serde(default)]
    pub policies: BTreeMap<String, Policy>,
    /// Message table: `when` dispatches, `validate` reads and constrains.
    #[serde(default)]
    pub messages: BTreeMap<String, MessageDef>,
}

/// Enforcement posture of a schema.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Signal and log violations, never disconnect (default).
    #[default]
    Shadow,
    /// Let the host drop the connection on the first violation.
    Enforce,
}

/// Transport binding of the protocol.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    /// Wire protocol family.
    pub protocol: TransportKind,
    /// Ports this schema guards (host wiring matches by port).
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Free-form socket flags (`nodelay: "true"`, …) consumed by the host.
    #[serde(default)]
    pub flags: BTreeMap<String, String>,
}

/// Wire protocol family.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// Raw TCP stream (binary or text framing).
    Tcp,
    /// UDP datagrams.
    Udp,
    /// WebSocket frames (JSON or binary payloads).
    Ws,
}

/// The per-message pipeline: pipe sugar (`a! | b! {as: x}`) parsed later.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnMessage {
    /// Raw `run:` string; parsed into steps by [`crate::steps::parse_run`].
    pub run: String,
}

/// Definition of a custom read macro (protocol-specific by design).
#[derive(Debug, Clone, PartialEq)]
pub enum TypeDef {
    /// One-line sugar, desugared to steps at load time.
    Sugar(SugarRead),
    /// Explicit register-machine body for exotic encodings.
    Body {
        /// Ordered steps; the last `return` yields the value.
        body: Vec<Step>,
    },
    /// Named composite: sequential reads of named sub-fields.
    Composite(Vec<CompositeField>),
}

impl<'de> Deserialize<'de> for TypeDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let v = serde_yaml::Value::deserialize(deserializer)?;
        match v {
            serde_yaml::Value::Sequence(_) => {
                Ok(Self::Composite(serde_yaml::from_value(v).map_err(|e| {
                    D::Error::custom(format!("composite type: {e}"))
                })?))
            }
            serde_yaml::Value::Mapping(ref m)
                if m.len() == 1 && m.contains_key(serde_yaml::Value::from("body")) =>
            {
                let body = m
                    .get(serde_yaml::Value::from("body"))
                    .cloned()
                    .unwrap_or(serde_yaml::Value::Null);
                Ok(Self::Body {
                    body: serde_yaml::from_value(body)
                        .map_err(|e| D::Error::custom(format!("macro body: {e}")))?,
                })
            }
            serde_yaml::Value::Mapping(_) => {
                Ok(Self::Sugar(serde_yaml::from_value(v).map_err(|e| {
                    D::Error::custom(format!("sugar type: {e}"))
                })?))
            }
            other => Err(D::Error::custom(format!(
                "type definition must be a map or a composite list, got {other:?}"
            ))),
        }
    }
}

/// Sugar form of a read macro.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]

pub struct SugarRead {
    /// Fixed byte count to read.
    #[serde(default)]
    pub fixed: Option<u64>,
    /// Length-prefixed read; the value names the prefix type (`u16`…).
    #[serde(default)]
    pub prefix: Option<String>,
    /// Terminator byte (hex, e.g. `0x02`) to read until.
    #[serde(default)]
    pub terminator: Option<u8>,
    /// Byte order for fixed numeric reads (default big).
    #[serde(default)]
    pub endian: Option<Endian>,
    /// Byte transform applied to the raw bytes (default none).
    #[serde(default)]
    pub decode: Option<Decode>,
    /// Max accepted byte length for prefix/terminator reads.
    #[serde(default)]
    pub max_len: Option<u64>,
    /// Mask check on each read byte: `(byte & bits) == value`.
    #[serde(default)]
    pub mask_ok: Option<MaskOk>,
}

/// Byte order for numeric reads.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    /// Most significant byte first (default).
    Big,
    /// Least significant byte first.
    Little,
}

/// Byte transform applied after a raw read.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decode {
    /// Keep raw bytes.
    None,
    /// UTF-8 string.
    Utf8,
    /// ISO-8859-1 string (legacy game logs render this way).
    Latin1,
    /// Standard base64 decode.
    B64,
    /// URL-safe base64 decode.
    B64Url,
    /// Hex decode.
    Hex,
}

/// `(byte & bits) == value` invariant enforced on every read byte.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MaskOk {
    /// AND mask.
    pub bits: u8,
    /// Required masked value.
    pub value: u8,
}

/// One field of a composite type: `[{id: VLInt}, {room: VLInt}]`.
#[derive(Debug, Clone, Deserialize, PartialEq)]

pub struct CompositeField {
    /// Sub-field name (register/label inside the composite).
    pub name: String,
    /// Wire type of the sub-field.
    #[serde(rename = "type")]
    pub type_name: String,
}

/// A register-machine step inside a macro body.
///
/// Surface forms:
///
/// ```yaml
/// - acc: "(b0 and 0x38) >> 3"     # assignment: infix expression
/// - bi: "read u8"                 # assignment: I/O atom call
/// - while min!(n, 4):             # bounded loop (compile-time cap)
///     - bi: "read u8"
/// - if sign:                      # conditional block (non-zero runs it)
///     - acc: "-acc"
/// - check_mask!(bi, 0xC0, 0x40)   # check statement
/// - return acc                    # yield the macro value
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// `NAME: "…"` — assignment: infix expression ([`crate::expr`]) or an
    /// I/O atom call (`read`, `decode`, `peek`).
    Assign {
        /// Destination register.
        name: String,
        /// Expression / atom call text.
        expr: String,
    },
    /// `while <bound>:` — bounded loop. The bound must be a constant or
    /// `min!(expr, const)`; iterations clamp to the cap.
    While {
        /// Bound expression text.
        bound: String,
        /// Steps executed per iteration.
        body: Vec<Step>,
    },
    /// `if <cond>:` — conditional block, run when the condition is
    /// non-zero. `return` inside an `if` (not under a `while`) is allowed.
    If {
        /// Condition expression text (non-zero = true).
        cond: String,
        /// Steps executed when the condition holds.
        body: Vec<Step>,
    },
    /// Statement text: `check_mask!(reg, bits, value)`,
    /// `check_range!(reg, min, max)`, `check_len!(reg, min, max)` or
    /// `return <reg>`.
    Statement(String),
}

impl<'de> Deserialize<'de> for Step {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let v = serde_yaml::Value::deserialize(deserializer)?;
        match v {
            serde_yaml::Value::String(s) => {
                let s = s.trim().to_string();
                if s.is_empty() {
                    return Err(D::Error::custom("empty statement"));
                }
                Ok(Self::Statement(s))
            }
            serde_yaml::Value::Mapping(ref m) if m.len() == 1 => {
                let (key, val) = m
                    .into_iter()
                    .next()
                    .ok_or_else(|| D::Error::custom("empty step"))?;
                let key = key
                    .as_str()
                    .ok_or_else(|| D::Error::custom("step key must be a string"))?;
                if let Some(cond) = key.strip_prefix("if ") {
                    let cond = cond.trim().to_string();
                    if cond.is_empty() {
                        return Err(D::Error::custom("if requires a condition expression"));
                    }
                    return Ok(Self::If {
                        cond,
                        body: serde_yaml::from_value(val.clone())
                            .map_err(|e| D::Error::custom(format!("if body: {e}")))?,
                    });
                }
                if let Some(bound) = key.strip_prefix("while ") {
                    let bound = bound.trim().to_string();
                    if bound.is_empty() {
                        return Err(D::Error::custom(
                            "while requires a bound: constant or min!(expr, cap)",
                        ));
                    }
                    return Ok(Self::While {
                        bound,
                        body: serde_yaml::from_value(val.clone())
                            .map_err(|e| D::Error::custom(format!("while body: {e}")))?,
                    });
                }
                if key == "return" {
                    let reg = val.as_str().map(str::trim).filter(|s| !s.is_empty());
                    return match reg {
                        Some(reg) => Ok(Self::Statement(format!("return {reg}"))),
                        None => Err(D::Error::custom("return requires a register name")),
                    };
                }
                Ok(Self::Assign {
                    name: key.to_string(),
                    expr: serde_yaml::from_value(val.clone())
                        .map_err(|e| D::Error::custom(format!("step {key:?}: {e}")))?,
                })
            }
            _ => Err(D::Error::custom(
                "step must be a string statement or a single-key map ({reg: \"expr\"} / if / while)",
            )),
        }
    }
}

/// Named severity policy.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Signal weight when this policy is violated (0-100).
    #[serde(default = "default_weight")]
    pub weight: u8,
    /// Escalation window for repeated violations of this policy.
    #[serde(default)]
    pub on_repeat: Option<OnRepeat>,
}

fn default_weight() -> u8 {
    20
}

/// Repeat-escalation spec: N violations of the policy inside the window.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OnRepeat {
    /// Violation count that triggers escalation.
    pub count: u32,
    /// Sliding window (e.g. `60s`).
    #[serde(deserialize_with = "de_duration")]
    pub window: std::time::Duration,
    /// Whether repeats raise the severity.
    #[serde(default)]
    pub escalate: bool,
}

/// Keepalive semantics for a message (ping/pong liveness).
#[derive(Debug, Clone, PartialEq)]
pub enum Keepalive {
    /// Marks the message as liveness traffic (no cadence or rate limit).
    Flag,
    /// Full spec: expected cadence (health/TTL only) and flood ceiling.
    Spec {
        /// Expected interval between keepalives.
        cadence: Option<std::time::Duration>,
        /// Max keepalives per window; exceeding it is a violation.
        rate_limit: Option<RateLimit>,
    },
}

impl<'de> Deserialize<'de> for Keepalive {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Spec {
            #[serde(default, deserialize_with = "de_duration_opt")]
            cadence: Option<std::time::Duration>,
            #[serde(default, deserialize_with = "de_rate_limit_opt")]
            rate_limit: Option<RateLimit>,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Map(Spec),
        }
        Ok(match Raw::deserialize(deserializer)? {
            Raw::Bool(true) => Keepalive::Flag,
            Raw::Bool(false) => {
                return Err(serde::de::Error::custom(
                    "keepalive: false is redundant; omit the key",
                ))
            }
            Raw::Map(s) => Keepalive::Spec {
                cadence: s.cadence,
                rate_limit: s.rate_limit,
            },
        })
    }
}

/// Flood ceiling: `2/60s` = at most 2 occurrences per 60-second window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Allowed occurrences per window.
    pub count: u32,
    /// Window length.
    pub window: std::time::Duration,
}

/// A message: dispatch condition plus optional validation body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageDef {
    /// Dispatch map: variable name → scalar or list-of-scalars (OR);
    /// multiple keys are ANDed. Required; the union of all `when` maps is
    /// the protocol's implicit allowlist.
    pub when: BTreeMap<String, WhenValue>,
    /// Severity policy name (defaults to `default`).
    #[serde(default)]
    pub policy: Option<String>,
    /// Messages that must have been seen earlier on the connection.
    #[serde(default)]
    pub after: Vec<String>,
    /// Liveness semantics (ping/pong).
    #[serde(default)]
    pub keepalive: Option<Keepalive>,
    /// Ordered read+constraint lines (binary: positional order matters).
    #[serde(default)]
    pub validate: Vec<ValidateLine>,
}

/// Dispatch value: scalar or OR-list.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum WhenValue {
    /// Single scalar.
    One(serde_yaml::Value),
    /// Any of the scalars.
    Many(Vec<serde_yaml::Value>),
}

/// One parsed `validate:` line.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidateLine {
    /// Field name (register/label for metrics and rules DSL).
    pub field: String,
    /// Parsed type + ops.
    pub line: FieldLine,
}

impl<'de> Deserialize<'de> for ValidateLine {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let raw: BTreeMap<String, String> = BTreeMap::deserialize(deserializer)?;
        let mut iter = raw.into_iter();
        let (field, text) = iter
            .next()
            .ok_or_else(|| D::Error::custom("validate line is empty"))?;
        if iter.next().is_some() {
            return Err(D::Error::custom(
                "validate line must have exactly one field",
            ));
        }
        let context = format!("field {field:?}");
        let line =
            ops::parse_field_line(&context, &text).map_err(|e| D::Error::custom(e.to_string()))?;
        Ok(Self { field, line })
    }
}

/// Parses a duration (`30s`, `500ms`, `5m`).
pub fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = num.parse().ok()?;
    let millis = match unit {
        "ms" => n,
        "s" => n.saturating_mul(1000),
        "m" => n.saturating_mul(60_000),
        "h" => n.saturating_mul(3_600_000),
        _ => return None,
    };
    Some(std::time::Duration::from_millis(millis))
}

fn de_duration<'de, D>(d: D) -> Result<std::time::Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    parse_duration(&s).ok_or_else(|| {
        serde::de::Error::custom(format!("invalid duration {s:?} (use 30s/500ms/5m)"))
    })
}

fn de_duration_opt<'de, D>(d: D) -> Result<Option<std::time::Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    parse_duration(&s).map(Some).ok_or_else(|| {
        serde::de::Error::custom(format!("invalid duration {s:?} (use 30s/500ms/5m)"))
    })
}

fn de_rate_limit_opt<'de, D>(d: D) -> Result<Option<RateLimit>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(d)?;
    let (count, window) = s
        .split_once('/')
        .ok_or_else(|| serde::de::Error::custom(format!("invalid rate limit {s:?} (use 2/60s)")))?;
    let count: u32 = count
        .parse()
        .map_err(|_| serde::de::Error::custom(format!("invalid rate count {count:?}")))?;
    let window = parse_duration(window)
        .ok_or_else(|| serde::de::Error::custom(format!("invalid rate window {window:?}")))?;
    Ok(Some(RateLimit { count, window }))
}

impl ProtocolSchema {
    /// Parses and validates a schema from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, ProtocolError> {
        let schema: Self = serde_yaml::from_str(text)?;
        schema.validate()?;
        Ok(schema)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        let id = &self.id;
        if id.trim().is_empty() {
            return Err(ProtocolError::schema(id, "id must not be empty"));
        }
        if !self.policies.contains_key("default") {
            return Err(ProtocolError::schema(id, "policies must define `default`"));
        }
        for (name, msg) in &self.messages {
            if let Some(policy) = &msg.policy {
                if !self.policies.contains_key(policy) {
                    return Err(ProtocolError::schema(
                        id,
                        format!("message {name:?} cites unknown policy {policy:?}"),
                    ));
                }
            }
            for after in &msg.after {
                if !self.messages.contains_key(after) {
                    return Err(ProtocolError::schema(
                        id,
                        format!("message {name:?} requires unknown message {after:?} in after"),
                    ));
                }
            }
            if msg.when.is_empty() {
                return Err(ProtocolError::schema(
                    id,
                    format!("message {name:?} must declare a non-empty when"),
                ));
            }
        }
        for (name, def) in &self.types {
            if let TypeDef::Sugar(sugar) = def {
                let sources = [
                    sugar.fixed.is_some(),
                    sugar.prefix.is_some(),
                    sugar.terminator.is_some(),
                ]
                .iter()
                .filter(|b| **b)
                .count();
                if sources != 1 {
                    return Err(ProtocolError::schema(
                        id,
                        format!(
                            "type {name:?}: exactly one of fixed/prefix/terminator is required"
                        ),
                    ));
                }
                if sugar.prefix.is_some() && sugar.mask_ok.is_some() {
                    return Err(ProtocolError::schema(
                        id,
                        format!("type {name:?}: mask_ok applies to fixed reads only"),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAME_SCHEMA: &str = r#"
id: game-relay
version: "1.0.0"
transport:
  protocol: tcp
  ports: [14901]
on_message:
  run: check_len! | parse_header!
types:
  LPStr: {prefix: u16, decode: utf8, max_len: 4096}
  VLInt:
    body:
      - b0: "read u8"
      - n: "(b0 and 0x38) >> 3"
      - acc: "b0 and 0x03"
      - while min!(n, 4):
          - bi: "read u8"
          - check_mask!(bi, 0xC0, 0x40)
          - acc: "(acc << 6) or (bi and 0x3F)"
      - sign: "b0 and 0x04"
      - if sign:
          - acc: "-acc"
      - return acc
policies:
  default: {weight: 20}
  unknown_header:
    weight: 35
    on_repeat: {count: 3, window: 60s, escalate: true}
messages:
  sso_ticket_event:
    when: {header: 400}
    validate:
      - sso_ticket: LPStr >16 <56 regex 'GAME-[a-zA-Z0-9]+-3324'
  ping_event:
    when: {header: 4096}
    keepalive: {cadence: 30s, rate_limit: 2/60s}
    validate:
      - payload: LPStr len<8
"#;

    #[test]
    fn parses_full_game_schema() {
        let s = ProtocolSchema::from_yaml(GAME_SCHEMA).unwrap();
        assert_eq!(s.id, "game-relay");
        assert_eq!(s.transport.ports, vec![14901]);
        assert!(matches!(s.types["LPStr"], TypeDef::Sugar(_)));
        assert_eq!(s.messages.len(), 2);
        let sso = &s.messages["sso_ticket_event"];
        assert_eq!(sso.when["header"], WhenValue::One(400.into()));
        assert_eq!(sso.validate[0].line.type_name, "LPStr");
        assert_eq!(
            s.policies["unknown_header"]
                .on_repeat
                .as_ref()
                .unwrap()
                .window,
            std::time::Duration::from_secs(60)
        );
        let ping = &s.messages["ping_event"];
        assert!(matches!(ping.keepalive, Some(Keepalive::Spec { .. })));
    }

    #[test]
    fn parses_composite_type() {
        let s = ProtocolSchema::from_yaml(
            r#"
id: t
transport: {protocol: tcp}
policies: {default: {weight: 1}}
types:
  Context: [{name: id, type: u16}, {name: room, type: u16}]
messages:
  m:
    when: {header: 1}
"#,
        )
        .unwrap();
        match &s.types["Context"] {
            TypeDef::Composite(fields) => {
                assert_eq!(fields[0].name, "id");
                assert_eq!(fields[1].type_name, "u16");
            }
            other => panic!("expected composite, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_default_policy() {
        let err = ProtocolSchema::from_yaml(
            "id: t\ntransport: {protocol: tcp}\npolicies: {strict: {weight: 9}}\nmessages: {m: {when: {header: 1}}}",
        )
        .unwrap_err();
        assert!(err.to_string().contains("default"));
    }

    #[test]
    fn rejects_unknown_policy_and_after() {
        assert!(ProtocolSchema::from_yaml(
            "id: t\ntransport: {protocol: tcp}\npolicies: {default: {weight: 1}}\nmessages: {m: {when: {header: 1}, policy: nope}}",
        )
        .is_err());
        assert!(ProtocolSchema::from_yaml(
            "id: t\ntransport: {protocol: tcp}\npolicies: {default: {weight: 1}}\nmessages: {m: {when: {header: 1}, after: [ghost]}}",
        )
        .is_err());
    }

    #[test]
    fn rejects_empty_when() {
        assert!(ProtocolSchema::from_yaml(
            "id: t\ntransport: {protocol: tcp}\npolicies: {default: {weight: 1}}\nmessages: {m: {when: {}}}",
        )
        .is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = ProtocolSchema::from_yaml(
            "id: t\ntransport: {protocol: tcp, bogus: 1}\npolicies: {default: {weight: 1}}\nmessages: {m: {when: {header: 1}}}",
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_sugar_without_source() {
        assert!(ProtocolSchema::from_yaml(
            "id: t\ntransport: {protocol: tcp}\npolicies: {default: {weight: 1}}\ntypes: {Bad: {decode: utf8}}\nmessages: {m: {when: {header: 1}}}",
        )
        .is_err());
    }

    #[test]
    fn parses_rate_limit_and_durations() {
        assert_eq!(
            parse_duration("30s"),
            Some(std::time::Duration::from_secs(30))
        );
        assert_eq!(
            parse_duration("500ms"),
            Some(std::time::Duration::from_millis(500))
        );
        assert_eq!(
            parse_duration("2m"),
            Some(std::time::Duration::from_secs(120))
        );
        assert_eq!(parse_duration("5x"), None);
        let s = ProtocolSchema::from_yaml(
            "id: t\ntransport: {protocol: tcp}\npolicies: {default: {weight: 1}}\nmessages:\n  ping:\n    when: {header: 9}\n    keepalive: {rate_limit: 2/60s}\n",
        )
        .unwrap();
        match &s.messages["ping"].keepalive {
            Some(Keepalive::Spec { rate_limit, .. }) => {
                assert_eq!(rate_limit.map(|r| r.count), Some(2));
            }
            other => panic!("expected spec, got {other:?}"),
        }
    }

    #[test]
    fn parses_all_step_forms() {
        let s = ProtocolSchema::from_yaml(
            r#"
id: t
transport: {protocol: tcp}
policies: {default: {weight: 1}}
types:
  T:
    body:
      - b0: "read u8"
      - n: "(b0 and 0x38) >> 3"
      - while min!(n, 4):
          - x: "read u8"
      - if n:
          - n: "-n"
      - check_mask!(b0, 0xC0, 0x40)
      - "check_range!(n, 0, 8)"
      - return n
messages:
  m:
    when: {header: 1}
"#,
        )
        .unwrap();
        let Some(TypeDef::Body { body }) = s.types.get("T") else {
            panic!("expected body type");
        };
        assert_eq!(
            body[0],
            Step::Assign {
                name: "b0".into(),
                expr: "read u8".into()
            }
        );
        assert_eq!(
            body[1],
            Step::Assign {
                name: "n".into(),
                expr: "(b0 and 0x38) >> 3".into()
            }
        );
        match &body[2] {
            Step::While { bound, body } => {
                assert_eq!(bound, "min!(n, 4)");
                assert_eq!(body.len(), 1);
            }
            other => panic!("expected while, got {other:?}"),
        }
        match &body[3] {
            Step::If { cond, body } => {
                assert_eq!(cond, "n");
                assert_eq!(body.len(), 1);
            }
            other => panic!("expected if, got {other:?}"),
        }
        assert_eq!(
            body[4],
            Step::Statement("check_mask!(b0, 0xC0, 0x40)".into())
        );
        assert_eq!(body[5], Step::Statement("check_range!(n, 0, 8)".into()));
        assert_eq!(body[6], Step::Statement("return n".into()));
    }

    #[test]
    fn map_return_form_still_accepted() {
        let s = ProtocolSchema::from_yaml(
            r#"
id: t
transport: {protocol: tcp}
policies: {default: {weight: 1}}
types:
  T:
    body:
      - b: "read u8"
      - return: b
messages:
  m:
    when: {header: 1}
"#,
        )
        .unwrap();
        let Some(TypeDef::Body { body }) = s.types.get("T") else {
            panic!("expected body type");
        };
        assert_eq!(body[1], Step::Statement("return b".into()));
    }

    #[test]
    fn rejects_bad_steps() {
        let preamble = "id: t\ntransport: {protocol: tcp}\npolicies: {default: {weight: 1}}\nmessages: {m: {when: {header: 1}}}\ntypes:\n  T:\n    body:\n";
        assert!(ProtocolSchema::from_yaml(&format!(
            "{preamble}      - while:\n          - x: \"read u8\"\n"
        ))
        .is_err());
        assert!(ProtocolSchema::from_yaml(&format!(
            "{preamble}      - if:\n          - x: \"read u8\"\n"
        ))
        .is_err());
        assert!(
            ProtocolSchema::from_yaml(&format!("{preamble}      - {{a: \"1\", b: \"2\"}}\n"))
                .is_err()
        );
        assert!(ProtocolSchema::from_yaml(&format!("{preamble}      - \"\"\n")).is_err());
        assert!(ProtocolSchema::from_yaml(&format!("{preamble}      - return:\n")).is_err());
    }
}
