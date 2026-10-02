//! Execution engine: per-connection state and the hot-swappable protocol
//! set.
//!
//! [`ProtocolEngine`] wraps the [`Compiled`] set in an [`ArcSwap`] so a
//! reload is a single pointer swap with zero downtime; in-flight frames
//! finish on the previous program. [`ConnectionState`] is owned by the
//! connection's task (no locks) and tracks the `after` set, keepalive
//! windows and per-policy escalation counters.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use crate::compile::{Compiled, CompiledProtocol};
use crate::instr::Value;
use crate::schema::Keepalive;
use crate::Violation;

/// Hot-swappable set of compiled protocols.
pub struct ProtocolEngine {
    inner: ArcSwap<Compiled>,
}

impl Default for ProtocolEngine {
    fn default() -> Self {
        Self::new(Compiled::default())
    }
}

impl ProtocolEngine {
    /// Engine with an initial compiled set.
    pub fn new(compiled: Compiled) -> Self {
        Self {
            inner: ArcSwap::from_pointee(compiled),
        }
    }

    /// Atomically replaces the compiled set (hot reload).
    pub fn swap(&self, compiled: Compiled) {
        self.inner.store(Arc::new(compiled));
    }

    /// Snapshot of the current compiled set.
    pub fn current(&self) -> Arc<Compiled> {
        self.inner.load_full()
    }
}

/// Free entry point so hosts holding their own compiled snapshot can
/// validate frames without touching the swappable engine.
pub fn feed_on(
    proto: &CompiledProtocol,
    state: &mut ConnectionState,
    bytes: &[u8],
) -> Result<FrameInfo, Vec<Violation>> {
    feed_impl(proto, state, bytes)
}

/// Per-connection validation state. Owned by the connection task.
#[derive(Debug)]
pub struct ConnectionState {
    seen: HashSet<u64>,
    last_seen: Option<Instant>,
    keepalive_hits: VecDeque<Instant>,
    last_keepalive: Option<Instant>,
    policy_hits: HashMap<String, VecDeque<Instant>>,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionState {
    /// Fresh state for a new connection.
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            last_seen: None,
            keepalive_hits: VecDeque::new(),
            last_keepalive: None,
            policy_hits: HashMap::new(),
        }
    }

    /// Whether no frame was seen for longer than `ttl` (stale prune).
    pub fn is_stale(&self, ttl: std::time::Duration) -> bool {
        self.last_seen.map(|t| t.elapsed() > ttl).unwrap_or(true)
    }

    /// Last keepalive instant, if any arrived.
    pub fn last_keepalive(&self) -> Option<Instant> {
        self.last_keepalive
    }
}

/// Successful frame validation outcome.
#[derive(Debug, Clone)]
pub struct FrameInfo {
    /// Matched message label.
    pub message: Arc<str>,
    /// Whether this frame refreshed connection liveness.
    pub keepalive: bool,
}

impl ProtocolEngine {
    /// Validates one frame against `proto`, updating `state`.
    ///
    /// `bytes` must be a complete frame (the host owns stream framing and
    /// reassembly). Returns all violations produced by the frame; an empty
    /// `Err` vec never happens (`Err` always has at least one entry).
    pub fn feed(
        &self,
        proto: &CompiledProtocol,
        state: &mut ConnectionState,
        bytes: &[u8],
    ) -> Result<FrameInfo, Vec<Violation>> {
        feed_impl(proto, state, bytes)
    }
}

fn feed_impl(
    proto: &CompiledProtocol,
    state: &mut ConnectionState,
    bytes: &[u8],
) -> Result<FrameInfo, Vec<Violation>> {
    {
        let now = Instant::now();
        state.last_seen = Some(now);
        let mut regs = std::array::from_fn(|_| Value::default());
        let mut cur = std::io::Cursor::new(bytes);

        let mut violations = Vec::new();
        if let Err(reason) = crate::compile::run_vm(&proto.preamble, &mut cur, &mut regs) {
            violations.push(
                proto
                    .violation(&proto.unknown_policy, "", format!("framing: {reason}"))
                    .with_escalation(proto, state, now),
            );
            return Err(violations);
        }

        let idx = proto.dispatch(&regs).ok_or_else(|| {
            let header = proto
                .dispatch_reg
                .and_then(|r| regs[r as usize].as_num())
                .unwrap_or(0);
            vec![proto
                .violation(
                    &proto.unknown_policy,
                    "",
                    format!("unknown header {header}"),
                )
                .with_escalation(proto, state, now)]
        })?;
        let msg = &proto.messages[idx as usize];

        for missing in &msg.after {
            if !state.seen.contains(missing) {
                violations.push(
                    proto
                        .violation(
                            &msg.policy,
                            &msg.name,
                            "sequence violation: required message not seen yet".to_string(),
                        )
                        .with_escalation(proto, state, now),
                );
            }
        }
        if !violations.is_empty() {
            return Err(violations);
        }

        if let Some(spec) = &msg.keepalive {
            match spec {
                Keepalive::Flag => {
                    state.last_keepalive = Some(now);
                }
                Keepalive::Spec { rate_limit, .. } => {
                    if let Some(limit) = rate_limit {
                        while state
                            .keepalive_hits
                            .front()
                            .map(|t| t.elapsed() > limit.window)
                            .unwrap_or(false)
                        {
                            state.keepalive_hits.pop_front();
                        }
                        state.keepalive_hits.push_back(now);
                        if state.keepalive_hits.len() as u32 > limit.count {
                            state.keepalive_hits.pop_front();
                            violations.push(
                                proto
                                    .violation(
                                        &msg.policy,
                                        &msg.name,
                                        format!(
                                            "keepalive flood: more than {} in {:?}",
                                            limit.count, limit.window
                                        ),
                                    )
                                    .with_escalation(proto, state, now),
                            );
                            return Err(violations);
                        }
                    }
                    state.last_keepalive = Some(now);
                }
            }
        }

        match crate::compile::run_vm(&msg.program, &mut cur, &mut regs) {
            Ok(()) => {
                state.seen.insert(msg.name_hash);
                if violations.is_empty() {
                    Ok(FrameInfo {
                        message: Arc::clone(&msg.name),
                        keepalive: msg.keepalive.is_some(),
                    })
                } else {
                    Err(violations)
                }
            }
            Err(reason) => {
                violations.push(
                    proto
                        .violation(&msg.policy, &msg.name, reason)
                        .with_escalation(proto, state, now),
                );
                Err(violations)
            }
        }
    }
}

impl Violation {
    fn with_escalation(
        mut self,
        proto: &CompiledProtocol,
        state: &mut ConnectionState,
        now: Instant,
    ) -> Self {
        if let Some(spec) = proto.policy(&self.policy) {
            if let Some(rep) = &spec.on_repeat {
                let hits = state
                    .policy_hits
                    .entry(self.policy.to_string())
                    .or_default();
                while hits
                    .front()
                    .map(|t| t.elapsed() > rep.window)
                    .unwrap_or(false)
                {
                    hits.pop_front();
                }
                hits.push_back(now);
                if hits.len() as u32 >= rep.count {
                    hits.clear();
                    if rep.escalate {
                        self.escalated = true;
                    }
                }
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{CompileOptions, Compiled};
    use crate::schema::ProtocolSchema;

    const GAME_SCHEMA: &str = r#"
id: game-relay
transport:
  protocol: tcp
  ports: [14901]
on_message:
  run: check_len! | parse_header!
types:
  LPStr: {prefix: u16, decode: utf8, max_len: 64}
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
    on_repeat: {count: 2, window: 60s, escalate: true}
messages:
  sso_ticket_event:
    when: {header: 400}
    validate:
      - sso_ticket: LPStr >2 <32 regex 'GAME-[a-zA-Z0-9]+-3324'
  move_event:
    when: {header: 3626}
    after: [sso_ticket_event]
    validate:
      - x: VLInt >-1 <149
      - y: VLInt >-1 <149
"#;

    /// Builds a game-protocol-style frame: [len:4][header:2][payload].
    fn frame(header: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(2 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn vlint(n: i64) -> Vec<u8> {
        let negative = n < 0;
        let v = n.unsigned_abs();
        // Layout matching the VLInt body: byte0 carries the MOST
        // significant 2 value bits, each continuation byte the next 6-bit
        // group down to the least significant (decode shifts acc left).
        let mut c = 0usize;
        while v >> (2 + 6 * c) > 0 {
            c += 1;
        }
        let sign = if negative { 4u8 } else { 0 };
        let mut out = vec![0x40 | (((c as u8) & 0x07) << 3) | sign | ((v >> (6 * c)) as u8 & 0x03)];
        for i in (0..c).rev() {
            out.push(((v >> (6 * i)) as u8 & 0x3F) | 0x40);
        }
        out
    }

    fn engine() -> ProtocolEngine {
        let schema = ProtocolSchema::from_yaml(GAME_SCHEMA).unwrap();
        let mut compiled = Compiled::default();
        compiled.add(schema, &CompileOptions::default()).unwrap();
        ProtocolEngine::new(compiled)
    }

    #[test]
    fn validates_valid_sso_frame() {
        let eng = engine();
        let compiled = eng.current();
        let proto = compiled.for_port(14901).unwrap();
        let mut state = ConnectionState::new();
        let payload = {
            let ticket = b"GAME-user-3324";
            let mut p = vec![];
            p.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            p.extend_from_slice(ticket);
            p
        };
        let frame = frame(400, &payload);
        let info = eng.feed(proto, &mut state, &frame).unwrap();
        assert_eq!(&*info.message, "sso_ticket_event");
    }

    #[test]
    fn rejects_framing_mismatch() {
        let eng = engine();
        let compiled = eng.current();
        let proto = compiled.for_port(14901).unwrap();
        let mut state = ConnectionState::new();
        let mut frame = frame(400, &[1, 2, 3]);
        frame[0] = 0xFF; // lie about the length
        let errs = eng.feed(proto, &mut state, &frame).unwrap_err();
        assert!(errs[0].reason.contains("framing"));
        assert_eq!(&*errs[0].policy, "unknown_header");
    }

    #[test]
    fn rejects_unknown_header() {
        let eng = engine();
        let compiled = eng.current();
        let proto = compiled.for_port(14901).unwrap();
        let mut state = ConnectionState::new();
        let errs = eng
            .feed(proto, &mut state, &frame(9999, &[0, 0]))
            .unwrap_err();
        assert!(errs[0].reason.contains("unknown header 9999"));
    }

    #[test]
    fn enforces_after_sequence_and_escalates() {
        let eng = engine();
        let compiled = eng.current();
        let proto = compiled.for_port(14901).unwrap();
        let mut state = ConnectionState::new();
        let payload = {
            let mut p = vec![];
            p.extend_from_slice(&2u16.to_be_bytes());
            p.extend_from_slice(&vlint(10));
            p.extend_from_slice(&vlint(20));
            p
        };
        // move_event before sso → sequence violation, twice → escalation.
        let frame = frame(3626, &payload);
        let e1 = eng.feed(proto, &mut state, &frame).unwrap_err();
        assert!(!e1[0].escalated);
        let e2 = eng.feed(proto, &mut state, &frame).unwrap_err();
        assert_eq!(&*e2[0].policy, "default");
        assert!(!e2[0].escalated, "after violations cite message policy");
    }

    #[test]
    fn valid_sequence_passes() {
        let eng = engine();
        let compiled = eng.current();
        let proto = compiled.for_port(14901).unwrap();
        let mut state = ConnectionState::new();
        let ticket = b"GAME-user-3324";
        let sso_payload = {
            let mut p = vec![];
            p.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            p.extend_from_slice(ticket);
            p
        };
        let sso = frame(400, &sso_payload);
        eng.feed(proto, &mut state, &sso).unwrap();
        let move_payload = {
            let mut p = vec![];
            p.extend_from_slice(&2u16.to_be_bytes());
            p.extend_from_slice(&vlint(10));
            p.extend_from_slice(&vlint(20));
            p
        };
        let info = eng
            .feed(proto, &mut state, &frame(3626, &move_payload))
            .unwrap();
        assert_eq!(&*info.message, "move_event");
    }

    #[test]
    fn rejects_bad_ticket_regex() {
        let eng = engine();
        let compiled = eng.current();
        let proto = compiled.for_port(14901).unwrap();
        let mut state = ConnectionState::new();
        let ticket = b"FORGED-ticket-9999";
        let payload = {
            let mut p = vec![];
            p.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            p.extend_from_slice(ticket);
            p
        };
        let errs = eng
            .feed(proto, &mut state, &frame(400, &payload))
            .unwrap_err();
        assert!(errs[0].reason.contains("regex"));
        assert_eq!(&*errs[0].message, "sso_ticket_event");
    }

    #[test]
    fn vlint_encoding_matches_schema() {
        // Sanity: our test encoder produces marker-valid bytes.
        for n in [0i64, 1, 3, 4, 100, -5] {
            let enc = vlint(n);
            assert_eq!(enc[0] & 0xC0, 0x40);
            for b in &enc[1..] {
                assert_eq!(b & 0xC0, 0x40);
            }
        }
    }

    const NOT_SCHEMA: &str = r#"
id: not-test
transport:
  protocol: tcp
  ports: [14902]
on_message:
  run: check_len! | parse_header!
types:
  ZeroFlag:
    body:
      - b: "read u8"
      - f: "not b"
      - check_range!(f, 1, 1)
policies:
  default: {weight: 20}
messages:
  ping_event:
    when: {header: 4096}
    validate:
      - flag: ZeroFlag
"#;

    #[test]
    fn not_operator_and_statement_checks() {
        let schema = ProtocolSchema::from_yaml(NOT_SCHEMA).unwrap();
        let mut compiled = Compiled::default();
        compiled.add(schema, &CompileOptions::default()).unwrap();
        let eng = ProtocolEngine::new(compiled);
        let compiled = eng.current();
        let proto = compiled.for_port(14902).unwrap();
        let mut state = ConnectionState::new();
        assert!(eng.feed(proto, &mut state, &frame(4096, &[0])).is_ok());
        let errs = eng.feed(proto, &mut state, &frame(4096, &[1])).unwrap_err();
        assert!(errs[0].reason.contains("out of range"), "{errs:?}");
    }

    #[test]
    fn negative_vlint_exercises_if_sign() {
        let eng = engine();
        let compiled = eng.current();
        let proto = compiled.for_port(14901).unwrap();
        let mut state = ConnectionState::new();
        let ticket = b"GAME-user-3324";
        let sso_payload = {
            let mut p = vec![];
            p.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            p.extend_from_slice(ticket);
            p
        };
        eng.feed(proto, &mut state, &frame(400, &sso_payload))
            .unwrap();
        let payload = {
            let mut p = vec![];
            p.extend_from_slice(&vlint(-5));
            p.extend_from_slice(&vlint(20));
            p
        };
        let errs = eng
            .feed(proto, &mut state, &frame(3626, &payload))
            .unwrap_err();
        assert!(
            errs[0].reason.contains("bound failed: -5"),
            "if sign must negate the accumulator: {errs:?}"
        );
    }
}
