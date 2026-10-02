//! Frame-level protocol validation on the edge-tcp listener (F9).
//!
//! The host streams raw bytes; [`ProtocolConnection`] splits the
//! client→server direction into frames using the schema's `check_len!`
//! framing metadata, feeds each frame through the compiled validator and
//! reports what may be forwarded upstream. Violations map to
//! [`SignalKind::ProtocolViolation`] signals with the violated policy's
//! weight; in `enforce` mode the host closes the connection.

use std::sync::Arc;

use sentry_core::analysis::{Signal, SignalKind, PROTOCOL_VIOLATION_WEIGHT};
use sentry_protocol::compile::FrameSpec;
use sentry_protocol::schema::{Endian, Mode};
use sentry_protocol::{Compiled, CompiledProtocol, ConnectionState, ProtocolEngine, Violation};

/// Prometheus handles wired by the daemon (mirrors `TlsMetrics`).
#[derive(Clone)]
pub struct ProtocolMetrics {
    /// `sentry_protocol_violations_total{schema, policy}`.
    pub violations: prometheus::CounterVec,
    /// `sentry_protocol_frames_total{schema}` — validated frames.
    pub frames: prometheus::CounterVec,
}

/// Per-connection validator state for the client→server direction.
pub struct ProtocolConnection {
    compiled: Arc<Compiled>,
    proto_index: usize,
    framing: FrameSpec,
    state: ConnectionState,
    metrics: Option<ProtocolMetrics>,
    reported: bool,
    buf: Vec<u8>,
}

/// Outcome of feeding one chunk of client bytes into the validator.
#[derive(Debug, Default)]
pub struct Ingest {
    /// Complete frames the upstream may receive.
    pub forward: Vec<Vec<u8>>,
    /// Violations produced by the frames in this chunk.
    pub violations: Vec<Violation>,
    /// Set in `enforce` mode once a violation closes the connection.
    pub disconnect: bool,
    /// Set when the buffer held unframeable garbage (dropped).
    pub framing_broken: bool,
}

impl ProtocolConnection {
    /// Binds to the protocol guarding `local_port`, if any schema claims
    /// the port and declares framing. `None` = plain passthrough.
    pub fn bind(
        engine: &ProtocolEngine,
        local_port: u16,
        metrics: Option<ProtocolMetrics>,
    ) -> Option<Self> {
        let compiled = engine.current();
        let proto = compiled.for_port(local_port)?;
        let framing = proto.framing?;
        let proto_index = compiled
            .protocols
            .iter()
            .position(|p| p.schema_id == proto.schema_id)
            .unwrap_or(0);
        Some(Self {
            compiled,
            proto_index,
            framing,
            state: ConnectionState::new(),
            metrics,
            reported: false,
            buf: Vec::with_capacity(8192),
        })
    }

    /// Enforcement posture of the bound schema.
    pub fn mode(&self) -> Mode {
        self.proto().mode
    }

    fn proto(&self) -> &CompiledProtocol {
        &self.compiled.protocols[self.proto_index]
    }

    /// Whether a violation signal was already reported for this connection.
    pub fn reported(&self) -> bool {
        self.reported
    }

    /// Marks the connection as having reported a violation signal.
    pub fn mark_reported(&mut self) {
        self.reported = true;
    }

    /// Signals for a batch of violations (one burst per connection).
    pub fn signals(&self, violations: &[Violation]) -> Vec<Signal> {
        let proto = self.proto();
        violations
            .iter()
            .map(|v| {
                let weight = proto
                    .policy(&v.policy)
                    .map(|p| {
                        if v.escalated {
                            p.weight.saturating_mul(2).min(100)
                        } else {
                            p.weight
                        }
                    })
                    .unwrap_or(PROTOCOL_VIOLATION_WEIGHT);
                let label = if v.message.is_empty() {
                    String::new()
                } else {
                    format!("/{}", v.message)
                };
                Signal {
                    kind: SignalKind::ProtocolViolation,
                    weight,
                    detail: Some(format!(
                        "{}{label} policy={}: {}",
                        proto.schema_id, v.policy, v.reason
                    )),
                }
            })
            .collect()
    }

    /// Feeds one chunk of client bytes; returns what to forward upstream
    /// and any violations raised.
    pub fn ingest(&mut self, chunk: &[u8]) -> Ingest {
        self.buf.extend_from_slice(chunk);
        let mut out = Ingest::default();
        while !out.disconnect {
            match self.next_frame_len() {
                None => {
                    let cap = self.framing.max as usize + self.framing.offset as usize + 16;
                    if self.buf.len() > cap {
                        // Oversized garbage: cannot resync without framing.
                        self.buf.clear();
                        out.framing_broken = true;
                        out.disconnect = self.mode() == Mode::Enforce;
                    }
                    break;
                }
                Some(usize::MAX) => {
                    // Declared length beyond the schema cap: fatal framing.
                    self.buf.clear();
                    out.framing_broken = true;
                    out.disconnect = self.mode() == Mode::Enforce;
                    break;
                }
                Some(total) => {
                    let frame: Vec<u8> = self.buf.drain(..total).collect();
                    let schema_label = self.proto().schema_id.clone();
                    // Field-disjoint borrows: `compiled` read + `state` write.
                    let proto = &self.compiled.protocols[self.proto_index];
                    match sentry_protocol::feed_on(proto, &mut self.state, &frame) {
                        Ok(_) => {
                            if let Some(m) = &self.metrics {
                                m.frames.with_label_values(&[&schema_label]).inc();
                            }
                            out.forward.push(frame);
                        }
                        Err(violations) => {
                            if let Some(m) = &self.metrics {
                                for v in &violations {
                                    m.violations
                                        .with_label_values(&[&schema_label, &v.policy])
                                        .inc();
                                }
                            }
                            out.violations.extend(violations);
                            if self.mode() == Mode::Enforce {
                                out.disconnect = true;
                            } else {
                                // Shadow mode still forwards (observe-only).
                                out.forward.push(frame);
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Length of the next complete frame in the buffer, if one arrived.
    /// `Some(usize::MAX)` signals a declared length beyond the cap.
    fn next_frame_len(&self) -> Option<usize> {
        let f = &self.framing;
        let header_end = f.offset as usize + f.prefix_size as usize;
        if self.buf.len() < header_end {
            return None;
        }
        let len_bytes = &self.buf[f.offset as usize..header_end];
        let declared = match (f.prefix_size, f.endian) {
            (1, _) => len_bytes[0] as u64,
            (2, Endian::Big) => u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as u64,
            (2, Endian::Little) => u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as u64,
            (4, Endian::Big) => {
                u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as u64
            }
            (4, Endian::Little) => {
                u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as u64
            }
            (8, Endian::Big) => {
                let mut b = [0u8; 8];
                b.copy_from_slice(len_bytes);
                u64::from_be_bytes(b)
            }
            (8, Endian::Little) => {
                let mut b = [0u8; 8];
                b.copy_from_slice(len_bytes);
                u64::from_le_bytes(b)
            }
            _ => return None,
        };
        if declared > f.max {
            return Some(usize::MAX);
        }
        let expected = match f.counts {
            sentry_protocol::instr::LenCounts::HeaderPlusData => declared,
            sentry_protocol::instr::LenCounts::Data => declared + f.header_size,
        };
        let total = header_end as u64 + expected;
        if total > usize::MAX as u64 {
            return Some(usize::MAX);
        }
        if self.buf.len() >= total as usize {
            Some(total as usize)
        } else {
            None
        }
    }
}
