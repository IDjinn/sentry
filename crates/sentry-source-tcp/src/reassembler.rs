//! Per-flow TCP state: stage tracking + bounded payload reassembly.
//!
//! Pure logic shared by the passive capture (feature `pcap`) and the inline
//! TCP listener (F3.9b). Flows are keyed by a stable hash of the 4-tuple.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use sentry_core::event::{TcpFlags, TcpStage};

/// Default cap on reassembled payload bytes kept per flow.
pub const DEFAULT_PAYLOAD_CAP: usize = 8 * 1024;

/// Stable correlation id for a TCP flow (order-independent 4-tuple hash).
pub fn stream_id(src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    // Normalize direction so both legs of a conversation share the id.
    let (a, pa, b, pb) = if (src, sport) <= (dst, dport) {
        (src, sport, dst, dport)
    } else {
        (dst, dport, src, sport)
    };
    a.hash(&mut h);
    pa.hash(&mut h);
    b.hash(&mut h);
    pb.hash(&mut h);
    h.finish()
}

/// State of a single TCP flow.
#[derive(Debug, Clone, Default)]
pub struct FlowState {
    /// Latest lifecycle stage observed.
    pub stage: TcpStage,
    /// Reassembled payload (bounded).
    pub payload: Vec<u8>,
}

/// What one observed segment tells the flow table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowObservation {
    /// Initial SYN (fingerprint material).
    Syn,
    /// Server SYN-ACK (connection established).
    SynAck,
    /// In-band data (`n` new bytes appended, capped).
    Data(usize),
    /// Graceful close.
    Fin,
    /// Abortive close.
    Reset,
}

/// Bounded table of active flows.
///
/// When the table is full, the oldest insertion is evicted (simple FIFO over
/// an insertion queue) so long-lived captures cannot grow without bound.
#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<u64, FlowState>,
    order: std::collections::VecDeque<u64>,
    cap: usize,
    payload_cap: usize,
}

impl FlowTable {
    /// New table with a flow cap and per-flow payload cap.
    pub fn new(cap: usize, payload_cap: usize) -> Self {
        Self {
            flows: HashMap::new(),
            order: std::collections::VecDeque::new(),
            cap: cap.max(1),
            payload_cap: payload_cap.max(1),
        }
    }

    /// Number of tracked flows.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether no flows are tracked.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Observe one segment, updating stage/payload. Returns the observation
    /// and the (possibly updated) flow state.
    pub fn observe(
        &mut self,
        id: u64,
        flags: TcpFlags,
        payload: &[u8],
    ) -> (FlowObservation, FlowState) {
        if !self.flows.contains_key(&id) {
            self.order.push_back(id);
            if self.order.len() > self.cap {
                if let Some(evict) = self.order.pop_front() {
                    self.flows.remove(&evict);
                }
            }
        }
        let state = self.flows.entry(id).or_default();

        let observation = if flags.syn && !flags.ack {
            state.stage = TcpStage::Syn;
            state.payload.clear();
            FlowObservation::Syn
        } else if flags.syn && flags.ack {
            state.stage = TcpStage::SynAck;
            FlowObservation::SynAck
        } else if flags.rst {
            state.stage = TcpStage::Reset;
            FlowObservation::Reset
        } else if flags.fin {
            state.stage = TcpStage::Fin;
            FlowObservation::Fin
        } else if !payload.is_empty() {
            state.stage = TcpStage::Data;
            let room = self.payload_cap.saturating_sub(state.payload.len());
            let take = room.min(payload.len());
            state.payload.extend_from_slice(&payload[..take]);
            FlowObservation::Data(take)
        } else {
            // Bare ACK: no stage change, nothing to reassemble.
            return (FlowObservation::Data(0), state.clone());
        };

        (observation, state.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn flags(syn: bool, ack: bool, fin: bool, rst: bool) -> TcpFlags {
        TcpFlags {
            syn,
            ack,
            fin,
            rst,
            psh: false,
            urg: false,
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn stream_id_is_direction_independent() {
        let a = stream_id(ip(1, 2, 3, 4), 5555, ip(9, 9, 9, 9), 443);
        let b = stream_id(ip(9, 9, 9, 9), 443, ip(1, 2, 3, 4), 5555);
        assert_eq!(a, b);
        let c = stream_id(ip(1, 2, 3, 4), 5556, ip(9, 9, 9, 9), 443);
        assert_ne!(a, c);
    }

    #[test]
    fn lifecycle_stages_progress() {
        let mut t = FlowTable::new(16, 1024);
        let id = 42;
        let (obs, st) = t.observe(id, flags(true, false, false, false), &[]);
        assert_eq!(obs, FlowObservation::Syn);
        assert_eq!(st.stage, TcpStage::Syn);
        let (obs, _) = t.observe(id, flags(true, true, false, false), &[]);
        assert_eq!(obs, FlowObservation::SynAck);
        let (obs, st) = t.observe(id, flags(false, true, false, false), b"GET / HTTP/1.1");
        assert_eq!(obs, FlowObservation::Data(14));
        assert_eq!(st.stage, TcpStage::Data);
        assert_eq!(st.payload, b"GET / HTTP/1.1");
        let (obs, _) = t.observe(id, flags(false, true, true, false), &[]);
        assert_eq!(obs, FlowObservation::Fin);
    }

    #[test]
    fn syn_reset_clears_payload() {
        let mut t = FlowTable::new(16, 1024);
        let id = 7;
        t.observe(id, flags(true, false, false, false), &[]);
        t.observe(id, flags(false, true, false, false), b"hello");
        let (obs, st) = t.observe(id, flags(false, false, false, true), &[]);
        assert_eq!(obs, FlowObservation::Reset);
        assert_eq!(st.stage, TcpStage::Reset);
        let (_, st2) = t.observe(id, flags(true, false, false, false), &[]);
        assert!(st2.payload.is_empty(), "new SYN starts a clean stream");
    }

    #[test]
    fn payload_is_capped_per_flow() {
        let mut t = FlowTable::new(16, 8);
        let id = 1;
        t.observe(id, flags(true, false, false, false), &[]);
        let (_, st) = t.observe(id, flags(false, true, false, false), &vec![b'x'; 100]);
        assert_eq!(st.payload.len(), 8);
        // Further data is dropped once the cap is reached.
        let (_, st) = t.observe(id, flags(false, true, false, false), &vec![b'y'; 10]);
        assert_eq!(st.payload.len(), 8);
    }

    #[test]
    fn table_evicts_oldest_flow_at_capacity() {
        let mut t = FlowTable::new(2, 16);
        t.observe(1, flags(true, false, false, false), &[]);
        t.observe(2, flags(true, false, false, false), &[]);
        t.observe(3, flags(true, false, false, false), &[]);
        assert_eq!(t.len(), 2, "flow 1 was evicted");
        assert!(!t.contains(1));
        assert!(t.contains(2));
        assert!(t.contains(3));
    }

    impl FlowTable {
        fn contains(&self, id: u64) -> bool {
            self.flows.contains_key(&id)
        }
    }
}
