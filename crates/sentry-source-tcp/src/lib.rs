//! Passive TCP capture source (F3.2).
//!
//! Captures packets on a monitored interface (feature `pcap`, pnet datalink
//! with a port filter) and emits [`ProtocolData::Tcp`] events. On captured
//! SYNs it computes a passive fingerprint (MuonFP/p0f style,
//! `window:options:MSS:wscale` — see `sentry_core::tcpfp`) that the
//! `tcp_scanner` heuristic matches against masscan/zmap/nmap signatures.
//!
//! The pure logic (fingerprint parse, flow table / stream reassembly) builds
//! and tests everywhere; the raw-socket capture loop requires elevated
//! privileges and is therefore feature-gated (Npcap on Windows,
//! CAP_NET_RAW on Linux). The same flow table drives the inline
//! `edge-tcp` listener mode (F3.9b) without any capture dependency.

#![forbid(unsafe_code)]

mod aggregate;
mod reassembler;
mod source;

pub use aggregate::{SynAggregate, SynAggregator};
pub use reassembler::{stream_id, FlowObservation, FlowState, FlowTable};
pub use source::{
    TcpCaptureSource, TcpSourceConfig, DEFAULT_CHANNEL_BUFFER, DEFAULT_SYN_WINDOW_MS,
};
