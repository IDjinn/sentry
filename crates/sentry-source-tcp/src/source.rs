//! [`Source`] impl: passive capture (feature `pcap`) over the shared flow
//! table + fingerprint logic.

#[cfg(feature = "pcap")]
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
#[cfg(feature = "pcap")]
use std::time::Duration;

use async_trait::async_trait;
use sentry_core::event::RawEvent;
#[cfg(feature = "pcap")]
use sentry_core::event::{SourceKind, TcpData, TcpFlags, Transport};
#[cfg(feature = "pcap")]
use sentry_core::source::event_channel;
use sentry_core::source::Source;
#[cfg(feature = "pcap")]
use sentry_core::tcpfp::SynFingerprint;
use tokio::sync::mpsc;

use crate::reassembler::FlowTable;
#[cfg(feature = "pcap")]
use crate::reassembler::{stream_id, FlowObservation};

/// TCP capture source configuration.
#[derive(Debug, Clone)]
pub struct TcpSourceConfig {
    /// Interface to capture on (feature `pcap`), e.g. `eth0` / `eth3`.
    pub interface: String,
    /// Destination ports to keep (BPF-style filter); empty = all.
    pub ports: Vec<u16>,
    /// Reassembled payload bytes kept per flow (default 8 KiB).
    pub payload_cap: usize,
    /// Max simultaneously tracked flows (default 65_536).
    pub flow_cap: usize,
}

impl Default for TcpSourceConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            ports: Vec::new(),
            payload_cap: crate::reassembler::DEFAULT_PAYLOAD_CAP,
            flow_cap: 65_536,
        }
    }
}

/// Shared flow table handed to the capture loop (and reusable by the inline
/// `edge-tcp` listener).
pub type SharedFlows = Arc<Mutex<FlowTable>>;

/// Passive TCP capture source (F3.2).
///
/// Built with `--features pcap`; without it the pure logic is still
/// exported (fingerprinting + [`FlowTable`]) for inline consumers.
#[derive(Debug)]
pub struct TcpCaptureSource {
    cfg: TcpSourceConfig,
    flows: SharedFlows,
}

impl TcpCaptureSource {
    /// Validate config and build the source.
    pub fn new(cfg: TcpSourceConfig) -> sentry_core::error::Result<Self> {
        #[cfg(not(feature = "pcap"))]
        {
            let _ = &cfg;
            Err(sentry_core::error::CoreError::Config(
                "sentry-source-tcp was built without the `pcap` feature — rebuild sentry-cli with --features sentry-cli/pcap (requires Npcap on Windows / CAP_NET_RAW on Linux)".into(),
            ))
        }
        #[cfg(feature = "pcap")]
        {
            if cfg.interface.trim().is_empty() {
                return Err(sentry_core::error::CoreError::Config(
                    "tcp source requires `interface`".into(),
                ));
            }
            let flows = Arc::new(Mutex::new(FlowTable::new(cfg.flow_cap, cfg.payload_cap)));
            Ok(Self { cfg, flows })
        }
    }

    /// Shared flow table (for inline listeners that feed their own segments).
    pub fn flows(&self) -> SharedFlows {
        Arc::clone(&self.flows)
    }
}

/// Owned view of one captured TCP segment (ethernet → IP → TCP).
#[cfg(feature = "pcap")]
struct SegmentView {
    src_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    flags: TcpFlags,
    window: u16,
    payload: Vec<u8>,
    options: Vec<u8>,
}

/// Decode one ethernet frame into a TCP segment view, or `None` when it is
/// not IPv4/IPv6+TCP.
#[cfg(feature = "pcap")]
fn parse_segment(eth_bytes: &[u8]) -> Option<SegmentView> {
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv6::Ipv6Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    let eth = EthernetPacket::new(eth_bytes)?;
    let flags_of = |tcp: &TcpPacket<'_>| TcpFlags {
        syn: tcp.get_flags() & 0x02 != 0,
        ack: tcp.get_flags() & 0x10 != 0,
        fin: tcp.get_flags() & 0x01 != 0,
        rst: tcp.get_flags() & 0x04 != 0,
        psh: tcp.get_flags() & 0x08 != 0,
        urg: tcp.get_flags() & 0x20 != 0,
    };
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let v4 = Ipv4Packet::new(eth.payload())?;
            let tcp = TcpPacket::new(v4.payload())?;
            Some(SegmentView {
                src_ip: IpAddr::V4(v4.get_source()),
                src_port: tcp.get_source(),
                dst_port: tcp.get_destination(),
                flags: flags_of(&tcp),
                window: tcp.get_window(),
                payload: tcp.payload().to_vec(),
                options: tcp.get_options_raw().to_vec(),
            })
        }
        EtherTypes::Ipv6 => {
            let v6 = Ipv6Packet::new(eth.payload())?;
            let tcp = TcpPacket::new(v6.payload())?;
            Some(SegmentView {
                src_ip: IpAddr::V6(v6.get_source()),
                src_port: tcp.get_source(),
                dst_port: tcp.get_destination(),
                flags: flags_of(&tcp),
                window: tcp.get_window(),
                payload: tcp.payload().to_vec(),
                options: tcp.get_options_raw().to_vec(),
            })
        }
        _ => None,
    }
}

#[async_trait]
impl Source for TcpCaptureSource {
    fn name(&self) -> &'static str {
        "tcp"
    }

    async fn stream(&self) -> sentry_core::error::Result<mpsc::Receiver<RawEvent>> {
        #[cfg(not(feature = "pcap"))]
        {
            let _ = &self.cfg;
            return Err(sentry_core::error::CoreError::Config(
                "tcp capture requires the `pcap` feature".into(),
            ));
        }

        #[cfg(feature = "pcap")]
        {
            use pnet::datalink::Channel::Ethernet;
            use pnet::datalink::{channel, Config, NetworkInterface};

            let iface_name = self.cfg.interface.clone();
            let interfaces: Vec<NetworkInterface> = pnet::datalink::interfaces()
                .into_iter()
                .filter(|i| i.name == iface_name)
                .collect();
            let Some(iface) = interfaces.into_iter().next() else {
                return Err(sentry_core::error::CoreError::Config(format!(
                    "interface `{iface_name}` not found"
                )));
            };
            let mut rx = match channel(&iface, Config::default()) {
                Ok(Ethernet(_tx, rx)) => rx,
                Ok(_) => {
                    return Err(sentry_core::error::CoreError::Config(
                        "capture channel: unsupported link type (ethernet only)".into(),
                    ))
                }
                Err(e) => {
                    return Err(sentry_core::error::CoreError::Config(format!(
                        "capture channel on {iface_name}: {e} (elevated privileges required)"
                    )))
                }
            };

            let (tx, chan_rx) = event_channel(1024);
            let cfg = self.cfg.clone();
            let flows = Arc::clone(&self.flows);
            tokio::task::spawn_blocking(move || loop {
                match rx.next() {
                    Ok(packet) => {
                        let Some(seg) = parse_segment(packet) else {
                            continue;
                        };
                        if !cfg.ports.is_empty() && !cfg.ports.contains(&seg.dst_port) {
                            continue;
                        }
                        let id = stream_id(seg.src_ip, seg.src_port, seg.src_ip, seg.dst_port);
                        let (observation, state) = {
                            let mut table = flows.lock().unwrap();
                            table.observe(id, seg.flags, &seg.payload)
                        };
                        let fingerprint = (observation == FlowObservation::Syn)
                            .then(|| SynFingerprint::from_parts(seg.window, &seg.options).code());
                        let evt = RawEvent {
                            source: SourceKind::Tcp,
                            timestamp: chrono::Utc::now(),
                            transport: Transport::Tcp,
                            client_ip: Some(seg.src_ip),
                            client_port: Some(seg.src_port),
                            server_port: Some(seg.dst_port),
                            bytes_in: Some(seg.payload.len() as u64),
                            bytes_out: None,
                            duration_ms: None,
                            raw: None,
                            protocol: sentry_core::ProtocolData::Tcp(TcpData {
                                flags: seg.flags,
                                payload: (!state.payload.is_empty()).then(|| state.payload.clone()),
                                stream_id: Some(id),
                                stage: state.stage,
                                fingerprint,
                            }),
                        };
                        sentry_core::source::send_or_log(&tx, evt, "tcp");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "tcp capture: recv failed");
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            });
            Ok(chan_rx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_pcap_feature_new_returns_config_error() {
        let err = TcpCaptureSource::new(TcpSourceConfig {
            interface: "eth0".into(),
            ..Default::default()
        })
        .expect_err("expected error without the pcap feature");
        assert!(err.to_string().contains("pcap"));
    }

    #[test]
    fn default_config_matches_backlog_defaults() {
        let cfg = TcpSourceConfig::default();
        assert_eq!(cfg.payload_cap, 8 * 1024);
        assert_eq!(cfg.flow_cap, 65_536);
        assert!(cfg.ports.is_empty());
    }
}
