//! UDP/TCP syslog receiver implementing the [`Source`] trait.
//!
//! The socket is bound inside [`Source::stream`] (so bind failures surface
//! as errors instead of dying silently in a background task); the receive
//! loop then runs in a spawned task pushing [`RawEvent`]s into a bounded
//! channel. TCP connections are framed per RFC 6587 — octet-counting or
//! newline-terminated.

use std::net::SocketAddr;
use std::str::FromStr;

use async_trait::async_trait;
use sentry_core::event::{ProtocolData, RawEvent, SourceKind, SyslogData, Transport};
use sentry_core::source::{event_channel, send_or_log, Source};
use sentry_core::{CoreError, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::parser::parse_syslog;

/// Default bind address (UDP 514 requires root, so 5140 is used instead).
pub const DEFAULT_BIND: &str = "0.0.0.0:5140";

/// L4 transport the receiver listens on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogTransport {
    /// UDP datagrams (classic syslog, RFC 5426).
    Udp,
    /// TCP connections with RFC 6587 framing.
    Tcp,
}

impl FromStr for SyslogTransport {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            other => Err(CoreError::Config(format!(
                "unknown syslog transport `{other}` — expected `udp` or `tcp`"
            ))),
        }
    }
}

/// Configuration for the syslog source.
#[derive(Debug, Clone)]
pub struct SyslogSourceConfig {
    /// Bind address (`ip:port`; prefer ports > 1024 to avoid needing root).
    pub bind_addr: String,
    /// Transport to listen on.
    pub transport: SyslogTransport,
}

impl Default for SyslogSourceConfig {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND.to_string(),
            transport: SyslogTransport::Udp,
        }
    }
}

/// Syslog receiver source.
pub struct SyslogSource {
    bind: SocketAddr,
    transport: SyslogTransport,
}

impl SyslogSource {
    /// Create the source, validating the bind address eagerly.
    pub fn new(cfg: SyslogSourceConfig) -> Result<Self> {
        let bind: SocketAddr = cfg.bind_addr.parse().map_err(|e| {
            CoreError::Config(format!("syslog bind address `{}`: {e}", cfg.bind_addr))
        })?;
        Ok(Self {
            bind,
            transport: cfg.transport,
        })
    }
}

#[async_trait]
impl Source for SyslogSource {
    fn name(&self) -> &'static str {
        "syslog"
    }

    async fn stream(&self) -> Result<tokio::sync::mpsc::Receiver<RawEvent>> {
        let (tx, rx) = event_channel(1024);
        match self.transport {
            SyslogTransport::Udp => {
                let sock = UdpSocket::bind(self.bind)
                    .await
                    .map_err(|e| CoreError::Plugin {
                        plugin: "syslog",
                        message: format!("udp bind on {}: {e}", self.bind),
                    })?;
                info!(bind = %self.bind, "syslog udp receiver listening");
                tokio::spawn(udp_loop(sock, tx));
            }
            SyslogTransport::Tcp => {
                let listener =
                    TcpListener::bind(self.bind)
                        .await
                        .map_err(|e| CoreError::Plugin {
                            plugin: "syslog",
                            message: format!("tcp bind on {}: {e}", self.bind),
                        })?;
                info!(bind = %self.bind, "syslog tcp receiver listening");
                tokio::spawn(tcp_loop(listener, tx));
            }
        }
        Ok(rx)
    }
}

fn build_event(
    line: &str,
    data: SyslogData,
    peer: SocketAddr,
    local_port: Option<u16>,
    len: usize,
    transport: Transport,
) -> RawEvent {
    RawEvent {
        source: SourceKind::Syslog,
        timestamp: data.timestamp.unwrap_or_else(chrono::Utc::now),
        transport,
        client_ip: Some(peer.ip()),
        client_port: Some(peer.port()),
        server_port: local_port,
        bytes_in: Some(len as u64),
        bytes_out: None,
        duration_ms: None,
        raw: Some(line.to_string()),
        protocol: ProtocolData::Syslog(data),
    }
}

fn dispatch(
    tx: &Sender<RawEvent>,
    line: &str,
    peer: SocketAddr,
    local_port: Option<u16>,
    len: usize,
    transport: Transport,
) {
    match parse_syslog(line) {
        Ok(data) => send_or_log(
            tx,
            build_event(line, data, peer, local_port, len, transport),
            "syslog",
        ),
        Err(e) => warn!(error = %e, peer = %peer, "skipping unparseable syslog message"),
    }
}

async fn udp_loop(sock: UdpSocket, tx: Sender<RawEvent>) {
    let local_port = sock.local_addr().ok().map(|a| a.port());
    let mut buf = vec![0u8; 65_536];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                let line = String::from_utf8_lossy(&buf[..n]);
                let line = line.trim_end_matches(['\r', '\n']).trim();
                if line.is_empty() {
                    continue;
                }
                dispatch(&tx, line, peer, local_port, n, Transport::Udp);
            }
            Err(e) => {
                warn!(error = %e, "syslog udp recv failed");
            }
        }
    }
}

async fn tcp_loop(listener: TcpListener, tx: Sender<RawEvent>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let local_port = stream.local_addr().ok().map(|a| a.port());
                    let mut reader = BufReader::new(stream);
                    let mut buf = Vec::with_capacity(1024);
                    loop {
                        buf.clear();
                        let n = match read_frame(&mut reader, &mut buf).await {
                            Ok(n) => n,
                            Err(e) => {
                                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                                    warn!(error = %e, peer = %peer, "syslog tcp read failed");
                                }
                                break;
                            }
                        };
                        if n == 0 {
                            break;
                        }
                        let line = String::from_utf8_lossy(&buf);
                        let line = line.trim_end_matches(['\r', '\n']).trim();
                        if line.is_empty() {
                            continue;
                        }
                        dispatch(&tx, line, peer, local_port, n, Transport::Tcp);
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "syslog tcp accept failed");
            }
        }
    }
}

/// Read one syslog frame from a TCP connection.
///
/// RFC 6587 allows two framings: octet-counting (`"123 <30>1 …"` with no
/// terminator) and the classic newline-terminated form. Syslog frames always
/// start with `<`, so a leading ASCII digit unambiguously selects
/// octet-counting.
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let is_octet = {
        let peek = reader.fill_buf().await?;
        !peek.is_empty() && peek[0].is_ascii_digit()
    };
    if !is_octet {
        return reader.read_until(b'\n', buf).await;
    }

    let mut prefix = Vec::with_capacity(8);
    reader.read_until(b' ', &mut prefix).await?;
    let len: usize = match std::str::from_utf8(&prefix[..prefix.len().saturating_sub(1)])
        .ok()
        .and_then(|s| s.trim().parse().ok())
    {
        Some(n) if n > 0 && n < 65_536 => n,
        _ => {
            buf.extend_from_slice(&prefix);
            let extra = reader.read_until(b'\n', buf).await?;
            return Ok(prefix.len() + extra);
        }
    };
    buf.resize(len, 0);
    reader.read_exact(buf).await?;
    Ok(len)
}
