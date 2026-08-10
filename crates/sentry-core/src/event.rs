//! Domain model for a single observed access event.
//!
//! [`Event`] is the normalized, protocol-agnostic representation that flows
//! through the entire pipeline. Protocol-specific details live inside the
//! [`ProtocolData`] enum, so adding a new protocol (e.g. raw TCP capture)
//! never breaks existing consumers: heuristics pattern-match on the variant
//! they understand and ignore the rest.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifier of the source plugin that produced the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// `sentry-source-nginx` — tail of an nginx access log.
    Nginx,
    /// `sentry-source-http` — inline HTTP middleware (future).
    HttpProxy,
    /// `sentry-source-tcp` — packet capture on a TCP port (future).
    Tcp,
    /// `sentry-source-cloudflare` — Cloudflare logs pulled via API.
    CloudflareLogs,
    /// `sentry-source-syslog` — RFC 5424 receiver (future).
    Syslog,
    /// Synthetic / test source.
    Synthetic,
}

impl SourceKind {
    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::HttpProxy => "http_proxy",
            Self::Tcp => "tcp",
            Self::CloudflareLogs => "cloudflare_logs",
            Self::Syslog => "syslog",
            Self::Synthetic => "synthetic",
        }
    }
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// L4 transport that carried the observed traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// QUIC / HTTP/3.
    Quic,
    /// Internal / synthetic event with no real transport.
    Internal,
}

/// Flow direction relative to the protected service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Incoming request to the service.
    Inbound,
    /// Outgoing response from the service (rarely observed).
    Outbound,
}

/// Coarse protocol family of the event. Used by `RuleMatch::Protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolKind {
    /// HTTP/1.x or HTTP/2 over TCP.
    Http,
    /// HTTP/3 over QUIC.
    Http3,
    /// Raw TCP stream (non-HTTP).
    Tcp,
    /// Raw UDP datagram.
    Udp,
    /// TLS handshake observation (SNI / JA3 / JA4).
    Tls,
    /// Anything else.
    Other,
}

/// HTTP method, stored as a small enum to allow cheap matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `HEAD`
    Head,
    /// `OPTIONS`
    Options,
    /// `CONNECT`
    Connect,
    /// `TRACE`
    Trace,
    /// Any other method, stored alongside.
    Other,
}

impl HttpMethod {
    /// Parse a method string into the enum, falling back to [`Other`].
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            _ => Self::Other,
        }
    }

    /// Uppercase stable name used in logs and route method checks.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Other => "OTHER",
        }
    }

    /// Whether this method is considered "rare/dangerous" by the default
    /// `http_anomaly` rule pack (`TRACE`, `CONNECT`).
    pub fn is_rare(self) -> bool {
        matches!(self, Self::Trace | Self::Connect)
    }
}

/// Geo enrichment attached to an event when a MaxMindDB lookup is available.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code (e.g. `BR`, `US`).
    pub country: Option<String>,
    /// ISO 3166-2 subdivision code (e.g. `BR-SP`).
    pub subdivision: Option<String>,
    /// City name in English.
    pub city: Option<String>,
    /// Approximate latitude.
    pub lat: Option<f32>,
    /// Approximate longitude.
    pub lon: Option<f32>,
}

/// The normalized, protocol-agnostic event that flows through the pipeline.
///
/// Fields common to every protocol live directly on the struct; protocol
/// specifics live in [`protocol`](Self::protocol). This keeps the core stable
/// as new sources (TCP, TLS, UDP) are added without touching consumers that
/// only care about HTTP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Stable unique id for this event.
    pub id: Uuid,
    /// Wall-clock time the event was observed (ingest time, not log time).
    pub timestamp: DateTime<Utc>,
    /// Which source plugin produced this event.
    pub source: SourceKind,
    /// L4 transport that carried the traffic.
    pub transport: Transport,
    /// Inbound (request) or Outbound (response).
    pub direction: Direction,
    /// Client IP that initiated the access.
    pub client_ip: IpAddr,
    /// Client source port, when known.
    pub client_port: Option<u16>,
    /// Server / listening port that was accessed, when known.
    pub server_port: Option<u16>,
    /// Geo enrichment from MaxMindDB (populated by ingestor).
    pub geo: Option<GeoInfo>,
    /// Autonomous System Number of the client IP, when known.
    pub asn: Option<u32>,
    /// Bytes received from the client.
    pub bytes_in: Option<u64>,
    /// Bytes sent back to the client.
    pub bytes_out: Option<u64>,
    /// Request/response duration, when known.
    pub duration_ms: Option<u64>,
    /// The raw original record (log line, syslog message, …) for audit.
    pub raw: Option<String>,

    /// Protocol-specific payload (HTTP, TCP, TLS, …).
    pub protocol: ProtocolData,
}

impl Event {
    /// Creates a new event with a fresh id and current timestamp.
    pub fn new(source: SourceKind, client_ip: IpAddr, protocol: ProtocolData) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source,
            transport: Transport::Tcp,
            direction: Direction::Inbound,
            client_ip,
            client_port: None,
            server_port: None,
            geo: None,
            asn: None,
            bytes_in: None,
            bytes_out: None,
            duration_ms: None,
            raw: None,
            protocol,
        }
    }

    /// Returns the HTTP payload if this is an HTTP event, else `None`.
    ///
    /// Heuristics and rules use this to opt-in to HTTP-specific logic without
    /// assuming every event is HTTP.
    pub fn http(&self) -> Option<&HttpData> {
        match &self.protocol {
            ProtocolData::Http(d) => Some(d),
            _ => None,
        }
    }

    /// Returns the TCP payload if this is a TCP event, else `None`.
    pub fn tcp(&self) -> Option<&TcpData> {
        match &self.protocol {
            ProtocolData::Tcp(d) => Some(d),
            _ => None,
        }
    }

    /// Returns the TLS handshake data if present, else `None`.
    pub fn tls(&self) -> Option<&TlsData> {
        match &self.protocol {
            ProtocolData::TlsHandshake(d) => Some(d),
            _ => None,
        }
    }

    /// `true` if this event carries an HTTP payload.
    pub fn is_http(&self) -> bool {
        matches!(self.protocol, ProtocolData::Http(_))
    }

    /// Coarse [`ProtocolKind`] for rule matching.
    pub fn protocol_kind(&self) -> ProtocolKind {
        match self.protocol {
            ProtocolData::Http(_) => ProtocolKind::Http,
            ProtocolData::Tcp(_) => ProtocolKind::Tcp,
            ProtocolData::Udp(_) => ProtocolKind::Udp,
            ProtocolData::TlsHandshake(_) => ProtocolKind::Tls,
            ProtocolData::Raw(_) => ProtocolKind::Other,
        }
    }
}

/// Event as produced by a [`Source`](crate::source::Source) before enrichment.
///
/// Sources emit raw events with only what they can extract from their origin
/// (log line, packet, API). The ingestor then fills in geo, asn, dedup id,
/// etc. and produces a fully-fledged [`Event`]. Keeping the two separate lets
/// sources stay thin and lets the core own enrichment policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    /// Source that produced this raw event.
    pub source: SourceKind,
    /// Wall-clock observation time.
    pub timestamp: DateTime<Utc>,
    /// Client IP, when the source can extract it.
    pub client_ip: Option<IpAddr>,
    /// Client source port.
    pub client_port: Option<u16>,
    /// Server port that was accessed.
    pub server_port: Option<u16>,
    /// Bytes received from client.
    pub bytes_in: Option<u64>,
    /// Bytes sent to client.
    pub bytes_out: Option<u64>,
    /// Observed duration.
    pub duration_ms: Option<u64>,
    /// The original record (log line, syslog message, …).
    pub raw: Option<String>,
    /// Protocol-specific payload, partially populated.
    pub protocol: ProtocolData,
}

impl RawEvent {
    /// Promote a raw event into a normalized [`Event`].
    ///
    /// Caller is expected to fill in `geo`/`asn` afterwards, or leave them
    /// `None` when enrichment isn't available.
    pub fn into_event(self, client_ip: IpAddr) -> Event {
        Event {
            id: Uuid::new_v4(),
            timestamp: self.timestamp,
            source: self.source,
            transport: Transport::Tcp,
            direction: Direction::Inbound,
            client_ip,
            client_port: self.client_port,
            server_port: self.server_port,
            geo: None,
            asn: None,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            duration_ms: self.duration_ms,
            raw: self.raw,
            protocol: self.protocol,
        }
    }
}

/// Protocol-specific payload. Extensible: new protocols add a variant and
/// consumers that don't care simply ignore it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProtocolData {
    /// HTTP/1.x or HTTP/2 request observation.
    Http(HttpData),
    /// Raw TCP stream observation (non-HTTP).
    Tcp(TcpData),
    /// Raw UDP datagram.
    Udp(UdpData),
    /// TLS handshake metadata.
    TlsHandshake(TlsData),
    /// Fallback for protocols without a dedicated variant.
    Raw(RawData),
}

/// HTTP-specific payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpData {
    /// Request method.
    pub method: Option<HttpMethod>,
    /// URL scheme (`http` / `https`).
    pub scheme: Option<String>,
    /// `Host` header value.
    pub host: Option<String>,
    /// Request path (without query string).
    pub path: String,
    /// Raw query string (without `?`).
    pub query: Option<String>,
    /// URL fragment, rarely present in server logs.
    pub fragment: Option<String>,
    /// HTTP response status code, when observed.
    pub status: Option<u16>,
    /// `User-Agent` header.
    pub user_agent: Option<String>,
    /// `Referer` header.
    pub referer: Option<String>,
    /// All headers captured by the source.
    pub headers: HashMap<String, String>,
    /// Request body bytes, when the source is inline (proxy/middleware).
    pub body: Option<Vec<u8>>,
    /// Parsed cookies, when available.
    pub cookies: Option<HashMap<String, String>>,
}

/// TCP-specific observation (packet capture path).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpData {
    /// TCP flags observed on the packet.
    pub flags: TcpFlags,
    /// Reassembled stream payload bytes, when capture allows.
    pub payload: Option<Vec<u8>>,
    /// Correlation id for segments belonging to the same flow.
    pub stream_id: Option<u64>,
    /// Stage of the connection lifecycle.
    pub stage: TcpStage,
}

/// Observed TCP flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFlags {
    /// SYN.
    pub syn: bool,
    /// ACK.
    pub ack: bool,
    /// FIN.
    pub fin: bool,
    /// RST.
    pub rst: bool,
    /// PSH.
    pub psh: bool,
    /// URG.
    pub urg: bool,
}

/// Stage of a TCP connection observation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TcpStage {
    /// SYN received (connection start).
    #[default]
    Syn,
    /// SYN-ACK seen.
    SynAck,
    /// Data transfer.
    Data,
    /// FIN (graceful close).
    Fin,
    /// RST (abortive close).
    Reset,
}

/// UDP-specific observation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UdpData {
    /// Datagram payload bytes.
    pub payload: Option<Vec<u8>>,
    /// Decoded DNS query name, when the datagram looks like DNS.
    pub dns_query: Option<String>,
}

/// TLS handshake metadata extracted from the ClientHello.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsData {
    /// Server Name Indication.
    pub sni: Option<String>,
    /// JA3 fingerprint hash.
    pub ja3: Option<String>,
    /// JA4 fingerprint.
    pub ja4: Option<String>,
    /// Negotiated cipher suite.
    pub cipher: Option<String>,
    /// TLS version.
    pub version: Option<String>,
}

/// Fallback payload for protocols without a dedicated variant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawData {
    /// Free-form note describing what the bytes represent.
    pub note: String,
    /// Raw captured bytes.
    pub bytes: Vec<u8>,
}
