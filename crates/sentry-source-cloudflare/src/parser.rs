//! NDJSON parsing for Cloudflare `logs/received` records.
//!
//! Pure and fixture-tested: one JSON object per line, Cloudflare's uppercase
//! field names mapped onto Sentry's [`HttpData`].

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sentry_core::event::{HttpData, HttpMethod, RawEvent, SourceKind, Transport};
use serde::Deserialize;

/// One Cloudflare log record (subset of fields Sentry consumes).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CfLogLine {
    /// Client IP (`ClientIP`).
    #[serde(rename = "ClientIP", default)]
    pub client_ip: Option<String>,
    /// Request method (`ClientRequestMethod`).
    #[serde(rename = "ClientRequestMethod", default)]
    pub method: Option<String>,
    /// Request path (`ClientRequestPath`).
    #[serde(rename = "ClientRequestPath", default)]
    pub path: Option<String>,
    /// Raw query string, without `?` (`ClientRequestQuery`).
    #[serde(rename = "ClientRequestQuery", default)]
    pub query: Option<String>,
    /// User agent (`ClientRequestUserAgent`).
    #[serde(rename = "ClientRequestUserAgent", default)]
    pub user_agent: Option<String>,
    /// Referer (`ClientRequestReferer`).
    #[serde(rename = "ClientRequestReferer", default)]
    pub referer: Option<String>,
    /// Response status (`EdgeResponseStatus`).
    #[serde(rename = "EdgeResponseStatus", default)]
    pub status: Option<u16>,
    /// Request start, nanoseconds since epoch (`EdgeStartTimestamp`).
    #[serde(rename = "EdgeStartTimestamp", default)]
    pub edge_start_ts: Option<i64>,
    /// Request id, unique per request (`RayID`).
    #[serde(rename = "RayID", default)]
    pub ray_id: Option<String>,
    /// Client ASN (`ClientASN`).
    #[serde(rename = "ClientASN", default)]
    pub client_asn: Option<u64>,
    /// Client country (`ClientCountry`).
    #[serde(rename = "ClientCountry", default)]
    pub country: Option<String>,
    /// Response bytes (`EdgeResponseBytes`).
    #[serde(rename = "EdgeResponseBytes", default)]
    pub bytes_out: Option<u64>,
}

/// Parse one NDJSON line; `None` on malformed JSON.
pub fn parse_line(line: &str) -> Option<CfLogLine> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    serde_json::from_str(line).ok()
}

impl CfLogLine {
    /// Wall-clock request time from the nanosecond epoch field.
    pub fn timestamp(&self) -> Option<DateTime<Utc>> {
        let ns = self.edge_start_ts?;
        let secs = ns.div_euclid(1_000_000_000);
        let sub = ns.rem_euclid(1_000_000_000) as u32;
        DateTime::from_timestamp(secs, sub)
    }

    /// Promote the record into a [`RawEvent`]; `None` when the client IP is
    /// missing or unparseable.
    pub fn into_raw_event(self) -> Option<(IpAddr, RawEvent)> {
        let ip: IpAddr = self.client_ip.as_deref()?.parse().ok()?;
        let ts = self.timestamp().unwrap_or_else(Utc::now);
        let http = HttpData {
            method: self.method.as_deref().map(HttpMethod::from_str_lossy),
            scheme: None,
            host: None,
            path: self.path.unwrap_or_else(|| "/".to_string()),
            query: self.query.filter(|q| !q.is_empty()),
            fragment: None,
            status: self.status,
            user_agent: self.user_agent.filter(|ua| !ua.is_empty()),
            referer: self.referer.filter(|r| !r.is_empty()),
            headers: Default::default(),
            body: None,
            cookies: None,
        };
        let evt = RawEvent {
            source: SourceKind::CloudflareLogs,
            timestamp: ts,
            transport: Transport::Tcp,
            client_ip: Some(ip),
            client_port: None,
            server_port: None,
            bytes_in: None,
            bytes_out: self.bytes_out,
            duration_ms: None,
            raw: self.ray_id,
            protocol: sentry_core::ProtocolData::Http(http),
        };
        Some((ip, evt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"ClientIP":"203.0.113.7","ClientRequestMethod":"GET","ClientRequestPath":"/wp-login.php","ClientRequestQuery":"redirect=%2f","ClientRequestUserAgent":"masscan/1.0","EdgeResponseStatus":403,"EdgeStartTimestamp":1727670000123456789,"RayID":"8c1f2a3b4c5d6e7f","ClientASN":64512,"ClientCountry":"BR","EdgeResponseBytes":512}"#;

    #[test]
    fn parses_sample_line() {
        let line = parse_line(SAMPLE).expect("valid line");
        assert_eq!(line.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(line.path.as_deref(), Some("/wp-login.php"));
        assert_eq!(line.status, Some(403));
        assert_eq!(line.ray_id.as_deref(), Some("8c1f2a3b4c5d6e7f"));
        assert_eq!(line.client_asn, Some(64512));
    }

    #[test]
    fn nanosecond_timestamp_converts() {
        let line = parse_line(SAMPLE).unwrap();
        let ts = line.timestamp().expect("timestamp");
        assert_eq!(ts.timestamp(), 1_727_670_000);
        assert_eq!(ts.timestamp_subsec_nanos(), 123_456_789);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        assert!(parse_line("not json").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("{\"ClientIP\":\"203.0.113.7\",}").is_none());
    }

    #[test]
    fn missing_ip_yields_no_event() {
        let line = parse_line(r#"{"ClientRequestPath":"/x"}"#).unwrap();
        assert!(line.into_raw_event().is_none());
    }

    #[test]
    fn raw_event_maps_http_fields() {
        let line = parse_line(SAMPLE).unwrap();
        let (ip, evt) = line.into_raw_event().expect("event");
        assert_eq!(ip.to_string(), "203.0.113.7");
        assert_eq!(evt.source, SourceKind::CloudflareLogs);
        let sentry_core::ProtocolData::Http(http) = evt.protocol else {
            panic!("expected http protocol");
        };
        assert_eq!(http.path, "/wp-login.php");
        assert_eq!(http.query.as_deref(), Some("redirect=%2f"));
        assert_eq!(http.status, Some(403));
        assert_eq!(http.user_agent.as_deref(), Some("masscan/1.0"));
        assert!(matches!(http.method, Some(HttpMethod::Get)));
        assert_eq!(evt.raw.as_deref(), Some("8c1f2a3b4c5d6e7f"));
    }

    #[test]
    fn empty_optionals_are_normalized() {
        let line = parse_line(
            r#"{"ClientIP":"198.51.100.2","ClientRequestPath":"/","ClientRequestQuery":"","ClientRequestUserAgent":""}"#,
        )
        .unwrap();
        let (_, evt) = line.into_raw_event().unwrap();
        let sentry_core::ProtocolData::Http(http) = evt.protocol else {
            panic!("expected http protocol");
        };
        assert_eq!(http.query, None);
        assert_eq!(http.user_agent, None);
    }
}
