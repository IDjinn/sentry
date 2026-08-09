//! Nginx access log format string parser.
//!
//! Supports the standard `$var` tokens nginx emits in `log_format`. We don't
//! implement a full nginx log parser — we convert the format string into a
//! regex at construction time and match each line against it.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use regex::Regex;
use sentry_core::event::{HttpData, HttpMethod, ProtocolData, RawEvent, SourceKind};

/// Parsed `log_format` spec: a sequence of literal segments and named tokens.
#[derive(Debug, Clone)]
pub struct LogFormat {
    /// Compiled regex matching one log line, with named captures.
    re: Regex,
    /// Ordered list of capture names (excluding the implicit full-match).
    fields: Vec<String>,
}

impl LogFormat {
    /// Build a `LogFormat` from an nginx `log_format` string.
    ///
    /// Each `$var` (or `${var}`) becomes a named capture; everything else
    /// is escaped literally. The resulting regex matches a single line.
    pub fn compile(format: &str) -> Result<Self, String> {
        let mut re = String::from("^");
        let mut fields = Vec::new();
        let bytes = format.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'$' {
                let braced = i + 1 < bytes.len() && bytes[i + 1] == b'{';
                i += if braced { 2 } else { 1 };
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = &format[start..i];
                if braced && i < bytes.len() && bytes[i] == b'}' {
                    i += 1;
                }
                let cap = make_capture(name);
                re.push_str(&format!("(?P<{name}>{cap})"));
                fields.push(name.to_string());
            } else {
                let ch = bytes[i] as char;
                re.push_str(&regex::escape(&ch.to_string()));
                i += 1;
            }
        }
        re.push('$');
        let re = Regex::new(&re).map_err(|e| format!("invalid compiled regex: {e}"))?;
        Ok(Self { re, fields })
    }

    /// Parse a single log line into a [`RawEvent`].
    ///
    /// Returns `Err` for lines that don't match the format; the source
    /// logs and skips those rather than failing the stream.
    pub fn parse_line(&self, line: &str) -> Result<RawEvent, ParseError> {
        let caps = self
            .re
            .captures(line)
            .ok_or_else(|| ParseError::NoMatch(line.to_string()))?;

        let mut client_ip: Option<IpAddr> = None;
        let mut method: Option<HttpMethod> = None;
        let mut path = String::new();
        let mut query: Option<String> = None;
        let mut status: Option<u16> = None;
        let mut user_agent: Option<String> = None;
        let mut referer: Option<String> = None;
        let mut bytes_out: Option<u64> = None;
        let mut duration_ms: Option<u64> = None;
        let mut timestamp = Utc::now();

        for name in &self.fields {
            let Some(val) = caps.name(name) else { continue };
            let val = val.as_str();
            match name.as_str() {
                "remote_addr" | "proxy_add_x_forwarded_for" | "http_x_forwarded_for" => {
                    // XFF can be a list; take the first (clientmost) IP.
                    let first = val.split(',').next().unwrap_or("").trim();
                    client_ip = first.parse().ok();
                }
                "request" => {
                    // "$request" = "METHOD PATH HTTP/1.1"
                    let parts: Vec<&str> = val.splitn(3, ' ').collect();
                    if parts.len() >= 2 {
                        method = Some(HttpMethod::from_str_lossy(parts[0]));
                        let full_path = parts[1];
                        if let Some((p, q)) = full_path.split_once('?') {
                            path = p.to_string();
                            query = Some(q.to_string());
                        } else {
                            path = full_path.to_string();
                        }
                    }
                }
                "request_method" | "m" => method = Some(HttpMethod::from_str_lossy(val)),
                "request_uri" | "uri" => {
                    if let Some((p, q)) = val.split_once('?') {
                        path = p.to_string();
                        query = Some(q.to_string());
                    } else {
                        path = val.to_string();
                    }
                }
                "status" => status = val.parse().ok(),
                "http_user_agent" => user_agent = Some(val.to_string()),
                "http_referer" => referer = Some(val.to_string()),
                "body_bytes_sent" | "bytes_sent" | "b" => bytes_out = val.parse().ok(),
                "request_time" => {
                    // nginx emits seconds as a float (e.g. "0.123").
                    duration_ms = val.parse::<f64>().ok().map(|f| (f * 1000.0) as u64);
                }
                "time_local" | "time_iso8601" | "t" => {
                    if let Ok(dt) = parse_nginx_time(val) {
                        timestamp = dt;
                    }
                }
                _ => {}
            }
        }

        let protocol = ProtocolData::Http(HttpData {
            method,
            scheme: None,
            host: None,
            path,
            query,
            fragment: None,
            status,
            user_agent,
            referer,
            headers: Default::default(),
            body: None,
            cookies: None,
        });

        Ok(RawEvent {
            source: SourceKind::Nginx,
            timestamp,
            client_ip,
            client_port: None,
            server_port: None,
            bytes_in: None,
            bytes_out,
            duration_ms,
            raw: Some(line.to_string()),
            protocol,
        })
    }
}

/// Parse nginx `time_local` (`10/Jan/2026:13:55:36 +0000`) and ISO 8601.
fn parse_nginx_time(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    // Try ISO 8601 first.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    // nginx default: `10/Jan/2026:13:55:36 +0000`
    DateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z").map(|dt| dt.with_timezone(&Utc))
}

/// Build a per-token capture group tuned to the variable name.
fn make_capture(name: &str) -> String {
    match name {
        // IPs: a sequence of hex digits, dots and colons.
        "remote_addr" | "proxy_add_x_forwarded_for" | "http_x_forwarded_for" | "remote_addr_v6" => {
            r"[0-9a-fA-F:.]+".to_string()
        }
        // Numeric tokens.
        "status" | "body_bytes_sent" | "bytes_sent" | "request_time" | "b" | "s" => {
            r"\d+(?:\.\d+)?".to_string()
        }
        // The request line: METHOD PATH PROTO (no spaces inside).
        "request" => r"\S+\s+\S+\s+\S+".to_string(),
        // Quoted strings: the format wraps UA/referer in double quotes, so the
        // capture is the inner content (anything but a quote).
        "http_user_agent" | "http_referer" => r#"[^"]*"#.to_string(),
        // Timestamps: anything but `]` (the format wraps time in `[...]`).
        "time_local" | "time_iso8601" | "t" => r"[^\]]+".to_string(),
        // Default: non-whitespace, or quoted for headers.
        _ => r"\S+".to_string(),
    }
}

/// Parse error.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Line didn't match the format string.
    #[error("line did not match format: {0}")]
    NoMatch(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_default_combined() {
        let fmt = LogFormat::compile(
            r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent""#,
        )
        .expect("format compiles");

        let line = r#"1.2.3.4 - - [10/Jan/2026:13:55:36 +0000] "GET /api/users?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        let evt = fmt.parse_line(line).expect("line matches");
        assert_eq!(evt.client_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        let http = match evt.protocol {
            ProtocolData::Http(ref h) => h,
            _ => panic!("expected http"),
        };
        assert_eq!(http.method, Some(HttpMethod::Get));
        assert_eq!(http.path, "/api/users");
        assert_eq!(http.query.as_deref(), Some("id=1"));
        assert_eq!(http.status, Some(200));
        assert_eq!(http.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(evt.bytes_out, Some(1234));
    }

    #[test]
    fn parse_request_time() {
        let fmt = LogFormat::compile(r#"$remote_addr "$request" $status $request_time"#).unwrap();
        let line = r#"5.6.7.8 "POST /login HTTP/1.1" 500 0.456"#;
        let evt = fmt.parse_line(line).unwrap();
        assert_eq!(evt.duration_ms, Some(456));
    }

    #[test]
    fn malformed_line_returns_error() {
        let fmt = LogFormat::compile(r#"$remote_addr "$request" $status"#).unwrap();
        let line = "garbage line";
        assert!(fmt.parse_line(line).is_err());
    }
}
