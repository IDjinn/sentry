//! Nginx access log format string parser.
//!
//! Supports the standard `$var` tokens nginx emits in `log_format`. We don't
//! implement a full nginx log parser — we convert the format string into a
//! regex at construction time and match each line against it.
//!
//! Client IP resolution is automatic and precedence-based: header-borne real
//! IPs (`$http_cf_connecting_ip` > `$http_true_client_ip` >
//! `$http_x_real_ip`) win over forwarded chains (`$http_x_forwarded_for` /
//! `$proxy_add_x_forwarded_for`, first entry) which win over `$remote_addr`
//! (`$remote_addr_v6`). Behind a CDN such as Cloudflare, `remote_addr` is the
//! edge address — include the CDN's client-IP header in the `log_format` and
//! the real client is resolved with no extra configuration. Every captured
//! `http_*` token is also exposed as a request header on the event.

use std::collections::HashMap;
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
    /// Trusted proxies (F7.2): when set, header-borne client IPs only win
    /// over `$remote_addr` if the remote address is itself a trusted proxy
    /// (Cloudflare ranges + `[real_ip] trusted_proxies`). `None` keeps the
    /// legacy unconditional precedence (log writer is the edge).
    trust: Option<sentry_core::SharedTrustSet>,
}

impl LogFormat {
    /// Build a `LogFormat` from an nginx `log_format` string.
    ///
    /// Each `$var` (or `${var}`) becomes a named capture; everything else
    /// is escaped literally. The resulting regex matches a single line.
    pub fn compile(format: &str) -> Result<Self, String> {
        Self::compile_inner(format, None)
    }

    /// Like [`Self::compile`], but honoring a trusted-proxy set: header
    /// candidates (`CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, XFF)
    /// are only trusted when `$remote_addr` is in the set.
    pub fn compile_with_trust(
        format: &str,
        trust: sentry_core::SharedTrustSet,
    ) -> Result<Self, String> {
        Self::compile_inner(format, Some(trust))
    }

    fn compile_inner(
        format: &str,
        trust: Option<sentry_core::SharedTrustSet>,
    ) -> Result<Self, String> {
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
        Ok(Self { re, fields, trust })
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

        // Real client IP resolution. Behind a reverse proxy/CDN (Cloudflare,
        // etc.) `$remote_addr` is the proxy's edge address, so header-borne
        // candidates take precedence when they parse. `-` (nginx's empty
        // marker) never parses, so absent headers fall through cleanly.
        let mut cf_ip: Option<IpAddr> = None;
        let mut true_client_ip: Option<IpAddr> = None;
        let mut x_real_ip: Option<IpAddr> = None;
        let mut forwarded_ip: Option<IpAddr> = None;
        let mut remote_ip: Option<IpAddr> = None;
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut method: Option<HttpMethod> = None;
        let mut path = String::new();
        let mut query: Option<String> = None;
        let mut host: Option<String> = None;
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
                "remote_addr" | "remote_addr_v6" => remote_ip = val.parse().ok(),
                "proxy_add_x_forwarded_for" | "http_x_forwarded_for" => {
                    // XFF can be a list; take the first (clientmost) IP.
                    let first = val.split(',').next().unwrap_or("").trim();
                    forwarded_ip = first.parse().ok();
                }
                "http_cf_connecting_ip" => cf_ip = val.parse().ok(),
                "http_true_client_ip" => true_client_ip = val.parse().ok(),
                "http_x_real_ip" => x_real_ip = val.parse().ok(),
                "http_host" | "host" => {
                    if val != "-" {
                        host = Some(val.to_string());
                    }
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
            // Every `http_*` token is a request header: expose it as such
            // (nginx maps `-` to hyphens, e.g. `http_cf_connecting_ip` →
            // `cf-connecting-ip`) so DSL `header.X` rules match log input.
            if val != "-" {
                if let Some(header) = name.strip_prefix("http_") {
                    headers.insert(header.replace('_', "-").to_lowercase(), val.to_string());
                }
            }
        }

        // Real client IP resolution (ARCHITECTURE §8.1). Without a trust
        // set, header-borne candidates always win (legacy behavior: the log
        // writer is the edge). With one (`[real_ip]`), they only win when
        // `$remote_addr` is a trusted proxy — a direct-to-origin client
        // cannot spoof a forged `CF-Connecting-IP`. `-` (nginx's empty
        // marker) never parses, so absent headers fall through cleanly.
        let header_ip = cf_ip.or(true_client_ip).or(x_real_ip).or(forwarded_ip);
        let client_ip = match (&self.trust, remote_ip) {
            (_, None) | (None, _) => header_ip.or(remote_ip),
            (Some(trust), Some(peer)) => {
                if trust.is_trusted_proxy(peer) {
                    header_ip.or(Some(peer))
                } else {
                    Some(peer)
                }
            }
        };

        let protocol = ProtocolData::Http(HttpData {
            method,
            scheme: None,
            host,
            path,
            query,
            fragment: None,
            status,
            user_agent,
            referer,
            headers,
            body: None,
            cookies: None,
        });

        Ok(RawEvent {
            source: SourceKind::Nginx,
            timestamp,
            transport: sentry_core::event::Transport::Tcp,
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
        "remote_addr" | "remote_addr_v6" => r"[0-9a-fA-F:.]+".to_string(),
        // XFF carries a comma-separated chain: "client, proxy1, proxy2".
        // `-` (nginx's empty marker) must also match: a direct (non-proxied)
        // request logs `"$http_x_forwarded_for" "-"` and would otherwise be
        // rejected wholesale instead of falling back to remote_addr.
        "proxy_add_x_forwarded_for" | "http_x_forwarded_for" => {
            r"(?:[0-9a-fA-F:., ]+|-)".to_string()
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

    #[test]
    fn cf_connecting_ip_overrides_edge_ip() {
        let fmt = LogFormat::compile(
            r#"$remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_user_agent" "$http_cf_connecting_ip""#,
        )
        .unwrap();
        let line = r#"104.16.1.2 - - [10/Jan/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 512 "curl/8.0" "2001:db8:abcd:12::42""#;
        let evt = fmt.parse_line(line).expect("line matches");
        let expected: IpAddr = "2001:db8:abcd:12::42".parse().unwrap();
        assert_eq!(evt.client_ip, Some(expected));
        let http = match evt.protocol {
            ProtocolData::Http(ref h) => h,
            _ => panic!("expected http"),
        };
        assert_eq!(
            http.headers.get("cf-connecting-ip").map(String::as_str),
            Some("2001:db8:abcd:12::42")
        );
        assert_eq!(
            http.headers.get("user-agent").map(String::as_str),
            Some("curl/8.0")
        );
    }

    #[test]
    fn real_ip_header_absent_falls_back_to_remote_addr() {
        let fmt = LogFormat::compile(
            r#"$remote_addr "$request" $status "$http_user_agent" "$http_cf_connecting_ip""#,
        )
        .unwrap();
        let line = r#"203.0.113.10 "GET / HTTP/1.1" 200 "Mozilla/5.0" "-""#;
        let evt = fmt.parse_line(line).expect("line matches");
        assert_eq!(
            evt.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
        let http = match evt.protocol {
            ProtocolData::Http(ref h) => h,
            _ => panic!("expected http"),
        };
        assert!(!http.headers.contains_key("cf-connecting-ip"));
    }

    #[test]
    fn x_real_ip_used_when_cf_header_missing() {
        let fmt = LogFormat::compile(r#"$remote_addr "$request" $status $http_x_real_ip"#).unwrap();
        let line = r#"104.16.1.2 "GET / HTTP/1.1" 200 198.51.100.7"#;
        let evt = fmt.parse_line(line).expect("line matches");
        assert_eq!(
            evt.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
    }

    #[test]
    fn xff_chain_takes_first_ip() {
        let fmt = LogFormat::compile(r#"$remote_addr "$request" $status "$http_x_forwarded_for""#)
            .unwrap();
        let line = r#"10.0.0.9 "GET / HTTP/1.1" 200 "198.51.100.7, 10.0.0.1, 10.0.0.2""#;
        let evt = fmt.parse_line(line).expect("line matches");
        assert_eq!(
            evt.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
    }

    #[test]
    fn empty_xff_marker_parses_and_falls_back_to_remote_addr() {
        let fmt = LogFormat::compile(
            r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for""#,
        )
        .unwrap();

        // Direct (non-proxied) request: nginx logs XFF as `-`, which must not
        // reject the whole line.
        let line = r#"177.171.45.43 - - [01/Oct/2026:03:28:03 +0000] "GET /admin HTTP/1.1" 200 2166 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0" "-""#;
        let evt = fmt.parse_line(line).expect("empty XFF marker must match");
        assert_eq!(
            evt.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(177, 171, 45, 43)))
        );
        let http = match evt.protocol {
            ProtocolData::Http(ref h) => h,
            _ => panic!("expected http"),
        };
        assert_eq!(http.method, Some(HttpMethod::Get));
        assert_eq!(http.path, "/admin");
        assert_eq!(http.status, Some(200));
    }

    #[test]
    fn cf_header_wins_over_xff_and_x_real_ip() {
        let fmt = LogFormat::compile(
            r#"$remote_addr "$request" $status $http_x_real_ip "$http_x_forwarded_for" "$http_cf_connecting_ip""#,
        )
        .unwrap();
        let line = r#"104.16.1.2 "GET / HTTP/1.1" 200 198.51.100.7 "198.51.100.99, 10.0.0.1" "192.0.2.33""#;
        let evt = fmt.parse_line(line).expect("line matches");
        assert_eq!(
            evt.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33)))
        );
    }

    /// F7.2: with a trust set, header-borne IPs are honored only from
    /// trusted-proxy peers; a direct client cannot spoof them. The
    /// structured `host` field is populated from `$http_host`.
    #[test]
    fn trusted_proxy_gate_and_host_capture() {
        let trust = sentry_core::SharedTrustSet::new(
            sentry_core::TrustSet::from_config(&sentry_core::config::RealIpConfig {
                cloudflare: true,
                ..Default::default()
            })
            .unwrap(),
        );
        let fmt = LogFormat::compile_with_trust(
            r#"$remote_addr "$request" $status "$http_cf_connecting_ip" "$http_host""#,
            trust,
        )
        .unwrap();

        // Behind Cloudflare: the CF edge is a trusted proxy → header wins.
        let via_cf = r#"108.162.192.5 "GET / HTTP/1.1" 200 "198.51.100.7" "example.com""#;
        let evt = fmt.parse_line(via_cf).expect("cf line matches");
        assert_eq!(
            evt.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );

        // Direct-to-origin: the forged header is ignored, remote wins.
        let direct = r#"198.51.100.9 "GET / HTTP/1.1" 200 "6.6.6.6" "example.com""#;
        let evt = fmt.parse_line(direct).expect("direct line matches");
        assert_eq!(
            evt.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)))
        );

        // Host header lands in the structured field.
        match evt.protocol {
            ProtocolData::Http(ref h) => assert_eq!(h.host.as_deref(), Some("example.com")),
            _ => panic!("expected http"),
        }
    }
}
