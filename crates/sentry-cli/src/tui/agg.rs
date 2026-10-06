//! Pure helpers shared by the tail views: level filters, text search,
//! signal summaries, window aggregation and sparkline bucketing.

use std::collections::HashMap;

use chrono::Utc;
use sentry_core::event::ProtocolData;
use sentry_storage::EventRow;

/// Risk levels, lowest first (matches the `RiskLevel` serde names).
pub const LEVELS: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// Rank of a risk level (higher = worse); unknown levels rank as `info`.
pub fn level_rank(level: &str) -> i32 {
    LEVELS
        .iter()
        .position(|l| *l == level)
        .map(|p| p as i32)
        .unwrap_or(0)
}

/// Parse a `--only High,Critical` spec into normalized level names.
/// Unknown or empty parts are dropped.
pub fn parse_only(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| LEVELS.contains(&s.as_str()))
        .collect()
}

/// Short label for a persisted signal kind (`SignalKind` snake_case name).
pub fn signal_label(kind: &str) -> &str {
    match kind {
        "sql_injection" => "SQLi",
        "xss" => "XSS",
        "path_traversal" => "Traversal",
        "lfi" => "LFI",
        "log4shell" => "Log4Shell",
        "rce" => "RCE",
        "unknown_route" => "UnknownRoute",
        "method_not_allowed" => "MethodNA",
        "scan_behavior" => "ScanBehavior",
        "random_scan" => "RandomScan",
        "auth_brute_force" => "AuthBrute",
        "suspicious_login_success" => "SuspLogin",
        "credential_stuffing" => "CredStuff",
        "directory_brute_force" => "DirBrute",
        "abnormal_rate" => "Rate",
        "suspicious_ua" => "SuspUA",
        "tor_exit_node" => "Tor",
        "known_bad_ip" => "BadIp",
        "sensitive_path" => "Sensitive",
        "vpn_proxy" => "VPN",
        "promiscuous_scanner" => "Promisc",
        "bad_crawler" => "BadBot",
        "anomalous_payload" => "AI",
        "tcp_scanner" => "TcpScan",
        "scan_attack_correlation" => "Corr",
        "llm_malicious" => "LLM",
        "external_reputation" => "ExtRep",
        "spoofed_bot" => "SpoofBot",
        "tls_sni_mismatch" => "SniMismatch",
        "protocol_violation" => "ProtoViol",
        "upload_type_mismatch" => "UpType",
        "upload_polyglot" => "UpPoly",
        "upload_executable" => "UpExec",
        "upload_flood" => "UpFlood",
        other => match other.split_once('_') {
            Some((first, _)) => first,
            None => other,
        },
    }
}

/// One persisted signal as `(kind, weight, detail)`.
pub fn signals_of(row: &EventRow) -> Vec<(String, i64, String)> {
    row.signals
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let kind = s.get("kind")?.as_str()?.to_string();
                    let weight = s.get("weight").and_then(|w| w.as_i64()).unwrap_or(0);
                    let detail = s
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or_default()
                        .to_string();
                    Some((kind, weight, detail))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Compact signal summary for a stream row, e.g. `SQLi+Sensitive`.
pub fn signal_summary(row: &EventRow) -> String {
    let mut labels: Vec<String> = Vec::new();
    for (kind, _, _) in signals_of(row) {
        let label = signal_label(&kind).to_string();
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels.truncate(3);
    labels.join("+")
}

/// Protocol-derived display fields for one event row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpParts {
    /// HTTP method (`GET`), or `None` for non-HTTP protocols.
    pub method: Option<String>,
    /// Path (HTTP) or protocol label (`tcp/443`, `tls example.com`, …).
    pub path: String,
    /// HTTP status code, when the response was observed.
    pub status: Option<u16>,
    /// Whether the row is HTTP traffic (non-HTTP rows are excluded from
    /// path aggregation).
    pub is_http: bool,
}

/// Extract the display fields from the `protocol` JSONB column.
pub fn http_parts(row: &EventRow) -> HttpParts {
    match serde_json::from_value::<ProtocolData>(row.protocol.clone()) {
        Ok(ProtocolData::Http(h)) => HttpParts {
            method: h.method.map(|m| m.as_str().to_string()),
            path: h.path,
            status: h.status,
            is_http: true,
        },
        Ok(ProtocolData::Tcp(_)) => HttpParts {
            method: None,
            path: format!("({})", port_label(row.server_port, "tcp")),
            status: None,
            is_http: false,
        },
        Ok(ProtocolData::Udp(d)) => {
            let path = match &d.dns_query {
                Some(q) => format!("(udp/dns {q})"),
                None => format!("({})", port_label(row.server_port, "udp")),
            };
            HttpParts {
                method: None,
                path,
                status: None,
                is_http: false,
            }
        }
        Ok(ProtocolData::TlsHandshake(d)) => HttpParts {
            method: None,
            path: match &d.sni {
                Some(sni) => format!("(tls {sni})"),
                None => "(tls)".to_string(),
            },
            status: None,
            is_http: false,
        },
        Ok(ProtocolData::Syslog(d)) => HttpParts {
            method: None,
            path: match &d.app_name {
                Some(app) => format!("(syslog {app})"),
                None => "(syslog)".to_string(),
            },
            status: None,
            is_http: false,
        },
        _ => HttpParts {
            method: None,
            path: "(non-http)".to_string(),
            status: None,
            is_http: false,
        },
    }
}

fn port_label(port: Option<i32>, proto: &str) -> String {
    port.and_then(|p| u16::try_from(p).ok())
        .map(|p| format!("{proto}/{p}"))
        .unwrap_or_else(|| proto.to_string())
}

/// Active stream filters: level set + free-text substring.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filters {
    /// Normalized level names; empty means all levels.
    pub only: Vec<String>,
    /// Case-insensitive substring matched against level, IP, path, signals,
    /// source, verdict, ASN and country.
    pub text: Option<String>,
}

impl Filters {
    /// Whether a row passes both filters.
    pub fn matches(&self, row: &EventRow) -> bool {
        if !self.only.is_empty() && !self.only.iter().any(|l| l == &row.risk_level) {
            return false;
        }
        if let Some(t) = &self.text {
            if !haystack(row)
                .to_ascii_lowercase()
                .contains(&t.to_ascii_lowercase())
            {
                return false;
            }
        }
        true
    }
}

fn haystack(row: &EventRow) -> String {
    let parts = http_parts(row);
    let signals: Vec<String> = signals_of(row)
        .iter()
        .flat_map(|(k, _, d)| {
            let mut parts = vec![signal_label(k).to_string(), k.clone()];
            if !d.is_empty() {
                parts.push(d.clone());
            }
            parts
        })
        .collect();
    format!(
        "{} {} {} {} {} {} {} {}",
        row.risk_level,
        row.client_ip,
        row.source,
        row.verdict,
        parts.path,
        row.asn.map(|a| a.to_string()).unwrap_or_default(),
        row.country.as_deref().unwrap_or_default(),
        signals.join(" "),
    )
}

/// Count of rows per risk level, ordered as [`LEVELS`].
pub fn level_counts(rows: &[&EventRow]) -> [usize; 5] {
    let mut counts = [0usize; 5];
    for row in rows {
        counts[level_rank(&row.risk_level) as usize] += 1;
    }
    counts
}

/// Event counts bucketed by time for the sparkline, oldest bucket first.
/// `now_ms` is the wall clock in milliseconds; `bucket_ms` the bucket span.
pub fn sparkline(rows: &[&EventRow], now_ms: i64, bucket_ms: i64, buckets: usize) -> Vec<u64> {
    let mut data = vec![0u64; buckets];
    for row in rows {
        let ts = row.timestamp.timestamp_millis();
        let age = now_ms - ts;
        if age < 0 {
            continue;
        }
        let idx = buckets - 1 - (age / bucket_ms).min(buckets as i64 - 1) as usize;
        data[idx] += 1;
    }
    data
}

/// Approximate requests per second over the last 5 seconds.
pub fn req_per_sec(rows: &[&EventRow], now_ms: i64) -> u64 {
    let cutoff = now_ms - 5_000;
    rows.iter()
        .filter(|r| r.timestamp.timestamp_millis() > cutoff)
        .count() as u64
        / 5
}

/// Aggregated count for one suspicious IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAgg {
    /// Client IP (text form).
    pub ip: String,
    /// Events in the window.
    pub count: usize,
    /// Worst risk level seen for the IP.
    pub worst_level: String,
}

/// Top-N IPs by event count in the window.
pub fn top_ips(rows: &[&EventRow], n: usize) -> Vec<IpAgg> {
    let mut map: HashMap<String, (usize, i32)> = HashMap::new();
    for row in rows {
        let rank = level_rank(&row.risk_level);
        let entry = map.entry(row.client_ip.clone()).or_insert((0, rank));
        entry.0 += 1;
        entry.1 = entry.1.max(rank);
    }
    let mut agg: Vec<IpAgg> = map
        .into_iter()
        .map(|(ip, (count, rank))| IpAgg {
            ip,
            count,
            worst_level: LEVELS[rank.clamp(0, LEVELS.len() as i32 - 1) as usize].to_string(),
        })
        .collect();
    agg.sort_by(|a, b| b.count.cmp(&a.count).then(a.ip.cmp(&b.ip)));
    agg.truncate(n);
    agg
}

/// Top-N attacked paths (HTTP rows only) by event count.
pub fn top_paths(rows: &[&EventRow], n: usize) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for row in rows {
        let parts = http_parts(row);
        if parts.is_http {
            *map.entry(parts.path).or_default() += 1;
        }
    }
    let mut paths: Vec<(String, usize)> = map.into_iter().collect();
    paths.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    paths.truncate(n);
    paths
}

/// ASN/Geo breakdown of the window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsnGeo {
    /// Top ASNs as `(asn, count)`, most frequent first.
    pub asns: Vec<(i64, usize)>,
    /// Rows flagged as Tor exits (signal `tor_exit_node`).
    pub tor: usize,
    /// Total rows in the window (denominator for percentages).
    pub total: usize,
}

impl AsnGeo {
    /// Percentage of the window belonging to ASN `asn`, 0-100 truncated.
    pub fn asn_pct(&self, asn: i64) -> u64 {
        pct(
            self.asns.iter().find(|a| a.0 == asn).map_or(0, |a| a.1),
            self.total,
        )
    }

    /// Percentage of the window flagged as Tor, 0-100 truncated.
    pub fn tor_pct(&self) -> u64 {
        pct(self.tor, self.total)
    }
}

fn pct(part: usize, total: usize) -> u64 {
    if total == 0 {
        0
    } else {
        part as u64 * 100 / total as u64
    }
}

/// Compute the ASN/Geo breakdown, keeping the top `n` ASNs.
pub fn asn_geo(rows: &[&EventRow], n: usize) -> AsnGeo {
    let mut map: HashMap<i64, usize> = HashMap::new();
    let mut tor = 0usize;
    for row in rows {
        if let Some(asn) = row.asn {
            *map.entry(asn).or_default() += 1;
        }
        if signals_of(row).iter().any(|(k, _, _)| k == "tor_exit_node") {
            tor += 1;
        }
    }
    let mut asns: Vec<(i64, usize)> = map.into_iter().collect();
    asns.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    asns.truncate(n);
    AsnGeo {
        asns,
        tor,
        total: rows.len(),
    }
}

/// Current wall clock in milliseconds (bucketing reference).
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// Truncate to `n` chars with an ellipsis.
pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, TimeZone, Utc};

    fn row(level: &str, ip: &str, ts: DateTime<Utc>) -> EventRow {
        EventRow {
            id: Default::default(),
            timestamp: ts,
            source: "nginx".to_string(),
            client_ip: ip.to_string(),
            client_port: None,
            server_port: None,
            asn: None,
            country: None,
            protocol: serde_json::json!({"kind": "http", "method": "GET", "path": "/", "headers": {}}),
            risk_score: 0,
            risk_level: level.to_string(),
            verdict: "allow".to_string(),
            signals: serde_json::json!([]),
            raw: None,
            duration_ms: None,
            process_us: None,
        }
    }

    fn t(mins: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).unwrap() + Duration::minutes(mins)
    }

    #[test]
    fn parse_only_normalizes_and_drops_unknown() {
        assert_eq!(
            parse_only("High, CRITICAL,, bogus, low"),
            vec!["high", "critical", "low"]
        );
        assert!(parse_only("").is_empty());
    }

    #[test]
    fn filters_by_level_and_text() {
        let mut hi = row("high", "1.2.3.4", t(0));
        hi.protocol = serde_json::json!({"kind": "http", "path": "/api/login", "headers": {}});
        let low = row("low", "5.6.7.8", t(0));

        let f = Filters {
            only: vec!["high".to_string()],
            text: None,
        };
        assert!(f.matches(&hi));
        assert!(!f.matches(&low));

        let f = Filters {
            only: vec![],
            text: Some("login".to_string()),
        };
        assert!(f.matches(&hi));
        assert!(!f.matches(&low));

        let f = Filters {
            only: vec!["critical".to_string()],
            text: Some("/api/login".to_string()),
        };
        assert!(!f.matches(&hi));
    }

    #[test]
    fn text_filter_matches_signals_details_and_country() {
        let mut r = row("medium", "1.2.3.4", t(0));
        r.country = Some("BR".to_string());
        r.signals = serde_json::json!([
            {"kind": "sql_injection", "weight": 60, "detail": "' OR 1=1"}
        ]);

        for probe in ["BR", "sql_injection", "OR 1=1", "SQLi", "MEDIUM"] {
            let f = Filters {
                only: vec![],
                text: Some(probe.to_string()),
            };
            assert!(f.matches(&r), "should match {probe}");
        }
        let f = Filters {
            only: vec![],
            text: Some("wpa_supplicant".to_string()),
        };
        assert!(!f.matches(&r));
    }

    #[test]
    fn signal_summary_joins_unique_labels() {
        let mut r = row("high", "1.2.3.4", t(0));
        r.signals = serde_json::json!([
            {"kind": "sql_injection", "weight": 60},
            {"kind": "sensitive_path", "weight": 20},
            {"kind": "sensitive_path", "weight": 20},
            {"kind": "scan_behavior", "weight": 35}
        ]);
        assert_eq!(signal_summary(&r), "SQLi+Sensitive+ScanBehavior");
    }

    #[test]
    fn http_parts_covers_protocols() {
        let mut r = row("low", "1.2.3.4", t(0));
        r.protocol = serde_json::json!(
            {"kind": "http", "method": "POST", "path": "/a", "status": 403, "headers": {}}
        );
        let parts = http_parts(&r);
        assert_eq!(parts.method.as_deref(), Some("POST"));
        assert_eq!(parts.path, "/a");
        assert_eq!(parts.status, Some(403));
        assert!(parts.is_http);

        r.protocol =
            serde_json::to_value(ProtocolData::Tcp(sentry_core::event::TcpData::default()))
                .unwrap();
        r.server_port = Some(443);
        let parts = http_parts(&r);
        assert_eq!(parts.path, "(tcp/443)");
        assert!(!parts.is_http);

        r.protocol = serde_json::json!({"kind": "tlshandshake", "sni": "example.com"});
        assert_eq!(http_parts(&r).path, "(tls example.com)");
    }

    #[test]
    fn top_ips_orders_by_count_with_worst_level() {
        let a = row("low", "1.1.1.1", t(0));
        let b = row("critical", "2.2.2.2", t(0));
        let b2 = row("high", "2.2.2.2", t(1));

        let rows = vec![&a, &b, &b2];
        let tops = top_ips(&rows, 5);
        assert_eq!(tops.len(), 2);
        assert_eq!(tops[0].ip, "2.2.2.2");
        assert_eq!(tops[0].count, 2);
        assert_eq!(tops[0].worst_level, "critical");
        assert_eq!(tops[1].ip, "1.1.1.1");
    }

    #[test]
    fn top_paths_only_counts_http_rows() {
        let http = row("low", "1.1.1.1", t(0));
        let mut tcp = row("low", "1.1.1.1", t(0));
        tcp.protocol =
            serde_json::to_value(ProtocolData::Tcp(sentry_core::event::TcpData::default()))
                .unwrap();

        let rows = vec![&http, &http, &tcp];
        assert_eq!(top_paths(&rows, 10), vec![("/".to_string(), 2)]);
    }

    #[test]
    fn asn_geo_breakdown_and_percentages() {
        let mut a = row("low", "1.1.1.1", t(0));
        a.asn = Some(64512);
        let mut b = row("low", "2.2.2.2", t(0));
        b.asn = Some(64512);
        let mut c = row("low", "3.3.3.3", t(0));
        c.asn = Some(64513);
        c.signals = serde_json::json!([{"kind": "tor_exit_node", "weight": 15}]);

        let rows = vec![&a, &b, &c];
        let geo = asn_geo(&rows, 2);
        assert_eq!(geo.asns, vec![(64512, 2), (64513, 1)]);
        assert_eq!(geo.tor, 1);
        assert_eq!(geo.total, 3);
        assert_eq!(geo.asn_pct(64512), 66);
        assert_eq!(geo.tor_pct(), 33);
    }

    #[test]
    fn sparkline_buckets_and_req_per_sec() {
        let now = t(10).timestamp_millis();
        let recent = row("low", "1.1.1.1", Utc.timestamp_millis_opt(now).unwrap());
        let older = row(
            "low",
            "1.1.1.1",
            Utc.timestamp_millis_opt(now - 30_000).unwrap(),
        );
        let rows = vec![&recent, &older];

        let data = sparkline(&rows, now, 5_000, 10);
        assert_eq!(data.len(), 10);
        assert_eq!(data[9], 1);
        assert_eq!(data[3], 1);
        assert!(data[..3].iter().all(|d| *d == 0));

        assert_eq!(req_per_sec(&rows, now), 0);
        let burst: Vec<EventRow> = (0..10)
            .map(|i| {
                row(
                    "low",
                    "1.1.1.1",
                    Utc.timestamp_millis_opt(now - i * 100).unwrap(),
                )
            })
            .collect();
        let refs: Vec<&EventRow> = burst.iter().chain(rows.iter().copied()).collect();
        assert_eq!(req_per_sec(&refs, now), 2);
    }

    #[test]
    fn level_counts_and_rank() {
        let rows = [
            row("info", "1.1.1.1", t(0)),
            row("critical", "2.2.2.2", t(0)),
            row("critical", "3.3.3.3", t(0)),
        ];
        let refs: Vec<&EventRow> = rows.iter().collect();
        assert_eq!(level_counts(&refs), [1, 0, 0, 0, 2]);
        assert_eq!(level_rank("critical"), 4);
        assert_eq!(level_rank("weird"), 0);
    }
}
