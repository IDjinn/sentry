//! SIEM export formats (F4.6): ArcSight CEF, LEEF and RFC5424 forwarding.
//!
//! Pure serializers over the stored [`EventRow`] shape so the same code
//! drives `sentry export siem` (batch) and `--follow` (syslog forward).

use chrono::{DateTime, Utc};
use sentry_storage::repo::EventRow;

/// Numeric severity per CEF spec (0–10).
pub fn cef_severity(risk_level: &str) -> u8 {
    match risk_level.to_ascii_lowercase().as_str() {
        "critical" => 10,
        "high" => 8,
        "medium" => 6,
        "low" => 3,
        _ => 2,
    }
}

/// RFC5424 severity for a risk level (local0 facility).
pub fn syslog_pri(risk_level: &str) -> u8 {
    let severity = match risk_level.to_ascii_lowercase().as_str() {
        "critical" => 2,
        "high" => 3,
        "medium" => 4,
        "low" => 5,
        _ => 6,
    };
    8 * 16 + severity
}

/// Escape a CEF extension value (`=` and newlines).
fn cef_ext_escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "")
}

/// Escape a CEF header field (`|` and `\`).
fn cef_header_escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('|', "\\|")
}

/// HTTP path/method/UA pulled out of the protocol JSON blob.
fn http_fields(protocol: &serde_json::Value) -> (String, String, String) {
    (
        protocol
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string(),
        protocol
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string(),
        protocol
            .get("user_agent")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string(),
    )
}

/// ArcSight CEF line:
/// `CEF:0|Sentry|Sentry|1.0|{verdict}|{verdict} {level}|{sev}|k=v ...`
pub fn cef(row: &EventRow) -> String {
    let (path, method, ua) = http_fields(&row.protocol);
    let sev = cef_severity(&row.risk_level);
    format!(
        "CEF:0|Sentry|Sentry|1.0|{}|{} {}|{}|rt={} src={} spt={} dpt={} request={} requestMethod={} requestClientApplication={} cs1Label=Verdict cs1={} cs2Label=RiskLevel cs2={} cfSentryScore={} cs3Label=Signals cs3={}",
        cef_header_escape(&row.verdict),
        cef_header_escape(&row.verdict),
        cef_header_escape(&row.risk_level),
        sev,
        row.timestamp.timestamp_millis(),
        cef_ext_escape(&row.client_ip),
        row.client_port.unwrap_or(0),
        row.server_port.unwrap_or(0),
        cef_ext_escape(&path),
        cef_ext_escape(&method),
        cef_ext_escape(&ua),
        cef_ext_escape(&row.verdict),
        cef_ext_escape(&row.risk_level),
        row.risk_score,
        cef_ext_escape(&signals_label(&row.signals)),
    )
}

/// QRadar LEEF 2.0 line (tab-delimited extension).
pub fn leef(row: &EventRow) -> String {
    let (path, method, ua) = http_fields(&row.protocol);
    format!(
        "LEEF:2.0|Sentry|Sentry|1.0|{}\tLEEF:1.0|devTime={}\tsrc={}\tspt={}\tdpt={}\tpath={}\tmethod={}\tua={}\tverdict={}\triskLevel={}\tseverity={}\tscore={}\tsignals={}",
        row.verdict.replace(['\t', '\n'], " "),
        row.timestamp.to_rfc3339(),
        row.client_ip,
        row.client_port.unwrap_or(0),
        row.server_port.unwrap_or(0),
        path.replace(['\t', '\n'], " "),
        method.replace(['\t', '\n'], " "),
        ua.replace(['\t', '\n'], " "),
        row.verdict,
        row.risk_level,
        cef_severity(&row.risk_level),
        row.risk_score,
        signals_label(&row.signals).replace(['\t', '\n'], " "),
    )
}

/// Comma-joined signal kinds from the signals JSON.
fn signals_label(signals: &serde_json::Value) -> String {
    match signals.as_array() {
        Some(list) if !list.is_empty() => list
            .iter()
            .map(|s| {
                s.get("kind")
                    .and_then(|k| k.as_str())
                    .unwrap_or("unknown")
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(","),
        _ => "-".to_string(),
    }
}

/// Wrap a payload line in an RFC5424 frame (facility local0, Sentry app).
pub fn syslog_frame(row: &EventRow, payload: &str) -> String {
    let pri = syslog_pri(&row.risk_level);
    let ts: DateTime<Utc> = row.timestamp;
    format!(
        "<{pri}>1 {} sentry sentry - - {payload}",
        ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> EventRow {
        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2026-09-30T12:00:00Z",
            "source": "nginx",
            "client_ip": "203.0.113.7",
            "client_port": 54321,
            "server_port": 443,
            "asn": 64512,
            "country": "BR",
            "protocol": {
                "kind": "http",
                "path": "/login",
                "method": "GET",
                "query": "user=admin",
                "user_agent": "masscan/1.0"
            },
            "risk_score": 85,
            "risk_level": "high",
            "verdict": "block",
            "signals": [{"kind": "sqli"}, {"kind": "tcp_scanner"}],
            "raw": null
        }))
        .unwrap()
    }

    #[test]
    fn cef_line_shape() {
        let line = cef(&row());
        assert!(line.starts_with("CEF:0|Sentry|Sentry|1.0|block|block high|8|"));
        assert!(line.contains("src=203.0.113.7"));
        assert!(line.contains("spt=54321"));
        assert!(line.contains("request=/login"));
        assert!(line.contains("requestMethod=GET"));
        assert!(line.contains("cs1=block"));
        assert!(line.contains("cfSentryScore=85"));
        assert!(line.contains("cs3=sqli,tcp_scanner"));
    }

    #[test]
    fn cef_escapes_pipe_and_equals() {
        let mut r = row();
        r.verdict = "block|extra=1".into();
        let line = cef(&r);
        // Header fields escape `\` and `|` (not `=`):
        assert!(line.contains("1.0|block\\|extra=1|"), "{line}");
        // Extension values escape `\` and `=` (not `|`):
        assert!(line.contains("cs1=block|extra\\=1"), "{line}");
    }

    #[test]
    fn leef_line_shape() {
        let line = leef(&row());
        assert!(line.starts_with("LEEF:2.0|Sentry|Sentry|1.0|block\tLEEF:1.0|"));
        assert!(line.contains("src=203.0.113.7"));
        assert!(line.contains("path=/login"));
        assert!(line.contains("verdict=block"));
        assert!(line.contains("severity=8"));
    }

    #[test]
    fn severity_and_pri_mapping() {
        assert_eq!(cef_severity("critical"), 10);
        assert_eq!(cef_severity("info"), 2);
        assert_eq!(syslog_pri("critical"), 16 * 8 + 2);
        assert_eq!(syslog_pri("low"), 16 * 8 + 5);
        assert_eq!(syslog_pri("unknown"), 16 * 8 + 6);
    }

    #[test]
    fn syslog_frame_wraps_rfc5424() {
        let frame = syslog_frame(&row(), "CEF:0|...");
        assert!(frame.starts_with("<131>1 2026-09-30T12:00:00Z sentry sentry - - CEF:0|..."));
    }

    #[test]
    fn missing_http_fields_fall_back() {
        let mut r = row();
        r.protocol = serde_json::json!({"kind": "tcp"});
        let line = cef(&r);
        assert!(line.contains("request=-"));
        assert!(line.contains("requestMethod=-"));
    }
}
