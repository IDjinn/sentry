//! Non-interactive tail (`sentry tail --stream`): one line per event on
//! stdout, pipe-friendly. Auto-selected when stdout is not a TTY.

use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::time::Duration;

use sentry_core::config::SentryConfig;
use sentry_storage::{EventRow, Repo};
use serde::Serialize;

/// Events printed before following the live stream.
const INITIAL_ROWS: usize = 20;
/// Poll interval for new events.
const POLL: Duration = Duration::from_secs(1);

/// Options for the stream mode.
#[derive(Debug, Clone, Default)]
pub struct StreamOptions {
    /// Normalized risk-level filter (`--only`).
    pub only: Vec<String>,
    /// Emit one JSON object per event instead of colored text (`--json`).
    pub json: bool,
}

/// Follow the events table, printing one line per new event.
pub async fn run(cfg: Option<&SentryConfig>, opts: StreamOptions) -> color_eyre::Result<()> {
    let Some(cfg) = cfg else {
        color_eyre::eyre::bail!("--stream needs a config — pass --config or create sentry.toml");
    };
    if cfg.storage.postgres.url.is_empty() {
        color_eyre::eyre::bail!("--stream needs storage.postgres.url configured");
    }
    let pool = sentry_storage::PgPool::connect(&cfg.storage.postgres)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("postgres connect failed: {e}"))?;
    let repo = Repo::new(pool);

    let color = std::io::stdout().is_terminal();
    let mut cursor: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut cursor_ids: HashSet<String> = HashSet::new();
    let mut printed_initial = false;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    loop {
        match repo.events().recent(200).await {
            Ok(rows) => {
                if !printed_initial {
                    printed_initial = true;
                    if let Some(newest) = rows.first() {
                        cursor = Some(newest.timestamp);
                        cursor_ids = rows
                            .iter()
                            .take_while(|r| r.timestamp == newest.timestamp)
                            .map(|r| r.id.to_string())
                            .collect();
                    }
                    let backlog: Vec<&EventRow> = rows
                        .iter()
                        .take(INITIAL_ROWS)
                        .filter(|r| {
                            opts.only.is_empty() || opts.only.iter().any(|l| l == &r.risk_level)
                        })
                        .collect();
                    for row in backlog.into_iter().rev() {
                        write_row(&mut out, row, &opts, color)?;
                    }
                } else {
                    let newest = rows.first().map(|r| r.timestamp);
                    let mut fresh: Vec<&EventRow> = rows
                        .iter()
                        .filter(|r| is_new(r, cursor, &cursor_ids))
                        .filter(|r| {
                            opts.only.is_empty() || opts.only.iter().any(|l| l == &r.risk_level)
                        })
                        .collect();
                    fresh.reverse();
                    for row in fresh {
                        write_row(&mut out, row, &opts, color)?;
                    }
                    if let Some(newest) = newest {
                        cursor = Some(newest);
                        cursor_ids = rows
                            .iter()
                            .take_while(|r| r.timestamp == newest)
                            .map(|r| r.id.to_string())
                            .collect();
                    }
                }
                out.flush().ok();
            }
            Err(e) => tracing::warn!(error = %e, "stream fetch failed"),
        }
        tokio::time::sleep(POLL).await;
    }
}

fn is_new(
    row: &EventRow,
    cursor: Option<chrono::DateTime<chrono::Utc>>,
    cursor_ids: &HashSet<String>,
) -> bool {
    match cursor {
        None => false,
        Some(cursor) => {
            row.timestamp > cursor
                || (row.timestamp == cursor && !cursor_ids.contains(&row.id.to_string()))
        }
    }
}

fn write_row(
    out: &mut impl Write,
    row: &EventRow,
    opts: &StreamOptions,
    color: bool,
) -> color_eyre::Result<()> {
    if opts.json {
        writeln!(out, "{}", serde_json::to_string(&StreamJson::of(row))?)?;
    } else {
        writeln!(out, "{}", text_line(row, color))?;
    }
    Ok(())
}

/// One plain/ANSI-colored line per event.
fn text_line(row: &EventRow, color: bool) -> String {
    let parts = crate::tui::agg::http_parts(row);
    let summary = crate::tui::agg::signal_summary(row);
    let time = row.timestamp.format("%d/%m %H:%M:%S").to_string();
    let line = format!(
        "{} {:<8} {:>3} {:<15} {:<7} {:<7} {:<40} {:>3} {}",
        time,
        row.risk_level,
        row.risk_score,
        row.client_ip,
        row.source,
        parts.method.as_deref().unwrap_or("-"),
        crate::tui::agg::truncate(&parts.path, 40),
        parts
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string()),
        summary,
    );
    if !color {
        return line;
    }
    let ansi = match row.risk_level.as_str() {
        "critical" => "\x1b[1;31m",
        "high" => "\x1b[31m",
        "medium" => "\x1b[33m",
        "low" => "\x1b[34m",
        _ => "\x1b[36m",
    };
    format!("{ansi}{line}\x1b[0m")
}

/// JSON-per-event shape (stable key set for `tail --stream --json`).
#[derive(Debug, Serialize)]
struct StreamJson<'a> {
    timestamp: String,
    source: &'a str,
    ip: &'a str,
    server_port: Option<i32>,
    asn: Option<i64>,
    country: Option<&'a str>,
    level: &'a str,
    score: i16,
    verdict: &'a str,
    method: Option<String>,
    path: String,
    status: Option<u16>,
    signals: Vec<String>,
}

impl<'a> StreamJson<'a> {
    fn of(row: &'a EventRow) -> Self {
        let parts = crate::tui::agg::http_parts(row);
        Self {
            timestamp: row.timestamp.to_rfc3339(),
            source: &row.source,
            ip: &row.client_ip,
            server_port: row.server_port,
            asn: row.asn,
            country: row.country.as_deref(),
            level: &row.risk_level,
            score: row.risk_score,
            verdict: &row.verdict,
            method: parts.method,
            path: parts.path,
            status: parts.status,
            signals: crate::tui::agg::signals_of(row)
                .into_iter()
                .map(|(kind, _, _)| kind)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn row(level: &str) -> EventRow {
        EventRow {
            id: Default::default(),
            timestamp: Utc::now(),
            source: "nginx".to_string(),
            client_ip: "203.0.113.9".to_string(),
            client_port: None,
            server_port: Some(443),
            asn: Some(64512),
            country: Some("BR".to_string()),
            protocol: serde_json::json!(
                {"kind": "http", "method": "POST", "path": "/api/login", "status": 403, "headers": {}}
            ),
            risk_score: 78,
            risk_level: level.to_string(),
            verdict: "challenge".to_string(),
            signals: serde_json::json!([
                {"kind": "sql_injection", "weight": 60, "detail": "' OR 1=1"}
            ]),
            raw: None,
            duration_ms: None,
            process_us: None,
        }
    }

    #[test]
    fn text_line_plain_has_fixed_fields() {
        let line = text_line(&row("critical"), false);
        assert!(!line.contains('\x1b'));
        assert!(line.contains("critical"));
        assert!(line.contains("203.0.113.9"));
        assert!(line.contains("POST"));
        assert!(line.contains("/api/login"));
        assert!(line.contains("403"));
        assert!(line.contains("SQLi"));
    }

    #[test]
    fn text_line_colored_wraps_in_ansi() {
        let line = text_line(&row("high"), true);
        assert!(line.starts_with("\x1b[31m"));
        assert!(line.ends_with("\x1b[0m"));
    }

    #[test]
    fn json_shape_is_stable() {
        let v = serde_json::to_value(StreamJson::of(&row("medium"))).unwrap();
        for key in [
            "timestamp",
            "source",
            "ip",
            "server_port",
            "asn",
            "country",
            "level",
            "score",
            "verdict",
            "method",
            "path",
            "status",
            "signals",
        ] {
            assert!(v.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(v["method"], "POST");
        assert_eq!(v["path"], "/api/login");
        assert_eq!(v["status"], 403);
        assert_eq!(v["signals"][0], "sql_injection");
    }

    #[test]
    fn is_new_honors_cursor_and_ids() {
        let r = row("low");
        assert!(!is_new(&r, None, &HashSet::new()));
        let cursor = r.timestamp;
        let ids: HashSet<String> = [r.id.to_string()].into_iter().collect();
        assert!(!is_new(&r, Some(cursor), &ids));
        assert!(is_new(&r, Some(cursor), &HashSet::new()));
    }
}
