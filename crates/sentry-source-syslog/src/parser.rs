//! RFC 5424 / RFC 3164 syslog message parser.
//!
//! RFC 5424: `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP
//! MSGID SP STRUCTURED-DATA [SP MSG]`. When the token after `<PRI>` is not a
//! version number the message is treated as legacy RFC 3164
//! (`<PRI>Mmm dd hh:mm:ss host msg`). Structured-data is scanned but not
//! retained; the free-form message is.

use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};
use sentry_core::event::SyslogData;
use thiserror::Error;

/// Failures while parsing a syslog line.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyslogParseError {
    /// Message does not start with `<PRI>`.
    #[error("message does not start with a <PRI> header")]
    MissingPri,
    /// `<PRI>` content is not a number in 0..=191.
    #[error("<PRI> is not a valid priority value")]
    InvalidPri,
    /// RFC 5424 header ended before all fields were present.
    #[error("truncated RFC 5424 header")]
    TruncatedHeader,
    /// STRUCTURED-DATA started but never closed.
    #[error("malformed structured-data field")]
    MalformedStructuredData,
}

/// Parse one syslog message (datagram or line).
pub fn parse_syslog(line: &str) -> Result<SyslogData, SyslogParseError> {
    let line = line.trim_start_matches('\u{feff}').trim();
    if !line.starts_with('<') {
        return Err(SyslogParseError::MissingPri);
    }
    let pri_end = line.find('>').ok_or(SyslogParseError::MissingPri)?;
    let pri: u16 = line[1..pri_end]
        .parse()
        .map_err(|_| SyslogParseError::InvalidPri)?;
    if pri > 191 {
        return Err(SyslogParseError::InvalidPri);
    }
    let facility = (pri / 8) as u8;
    let severity = (pri % 8) as u8;
    let rest = &line[pri_end + 1..];

    if looks_like_5424(rest) {
        parse_5424(rest, facility, severity)
    } else {
        Ok(parse_3164(rest, facility, severity))
    }
}

/// RFC 5424 messages carry a numeric VERSION right after `<PRI>`.
fn looks_like_5424(rest: &str) -> bool {
    rest.split(' ')
        .next()
        .is_some_and(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
}

fn parse_5424(rest: &str, facility: u8, severity: u8) -> Result<SyslogData, SyslogParseError> {
    let mut parts = rest.splitn(7, ' ');
    let mut header = || parts.next().filter(|s| !s.is_empty());

    let version: u16 = header()
        .ok_or(SyslogParseError::TruncatedHeader)?
        .parse()
        .map_err(|_| SyslogParseError::TruncatedHeader)?;
    let ts = header().ok_or(SyslogParseError::TruncatedHeader)?;
    let host = header().ok_or(SyslogParseError::TruncatedHeader)?;
    let app = header().ok_or(SyslogParseError::TruncatedHeader)?;
    let proc = header().ok_or(SyslogParseError::TruncatedHeader)?;
    let msgid = header().ok_or(SyslogParseError::TruncatedHeader)?;
    let sd_msg = parts.next().unwrap_or("-");

    Ok(SyslogData {
        facility,
        severity,
        version: Some(version),
        timestamp: parse_rfc3339(ts),
        hostname: nilval(host),
        app_name: nilval(app),
        proc_id: nilval(proc),
        msg_id: nilval(msgid),
        message: split_structured_data(sd_msg)?,
    })
}

/// Split `STRUCTURED-DATA [SP MSG]`, returning the message part.
fn split_structured_data(rest: &str) -> Result<String, SyslogParseError> {
    if let Some(after) = rest.strip_prefix('-') {
        return Ok(after.strip_prefix(' ').unwrap_or("").to_string());
    }
    if !rest.starts_with('[') {
        return Ok(rest.to_string());
    }
    let chars: Vec<char> = rest.chars().collect();
    let mut in_quote = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '"' => in_quote = !in_quote,
            ']' if !in_quote => match chars.get(i + 1) {
                None => return Ok(String::new()),
                Some(' ') => return Ok(chars[i + 2..].iter().collect()),
                Some('[') => {}
                _ => return Ok(chars[i + 1..].iter().collect()),
            },
            _ => {}
        }
        i += 1;
    }
    Err(SyslogParseError::MalformedStructuredData)
}

/// RFC 3164 legacy format: `Mmm dd hh:mm:ss host msg` (no year, local-ish
/// clock assumed UTC). Unparseable timestamps degrade to a message-only
/// payload so no event is lost.
fn parse_3164(rest: &str, facility: u8, severity: u8) -> SyslogData {
    let mut data = SyslogData {
        facility,
        severity,
        version: None,
        timestamp: None,
        hostname: None,
        app_name: None,
        proc_id: None,
        msg_id: None,
        message: rest.to_string(),
    };
    if rest.len() < 15 {
        return data;
    }
    let Some(ts_part) = rest.get(..15) else {
        return data;
    };
    // RFC 3164 has no year; parse with a leap dummy year so "Feb 29" is
    // accepted, then rebuild the date with the current year.
    let padded = format!("2000 {ts_part}");
    let Ok(naive) = NaiveDateTime::parse_from_str(&padded, "%Y %b %e %H:%M:%S") else {
        return data;
    };
    let mut year = Utc::now().year();
    if naive.month() == 12 && Utc::now().month() == 1 {
        year -= 1;
    }
    let Some(date) = chrono::NaiveDate::from_ymd_opt(year, naive.month(), naive.day()) else {
        return data;
    };
    data.timestamp = Some(Utc.from_utc_datetime(&date.and_time(naive.time())));
    let after = rest[15..].trim_start();
    let (host, message) = match after.split_once(' ') {
        Some((h, m)) => (Some(h.to_string()), m.to_string()),
        None => (Some(after.to_string()), String::new()),
    };
    data.hostname = host.filter(|h| !h.is_empty());
    data.message = message;
    data
}

fn nilval(t: &str) -> Option<String> {
    (t != "-").then(|| t.to_string())
}

fn parse_rfc3339(ts: &str) -> Option<DateTime<Utc>> {
    if ts == "-" {
        return None;
    }
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5424_full_header() {
        let d = parse_syslog(
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8",
        )
        .unwrap();
        assert_eq!(d.facility, 4);
        assert_eq!(d.severity, 2);
        assert_eq!(d.version, Some(1));
        assert_eq!(
            d.timestamp.map(|t| t.to_rfc3339()),
            Some("2003-10-11T22:14:15.003+00:00".to_string())
        );
        assert_eq!(d.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(d.app_name.as_deref(), Some("su"));
        assert_eq!(d.proc_id, None);
        assert_eq!(d.msg_id.as_deref(), Some("ID47"));
        assert_eq!(d.message, "'su root' failed for lonvick on /dev/pts/8");
    }

    #[test]
    fn rfc5424_with_structured_data() {
        let d = parse_syslog(
            r#"<165>1 2003-10-11T22:14:15.003Z mymachine evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOM An application event log entry"#,
        )
        .unwrap();
        assert_eq!(d.facility, 20);
        assert_eq!(d.severity, 5);
        assert_eq!(d.app_name.as_deref(), Some("evntslog"));
        assert_eq!(d.message, "BOM An application event log entry");
    }

    #[test]
    fn rfc5424_multiple_sd_elements() {
        let d = parse_syslog(r#"<13>1 - - - - - [a x="1"][b y="]"] msg here"#).unwrap();
        assert_eq!(d.message, "msg here");
        assert_eq!(d.timestamp, None);
        assert_eq!(d.hostname, None);
    }

    #[test]
    fn rfc5424_nil_everything() {
        let d = parse_syslog("<13>1 - - - - - - hello world").unwrap();
        assert_eq!(d.version, Some(1));
        assert_eq!(d.facility, 1);
        assert_eq!(d.severity, 5);
        assert_eq!(d.hostname, None);
        assert_eq!(d.app_name, None);
        assert_eq!(d.msg_id, None);
        assert_eq!(d.message, "hello world");
    }

    #[test]
    fn rfc5424_offset_timestamp_converts_to_utc() {
        let d = parse_syslog("<13>1 2003-10-11T22:14:15+02:00 h a p m - x").unwrap();
        assert_eq!(
            d.timestamp.map(|t| t.to_rfc3339()),
            Some("2003-10-11T20:14:15+00:00".to_string())
        );
    }

    #[test]
    fn rfc3164_legacy() {
        let d = parse_syslog("<34>Oct 11 22:14:15 mymachine su: 'su root' failed").unwrap();
        assert_eq!(d.version, None);
        assert_eq!(d.facility, 4);
        assert_eq!(d.severity, 2);
        assert_eq!(d.hostname.as_deref(), Some("mymachine"));
        assert!(d.message.contains("'su root' failed"));
        assert_eq!(
            d.timestamp.map(|t| t.format("%m-%d %H:%M:%S").to_string()),
            Some("10-11 22:14:15".to_string())
        );
    }

    #[test]
    fn rfc3164_without_timestamp_degrades() {
        let d = parse_syslog("<13>some free-form message").unwrap();
        assert_eq!(d.severity, 5);
        assert_eq!(d.timestamp, None);
        assert_eq!(d.message, "some free-form message");
    }

    #[test]
    fn malformed_inputs() {
        assert_eq!(
            parse_syslog("no pri here").unwrap_err(),
            SyslogParseError::MissingPri
        );
        assert_eq!(
            parse_syslog("<abc>1 - - - - - x").unwrap_err(),
            SyslogParseError::InvalidPri
        );
        assert_eq!(
            parse_syslog("<999>1 - - - - - x").unwrap_err(),
            SyslogParseError::InvalidPri
        );
        assert_eq!(
            parse_syslog("<30>1").unwrap_err(),
            SyslogParseError::TruncatedHeader
        );
        assert_eq!(
            parse_syslog("<30>1 - - - - - [unclosed").unwrap_err(),
            SyslogParseError::MalformedStructuredData
        );
    }
}
