//! Email-authentication posture (F16): SPF, DMARC and DKIM grading.
//!
//! These are DNS records, not HTTP headers, so the inline edge cannot add
//! them — Sentry audits them instead and prints the exact record to publish.
//! This module is pure: callers resolve the TXT/MX records and hand them in.
//! A domain that sends no mail (a plain website) should publish the strict
//! "null sender" set, which is what [`recommended`] returns for it.

/// Severity of one finding, ordered low → high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational.
    Info,
    /// Weak but not exploitable on its own.
    Medium,
    /// Spoofing is possible.
    High,
}

impl Severity {
    /// Lowercase stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One email-authentication finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailFinding {
    /// `spf`, `dmarc` or `dkim`.
    pub check: &'static str,
    /// How bad it is.
    pub severity: Severity,
    /// Explanation.
    pub detail: String,
}

fn finding(check: &'static str, severity: Severity, detail: impl Into<String>) -> EmailFinding {
    EmailFinding {
        check,
        severity,
        detail: detail.into(),
    }
}

/// DKIM selectors probed by default (the common provider defaults).
pub const COMMON_DKIM_SELECTORS: [&str; 10] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "dkim",
    "k1",
    "mail",
    "s1",
    "s2",
    "mandrill",
];

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.trim_start()
        .get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// Grade the TXT records at the domain apex for SPF.
pub fn grade_spf(txt: &[String]) -> Vec<EmailFinding> {
    let spf: Vec<&String> = txt.iter().filter(|t| starts_with_ci(t, "v=spf1")).collect();
    match spf.as_slice() {
        [] => vec![finding(
            "spf",
            Severity::High,
            "no SPF record: any server can send email as this domain",
        )],
        [one] => {
            let lower = one.to_ascii_lowercase();
            let terms: Vec<&str> = lower.split_whitespace().collect();
            let all = terms
                .iter()
                .find(|t| t.trim_start_matches(['+', '-', '~', '?']) == "all");
            match all {
                Some(t) if t.starts_with('-') => Vec::new(),
                Some(t) if t.starts_with('~') => vec![finding(
                    "spf",
                    Severity::Info,
                    "SPF ends in ~all (softfail): acceptable with an enforcing DMARC, \
                     prefer -all",
                )],
                Some(_) => vec![finding(
                    "spf",
                    Severity::High,
                    "SPF ends in +all/?all: it authorizes (or ignores) every sender",
                )],
                None if terms.iter().any(|t| t.starts_with("redirect=")) => Vec::new(),
                None => vec![finding(
                    "spf",
                    Severity::Medium,
                    "SPF has no terminating all mechanism",
                )],
            }
        }
        _ => vec![finding(
            "spf",
            Severity::High,
            "multiple SPF records: receivers return permerror and ignore SPF",
        )],
    }
}

/// Grade the TXT records found at `_dmarc.<domain>` (or the parent that
/// DMARC inherits from).
pub fn grade_dmarc(txt: &[String]) -> Vec<EmailFinding> {
    let Some(rec) = txt.iter().find(|t| starts_with_ci(t, "v=dmarc1")) else {
        return vec![finding(
            "dmarc",
            Severity::High,
            "no DMARC record: spoofing protection is not configured",
        )];
    };
    let tag = |name: &str| -> Option<String> {
        rec.split(';').find_map(|part| {
            let (k, v) = part.split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_ascii_lowercase())
        })
    };
    let mut out = Vec::new();
    match tag("p").as_deref() {
        Some("reject") => {}
        Some("quarantine") => out.push(finding(
            "dmarc",
            Severity::Info,
            "DMARC p=quarantine: move to p=reject once reports are clean",
        )),
        Some("none") => out.push(finding(
            "dmarc",
            Severity::Medium,
            "DMARC p=none is monitoring only: spoofed mail is still delivered",
        )),
        _ => out.push(finding(
            "dmarc",
            Severity::High,
            "DMARC record has no valid p= policy",
        )),
    }
    if tag("rua").is_none() {
        out.push(finding(
            "dmarc",
            Severity::Info,
            "DMARC has no rua= address: aggregate reports are not collected",
        ));
    }
    out
}

/// Grade DKIM. `found_selectors` are the probed selectors that returned a
/// key; `sends_mail` is false for a web-only domain (no MX), where DKIM is
/// not needed and no finding is raised.
pub fn grade_dkim(found_selectors: &[String], sends_mail: bool) -> Vec<EmailFinding> {
    if !found_selectors.is_empty() || !sends_mail {
        return Vec::new();
    }
    vec![finding(
        "dkim",
        Severity::Medium,
        "no DKIM key found for common selectors: mail may be unsigned (a custom \
         selector would not be detected)",
    )]
}

/// Records to publish. `sends_mail = false` returns the strict null-sender
/// set for a website-only domain.
pub fn recommended(domain: &str, sends_mail: bool) -> Vec<String> {
    if sends_mail {
        return vec![
            format!("{domain}. TXT \"v=spf1 include:<your-mail-provider> -all\""),
            format!(
                "_dmarc.{domain}. TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; \
                 adkim=s; aspf=s\" (move to p=reject when reports are clean)"
            ),
            format!("<selector>._domainkey.{domain}. TXT (public key from your mail provider)"),
        ];
    }
    vec![
        format!("{domain}. TXT \"v=spf1 -all\""),
        format!("_dmarc.{domain}. TXT \"v=DMARC1; p=reject; adkim=s; aspf=s\""),
        format!("*._domainkey.{domain}. TXT \"v=DKIM1; p=\""),
        format!("{domain}. MX 0 ."),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn missing_spf_is_high() {
        let f = grade_spf(&t(&["google-site-verification=abc"]));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn spf_all_variants() {
        assert!(grade_spf(&t(&["v=spf1 include:_spf.google.com -all"])).is_empty());
        assert_eq!(
            grade_spf(&t(&["v=spf1 mx ~all"]))[0].severity,
            Severity::Info
        );
        assert_eq!(grade_spf(&t(&["v=spf1 +all"]))[0].severity, Severity::High);
        assert_eq!(
            grade_spf(&t(&["v=spf1 ip4:1.2.3.4"]))[0].severity,
            Severity::Medium
        );
        assert!(grade_spf(&t(&["v=spf1 redirect=_spf.example.com"])).is_empty());
    }

    #[test]
    fn duplicate_spf_is_permerror() {
        let f = grade_spf(&t(&["v=spf1 -all", "v=spf1 mx -all"]));
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn dmarc_policies() {
        assert_eq!(grade_dmarc(&[])[0].severity, Severity::High);
        let none = grade_dmarc(&t(&["v=DMARC1; p=none"]));
        assert!(none.iter().any(|f| f.severity == Severity::Medium));
        let reject = grade_dmarc(&t(&["v=DMARC1; p=reject; rua=mailto:a@b.c"]));
        assert!(reject.is_empty());
        let quarantine = grade_dmarc(&t(&["V=dmarc1; P=Quarantine; rua=mailto:a@b.c"]));
        assert_eq!(quarantine[0].severity, Severity::Info);
        assert_eq!(
            grade_dmarc(&t(&["v=DMARC1; rua=mailto:a@b.c"]))[0].severity,
            Severity::High
        );
    }

    #[test]
    fn dkim_only_matters_for_mail_domains() {
        assert!(grade_dkim(&[], false).is_empty());
        assert_eq!(grade_dkim(&[], true)[0].severity, Severity::Medium);
        assert!(grade_dkim(&t(&["google"]), true).is_empty());
    }

    #[test]
    fn recommended_null_sender_set() {
        let r = recommended("example.com", false);
        assert!(r[0].contains("v=spf1 -all"));
        assert!(r[1].contains("p=reject"));
        assert!(r.iter().any(|l| l.contains("MX 0 .")));
        assert!(recommended("example.com", true)[0].contains("include:"));
    }
}
