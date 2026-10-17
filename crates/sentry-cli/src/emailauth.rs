//! Email-authentication audit (F16): resolves SPF/DMARC/DKIM/MX for the
//! protected domains and grades them with `sentry_core::email_auth`.

use std::time::Duration;

use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::TokioAsyncResolver;
use sentry_core::email_auth::{
    grade_dkim, grade_dmarc, grade_spf, recommended, EmailFinding, COMMON_DKIM_SELECTORS,
};
use sentry_core::SentryConfig;

/// Result of auditing one domain.
#[derive(Debug)]
pub struct DomainAudit {
    /// Audited domain.
    pub domain: String,
    /// Domain where the DMARC record was found (the host or a parent).
    pub dmarc_at: Option<String>,
    /// Whether the domain publishes a real MX (sends/receives mail).
    pub sends_mail: bool,
    /// Findings, worst first.
    pub findings: Vec<EmailFinding>,
    /// Records to publish.
    pub recommended: Vec<String>,
}

fn resolver() -> TokioAsyncResolver {
    let mut opts = hickory_resolver::config::ResolverOpts::default();
    opts.timeout = Duration::from_secs(4);
    opts.attempts = 2;
    TokioAsyncResolver::tokio(hickory_resolver::config::ResolverConfig::default(), opts)
}

async fn txt(r: &TokioAsyncResolver, name: &str) -> Result<Vec<String>, String> {
    match r.txt_lookup(name).await {
        Ok(l) => Ok(l
            .iter()
            .map(|t| {
                t.txt_data()
                    .iter()
                    .map(|d| String::from_utf8_lossy(d).into_owned())
                    .collect::<String>()
            })
            .collect()),
        Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}

async fn has_mx(r: &TokioAsyncResolver, name: &str) -> bool {
    match r.mx_lookup(name).await {
        Ok(l) => l.iter().any(|m| m.exchange().to_string() != "."),
        Err(_) => false,
    }
}

/// Audit one domain. DNS failures are reported as an `Err` string so a
/// resolver outage is never mistaken for a missing record.
pub async fn audit_domain(domain: &str) -> Result<DomainAudit, String> {
    let r = resolver();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let apex = txt(&r, &domain).await?;
    let sends_mail = has_mx(&r, &domain).await;

    let mut dmarc_txt = Vec::new();
    let mut dmarc_at = None;
    let mut cursor = domain.as_str();
    loop {
        let found = txt(&r, &format!("_dmarc.{cursor}")).await?;
        if found
            .iter()
            .any(|t| t.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
        {
            dmarc_txt = found;
            dmarc_at = Some(cursor.to_string());
            break;
        }
        match cursor.split_once('.') {
            Some((_, parent)) if parent.contains('.') => cursor = parent,
            _ => break,
        }
    }

    let mut selectors = Vec::new();
    for sel in COMMON_DKIM_SELECTORS {
        let found = txt(&r, &format!("{sel}._domainkey.{domain}")).await?;
        if found.iter().any(|t| t.to_ascii_lowercase().contains("p=")) {
            selectors.push(sel.to_string());
        }
    }

    let mut findings = grade_spf(&apex);
    findings.extend(grade_dmarc(&dmarc_txt));
    findings.extend(grade_dkim(&selectors, sends_mail));
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Ok(DomainAudit {
        recommended: recommended(&domain, sends_mail),
        domain,
        dmarc_at,
        sends_mail,
        findings,
    })
}

/// Domains to audit: explicit `--domain` values, else the concrete hosts of
/// the configured sites and `[posture] hosts` (wildcards, regexes, IPs and
/// localhost are skipped).
pub fn domains(cfg: &SentryConfig, explicit: &[String]) -> Vec<String> {
    let mut raw: Vec<String> = if explicit.is_empty() {
        let (_, sites) = sentry_core::edge_routes::normalized(&cfg.edge);
        sites
            .iter()
            .flat_map(|s| s.hosts.clone())
            .chain(cfg.posture.hosts.clone())
            .collect()
    } else {
        explicit.to_vec()
    };
    raw.iter_mut()
        .for_each(|h| *h = h.trim().trim_end_matches('.').to_ascii_lowercase());
    raw.retain(|h| {
        h.contains('.')
            && !h.starts_with(['*', '~'])
            && h.parse::<std::net::IpAddr>().is_err()
            && h != "localhost"
            && !h.ends_with(".localhost")
            && !h.ends_with(".test")
    });
    raw.sort();
    raw.dedup();
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_domains_are_filtered_and_deduped() {
        let cfg = SentryConfig::default();
        let d = domains(
            &cfg,
            &[
                "Example.com.".into(),
                "example.com".into(),
                "*.wild.com".into(),
                "127.0.0.1".into(),
                "localhost".into(),
            ],
        );
        assert_eq!(d, vec!["example.com".to_string()]);
    }
}
