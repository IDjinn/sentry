//! DB-backed dataset management (F7.7).
//!
//! `sentry datasets import <file|url> --kind user_agent|path|ja3` stores a
//! curated one-entry-per-line list in Postgres; the daemon turns each
//! enabled dataset into a synthetic `dataset:<name>` rule and merges its
//! UA/path literals into the dynamic prefilter. Mutations notify
//! `sentry_datasets_changed`, so running daemons hot-reload without a
//! restart.

use std::collections::HashSet;

use sentry_storage::DatasetRow;

/// Parse a one-entry-per-line dataset body: blank lines and `#` comments
/// are skipped, entries are trimmed and deduplicated (order-preserving),
/// and the per-dataset entry cap applies.
pub fn parse_entries(body: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if seen.insert(line.to_string()) {
            out.push(line.to_string());
        }
        if out.len() >= sentry_core::MAX_DATASET_ENTRIES {
            break;
        }
    }
    out
}

/// Read dataset entries from a local file or an HTTP(S) URL.
pub async fn read_source(path: &str) -> color_eyre::Result<String> {
    if path.starts_with("http://") || path.starts_with("https://") {
        let resp = reqwest::get(path)
            .await
            .map_err(|e| color_eyre::eyre::eyre!("fetch {path}: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("read body from {path}: {e}"))?;
        if !status.is_success() {
            color_eyre::eyre::bail!("fetch {path}: HTTP {status}");
        }
        Ok(body)
    } else {
        std::fs::read_to_string(path).map_err(|e| color_eyre::eyre::eyre!("read {path}: {e}"))
    }
}

/// `sentry datasets list`.
pub fn print_list(rows: &[DatasetRow]) {
    if rows.is_empty() {
        println!("No datasets in database. Import one with `sentry datasets import <file> --kind user_agent --name <n>`.");
        return;
    }
    println!(
        "{:<24} {:<12} {:<10} {:>7}  URL / ACTION",
        "NAME", "KIND", "ENABLED", "ENTRIES"
    );
    for r in rows {
        println!(
            "{:<24} {:<12} {:<10} {:>7}  {}",
            r.name,
            r.kind,
            if r.enabled { "yes" } else { "no" },
            r.entry_count,
            r.source_url.as_deref().unwrap_or("-")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entries_skips_comments_and_dedupes() {
        let body = "# comment\n\nsqlmap\n  nikto  \nsqlmap\nnikto # inline comment stays literal\n";
        let parsed = parse_entries(body);
        assert_eq!(
            parsed,
            vec!["sqlmap", "nikto", "nikto # inline comment stays literal"]
        );
    }

    #[test]
    fn parse_entries_caps_at_the_dataset_limit() {
        let body = (0..sentry_core::MAX_DATASET_ENTRIES + 10)
            .map(|i| format!("tool-{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_entries(&body).len(), sentry_core::MAX_DATASET_ENTRIES);
    }
}
