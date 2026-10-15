//! DB-backed dataset management (F7.7).
//!
//! `sentry datasets import <file|url> --kind user_agent|path|ja3` stores a
//! curated one-entry-per-line list in Postgres; the daemon turns each
//! enabled dataset into a synthetic `dataset:<name>` rule and merges its
//! UA/path literals into the dynamic prefilter. Mutations notify
//! `sentry_datasets_changed`, so running daemons hot-reload without a
//! restart.
//!
//! `sentry datasets preset` renders the built-in sensitive-file categories
//! ([`sentry_core::sensitive_files`]) as dataset text ready for a gist.

use std::collections::HashSet;
use std::path::Path;

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

/// Resolve the category names requested by `datasets preset`: every
/// category when the list is empty, otherwise the validated names
/// (deduplicated, request order kept).
pub fn preset_names(categories: &[String]) -> color_eyre::Result<Vec<String>> {
    if categories.is_empty() {
        return Ok(sentry_core::sensitive_files::category_names());
    }
    let mut names = Vec::new();
    for requested in categories {
        match sentry_core::sensitive_files::category(requested) {
            Some(c) => {
                if !names.iter().any(|n| n == c.name) {
                    names.push(c.name.to_string());
                }
            }
            None => {
                return Err(color_eyre::eyre::eyre!(
                    "unknown sensitive-file category `{requested}` — valid: {}",
                    sentry_core::sensitive_files::category_names().join(", ")
                ));
            }
        }
    }
    Ok(names)
}

/// Entries a rendered category contributes (non-comment lines).
fn render_entry_count(name: &str) -> usize {
    sentry_core::sensitive_files::render(name)
        .map(|body| body.lines().filter(|l| !l.starts_with('#')).count())
        .unwrap_or(0)
}

/// `sentry datasets preset`: with no flags, list the categories; with
/// `--category`, print the dataset text to stdout; with `--out`, write
/// `<category>.txt` files ready for a gist.
pub fn run_preset(categories: &[String], out: Option<&str>, list: bool) -> color_eyre::Result<()> {
    if out.is_none() && categories.is_empty() {
        print_preset_list();
        if list {
            println!();
            println!("use --category <name> to print a dataset, --out <dir> to write .txt files");
        }
        return Ok(());
    }
    let names = preset_names(categories)?;
    match out {
        None => {
            for name in &names {
                print!(
                    "{}",
                    sentry_core::sensitive_files::render(name)
                        .expect("preset_names validated the category")
                );
            }
        }
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .map_err(|e| color_eyre::eyre::eyre!("create {}: {e}", Path::new(dir).display()))?;
            for name in &names {
                let body = sentry_core::sensitive_files::render(name)
                    .expect("preset_names validated the category");
                let path = Path::new(dir).join(format!("{name}.txt"));
                std::fs::write(&path, &body)
                    .map_err(|e| color_eyre::eyre::eyre!("write {}: {e}", path.display()))?;
                println!(
                    "wrote {} ({} entries)",
                    path.display(),
                    body.lines().count()
                );
            }
            println!();
            println!("upload the directory to a gist, then import each raw URL:");
            for name in &names {
                println!(
                    "  sentry datasets import <raw-url>/{name}.txt --kind path --name sensitive-{name} --action block"
                );
            }
            println!(
                "tune each one independently: sentry datasets enable|disable sensitive-<category>"
            );
        }
    }
    Ok(())
}

fn print_preset_list() {
    println!(
        "{:<10} {:>7}  {:<7} DESCRIPTION",
        "CATEGORY", "ENTRIES", "WALK"
    );
    for c in sentry_core::sensitive_files::CATEGORIES {
        println!(
            "{:<10} {:>7}  {:<7} {}",
            c.name,
            render_entry_count(c.name),
            if c.walk_default { "yes" } else { "opt-in" },
            c.description
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

    #[test]
    fn preset_names_defaults_to_all_and_validates() {
        let all = preset_names(&[]).unwrap();
        assert_eq!(all, sentry_core::sensitive_files::category_names());
        assert_eq!(all.first().map(String::as_str), Some("cloud"));

        let picked =
            preset_names(&["keys".to_string(), "KEYS".to_string(), "ssh".to_string()]).unwrap();
        assert_eq!(picked, vec!["keys", "ssh"]);

        let err = preset_names(&["nope".to_string()]).unwrap_err();
        assert!(err.to_string().contains("valid:"));
    }

    #[test]
    fn run_preset_writes_category_files() {
        let dir = std::env::temp_dir().join(format!("sentry-ds-preset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        run_preset(&["ssh".to_string()], Some(dir.to_str().unwrap()), false).unwrap();
        let body = std::fs::read_to_string(dir.join("ssh.txt")).unwrap();
        assert!(body.contains("/id_rsa"));
        assert!(body.contains("/.ssh"));
        assert_eq!(render_entry_count("ssh"), 5);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
