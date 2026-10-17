//! `sentry config get|set|unset|reload` (F17): change a value without
//! hand-editing the file or restarting the service. Edits keep comments and
//! layout ([`sentry_conf::edit`]), the result is validated like
//! `config validate` and rolled back if it does not load, and a running
//! daemon applies it live (see [`crate::reload`]).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use color_eyre::eyre::{bail, eyre, Result};
use sentry_conf::edit::{self, Lookup};

use crate::config::{self, Resolved};

fn resolved(config_path: Option<&str>) -> Result<(Resolved, Vec<PathBuf>)> {
    let r = config::resolve(config_path.map(Path::new))?;
    if r.files.is_empty() {
        bail!("no config file found — create sentry.conf (or pass --config) before editing it");
    }
    let mut all = Vec::new();
    for f in &r.files {
        all.push(f.clone());
        all.extend(crate::cmd::included_files(f));
    }
    Ok((r, all))
}

/// Print the value written for `path` in the config files.
pub fn get(config_path: Option<&str>, path: &str) -> Result<()> {
    let segs = edit::split_path(path).map_err(|e| eyre!("{e}"))?;
    let (r, _) = resolved(config_path)?;
    let body = sentry_conf::Loader::default()
        .load_files(&r.files)
        .map_err(|e| eyre!("config error: {e}"))?;
    match edit::lookup(&body, &segs) {
        Some(Lookup::Directive(d)) => {
            let values: Vec<String> = d.values.iter().map(edit::render_node).collect();
            println!("{}", values.join(" "));
        }
        Some(Lookup::Block(names)) => {
            for n in names {
                println!("{path}.{n}");
            }
        }
        None => {
            return Err(eyre!(
                "`{path}` is not set in the config files (the built-in default applies — \
             `sentry config show --full` lists every value)"
            ))
        }
    }
    Ok(())
}

/// Which file to edit for `segs`: an explicit `--file`, the file that
/// already defines it, the file holding its parent block, else the main one.
fn target_file(
    r: &Resolved,
    all: &[PathBuf],
    segs: &[edit::Seg],
    explicit: Option<&str>,
) -> Result<PathBuf> {
    if let Some(f) = explicit {
        let want = Path::new(f);
        let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        return all
            .iter()
            .find(|p| canon(p) == canon(want))
            .cloned()
            .ok_or_else(|| {
                eyre!(
                    "{f} is not one of the loaded config files (`sentry config files` lists them)"
                )
            });
    }
    let parse = |p: &PathBuf| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| sentry_conf::parse_str(&s, &p.display().to_string()).ok())
    };
    let bodies: Vec<(PathBuf, sentry_conf::Body)> = all
        .iter()
        .filter_map(|p| parse(p).map(|b| (p.clone(), b)))
        .collect();
    if let Some((p, _)) = bodies
        .iter()
        .find(|(_, b)| matches!(edit::lookup(b, segs), Some(Lookup::Directive(_))))
    {
        return Ok(p.clone());
    }
    if segs.len() > 1 {
        let parent = &segs[..segs.len() - 1];
        if let Some((p, _)) = bodies
            .iter()
            .find(|(_, b)| matches!(edit::lookup(b, parent), Some(Lookup::Block(_))))
        {
            return Ok(p.clone());
        }
    }
    match &r.main {
        Some(m) if m.is_file() => Ok(m.clone()),
        _ => r
            .files
            .first()
            .cloned()
            .ok_or_else(|| eyre!("no config file to edit")),
    }
}

fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "sentry.conf".into());
    let tmp = path.with_file_name(format!(".{name}.sentry-tmp"));
    std::fs::write(&tmp, text).map_err(|e| eyre!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        eyre!("{}: {e}", path.display())
    })
}

/// Lines that differ, trimmed to the changed middle region.
fn print_diff(before: &str, after: &str) {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let mut start = 0;
    while start < a.len() && start < b.len() && a[start] == b[start] {
        start += 1;
    }
    let (mut ea, mut eb) = (a.len(), b.len());
    while ea > start && eb > start && a[ea - 1] == b[eb - 1] {
        ea -= 1;
        eb -= 1;
    }
    for l in &a[start..ea] {
        println!("- {l}");
    }
    for l in &b[start..eb] {
        println!("+ {l}");
    }
}

fn with_original_newlines(original: &str, edited: String) -> String {
    if original.contains("\r\n") {
        edited.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        edited
    }
}

#[derive(Clone, Copy)]
enum Op<'a> {
    Set(&'a str),
    Unset,
}

fn change(
    config_path: Option<&str>,
    path: &str,
    op: Op<'_>,
    file: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let segs = edit::split_path(path).map_err(|e| eyre!("{e}"))?;
    let (r, all) = resolved(config_path)?;
    let target = target_file(&r, &all, &segs, file)?;
    let before =
        std::fs::read_to_string(&target).map_err(|e| eyre!("{}: {e}", target.display()))?;
    let edited = match op {
        Op::Set(v) => edit::set(&before, &segs, v).map_err(|e| eyre!("{e}"))?,
        Op::Unset => match edit::unset(&before, &segs).map_err(|e| eyre!("{e}"))? {
            Some(s) => s,
            None => {
                return Err(eyre!("`{path}` is not set in {}", target.display()));
            }
        },
    };
    let edited = with_original_newlines(&before, edited);
    if edited == before {
        println!("{path} already has that value — nothing to do");
        return Ok(());
    }
    sentry_conf::parse_str(&edited, &target.display().to_string())
        .map_err(|e| eyre!("edit produces an invalid file: {e}"))?;

    println!("{}", target.display());
    print_diff(&before, &edited);
    if dry_run {
        println!("(dry run — nothing written; the full schema check runs on a real write)");
        return Ok(());
    }

    let old_cfg = config::load(config_path.map(Path::new)).ok();
    let backup = PathBuf::from(format!("{}.bak", target.display()));
    std::fs::write(&backup, &before).map_err(|e| eyre!("{}: {e}", backup.display()))?;
    write_atomic(&target, &edited)?;

    let checked = config::load(config_path.map(Path::new)).and_then(|c| {
        config::validate(&c)?;
        Ok(c)
    });
    let new_cfg = match checked {
        Ok(c) => c,
        Err(e) => {
            write_atomic(&target, &before)?;
            bail!("rejected, {} left unchanged: {e}", target.display());
        }
    };

    println!("saved (previous version: {})", backup.display());
    match old_cfg {
        Some(old) => {
            let plan = crate::reload::plan(&old, &new_cfg);
            if !plan.live().is_empty() {
                println!(
                    "a running daemon applies this within seconds: {}",
                    plan.live().join(", ")
                );
            }
            if !plan.restart.is_empty() {
                println!(
                    "needs a service restart to take effect: {} (`sentry service restart`)",
                    plan.restart.join(", ")
                );
            }
            if plan.is_empty() {
                println!("no effective change to the runtime config");
            }
        }
        None => println!("a running daemon picks this up within seconds"),
    }
    Ok(())
}

/// `sentry config set <path> <value>`.
pub fn set(
    config_path: Option<&str>,
    path: &str,
    value: &[String],
    file: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let joined = value.join(" ");
    change(config_path, path, Op::Set(&joined), file, dry_run)
}

/// `sentry config unset <path>`.
pub fn unset(
    config_path: Option<&str>,
    path: &str,
    file: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    change(config_path, path, Op::Unset, file, dry_run)
}

/// `sentry config reload`: validate the files on disk, then nudge a running
/// daemon (it watches the files; touching the main one forces a re-read).
pub fn reload(config_path: Option<&str>) -> Result<()> {
    let (r, _) = resolved(config_path)?;
    let cfg = config::load(config_path.map(Path::new))?;
    config::validate(&cfg)?;
    let main = match &r.main {
        Some(m) if m.is_file() => m.clone(),
        _ => r.files[0].clone(),
    };
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&main)
        .map_err(|e| eyre!("{}: {e}", main.display()))?;
    f.set_modified(SystemTime::now())
        .map_err(|e| eyre!("{}: {e}", main.display()))?;
    println!(
        "config OK — signalled {} (a running daemon re-reads it within seconds and applies \
         rules, routes and http routing live; other sections need `sentry service restart`)",
        main.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sentry_cfgedit_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn set_edits_file_validates_and_keeps_comments() {
        let d = dir("set");
        let f = d.join("sentry.conf");
        std::fs::write(&f, "# my config\nmetrics {\n  enabled: on  # prom\n}\n").unwrap();
        let cfg = f.to_str().unwrap();
        set(Some(cfg), "metrics.enabled", &["off".into()], None, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            "# my config\nmetrics {\n  enabled: off  # prom\n}\n"
        );
        assert!(d.join("sentry.conf.bak").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn invalid_value_is_rejected_and_rolled_back() {
        let d = dir("rollback");
        let f = d.join("sentry.conf");
        let original = "metrics {\n  enabled: on\n}\n";
        std::fs::write(&f, original).unwrap();
        let cfg = f.to_str().unwrap();
        let err = set(Some(cfg), "metrics.enabled", &["maybe".into()], None, false);
        assert!(err.is_err());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), original);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dry_run_writes_nothing_and_unset_removes() {
        let d = dir("dry");
        let f = d.join("sentry.conf");
        let original = "metrics {\n  enabled: on\n  listen: 127.0.0.1:9100\n}\n";
        std::fs::write(&f, original).unwrap();
        let cfg = f.to_str().unwrap();
        set(
            Some(cfg),
            "metrics.listen",
            &["127.0.0.1:9200".into()],
            None,
            true,
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), original);
        unset(Some(cfg), "metrics.listen", None, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            "metrics {\n  enabled: on\n}\n"
        );
        assert!(unset(Some(cfg), "metrics.nope", None, false).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn crlf_files_keep_crlf() {
        let d = dir("crlf");
        let f = d.join("sentry.conf");
        std::fs::write(&f, "metrics {\r\n  enabled: on\r\n}\r\n").unwrap();
        let cfg = f.to_str().unwrap();
        set(
            Some(cfg),
            "metrics.listen",
            &["127.0.0.1:9100".into()],
            None,
            false,
        )
        .unwrap();
        let out = std::fs::read_to_string(&f).unwrap();
        assert_eq!(
            out,
            "metrics {\r\n  enabled: on\r\n  listen: 127.0.0.1:9100\r\n}\r\n"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn edits_the_included_file_that_defines_the_key() {
        let d = dir("inc");
        std::fs::write(d.join("sentry.conf"), "include: detect.conf\n").unwrap();
        std::fs::write(d.join("detect.conf"), "metrics {\n  enabled: on\n}\n").unwrap();
        let cfg = d.join("sentry.conf");
        set(
            Some(cfg.to_str().unwrap()),
            "metrics.enabled",
            &["off".into()],
            None,
            false,
        )
        .unwrap();
        assert!(std::fs::read_to_string(d.join("detect.conf"))
            .unwrap()
            .contains("enabled: off"));
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            "include: detect.conf\n"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
