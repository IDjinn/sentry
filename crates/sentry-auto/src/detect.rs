//! Bounded directory walk and the detector registry.

use std::path::Path;

use crate::profiles;
use crate::{FrameworkDetector, ScanContext};

/// Hard cap on the number of files yielded by a walk.
pub const MAX_FILES: usize = 50_000;

const MAX_DEPTH_PLAIN: usize = 6;
const MAX_DEPTH_DEEP: usize = 12;

/// Directories never descended into (package managers, VCS, build output).
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "vendor",
    "target",
    ".next",
    "__pycache__",
    ".venv",
    ".idea",
    ".vscode",
    "storage",
];

/// Walk `root` (bounded, symlinks skipped) and return `/`-separated paths
/// relative to it, sorted. Depth is 6 by default and 12 with `deep`.
pub fn bounded_walk(root: &Path, deep: bool) -> Vec<String> {
    let max_depth = if deep {
        MAX_DEPTH_DEEP
    } else {
        MAX_DEPTH_PLAIN
    };
    let mut out = Vec::new();
    walk_dir(root, String::new(), 0, max_depth, &mut out);
    out.sort();
    out
}

fn walk_dir(root: &Path, rel: String, depth: usize, max_depth: usize, out: &mut Vec<String>) {
    if out.len() >= MAX_FILES || depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_FILES {
            return;
        }
        // Symlinks are skipped entirely: they can loop and they rarely
        // carry app source.
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let child = if rel.is_empty() {
            name.to_string()
        } else {
            format!("{rel}/{name}")
        };
        if ft.is_dir() {
            if SKIPPED_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk_dir(&entry.path(), child, depth + 1, max_depth, out);
        } else if ft.is_file() {
            out.push(child);
        }
    }
}

/// Every built-in detector.
pub fn detectors() -> Vec<Box<dyn FrameworkDetector>> {
    vec![
        Box::new(profiles::nginx::NginxDetector),
        Box::new(profiles::wordpress::WordPressDetector),
        Box::new(profiles::laravel::LaravelDetector),
        Box::new(profiles::nextjs::NextjsDetector),
        Box::new(profiles::express::ExpressDetector),
    ]
}

/// Valid profile names, sorted (used in error messages).
pub fn profile_names() -> Vec<String> {
    let mut names: Vec<String> = detectors().iter().map(|d| d.name().to_string()).collect();
    names.sort();
    names
}

/// Build a [`ScanContext`] from parts (used by tests to inject a fake walk).
pub fn ctx_from(root: std::path::PathBuf, files: Vec<String>, deep: bool) -> ScanContext {
    ScanContext {
        root,
        deep,
        nginx_extra_dirs: Vec::new(),
        files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_lists_files_relative_and_sorted() {
        let dir = std::env::temp_dir().join(format!("sentry-auto-walk-{}", std::process::id()));
        let nested = dir.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.join("composer.json"), "{}").unwrap();
        std::fs::write(nested.join("web.php"), "<?php").unwrap();
        std::fs::create_dir_all(dir.join("node_modules/x")).unwrap();
        std::fs::write(dir.join("node_modules/x/index.js"), "").unwrap();

        let files = bounded_walk(&dir, false);
        assert_eq!(files, vec!["a/b/web.php", "composer.json"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn walk_skips_symlinks() {
        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join(format!("sentry-auto-sym-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("real.txt"), "x").unwrap();
            std::os::unix::fs::symlink(dir.join("real.txt"), dir.join("link.txt")).unwrap();
            let files = bounded_walk(&dir, false);
            assert_eq!(files, vec!["real.txt"]);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn profile_names_are_sorted_and_complete() {
        let names = profile_names();
        assert_eq!(
            names,
            vec!["express", "laravel", "nextjs", "nginx", "wordpress"]
        );
    }

    #[test]
    fn scan_rejects_missing_root() {
        let err = crate::scan(
            Path::new("/definitely/not/here"),
            &crate::ScanOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, crate::AutoError::RootNotFound(_)));
    }
}
