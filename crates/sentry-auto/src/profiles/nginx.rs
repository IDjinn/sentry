//! nginx config detection: parse `server`/`location` blocks into routes.
//!
//! The parser is deliberately tolerant and regex-based: nginx configs are
//! usually machine-managed and well-formed, and a full grammar would buy
//! nothing for route extraction. Comments are stripped, then `location`,
//! `root` and `alias` directives are scanned.

use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use crate::{
    read_capped, FoundRoute, FrameworkDetector, FrameworkProfile, PackSuggestion, ScanContext,
};

/// Per-file read cap for configs (chained includes stay small).
const CONFIG_READ_CAP: u64 = 1024 * 1024;

/// `location [modifier] path {` — the path may be quoted.
static LOCATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"location\s+(?:(=|\^\*|~\*|~|\^)\s+)?(?:"([^"]*)"|'([^']*)'|([^\s{]+))\s*\{"#)
        .expect("valid location regex")
});

/// `root /var/www;` / `alias /var/www;` — preceded by `{`, `}`, `;` or
/// line start so path fragments containing "root" don't match.
static ROOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|[;{}])\s*root\s+([^;\s]+)\s*;").expect("valid root regex")
});
static ALIAS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|[;{}])\s*alias\s+([^;\s]+)\s*;").expect("valid alias regex")
});

pub struct NginxDetector;

impl FrameworkDetector for NginxDetector {
    fn name(&self) -> &'static str {
        "nginx"
    }

    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile> {
        let mut dirs: Vec<PathBuf> = vec![ctx.root.clone()];
        dirs.extend(ctx.nginx_extra_dirs.iter().cloned());
        detect_from_dirs(&dirs)
    }
}

/// Scan explicit directories for nginx config files: `nginx.conf`,
/// `conf.d/*`, `sites-enabled/*` and top-level `*.conf`. Symlinked entries
/// (the usual `sites-enabled` layout) are followed on read.
pub fn detect_from_dirs(dirs: &[PathBuf]) -> Option<FrameworkProfile> {
    let mut files: Vec<(String, String)> = Vec::new();
    for dir in dirs {
        let top: Vec<String> = match std::fs::read_dir(dir) {
            Ok(entries) => {
                let mut names: Vec<String> = entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                names
            }
            Err(_) => Vec::new(),
        };
        for name in &top {
            if name != "nginx.conf" && !name.ends_with(".conf") {
                continue;
            }
            if let Ok(content) = read_capped(&dir.join(name), CONFIG_READ_CAP) {
                files.push((format!("{}/{name}", dir.display()), content));
            }
        }
        for sub in ["conf.d", "sites-enabled"] {
            let sub_dir = dir.join(sub);
            let Ok(entries) = std::fs::read_dir(&sub_dir) else {
                continue;
            };
            let mut names: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            for name in names {
                if let Ok(content) = read_capped(&sub_dir.join(&name), CONFIG_READ_CAP) {
                    files.push((format!("{}/{sub}/{name}", dir.display()), content));
                }
            }
        }
    }
    if files.is_empty() {
        return None;
    }
    let parsed = parse_configs(&files);
    if parsed.routes.is_empty() && parsed.doc_roots.is_empty() {
        return None;
    }
    let mut doc_roots = parsed.doc_roots;
    doc_roots.sort();
    doc_roots.dedup();
    Some(FrameworkProfile {
        framework: "nginx".to_string(),
        version: None,
        routes: crate::normalize_found(parsed.routes),
        sensitive_paths: Vec::new(),
        recommended_packs: vec![
            PackSuggestion {
                name: "sensitive_paths".to_string(),
                mode: "enforce".to_string(),
            },
            PackSuggestion {
                name: "crawlers_bad".to_string(),
                mode: "enforce".to_string(),
            },
            PackSuggestion {
                name: "http_anomaly".to_string(),
                mode: "shadow".to_string(),
            },
        ],
        recommended_rules: Vec::new(),
        doc_roots,
    })
}

/// Result of parsing a set of nginx config files.
#[derive(Debug, Default, Clone)]
pub struct NginxScan {
    pub routes: Vec<FoundRoute>,
    pub doc_roots: Vec<PathBuf>,
    /// `location ~` regex blocks found (reported, not converted).
    pub skipped_regex_locations: usize,
}

/// Parse the given (label, content) config files into routes and document
/// roots. Prefix locations produce both the bare path and a `/*` glob;
/// exact (`=`) locations produce only the exact path; regex (`~`, `~*`)
/// locations are counted and skipped.
pub fn parse_configs(files: &[(String, String)]) -> NginxScan {
    let mut out = NginxScan::default();
    for (label, content) in files {
        let stripped = strip_comments(content);
        for caps in LOCATION_RE.captures_iter(&stripped) {
            let modifier = caps.get(1).map(|m| m.as_str());
            if matches!(modifier, Some("~") | Some("~*")) {
                out.skipped_regex_locations += 1;
                continue;
            }
            let raw = caps
                .get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .map(|m| m.as_str())
                .unwrap_or_default();
            if !raw.starts_with('/') {
                continue;
            }
            let trimmed = raw.trim_end_matches('/');
            let path = if trimmed.is_empty() {
                "/".to_string()
            } else {
                trimmed.to_string()
            };
            let exact = matches!(modifier, Some("="));
            if !exact && path != "/" {
                out.routes
                    .push(FoundRoute::new(format!("{path}/*"), &[], label.as_str()));
            }
            out.routes.push(FoundRoute::new(path, &[], label.as_str()));
        }
        for caps in ROOT_RE.captures_iter(&stripped) {
            if let Some(root) = caps.get(1) {
                out.doc_roots.push(PathBuf::from(root.as_str()));
            }
        }
        for caps in ALIAS_RE.captures_iter(&stripped) {
            if let Some(alias) = caps.get(1) {
                out.doc_roots.push(PathBuf::from(alias.as_str()));
            }
        }
    }
    out
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        match line.find('#') {
            Some(idx) => out.push_str(&line[..idx]),
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> NginxScan {
        parse_configs(&[("test.conf".to_string(), content.to_string())])
    }

    #[test]
    fn exact_and_prefix_locations() {
        let scan = parse(
            r#"
            server {
                listen 80;
                root /var/www/html;
                location = /health { return 200; }
                location /api/ { proxy_pass http://backend; }
                location / { try_files $uri /index.html; }
                location ~ \.php$ { deny all; }
            }
            "#,
        );
        let paths: Vec<&str> = scan.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/health"));
        assert!(paths.contains(&"/api/*"));
        assert!(paths.contains(&"/api"));
        assert!(paths.contains(&"/"));
        assert_eq!(scan.skipped_regex_locations, 1);
        assert_eq!(scan.doc_roots, vec![PathBuf::from("/var/www/html")]);
    }

    #[test]
    fn comments_are_stripped() {
        let scan = parse("# location /commented/ { }\nlocation /real/ { }\n");
        let paths: Vec<&str> = scan.routes.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["/real/*", "/real"]);
    }

    #[test]
    fn quoted_location_paths_are_unquoted() {
        let scan = parse("location \"/quoted path/\" { }\n");
        let paths: Vec<&str> = scan.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/quoted path"));
    }

    #[test]
    fn root_location_does_not_globber_everything() {
        let scan = parse("location / { try_files $uri; }\n");
        assert_eq!(scan.routes.len(), 1);
        assert_eq!(scan.routes[0].path, "/");
    }

    #[test]
    fn detect_from_dirs_reads_sites_enabled() {
        let dir = std::env::temp_dir().join(format!("sentry-auto-nginx-{}", std::process::id()));
        let sites = dir.join("sites-enabled");
        std::fs::create_dir_all(&sites).unwrap();
        std::fs::write(
            sites.join("app"),
            "server { location /admin/ { proxy_pass http://x; } root /srv/app; }\n",
        )
        .unwrap();

        let profile = detect_from_dirs(&[dir.clone()]).unwrap();
        assert_eq!(profile.framework, "nginx");
        assert!(profile.routes.iter().any(|r| r.path == "/admin/*"));
        assert_eq!(profile.doc_roots, vec![PathBuf::from("/srv/app")]);
        let packs = profile
            .recommended_packs
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>();
        assert!(packs.contains(&"sensitive_paths"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
