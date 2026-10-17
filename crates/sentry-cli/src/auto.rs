//! `sentry auto` orchestration: filesystem framework scan, on-disk server
//! config detection and a bounded live HTTP probe of the local web
//! service, merged into `sentry.auto.conf`.
//!
//! Module flags are opt-in: no flags runs everything (`--probe` + `--disk`
//! equivalent); passing one or more restricts the run to those modules.
//! When nothing is found the command prints nothing and exits 0.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use sentry_auto::generate::{self, AutoArtifacts};
use sentry_auto::probe::{self, Hit};
use sentry_auto::{FoundRoute, FrameworkProfile, ScanOptions};

/// Probe tuning: bounded by design so a tarpit server can't stall the run.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_CONCURRENCY: usize = 8;
const MAX_CANDIDATES_PER_PORT: usize = 80;
const MAX_SITEMAPS: usize = 2;
const BODY_PREFIX_CAP: usize = 64 * 1024;
const SPEC_BODY_CAP: usize = 2 * 1024 * 1024;

/// Arguments for [`run`], straight from the CLI variant plus the
/// `[auto.sensitive]` config section (CLI flags extend both lists).
pub struct AutoArgs {
    pub root: Option<String>,
    pub profile: Option<String>,
    pub probe: bool,
    pub disk: bool,
    pub deep: bool,
    pub dry_run: bool,
    pub verbose: u8,
    pub config_path: Option<String>,
    /// Sensitive-file categories added to the walk filter.
    pub sensitive_enable: Vec<String>,
    /// Sensitive-file categories removed from the walk filter.
    pub sensitive_skip: Vec<String>,
}

/// Run the auto-discovery pipeline. Returns `Ok(())` with no output when
/// nothing is found.
pub async fn run(args: AutoArgs) -> color_eyre::Result<()> {
    let (run_probe, run_disk) = match (args.probe, args.disk) {
        (false, false) => (true, true),
        (p, d) => (p, d),
    };

    let mut profiles: Vec<FrameworkProfile> = Vec::new();

    match &args.root {
        Some(root) => {
            let path = PathBuf::from(root);
            let opts = ScanOptions {
                deep: args.deep,
                forced_profile: args.profile.clone(),
                nginx_extra_dirs: nginx_extra_dirs(),
                sensitive_extra: args.sensitive_enable.clone(),
                sensitive_skip: args.sensitive_skip.clone(),
            };
            let report = sentry_auto::scan(&path, &opts)?;
            if args.verbose >= 1 {
                print_tree(&report.root, &report.files, args.verbose);
            }
            profiles.extend(report.profiles);
        }
        None => {
            if run_disk {
                profiles.extend(scan_disk(&args));
            }
            if run_probe {
                profiles.push(probe_local(args.profile.as_deref()).await);
            }
        }
    }

    let artifacts = generate::from_profiles(&profiles);
    if artifacts.routes.is_empty() {
        return Ok(());
    }

    report(&artifacts, &profiles, args.verbose);

    if args.dry_run {
        println!("[dry-run] nothing written");
    } else {
        let out_path = auto_file_path(args.config_path.as_deref());
        write_atomic(&out_path, &artifacts)?;
        println!(
            "wrote {} ({} routes, {} packs, {} rules)",
            out_path.display(),
            artifacts.routes.len(),
            artifacts.packs.len(),
            artifacts.rules.len()
        );
    }
    Ok(())
}

/// On-disk module: system nginx configs, then a framework scan chained
/// into every document root found.
fn scan_disk(args: &AutoArgs) -> Vec<FrameworkProfile> {
    let mut dirs = nginx_extra_dirs();
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    let Some(nginx) = sentry_auto::profiles::nginx::detect_from_dirs(&dirs) else {
        if args.verbose >= 1 {
            println!("[auto] disk: no server configs found");
        }
        return Vec::new();
    };
    if args.verbose >= 1 {
        println!(
            "[auto] disk: {} nginx routes, doc roots: {:?}",
            nginx.routes.len(),
            nginx.doc_roots
        );
    }
    let doc_roots = nginx.doc_roots.clone();
    let mut profiles = vec![nginx];
    for doc_root in doc_roots {
        if !doc_root.is_dir() {
            continue;
        }
        let opts = ScanOptions {
            deep: args.deep,
            forced_profile: args.profile.clone(),
            nginx_extra_dirs: Vec::new(),
            sensitive_extra: args.sensitive_enable.clone(),
            sensitive_skip: args.sensitive_skip.clone(),
        };
        let Ok(report) = sentry_auto::scan(&doc_root, &opts) else {
            continue;
        };
        if args.verbose >= 1 {
            println!(
                "[auto] doc root {}: {} files walked, {} profiles",
                doc_root.display(),
                report.files.len(),
                report.profiles.len()
            );
        }
        profiles.extend(report.profiles);
    }
    profiles
}

/// Live probe of 127.0.0.1:80 and :443 (when open). Routes are any path
/// answering with something other than 404/410; a sentinel path filters
/// SPA-style catch-alls.
async fn probe_local(forced_profile: Option<&str>) -> FrameworkProfile {
    let mut profile = FrameworkProfile {
        framework: "http-probe".to_string(),
        ..Default::default()
    };

    let mut targets: Vec<(&str, u16)> = Vec::new();
    if tcp_open(80).await {
        targets.push(("http", 80));
    }
    if tcp_open(443).await {
        targets.push(("https", 443));
    }
    for (scheme, port) in targets {
        if let Some(routes) = probe_port(scheme, port, forced_profile).await {
            profile.routes.extend(routes);
        }
    }
    profile.routes = sentry_auto::normalize_found(profile.routes);
    profile
}

async fn tcp_open(port: u16) -> bool {
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .is_ok()
}

/// Probe one open port; `None` when the port is a tarpit (nothing useful
/// answered in time).
async fn probe_port(
    scheme: &str,
    port: u16,
    forced_profile: Option<&str>,
) -> Option<Vec<FoundRoute>> {
    let source = format!("probe:{port}");
    let base = format!("{scheme}://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .connect_timeout(PROBE_TIMEOUT)
        .danger_accept_invalid_certs(scheme == "https")
        .user_agent("sentry-auto (+https://github.com/lucas/sentry)")
        .build()
        .ok()?;

    // Liveness: `/` must answer, otherwise the sentinel gets one chance —
    // a port that accepts TCP but never responds is a tarpit, skip it.
    let mut sentinel = None;
    if fetch(&client, &base, "/").await.is_none() {
        sentinel = fetch(&client, &base, &sentinel_path()).await;
        sentinel.as_ref()?;
    }

    let mut candidates: Vec<String> = vec![
        "/".to_string(),
        "/robots.txt".to_string(),
        "/sitemap.xml".to_string(),
    ];
    candidates.extend(extra_candidates(&client, &base, forced_profile).await);
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|p| seen.insert(p.clone()));
    candidates.truncate(MAX_CANDIDATES_PER_PORT);

    // The sentinel marks catch-all servers: any hit with the same
    // (status, body length) signature is the fallback page, not a route.
    let sentinel = Some(match sentinel {
        Some(resp) => (resp.status, resp.total),
        None => match fetch(&client, &base, &sentinel_path()).await {
            Some(resp) => (resp.status, resp.total),
            None => return Some(Vec::new()),
        },
    });

    let futures = candidates.into_iter().map(|path| {
        let client = client.clone();
        let base = base.clone();
        async move {
            fetch(&client, &base, &path)
                .await
                .map(|resp| (path, resp.status, resp.total))
        }
    });
    let hits: Vec<Hit> = stream::iter(futures)
        .buffer_unordered(PROBE_CONCURRENCY)
        .filter_map(|h| async move { h })
        .collect()
        .await;

    let mut routes: Vec<FoundRoute> = probe::filter_catch_all(sentinel, hits)
        .into_iter()
        .map(|path| FoundRoute::new(path, &[], source.as_str()))
        .collect();
    routes.extend(spec_routes(&client, &base, &source).await);
    Some(routes)
}

/// Fetch every well-known spec location and keep the routes of the first
/// document that parses as OpenAPI/Swagger. Unlike the blind candidates
/// these carry real methods and templates, and a body that parses as a
/// spec cannot be a catch-all page.
async fn spec_routes(client: &reqwest::Client, base: &str, source: &str) -> Vec<FoundRoute> {
    let responses: Vec<(String, ProbeResp)> = stream::iter(probe::SPEC_PATHS.iter().map(|path| {
        let client = client.clone();
        let base = base.to_string();
        async move {
            let resp = fetch_capped(&client, &base, path, SPEC_BODY_CAP).await?;
            (resp.status == 200).then(|| (path.to_string(), resp))
        }
    }))
    .buffered(PROBE_CONCURRENCY)
    .filter_map(|r| async move { r })
    .collect()
    .await;

    for (path, resp) in responses {
        if let Some(routes) =
            sentry_auto::openapi::parse_spec(&resp.body, &format!("{source}{path}"))
        {
            return routes;
        }
    }
    Vec::new()
}

/// Paths discovered off-probe: robots.txt entries, sitemap `<loc>`s and
/// profile-specific signatures.
async fn extra_candidates(
    client: &reqwest::Client,
    base: &str,
    forced_profile: Option<&str>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(name) = forced_profile {
        out.extend(probe::profile_paths(name).iter().map(|s| s.to_string()));
    }
    let robots_resp = match fetch(client, base, "/robots.txt").await {
        Some(r) if probe::status_is_route(r.status) => r,
        _ => return out,
    };
    let robots = probe::parse_robots(&robots_resp.body);
    for path in &robots.paths {
        out.push(sentry_core::routes_learn::normalize_route_path(path));
    }
    for sitemap_url in robots.sitemaps.iter().take(MAX_SITEMAPS) {
        let sitemap_path = probe::url_path(sitemap_url);
        let Some(resp) = fetch(client, base, &sitemap_path).await else {
            continue;
        };
        if !probe::status_is_route(resp.status) {
            continue;
        }
        for loc in probe::parse_sitemap(&resp.body).into_iter().take(50) {
            out.push(probe::url_path(&loc));
        }
    }
    out
}

/// A probe response: status, full transfer size and a body prefix (for
/// robots.txt/sitemap parsing).
struct ProbeResp {
    status: u16,
    total: usize,
    body: String,
}

/// GET a path on the probe base. Body is read up to [`BODY_PREFIX_CAP`];
/// the full transfer size (`total`) feeds the catch-all signature.
async fn fetch(client: &reqwest::Client, base: &str, path: &str) -> Option<ProbeResp> {
    fetch_capped(client, base, path, BODY_PREFIX_CAP).await
}

/// [`fetch`] with a custom body-prefix cap (OpenAPI documents outgrow the
/// default).
async fn fetch_capped(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    cap: usize,
) -> Option<ProbeResp> {
    let resp = client.get(format!("{base}{path}")).send().await.ok()?;
    let status = resp.status().as_u16();
    let mut total = 0usize;
    let mut body = Vec::new();
    let mut resp = resp;
    while total < 4 * cap {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                total += chunk.len();
                if body.len() < cap {
                    let remaining = cap - body.len();
                    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                }
            }
            _ => break,
        }
    }
    Some(ProbeResp {
        status,
        total,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn sentinel_path() -> String {
    format!("/sentry-auto-{}", uuid::Uuid::new_v4().simple())
}

/// System locations where nginx configs live (existence-checked by the
/// detector).
fn nginx_extra_dirs() -> Vec<PathBuf> {
    [
        "/etc/nginx",
        "/usr/local/nginx/conf",
        "/usr/local/etc/nginx",
        "C:/nginx/conf",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// Where `sentry.auto.conf` goes: next to the resolved main config (or
/// inside a config directory), else the best config directory available.
fn auto_file_path(config_path: Option<&str>) -> PathBuf {
    let auto = crate::config::AUTO_FILE;
    if let Some(main) = config_path {
        let main = Path::new(main);
        if main.is_dir() {
            return main.join(auto);
        }
        if let Some(parent) = main.parent() {
            if parent.as_os_str().is_empty() {
                return PathBuf::from(auto);
            }
            return parent.join(auto);
        }
    }
    if Path::new(crate::config::MAIN_FILE).exists() {
        return PathBuf::from(auto);
    }
    let etc = PathBuf::from("/etc/sentry");
    if etc.join(crate::config::MAIN_FILE).exists() {
        return etc.join(auto);
    }
    PathBuf::from(auto)
}

/// Write via temp file + rename so a crash never leaves a truncated auto
/// config.
fn write_atomic(path: &Path, artifacts: &AutoArtifacts) -> color_eyre::Result<()> {
    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, artifacts.to_conf())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn print_tree(root: &Path, files: &[String], verbose: u8) {
    println!(
        "[auto] root {} — {} files walked",
        root.display(),
        files.len()
    );
    let cap = if verbose >= 2 { usize::MAX } else { 200 };
    for f in files.iter().take(cap) {
        println!("  {f}");
    }
    if files.len() > cap {
        println!("  … {} more", files.len() - cap);
    }
}

fn report(artifacts: &AutoArtifacts, profiles: &[FrameworkProfile], verbose: u8) {
    let mut frameworks: Vec<&str> = profiles
        .iter()
        .filter(|p| !p.routes.is_empty())
        .map(|p| p.framework.as_str())
        .collect();
    frameworks.sort_unstable();
    frameworks.dedup();
    if verbose >= 1 {
        for p in profiles {
            if let Some(version) = &p.version {
                println!("[auto] {} {}", p.framework, version);
            }
        }
    }
    println!("frameworks: {}", frameworks.join(", "));
    println!("\n{:<24} PATH", "METHODS");
    for route in &artifacts.routes {
        let methods = if route.methods.is_empty() {
            "*".to_string()
        } else {
            route.methods.join(",")
        };
        println!("{:<24} {}", methods, route.path);
    }
    println!();
    for line in summary_lines(artifacts, profiles) {
        println!("{line}");
    }
}

/// End-of-run totals: routes actually added (deduped, canonical), the
/// per-framework contributions (overlapping frameworks can sum above the
/// total) and the pack/rule suggestions generated alongside.
fn summary_lines(artifacts: &AutoArtifacts, profiles: &[FrameworkProfile]) -> Vec<String> {
    let mut lines = vec![format!(
        "summary: {} routes added, {} pack(s), {} rule(s)",
        artifacts.routes.len(),
        artifacts.packs.len(),
        artifacts.rules.len()
    )];
    let mut by_framework: Vec<(String, usize)> = profiles
        .iter()
        .filter(|p| !p.routes.is_empty())
        .map(|p| (p.framework.clone(), p.routes.len()))
        .collect();
    by_framework.sort();
    for (framework, count) in by_framework {
        lines.push(format!("  {framework:<14} {count} routes"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_lines_totals_routes_and_frameworks() {
        let artifacts = AutoArtifacts {
            routes: vec![
                sentry_core::config::RouteDefConfig {
                    path: "/a".to_string(),
                    methods: Vec::new(),
                },
                sentry_core::config::RouteDefConfig {
                    path: "/b".to_string(),
                    methods: Vec::new(),
                },
            ],
            packs: vec![sentry_core::config::RulePackConfig {
                name: "sensitive_paths".to_string(),
                mode: "enforce".to_string(),
                params: Default::default(),
            }],
            rules: Vec::new(),
        };
        let profiles = vec![
            FrameworkProfile {
                framework: "wordpress".to_string(),
                routes: vec![FoundRoute::new("/wp-login.php", &[], "disk")],
                ..Default::default()
            },
            FrameworkProfile {
                framework: "http-probe".to_string(),
                routes: vec![
                    FoundRoute::new("/", &[], "probe:80"),
                    FoundRoute::new("/robots.txt", &[], "probe:80"),
                ],
                ..Default::default()
            },
        ];
        let lines = summary_lines(&artifacts, &profiles);
        assert_eq!(lines[0], "summary: 2 routes added, 1 pack(s), 0 rule(s)");
        assert!(lines
            .iter()
            .any(|l| l.contains("http-probe") && l.contains("2 routes")));
        assert!(lines
            .iter()
            .any(|l| l.contains("wordpress") && l.contains("1 routes")));
    }

    #[test]
    fn auto_file_path_prefers_config_parent() {
        let path = auto_file_path(Some("/etc/sentry/sentry.conf"));
        assert_eq!(path, PathBuf::from("/etc/sentry/sentry.auto.conf"));
        let bare = auto_file_path(Some("sentry.conf"));
        assert_eq!(bare, PathBuf::from("sentry.auto.conf"));
    }

    #[test]
    fn probe_profile_paths_are_valid() {
        for name in ["wordpress", "laravel", "nextjs", "express", "nginx"] {
            assert!(probe::profile_paths(name)
                .iter()
                .all(|p| p.starts_with('/')));
        }
        assert!(probe::profile_paths("unknown").is_empty());
    }

    #[test]
    fn write_atomic_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("sentry-auto-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("sentry.auto.conf");
        std::fs::write(&target, "old").unwrap();
        let artifacts = AutoArtifacts {
            routes: vec![sentry_core::config::RouteDefConfig {
                path: "/x".to_string(),
                methods: vec!["GET".to_string()],
            }],
            ..Default::default()
        };
        write_atomic(&target, &artifacts).unwrap();
        let content = std::fs::read_to_string(&target).unwrap();
        assert!(content.contains("routes {"), "{content}");
        assert!(content.contains("\"/x\": GET"), "{content}");
        assert!(!dir.join("sentry.auto.conf.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
