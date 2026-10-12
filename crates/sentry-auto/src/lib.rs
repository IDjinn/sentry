//! sentry-auto: framework detection and route extraction for `sentry auto`.
//!
//! Pure crate: filesystem reads only, no network. Detectors look for
//! framework anchor files (`composer.json`, `package.json`, `wp-config.php`,
//! `nginx.conf`, …) under a project root and extract the routes they
//! declare. The `sentry auto` command (sentry-cli) orchestrates the scan,
//! adds live HTTP probing and generates `sentry.auto.toml` via
//! [`generate`].

#![forbid(unsafe_code)]

pub mod detect;
pub mod generate;
pub mod probe;
pub mod profiles;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sentry_core::pipeline::RouteDef;
use sentry_core::routes_learn::normalize_routes;
use sentry_core::sensitive_files::Filter;

/// Cap for a single file read performed by a detector (route files and
/// configs are small; big files are irrelevant).
pub const MAX_FILE_READ: u64 = 256 * 1024;

/// A route discovered by a detector or by the live probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundRoute {
    /// Route path: exact (`/api/users`), template (`/users/{id}`) or glob
    /// (`/static/*`).
    pub path: String,
    /// Uppercase methods; empty means "any method".
    pub methods: Vec<String>,
    /// Where it came from (file path or probe port), for verbose output.
    pub source: String,
}

impl FoundRoute {
    pub fn new(path: impl Into<String>, methods: &[&str], source: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            methods: methods.iter().map(|m| m.to_string()).collect(),
            source: source.into(),
        }
    }

    /// Like [`FoundRoute::new`] for an already-built method list.
    pub fn new_owned(
        path: impl Into<String>,
        methods: Vec<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            methods,
            source: source.into(),
        }
    }
}

/// A rule pack recommendation from a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSuggestion {
    /// Pack name (`sensitive_paths`, `crawlers_bad`, …).
    pub name: String,
    /// Suggested mode: `shadow` or `enforce`.
    pub mode: String,
}

/// A custom rule recommendation from a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSuggestion {
    /// Rule name (prefixed with the framework for dedupe clarity).
    pub name: String,
    /// Lower number = evaluated first.
    pub priority: i32,
    /// DSL match expression.
    pub match_expr: String,
    /// `allow` | `block` | `challenge` | `rate_limit` | `log` | `tag`.
    pub action: String,
    /// Free-form tags for grouping.
    pub tags: Vec<String>,
}

/// A detected framework and everything it contributes to the generated
/// config.
#[derive(Debug, Clone, Default)]
pub struct FrameworkProfile {
    /// Profile name (`nginx`, `wordpress`, `laravel`, `nextjs`, `express`,
    /// `http-probe`).
    pub framework: String,
    /// Framework version when the manifest declares one.
    pub version: Option<String>,
    pub routes: Vec<FoundRoute>,
    /// Sensitive paths worth protecting (informational; the fixed
    /// `sensitive_paths` pack already covers the common ones).
    pub sensitive_paths: Vec<String>,
    pub recommended_packs: Vec<PackSuggestion>,
    pub recommended_rules: Vec<RuleSuggestion>,
    /// Document roots found in server configs (nginx `root`/`alias`
    /// directives); the CLI chains a framework scan on them.
    pub doc_roots: Vec<PathBuf>,
}

/// A framework detector.
pub trait FrameworkDetector: Send + Sync {
    /// Profile name reported by [`FrameworkProfile::framework`].
    fn name(&self) -> &'static str;

    /// Inspect the scan context; `None` when the framework is not present.
    fn detect(&self, ctx: &ScanContext) -> Option<FrameworkProfile>;
}

/// Options for [`scan`].
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Scan the whole source tree (deeper walk), not just canonical files.
    pub deep: bool,
    /// Run a single detector by name, skipping anchor detection.
    pub forced_profile: Option<String>,
    /// Extra directories searched by the nginx config detector (system
    /// config locations like `/etc/nginx`); tests pass an empty vec.
    pub nginx_extra_dirs: Vec<PathBuf>,
    /// Sensitive-file categories force-added to the walk filter on top of
    /// the defaults (e.g. `config`).
    pub sensitive_extra: Vec<String>,
    /// Sensitive-file categories removed from the walk filter.
    pub sensitive_skip: Vec<String>,
}

/// Result of a [`scan`] pass.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// The scanned root.
    pub root: PathBuf,
    pub profiles: Vec<FrameworkProfile>,
    /// Bounded file walk (relative, `/`-separated, sorted) — used for
    /// verbose output.
    pub files: Vec<String>,
}

/// Scan a project root and return every framework profile found.
pub fn scan(root: &Path, opts: &ScanOptions) -> Result<ScanReport, AutoError> {
    if !root.is_dir() {
        return Err(AutoError::RootNotFound(root.display().to_string()));
    }
    let filter = Filter::from_names(&opts.sensitive_extra, &opts.sensitive_skip)
        .map_err(AutoError::UnknownCategory)?;
    let files = detect::bounded_walk_with(root, opts.deep, &filter);
    let ctx = ScanContext {
        root: root.to_path_buf(),
        deep: opts.deep,
        nginx_extra_dirs: opts.nginx_extra_dirs.clone(),
        files,
    };
    let profiles = match &opts.forced_profile {
        Some(name) => {
            let detector = detect::detectors()
                .into_iter()
                .find(|d| d.name() == name.as_str())
                .ok_or_else(|| AutoError::UnknownProfile(name.clone(), detect::profile_names()))?;
            detector.detect(&ctx).into_iter().collect()
        }
        None => detect::detectors()
            .iter()
            .filter_map(|d| d.detect(&ctx))
            .collect(),
    };
    Ok(ScanReport {
        root: root.to_path_buf(),
        profiles,
        files: ctx.files,
    })
}

/// Errors surfaced by [`scan`].
#[derive(Debug, thiserror::Error)]
pub enum AutoError {
    #[error("root path `{0}` does not exist or is not a directory")]
    RootNotFound(String),
    #[error("unknown profile `{0}` — valid profiles: {}", .1.join(", "))]
    UnknownProfile(String, Vec<String>),
    #[error("{0}")]
    UnknownCategory(String),
}

/// Shared context handed to every detector: the root, the bounded file walk
/// (done once) and the scan options.
pub struct ScanContext {
    /// Absolute (or caller-provided) project root.
    pub root: PathBuf,
    /// Deep scan requested — detectors may widen their file selection.
    pub deep: bool,
    /// Extra directories searched by the nginx config detector.
    pub nginx_extra_dirs: Vec<PathBuf>,
    /// Files from the bounded walk, relative to `root`, `/`-separated,
    /// sorted.
    pub files: Vec<String>,
}

impl ScanContext {
    /// True when the walk contains `rel` (e.g. `composer.json`).
    pub fn has(&self, rel: &str) -> bool {
        self.files.iter().any(|f| f == rel)
    }

    /// All walked files matching a predicate over their `/`-separated
    /// relative path.
    pub fn matching(&self, pred: impl Fn(&str) -> bool) -> Vec<String> {
        self.files.iter().filter(|f| pred(f)).cloned().collect()
    }

    /// Read a walked file (relative to root), capped at [`MAX_FILE_READ`].
    pub fn read(&self, rel: &str) -> std::io::Result<String> {
        read_capped(&self.root.join(rel), MAX_FILE_READ)
    }
}

/// Normalize a set of found routes the same way config routes are
/// normalized: dedupe by path, merge methods (empty = any method wins).
/// The source label of the first occurrence is kept.
pub fn normalize_found(routes: Vec<FoundRoute>) -> Vec<FoundRoute> {
    let mut sources: HashMap<String, String> = HashMap::new();
    let defs: Vec<RouteDef> = routes
        .into_iter()
        .map(|r| {
            sources
                .entry(r.path.clone())
                .or_insert_with(|| r.source.clone());
            RouteDef {
                path: r.path,
                methods: r.methods,
            }
        })
        .collect();
    normalize_routes(defs)
        .into_iter()
        .map(|d| FoundRoute {
            source: sources.get(&d.path).cloned().unwrap_or_default(),
            path: d.path,
            methods: d.methods,
        })
        .collect()
}

/// Read a file as UTF-8 (lossy), truncated to `cap` bytes.
pub fn read_capped(path: &Path, cap: u64) -> std::io::Result<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)?.take(cap).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
