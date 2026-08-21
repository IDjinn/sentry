//! CLI definition (clap derive).
//!
//! Subcommands map to handlers in [`crate::cmd`].

use clap::{Parser, Subcommand};

/// Sentry — access monitor with AI-powered threat detection.
#[derive(Debug, Parser)]
#[command(name = "sentry", version, about, long_about = None)]
pub struct Cli {
    /// Path to the config file (default: `sentry.toml` in cwd or `/etc/sentry/sentry.toml`).
    #[arg(long, global = true, env = "SENTRY_CONFIG")]
    pub config: Option<String>,

    /// Increase verbosity (`-v` info, `-vv` debug, `-vvv` trace).
    #[arg(long, short = 'v', action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the monitor daemon (foreground).
    Run,
    /// Live tail of events.
    Tail {
        /// Filter by risk levels (comma-separated, e.g. `High,Critical`).
        #[arg(long)]
        only: Option<String>,
        /// Force TUI fullscreen mode (default when TTY).
        #[arg(long)]
        tui: bool,
        /// Force non-interactive stream mode.
        #[arg(long)]
        stream: bool,
    },
    /// Manage incidents.
    Incidents {
        #[command(subcommand)]
        action: IncidentsCmd,
    },
    /// Inspect or block/unblock an IP.
    Ip {
        ip: String,
        #[command(subcommand)]
        action: Option<IpCmd>,
    },
    /// Manage known routes.
    Routes {
        #[command(subcommand)]
        action: RoutesCmd,
    },
    /// Manage rules (blacklist/allowlist/packs).
    Rules {
        #[command(subcommand)]
        action: RulesCmd,
    },
    /// Generate aggregate reports.
    Report {
        /// Time window (e.g. `24h`, `7d`).
        #[arg(long, default_value = "24h")]
        from: String,
        /// Export format.
        #[arg(long)]
        export: Option<String>,
        /// List top unknown paths (candidates for `[[routes.known]]`).
        #[arg(long)]
        unknown_paths: bool,
    },
    /// Show or validate configuration.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Model management (ONNX threat model).
    Model {
        #[command(subcommand)]
        action: ModelCmd,
    },
    /// Cloudflare integration.
    Cloudflare {
        #[command(subcommand)]
        action: CloudflareCmd,
    },
    /// Run the pipeline on a single payload (dry run).
    Test {
        /// Payload string to analyze.
        payload: String,
        /// Simulated path.
        #[arg(long, default_value = "/")]
        path: String,
        /// Simulated method.
        #[arg(long, default_value = "GET")]
        method: String,
    },
    /// Auto-detect framework and generate rules/routes (zero-config).
    Auto {
        /// Project root (default: current directory).
        #[arg(long)]
        root: Option<String>,
        /// Force a specific profile (skip detection).
        #[arg(long)]
        profile: Option<String>,
        /// Only show what would be detected, don't write.
        #[arg(long)]
        dry_run: bool,
        /// Merge into existing sentry.toml instead of writing sentry.auto.toml.
        #[arg(long)]
        merge: bool,
        /// Deep scan: AST-parse route files (slower, precise).
        #[arg(long)]
        deep: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum IncidentsCmd {
    /// List recent incidents.
    List,
    /// Show details of a specific incident.
    Show { id: String },
}

#[derive(Debug, Subcommand)]
pub enum IpCmd {
    /// Block an IP.
    Block {
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Unblock an IP.
    Unblock,
    /// Show full history of an IP.
    Info,
    /// Reset the strike counters (offender memory) for an IP.
    Forgive,
}

#[derive(Debug, Subcommand)]
pub enum RoutesCmd {
    /// List known routes.
    List,
    /// Start baseline learning mode.
    Learn {
        /// Dry-run: only print inferred routes, don't persist them.
        #[arg(long)]
        dry_run: bool,
        /// Minimum hits for a route shape to be considered stable.
        #[arg(long, default_value = "10")]
        min_hits: u32,
        /// Minimum number of distinct IPs that hit the shape.
        #[arg(long, default_value = "2")]
        min_ips: u32,
    },
    /// Import routes from an OpenAPI/Swagger/Postman/HAR spec.
    Import {
        /// Path to the spec file (JSON or YAML).
        path: String,
        /// Force a format instead of auto-detecting.
        #[arg(long, value_enum)]
        format: Option<crate::routes_import::ImportFormat>,
        /// Dry-run: parse and report what would be imported, don't persist.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RulesCmd {
    /// List rules.
    List,
    /// Show a specific rule.
    Show { id: String },
    /// Add a rule.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        r#match: String,
        #[arg(long)]
        action: String,
        #[arg(long, default_value = "100")]
        priority: i32,
    },
    /// Allow an IP (allowlist).
    Allow {
        ip: String,
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Block an IP (blacklist).
    Block {
        ip: String,
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Enable a rule.
    Enable { id: String },
    /// Disable a rule.
    Disable { id: String },
    /// Delete a rule.
    Delete { id: String },
    /// List default rule packs and their state.
    Packs,
    /// Test which rules would match a given request shape.
    Test {
        #[arg(long, default_value = "/")]
        path: String,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        ua: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Validate the config file.
    Validate,
    /// Print the resolved config.
    Show,
}

#[derive(Debug, Subcommand)]
pub enum ModelCmd {
    /// Show model status (provider, model file, threshold).
    Status,
    /// Reload the model from disk.
    Reload,
    /// Export training features from stored events as CSV.
    Export {
        /// Look-back window in hours (default 30 days).
        #[arg(long, default_value = "720")]
        hours: u64,
        /// Output CSV path (default `dataset.csv` in cwd).
        #[arg(long, default_value = "dataset.csv")]
        out: String,
        /// Generate a synthetic seed dataset instead of reading Postgres
        /// (no storage required; features still extracted by Rust).
        #[arg(long)]
        synthetic: bool,
        /// Row count for `--synthetic` (default 4000, half benign).
        #[arg(long, default_value = "4000")]
        rows: u64,
    },
}

#[derive(Debug, Subcommand)]
pub enum CloudflareCmd {
    /// Show Cloudflare sync status (token validity, zone, rule count).
    Status,
    /// Verify the token + zone without making changes (dry-run).
    Test,
    /// Pull existing logs (best-effort Logpull / GraphQL).
    Pull,
}
