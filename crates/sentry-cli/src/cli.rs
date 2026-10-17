//! CLI definition (clap derive).
//!
//! Subcommands map to handlers in [`crate::cmd`].

use clap::{Parser, Subcommand};

/// Sentry — access monitor with AI-powered threat detection.
#[derive(Debug, Parser)]
#[command(name = "sentry", version, about, long_about = None)]
pub struct Cli {
    /// Path to the config file or directory (default: `sentry.conf` in cwd or `/etc/sentry/sentry.conf`).
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
    /// Start the web dashboard + JSON API server (requires Postgres).
    Serve,
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
        /// TUI color theme (`dark`, `light` or `mono`).
        #[arg(long)]
        theme: Option<String>,
        /// Emit one JSON object per event (with `--stream`).
        #[arg(long)]
        json: bool,
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
    /// Inspect and ban client fingerprints (device / TLS / visitor ids).
    Fingerprint {
        #[command(subcommand)]
        action: FingerprintCmd,
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
    /// Manage reputation feeds (Tor exits, blocklists, datasets).
    Feeds {
        #[command(subcommand)]
        action: FeedsCmd,
    },
    /// Manage DB-backed datasets (F7.7): UA/path/JA3 lists that become
    /// synthetic rules and feed the dynamic prefilter.
    Datasets {
        #[command(subcommand)]
        action: DatasetsCmd,
    },
    /// Built-in trusted IP presets (`[real_ip] trusted_lists`).
    Trusted {
        #[command(subcommand)]
        action: TrustedCmd,
    },
    /// Inspect the local firewall ban backends (nftables/ipset/firewalld).
    Firewall {
        #[command(subcommand)]
        action: FirewallCmd,
    },
    /// rDNS bot verification (F7.7): check a claimed crawler IP.
    Bots {
        #[command(subcommand)]
        action: BotsCmd,
    },
    /// Protocol schema validation (F9): compile/inspect YAML protocol
    /// descriptions and test raw frames against them.
    Protocol {
        #[command(subcommand)]
        action: ProtocolCmd,
    },
    /// Auth helpers (hash generation for `[server.auth]`).
    Auth {
        #[command(subcommand)]
        action: AuthCmd,
    },
    /// Manage the OS service (systemd / launchd / Windows Service).
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Check GitHub Releases for a newer sentry binary and swap it in.
    ///
    /// Works regardless of `[update] enabled` (which only gates the
    /// daemon's periodic check).
    Update {
        /// Only compare versions; never download or install.
        #[arg(long)]
        check: bool,
        /// Pin the target release tag (e.g. `v0.2.0`); only applies when
        /// newer than the running binary — no downgrades.
        #[arg(long, value_name = "TAG")]
        version: Option<String>,
        /// GitHub repository override, `owner/name` (default: `[update] repo`).
        #[arg(long, value_name = "OWNER/NAME")]
        repo: Option<String>,
        /// Restart the OS service after the swap (overrides
        /// `[update] auto_restart`).
        #[arg(long, conflicts_with = "no_restart")]
        restart: bool,
        /// Never restart the service (overrides `[update] auto_restart`).
        #[arg(long)]
        no_restart: bool,
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
    /// Web security posture report (F11): missing/weak security headers
    /// observed on the protected site's responses, plus the HTTPS checklist.
    Posture {
        /// Look-back window for observed advisories (e.g. `24h`, `7d`).
        #[arg(long, default_value = "24h")]
        from: String,
        /// Domain(s) for the SPF/DMARC/DKIM DNS audit (default: hosts of the
        /// configured sites).
        #[arg(long = "domain")]
        domains: Vec<String>,
        /// Skip the email-authentication DNS audit.
        #[arg(long)]
        no_email: bool,
    },
    /// Export raw events for SIEM consumption (F4.6).
    Export {
        /// Look-back window (e.g. `24h`, `7d`).
        #[arg(long, default_value = "24h")]
        from: String,
        /// Output format.
        #[arg(long, default_value = "cef")]
        format: String,
        /// Write to a file instead of stdout.
        #[arg(long)]
        out: Option<String>,
        /// Keep tailing new events after the initial window.
        #[arg(long)]
        follow: bool,
        /// Syslog forward target with `--follow` (`udp://host:514` or `tcp://…`).
        #[arg(long)]
        to: Option<String>,
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
    /// Benchmarks (provider evaluation harnesses).
    Bench {
        #[command(subcommand)]
        action: BenchCmd,
    },
    /// Auto-detect frameworks/routes and generate sentry.auto.toml.
    ///
    /// Without a root path, probes the local web service on ports 80/443
    /// and reads server configs from disk. Module flags are opt-in: pass
    /// none to run everything, or one/more to restrict the run.
    Auto {
        /// Project root to scan (instead of the local-service default).
        root: Option<String>,
        /// Force a specific profile (skip detection).
        #[arg(long)]
        profile: Option<String>,
        /// Run only the live HTTP probe (127.0.0.1:80 + :443).
        #[arg(long)]
        probe: bool,
        /// Run only the on-disk config detection (nginx configs etc.).
        #[arg(long)]
        disk: bool,
        /// Scan the whole source tree, not just canonical route files.
        #[arg(long)]
        deep: bool,
        /// Only show what would be detected, don't write sentry.auto.toml.
        #[arg(long)]
        dry_run: bool,
        /// Sensitive-file category added to the scan filter on top of the
        /// defaults (repeatable/comma-separated; e.g. `config`).
        #[arg(long, value_name = "CATEGORY", value_delimiter = ',')]
        category: Vec<String>,
        /// Sensitive-file category removed from the scan filter
        /// (repeatable/comma-separated).
        #[arg(long, value_name = "CATEGORY", value_delimiter = ',')]
        skip_category: Vec<String>,
        /// Drop discovered routes under this path prefix (repeatable/
        /// comma-separated; e.g. `/api` when the backend is mapped
        /// elsewhere). Matches the prefix itself and everything below it.
        #[arg(long, value_name = "PREFIX", value_delimiter = ',')]
        ignore: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum IncidentsCmd {
    /// List recent incidents.
    List {
        /// Include the client IP column.
        #[arg(long)]
        show_ip: bool,
    },
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
pub enum FingerprintCmd {
    /// List active fingerprint bans.
    List,
    /// Rank the most active fingerprints (by flagged IPs, then volume).
    Top {
        /// Id kind to rank: `device`, `tls` or `visitor`.
        #[arg(long, default_value = "device")]
        kind: String,
        /// Look-back window (e.g. `24h`).
        #[arg(long, default_value = "24h")]
        from: String,
        /// Rows to show.
        #[arg(long, default_value_t = 20)]
        limit: i64,
    },
    /// Show how many events/IPs share a fingerprint and whether it is banned.
    Show {
        /// `d-…`, `t-…` or `v-…` id.
        id: String,
        /// Look-back window.
        #[arg(long, default_value = "7d")]
        from: String,
    },
    /// Ban a fingerprint (every node reloads via NOTIFY).
    Ban {
        /// `d-…`, `t-…` or `v-…` id.
        id: String,
        /// Ban lifetime (e.g. `24h`); permanent when omitted.
        #[arg(long)]
        ttl: Option<String>,
        /// Free-text reason.
        #[arg(long)]
        note: Option<String>,
        /// Ban even when the id is shared by many mostly-clean IPs.
        #[arg(long)]
        force: bool,
    },
    /// Lift a fingerprint ban.
    Unban { id: String },
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
pub enum FeedsCmd {
    /// List configured feeds (name, kind, tier, refresh, URL).
    List,
    /// Fetch all feeds once and show entry counts (no daemon needed).
    Refresh,
    /// Refresh feeds, then look up an IP against them.
    Check { ip: String },
}

/// Built-in trusted IP preset commands.
#[derive(Debug, Subcommand)]
pub enum TrustedCmd {
    /// List the bundled presets and whether each is approved in config.
    List,
}

/// DB-backed dataset commands (F7.7).
#[derive(Debug, Subcommand)]
pub enum DatasetsCmd {
    /// List datasets with kind, entry count and enabled state.
    List,
    /// Import a one-entry-per-line list (file path or http(s) URL) as a
    /// named dataset, replacing any previous version of that name.
    Import {
        /// File path or URL.
        path: String,
        /// What the entries match: user_agent, path or ja3.
        #[arg(long, value_enum)]
        kind: DatasetKindArg,
        /// Unique dataset name (the synthetic rule id becomes `dataset:<name>`).
        #[arg(long)]
        name: String,
        /// Action when the synthetic rule matches (allow | block | challenge |
        /// rate_limit | log | tag; default log).
        #[arg(long, default_value = "log")]
        action: String,
        /// Parse and validate only, don't persist.
        #[arg(long)]
        dry_run: bool,
    },
    /// Enable a dataset (running daemons hot-reload on the next notification).
    Enable {
        /// Dataset name.
        name: String,
    },
    /// Disable a dataset without deleting it.
    Disable {
        /// Dataset name.
        name: String,
    },
    /// Delete a dataset.
    Delete {
        /// Dataset name.
        name: String,
    },
    /// Re-fetch every dataset that has a source URL and show the new counts.
    Fetch,
    /// Print or write the built-in sensitive-file categories as dataset
    /// text (one entry per line) ready for a gist plus
    /// `sentry datasets import <raw-url> --kind path`.
    Preset {
        /// List categories with descriptions (default when nothing else is
        /// requested).
        #[arg(long)]
        list: bool,
        /// Print/write only these categories (repeatable; default: all).
        #[arg(long, value_name = "CATEGORY", value_delimiter = ',')]
        category: Vec<String>,
        /// Write `<category>.txt` files into this directory instead of
        /// printing.
        #[arg(long, value_name = "DIR")]
        out: Option<String>,
    },
}

/// Entry kind accepted by `sentry datasets import`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DatasetKindArg {
    /// User-Agent substrings.
    UserAgent,
    /// Path fragments.
    Path,
    /// JA3 fingerprints (lowercase hex).
    Ja3,
}

impl DatasetKindArg {
    /// Storage string for the dataset kind column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserAgent => "user_agent",
            Self::Path => "path",
            Self::Ja3 => "ja3",
        }
    }
}

/// Local firewall ban backend status.
#[derive(Debug, Subcommand)]
pub enum FirewallCmd {
    /// Detect available backends (nftables / ipset / firewalld) and their
    /// privileges; shows live set sizes when a backend responds.
    Status,
}

/// Protocol schema commands (F9).
#[derive(Debug, Subcommand)]
pub enum ProtocolCmd {
    /// Compile every `*.protocol.yaml` in a directory and report errors.
    Validate {
        /// Schema directory (defaults to `[protocol] dir`).
        dir: Option<String>,
    },
    /// List compiled protocols: ports, messages and policies.
    List {
        /// Schema directory (defaults to `[protocol] dir`).
        dir: Option<String>,
    },
    /// Validate one raw frame (hex) against one schema file.
    Check {
        /// Schema file to compile.
        schema: String,
        /// Frame bytes as hex (e.g. 00000024...).
        #[arg(long)]
        hex: String,
    },
}

/// rDNS bot verification commands (F7.7).
#[derive(Debug, Subcommand)]
pub enum BotsCmd {
    /// Verify one IP as a claimed crawler via reverse DNS + forward
    /// confirmation (no daemon needed; uses the system resolver).
    Check {
        /// Client IP to verify.
        ip: String,
        /// User-Agent claiming the bot identity (e.g. "Googlebot/2.1").
        #[arg(long)]
        ua: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthCmd {
    /// Generate an Argon2 password hash for `[[server.auth.users]]`.
    HashPassword {
        /// The plain-text password to hash.
        password: String,
    },
    /// Generate the SHA-256 hex hash of an API token for `[[server.auth.tokens]]`.
    TokenHash {
        /// The raw API token to hash.
        token: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ServiceCmd {
    /// Install and start the system service.
    Install {
        /// System user to run the service as (systemd only).
        #[arg(long)]
        user: Option<String>,
        /// Working directory for the service.
        #[arg(long)]
        workdir: Option<String>,
    },
    /// Stop and remove the system service.
    Uninstall,
    /// Show service install paths + best-effort live status.
    Status,
    /// Stop and start the system service (picks up a swapped binary).
    Restart,
    /// Internal entry point: run under the Windows Service Control Manager.
    #[command(hide = true)]
    Run,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Validate the config files (syntax, schema, routing, references).
    Validate,
    /// Print the resolved config in `sentry.conf` syntax (non-default
    /// values only; `--full` prints every value).
    Show {
        /// Include default values.
        #[arg(long)]
        full: bool,
    },
    /// List the files a load reads (main, conf.d, includes, auto file).
    Files,
    /// Print the value written for a dotted path (`http.compress.enabled`),
    /// or the names inside a block.
    Get {
        /// Dotted path of unlabeled blocks ending in a directive.
        path: String,
    },
    /// Set a value in the config file (keeps comments, validates, backs up
    /// to `<file>.bak`). A running daemon applies rules, routes and http
    /// routing live; other sections report "restart required".
    Set {
        /// Dotted path, e.g. `http.compress.enabled`.
        path: String,
        /// New value (several words are joined; quoted when needed).
        #[arg(required = true, num_args = 1..)]
        value: Vec<String>,
        /// Edit this file instead of the one that defines the key.
        #[arg(long)]
        file: Option<String>,
        /// Show the change without writing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a directive from the config file (the default applies again).
    Unset {
        /// Dotted path, e.g. `http.compress.enabled`.
        path: String,
        /// Edit this file instead of the one that defines the key.
        #[arg(long)]
        file: Option<String>,
        /// Show the change without writing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Validate the files and make a running daemon re-read them now
    /// (it also polls the files and reloads on SIGHUP).
    Reload,
    /// Convert a legacy `sentry.toml` into `sentry.conf` syntax.
    Migrate {
        /// Legacy TOML file.
        input: String,
        /// Write here instead of stdout (refuses to overwrite).
        #[arg(long)]
        out: Option<String>,
    },
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
        /// Label from confirmed incidents (F4.5 feedback) instead of pipeline
        /// verdicts: incident-linked events → 1, everything else → 0.
        #[arg(long)]
        confirmed: bool,
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

#[derive(Debug, Subcommand)]
pub enum BenchCmd {
    /// Compare risk-classification providers (LLM / jev / mock) on latency,
    /// agreement with the heuristic pipeline, output quality and cost.
    Llm {
        /// Comma-separated providers: jev | openrouter | openai | ollama | mock.
        #[arg(long, default_value = "jev,mock")]
        providers: String,
        /// Replay events from an nginx access.log (or .jsonl of events)
        /// instead of the built-in labeled synthetic kit.
        #[arg(long)]
        events: Option<String>,
        /// nginx log_format string for `--events` (default: the first
        /// `[source] type = "nginx"` format from config, else combined).
        #[arg(long)]
        format: Option<String>,
        /// Max events per provider (0 = all).
        #[arg(long, default_value = "0")]
        n: usize,
        /// Concurrent in-flight classify calls per provider.
        #[arg(long, default_value = "4")]
        concurrency: usize,
        /// Write the raw per-call results as JSON to a file.
        #[arg(long)]
        out: Option<String>,
    },
}
