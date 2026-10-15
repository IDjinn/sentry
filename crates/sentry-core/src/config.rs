//! Configuration schema (serde structs) for `sentry.toml`.
//!
//! Loading (figment, env overlay) lives in `sentry-cli`; this module only
//! defines the typed shape so it can be shared with tests and the daemon
//! without pulling figment into the core.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentryConfig {
    /// Core runtime settings.
    #[serde(default)]
    pub core: CoreConfig,
    /// Storage backend.
    #[serde(default)]
    pub storage: StorageConfig,
    /// Geo/ASN enrichment.
    #[serde(default)]
    pub geo: GeoConfig,
    /// LLM provider.
    #[serde(default)]
    pub llm: LlmConfig,
    /// Rules engine.
    #[serde(default)]
    pub rules: RulesConfig,
    /// Known routes for the route validator.
    #[serde(default)]
    pub routes: RoutesConfig,
    /// Scorer weights and repetition bonus.
    #[serde(default)]
    pub scorer: ScorerConfig,
    /// Verdict policy (decider stage).
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Repeat-offender strike escalation.
    #[serde(default)]
    pub escalation: EscalationConfig,
    /// Behavioral scan detection (random-path / 404 sweeps).
    #[serde(default)]
    pub scan: ScanConfig,
    /// Behavioral attack detection (auth brute-force, credential stuffing,
    /// directory brute-force).
    #[serde(default)]
    pub behavior: BehaviorConfig,
    /// Cross-IP scan→attack correlation (F3.10).
    #[serde(default)]
    pub correlation: CorrelationConfig,
    /// rDNS bot verification (F7.7).
    #[serde(default)]
    pub bot_verification: BotVerificationConfig,
    /// Local ML threat model (async fork stage).
    #[serde(default)]
    pub ai: AiConfig,
    /// Rate-limit backend for `RuleMatch::Rate` conditions.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Prometheus metrics server.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Web dashboard + JSON API server (`sentry serve`).
    #[serde(default)]
    pub server: ServerConfig,
    /// Background route learner.
    #[serde(default)]
    pub route_learner: RouteLearnerConfig,
    /// Deployment positioning (passive | inline) (F3.9).
    #[serde(default)]
    pub deployment: DeploymentConfig,
    /// Inline edge settings (used when deployment.mode = "inline").
    #[serde(default)]
    pub edge: EdgeConfig,
    /// Real client IP resolution, trusted proxies and never-ban IPs (F7.2).
    #[serde(default)]
    pub real_ip: RealIpConfig,
    /// On-demand external IP reputation lookup (F7.5).
    #[serde(default)]
    pub ip_lookup: IpLookupConfig,
    /// Protocol schema validation (F9).
    #[serde(default)]
    pub protocol: ProtocolConfig,
    /// Request-body/upload inspection (F10, inline edge only).
    #[serde(default)]
    pub uploads: UploadsConfig,
    /// Web security posture advisories (F11, inline edge only).
    #[serde(default)]
    pub posture: PostureConfig,
    /// Overload response: measured pressure → tiered degradation of
    /// telemetry (persistence/eventlog/print). Detection and containment
    /// never degrade.
    #[serde(default)]
    pub overload: OverloadConfig,
    /// `sentry auto` command settings (framework scan).
    #[serde(default)]
    pub auto: AutoConfig,
    /// Binary self-update (F13): daemon version check + `sentry update`.
    #[serde(default)]
    pub update: UpdateConfig,
    /// Tokio runtime tuning (F14): worker threads, CPU pinning, priority.
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Event sources.
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceConfig>,
    /// Response actions.
    #[serde(default, rename = "action")]
    pub actions: Vec<ActionConfig>,
}

/// `sentry auto` command settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoConfig {
    /// Sensitive-file category filter for the disk scan.
    #[serde(default)]
    pub sensitive: AutoSensitiveConfig,
}

/// Sensitive-file categories for the `sentry auto` walk: the built-in
/// defaults apply (every category but `config`), `enable` adds opt-in
/// categories and `skip` removes defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutoSensitiveConfig {
    /// Category names removed from the default walk filter.
    #[serde(default)]
    pub skip: Vec<String>,
    /// Category names added on top of the default walk filter (e.g.
    /// `config`).
    #[serde(default)]
    pub enable: Vec<String>,
}

/// Binary self-update settings (F13).
///
/// `[update] enabled = false` only turns off the daemon's periodic version
/// check; the manual `sentry update` command always works regardless.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Periodic version check in the daemon (logs only — never downloads or
    /// applies anything).
    #[serde(default = "default_update_enabled")]
    pub enabled: bool,
    /// Seconds between daemon checks (clamped to a 300s floor by
    /// `validate`).
    #[serde(default = "default_update_interval_secs")]
    pub interval_secs: u64,
    /// GitHub repository (`owner/name`) releases are fetched from.
    #[serde(default = "default_update_repo")]
    pub repo: String,
    /// `sentry update` restarts the OS service after swapping the binary.
    #[serde(default)]
    pub auto_restart: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: default_update_enabled(),
            interval_secs: default_update_interval_secs(),
            repo: default_update_repo(),
            auto_restart: false,
        }
    }
}

impl UpdateConfig {
    /// Cross-field validation surfaced by `sentry config validate`.
    pub fn validate(&self) -> Result<(), String> {
        if self.repo.is_empty() {
            return Err("[update] repo must not be empty".to_string());
        }
        let slashes = self.repo.matches('/').count();
        if slashes != 1 || self.repo.split('/').any(|p| p.is_empty()) {
            return Err(format!(
                "[update] repo must be `owner/name`, got {:?}",
                self.repo
            ));
        }
        if self.enabled && self.interval_secs < 300 {
            return Err(
                "[update] interval_secs must be >= 300 (protect the GitHub API rate limit)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn default_update_enabled() -> bool {
    true
}

fn default_update_interval_secs() -> u64 {
    86_400
}

fn default_update_repo() -> String {
    "IDjinn/sentry".to_string()
}

/// Core runtime settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Data directory for MMDB files, models, cache.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Event channel buffer size.
    #[serde(default = "default_channel_buffer")]
    pub channel_buffer: usize,
    /// Capacity of the deferred action queue (post-processing workers).
    /// Under overload this queue fills first, shedding actions — never
    /// events.
    #[serde(default = "default_action_buffer")]
    pub action_buffer: usize,
    /// Parallel workers executing deferred (network-bound) actions.
    /// `1` preserves strict action ordering and tight incident coalescing.
    #[serde(default = "default_action_workers")]
    pub action_workers: usize,
    /// Capacity of the bounded persistence queue. The persist worker drains
    /// it in batches (one multi-row INSERT per batch); when it fills under
    /// overload, low-priority events are shed while security events fall
    /// back to direct writes.
    #[serde(default = "default_persist_buffer")]
    pub persist_buffer: usize,
    /// Ingest dedupe window in seconds: identical (ip, method, path) events
    /// within the window are dropped before the pipeline.
    #[serde(default = "default_dedupe_ttl_secs")]
    pub dedupe_ttl_secs: u64,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            channel_buffer: default_channel_buffer(),
            action_buffer: default_action_buffer(),
            action_workers: default_action_workers(),
            persist_buffer: default_persist_buffer(),
            dedupe_ttl_secs: default_dedupe_ttl_secs(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/sentry")
}

fn default_channel_buffer() -> usize {
    4096
}

fn default_action_buffer() -> usize {
    4096
}

fn default_action_workers() -> usize {
    1
}

fn default_persist_buffer() -> usize {
    2048
}

fn default_dedupe_ttl_secs() -> u64 {
    10
}

/// Overload response settings: measured pressure (queue occupancy, Postgres
/// write latency) switches the daemon into tiered degradation — telemetry
/// (persistence, eventlog, console print, benign forks) yields first.
/// Detection (pipeline) and containment (block table, actions) never yield.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverloadConfig {
    /// Master switch for pressure detection and the degradation tiers.
    #[serde(default = "default_overload_enabled")]
    pub enabled: bool,
    /// Fan-in/action/persist queue occupancy (0.0-1.0) that turns pressure
    /// on.
    #[serde(default = "default_queue_pressure")]
    pub queue_pressure: f64,
    /// Occupancy below which pressure turns off again (hysteresis).
    #[serde(default = "default_release_pressure")]
    pub release_pressure: f64,
    /// Seconds the release condition must hold before pressure clears.
    #[serde(default = "default_release_secs")]
    pub release_secs: u64,
    /// Postgres INSERT latency EMA (ms) that turns pressure on by itself —
    /// catches a slow/saturated database even when the queues are calm.
    #[serde(default = "default_pg_insert_budget_ms")]
    pub pg_insert_budget_ms: u64,
    /// Fraction (0.0-1.0) of low-priority events (Allow, below High) kept
    /// while under pressure — deterministic per source IP, so an IP is
    /// either consistently in or consistently out of the sample.
    #[serde(default = "default_sample_keep")]
    pub sample_keep: f64,
    /// Collapse repeated benign requests (Allow, GET, no signals) per
    /// (ip, path) into the first hit of each window; repeats are counted in
    /// `sentry_coalesced_requests_total` instead of persisted/printed.
    #[serde(default = "default_coalesce_benign")]
    pub coalesce_benign: bool,
    /// Window for benign coalescing.
    #[serde(default = "default_coalesce_window_secs")]
    pub coalesce_window_secs: u64,
    /// Max tracked (ip, path) buckets; oldest bucket is evicted beyond it.
    #[serde(default = "default_coalesce_cap")]
    pub coalesce_cap: usize,
}

impl Default for OverloadConfig {
    fn default() -> Self {
        Self {
            enabled: default_overload_enabled(),
            queue_pressure: default_queue_pressure(),
            release_pressure: default_release_pressure(),
            release_secs: default_release_secs(),
            pg_insert_budget_ms: default_pg_insert_budget_ms(),
            sample_keep: default_sample_keep(),
            coalesce_benign: default_coalesce_benign(),
            coalesce_window_secs: default_coalesce_window_secs(),
            coalesce_cap: default_coalesce_cap(),
        }
    }
}

fn default_overload_enabled() -> bool {
    true
}

fn default_queue_pressure() -> f64 {
    0.8
}

fn default_release_pressure() -> f64 {
    0.5
}

fn default_release_secs() -> u64 {
    30
}

fn default_pg_insert_budget_ms() -> u64 {
    250
}

fn default_sample_keep() -> f64 {
    0.1
}

fn default_coalesce_benign() -> bool {
    true
}

fn default_coalesce_window_secs() -> u64 {
    60
}

fn default_coalesce_cap() -> usize {
    4096
}

/// Storage backend selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Postgres connection settings.
    #[serde(default)]
    pub postgres: PostgresConfig,
}

/// Postgres connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// `postgres://user:pass@host:port/db`
    #[serde(default)]
    pub url: String,
    /// Max connections in the pool.
    #[serde(default = "default_pg_max_conn")]
    pub max_connections: u32,
    /// Seconds waiting for a free pool connection before the query fails
    /// fast instead of piling up (default 5; sqlx default is 30).
    #[serde(default = "default_pg_acquire_timeout")]
    pub acquire_timeout_secs: u64,
    /// Seconds a single INSERT may run before it is cancelled and the
    /// batch dropped (default 30). Keeps a saturated Postgres from stalling
    /// the persist worker indefinitely while batch memory stays allocated.
    #[serde(default = "default_pg_statement_timeout")]
    pub statement_timeout_secs: u64,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: default_pg_max_conn(),
            acquire_timeout_secs: default_pg_acquire_timeout(),
            statement_timeout_secs: default_pg_statement_timeout(),
        }
    }
}

fn default_pg_max_conn() -> u32 {
    10
}

fn default_pg_acquire_timeout() -> u64 {
    5
}

fn default_pg_statement_timeout() -> u64 {
    30
}

/// Geo/ASN enrichment config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    /// Path to the GeoLite2-City database file.
    #[serde(default = "default_geo_city_db")]
    pub city_db: PathBuf,
    /// Path to the GeoLite2-ASN database file.
    #[serde(default = "default_geo_asn_db")]
    pub asn_db: PathBuf,
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            city_db: default_geo_city_db(),
            asn_db: default_geo_asn_db(),
        }
    }
}

fn default_geo_city_db() -> PathBuf {
    PathBuf::from("/var/lib/sentry/GeoLite2-City.mmdb")
}

fn default_geo_asn_db() -> PathBuf {
    PathBuf::from("/var/lib/sentry/GeoLite2-ASN.mmdb")
}

/// Known routes for the route validator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutesConfig {
    /// Known routes (exact path or glob like `/api/*`).
    #[serde(default)]
    pub known: Vec<RouteDefConfig>,
}

/// A single known route definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteDefConfig {
    /// Path pattern (exact or glob like `/api/*`).
    pub path: String,
    /// Allowed methods (empty = any).
    #[serde(default)]
    pub methods: Vec<String>,
}

/// Scorer config: signal weights and repetition bonus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorerConfig {
    /// Override weights for specific signal kinds (key = signal name, e.g. `"sql_injection"`).
    #[serde(default)]
    pub weights: HashMap<String, u8>,
    /// Whether to apply a repetition bonus for repeated signals in a time window.
    #[serde(default = "default_repetition_bonus")]
    pub repetition_bonus: bool,
    /// Sliding window duration in seconds for repetition tracking.
    #[serde(default = "default_repetition_window")]
    pub repetition_window_secs: u64,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            weights: HashMap::new(),
            repetition_bonus: default_repetition_bonus(),
            repetition_window_secs: default_repetition_window(),
        }
    }
}

fn default_repetition_bonus() -> bool {
    true
}

fn default_repetition_window() -> u64 {
    60
}

/// Verdict policy: level → verdict mapping plus ordered overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Verdict for Info events (default `allow`).
    #[serde(default = "default_policy_allow")]
    pub info: String,
    /// Verdict for Low events (default `allow`).
    #[serde(default = "default_policy_allow")]
    pub low: String,
    /// Verdict for Medium events (default `rate_limit`).
    #[serde(default = "default_policy_rate_limit")]
    pub medium: String,
    /// Verdict for High events (default `challenge`).
    #[serde(default = "default_policy_challenge")]
    pub high: String,
    /// Verdict for Critical events (default `block`).
    #[serde(default = "default_policy_block")]
    pub critical: String,
    /// Ordered overrides: first DSL expression matching the event wins.
    #[serde(default, rename = "override")]
    pub overrides: Vec<PolicyOverrideConfig>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            info: default_policy_allow(),
            low: default_policy_allow(),
            medium: default_policy_rate_limit(),
            high: default_policy_challenge(),
            critical: default_policy_block(),
            overrides: Vec::new(),
        }
    }
}

/// A single policy override: DSL match expression → forced verdict.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyOverrideConfig {
    /// DSL match expression (same syntax as `rules.custom`).
    pub r#match: String,
    /// Verdict to force: `allow` | `rate_limit` | `challenge` | `block` | `quarantine`.
    pub verdict: String,
}

fn default_policy_allow() -> String {
    "allow".to_string()
}
fn default_policy_rate_limit() -> String {
    "rate_limit".to_string()
}
fn default_policy_challenge() -> String {
    "challenge".to_string()
}
fn default_policy_block() -> String {
    "block".to_string()
}

/// Repeat-offender escalation: per-IP strikes that climb the verdict ladder.
///
/// Every event whose final verdict is not `Allow` records one strike for the
/// client IP. Strikes accumulate over `window_secs` (which should outlive the
/// edge-action TTL, e.g. Cloudflare access rules) so a returning offender is
/// re-blocked on its first violating event instead of starting from zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Enable strike-based verdict escalation.
    #[serde(default = "default_escalation_enabled")]
    pub enabled: bool,
    /// Strikes expire this many seconds after the last violation.
    #[serde(default = "default_escalation_window")]
    pub window_secs: u64,
    /// Strikes needed to escalate a non-Allow verdict to at least `challenge`.
    #[serde(default = "default_escalation_challenge_at")]
    pub challenge_at: u32,
    /// Strikes needed to escalate a non-Allow verdict to `block`.
    #[serde(default = "default_escalation_block_at")]
    pub block_at: u32,
    /// Mirror strikes to the `ip_state` table (Postgres) and pre-warm the
    /// in-memory tracker from it on startup.
    #[serde(default = "default_escalation_persist")]
    pub persist: bool,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            enabled: default_escalation_enabled(),
            window_secs: default_escalation_window(),
            challenge_at: default_escalation_challenge_at(),
            block_at: default_escalation_block_at(),
            persist: default_escalation_persist(),
        }
    }
}

fn default_escalation_enabled() -> bool {
    true
}
fn default_escalation_window() -> u64 {
    604_800 // 7 days — outlives the default 24h edge-action TTL
}
fn default_escalation_challenge_at() -> u32 {
    3
}
fn default_escalation_block_at() -> u32 {
    5
}
fn default_escalation_persist() -> bool {
    true
}

/// Behavioral scan detection over per-IP sliding windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Enable the scan trackers.
    #[serde(default = "default_scan_enabled")]
    pub enabled: bool,
    /// Sliding window duration in seconds.
    #[serde(default = "default_scan_window")]
    pub window_secs: u64,
    /// Distinct 4xx paths per IP in the window that trigger `RandomScan`.
    #[serde(default = "default_scan_distinct_paths")]
    pub distinct_paths: u32,
    /// Total 4xx responses per IP in the window that trigger `ScanBehavior`.
    #[serde(default = "default_scan_not_found")]
    pub not_found: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enabled: default_scan_enabled(),
            window_secs: default_scan_window(),
            distinct_paths: default_scan_distinct_paths(),
            not_found: default_scan_not_found(),
        }
    }
}

fn default_scan_enabled() -> bool {
    true
}
fn default_scan_window() -> u64 {
    60
}
fn default_scan_distinct_paths() -> u32 {
    8
}
fn default_scan_not_found() -> u32 {
    10
}

/// Cross-IP scan→attack correlation windows (F3.10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Enable the correlation tracker.
    #[serde(default = "default_correlation_enabled")]
    pub enabled: bool,
    /// An attack from IP B only correlates with a scan from a *different*
    /// IP in the same /24 (IPv4), /64 (IPv6) or ASN observed this many
    /// seconds ago.
    #[serde(default = "default_correlation_window")]
    pub window_secs: u64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: default_correlation_enabled(),
            window_secs: default_correlation_window(),
        }
    }
}

fn default_correlation_enabled() -> bool {
    true
}
fn default_correlation_window() -> u64 {
    900 // 15 minutes — the honeypot shot-calling window
}

/// rDNS forward-confirmed bot verification (F7.7): UA claims of known
/// crawlers (Googlebot, bingbot, …) are validated via reverse DNS + forward
/// confirmation; verified bots can bypass edge challenges, spoofed claims
/// raise the risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotVerificationConfig {
    /// Enable verification (off by default; requires DNS resolution).
    #[serde(default)]
    pub enabled: bool,
    /// TTL for verified results (per IP).
    #[serde(default = "default_bv_cache_ttl")]
    pub cache_ttl_secs: u64,
    /// Shorter TTL for failed (spoofed) results so bots recover quickly
    /// from transient DNS outages.
    #[serde(default = "default_bv_failed_ttl")]
    pub failed_ttl_secs: u64,
    /// Timeout for one PTR+A verification round.
    #[serde(default = "default_bv_timeout")]
    pub timeout_ms: u64,
    /// Maximum claims verified per background drain cycle.
    #[serde(default = "default_bv_batch")]
    pub batch_size: usize,
}

impl Default for BotVerificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_ttl_secs: default_bv_cache_ttl(),
            failed_ttl_secs: default_bv_failed_ttl(),
            timeout_ms: default_bv_timeout(),
            batch_size: default_bv_batch(),
        }
    }
}

fn default_bv_cache_ttl() -> u64 {
    3600
}
fn default_bv_failed_ttl() -> u64 {
    600
}
fn default_bv_timeout() -> u64 {
    2000
}
fn default_bv_batch() -> usize {
    16
}

/// Real client IP resolution and trusted infrastructure (F7.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealIpConfig {
    /// Proxy CIDRs/IPs allowed to set header-borne client IPs
    /// (`CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, XFF). Header
    /// candidates from any other peer are ignored (spoof guard).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Include the bundled Cloudflare ranges in the trusted proxies
    /// (refreshed from cloudflare.com/ips-v4|ips-v6 in the background).
    #[serde(default = "default_real_ip_cloudflare")]
    pub cloudflare: bool,
    /// Clients never to ban, block or report (admins, uptime probes) —
    /// the nginx-honeypot `TRUSTED_IPS`. They score as
    /// `ReputationTier::Authorized` and short-circuit the pipeline to
    /// `Allow`.
    #[serde(default)]
    pub trusted_ips: Vec<String>,
    /// Built-in trusted IP presets (see `trusted_lists::PRESETS`) to
    /// approve by name — e.g. `["paypal", "googlebot"]`. Approved presets
    /// join the never-ban set with the same guarantees as `trusted_ips`.
    #[serde(default)]
    pub trusted_lists: Vec<String>,
    /// Whitelist: allow everything, never ban/block/report. Merged with
    /// `trusted_ips`/`trusted_lists` into the same never-ban set.
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// Blacklist: deny immediately — the pipeline short-circuits to `Block`
    /// (sticky via the block table, kernel bans, edge actions) before any
    /// detector runs.
    #[serde(default)]
    pub blacklist: Vec<String>,
    /// Shadow: traffic is fully processed — logged, scored, heuristics/
    /// rules/AI/LLM all run — but the verdict is capped so the IP is never
    /// banned or blocked (`Block`/`Quarantine` downgrade to `Challenge`).
    #[serde(default)]
    pub shadow: Vec<String>,
    /// Cloudflare ranges refresh interval in seconds (0 disables refresh;
    /// the bundled constants stay in effect).
    #[serde(default = "default_real_ip_refresh")]
    pub refresh_secs: u64,
}

impl Default for RealIpConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            cloudflare: default_real_ip_cloudflare(),
            trusted_ips: Vec::new(),
            trusted_lists: Vec::new(),
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            shadow: Vec::new(),
            refresh_secs: default_real_ip_refresh(),
        }
    }
}

fn default_real_ip_cloudflare() -> bool {
    true
}

fn default_real_ip_refresh() -> u64 {
    86400
}

/// On-demand external IP reputation lookup (F7.5): queries a provider
/// (AbuseIPDB `/check`) for IPs in the "gray band" — local risk score
/// elevated but not yet acted on — or carrying configured suspicious
/// signals, then feeds the provider's confidence score back through
/// `rescore_from` (which only ever raises the verdict).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupConfig {
    /// Enable the lookup fork (off by default — it consumes provider quota).
    #[serde(default)]
    pub enabled: bool,
    /// Provider name (`abuseipdb`).
    #[serde(default = "default_ip_lookup_provider")]
    pub provider: String,
    /// Env var carrying the provider API key.
    #[serde(default = "default_ip_lookup_key_env")]
    pub key_env: String,
    /// Look up IPs whose local risk score is at least this (0-100) but whose
    /// verdict is not yet `Block`.
    #[serde(default = "default_ip_lookup_trigger_above")]
    pub trigger_above: u8,
    /// Additional trigger: event carries any of these signal kinds
    /// (snake_case names, e.g. `"sensitive_path"`). Empty = score band only.
    #[serde(default)]
    pub on_signals: Vec<String>,
    /// Per-IP result cache TTL in seconds.
    #[serde(default = "default_ip_lookup_cache_ttl")]
    pub cache_ttl_secs: u64,
    /// Provider quota guard: at most this many lookups per rolling hour.
    #[serde(default = "default_ip_lookup_max_per_hour")]
    pub max_per_hour: u32,
    /// Per-request timeout in seconds.
    #[serde(default = "default_ip_lookup_timeout")]
    pub timeout_secs: u64,
}

impl Default for IpLookupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_ip_lookup_provider(),
            key_env: default_ip_lookup_key_env(),
            trigger_above: default_ip_lookup_trigger_above(),
            on_signals: Vec::new(),
            cache_ttl_secs: default_ip_lookup_cache_ttl(),
            max_per_hour: default_ip_lookup_max_per_hour(),
            timeout_secs: default_ip_lookup_timeout(),
        }
    }
}

fn default_ip_lookup_provider() -> String {
    "abuseipdb".to_string()
}
fn default_ip_lookup_key_env() -> String {
    "SENTRY_ABUSEIPDB_KEY".to_string()
}
fn default_ip_lookup_trigger_above() -> u8 {
    25
}
fn default_ip_lookup_cache_ttl() -> u64 {
    86400
}
fn default_ip_lookup_max_per_hour() -> u32 {
    500
}
fn default_ip_lookup_timeout() -> u64 {
    10
}

/// Protocol schema validation (F9): compiles YAML protocol descriptions
/// and validates frames on non-standard ports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Enable the protocol validator (off by default).
    #[serde(default)]
    pub enabled: bool,
    /// Directory holding `*.protocol.yaml` schemas (watched for live
    /// add/modify/remove).
    #[serde(default = "default_protocol_dir")]
    pub dir: PathBuf,
    /// Safety rescan interval in seconds (catches fs-event losses).
    #[serde(default = "default_protocol_safety_poll_secs")]
    pub safety_poll_secs: u64,
    /// Debounce window in milliseconds coalescing fs events before a
    /// full-directory rescan.
    #[serde(default = "default_protocol_debounce_ms")]
    pub debounce_ms: u64,
    /// Max compiled schemas accepted from the directory.
    #[serde(default = "default_protocol_max_schemas")]
    pub max_schemas: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_protocol_dir(),
            safety_poll_secs: default_protocol_safety_poll_secs(),
            debounce_ms: default_protocol_debounce_ms(),
            max_schemas: default_protocol_max_schemas(),
        }
    }
}

fn default_protocol_dir() -> PathBuf {
    PathBuf::from("schemas")
}
fn default_protocol_safety_poll_secs() -> u64 {
    60
}
fn default_protocol_debounce_ms() -> u64 {
    500
}
fn default_protocol_max_schemas() -> usize {
    64
}

/// What happens to a request body larger than `inspect_kb` (F12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OversizePolicy {
    /// Refuse with 413 (default — keeps the memory ceiling at
    /// concurrent requests × `inspect_kb`).
    #[default]
    Reject,
    /// Forward the body uninspected — no parsing, no signals.
    Skip,
    /// Forward the body uninspected but raise `UploadOversize`
    /// (weight-0 in shadow mode) and count the volume in the flood window.
    Flag,
}

impl OversizePolicy {
    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Skip => "skip",
            Self::Flag => "flag",
        }
    }
}

/// Request-body/upload inspection (F10): the inline edge buffers the body,
/// parses multipart/urlencoded/JSON and the upload heuristics score what
/// they find — SQLi/XSS in filenames and form fields, polyglot images,
/// executables disguised as images, flood volume.
///
/// Only meaningful with `[deployment] mode = "inline"`: passive sources
/// (log tails) never see request bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadsConfig {
    /// Enable upload inspection (off by default; requires inline mode).
    #[serde(default)]
    pub enabled: bool,
    /// `shadow` (detect + log, weight-0 signals) | `enforce` (full weights,
    /// verdicts block/challenge before the upstream sees the request).
    #[serde(default)]
    pub mode: UploadMode,
    /// Per-request inspection cap in KiB — what happens to larger bodies is
    /// `oversize` (default: rejected with 413 while uploads are enabled).
    /// Enabling uploads consciously raises the memory ceiling: concurrent
    /// requests × this size.
    #[serde(default = "default_uploads_inspect_kb")]
    pub inspect_kb: usize,
    /// Max multipart parts parsed per request.
    #[serde(default = "default_uploads_max_files")]
    pub max_files: usize,
    /// Text-scan JSON bodies as well (SQLi/XSS inside API payloads).
    #[serde(default = "default_uploads_scan_json")]
    pub scan_json: bool,
    /// Filename extensions that always raise `UploadExecutable`
    /// (lowercase, without the dot).
    #[serde(default = "default_uploads_blocked_extensions")]
    pub blocked_extensions: Vec<String>,
    /// Filename extensions allowlist (lowercase, without the dot). When
    /// non-empty, a named upload whose extension (or double extension) is
    /// not listed raises `UploadDisallowed`. Entries accept a `*` glob in
    /// any position (`ts*`, `*php`, `*` = allow everything). Files without
    /// an extension follow `allow_extensionless`. `blocked_extensions`
    /// wins over this list.
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
    /// Declared content-type allowlist for file uploads: when non-empty, a
    /// file part that declares a Content-Type matching none of these globs
    /// (`image/*`, `application/pdf`, `*`) raises `UploadDisallowed`.
    /// Parts without a declared content type are not affected; a direct
    /// binary upload (PUT/POST of `image/*`/`application/octet-stream`)
    /// is checked against the request Content-Type.
    #[serde(default)]
    pub allowed_content_types: Vec<String>,
    /// HTTP methods allowed to carry an upload body (multipart file parts
    /// or a direct binary PUT/POST). An upload-shaped body on any other
    /// method raises `UploadDisallowed`.
    #[serde(default = "default_uploads_methods")]
    pub methods: Vec<String>,
    /// Path prefixes where uploads may land (`/wp-admin/`,
    /// `/wp-json/wp/v2/media`). An upload-shaped body on any other path
    /// raises `UploadDisallowed`. Empty = off. A prefix without a trailing
    /// slash still only matches on a `/` boundary.
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    /// Whether files without an extension pass the `allowed_extensions`
    /// allowlist (`false` raises `UploadDisallowed` for them).
    #[serde(default = "default_uploads_allow_extensionless")]
    pub allow_extensionless: bool,
    /// Policy for bodies larger than `inspect_kb` (F12): `reject` (413),
    /// `skip` (forward uninspected) or `flag` (forward + `UploadOversize`).
    #[serde(default)]
    pub oversize: OversizePolicy,
    /// Volume thresholds (`UploadFlood`).
    #[serde(default)]
    pub flood: UploadFloodConfig,
}

impl Default for UploadsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: UploadMode::default(),
            inspect_kb: default_uploads_inspect_kb(),
            max_files: default_uploads_max_files(),
            scan_json: default_uploads_scan_json(),
            blocked_extensions: default_uploads_blocked_extensions(),
            allowed_extensions: Vec::new(),
            allowed_content_types: Vec::new(),
            methods: default_uploads_methods(),
            allowed_paths: Vec::new(),
            allow_extensionless: default_uploads_allow_extensionless(),
            oversize: OversizePolicy::default(),
            flood: UploadFloodConfig::default(),
        }
    }
}

fn default_uploads_inspect_kb() -> usize {
    4096
}
fn default_uploads_max_files() -> usize {
    16
}
fn default_uploads_scan_json() -> bool {
    true
}
fn default_uploads_blocked_extensions() -> Vec<String> {
    [
        "php", "phtml", "php5", "jsp", "jspx", "asp", "aspx", "exe", "dll", "sh", "bat", "ps1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_uploads_methods() -> Vec<String> {
    ["post", "put", "patch"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_uploads_allow_extensionless() -> bool {
    true
}

/// Enforcement posture of upload inspection (F10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadMode {
    /// Detection only: signals are emitted with weight 0 (still logged and
    /// metricized) so thresholds can be tuned before anything blocks.
    #[default]
    Shadow,
    /// Full weights: polyglot/executable uploads score into Block/Challenge
    /// verdicts before the upstream sees the request.
    Enforce,
}

impl UploadMode {
    /// Whether `[uploads] mode = "enforce"`.
    pub fn is_enforce(self) -> bool {
        self == Self::Enforce
    }

    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

/// Volume thresholds for the per-IP upload flood window (F10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFloodConfig {
    /// Sliding window duration in seconds.
    #[serde(default = "default_uploads_flood_window")]
    pub window_secs: u64,
    /// Files per IP in the window that trigger `UploadFlood` (0 = off).
    #[serde(default = "default_uploads_flood_max_uploads")]
    pub max_uploads: u32,
    /// Total uploaded MiB per IP in the window that trigger `UploadFlood`.
    #[serde(default = "default_uploads_flood_max_total_mb")]
    pub max_total_mb: u32,
}

impl Default for UploadFloodConfig {
    fn default() -> Self {
        Self {
            window_secs: default_uploads_flood_window(),
            max_uploads: default_uploads_flood_max_uploads(),
            max_total_mb: default_uploads_flood_max_total_mb(),
        }
    }
}

fn default_uploads_flood_window() -> u64 {
    60
}
fn default_uploads_flood_max_uploads() -> u32 {
    30
}
fn default_uploads_flood_max_total_mb() -> u32 {
    50
}

/// Web security posture advisories (F11): the inline edge inspects origin
/// response headers and reports missing/weak security headers (CSP, HSTS,
/// COOP, frame protection, Trusted Types, nosniff, referrer policy) as
/// weight-0 signals, startup warnings and a `sentry posture` report.
///
/// Advisory only — findings describe the protected site, never the visitor,
/// and never change a score or verdict. Header injection (`enforce`) is
/// deliberately roadmap: an auto-generated CSP would break pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureConfig {
    /// Enable posture advisories (on by default; zero enforcement impact).
    #[serde(default = "default_posture_enabled")]
    pub enabled: bool,
    /// `shadow` (report only) or `enforce` (reserved for header injection —
    /// roadmap; loading `enforce` is rejected for now).
    #[serde(default)]
    pub mode: PostureMode,
    /// A finding is re-reported for the same host after this idle period.
    #[serde(default = "default_posture_dedupe_ttl_secs")]
    pub dedupe_ttl_secs: u64,
    /// HSTS `max-age` below which the header counts as weak.
    #[serde(default = "default_posture_hsts_min_max_age")]
    pub hsts_min_max_age: u64,
    /// Enabled check ids (empty = all): `csp`, `hsts`, `coop`, `clickjacking`,
    /// `trusted_types`, `nosniff`, `referrer_policy`.
    #[serde(default)]
    pub checks: Vec<String>,
    /// Restrict advisories to these hosts (empty = any, capped at 64 hosts).
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl Default for PostureConfig {
    fn default() -> Self {
        Self {
            enabled: default_posture_enabled(),
            mode: PostureMode::default(),
            dedupe_ttl_secs: default_posture_dedupe_ttl_secs(),
            hsts_min_max_age: default_posture_hsts_min_max_age(),
            checks: Vec::new(),
            hosts: Vec::new(),
        }
    }
}

impl PostureConfig {
    /// Check ids in `checks` that Sentry does not know (daemon warning).
    pub fn unknown_checks(&self) -> Vec<String> {
        self.checks
            .iter()
            .filter(|c| crate::posture::known_check(c).is_none())
            .cloned()
            .collect()
    }
}

impl SentryConfig {
    /// Expand `[rules] feed_presets` into `rules.feeds` (idempotent; a
    /// user-defined feed with the same name wins). Returns preset names
    /// that match nothing — callers should warn.
    pub fn resolve_feed_presets(&mut self) -> Vec<String> {
        crate::feed_presets::expand(&mut self.rules.feeds, &self.rules.feed_presets)
    }

    /// Performance/topology advisories for the inline edge (F12): config
    /// combinations that cost speed or expose traffic unnecessarily. Pure
    /// and testable — the daemon logs each entry with `warn!` at startup
    /// and `sentry config validate` prints them.
    pub fn edge_advisories(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.deployment.is_inline() {
            if self.edge.compress.enabled {
                out.push(
                    "[edge.compress] enabled but [deployment] mode is not inline — \
                     compression only applies to the reverse proxy"
                        .to_string(),
                );
            }
            return out;
        }
        let tls = self.edge.tls_cert.is_some() && self.edge.tls_key.is_some();
        // Every upstream group is graded: the default (catch-all) group and
        // each vhost's own servers (F14).
        let default_servers = self.edge.default_group_servers();
        let mut groups: Vec<(&str, &str)> =
            default_servers.iter().map(|u| ("", u.as_str())).collect();
        for vhost in &self.edge.vhosts {
            for url in &vhost.upstreams {
                groups.push((vhost.host.as_str(), url.as_str()));
            }
        }
        for (label, url) in &groups {
            let upstream_https = url.starts_with("https://");
            let site = if label.is_empty() {
                String::new()
            } else {
                format!(" (vhost {label})")
            };
            if tls && upstream_https {
                out.push(format!(
                    "[edge]{site} TLS terminates at the edge but upstream is https:// — \
                     double TLS costs CPU and a second certificate to manage; serve the \
                     backend over plain http:// (ideally on 127.0.0.1)"
                ));
            }
            if let Some(host) = upstream_host(url) {
                let loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
                if !loopback && !upstream_https {
                    out.push(format!(
                        "[edge]{site} upstream {host} is off-loopback over plain http — \
                         edge→backend traffic crosses the network unencrypted (container \
                         names included: the Docker bridge is cleartext); prefer \
                         127.0.0.1 or a tunnel"
                    ));
                }
            }
        }
        out
    }
}

/// Host component of an upstream base URL (`http://127.0.0.1:8080` →
/// `127.0.0.1`), parsed without a URL dependency. Returns `None` for
/// scheme-less or empty inputs.
fn upstream_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host.strip_prefix('[') {
        // IPv6 literal: the port lives outside the closing bracket.
        Some(h) => h.split_once(']').map_or(h, |(h, _)| h),
        None => host.split_once(':').map_or(host, |(h, _)| h),
    };
    (!host.is_empty()).then(|| host.to_string())
}

fn default_posture_enabled() -> bool {
    true
}
fn default_posture_dedupe_ttl_secs() -> u64 {
    3600
}
fn default_posture_hsts_min_max_age() -> u64 {
    31_536_000
}

/// Enforcement posture of security-header advisories (F11). Only `shadow`
/// exists today: `enforce` (injecting missing headers at the edge) is
/// roadmap because an auto-generated CSP breaks sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PostureMode {
    /// Report only: findings become weight-0 signals, warnings and report
    /// rows — responses are never modified.
    #[default]
    Shadow,
    /// Reserved for header injection (roadmap); rejected at load for now.
    Enforce,
}

impl PostureMode {
    /// Whether `[posture] mode = "enforce"`.
    pub fn is_enforce(self) -> bool {
        self == Self::Enforce
    }

    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

/// Behavioral attack detection over per-IP sliding windows (F3.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorConfig {
    /// Enable the behavior trackers.
    #[serde(default = "default_behavior_enabled")]
    pub enabled: bool,
    /// Sliding window duration in seconds (5 minutes per the F3 criteria).
    #[serde(default = "default_behavior_window")]
    pub window_secs: u64,
    /// Auth failures (401/403) per IP on login routes that trigger
    /// `AuthBruteForce`.
    #[serde(default = "default_behavior_auth_failures")]
    pub auth_failures: u32,
    /// Distinct User-Agents failing auth that trigger `CredentialStuffing`.
    #[serde(default = "default_behavior_distinct_uas")]
    pub distinct_uas: u32,
    /// Wordlist-path 404s per IP that trigger `DirectoryBruteForce`.
    #[serde(default = "default_behavior_wordlist_hits")]
    pub wordlist_hits: u32,
    /// Auth failures that must precede a successful login on an auth route
    /// for the success itself to fire `SuspiciousLoginSuccess`. `0` disables
    /// the detector.
    #[serde(default = "default_behavior_suspicious_success")]
    pub suspicious_success_min_failures: u32,
    /// Substrings identifying authentication routes (empty = built-in list).
    #[serde(default)]
    pub login_patterns: Vec<String>,
    /// Well-known probe paths (empty = built-in wordlist).
    #[serde(default)]
    pub wordlist_paths: Vec<String>,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            enabled: default_behavior_enabled(),
            window_secs: default_behavior_window(),
            auth_failures: default_behavior_auth_failures(),
            distinct_uas: default_behavior_distinct_uas(),
            wordlist_hits: default_behavior_wordlist_hits(),
            suspicious_success_min_failures: default_behavior_suspicious_success(),
            login_patterns: Vec::new(),
            wordlist_paths: Vec::new(),
        }
    }
}

fn default_behavior_enabled() -> bool {
    true
}
fn default_behavior_window() -> u64 {
    300
}
fn default_behavior_auth_failures() -> u32 {
    10
}
fn default_behavior_distinct_uas() -> u32 {
    3
}
fn default_behavior_wordlist_hits() -> u32 {
    5
}
fn default_behavior_suspicious_success() -> u32 {
    3
}

/// Local ML threat model (classic ML, ONNX) running as a pipeline fork.
///
/// The hot path (rules → heuristics → routes → scan → score → policy →
/// escalation) stays synchronous and fast; the model runs off to the side
/// (`fork` mode) and only feeds back through a re-score when it finds
/// something the deterministic detectors missed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Enable the ML threat-model stage.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the ONNX model file.
    #[serde(default = "default_ai_model_path")]
    pub model_path: PathBuf,
    /// Anomaly probability above which an `AnomalousPayload` signal is
    /// emitted (0.0–1.0).
    #[serde(default = "default_ai_threshold")]
    pub threshold: f32,
    /// Weight of the emitted signal (also overridable via
    /// `[scorer.weights] anomalous_payload = N`).
    #[serde(default = "default_ai_signal_weight")]
    pub signal_weight: u8,
    /// Execution mode: `fork` (async, non-blocking), `inline` (blocking,
    /// before actions dispatch) or `shadow` (log only, never re-scores).
    #[serde(default = "default_ai_mode")]
    pub mode: String,
    /// When to run the model: `always`, `above_score` or `quarantine_only`.
    #[serde(default = "default_ai_trigger")]
    pub trigger: String,
    /// Minimum hot-path score for `trigger = "above_score"`.
    #[serde(default = "default_ai_min_score")]
    pub min_score: u8,
    /// Max concurrent model inferences (fork mode).
    #[serde(default = "default_ai_concurrency")]
    pub concurrency: usize,
    /// Result cache TTL keyed by payload hash, in seconds.
    #[serde(default = "default_ai_cache_ttl")]
    pub cache_ttl_secs: u64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: default_ai_model_path(),
            threshold: default_ai_threshold(),
            signal_weight: default_ai_signal_weight(),
            mode: default_ai_mode(),
            trigger: default_ai_trigger(),
            min_score: default_ai_min_score(),
            concurrency: default_ai_concurrency(),
            cache_ttl_secs: default_ai_cache_ttl(),
        }
    }
}

fn default_ai_model_path() -> PathBuf {
    PathBuf::from("models/anomaly_v1.onnx")
}
fn default_ai_threshold() -> f32 {
    0.7
}
fn default_ai_signal_weight() -> u8 {
    25
}
fn default_ai_mode() -> String {
    "fork".to_string()
}
fn default_ai_trigger() -> String {
    "above_score".to_string()
}
fn default_ai_min_score() -> u8 {
    20
}
fn default_ai_concurrency() -> usize {
    4
}
fn default_ai_cache_ttl() -> u64 {
    300
}

/// Rate-limit backend config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Backend: `memory` (default, single-node) | `redis` (multi-node,
    /// requires the `rate-redis` feature on the CLI build).
    #[serde(default = "default_rate_backend")]
    pub backend: String,
    /// Redis URL (used only when `backend = "redis"`).
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            backend: default_rate_backend(),
            redis_url: default_redis_url(),
        }
    }
}

fn default_rate_backend() -> String {
    "memory".to_string()
}
fn default_redis_url() -> String {
    "redis://127.0.0.1/".to_string()
}

/// Prometheus metrics server config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable the `/metrics` HTTP endpoint.
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    /// Bind address (e.g. `0.0.0.0`).
    #[serde(default = "default_metrics_host")]
    pub host: String,
    /// Bind port (default 9100).
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_metrics_enabled(),
            host: default_metrics_host(),
            port: default_metrics_port(),
        }
    }
}

fn default_metrics_enabled() -> bool {
    true
}
fn default_metrics_host() -> String {
    "0.0.0.0".to_string()
}
fn default_metrics_port() -> u16 {
    9100
}

/// Web dashboard + JSON API server config (F4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address. Defaults to loopback — with auth disabled (F4.4) only
    /// loopback is safe; front the server with an authenticating reverse
    /// proxy before binding wider.
    #[serde(default = "default_server_host")]
    pub host: String,
    /// Bind port (default 8080).
    #[serde(default = "default_server_port")]
    pub port: u16,
    /// Authentication + RBAC for the dashboard and API.
    #[serde(default)]
    pub auth: ServerAuthConfig,
    /// Env var holding the shared webhook secret (F4.5). When set, requests
    /// carrying a matching `X-Sentry-Webhook-Secret` header may ack/resolve
    /// incidents — the callback path for external alert systems.
    #[serde(default = "default_webhook_secret_env")]
    pub webhook_secret_env: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_server_host(),
            port: default_server_port(),
            auth: ServerAuthConfig::default(),
            webhook_secret_env: default_webhook_secret_env(),
        }
    }
}

fn default_server_host() -> String {
    "127.0.0.1".to_string()
}
fn default_server_port() -> u16 {
    8080
}

/// Dashboard user with an Argon2 password hash (F4.4).
///
/// Generate the hash with `sentry auth hash-password <password>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUserConfig {
    /// Login name.
    pub username: String,
    /// Argon2id hash in PHC string format.
    pub password_hash: String,
    /// `admin` (mutations allowed) or `viewer` (read-only). Default `viewer`.
    #[serde(default = "default_auth_role")]
    pub role: String,
}

/// API token with a SHA-256 hash (F4.4).
///
/// Provide either `token_sha256` (hex of the SHA-256 of the raw token) or
/// `token_env` (name of an env var holding the raw token, hashed at load).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenConfig {
    /// Hex-encoded SHA-256 of the raw bearer token.
    #[serde(default)]
    pub token_sha256: String,
    /// Env var holding the raw token (hashed at startup; preferred).
    #[serde(default)]
    pub token_env: String,
    /// `admin` or `viewer`. Default `viewer`.
    #[serde(default = "default_auth_role")]
    pub role: String,
}

/// Auth + RBAC config for the dashboard/API server (F4.4).
///
/// `mode` selects which mechanisms are active: `none` (default — loopback
/// only), `password` (Argon2 login issuing an HMAC-signed session cookie),
/// `token` (static bearer tokens) or `both`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthConfig {
    /// `none` | `password` | `token` | `both`.
    #[serde(default)]
    pub mode: String,
    /// Dashboard users (password mode).
    #[serde(default)]
    pub users: Vec<AuthUserConfig>,
    /// Static API tokens (token mode).
    #[serde(default)]
    pub tokens: Vec<AuthTokenConfig>,
    /// Env var holding the HMAC session-signing key (password mode).
    #[serde(default = "default_session_secret_env")]
    pub session_secret_env: String,
    /// Session cookie lifetime in seconds (default 12h).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
}

impl Default for ServerAuthConfig {
    fn default() -> Self {
        Self {
            mode: String::new(),
            users: Vec::new(),
            tokens: Vec::new(),
            session_secret_env: default_session_secret_env(),
            session_ttl_secs: default_session_ttl(),
        }
    }
}

fn default_auth_role() -> String {
    "viewer".to_string()
}
fn default_session_secret_env() -> String {
    "SENTRY_SESSION_SECRET".to_string()
}
fn default_session_ttl() -> u64 {
    43_200
}
fn default_webhook_secret_env() -> String {
    "SENTRY_WEBHOOK_SECRET".to_string()
}

/// Deployment positioning (F3.9): where Sentry sits relative to the app.
///
/// `passive` (default) reads logs/mirrors traffic and acts ex-post via
/// actions; `inline` runs the [`EdgeConfig`] reverse proxy in front of the
/// upstream and enforces verdicts before the app sees the request.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// `passive` | `inline`.
    #[serde(default)]
    pub mode: String,
    /// Instance label for metrics and multi-node deployments (F4.7).
    /// Empty = derive from the hostname.
    #[serde(default)]
    pub instance_id: String,
}

impl DeploymentConfig {
    /// Whether inline (edge) mode is requested.
    pub fn is_inline(&self) -> bool {
        self.mode.eq_ignore_ascii_case("inline")
    }
}

/// Who executes a `Challenge` verdict at the inline edge. Purely about
/// enforcement — the verdict pages themselves are always Sentry's.
/// Type-safe like [`ActionKind`]: typos fail at config-load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeBackend {
    /// Built-in proof-of-work interstitial (F7.8) — or the static 403
    /// fallback when `[edge.challenge]` is disabled.
    #[default]
    Sentry,
    /// Delegate to the Cloudflare provider: the verdict becomes a
    /// Cloudflare rule via the CF API (`provider = "cloudflare"` action)
    /// and visitors are challenged by Cloudflare itself. Requires an
    /// action with `provider = "cloudflare"`.
    Cloudflare,
}

impl ChallengeBackend {
    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sentry => "sentry",
            Self::Cloudflare => "cloudflare",
        }
    }
}

/// Inline edge settings (F3.1/F3.9) — required when
/// `[deployment] mode = "inline"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Public HTTP listen address (default `0.0.0.0:80`).
    #[serde(default = "default_edge_listen")]
    pub listen: String,
    /// Protected upstream base URL (`http://127.0.0.1:8080`). The host part
    /// may be a hostname (`http://web:3000`, e.g. a Docker container name) —
    /// it resolves through the system resolver. Stays as the default
    /// (catch-all) backend for requests whose Host matches no vhost.
    #[serde(default)]
    pub upstream: String,
    /// Additional default-group backends (F14). When set, they replace
    /// `upstream` as the catch-all group and requests are load-balanced
    /// across them with `balance` + passive health checks.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Load-balancing strategy for upstream groups (F14).
    #[serde(default)]
    pub balance: BalanceMode,
    /// Passive health check (F14): consecutive failures within
    /// `fail_timeout_secs` before a server is ejected (0 = never eject).
    #[serde(default = "default_edge_max_fails")]
    pub max_fails: u32,
    /// Window for counting failures AND the ejection duration (F14,
    /// nginx `fail_timeout` semantics — default 30).
    #[serde(default = "default_edge_fail_timeout")]
    pub fail_timeout_secs: u64,
    /// Buffer upstream responses before forwarding (default true). `false`
    /// streams them through (SSE/WebSocket-friendly payloads) at the cost
    /// of response compression and full posture grading.
    #[serde(default = "default_edge_response_buffering")]
    pub response_buffering: bool,
    /// Total per-request upstream budget in seconds (connect + read + write,
    /// default 300). A hung backend fails the request instead of hanging
    /// the edge worker.
    #[serde(default = "default_edge_upstream_timeout")]
    pub upstream_timeout_secs: u64,
    /// Nginx-style virtual hosts (F14): route by Host header to per-site
    /// upstream groups (each with its own balancer/health settings).
    #[serde(default)]
    pub vhosts: Vec<EdgeVhostConfig>,
    /// Path used for the mandatory startup health check (default `/`).
    #[serde(default = "default_edge_health_path")]
    pub health_path: String,
    /// Health check timeout in seconds (default 5).
    #[serde(default = "default_edge_health_timeout")]
    pub health_timeout_secs: u64,
    /// Request-body bytes captured for inspection, in KiB (0 = off).
    #[serde(default)]
    pub body_capture_kb: usize,
    /// TLS certificate path (feature `edge-tls`); both cert and key enable TLS.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// TLS private key path (feature `edge-tls`).
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    /// HTTPS listen address used together with `tls_cert`/`tls_key`
    /// (default `0.0.0.0:443`). The plain `listen` stays up at the same
    /// time, so both 80 and 443 are monitored in inline mode.
    #[serde(default)]
    pub tls_listen: Option<String>,
    /// Answer plain-HTTP requests with a 301 to the HTTPS listener
    /// (host + path preserved). Only meaningful with TLS enabled; the
    /// redirect runs after the pipeline, so port-80 traffic keeps being
    /// monitored and blocked normally.
    #[serde(default)]
    pub tls_redirect_https: bool,
    /// Hostnames accepted in the TLS ClientHello SNI (F8). Empty disables
    /// the check. When set, a handshake whose SNI is missing or unknown
    /// scores as a scanner probe through the `TlsSniMismatch` signal.
    #[serde(default)]
    pub tls_allowed_hosts: Vec<String>,
    /// Emit one `TlsHandshake` event per completed handshake (SNI + JA3 +
    /// JA4 telemetry) into the pipeline. SNI mismatches are always emitted
    /// regardless of this flag.
    #[serde(default = "default_tls_handshake_events")]
    pub tls_handshake_events: bool,
    /// Optional inline TCP listener for non-HTTP services (`0.0.0.0:2222`).
    #[serde(default)]
    pub tcp_listen: Option<String>,
    /// Real backend for the TCP listener (`127.0.0.1:22`).
    #[serde(default)]
    pub tcp_upstream: Option<String>,
    /// Interactive JavaScript challenge for `Challenge` verdicts (F7.8).
    #[serde(default)]
    pub challenge: EdgeChallengeConfig,
    /// Custom HTML error pages for every edge-generated response (F12).
    #[serde(default)]
    pub error_pages: EdgeErrorPagesConfig,
    /// Who executes `Challenge` verdicts — `sentry` (built-in PoW) or
    /// `cloudflare` (the verdict becomes a Cloudflare rule via the CF
    /// provider; requires an action with `provider = "cloudflare"`).
    /// Default `sentry`.
    #[serde(default)]
    pub challenge_backend: ChallengeBackend,
    /// Response compression at the edge (F12) — `[edge.compress]`.
    /// Enabled by default: compressible responses (HTML/JSON/CSS/JS/…)
    /// are negotiated against `Accept-Encoding` (zstd > brotli > gzip).
    #[serde(default)]
    pub compress: EdgeCompressConfig,
    /// Set `X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host` /
    /// `X-Real-IP` on forwarded requests (default true). Client-supplied
    /// copies of these headers are stripped first — the edge is the
    /// internet-facing boundary, so its view of the client wins. Turning
    /// this off restores pass-through (the backend sees the edge's own
    /// address and whatever the client sent).
    #[serde(default = "default_edge_forwarded_headers")]
    pub forwarded_headers: bool,
    /// Negotiate HTTP/2 on the TLS listener (ALPN `h2` + `http/1.1`).
    /// Only meaningful with `tls_cert`/`tls_key` and a build carrying the
    /// `edge-tls` feature; default true.
    #[serde(default = "default_edge_http2")]
    pub http2: bool,
    /// Connect timeout for the edge → upstream hop, in seconds (default 5).
    #[serde(default = "default_edge_upstream_connect_timeout")]
    pub upstream_connect_timeout_secs: u64,
    /// Idle keepalive connections pooled per upstream host (default 32).
    /// Connection reuse removes a TCP handshake per request on the
    /// edge → backend hop.
    #[serde(default = "default_edge_upstream_pool_idle")]
    pub upstream_pool_idle: usize,
    /// Max requests served concurrently by the inline edge (default 1024;
    /// 0 = unlimited). Each in-flight request buffers up to the inspection/
    /// forward cap in memory, so an unbounded connection flood multiplies
    /// that per-request cost into an OOM. Beyond the cap, requests get an
    /// immediate 503 (custom error pages apply) instead of being buffered.
    #[serde(default = "default_edge_max_concurrent")]
    pub max_concurrent_requests: usize,
    /// Accept-loop workers bound to the same port with `SO_REUSEPORT`
    /// (F14, unix only; Windows ignores this). 1 = off (single listener).
    /// Each worker gets its own kernel accept queue — less lock contention
    /// under bursty accepts.
    #[serde(default = "default_edge_reuseport_workers")]
    pub reuseport_workers: usize,
    /// Listen backlog for the edge listeners (F14). 0 = `SOMAXCONN`.
    #[serde(default)]
    pub tcp_backlog: u32,
    /// `TCP_NODELAY` on client-facing connections (F14, default true):
    /// request/response payloads are written immediately instead of
    /// waiting on Nagle coalescing.
    #[serde(default = "default_edge_tcp_nodelay")]
    pub tcp_nodelay: bool,
    /// Keepalive idle time in seconds for client-facing connections
    /// (F14, default 60; 0 = off). Probes every 10s × 5 detect dead
    /// peers within ~2 minutes of silence.
    #[serde(default = "default_edge_tcp_keepalive")]
    pub tcp_keepalive_secs: u64,
    /// `SO_SNDBUF` on the client-facing sockets, KiB (F14, 0 = system
    /// default). Larger buffers absorb bursty upstreams on lossy links.
    #[serde(default)]
    pub tcp_send_buffer_kb: u32,
    /// `SO_RCVBUF` on the client-facing sockets, KiB (F14, 0 = system
    /// default).
    #[serde(default)]
    pub tcp_recv_buffer_kb: u32,
}

/// Load-balancing strategy for an upstream group (F14, nginx `upstream`
/// semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BalanceMode {
    /// Each new request goes to the next server in order (default).
    #[default]
    RoundRobin,
    /// The in-flight request counter decides: fewest concurrent requests
    /// wins — fits uneven request durations (large uploads next to pings).
    LeastConn,
    /// Same client IP always lands on the same server while it is up
    /// (sticky backends, server-local sessions).
    IpHash,
}

impl BalanceMode {
    /// Stable lowercase name for logs and config summaries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::LeastConn => "least_conn",
            Self::IpHash => "ip_hash",
        }
    }
}

/// One nginx-like virtual host (F14): requests whose Host header matches
/// `host` are load-balanced across `upstreams` instead of the default
/// group. Per-vhost settings omitted here inherit the `[edge]` globals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeVhostConfig {
    /// Host header to match (case-insensitive; the `:port` suffix is
    /// ignored). `*.example.com` matches any subdomain (multi-label, but
    /// not the bare `example.com` — nginx wildcard semantics).
    pub host: String,
    /// Backend base URLs for this site — IP or hostname (`http://web:3000`).
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Load-balancing strategy (default: `[edge] balance`).
    #[serde(default)]
    pub balance: Option<BalanceMode>,
    /// Passive health check failures before ejection (default: `[edge] max_fails`).
    #[serde(default)]
    pub max_fails: Option<u32>,
    /// Failure window / ejection duration in seconds (default:
    /// `[edge] fail_timeout_secs`).
    #[serde(default)]
    pub fail_timeout_secs: Option<u64>,
    /// Startup health-check path override (default: `[edge] health_path`).
    #[serde(default)]
    pub health_path: Option<String>,
    /// TLS certificate served for this hostname via SNI (feature
    /// `edge-tls`); both paths together. Requires the global TLS front.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// TLS private key for this hostname.
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
}

impl EdgeVhostConfig {
    /// Effective balancer, resolving the inheritance from `[edge]`.
    pub fn effective_balance(&self, global: BalanceMode) -> BalanceMode {
        self.balance.unwrap_or(global)
    }

    /// Effective `max_fails`, resolving the inheritance from `[edge]`.
    pub fn effective_max_fails(&self, global: u32) -> u32 {
        self.max_fails.unwrap_or(global)
    }

    /// Effective `fail_timeout`, resolving the inheritance from `[edge]`.
    pub fn effective_fail_timeout(&self, global: u64) -> u64 {
        self.fail_timeout_secs.unwrap_or(global)
    }

    /// Effective health-check path, resolving the inheritance from `[edge]`.
    pub fn effective_health_path<'a>(&'a self, global: &'a str) -> &'a str {
        self.health_path.as_deref().unwrap_or(global)
    }
}

impl EdgeConfig {
    /// Servers of the default (catch-all) group: `upstreams` when set,
    /// otherwise the single legacy `upstream` string.
    pub fn default_group_servers(&self) -> Vec<String> {
        if self.upstreams.is_empty() {
            if self.upstream.is_empty() {
                Vec::new()
            } else {
                vec![self.upstream.clone()]
            }
        } else {
            self.upstreams.clone()
        }
    }

    /// Config errors for `[edge]` (F14): bad vhost hosts, upstreams without
    /// scheme, duplicate hosts, TLS-cert pairing. Pure — `sentry config
    /// validate` fails on them and the daemon refuses to start inline.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let servers = self.default_group_servers();
        for url in &servers {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                errors.push(format!(
                    "[edge] upstream `{url}` must start with http:// or https://"
                ));
            }
        }
        let mut seen: Vec<String> = Vec::new();
        for vhost in &self.vhosts {
            let host = vhost.host.trim();
            if host.is_empty() {
                errors.push("[edge.vhosts] `host` must not be empty".to_string());
                continue;
            }
            if host != host.to_ascii_lowercase() {
                errors.push(format!(
                    "[edge.vhosts] host `{host}` must be lowercase (matching is case-insensitive)"
                ));
            }
            if host.starts_with("*.") && host[2..].is_empty() {
                errors.push("[edge.vhosts] wildcard `*.` needs a domain suffix".to_string());
            } else if host.contains('*') && !host.starts_with("*.") {
                errors.push(format!(
                    "[edge.vhosts] host `{host}`: `*` is only valid as a leading `*.` wildcard"
                ));
            }
            if seen.iter().any(|h| h == host) {
                errors.push(format!("[edge.vhosts] duplicate host `{host}`"));
            } else {
                seen.push(host.to_string());
            }
            if vhost.upstreams.is_empty() {
                errors.push(format!(
                    "[edge.vhosts] `{host}` needs at least one entry in `upstreams`"
                ));
            }
            for url in &vhost.upstreams {
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    errors.push(format!(
                        "[edge.vhosts] `{host}` upstream `{url}` must start with http:// or https://"
                    ));
                }
            }
            let cert = vhost.tls_cert.is_some();
            let key = vhost.tls_key.is_some();
            if cert != key {
                errors.push(format!(
                    "[edge.vhosts] `{host}`: tls_cert and tls_key must be configured together"
                ));
            }
            if cert && (self.tls_cert.is_none() || self.tls_key.is_none()) {
                errors.push(format!(
                    "[edge.vhosts] `{host}`: per-vhost tls_cert requires the global [edge] \
                     tls_cert/tls_key front (the certificate is served via SNI on the same listener)"
                ));
            }
        }
        errors
    }
}

/// Tokio runtime tuning (F14): worker count, CPU pinning and thread
/// priority for the whole process. Applied when the binary builds its
/// runtime (before any command runs); every knob is optional.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeConfig {
    /// Tokio worker threads (default 0 = tokio auto, one per core).
    /// Pinning + fewer-than-core workers is the classic dedication recipe
    /// for a protection daemon that must never starve.
    #[serde(default)]
    pub worker_threads: usize,
    /// Pin the workers to these CPU core ids (in order; workers cycle
    /// through the list when there are more workers than cores). Empty =
    /// let the OS scheduler place threads.
    #[serde(default)]
    pub pin_cores: Vec<usize>,
    /// Thread priority class for the worker threads.
    #[serde(default)]
    pub thread_priority: ThreadPriority,
}

impl RuntimeConfig {
    /// Config errors for `[runtime]` (F14). Pure; checked by
    /// `sentry config validate`.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.worker_threads > 1024 {
            errors.push(format!(
                "[runtime] worker_threads = {} is unreasonable (max 1024)",
                self.worker_threads
            ));
        }
        let mut seen: Vec<usize> = Vec::new();
        for core in &self.pin_cores {
            if *core > 65535 {
                errors.push(format!(
                    "[runtime] pin_cores: core id {core} is out of range (0..=65535)"
                ));
            }
            if seen.contains(core) {
                errors.push(format!("[runtime] pin_cores: duplicate core id {core}"));
            } else {
                seen.push(*core);
            }
        }
        errors
    }
}

/// Thread priority class for `[runtime] thread_priority` (F14). Mapped to
/// nice values on unix and priority classes on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThreadPriority {
    /// Yield to everything else (nice +15 / IDLE) — for co-located boxes.
    Idle,
    /// Slightly below normal (nice +5 / BELOW_NORMAL).
    BelowNormal,
    /// The default: no change from the OS default (nice 0 / NORMAL).
    #[default]
    Normal,
    /// Slightly above normal (nice -5 / ABOVE_NORMAL).
    AboveNormal,
    /// Elevated (nice -10 / HIGH) — needs privileges on unix.
    High,
}

impl ThreadPriority {
    /// Stable lowercase name for logs and config summaries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::BelowNormal => "below_normal",
            Self::Normal => "normal",
            Self::AboveNormal => "above_normal",
            Self::High => "high",
        }
    }
}

/// Response compression at the edge (F12). Bodies are already buffered in
/// memory, so compression is a synchronous re-encode of the response body:
/// compressible content types only (HTML/JSON/CSS/JS/SVG/…), negotiated
/// against the request's `Accept-Encoding`. Range responses (206) and
/// responses already carrying a `content-encoding` are never touched; under
/// overload pressure compression turns itself off (CPU shedding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCompressConfig {
    /// Master switch (default true — the point of the feature).
    #[serde(default = "default_edge_compress_enabled")]
    pub enabled: bool,
    /// Bodies smaller than this are passed through untouched (default 256).
    #[serde(default = "default_edge_compress_min_length")]
    pub min_length: usize,
    /// Brotli quality 0..=11 (default 4 — the CDN sweet spot).
    #[serde(default = "default_edge_compress_level_br")]
    pub level_br: u8,
    /// gzip level 0..=9 (default 6).
    #[serde(default = "default_edge_compress_level_gzip")]
    pub level_gzip: u8,
    /// zstd level 1..=22 (default 3). Only honored when the binary was
    /// built with the `edge-zstd` feature.
    #[serde(default = "default_edge_compress_level_zstd")]
    pub level_zstd: u8,
}

impl Default for EdgeCompressConfig {
    fn default() -> Self {
        Self {
            enabled: default_edge_compress_enabled(),
            min_length: default_edge_compress_min_length(),
            level_br: default_edge_compress_level_br(),
            level_gzip: default_edge_compress_level_gzip(),
            level_zstd: default_edge_compress_level_zstd(),
        }
    }
}

fn default_edge_compress_enabled() -> bool {
    true
}
fn default_edge_compress_min_length() -> usize {
    256
}
fn default_edge_compress_level_br() -> u8 {
    4
}
fn default_edge_compress_level_gzip() -> u8 {
    6
}
fn default_edge_compress_level_zstd() -> u8 {
    3
}
fn default_edge_forwarded_headers() -> bool {
    true
}
fn default_edge_max_concurrent() -> usize {
    1024
}
fn default_edge_http2() -> bool {
    true
}
fn default_edge_upstream_connect_timeout() -> u64 {
    5
}
fn default_edge_upstream_pool_idle() -> usize {
    32
}

/// Custom HTML error pages (F12): `<status>.html` files (e.g. `403.html`,
/// `413.html`, `429.html`, `502.html`) override that status and
/// `default.html` covers every other edge-rendered status. Loaded once at
/// startup — editing a page requires a restart (the challenge interstitial
/// keeps its own hot-read `template_path`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeErrorPagesConfig {
    /// Directory holding the page overrides. Missing/unreadable files are
    /// skipped with a warning; without this the built-in styled pages are
    /// served.
    #[serde(default)]
    pub dir: Option<PathBuf>,
}

/// JavaScript proof-of-work challenge settings (F7.8). When enabled, the
/// inline edge answers `Challenge` verdicts with a browser PoW interstitial
/// instead of the static 403 page; solved clients get a cookie valid for the
/// rest of the bucket. Stateless: share `secret_env` across edge nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeChallengeConfig {
    /// Enable the interactive challenge (off by default).
    #[serde(default)]
    pub enabled: bool,
    /// Env var holding the shared secret (32+ random bytes recommended:
    /// `openssl rand -hex 32`). Required when enabled; startup fails without
    /// it.
    #[serde(default = "default_edge_challenge_secret_env")]
    pub secret_env: String,
    /// Bucket length in seconds — the challenge rotates and cookies expire
    /// with it (clients re-solve once per bucket).
    #[serde(default = "default_edge_challenge_bucket")]
    pub bucket_secs: u64,
    /// PoW difficulty in leading zero bits (clamped 8..=28 by the edge).
    #[serde(default = "default_edge_challenge_difficulty")]
    pub difficulty: u8,
    /// Interstitial page title.
    #[serde(default = "default_edge_challenge_title")]
    pub title: String,
    /// Optional file overriding the challenge page HTML. Re-read on every
    /// render (edits go live without a restart); falls back to the built-in
    /// page when unreadable or missing the required `{{…}}` markers.
    #[serde(default)]
    pub template_path: Option<std::path::PathBuf>,
}

impl Default for EdgeChallengeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret_env: default_edge_challenge_secret_env(),
            bucket_secs: default_edge_challenge_bucket(),
            difficulty: default_edge_challenge_difficulty(),
            title: default_edge_challenge_title(),
            template_path: None,
        }
    }
}

fn default_edge_challenge_secret_env() -> String {
    "SENTRY_EDGE_CHALLENGE_SECRET".to_string()
}
fn default_edge_challenge_bucket() -> u64 {
    3600
}
fn default_edge_challenge_difficulty() -> u8 {
    16
}
fn default_edge_challenge_title() -> String {
    "Verifying your browser...".to_string()
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            listen: default_edge_listen(),
            upstream: String::new(),
            upstreams: Vec::new(),
            balance: BalanceMode::default(),
            max_fails: default_edge_max_fails(),
            fail_timeout_secs: default_edge_fail_timeout(),
            response_buffering: default_edge_response_buffering(),
            upstream_timeout_secs: default_edge_upstream_timeout(),
            vhosts: Vec::new(),
            health_path: default_edge_health_path(),
            health_timeout_secs: default_edge_health_timeout(),
            body_capture_kb: 0,
            tls_cert: None,
            tls_key: None,
            tls_listen: None,
            tls_redirect_https: false,
            tls_allowed_hosts: Vec::new(),
            tls_handshake_events: default_tls_handshake_events(),
            tcp_listen: None,
            tcp_upstream: None,
            challenge: EdgeChallengeConfig::default(),
            error_pages: EdgeErrorPagesConfig::default(),
            challenge_backend: ChallengeBackend::default(),
            compress: EdgeCompressConfig::default(),
            forwarded_headers: default_edge_forwarded_headers(),
            http2: default_edge_http2(),
            upstream_connect_timeout_secs: default_edge_upstream_connect_timeout(),
            upstream_pool_idle: default_edge_upstream_pool_idle(),
            max_concurrent_requests: default_edge_max_concurrent(),
            reuseport_workers: default_edge_reuseport_workers(),
            tcp_backlog: 0,
            tcp_nodelay: default_edge_tcp_nodelay(),
            tcp_keepalive_secs: default_edge_tcp_keepalive(),
            tcp_send_buffer_kb: 0,
            tcp_recv_buffer_kb: 0,
        }
    }
}

fn default_edge_listen() -> String {
    "0.0.0.0:80".to_string()
}
fn default_edge_health_path() -> String {
    "/".to_string()
}
fn default_edge_health_timeout() -> u64 {
    5
}
fn default_tls_handshake_events() -> bool {
    true
}
fn default_edge_max_fails() -> u32 {
    2
}
fn default_edge_fail_timeout() -> u64 {
    30
}
fn default_edge_response_buffering() -> bool {
    true
}
fn default_edge_upstream_timeout() -> u64 {
    300
}
fn default_edge_reuseport_workers() -> usize {
    1
}
fn default_edge_tcp_nodelay() -> bool {
    true
}
fn default_edge_tcp_keepalive() -> u64 {
    60
}

/// Background route learner config.
///
/// When enabled, the daemon periodically scans recent events from Postgres
/// (within `window_secs`), infers stable route shapes, and auto-pushes new
/// routes to the DB + hot-reloads them via `NOTIFY sentry_routes_changed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteLearnerConfig {
    /// Enable continuous background learning (requires Postgres storage).
    #[serde(default)]
    pub enabled: bool,
    /// How often (in seconds) to run a learning pass.
    #[serde(default = "default_learner_interval")]
    pub interval_secs: u64,
    /// Look-back window for events (in seconds).
    #[serde(default = "default_learner_window")]
    pub window_secs: u64,
    /// Minimum total hits for a shape to be considered stable.
    #[serde(default = "default_learner_min_hits")]
    pub min_hits: u32,
    /// Minimum number of distinct IPs that hit the shape.
    #[serde(default = "default_learner_min_ips")]
    pub min_ips: u32,
}

impl Default for RouteLearnerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_learner_interval(),
            window_secs: default_learner_window(),
            min_hits: default_learner_min_hits(),
            min_ips: default_learner_min_ips(),
        }
    }
}

fn default_learner_interval() -> u64 {
    300
}
fn default_learner_window() -> u64 {
    3600
}
fn default_learner_min_hits() -> u32 {
    10
}
fn default_learner_min_ips() -> u32 {
    2
}

/// LLM provider config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider: `none` | `openrouter` | `ollama` | `openai` | `anthropic`.
    #[serde(default = "default_llm_provider")]
    pub provider: String,
    /// Model id (provider-specific, e.g. `anthropic/claude-3.5-sonnet`).
    #[serde(default)]
    pub model: String,
    /// API base URL override (for self-hosted Ollama / OpenAI-compatible).
    #[serde(default)]
    pub base_url: Option<String>,
    /// Execution mode: `fork` (async re-score + action re-dispatch) or
    /// `shadow` (log what the LLM would decide, never act).
    #[serde(default = "default_llm_mode")]
    pub mode: String,
    /// Only invoke LLM for events with risk score above this threshold.
    #[serde(default = "default_llm_threshold")]
    pub only_above: u8,
    /// Max concurrent LLM requests.
    #[serde(default = "default_llm_concurrency")]
    pub concurrency: usize,
    /// Cache TTL for LLM verdicts keyed by payload hash.
    #[serde(default = "default_llm_cache_ttl")]
    pub cache_ttl_secs: u64,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: default_llm_provider(),
            model: String::new(),
            base_url: None,
            mode: default_llm_mode(),
            only_above: default_llm_threshold(),
            concurrency: default_llm_concurrency(),
            cache_ttl_secs: default_llm_cache_ttl(),
        }
    }
}

fn default_llm_provider() -> String {
    "none".to_string()
}
fn default_llm_mode() -> String {
    "fork".to_string()
}
fn default_llm_threshold() -> u8 {
    30
}
fn default_llm_concurrency() -> usize {
    4
}
fn default_llm_cache_ttl() -> u64 {
    300
}

/// Rules engine config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Default rule packs and their mode.
    #[serde(default, rename = "pack")]
    pub packs: Vec<RulePackConfig>,
    /// Static inline rules.
    #[serde(default)]
    pub custom: Vec<RuleDefConfig>,
    /// Reputation feeds to sync.
    #[serde(default)]
    pub feeds: Vec<FeedConfig>,
    /// Built-in feed presets to enable by name (`tor_exit`,
    /// `firehol_level1`, `proxy_list`, `open_source_vpn_ips`, `anti_vpn`).
    /// Expanded into `feeds` at load time — a user-defined feed with the
    /// same name wins. Preset feeds block by default.
    #[serde(default)]
    pub feed_presets: Vec<String>,
}

/// A default rule pack entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePackConfig {
    /// Pack name: `vpn_proxy`, `tor`, `crawlers_bad`, `sensitive_paths`, …
    pub name: String,
    /// `shadow` | `enforce` | `off`.
    #[serde(default = "default_pack_mode")]
    pub mode: String,
    /// Extra parameters (e.g. `countries = ["RU","CN"]`).
    #[serde(default)]
    pub params: HashMap<String, toml::Value>,
}

impl Default for RulePackConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            mode: default_pack_mode(),
            params: HashMap::new(),
        }
    }
}

fn default_pack_mode() -> String {
    "shadow".to_string()
}

/// A static rule definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleDefConfig {
    /// Human-readable rule name.
    pub name: String,
    /// Lower number = evaluated first.
    #[serde(default)]
    pub priority: i32,
    /// DSL match expression (parsed at load time).
    pub r#match: String,
    /// Action: `allow` | `block` | `challenge` | `rate_limit` | `log` | `tag`.
    pub action: String,
    /// Free-form tags for grouping.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Console verbosity for events this rule matches: `silent` (no event
    /// line at all), `info` (default), `warn` or `error`.
    #[serde(default)]
    pub log_level: Option<String>,
}

/// A reputation feed or dataset to sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Feed name (used as the rule tag prefix).
    pub name: String,
    /// URL to fetch the feed from (http/https; loopback/private hosts are
    /// rejected).
    pub url: String,
    /// Entry kind: `ip` (default — reputation ranges), `user_agent` or
    /// `path` (plain one-per-line lists compiled into a synthetic rule,
    /// F7.6).
    #[serde(default)]
    pub kind: FeedKind,
    /// Refresh interval in hours.
    #[serde(default = "default_feed_refresh")]
    pub refresh_hours: u32,
    /// Reputation tier entries are tagged with: `unknown` | `clean` |
    /// `suspicious` | `malicious` | `datacenter` | `vpn` | `tor`. Only used
    /// by `kind = "ip"`.
    #[serde(default = "default_feed_tier")]
    pub tier: String,
    /// Optional action for the synthetic feed rule (`block`, `challenge`,
    /// `rate_limit`, …). For `kind = "ip"`: empty = enrichment only (match
    /// via the `tor` / `vpn_proxy` packs or user rules). For `user_agent` /
    /// `path` datasets: empty = `log` (annotate only).
    #[serde(default)]
    pub action: String,
    /// Whether the feed is fetched at all.
    #[serde(default = "default_feed_enabled")]
    pub enabled: bool,
    /// Header name → env var name; the header is sent with the value of the
    /// env var when set (e.g. authenticated feeds such as the AbuseIPDB
    /// blacklist). Missing env vars are skipped silently.
    #[serde(default)]
    pub headers_env: HashMap<String, String>,
}

/// What a feed's entries represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    /// IP ranges/CIDRs → [`ReputationStore`](crate::reputation::ReputationStore)
    /// enrichment + synthetic reputation rule.
    #[default]
    Ip,
    /// User-Agent substrings, one per line → synthetic UA rule.
    UserAgent,
    /// Path fragments, one per line → synthetic path rule.
    Path,
    /// JA3 fingerprints (lowercase hex), one per line → synthetic TLS
    /// fingerprint rule (F7.7). Only evaluated against `TlsHandshake`
    /// events from the inline edge.
    Ja3,
}

impl FeedKind {
    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::UserAgent => "user_agent",
            Self::Path => "path",
            Self::Ja3 => "ja3",
        }
    }
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            kind: FeedKind::default(),
            refresh_hours: default_feed_refresh(),
            tier: default_feed_tier(),
            action: String::new(),
            enabled: default_feed_enabled(),
            headers_env: HashMap::new(),
        }
    }
}

fn default_feed_refresh() -> u32 {
    24
}

fn default_feed_tier() -> String {
    "malicious".to_string()
}

fn default_feed_enabled() -> bool {
    true
}

/// A source plugin entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceConfig {
    /// Plugin type: `nginx` | `cloudflare` | `tcp` | …
    #[serde(rename = "type")]
    pub kind: String,
    /// Arbitrary plugin-specific fields.
    #[serde(default)]
    pub options: HashMap<String, toml::Value>,
}

/// An action plugin entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionConfig {
    /// Plugin kind: `cloudflare` | `webhook` | `blocklist` | `log` | `challenge`.
    #[serde(rename = "type")]
    pub kind: ActionKind,
    /// Edge provider name, used only when `kind = "challenge"`
    /// (e.g. `"cloudflare"` | `"aws_waf"` | `"fastly"`). Ignored by other
    /// kinds. Enables adding new edge providers without a new `ActionKind`
    /// variant each time — see [`ChallengeProvider`](crate::challenge::ChallengeProvider).
    #[serde(default)]
    pub provider: Option<String>,
    /// Where this action runs relative to the ingest hot path
    /// (`"inline"` | `"deferred"`). When unset, each action uses its natural
    /// default: local containment (blocklist, log, kernel firewall) runs
    /// inline; network side effects (Cloudflare/nginx/OPNsense APIs,
    /// webhooks, abuse reports) defer to the post-processing workers.
    #[serde(default)]
    pub dispatch: Option<crate::action::ActionDispatch>,
    /// Arbitrary plugin-specific fields.
    #[serde(default)]
    pub options: HashMap<String, toml::Value>,
}

/// Type-safe discriminator for action plugins.
///
/// Replaces the previous stringly-typed `kind: String` so the compiler
/// catches typos and unknown plugins at config-load time instead of at
/// runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    /// `sentry-action-cloudflare` — block/challenge via the Cloudflare API.
    ///
    /// Backward-compatible alias for [`Self::Challenge`] with
    /// `provider = "cloudflare"`. New configs should prefer the canonical
    /// `challenge` form.
    Cloudflare,
    /// Provider-agnostic edge action. The actual provider is selected by
    /// [`ActionConfig::provider`] (e.g. `"cloudflare"`). New edge providers
    /// implement [`ChallengeProvider`](crate::challenge::ChallengeProvider)
    /// and are wired in `daemon::build_registry` — no new `ActionKind`
    /// variant needed.
    Challenge,
    /// `sentry-action-webhook` — POST a JSON alert to a URL.
    Webhook,
    /// `sentry-action-blocklist` — in-memory IP blocklist with TTL.
    Blocklist,
    /// `sentry-action-report` — report enforcing-verdict IPs to community
    /// abuse databases (provider: `abuseipdb` | `reportedip`, F7.4).
    Report,
    /// Built-in log action — always present, emits a tracing line on act.
    #[default]
    Log,
}

impl ActionKind {
    /// Lowercase stable name used in logs and config.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Challenge => "challenge",
            Self::Webhook => "webhook",
            Self::Blocklist => "blocklist",
            Self::Report => "report",
            Self::Log => "log",
        }
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_default_has_nonzero_pool() {
        assert_eq!(PostgresConfig::default().max_connections, 10);
    }

    #[test]
    fn postgres_serde_missing_field_uses_default() {
        let toml = r#"url = "postgres://localhost/sentry""#;
        let pg: PostgresConfig = toml::from_str(toml).unwrap();
        assert_eq!(pg.max_connections, 10);
    }

    #[test]
    fn llm_default_matches_serde_defaults() {
        let c = LlmConfig::default();
        assert_eq!(c.provider, "none");
        assert_eq!(c.mode, "fork");
        assert_eq!(c.only_above, 30);
        assert_eq!(c.concurrency, 4);
        assert_eq!(c.cache_ttl_secs, 300);
    }

    #[test]
    fn rule_pack_default_mode_is_shadow() {
        assert_eq!(RulePackConfig::default().mode, "shadow");
    }

    #[test]
    fn feed_default_refresh_is_24h() {
        assert_eq!(FeedConfig::default().refresh_hours, 24);
    }

    #[test]
    fn auto_sensitive_section_parses_with_defaults() {
        let cfg: SentryConfig =
            toml::from_str("[auto.sensitive]\nskip = [\"logs\"]\nenable = [\"config\"]\n").unwrap();
        assert_eq!(cfg.auto.sensitive.skip, vec!["logs"]);
        assert_eq!(cfg.auto.sensitive.enable, vec!["config"]);

        let cfg: SentryConfig = toml::from_str("").unwrap();
        assert!(cfg.auto.sensitive.skip.is_empty());
        assert!(cfg.auto.sensitive.enable.is_empty());
    }

    #[test]
    fn update_section_parses_with_defaults() {
        let cfg: SentryConfig = toml::from_str("").unwrap();
        assert!(cfg.update.enabled);
        assert_eq!(cfg.update.interval_secs, 86_400);
        assert_eq!(cfg.update.repo, "IDjinn/sentry");
        assert!(!cfg.update.auto_restart);
        assert!(cfg.update.validate().is_ok());

        let cfg: SentryConfig = toml::from_str(
            "[update]\nenabled = false\ninterval_secs = 3600\nrepo = \"me/fork\"\nauto_restart = true\n",
        )
        .unwrap();
        assert!(!cfg.update.enabled);
        assert_eq!(cfg.update.interval_secs, 3600);
        assert_eq!(cfg.update.repo, "me/fork");
        assert!(cfg.update.auto_restart);
        assert!(cfg.update.validate().is_ok());
    }

    #[test]
    fn update_validation_rejects_bad_repo_and_interval() {
        let mut cfg = UpdateConfig::default();
        cfg.repo = "just-a-name".to_string();
        assert!(cfg.validate().is_err());
        cfg.repo = "a/b/c".to_string();
        assert!(cfg.validate().is_err());
        cfg.repo = "owner/".to_string();
        assert!(cfg.validate().is_err());
        cfg.repo = String::new();
        assert!(cfg.validate().is_err());

        cfg = UpdateConfig::default();
        cfg.interval_secs = 299;
        assert!(cfg.validate().is_err());
        // A disabled check is never rate-limited, so the floor does not apply.
        cfg.enabled = false;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn full_config_default_has_sane_storage_pool() {
        assert_eq!(SentryConfig::default().storage.postgres.max_connections, 10);
    }

    #[test]
    fn correlation_default_window_is_15min() {
        let c = CorrelationConfig::default();
        assert!(c.enabled);
        assert_eq!(c.window_secs, 900);
        let parsed: CorrelationConfig = toml::from_str("").unwrap();
        assert!(parsed.enabled);
        assert_eq!(parsed.window_secs, 900);
    }

    #[test]
    fn edge_challenge_backend_defaults_to_sentry_and_parses_variants() {
        assert_eq!(
            EdgeConfig::default().challenge_backend,
            ChallengeBackend::Sentry
        );

        let parsed: EdgeConfig = toml::from_str("challenge_backend = \"cloudflare\"").unwrap();
        assert_eq!(parsed.challenge_backend, ChallengeBackend::Cloudflare);

        let parsed: EdgeConfig = toml::from_str("challenge_backend = \"sentry\"").unwrap();
        assert_eq!(parsed.challenge_backend, ChallengeBackend::Sentry);

        let err = toml::from_str::<EdgeConfig>("challenge_backend = \"bunny\"");
        assert!(err.is_err(), "typos must fail at config-load time");
    }

    #[test]
    fn core_defaults_include_post_processing_lane() {
        let c = CoreConfig::default();
        assert_eq!(c.action_buffer, 4096);
        assert_eq!(c.action_workers, 1);
        assert_eq!(c.persist_buffer, 2048);
        assert_eq!(c.dedupe_ttl_secs, 10);
        let parsed: CoreConfig = toml::from_str("channel_buffer = 8192").unwrap();
        assert_eq!(parsed.channel_buffer, 8192);
        assert_eq!(parsed.action_buffer, 4096);
        assert_eq!(parsed.action_workers, 1);
        assert_eq!(parsed.persist_buffer, 2048);
        assert_eq!(parsed.dedupe_ttl_secs, 10);
    }

    #[test]
    fn overload_defaults_are_safe_and_parse() {
        let c = OverloadConfig::default();
        assert!(c.enabled);
        assert!((c.queue_pressure - 0.8).abs() < f64::EPSILON);
        assert!((c.release_pressure - 0.5).abs() < f64::EPSILON);
        assert_eq!(c.release_secs, 30);
        assert_eq!(c.pg_insert_budget_ms, 250);
        assert!((c.sample_keep - 0.1).abs() < f64::EPSILON);
        assert!(c.coalesce_benign);
        assert_eq!(c.coalesce_window_secs, 60);
        assert_eq!(c.coalesce_cap, 4096);

        let parsed: OverloadConfig = toml::from_str("sample_keep = 0.5").unwrap();
        assert!((parsed.sample_keep - 0.5).abs() < f64::EPSILON);
        assert!((parsed.queue_pressure - 0.8).abs() < f64::EPSILON);

        let full: SentryConfig = toml::from_str("[overload]\ncoalesce_benign = false").unwrap();
        assert!(!full.overload.coalesce_benign);
    }

    #[test]
    fn action_dispatch_option_parses_from_toml() {
        let parsed: ActionConfig =
            toml::from_str("type = \"webhook\"\ndispatch = \"inline\"").unwrap();
        assert_eq!(parsed.dispatch, Some(crate::action::ActionDispatch::Inline));

        let parsed: ActionConfig = toml::from_str("type = \"log\"").unwrap();
        assert_eq!(parsed.dispatch, None);

        assert!(
            toml::from_str::<ActionConfig>("type = \"log\"\ndispatch = \"fast\"").is_err(),
            "typos must fail at config-load time"
        );
    }

    #[test]
    fn uploads_default_is_shadow_and_off() {
        let c = UploadsConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.mode, UploadMode::Shadow);
        assert_eq!(c.inspect_kb, 4096);
        assert_eq!(c.max_files, 16);
        assert!(c.scan_json);
        assert!(c.blocked_extensions.iter().any(|e| e == "php"));
        assert!(c.allowed_extensions.is_empty(), "allowlist off by default");
        assert!(
            c.allowed_content_types.is_empty(),
            "content-type allowlist off by default"
        );
        assert_eq!(c.methods, vec!["post", "put", "patch"]);
        assert!(c.allowed_paths.is_empty(), "path allowlist off by default");
        assert!(c.allow_extensionless, "extensionless files pass by default");
        assert_eq!(c.oversize, OversizePolicy::Reject);
        assert_eq!(c.flood.max_uploads, 30);

        let parsed: UploadsConfig = toml::from_str(
            r#"
            enabled = true
            mode = "enforce"
            inspect_kb = 8192
            blocked_extensions = ["php", "jsp"]
            allowed_extensions = ["png", "jpg", "pdf"]
            oversize = "flag"
        "#,
        )
        .unwrap();
        assert!(parsed.enabled);
        assert!(parsed.mode.is_enforce());
        assert_eq!(parsed.inspect_kb, 8192);
        assert_eq!(parsed.blocked_extensions, vec!["php", "jsp"]);
        assert_eq!(parsed.allowed_extensions, vec!["png", "jpg", "pdf"]);
        assert_eq!(parsed.oversize, OversizePolicy::Flag);

        let err = toml::from_str::<UploadsConfig>("mode = \"block\"");
        assert!(err.is_err(), "typos must fail at config-load time");
        let err = toml::from_str::<UploadsConfig>("oversize = \"ignore\"");
        assert!(err.is_err(), "oversize typos must fail at config-load time");
    }

    #[test]
    fn edge_error_pages_default_and_parse() {
        let c = EdgeConfig::default();
        assert!(c.error_pages.dir.is_none());

        let parsed: EdgeConfig = toml::from_str("error_pages.dir = \"/etc/sentry/pages\"").unwrap();
        assert_eq!(
            parsed.error_pages.dir,
            Some(std::path::PathBuf::from("/etc/sentry/pages"))
        );
    }

    #[test]
    fn edge_compress_defaults_are_on_and_parse() {
        let c = EdgeConfig::default();
        assert!(c.compress.enabled, "compression ships enabled");
        assert_eq!(c.compress.min_length, 256);
        assert_eq!(c.compress.level_br, 4);
        assert_eq!(c.compress.level_gzip, 6);
        assert_eq!(c.compress.level_zstd, 3);
        assert!(c.forwarded_headers);
        assert!(c.http2);
        assert_eq!(c.upstream_connect_timeout_secs, 5);
        assert_eq!(c.upstream_pool_idle, 32);

        let parsed: EdgeConfig = toml::from_str(
            r#"
            forwarded_headers = false
            http2 = false
            upstream_connect_timeout_secs = 2
            upstream_pool_idle = 8
            [compress]
            enabled = false
            min_length = 1024
            level_br = 9
            level_gzip = 1
            level_zstd = 19
            "#,
        )
        .unwrap();
        assert!(!parsed.forwarded_headers);
        assert!(!parsed.http2);
        assert_eq!(parsed.upstream_connect_timeout_secs, 2);
        assert_eq!(parsed.upstream_pool_idle, 8);
        assert!(!parsed.compress.enabled);
        assert_eq!(parsed.compress.min_length, 1024);
        assert_eq!(parsed.compress.level_br, 9);
        assert_eq!(parsed.compress.level_gzip, 1);
        assert_eq!(parsed.compress.level_zstd, 19);
    }

    #[test]
    fn edge_advisories_flag_double_tls_and_off_loopback_upstream() {
        let mut cfg = SentryConfig::default();
        cfg.deployment.mode = "inline".to_string();
        cfg.edge.upstream = "http://127.0.0.1:8080".to_string();
        assert!(
            cfg.edge_advisories().is_empty(),
            "loopback plain upstream is the recommended topology"
        );

        // TLS at the edge + https upstream = double TLS.
        cfg.edge.tls_cert = Some("/certs/fullchain.pem".into());
        cfg.edge.tls_key = Some("/certs/privkey.pem".into());
        cfg.edge.upstream = "https://backend.internal:8443".to_string();
        let advisories = cfg.edge_advisories();
        assert!(
            advisories.iter().any(|a| a.contains("double TLS")),
            "{advisories:?}"
        );

        // Off-loopback plain upstream = unencrypted hop.
        cfg.edge.upstream = "http://10.0.0.5:80".to_string();
        let advisories = cfg.edge_advisories();
        assert!(
            advisories
                .iter()
                .any(|a| a.contains("off-loopback over plain http")),
            "{advisories:?}"
        );
        assert!(
            !advisories.iter().any(|a| a.contains("double TLS")),
            "plain upstream is not a double-TLS problem"
        );

        // Passive mode: only the inert-compression note.
        let mut cfg = SentryConfig::default();
        cfg.deployment.mode = "passive".to_string();
        let advisories = cfg.edge_advisories();
        assert_eq!(advisories.len(), 1, "{advisories:?}");
        assert!(advisories[0].contains("not inline"));
        cfg.edge.compress.enabled = false;
        assert!(cfg.edge_advisories().is_empty());
    }

    #[test]
    fn edge_advisories_grade_vhost_upstreams() {
        let toml = r#"
            [deployment]
            mode = "inline"
            [edge]
            upstream = "http://127.0.0.1:8080"
            [[edge.vhosts]]
            host = "app.example.com"
            upstreams = ["http://web:3000", "https://api.internal:8443"]
            "#;
        let cfg: SentryConfig = toml::from_str(toml).unwrap();
        let advisories = cfg.edge_advisories();
        // `web` (container name, plain http) trips the off-loopback note
        // labeled with the vhost; `127.0.0.1` stays silent.
        assert!(
            advisories
                .iter()
                .any(|a| a.contains("(vhost app.example.com)") && a.contains("off-loopback")),
            "{advisories:?}"
        );
        // https upstream without TLS at the edge is not a double-TLS issue.
        assert!(!advisories.iter().any(|a| a.contains("double TLS")));

        // With TLS at the edge, the https vhost upstream becomes double TLS.
        let mut cfg = cfg.clone();
        cfg.edge.tls_cert = Some("/c.pem".into());
        cfg.edge.tls_key = Some("/k.pem".into());
        assert!(cfg
            .edge_advisories()
            .iter()
            .any(|a| a.contains("double TLS")));
    }

    #[test]
    fn edge_vhosts_parse_with_inheritance_defaults() {
        let toml = r#"
            [edge]
            upstream = "http://127.0.0.1:8080"
            balance = "least_conn"
            max_fails = 5
            [[edge.vhosts]]
            host = "App.Example.com"
            upstreams = ["http://web-a:3000", "http://web-b:3000"]
            [[edge.vhosts]]
            host = "*.api.example.com"
            upstreams = ["http://api:8080"]
            balance = "ip_hash"
            max_fails = 1
            fail_timeout_secs = 10
            health_path = "/healthz"
            "#;
        let cfg: SentryConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.edge.balance, BalanceMode::LeastConn);
        assert_eq!(cfg.edge.max_fails, 5);
        assert_eq!(cfg.edge.vhosts.len(), 2);

        let first = &cfg.edge.vhosts[0];
        assert_eq!(first.host, "App.Example.com");
        assert_eq!(first.upstreams, ["http://web-a:3000", "http://web-b:3000"]);
        assert_eq!(
            first.effective_balance(cfg.edge.balance),
            BalanceMode::LeastConn
        );
        assert_eq!(first.effective_max_fails(cfg.edge.max_fails), 5);
        assert_eq!(first.effective_fail_timeout(cfg.edge.fail_timeout_secs), 30);
        assert_eq!(first.effective_health_path(&cfg.edge.health_path), "/");

        let second = &cfg.edge.vhosts[1];
        assert_eq!(
            second.effective_balance(BalanceMode::RoundRobin),
            BalanceMode::IpHash
        );
        assert_eq!(second.effective_max_fails(2), 1);
        assert_eq!(second.effective_fail_timeout(30), 10);
        assert_eq!(second.effective_health_path("/"), "/healthz");
    }

    #[test]
    fn edge_validate_flags_bad_vhosts_and_upstreams() {
        let vhost = |host: &str, upstreams: &[&str]| EdgeVhostConfig {
            host: host.to_string(),
            upstreams: upstreams.iter().map(|s| s.to_string()).collect(),
            balance: None,
            max_fails: None,
            fail_timeout_secs: None,
            health_path: None,
            tls_cert: None,
            tls_key: None,
        };
        let mut cfg = EdgeConfig::default();
        assert!(cfg.validate().is_empty(), "defaults validate cleanly");

        cfg.upstream = "127.0.0.1:8080".to_string();
        assert!(cfg.validate().iter().any(|e| e.contains("http://")));
        cfg.upstream = "http://127.0.0.1:8080".to_string();

        cfg.vhosts
            .push(vhost("app.example.com", &["http://web:3000"]));
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());

        // Duplicate host.
        cfg.vhosts
            .push(vhost("app.example.com", &["http://other:80"]));
        assert!(cfg.validate().iter().any(|e| e.contains("duplicate")));

        // Uppercase host + missing upstreams.
        cfg.vhosts.clear();
        cfg.vhosts.push(vhost("App.Example.com", &[]));
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.contains("lowercase")), "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("upstreams")), "{errors:?}");

        // `*` only as a leading `*.` wildcard.
        cfg.vhosts[0].host = "a*b.example.com".to_string();
        assert!(cfg
            .validate()
            .iter()
            .any(|e| e.contains("`*` is only valid")));
        cfg.vhosts[0].host = "*.example.com".to_string();
        cfg.vhosts[0].upstreams = vec!["http://api:8080".to_string()];
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());

        // Cert pairing; per-vhost cert requires the global TLS front.
        cfg.vhosts[0].host = "app.example.com".to_string();
        cfg.vhosts[0].upstreams = vec!["http://web:3000".to_string()];
        cfg.vhosts[0].tls_cert = Some("/c.pem".into());
        assert!(cfg
            .validate()
            .iter()
            .any(|e| e.contains("tls_cert and tls_key")));
        cfg.vhosts[0].tls_key = Some("/k.pem".into());
        assert!(cfg
            .validate()
            .iter()
            .any(|e| e.contains("requires the global [edge] tls_cert")));
        cfg.tls_cert = Some("/gc.pem".into());
        cfg.tls_key = Some("/gk.pem".into());
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
    }

    #[test]
    fn runtime_config_defaults_and_validate() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.worker_threads, 0);
        assert!(cfg.pin_cores.is_empty());
        assert_eq!(cfg.thread_priority, ThreadPriority::Normal);
        assert!(cfg.validate().is_empty());

        let parsed: RuntimeConfig = toml::from_str(
            r#"
            worker_threads = 4
            pin_cores = [0, 2]
            thread_priority = "high"
            "#,
        )
        .unwrap();
        assert_eq!(parsed.worker_threads, 4);
        assert_eq!(parsed.pin_cores, [0, 2]);
        assert_eq!(parsed.thread_priority, ThreadPriority::High);

        let bad = RuntimeConfig {
            worker_threads: 9999,
            pin_cores: vec![3, 3, 999999],
            thread_priority: ThreadPriority::Normal,
        };
        let errors = bad.validate();
        assert_eq!(errors.len(), 3, "{errors:?}");
    }

    #[test]
    fn edge_defaults_group_servers_merge_legacy_upstream() {
        let mut cfg = EdgeConfig::default();
        assert!(cfg.default_group_servers().is_empty());
        cfg.upstream = "http://a:1".to_string();
        assert_eq!(cfg.default_group_servers(), ["http://a:1"]);
        cfg.upstreams = vec!["http://b:2".to_string(), "http://c:3".to_string()];
        assert_eq!(cfg.default_group_servers(), ["http://b:2", "http://c:3"]);
    }

    #[test]
    fn upstream_host_parses_authority_forms() {
        assert_eq!(
            upstream_host("http://127.0.0.1:8080").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            upstream_host("https://backend.internal").as_deref(),
            Some("backend.internal")
        );
        assert_eq!(
            upstream_host("http://user:pw@10.0.0.9:9000/").as_deref(),
            Some("10.0.0.9")
        );
        assert_eq!(upstream_host("http://[::1]:8443").as_deref(), Some("::1"));
        assert_eq!(upstream_host("127.0.0.1:80"), None, "no scheme");
        assert_eq!(upstream_host(""), None);
    }

    #[test]
    fn posture_default_is_shadow_and_on() {
        let c = PostureConfig::default();
        assert!(c.enabled, "advisories inform by default");
        assert_eq!(c.mode, PostureMode::Shadow);
        assert_eq!(c.dedupe_ttl_secs, 3600);
        assert_eq!(c.hsts_min_max_age, 31_536_000);
        assert!(c.checks.is_empty(), "empty = all checks");
        assert!(c.hosts.is_empty());
        assert!(c.unknown_checks().is_empty());
        assert_eq!(c.unknown_checks(), Vec::<String>::new());

        let parsed: PostureConfig = toml::from_str(
            r#"
            enabled = true
            checks = ["csp", "hsts", "bogus_check"]
            hosts = ["Example.com"]
        "#,
        )
        .unwrap();
        assert_eq!(parsed.unknown_checks(), vec!["bogus_check".to_string()]);
        let scan = crate::posture::PostureScan::from_config(&parsed);
        assert!(scan.checks.contains("csp"));
        assert!(scan.checks.contains("hsts"));
        assert!(!scan.checks.contains("coop"), "explicit list replaces all");
        assert!(scan.hosts.contains("example.com"));

        let err = toml::from_str::<PostureConfig>("mode = \"block\"");
        assert!(err.is_err(), "typos must fail at config-load time");
    }
}
