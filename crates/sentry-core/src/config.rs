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
    /// Rate-limit backend for `RuleMatch::Rate` conditions.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Prometheus metrics server.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Background route learner.
    #[serde(default)]
    pub route_learner: RouteLearnerConfig,
    /// Event sources.
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceConfig>,
    /// Response actions.
    #[serde(default, rename = "action")]
    pub actions: Vec<ActionConfig>,
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
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            channel_buffer: default_channel_buffer(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/sentry")
}

fn default_channel_buffer() -> usize {
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// `postgres://user:pass@host:port/db`
    #[serde(default)]
    pub url: String,
    /// Max connections in the pool.
    #[serde(default = "default_pg_max_conn")]
    pub max_connections: u32,
}

fn default_pg_max_conn() -> u32 {
    10
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

fn default_llm_provider() -> String {
    "none".to_string()
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
}

/// A default rule pack entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
}

/// A reputation feed to sync.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Feed name (used as the rule tag prefix).
    pub name: String,
    /// URL to fetch the feed from.
    pub url: String,
    /// Refresh interval in hours.
    #[serde(default = "default_feed_refresh")]
    pub refresh_hours: u32,
    /// Action to apply to feed entries.
    pub action: String,
}

fn default_feed_refresh() -> u32 {
    24
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
            Self::Log => "log",
        }
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
