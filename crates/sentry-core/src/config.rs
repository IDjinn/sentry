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
    /// LLM provider.
    #[serde(default)]
    pub llm: LlmConfig,
    /// Rules engine.
    #[serde(default)]
    pub rules: RulesConfig,
    /// Event sources.
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    /// Response actions.
    #[serde(default)]
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
    #[serde(default)]
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
    /// Plugin kind: `cloudflare` | `webhook` | `blocklist` | `log`.
    #[serde(rename = "type")]
    pub kind: ActionKind,
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
    Cloudflare,
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
