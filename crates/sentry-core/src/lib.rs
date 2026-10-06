//! Sentry core library.
//!
//! Contains the domain model ([`Event`], [`ProtocolData`], [`AnalysisResult`]),
//! the plugin traits ([`Source`], [`Action`]), the rules engine types and the
//! shared error type.
//!
//! The core is intentionally free of any I/O implementation — it only defines
//! contracts that plugins (`sentry-source-*`, `sentry-action-*`) fulfil.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod action;
pub mod analysis;
pub mod behavior;
pub mod blocks;
pub mod botverify;
pub mod challenge;
pub mod config;
pub mod correlation;
pub mod error;
pub mod event;
pub mod heuristics;
pub mod lists;
pub mod multipart;
pub mod offender;
pub mod packs;
pub mod pipeline;
pub mod policy;
pub mod posture;
pub mod ratelimit;
pub mod registry;
pub mod reputation;
pub mod routes_learn;
pub mod rules;
pub mod scan;
pub mod source;
pub mod tcpfp;
pub mod trust;
pub mod trusted_lists;
pub mod uploads;

pub use action::{Action, ActionContext};
pub use analysis::{
    AnalysisResult, Decision, RiskLevel, RuleLogLevel, Signal, SignalKind, Verdict,
};
pub use behavior::BehaviorTracker;
pub use blocks::BlockTable;
pub use botverify::{
    claimed_engine, forward_confirms, hostname_matches, verify_with, BotDnsResolver, BotEngine,
    BotStatus, BotVerifier, SharedBotVerifier, SPOOFED_BOT_WEIGHT,
};
pub use challenge::{ChallengeAction, ChallengeProvider, EdgeMode, EdgeOptions};
pub use config::{
    ActionConfig, ActionKind, AiConfig, AuthTokenConfig, AuthUserConfig, BehaviorConfig,
    BotVerificationConfig, CoreConfig, CorrelationConfig, DeploymentConfig, EdgeChallengeConfig,
    EdgeConfig, EscalationConfig, FeedConfig, FeedKind, GeoConfig, IpLookupConfig, LlmConfig,
    MetricsConfig, PolicyConfig, PolicyOverrideConfig, PostgresConfig, PostureConfig, PostureMode,
    RateLimitConfig, RealIpConfig, RouteDefConfig, RouteLearnerConfig, RoutesConfig, RuleDefConfig,
    RulePackConfig, RulesConfig, ScanConfig, ScorerConfig, SentryConfig, ServerAuthConfig,
    ServerConfig, SourceConfig, StorageConfig, UploadFloodConfig, UploadMode, UploadsConfig,
};
pub use correlation::CorrelationTracker;
pub use error::{CoreError, Result};
pub use event::{
    Direction, Event, GeoInfo, HttpData, HttpMethod, ProtocolData, ProtocolKind, RawData, RawEvent,
    ReputationInfo, SourceKind, SyslogData, TcpData, TcpFlags, TcpStage, TlsData, Transport,
    UdpData, UploadInfo, UploadKind,
};
pub use heuristics::{Heuristic, HeuristicEngine};
pub use offender::OffenderTracker;
pub use packs::{build_default_ruleset, PackMode};
pub use pipeline::{Pipeline, ProcessedEvent, RouteDef, RouteLike, RouteValidator};
pub use policy::VerdictPolicy;
pub use posture::{PostureFinding, PostureScan, PostureTracker};
pub use ratelimit::{InMemoryRateLimiter, RateLimitBackend};
pub use registry::{Registry, RegistryBuilder};
pub use reputation::{
    dataset_rule, feed_rule, parse_feed, parse_string_list, reputation_signals, ReputationStore,
    KNOWN_BAD_IP_WEIGHT, MAX_DATASET_ENTRIES, TOR_EXIT_NODE_WEIGHT, VPN_PROXY_WEIGHT,
};
pub use rules::{
    dsl, rules_from_config, shared, ReputationTier, Rule, RuleAction, RuleId, RuleMatch, RuleSet,
    RuleSource, SharedRuleSet,
};
pub use scan::ScanTracker;
pub use source::Source;
pub use trust::{SharedTrustSet, TrustSet};
pub use trusted_lists::{matching_presets, preset, PRESETS};
pub use uploads::{UploadTracker, UploadsScan};
