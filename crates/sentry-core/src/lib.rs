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
pub mod challenge;
pub mod config;
pub mod error;
pub mod event;
pub mod heuristics;
pub mod offender;
pub mod packs;
pub mod pipeline;
pub mod policy;
pub mod ratelimit;
pub mod registry;
pub mod reputation;
pub mod routes_learn;
pub mod rules;
pub mod scan;
pub mod source;
pub mod tcpfp;

pub use action::{Action, ActionContext};
pub use analysis::{AnalysisResult, Decision, RiskLevel, Signal, SignalKind, Verdict};
pub use behavior::BehaviorTracker;
pub use challenge::{ChallengeAction, ChallengeProvider, EdgeMode, EdgeOptions};
pub use config::{
    ActionConfig, ActionKind, AiConfig, AuthTokenConfig, AuthUserConfig, BehaviorConfig,
    CoreConfig, DeploymentConfig, EdgeConfig, EscalationConfig, FeedConfig, GeoConfig, LlmConfig,
    MetricsConfig, PolicyConfig, PolicyOverrideConfig, PostgresConfig, RateLimitConfig,
    RouteDefConfig, RouteLearnerConfig, RoutesConfig, RuleDefConfig, RulePackConfig, RulesConfig,
    ScanConfig, ScorerConfig, SentryConfig, ServerAuthConfig, ServerConfig, SourceConfig,
    StorageConfig,
};
pub use error::{CoreError, Result};
pub use event::{
    Direction, Event, GeoInfo, HttpData, HttpMethod, ProtocolData, ProtocolKind, RawData, RawEvent,
    ReputationInfo, SourceKind, SyslogData, TcpData, TcpFlags, TcpStage, TlsData, Transport,
    UdpData,
};
pub use heuristics::{Heuristic, HeuristicEngine};
pub use offender::OffenderTracker;
pub use packs::{build_default_ruleset, PackMode};
pub use pipeline::{Pipeline, ProcessedEvent, RouteDef, RouteLike, RouteValidator};
pub use policy::VerdictPolicy;
pub use ratelimit::{InMemoryRateLimiter, RateLimitBackend};
pub use registry::{Registry, RegistryBuilder};
pub use reputation::{
    feed_rule, parse_feed, reputation_signals, ReputationStore, KNOWN_BAD_IP_WEIGHT,
    TOR_EXIT_NODE_WEIGHT, VPN_PROXY_WEIGHT,
};
pub use rules::{
    dsl, rules_from_config, shared, ReputationTier, Rule, RuleAction, RuleId, RuleMatch, RuleSet,
    RuleSource, SharedRuleSet,
};
pub use scan::ScanTracker;
pub use source::Source;
