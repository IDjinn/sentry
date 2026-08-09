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
pub mod challenge;
pub mod config;
pub mod error;
pub mod event;
pub mod heuristics;
pub mod packs;
pub mod pipeline;
pub mod registry;
pub mod rules;
pub mod source;

pub use action::Action;
pub use analysis::{AnalysisResult, Decision, RiskLevel, Signal, SignalKind, Verdict};
pub use challenge::{ChallengeAction, ChallengeProvider, EdgeMode, EdgeOptions};
pub use config::{
    ActionConfig, ActionKind, CoreConfig, FeedConfig, GeoConfig, LlmConfig, PostgresConfig,
    RouteDefConfig, RoutesConfig, RuleDefConfig, RulePackConfig, RulesConfig, ScorerConfig,
    SentryConfig, SourceConfig, StorageConfig,
};
pub use error::{CoreError, Result};
pub use event::{
    Direction, Event, GeoInfo, HttpData, HttpMethod, ProtocolData, ProtocolKind, RawData, RawEvent,
    SourceKind, TcpData, TcpFlags, TcpStage, TlsData, Transport, UdpData,
};
pub use heuristics::{Heuristic, HeuristicEngine};
pub use packs::{build_default_ruleset, PackMode};
pub use pipeline::{Pipeline, ProcessedEvent, RouteDef, RouteValidator};
pub use registry::{Registry, RegistryBuilder};
pub use rules::{
    dsl, shared, Rule, RuleAction, RuleId, RuleMatch, RuleSet, RuleSource, SharedRuleSet,
};
pub use source::Source;
