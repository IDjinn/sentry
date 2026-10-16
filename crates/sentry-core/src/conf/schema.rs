//! Typed shape of `sentry.conf` (what users write). Every field is optional:
//! lowering starts from [`SentryConfig::default`](crate::config::SentryConfig)
//! and applies only what the file sets.

#![allow(missing_docs)]

use std::path::PathBuf;

use sentry_conf::{Bytes, ConfValue, Millis, OneOrMany, OrderedMap, RawBlock, Secs};
use serde::{Deserialize, Serialize};

use crate::config::{
    BalanceMode, ChallengeBackend, FeedKind, OversizePolicy, PostureMode, ThreadPriority,
    UploadMode,
};

macro_rules! conf_struct {
    ($(#[$m:meta])* $name:ident { $($(#[$fm:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields, default)]
        pub struct $name {
            $($(#[$fm])* pub $field: $ty,)*
        }
    };
}

conf_struct!(
    /// The whole file set.
    ConfFile {
        sentry: Option<SentryBlock>,
        server: Option<ServerBlock>,
        storage: Option<StorageBlock>,
        detect: Option<DetectBlock>,
        trust: Option<TrustBlock>,
        rules: Option<RulesBlock>,
        routes: Option<OrderedMap<OneOrMany<String>>>,
        source: Vec<RawBlock>,
        action: Vec<RawBlock>,
        dashboard: Option<DashboardBlock>,
        metrics: Option<MetricsBlock>,
        http: Option<HttpBlock>,
        tcp: Option<TcpBlock>,
    }
);

conf_struct!(
    /// `sentry {}` — instance-level settings.
    SentryBlock {
        mode: Option<String>,
        instance_id: Option<String>,
        runtime: Option<RuntimeBlock>,
        update: Option<UpdateBlock>,
        auto: Option<AutoBlock>,
    }
);

conf_struct!(RuntimeBlock {
    worker_threads: Option<usize>,
    pin_cores: Option<OneOrMany<usize>>,
    priority: Option<ThreadPriority>,
});

conf_struct!(UpdateBlock {
    enabled: Option<bool>,
    #[serde(alias = "interval_secs")]
    interval: Option<Secs>,
    repo: Option<String>,
    auto_restart: Option<bool>,
});

conf_struct!(AutoBlock {
    skip: Option<OneOrMany<String>>,
    enable: Option<OneOrMany<String>>,
});

conf_struct!(
    /// `server {}` — the detection engine core.
    ServerBlock {
        #[serde(alias = "data_dir")]
        data_directory: Option<PathBuf>,
        channel_buffer: Option<usize>,
        action_buffer: Option<usize>,
        action_workers: Option<usize>,
        persist_buffer: Option<usize>,
        #[serde(alias = "dedupe_ttl_secs")]
        dedupe_ttl: Option<Secs>,
        geo: Option<GeoBlock>,
        policy: Option<PolicyBlock>,
        scorer: Option<ScorerBlock>,
        escalation: Option<EscalationBlock>,
        overload: Option<OverloadBlock>,
    }
);

conf_struct!(GeoBlock {
    city_db: Option<PathBuf>,
    asn_db: Option<PathBuf>,
});

conf_struct!(PolicyBlock {
    info: Option<String>,
    low: Option<String>,
    medium: Option<String>,
    high: Option<String>,
    critical: Option<String>,
    #[serde(rename = "override")]
    overrides: Vec<OverrideBlock>,
});

conf_struct!(
    /// `override 'DSL' { verdict: block }` (or `match:` inside the block).
    OverrideBlock {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        #[serde(rename = "match")]
        match_: Option<String>,
        verdict: Option<String>,
    }
);

conf_struct!(ScorerBlock {
    repetition_bonus: Option<bool>,
    #[serde(alias = "repetition_window_secs")]
    repetition_window: Option<Secs>,
    weights: Option<OrderedMap<u8>>,
});

conf_struct!(EscalationBlock {
    enabled: Option<bool>,
    #[serde(alias = "window_secs")]
    window: Option<Secs>,
    challenge_at: Option<u32>,
    block_at: Option<u32>,
    persist: Option<bool>,
});

conf_struct!(OverloadBlock {
    enabled: Option<bool>,
    queue_pressure: Option<f64>,
    release_pressure: Option<f64>,
    #[serde(alias = "release_secs")]
    release: Option<Secs>,
    pg_insert_budget: Option<Millis>,
    sample_keep: Option<f64>,
    coalesce_benign: Option<bool>,
    #[serde(alias = "coalesce_window_secs")]
    coalesce_window: Option<Secs>,
    coalesce_cap: Option<usize>,
});

conf_struct!(
    /// `storage {}` — Postgres.
    StorageBlock {
        url: Option<String>,
        max_connections: Option<u32>,
        #[serde(alias = "acquire_timeout_secs")]
        acquire_timeout: Option<Secs>,
        #[serde(alias = "statement_timeout_secs")]
        statement_timeout: Option<Secs>,
    }
);

conf_struct!(
    /// `detect {}` — detectors and intelligence.
    DetectBlock {
        scan: Option<ScanBlock>,
        behavior: Option<BehaviorBlock>,
        correlation: Option<CorrelationBlock>,
        bot_verification: Option<BotVerificationBlock>,
        uploads: Option<UploadsBlock>,
        posture: Option<PostureBlock>,
        protocol: Option<ProtocolBlock>,
        route_learner: Option<RouteLearnerBlock>,
        ai: Option<AiBlock>,
        llm: Option<LlmBlock>,
        ip_lookup: Option<IpLookupBlock>,
    }
);

conf_struct!(ScanBlock {
    enabled: Option<bool>,
    #[serde(alias = "window_secs")]
    window: Option<Secs>,
    distinct_paths: Option<u32>,
    not_found: Option<u32>,
});

conf_struct!(BehaviorBlock {
    enabled: Option<bool>,
    #[serde(alias = "window_secs")]
    window: Option<Secs>,
    auth_failures: Option<u32>,
    distinct_uas: Option<u32>,
    wordlist_hits: Option<u32>,
    suspicious_success_min_failures: Option<u32>,
    login_patterns: Option<OneOrMany<String>>,
    wordlist_paths: Option<OneOrMany<String>>,
});

conf_struct!(CorrelationBlock {
    enabled: Option<bool>,
    #[serde(alias = "window_secs")]
    window: Option<Secs>,
});

conf_struct!(BotVerificationBlock {
    enabled: Option<bool>,
    #[serde(alias = "cache_ttl_secs")]
    cache_ttl: Option<Secs>,
    #[serde(alias = "failed_ttl_secs")]
    failed_ttl: Option<Secs>,
    timeout: Option<Millis>,
    batch_size: Option<usize>,
});

conf_struct!(UploadsBlock {
    enabled: Option<bool>,
    mode: Option<UploadMode>,
    inspect: Option<Bytes>,
    max_files: Option<usize>,
    scan_json: Option<bool>,
    oversize: Option<OversizePolicy>,
    blocked_extensions: Option<OneOrMany<String>>,
    allowed_extensions: Option<OneOrMany<String>>,
    allowed_content_types: Option<OneOrMany<String>>,
    methods: Option<OneOrMany<String>>,
    allowed_paths: Option<OneOrMany<String>>,
    allow_extensionless: Option<bool>,
    flood: Option<UploadFloodBlock>,
});

conf_struct!(UploadFloodBlock {
    #[serde(alias = "window_secs")]
    window: Option<Secs>,
    max_uploads: Option<u32>,
    max_total: Option<Bytes>,
});

conf_struct!(PostureBlock {
    enabled: Option<bool>,
    mode: Option<PostureMode>,
    #[serde(alias = "dedupe_ttl_secs")]
    dedupe_ttl: Option<Secs>,
    hsts_min_max_age: Option<u64>,
    checks: Option<OneOrMany<String>>,
    hosts: Option<OneOrMany<String>>,
});

conf_struct!(ProtocolBlock {
    enabled: Option<bool>,
    dir: Option<PathBuf>,
    #[serde(alias = "safety_poll_secs")]
    safety_poll: Option<Secs>,
    debounce: Option<Millis>,
    max_schemas: Option<usize>,
});

conf_struct!(RouteLearnerBlock {
    enabled: Option<bool>,
    #[serde(alias = "interval_secs")]
    interval: Option<Secs>,
    #[serde(alias = "window_secs")]
    window: Option<Secs>,
    min_hits: Option<u32>,
    min_ips: Option<u32>,
});

conf_struct!(AiBlock {
    enabled: Option<bool>,
    model_path: Option<PathBuf>,
    threshold: Option<f32>,
    signal_weight: Option<u8>,
    mode: Option<String>,
    trigger: Option<String>,
    min_score: Option<u8>,
    concurrency: Option<usize>,
    #[serde(alias = "cache_ttl_secs")]
    cache_ttl: Option<Secs>,
});

conf_struct!(LlmBlock {
    provider: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
    mode: Option<String>,
    only_above: Option<u8>,
    concurrency: Option<usize>,
    #[serde(alias = "cache_ttl_secs")]
    cache_ttl: Option<Secs>,
});

conf_struct!(IpLookupBlock {
    enabled: Option<bool>,
    provider: Option<String>,
    key_env: Option<String>,
    trigger_above: Option<u8>,
    on_signals: Option<OneOrMany<String>>,
    #[serde(alias = "cache_ttl_secs")]
    cache_ttl: Option<Secs>,
    max_per_hour: Option<u32>,
    #[serde(alias = "timeout_secs")]
    timeout: Option<Secs>,
});

conf_struct!(
    /// `trust {}` — real client IP and trusted infrastructure.
    TrustBlock {
        #[serde(alias = "trusted_proxies")]
        proxies: Option<OneOrMany<String>>,
        cloudflare: Option<bool>,
        trusted_ips: Option<OneOrMany<String>>,
        trusted_lists: Option<OneOrMany<String>>,
        whitelist: Option<OneOrMany<String>>,
        blacklist: Option<OneOrMany<String>>,
        shadow: Option<OneOrMany<String>>,
        #[serde(alias = "refresh_secs")]
        refresh: Option<Secs>,
    }
);

conf_struct!(
    /// `rules {}`.
    RulesBlock {
        packs: Option<OrderedMap<String>>,
        pack: Vec<PackBlock>,
        rule: Vec<RuleBlock>,
        feed_presets: Option<OneOrMany<String>>,
        feed: Vec<FeedBlock>,
        rate_limit: Option<RateLimitBlock>,
    }
);

conf_struct!(
    /// `pack NAME { mode, params… }`.
    PackBlock {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        mode: Option<String>,
        countries: Option<OneOrMany<String>>,
        domains: Option<OneOrMany<String>>,
    }
);

conf_struct!(
    /// `rule "name" { match, action, … }`.
    RuleBlock {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        priority: Option<i32>,
        #[serde(rename = "match")]
        match_: Option<String>,
        action: Option<String>,
        tags: Option<OneOrMany<String>>,
        #[serde(alias = "log_level")]
        log: Option<String>,
    }
);

conf_struct!(
    /// `feed NAME { url, … }`.
    FeedBlock {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        url: Option<String>,
        kind: Option<FeedKind>,
        refresh: Option<Secs>,
        refresh_hours: Option<u32>,
        tier: Option<String>,
        action: Option<String>,
        enabled: Option<bool>,
        headers_env: Option<OrderedMap<String>>,
    }
);

conf_struct!(RateLimitBlock {
    backend: Option<String>,
    redis_url: Option<String>,
});

conf_struct!(
    /// `dashboard {}` — `sentry serve`.
    DashboardBlock {
        listen: Option<String>,
        webhook_secret_env: Option<String>,
        auth: Option<AuthBlock>,
    }
);

conf_struct!(AuthBlock {
    mode: Option<String>,
    session_secret_env: Option<String>,
    #[serde(alias = "session_ttl_secs")]
    session_ttl: Option<Secs>,
    user: Vec<UserBlock>,
    token: Vec<TokenBlock>,
});

conf_struct!(UserBlock {
    #[serde(rename = "$labels")]
    labels: Vec<String>,
    password_hash: Option<String>,
    role: Option<String>,
});

conf_struct!(TokenBlock {
    #[serde(rename = "$labels")]
    labels: Vec<String>,
    token_sha256: Option<String>,
    token_env: Option<String>,
    role: Option<String>,
});

conf_struct!(MetricsBlock {
    enabled: Option<bool>,
    listen: Option<String>,
});

conf_struct!(
    /// `http {}` — the inline edge.
    HttpBlock {
        listen: Option<String>,
        tls: Option<TlsBlock>,
        forwarded_headers: Option<bool>,
        response_buffering: Option<bool>,
        body_capture: Option<Bytes>,
        max_concurrent_requests: Option<usize>,
        upstream_timeout: Option<Secs>,
        upstream_connect_timeout: Option<Secs>,
        upstream_pool_idle: Option<usize>,
        health_timeout: Option<Secs>,
        health_path: Option<String>,
        balance: Option<BalanceMode>,
        max_fails: Option<u32>,
        fail_timeout: Option<Secs>,
        socket: Option<SocketBlock>,
        compress: Option<CompressBlock>,
        challenge: Option<ChallengeBlock>,
        error_pages: Option<PathBuf>,
        upstream: Vec<UpstreamBlock>,
        security: Option<SecurityBlock>,
        site: Vec<SiteBlock>,
        location: Vec<LocationBlock>,
        proxy_pass: Option<String>,
    }
);

conf_struct!(TlsBlock {
    listen: Option<String>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    redirect_https: Option<bool>,
    http2: Option<bool>,
    handshake_events: Option<bool>,
    allowed_hosts: Option<OneOrMany<String>>,
});

conf_struct!(SocketBlock {
    reuseport_workers: Option<usize>,
    backlog: Option<u32>,
    nodelay: Option<bool>,
    keepalive: Option<Secs>,
    send_buffer: Option<Bytes>,
    recv_buffer: Option<Bytes>,
});

conf_struct!(CompressBlock {
    enabled: Option<bool>,
    min_length: Option<usize>,
    level_br: Option<u8>,
    level_gzip: Option<u8>,
    level_zstd: Option<u8>,
});

conf_struct!(ChallengeBlock {
    backend: Option<ChallengeBackend>,
    enabled: Option<bool>,
    secret_env: Option<String>,
    bucket: Option<Secs>,
    difficulty: Option<u8>,
    title: Option<String>,
    template: Option<PathBuf>,
});

conf_struct!(
    /// `upstream NAME { server: … }`.
    UpstreamBlock {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        server: Option<OneOrMany<String>>,
        balance: Option<BalanceMode>,
        max_fails: Option<u32>,
        fail_timeout: Option<Secs>,
        health_path: Option<String>,
    }
);

conf_struct!(
    /// `security {}` at http, site or location level.
    SecurityBlock {
        mode: Option<crate::edge_routes::SecurityMode>,
        policy: Option<LevelPolicyBlock>,
        challenge: Option<String>,
        rate_limit: Option<ConfValue>,
        allow: Option<OneOrMany<String>>,
        deny: Option<OneOrMany<String>>,
        packs: Option<OrderedMap<String>>,
    }
);

conf_struct!(LevelPolicyBlock {
    info: Option<String>,
    low: Option<String>,
    medium: Option<String>,
    high: Option<String>,
    critical: Option<String>,
});

conf_struct!(
    /// `site { host: …, location … }`.
    SiteBlock {
        host: Option<OneOrMany<String>>,
        default: Option<bool>,
        tls: Option<SiteTlsBlock>,
        location: Vec<LocationBlock>,
        proxy_pass: Option<String>,
        #[serde(rename = "return")]
        return_: Option<OneOrMany<ConfValue>>,
        redirect: Option<OneOrMany<ConfValue>>,
        set_request_header: Vec<(String, String)>,
        remove_request_header: Option<OneOrMany<String>>,
        set_response_header: Vec<(String, String)>,
        remove_response_header: Option<OneOrMany<String>>,
        security: Option<SecurityBlock>,
    }
);

conf_struct!(SiteTlsBlock {
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
});

conf_struct!(
    /// `location [=|^~|~|~*] "path" { … }`.
    LocationBlock {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        #[serde(rename = "match")]
        match_: Option<OrderedMap<ConfValue>>,
        proxy_pass: Option<String>,
        #[serde(rename = "return")]
        return_: Option<OneOrMany<ConfValue>>,
        redirect: Option<OneOrMany<ConfValue>>,
        rewrite: Vec<(String, String)>,
        set_request_header: Vec<(String, String)>,
        remove_request_header: Option<OneOrMany<String>>,
        set_response_header: Vec<(String, String)>,
        remove_response_header: Option<OneOrMany<String>>,
        timeout: Option<Secs>,
        response_buffering: Option<bool>,
        security: Option<SecurityBlock>,
    }
);

conf_struct!(
    /// `tcp {}` — inline TCP front.
    TcpBlock {
        listen: Option<String>,
        proxy_pass: Option<String>,
    }
);
