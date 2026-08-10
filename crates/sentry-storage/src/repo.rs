//! Repositories: typed access to each table.
//!
//! Each repo wraps the shared [`PgPool`] and exposes async methods for the
//! daemon and CLI. All queries use `sqlx::query()` (runtime) so the crate
//! compiles without a live `DATABASE_URL` at build time.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sentry_core::analysis::{RiskLevel, Verdict};
use sentry_core::event::Event;
use sentry_core::rules::{RuleAction, RuleSet, RuleSource};

use crate::error::{Result, StorageError};
use crate::pool::PgPool;

/// Generic repo handle carrying the pool.
#[derive(Clone)]
pub struct Repo {
    pool: PgPool,
}

impl Repo {
    /// Create a repo backed by the given pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Access the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Borrow the events repo.
    pub fn events(&self) -> EventRepo {
        EventRepo {
            pool: self.pool.clone(),
        }
    }

    /// Borrow the incidents repo.
    pub fn incidents(&self) -> IncidentRepo {
        IncidentRepo {
            pool: self.pool.clone(),
        }
    }

    /// Borrow the ip-state repo.
    pub fn ip_state(&self) -> IpStateRepo {
        IpStateRepo {
            pool: self.pool.clone(),
        }
    }

    /// Borrow the rules repo.
    pub fn rules(&self) -> RuleRepo {
        RuleRepo {
            pool: self.pool.clone(),
        }
    }

    /// Borrow the routes repo.
    pub fn routes(&self) -> RouteRepo {
        RouteRepo {
            pool: self.pool.clone(),
        }
    }
}

// ─── EventRepo ──────────────────────────────────────────────────────────────

/// Repository for the `events` table.
#[derive(Clone)]
pub struct EventRepo {
    pool: PgPool,
}

/// Row representation for event inserts/queries.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct EventRow {
    /// Event id.
    pub id: Uuid,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Source kind.
    pub source: String,
    /// Client IP (text form).
    pub client_ip: String,
    /// Client port.
    pub client_port: Option<i32>,
    /// Server port.
    pub server_port: Option<i32>,
    /// ASN.
    pub asn: Option<i64>,
    /// Country code.
    pub country: Option<String>,
    /// Protocol data (JSON).
    pub protocol: serde_json::Value,
    /// Risk score.
    pub risk_score: i16,
    /// Risk level.
    pub risk_level: String,
    /// Verdict.
    pub verdict: String,
    /// Signals (JSON).
    pub signals: serde_json::Value,
    /// Raw original record.
    pub raw: Option<String>,
}

impl EventRepo {
    /// Insert an event with its analysis result.
    pub async fn insert(
        &self,
        evt: &Event,
        risk_score: u8,
        risk_level: RiskLevel,
        verdict: Verdict,
        signals: &serde_json::Value,
    ) -> Result<()> {
        let protocol_json = serde_json::to_value(&evt.protocol)
            .map_err(|e| StorageError::Query(format!("protocol serialize: {e}")))?;
        let source = evt.source.as_str();
        let risk_level_str = risk_level_label(risk_level);
        let verdict_str = verdict_label(verdict);

        sqlx::query(
            r#"INSERT INTO events
               (id, timestamp, source, client_ip, client_port, server_port,
                asn, country, protocol, risk_score, risk_level, verdict, signals, raw)
               VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(evt.id)
        .bind(evt.timestamp)
        .bind(source)
        .bind(evt.client_ip.to_string())
        .bind(evt.client_port.map(|p| p as i32))
        .bind(evt.server_port.map(|p| p as i32))
        .bind(evt.asn.map(|a| a as i64))
        .bind(evt.geo.as_ref().and_then(|g| g.country.clone()))
        .bind(protocol_json)
        .bind(risk_score as i16)
        .bind(risk_level_str)
        .bind(verdict_str)
        .bind(signals)
        .bind(evt.raw.as_deref())
        .execute(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Fetch recent events (newest first).
    pub async fn recent(&self, limit: i64) -> Result<Vec<EventRow>> {
        let rows = sqlx::query_as::<_, EventRow>(
            r#"SELECT id, timestamp, source, client_ip::text AS client_ip,
                      client_port, server_port, asn, country,
                      protocol, risk_score, risk_level, verdict, signals, raw
               FROM events
               ORDER BY timestamp DESC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Fetch all events since a given timestamp (oldest first).
    ///
    /// Used by the background route learner to scan a sliding window.
    pub async fn recent_since(&self, since: DateTime<Utc>) -> Result<Vec<EventRow>> {
        let rows = sqlx::query_as::<_, EventRow>(
            r#"SELECT id, timestamp, source, client_ip::text AS client_ip,
                      client_port, server_port, asn, country,
                      protocol, risk_score, risk_level, verdict, signals, raw
               FROM events
               WHERE timestamp >= $1
               ORDER BY timestamp ASC"#,
        )
        .bind(since)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Count events by risk level.
    pub async fn count_by_level(&self) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT risk_level, COUNT(*)::bigint FROM events GROUP BY risk_level"#,
        )
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Count events by risk level since a given timestamp.
    pub async fn count_by_level_since(&self, since: DateTime<Utc>) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT risk_level, COUNT(*)::bigint
               FROM events WHERE timestamp >= $1
               GROUP BY risk_level ORDER BY risk_level"#,
        )
        .bind(since)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Count events per hour since `since`.
    pub async fn queries_per_hour(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Vec<(DateTime<Utc>, i64)>> {
        let rows: Vec<(DateTime<Utc>, i64)> = sqlx::query_as(
            r#"SELECT date_trunc('hour', timestamp) AS bucket,
                      COUNT(*)::bigint AS n
               FROM events WHERE timestamp >= $1
               GROUP BY bucket ORDER BY bucket"#,
        )
        .bind(since)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Top client IPs by event count since `since`.
    pub async fn top_ips(&self, limit: i64, since: DateTime<Utc>) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT client_ip, COUNT(*)::bigint AS n
               FROM events WHERE timestamp >= $1
               GROUP BY client_ip ORDER BY n DESC LIMIT $2"#,
        )
        .bind(since)
        .bind(limit)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Top request paths by event count since `since`.
    pub async fn top_paths(&self, limit: i64, since: DateTime<Utc>) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT protocol->>'path' AS path, COUNT(*)::bigint AS n
               FROM events WHERE timestamp >= $1 AND protocol->>'path' IS NOT NULL
               GROUP BY path ORDER BY n DESC LIMIT $2"#,
        )
        .bind(since)
        .bind(limit)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Count events by verdict since `since`.
    pub async fn count_by_verdict_since(&self, since: DateTime<Utc>) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT verdict, COUNT(*)::bigint
               FROM events WHERE timestamp >= $1
               GROUP BY verdict ORDER BY verdict"#,
        )
        .bind(since)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }
}

// ─── IncidentRepo ───────────────────────────────────────────────────────────

/// Repository for the `incidents` table.
#[derive(Clone)]
pub struct IncidentRepo {
    pool: PgPool,
}

/// Row representation for incidents.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct IncidentRow {
    /// Incident id.
    pub id: Uuid,
    /// Related event id.
    pub event_id: Option<Uuid>,
    /// Created at.
    pub created_at: DateTime<Utc>,
    /// Risk level.
    pub risk_level: String,
    /// Action taken.
    pub action: String,
    /// Resolved flag.
    pub resolved: bool,
    /// Notes.
    pub notes: Option<String>,
}

impl IncidentRepo {
    /// Create a new incident.
    pub async fn create(
        &self,
        event_id: Option<Uuid>,
        risk_level: RiskLevel,
        action: Verdict,
        notes: Option<&str>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO incidents (id, event_id, risk_level, action, notes)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(id)
        .bind(event_id)
        .bind(risk_level_label(risk_level))
        .bind(verdict_label(action))
        .bind(notes)
        .execute(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(id)
    }

    /// Fetch unresolved incidents.
    pub async fn unresolved(&self, limit: i64) -> Result<Vec<IncidentRow>> {
        let rows = sqlx::query_as::<_, IncidentRow>(
            r#"SELECT id, event_id, created_at, risk_level, action, resolved, notes
               FROM incidents
               WHERE resolved = false
               ORDER BY created_at DESC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Mark an incident as resolved.
    pub async fn resolve(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE incidents SET resolved = true WHERE id = $1")
            .bind(id)
            .execute(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }
}

// ─── IpStateRepo ────────────────────────────────────────────────────────────

/// Repository for the `ip_state` table.
#[derive(Clone)]
pub struct IpStateRepo {
    pool: PgPool,
}

/// Row representation for ip_state.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct IpStateRow {
    /// IP address (text).
    pub ip: String,
    /// Status (blocked, allowed, etc.).
    pub status: String,
    /// Reason.
    pub reason: Option<String>,
    /// Expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Last updated.
    pub updated_at: DateTime<Utc>,
}

impl IpStateRepo {
    /// Block an IP with optional TTL and reason.
    pub async fn block(
        &self,
        ip: IpAddr,
        reason: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO ip_state (ip, status, reason, expires_at)
               VALUES ($1::inet, 'blocked', $2, $3)
               ON CONFLICT (ip) DO UPDATE SET
                   status = 'blocked',
                   reason = $2,
                   expires_at = $3,
                   updated_at = now()"#,
        )
        .bind(ip.to_string())
        .bind(reason)
        .bind(expires_at)
        .execute(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Check if an IP is blocked.
    pub async fn is_blocked(&self, ip: IpAddr) -> Result<bool> {
        let row: (bool,) = sqlx::query_as(
            r#"SELECT EXISTS(
                   SELECT 1 FROM ip_state
                   WHERE ip = $1::inet AND status = 'blocked'
                     AND (expires_at IS NULL OR expires_at > now())
               )"#,
        )
        .bind(ip.to_string())
        .fetch_one(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(row.0)
    }

    /// List blocked IPs.
    pub async fn blocked(&self, limit: i64) -> Result<Vec<IpStateRow>> {
        let rows = sqlx::query_as::<_, IpStateRow>(
            r#"SELECT ip::text AS ip, status, reason, expires_at, updated_at
               FROM ip_state
               WHERE status = 'blocked'
               ORDER BY updated_at DESC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Remove an IP from the state table.
    pub async fn unblock(&self, ip: IpAddr) -> Result<()> {
        sqlx::query("DELETE FROM ip_state WHERE ip = $1::inet")
            .bind(ip.to_string())
            .execute(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }
}

// ─── RuleRepo ───────────────────────────────────────────────────────────────

/// Repository for the `rules` table.
#[derive(Clone)]
pub struct RuleRepo {
    pool: PgPool,
}

/// Row representation for rules.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct RuleRow {
    /// Rule id.
    pub id: String,
    /// Rule name.
    pub name: String,
    /// Priority.
    pub priority: i32,
    /// Enabled.
    pub enabled: bool,
    /// Match expression (DSL string).
    pub match_expr: String,
    /// Action.
    pub action: String,
    /// TTL in seconds.
    pub ttl_secs: Option<i32>,
    /// Source.
    pub source: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Created at.
    pub created_at: DateTime<Utc>,
}

impl RuleRepo {
    /// Load all enabled rules from the database into a [`RuleSet`].
    ///
    /// Rules with invalid DSL or action are skipped (with a warning logged).
    pub async fn load_ruleset(&self) -> Result<RuleSet> {
        let rows = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, priority, enabled, match_expr, action,
                      ttl_secs, source, tags, created_at
               FROM rules
               WHERE enabled = true
               ORDER BY priority ASC"#,
        )
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;

        let mut rules = Vec::new();
        for row in rows {
            let match_ = match sentry_core::rules::dsl::parse(&row.match_expr) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(rule_id = %row.id, error = %e, "skipping rule with invalid DSL");
                    continue;
                }
            };
            let action = match parse_rule_action(&row.action) {
                Some(a) => a,
                None => {
                    tracing::warn!(rule_id = %row.id, action = %row.action, "skipping rule with invalid action");
                    continue;
                }
            };
            let source = match row.source.as_str() {
                "db" => RuleSource::Db,
                "config" => RuleSource::Config,
                "cloudflare_sync" => RuleSource::CloudflareSync,
                "feed" => RuleSource::Feed,
                "auto_learned" => RuleSource::AutoLearned,
                "default_pack" => RuleSource::DefaultPack,
                _ => RuleSource::Db,
            };
            rules.push(sentry_core::rules::Rule {
                id: row.id,
                name: row.name,
                priority: row.priority,
                enabled: row.enabled,
                match_,
                action,
                ttl: row
                    .ttl_secs
                    .map(|t| std::time::Duration::from_secs(t as u64)),
                source,
                tags: row.tags,
                created_at: Some(row.created_at),
            });
        }

        Ok(RuleSet::new(rules))
    }

    /// Insert or update a rule (upsert by id).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        &self,
        id: &str,
        name: &str,
        priority: i32,
        enabled: bool,
        match_expr: &str,
        action: &str,
        ttl_secs: Option<i32>,
        tags: &[String],
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO rules (id, name, priority, enabled, match_expr, action, ttl_secs, source, tags)
               VALUES ($1, $2, $3, $4, $5, $6, $7, 'db', $8)
               ON CONFLICT (id) DO UPDATE SET
                   name = $2, priority = $3, enabled = $4, match_expr = $5,
                   action = $6, ttl_secs = $7, tags = $8"#,
        )
        .bind(id)
        .bind(name)
        .bind(priority)
        .bind(enabled)
        .bind(match_expr)
        .bind(action)
        .bind(ttl_secs)
        .bind(tags)
        .execute(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Delete a rule by id.
    pub async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM rules WHERE id = $1")
            .bind(id)
            .execute(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// List all rules.
    pub async fn list(&self) -> Result<Vec<RuleRow>> {
        let rows = sqlx::query_as::<_, RuleRow>(
            r#"SELECT id, name, priority, enabled, match_expr, action,
                      ttl_secs, source, tags, created_at
               FROM rules
               ORDER BY priority ASC"#,
        )
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Enable or disable a rule.
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        sqlx::query("UPDATE rules SET enabled = $2 WHERE id = $1")
            .bind(id)
            .bind(enabled)
            .execute(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }
}

// ─── RouteRepo ──────────────────────────────────────────────────────────────

/// Repository for the `routes` table.
#[derive(Clone)]
pub struct RouteRepo {
    pool: PgPool,
}

/// Row representation for routes.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct RouteRow {
    /// Route id.
    pub id: i32,
    /// Path pattern.
    pub path: String,
    /// Allowed methods.
    pub methods: Vec<String>,
    /// Created at.
    pub created_at: DateTime<Utc>,
}

impl sentry_core::RouteLike for RouteRow {
    fn path(&self) -> &str {
        &self.path
    }
    fn methods(&self) -> &[String] {
        &self.methods
    }
}

impl RouteRepo {
    /// Load all routes.
    pub async fn list(&self) -> Result<Vec<RouteRow>> {
        let rows = sqlx::query_as::<_, RouteRow>(
            r#"SELECT id, path, methods, created_at FROM routes ORDER BY id"#,
        )
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Insert a route.
    pub async fn insert(&self, path: &str, methods: &[String]) -> Result<i32> {
        let row: (i32,) = sqlx::query_as(
            r#"INSERT INTO routes (path, methods) VALUES ($1, $2)
               RETURNING id"#,
        )
        .bind(path)
        .bind(methods)
        .fetch_one(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(row.0)
    }

    /// Delete a route by id.
    pub async fn delete(&self, id: i32) -> Result<()> {
        sqlx::query("DELETE FROM routes WHERE id = $1")
            .bind(id)
            .execute(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn risk_level_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Info => "info",
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::RateLimit => "rate_limit",
        Verdict::Challenge => "challenge",
        Verdict::Block => "block",
        Verdict::Quarantine => "quarantine",
    }
}

fn parse_rule_action(s: &str) -> Option<RuleAction> {
    match s.to_ascii_lowercase().as_str() {
        "allow" => Some(RuleAction::Allow),
        "block" => Some(RuleAction::Block),
        "challenge" => Some(RuleAction::Challenge),
        "rate_limit" | "ratelimit" => Some(RuleAction::RateLimit),
        "log" => Some(RuleAction::Log),
        "tag" => Some(RuleAction::Tag),
        _ => None,
    }
}
