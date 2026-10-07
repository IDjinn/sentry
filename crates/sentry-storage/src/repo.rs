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

    /// Borrow the datasets repo (F7.7).
    pub fn datasets(&self) -> DatasetRepo {
        DatasetRepo {
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

/// One event prepared for [`EventRepo::insert_batch_with_hash`] — the same
/// columns as the single-row insert, plus the cross-node `payload_hash`.
#[derive(Debug, Clone)]
pub struct EventInsert {
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
    /// Cross-node dedupe hash (None skips the dedupe guard).
    pub payload_hash: Option<i64>,
    /// Observed request duration in ms from the source log.
    pub duration_ms: Option<i64>,
    /// Pipeline processing time in microseconds.
    pub process_us: Option<i64>,
}

impl EventInsert {
    /// Prepare one row from a processed event, mirroring the bindings of
    /// [`EventRepo::insert_with_hash`]. A protocol that fails to serialize
    /// becomes JSON `null` (the row still persists) — batching must not
    /// lose events over one bad payload.
    #[allow(clippy::too_many_arguments)]
    pub fn from_event(
        evt: &Event,
        risk_score: u8,
        risk_level: RiskLevel,
        verdict: Verdict,
        signals: &serde_json::Value,
        payload_hash: Option<i64>,
        process_us: Option<u64>,
    ) -> Self {
        let protocol = serde_json::to_value(&evt.protocol).unwrap_or(serde_json::Value::Null);
        Self {
            id: evt.id,
            timestamp: evt.timestamp,
            source: evt.source.as_str().to_string(),
            client_ip: evt.client_ip.to_string(),
            client_port: evt.client_port.map(|p| p as i32),
            server_port: evt.server_port.map(|p| p as i32),
            asn: evt.asn.map(|a| a as i64),
            country: evt.geo.as_ref().and_then(|g| g.country.clone()),
            protocol,
            risk_score: risk_score as i16,
            risk_level: risk_level_label(risk_level).to_string(),
            verdict: verdict_label(verdict).to_string(),
            signals: signals.clone(),
            raw: evt.raw.clone(),
            payload_hash,
            duration_ms: evt.duration_ms.map(|d| d as i64),
            process_us: process_us.map(|p| p as i64),
        }
    }
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
    /// Observed request duration in ms from the source log.
    pub duration_ms: Option<i64>,
    /// Pipeline processing time in microseconds.
    pub process_us: Option<i64>,
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
        self.insert_with_hash(evt, risk_score, risk_level, verdict, signals, None, None)
            .await
    }

    /// Insert with a payload hash for cross-node dedupe (F4.7).
    ///
    /// When `payload_hash` is set and a sibling node persisted the same
    /// payload within the dedupe window (10s), the insert is skipped — the
    /// per-process dedupe LRU cannot see other nodes' events.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_with_hash(
        &self,
        evt: &Event,
        risk_score: u8,
        risk_level: RiskLevel,
        verdict: Verdict,
        signals: &serde_json::Value,
        payload_hash: Option<i64>,
        process_us: Option<u64>,
    ) -> Result<()> {
        let protocol_json = serde_json::to_value(&evt.protocol)
            .map_err(|e| StorageError::Query(format!("protocol serialize: {e}")))?;
        let source = evt.source.as_str();
        let risk_level_str = risk_level_label(risk_level);
        let verdict_str = verdict_label(verdict);

        sqlx::query(
            r#"INSERT INTO events
               (id, timestamp, source, client_ip, client_port, server_port,
                asn, country, protocol, risk_score, risk_level, verdict, signals, raw,
                payload_hash, duration_ms, process_us)
               SELECT $1, $2, $3, $4::inet, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
               WHERE $15::bigint IS NULL
                  OR NOT EXISTS (
                      SELECT 1 FROM events
                      WHERE payload_hash = $15
                        AND timestamp > now() - interval '10 seconds'
                  )
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
        .bind(payload_hash)
        .bind(evt.duration_ms.map(|d| d as i64))
        .bind(process_us.map(|p| p as i64))
        .execute(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Max rows per batched INSERT (Postgres param limit is 65535; 64 × 17
    /// columns stays far below it).
    pub const MAX_EVENT_BATCH: usize = 64;

    /// Build the multi-row INSERT statement for `n` event rows, preserving
    /// the per-row cross-node dedupe semantics of [`EventRepo::insert_with_hash`]
    /// (skip the row when a sibling node persisted the same `payload_hash`
    /// within the 10-second window).
    fn batch_insert_sql(n: usize) -> String {
        let mut values = String::with_capacity(n * 128);
        for (i, slot) in (0..n).enumerate() {
            let b = slot * 17 + 1;
            if i > 0 {
                values.push_str(", ");
            }
            values.push_str(&format!(
                "(${b}::uuid, ${b1}::timestamptz, ${b2}::text, ${b3}::inet, \
                 ${b4}::int4, ${b5}::int4, ${b6}::int8, ${b7}::text, ${b8}::jsonb, \
                 ${b9}::int2, ${b10}::text, ${b11}::text, ${b12}::jsonb, ${b13}::text, \
                 ${b14}::int8, ${b15}::int8, ${b16}::int8)",
                b1 = b + 1,
                b2 = b + 2,
                b3 = b + 3,
                b4 = b + 4,
                b5 = b + 5,
                b6 = b + 6,
                b7 = b + 7,
                b8 = b + 8,
                b9 = b + 9,
                b10 = b + 10,
                b11 = b + 11,
                b12 = b + 12,
                b13 = b + 13,
                b14 = b + 14,
                b15 = b + 15,
                b16 = b + 16,
            ));
        }
        format!(
            r#"INSERT INTO events
               (id, timestamp, source, client_ip, client_port, server_port,
                asn, country, protocol, risk_score, risk_level, verdict, signals, raw,
                payload_hash, duration_ms, process_us)
               SELECT column1, column2, column3, column4, column5, column6, column7,
                      column8, column9, column10, column11, column12, column13, column14,
                      column15, column16, column17
               FROM (VALUES {values}) AS v
               WHERE column15 IS NULL
                  OR NOT EXISTS (
                      SELECT 1 FROM events
                      WHERE payload_hash = column15
                        AND timestamp > now() - interval '10 seconds'
                  )
               ON CONFLICT (id) DO NOTHING"#
        )
    }

    /// Insert a batch of events in one round-trip.
    ///
    /// Same skip semantics as [`EventRepo::insert_with_hash`], applied per
    /// row; chunks beyond [`EventRepo::MAX_EVENT_BATCH`] run as separate
    /// statements. Under overload the daemon routes telemetry through here
    /// so 64 events cost one INSERT instead of 64.
    pub async fn insert_batch_with_hash(&self, rows: &[EventInsert]) -> Result<()> {
        for chunk in rows.chunks(Self::MAX_EVENT_BATCH) {
            let sql = Self::batch_insert_sql(chunk.len());
            let mut query = sqlx::query(&sql);
            for row in chunk {
                query = query
                    .bind(row.id)
                    .bind(row.timestamp)
                    .bind(row.source.as_str())
                    .bind(row.client_ip.as_str())
                    .bind(row.client_port)
                    .bind(row.server_port)
                    .bind(row.asn)
                    .bind(row.country.as_deref())
                    .bind(row.protocol.clone())
                    .bind(row.risk_score)
                    .bind(row.risk_level.as_str())
                    .bind(row.verdict.as_str())
                    .bind(row.signals.clone())
                    .bind(row.raw.as_deref())
                    .bind(row.payload_hash)
                    .bind(row.duration_ms)
                    .bind(row.process_us);
            }
            query
                .execute(self.pool.inner())
                .await
                .map_err(|e| StorageError::Query(e.to_string()))?;
        }
        Ok(())
    }

    /// Fetch recent events (newest first).
    pub async fn recent(&self, limit: i64) -> Result<Vec<EventRow>> {
        let rows = sqlx::query_as::<_, EventRow>(
            r#"SELECT id, timestamp, source, host(client_ip) AS client_ip,
                      client_port, server_port, asn, country,
                      protocol, risk_score, risk_level, verdict, signals, raw,
                      duration_ms, process_us
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

    /// Fetch recent events for a single client IP (newest first).
    ///
    /// Backs the per-IP info panel in the tail TUI.
    pub async fn recent_for_ip(&self, ip: IpAddr, limit: i64) -> Result<Vec<EventRow>> {
        let rows = sqlx::query_as::<_, EventRow>(
            r#"SELECT id, timestamp, source, host(client_ip) AS client_ip,
                      client_port, server_port, asn, country,
                      protocol, risk_score, risk_level, verdict, signals, raw,
                      duration_ms, process_us
               FROM events
               WHERE client_ip = $1::inet
               ORDER BY timestamp DESC
               LIMIT $2"#,
        )
        .bind(ip.to_string())
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
            r#"SELECT id, timestamp, source, host(client_ip) AS client_ip,
                      client_port, server_port, asn, country,
                      protocol, risk_score, risk_level, verdict, signals, raw,
                      duration_ms, process_us
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

    /// Update the verdict of an already-persisted event (async fork stages
    /// such as the ML threat model may raise it after the initial insert).
    pub async fn update_verdict(
        &self,
        id: Uuid,
        verdict: Verdict,
        risk_score: u8,
        risk_level: RiskLevel,
    ) -> Result<()> {
        sqlx::query(
            r#"UPDATE events
               SET verdict = $2, risk_score = $3, risk_level = $4
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(verdict_label(verdict))
        .bind(risk_score as i16)
        .bind(risk_level_label(risk_level))
        .execute(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Event ids referenced by at least one incident, within the window.
    ///
    /// Feeds `sentry model export --confirmed`: incident-linked events are
    /// the operator-confirmed positives of the retraining dataset (F3.6).
    pub async fn incident_event_ids(&self, since: DateTime<Utc>) -> Result<Vec<Uuid>> {
        let rows: Vec<Uuid> = sqlx::query_scalar(
            r#"SELECT DISTINCT i.event_id
               FROM incidents i
               JOIN events e ON e.id = i.event_id
               WHERE i.event_id IS NOT NULL AND e.timestamp >= $1"#,
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
        // client_ip is INET; sqlx decodes it into ip types, not String —
        // cast to text for the (ip, count) aggregate.
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT host(client_ip), COUNT(*)::bigint AS n
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

    /// Top paths flagged `UnknownRoute` since `since`.
    ///
    /// Helps operators promote legitimate-but-unlisted paths to
    /// `[[routes.known]]` (the learner intentionally never learns them).
    pub async fn top_unknown_paths(
        &self,
        limit: i64,
        since: DateTime<Utc>,
    ) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT protocol->>'path' AS path, COUNT(*)::bigint AS n
               FROM events
               WHERE timestamp >= $1
                 AND protocol->>'path' IS NOT NULL
                 AND signals::text LIKE '%"unknown_route"%'
               GROUP BY path ORDER BY n DESC LIMIT $2"#,
        )
        .bind(since)
        .bind(limit)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Web security posture advisories (F11) since `since`, aggregated by
    /// host and signal `detail` (`"<check>: <explanation>"`).
    pub async fn posture_findings(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Vec<(String, String, i64)>> {
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"SELECT protocol->>'host' AS host, s->>'detail' AS detail, COUNT(*)::bigint AS n
               FROM events, jsonb_array_elements(signals) AS s
               WHERE timestamp >= $1
                 AND s->>'kind' = 'posture_advisory'
               GROUP BY host, detail
               ORDER BY host, n DESC"#,
        )
        .bind(since)
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
    /// Client IP (text form) the incident was raised for.
    #[serde(default)]
    pub client_ip: Option<String>,
    /// Risk level.
    pub risk_level: String,
    /// Action taken.
    pub action: String,
    /// Resolved flag.
    pub resolved: bool,
    /// When the incident was acknowledged (F4.5), if it was.
    #[serde(default)]
    pub acknowledged_at: Option<DateTime<Utc>>,
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

    /// Get (or create) the incident tied to an event.
    ///
    /// Idempotent per event: the unique index on `event_id` makes a replay a
    /// no-op that returns the existing incident instead of a duplicate.
    pub async fn get_or_create_for_event(
        &self,
        event_id: Uuid,
        client_ip: IpAddr,
        risk_level: RiskLevel,
        action: Verdict,
        notes: Option<&str>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        // The unique index is partial (`WHERE event_id IS NOT NULL`), so the
        // conflict target must repeat the predicate or Postgres rejects the
        // inference with "no unique or exclusion constraint matching".
        let inserted = sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO incidents (id, event_id, client_ip, risk_level, action, notes)
               VALUES ($1, $2, $3::inet, $4, $5, $6)
               ON CONFLICT (event_id) WHERE event_id IS NOT NULL DO NOTHING
               RETURNING id"#,
        )
        .bind(id)
        .bind(event_id)
        .bind(client_ip.to_string())
        .bind(risk_level_label(risk_level))
        .bind(verdict_label(action))
        .bind(notes)
        .fetch_optional(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        if let Some(existing) = inserted {
            return Ok(existing);
        }
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM incidents WHERE event_id = $1")
            .bind(event_id)
            .fetch_one(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))
    }

    /// Id of an unresolved incident already open for this IP, if any.
    ///
    /// Used to coalesce bursts of High/Critical events into a single open
    /// incident per attacker instead of one row per event.
    pub async fn open_incident_for_ip(&self, ip: IpAddr) -> Result<Option<Uuid>> {
        sqlx::query_scalar::<_, Uuid>(
            r#"SELECT id FROM incidents
               WHERE client_ip = $1::inet AND resolved = false
               ORDER BY created_at DESC
               LIMIT 1"#,
        )
        .bind(ip.to_string())
        .fetch_optional(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))
    }

    /// Fetch unresolved incidents.
    pub async fn unresolved(&self, limit: i64) -> Result<Vec<IncidentRow>> {
        let rows = sqlx::query_as::<_, IncidentRow>(
            r#"SELECT id, event_id, created_at, host(client_ip) AS client_ip,
                      risk_level, action, resolved, acknowledged_at, notes
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

    /// Acknowledge an incident (first ack wins; F4.5).
    pub async fn ack(&self, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE incidents SET acknowledged_at = now() WHERE id = $1 AND acknowledged_at IS NULL",
        )
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
    ///
    /// IPs come back through `host()` because `ip::text` on an INET column
    /// renders CIDR notation (`203.0.113.7/32`), which `IpAddr::from_str`
    /// rejects — consumers that parse the value (block-table pre-warm,
    /// hot-reload) would silently drop every row.
    pub async fn blocked(&self, limit: i64) -> Result<Vec<IpStateRow>> {
        let rows = sqlx::query_as::<_, IpStateRow>(
            r#"SELECT host(ip) AS ip, status, reason, expires_at, updated_at
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

    /// Record a violation for an IP (offender memory), applying the same
    /// window decay as the in-memory tracker: strikes whose window expired
    /// reset to 1, otherwise they increment. `total_violations` never resets.
    ///
    /// Returns the resulting row.
    pub async fn record_violation(&self, ip: IpAddr, window_secs: u64) -> Result<OffenderRow> {
        let row = sqlx::query_as::<_, OffenderRow>(
            r#"INSERT INTO ip_state (ip, status, strikes, total_violations, last_violation_at)
               VALUES ($1::inet, 'watched', 1, 1, now())
               ON CONFLICT (ip) DO UPDATE SET
                   strikes = CASE
                       WHEN ip_state.last_violation_at IS NULL
                         OR ip_state.last_violation_at < now() - make_interval(secs => $2)
                       THEN 1 ELSE ip_state.strikes + 1 END,
                   total_violations = ip_state.total_violations + 1,
                   last_violation_at = now(),
                   updated_at = now()
               RETURNING host(ip) AS ip, strikes, total_violations, last_violation_at"#,
        )
        .bind(ip.to_string())
        .bind(window_secs as f64)
        .fetch_one(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(row)
    }

    /// Offender state for a single IP (strikes, totals, last violation).
    pub async fn offender(&self, ip: IpAddr) -> Result<Option<OffenderRow>> {
        let row = sqlx::query_as::<_, OffenderRow>(
            r#"SELECT host(ip) AS ip, strikes, total_violations, last_violation_at
               FROM ip_state WHERE ip = $1::inet"#,
        )
        .bind(ip.to_string())
        .fetch_optional(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(row)
    }

    /// Offenders with live strikes inside the window (startup pre-warm).
    pub async fn recent_offenders(&self, window_secs: u64, limit: i64) -> Result<Vec<OffenderRow>> {
        let rows = sqlx::query_as::<_, OffenderRow>(
            r#"SELECT host(ip) AS ip, strikes, total_violations, last_violation_at
               FROM ip_state
               WHERE strikes > 0
                 AND last_violation_at >= now() - make_interval(secs => $1)
               ORDER BY last_violation_at DESC
               LIMIT $2"#,
        )
        .bind(window_secs as f64)
        .bind(limit)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(rows)
    }

    /// Reset the strike counters for an IP (manual forgiveness). Keeps the
    /// `total_violations` history.
    pub async fn reset_offender(&self, ip: IpAddr) -> Result<()> {
        sqlx::query(
            r#"UPDATE ip_state
               SET strikes = 0, last_violation_at = NULL, updated_at = now()
               WHERE ip = $1::inet"#,
        )
        .bind(ip.to_string())
        .execute(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }
}

/// Row representation of the offender-memory columns in `ip_state`.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct OffenderRow {
    /// IP address (text).
    pub ip: String,
    /// Strikes accumulated in the current window.
    pub strikes: i32,
    /// Violations ever recorded.
    pub total_violations: i64,
    /// When the last violation happened.
    pub last_violation_at: Option<DateTime<Utc>>,
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
                log_level: None,
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

// ─── DatasetRepo ────────────────────────────────────────────────────────────

/// Repository for DB-backed datasets (F7.7): curated user-agent / path /
/// JA3 lists that become synthetic `feed:<name>` rules and feed the dynamic
/// prefilter. Every mutation notifies `sentry_datasets_changed` so all
/// nodes hot-reload without a restart.
#[derive(Clone)]
pub struct DatasetRepo {
    pool: PgPool,
}

/// One dataset with its metadata and entry count.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct DatasetRow {
    /// Unique name (the synthetic rule id becomes `feed:<name>`).
    pub name: String,
    /// `user_agent` | `path` | `ja3`.
    pub kind: String,
    /// Optional URL the list was imported from (enables re-fetch).
    pub source_url: Option<String>,
    /// Pipeline action when the synthetic rule matches (`log` default).
    pub action: String,
    /// Whether the dataset feeds the pipeline.
    pub enabled: bool,
    /// Number of stored entries.
    pub entry_count: i64,
}

const NOTIFY_DATASETS: &str = "sentry_datasets_changed";

impl DatasetRepo {
    /// Replace a dataset wholesale: upsert metadata, swap the entry set and
    /// notify listeners.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        &self,
        name: &str,
        kind: &str,
        source_url: Option<&str>,
        action: &str,
        entries: &[String],
    ) -> Result<()> {
        let mut tx = self
            .pool
            .inner()
            .begin()
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        sqlx::query(
            r#"INSERT INTO datasets (name, kind, source_url, action)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (name) DO UPDATE
                 SET kind = EXCLUDED.kind,
                     source_url = EXCLUDED.source_url,
                     action = EXCLUDED.action,
                     updated_at = now()"#,
        )
        .bind(name)
        .bind(kind)
        .bind(source_url)
        .bind(action)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::Query(e.to_string()))?;
        sqlx::query("DELETE FROM dataset_entries WHERE dataset_id = (SELECT id FROM datasets WHERE name = $1)")
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        if !entries.is_empty() {
            sqlx::query(
                r#"INSERT INTO dataset_entries (dataset_id, value)
                   SELECT id, v FROM datasets, UNNEST($2::text[]) AS t(v)
                   WHERE datasets.name = $1
                   ON CONFLICT (dataset_id, value) DO NOTHING"#,
            )
            .bind(name)
            .bind(entries.to_vec())
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        }
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(NOTIFY_DATASETS)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| StorageError::Query(e.to_string()))
    }

    /// List all datasets (metadata + entry counts), by name.
    pub async fn list(&self) -> Result<Vec<DatasetRow>> {
        sqlx::query_as::<_, DatasetRow>(
            r#"SELECT d.name, d.kind, d.source_url, d.action, d.enabled, count(e.value) AS entry_count
               FROM datasets d
               LEFT JOIN dataset_entries e ON e.dataset_id = d.id
               GROUP BY d.id, d.name, d.kind, d.source_url, d.action, d.enabled
               ORDER BY d.name ASC"#,
        )
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))
    }

    /// Fetch every entry of one dataset (empty when absent).
    pub async fn entries(&self, name: &str) -> Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT e.value FROM dataset_entries e \
             JOIN datasets d ON d.id = e.dataset_id WHERE d.name = $1",
        )
        .bind(name)
        .fetch_all(self.pool.inner())
        .await
        .map_err(|e| StorageError::Query(e.to_string()))
    }

    /// Enable or disable a dataset and notify listeners.
    pub async fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        sqlx::query("UPDATE datasets SET enabled = $2, updated_at = now() WHERE name = $1")
            .bind(name)
            .bind(enabled)
            .execute(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(NOTIFY_DATASETS)
            .bind(name)
            .execute(self.pool.inner())
            .await
            .map(|_| ())
            .map_err(|e| StorageError::Query(e.to_string()))
    }

    /// Delete a dataset (entries cascade) and notify listeners.
    pub async fn delete(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM datasets WHERE name = $1")
            .bind(name)
            .execute(self.pool.inner())
            .await
            .map_err(|e| StorageError::Query(e.to_string()))?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(NOTIFY_DATASETS)
            .bind(name)
            .execute(self.pool.inner())
            .await
            .map(|_| ())
            .map_err(|e| StorageError::Query(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_insert_sql_single_row_matches_single_insert_shape() {
        let sql = EventRepo::batch_insert_sql(1);
        assert!(sql.contains("INSERT INTO events"));
        assert!(sql.contains("($1::uuid, $2::timestamptz, $3::text, $4::inet"));
        assert!(sql.contains("$15::int8, $16::int8, $17::int8"));
        assert!(sql.contains("WHERE column15 IS NULL"));
        assert!(sql.contains("ON CONFLICT (id) DO NOTHING"));
    }

    #[test]
    fn batch_insert_sql_offsets_params_per_row() {
        let sql = EventRepo::batch_insert_sql(3);
        assert_eq!(sql.matches("::uuid").count(), 3);
        assert!(sql.contains("$18::uuid"));
        assert!(sql.contains("$34::int8"));
        // One dedupe guard over the whole VALUES set.
        assert_eq!(sql.matches("NOT EXISTS").count(), 1);
    }

    #[test]
    fn batch_insert_sql_max_batch_stays_under_pg_param_limit() {
        let sql = EventRepo::batch_insert_sql(EventRepo::MAX_EVENT_BATCH);
        let last = EventRepo::MAX_EVENT_BATCH * 17;
        assert!(sql.contains(&format!("${last}::int8")));
        assert!(last <= 65_535);
    }
}
