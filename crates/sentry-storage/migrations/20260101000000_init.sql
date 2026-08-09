-- Schema for Sentry.
-- All migrations are SQL files in this directory, run via sqlx::migrate!.

CREATE TABLE IF NOT EXISTS events (
    id          UUID PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    source      TEXT NOT NULL,
    client_ip   INET NOT NULL,
    client_port INTEGER,
    server_port INTEGER,
    asn         BIGINT,
    country     TEXT,
    protocol    JSONB NOT NULL,
    risk_score  SMALLINT NOT NULL DEFAULT 0,
    risk_level  TEXT NOT NULL DEFAULT 'info',
    verdict     TEXT NOT NULL DEFAULT 'allow',
    signals     JSONB NOT NULL DEFAULT '[]',
    raw         TEXT
);

CREATE INDEX IF NOT EXISTS events_ts_idx      ON events (timestamp DESC);
CREATE INDEX IF NOT EXISTS events_ip_idx      ON events (client_ip);
CREATE INDEX IF NOT EXISTS events_level_idx   ON events (risk_level);

CREATE TABLE IF NOT EXISTS incidents (
    id          UUID PRIMARY KEY,
    event_id    UUID REFERENCES events(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    risk_level  TEXT NOT NULL,
    action      TEXT NOT NULL,
    resolved    BOOLEAN NOT NULL DEFAULT false,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 100,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    match_expr  TEXT NOT NULL,
    action      TEXT NOT NULL,
    ttl_secs    INTEGER,
    source      TEXT NOT NULL DEFAULT 'db',
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rules_priority_idx ON rules (priority);

CREATE TABLE IF NOT EXISTS ip_state (
    ip          INET PRIMARY KEY,
    status      TEXT NOT NULL,
    reason      TEXT,
    expires_at  TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS llm_cache (
    payload_hash BYTEA PRIMARY KEY,
    verdict     TEXT NOT NULL,
    risk_score  SMALLINT NOT NULL,
    signals     JSONB NOT NULL,
    confidence  REAL NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);