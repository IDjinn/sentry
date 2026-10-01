-- DB-backed datasets (F7.7): curated user-agent / path / JA3 lists that
-- become synthetic `feed:<name>` rules in the pipeline and feed the
-- dynamic prefilter. Hot-reloadable via LISTEN/NOTIFY.

CREATE TABLE IF NOT EXISTS datasets (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL CHECK (kind IN ('user_agent', 'path', 'ja3')),
    source_url  TEXT,
    action      TEXT NOT NULL DEFAULT 'log',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dataset_entries (
    dataset_id  INT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    value       TEXT NOT NULL,
    PRIMARY KEY (dataset_id, value)
);

CREATE INDEX IF NOT EXISTS dataset_entries_dataset_idx ON dataset_entries (dataset_id);
