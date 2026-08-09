-- Routes table for the route validator (hot-reloadable via LISTEN/NOTIFY).

CREATE TABLE IF NOT EXISTS routes (
    id          SERIAL PRIMARY KEY,
    path        TEXT NOT NULL,
    methods     TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS routes_path_idx ON routes (path);
