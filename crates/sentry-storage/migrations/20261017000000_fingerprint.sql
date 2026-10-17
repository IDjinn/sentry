-- Fingerprint bans (F18): device (`d-…`), TLS (`t-…`) and visitor (`v-…`)
-- ids denied by the pipeline before any detector runs. NOTIFY channel
-- `sentry_fingerprints_changed` makes every node reload the table.

CREATE TABLE IF NOT EXISTS fingerprint_bans (
    fp          TEXT PRIMARY KEY,
    reason      TEXT,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fingerprint ids live inside `events.protocol` (HttpData.fingerprint);
-- expression indexes keep `sentry fingerprint show` off a sequential scan.
CREATE INDEX IF NOT EXISTS events_fp_device_idx
    ON events ((protocol->'fingerprint'->>'device'))
    WHERE protocol->'fingerprint' IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_fp_tls_idx
    ON events ((protocol->'fingerprint'->>'tls'))
    WHERE protocol->'fingerprint' IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_fp_visitor_idx
    ON events ((protocol->'fingerprint'->>'visitor'))
    WHERE protocol->'fingerprint' IS NOT NULL;
