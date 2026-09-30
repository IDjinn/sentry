-- F4.7 high availability: cross-node event dedupe.
-- Nodes share Postgres; the per-process dedupe LRU does not see other
-- nodes' events. payload_hash (same hash the local dedupe uses: IP+method+
-- path for HTTP, IP+raw-hash otherwise) lets INSERT skip a duplicate seen
-- by a sibling node within the dedupe window.

ALTER TABLE events ADD COLUMN IF NOT EXISTS payload_hash BIGINT;

CREATE INDEX IF NOT EXISTS events_payload_hash_ts
    ON events (payload_hash, timestamp)
    WHERE payload_hash IS NOT NULL;
