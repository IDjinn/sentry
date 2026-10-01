-- Request/processing timings (F2.8 follow-up): observed request duration
-- from the source log (`$request_time`) and wall-clock pipeline processing
-- time in microseconds. Upstream response time stays inside the `protocol`
-- JSONB (`HttpData.upstream_time_ms`), following the protocol-data model.

ALTER TABLE events ADD COLUMN IF NOT EXISTS duration_ms BIGINT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS process_us BIGINT;
