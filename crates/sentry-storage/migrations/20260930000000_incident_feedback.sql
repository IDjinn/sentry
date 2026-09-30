-- F4.5 bidirectional alerts + F3.6 retraining feedback.
-- Incidents gain a client_ip (open-per-IP dedupe + UI), an ack timestamp
-- (ack/resolve round-trip) and a unique index on event_id so one event can
-- never spawn two incidents.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS client_ip INET;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS incidents_event_id_key
    ON incidents (event_id) WHERE event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS incidents_open_by_ip
    ON incidents (client_ip) WHERE resolved = false;
