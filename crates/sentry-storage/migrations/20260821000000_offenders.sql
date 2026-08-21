-- Offender memory: per-IP strike counters backing verdict escalation.
-- Strikes decay when `last_violation_at` falls outside the configured
-- escalation window (enforced on write/read by IpStateRepo).

ALTER TABLE ip_state ADD COLUMN IF NOT EXISTS strikes INT NOT NULL DEFAULT 0;
ALTER TABLE ip_state ADD COLUMN IF NOT EXISTS total_violations BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ip_state ADD COLUMN IF NOT EXISTS last_violation_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ip_state_last_violation_idx ON ip_state (last_violation_at);
