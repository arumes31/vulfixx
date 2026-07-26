-- +goose Up
-- alert_history already has UNIQUE(user_id, cve_id), which serves lookups keyed on
-- user_id. These two indexes cover the access patterns that constraint cannot.

-- Worker hot path: "SELECT user_id FROM alert_history WHERE cve_id = $1" runs once per
-- CVE per sync. user_id is the leading column of the unique constraint, so a cve_id-only
-- predicate cannot use it and falls back to a sequential scan.
CREATE INDEX IF NOT EXISTS idx_alert_history_cve_id
    ON alert_history (cve_id);

-- Alert history page: "WHERE user_id = $1 ORDER BY sent_at DESC LIMIT 100". The unique
-- constraint filters by user_id but leaves an explicit sort; ordering the index by
-- sent_at DESC lets the limit be satisfied by an index scan.
CREATE INDEX IF NOT EXISTS idx_alert_history_user_id_sent_at
    ON alert_history (user_id, sent_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_alert_history_user_id_sent_at;
DROP INDEX IF EXISTS idx_alert_history_cve_id;
