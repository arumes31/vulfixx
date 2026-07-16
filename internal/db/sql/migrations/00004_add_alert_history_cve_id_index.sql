-- +goose Up
CREATE INDEX IF NOT EXISTS idx_alert_history_cve_id ON alert_history(cve_id);

-- +goose Down
DROP INDEX IF EXISTS idx_alert_history_cve_id;
