-- +goose Up
CREATE INDEX IF NOT EXISTS idx_alert_history_user_id_sent_at ON alert_history(user_id, sent_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_alert_history_user_id_sent_at;
