-- +goose Up
-- Persists the items syncAdvisoryRSS already fetches from the 12 advisory feeds.
-- Before this, items were parsed, used to enrich the cves table, and discarded.
CREATE TABLE IF NOT EXISTS advisory_news (
    id           BIGSERIAL PRIMARY KEY,
    feed_name    TEXT        NOT NULL,
    title        TEXT        NOT NULL,
    link         TEXT        NOT NULL UNIQUE,
    summary      TEXT        NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ NOT NULL,
    cve_ids      TEXT[]      NOT NULL DEFAULT '{}',
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rail query: newest across all feeds.
CREATE INDEX IF NOT EXISTS idx_advisory_news_published
    ON advisory_news (published_at DESC);

-- Per-source filtering, and the retention prune.
CREATE INDEX IF NOT EXISTS idx_advisory_news_feed_published
    ON advisory_news (feed_name, published_at DESC);

-- +goose Down
DROP TABLE IF EXISTS advisory_news;
