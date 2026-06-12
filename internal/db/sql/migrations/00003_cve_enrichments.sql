-- +goose Up
-- Add EPSS percentile column
ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(5,2) DEFAULT 0;

-- Add CISA KEV details as JSONB
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cisa_kev_data JSONB DEFAULT '{}';

-- Add NVD reference tags (parallel array to references)
ALTER TABLE cves ADD COLUMN IF NOT EXISTS reference_tags TEXT[] DEFAULT '{}';

-- Add GitHub PoC repo details as JSONB
ALTER TABLE cves ADD COLUMN IF NOT EXISTS github_poc_repos JSONB DEFAULT '[]';

-- +goose Down
ALTER TABLE cves DROP COLUMN IF EXISTS github_poc_repos;
ALTER TABLE cves DROP COLUMN IF EXISTS reference_tags;
ALTER TABLE cves DROP COLUMN IF EXISTS cisa_kev_data;
ALTER TABLE cves DROP COLUMN IF EXISTS epss_percentile;
