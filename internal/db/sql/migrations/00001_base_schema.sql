-- +goose Up
-- 1. Create independent tables
CREATE TABLE IF NOT EXISTS teams (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    invite_code VARCHAR(50) UNIQUE NOT NULL,
    max_subscriptions INTEGER DEFAULT 10,
    max_assets INTEGER DEFAULT 20,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_email_verified BOOLEAN DEFAULT FALSE,
    email_verify_token VARCHAR(255),
    totp_secret VARCHAR(255),
    is_totp_enabled BOOLEAN DEFAULT FALSE,
    is_admin BOOLEAN DEFAULT FALSE,
    rss_feed_token VARCHAR(255) UNIQUE,
    onboarding_completed BOOLEAN DEFAULT FALSE,
    max_subscriptions INTEGER DEFAULT 5,
    max_assets INTEGER DEFAULT 10,
    verification_resend_count INTEGER DEFAULT 0,
    last_verification_resend_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id SERIAL,
    cve_id VARCHAR(50) NOT NULL,
    description TEXT,
    cvss_score NUMERIC(4,1),
    vector_string TEXT,
    cisa_kev BOOLEAN DEFAULT FALSE,
    cisa_ransomware BOOLEAN DEFAULT FALSE,
    exploit_available BOOLEAN DEFAULT FALSE,
    epss_score NUMERIC(6,5),
    cwe_id VARCHAR(50),
    cwe_name TEXT,
    github_poc_count INTEGER DEFAULT 0,
    greynoise_hits INTEGER DEFAULT 0,
    greynoise_classification VARCHAR(50),
    greynoise_last_updated TIMESTAMP WITH TIME ZONE,
    osv_data JSONB DEFAULT '{}',
    osv_last_updated TIMESTAMP WITH TIME ZONE,
    inthewild_data JSONB DEFAULT '{}',
    inthewild_last_updated TIMESTAMP WITH TIME ZONE,
    osint_data JSONB DEFAULT '{}',
    published_date TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_date TIMESTAMP WITH TIME ZONE,
    "references" TEXT[],
    configurations JSONB DEFAULT '[]',
    vendor VARCHAR(255),
    product VARCHAR(255),
    affected_products JSONB DEFAULT '[]',
    priority VARCHAR(2) DEFAULT 'P3',
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, published_date),
    UNIQUE (cve_id, published_date)
) PARTITION BY RANGE (published_date);

CREATE TABLE IF NOT EXISTS cves_y2000to2010 PARTITION OF cves FOR VALUES FROM ('2000-01-01 00:00:00+00') TO ('2010-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2010to2015 PARTITION OF cves FOR VALUES FROM ('2010-01-01 00:00:00+00') TO ('2015-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2015to2020 PARTITION OF cves FOR VALUES FROM ('2015-01-01 00:00:00+00') TO ('2020-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2020 PARTITION OF cves FOR VALUES FROM ('2020-01-01 00:00:00+00') TO ('2021-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2021 PARTITION OF cves FOR VALUES FROM ('2021-01-01 00:00:00+00') TO ('2022-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2022 PARTITION OF cves FOR VALUES FROM ('2022-01-01 00:00:00+00') TO ('2023-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2023 PARTITION OF cves FOR VALUES FROM ('2023-01-01 00:00:00+00') TO ('2024-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2024 PARTITION OF cves FOR VALUES FROM ('2024-01-01 00:00:00+00') TO ('2025-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2025 PARTITION OF cves FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2026-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2026 PARTITION OF cves FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2027 PARTITION OF cves FOR VALUES FROM ('2027-01-01 00:00:00+00') TO ('2028-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2028 PARTITION OF cves FOR VALUES FROM ('2028-01-01 00:00:00+00') TO ('2029-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_y2029 PARTITION OF cves FOR VALUES FROM ('2029-01-01 00:00:00+00') TO ('2030-01-01 00:00:00+00');
CREATE TABLE IF NOT EXISTS cves_default PARTITION OF cves DEFAULT;

CREATE TABLE IF NOT EXISTS sync_state (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS worker_sync_stats (
    task_name VARCHAR(100) PRIMARY KEY,
    last_run TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS team_members (
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100),
    priority VARCHAR(2) DEFAULT 'P3',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_assets_user_xor_team CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE TABLE IF NOT EXISTS asset_keywords (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    keyword VARCHAR(255) NOT NULL,
    UNIQUE(asset_id, keyword)
);

CREATE TABLE IF NOT EXISTS user_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    keyword VARCHAR(255),
    min_severity NUMERIC(4,1),
    webhook_url TEXT,
    slack_webhook_url TEXT,
    teams_webhook_url TEXT,
    enable_email BOOLEAN DEFAULT TRUE,
    enable_webhook BOOLEAN DEFAULT TRUE,
    enable_slack BOOLEAN DEFAULT FALSE,
    enable_teams BOOLEAN DEFAULT FALSE,
    enable_browser_push BOOLEAN DEFAULT FALSE,
    filter_logic TEXT DEFAULT '',
    aggregation_mode VARCHAR(20) DEFAULT 'instant',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_user_subscriptions_user_xor_team CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE TABLE IF NOT EXISTS notification_delivery_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    subscription_id INTEGER REFERENCES user_subscriptions(id) ON DELETE CASCADE,
    cve_id INTEGER,
    channel VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    error_message TEXT,
    delivery_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS browser_push_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, endpoint)
);

CREATE TABLE IF NOT EXISTS user_cve_status (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    cve_id INTEGER,
    status VARCHAR(50) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_user_cve_status_user_xor_team CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE TABLE IF NOT EXISTS cve_notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    cve_id INTEGER,
    notes TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_cve_notes_user_xor_team CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE TABLE IF NOT EXISTS alert_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    cve_id INTEGER,
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, cve_id)
);

CREATE TABLE IF NOT EXISTS user_activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    activity_type VARCHAR(50) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    retention_expires_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS email_change_requests (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    new_email VARCHAR(255) NOT NULL,
    old_email_token VARCHAR(255) NOT NULL,
    new_email_token VARCHAR(255) NOT NULL,
    old_email_confirmed BOOLEAN DEFAULT FALSE,
    new_email_confirmed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';
-- +goose StatementEnd

DROP TRIGGER IF EXISTS update_cves_updated_at ON cves;
CREATE TRIGGER update_cves_updated_at
    BEFORE UPDATE ON cves
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_worker_sync_stats_updated_at ON worker_sync_stats;
CREATE TRIGGER update_worker_sync_stats_updated_at
    BEFORE UPDATE ON worker_sync_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION calculate_cve_priority() RETURNS TRIGGER AS $$
BEGIN
    IF COALESCE(NEW.cvss_score, 0.0) >= 9.0 OR NEW.cisa_kev = TRUE OR COALESCE(NEW.epss_score, 0.0) >= 0.5 THEN
        NEW.priority := 'P0';
    ELSIF COALESCE(NEW.cvss_score, 0.0) >= 7.0 OR COALESCE(NEW.epss_score, 0.0) >= 0.1 THEN
        NEW.priority := 'P1';
    ELSIF COALESCE(NEW.cvss_score, 0.0) >= 4.0 THEN
        NEW.priority := 'P2';
    ELSE
        NEW.priority := 'P3';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trigger_calculate_cve_priority ON cves;
CREATE TRIGGER trigger_calculate_cve_priority
BEFORE INSERT OR UPDATE ON cves
FOR EACH ROW EXECUTE FUNCTION calculate_cve_priority();

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_user_id_created_at ON user_activity_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_user_type_created ON user_activity_logs (user_id, activity_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_created_at ON user_activity_logs (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_change_requests_old_token ON email_change_requests (old_email_token);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_change_requests_new_token ON email_change_requests (new_email_token);
CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves (published_date DESC);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves (cvss_score);
CREATE INDEX IF NOT EXISTS idx_cves_updated_date ON cves (updated_date DESC);
CREATE INDEX IF NOT EXISTS idx_assets_team_id ON assets(team_id);
CREATE INDEX IF NOT EXISTS idx_user_cve_status_team_id ON user_cve_status(team_id);
CREATE INDEX IF NOT EXISTS idx_cve_notes_team_id ON cve_notes(team_id);
CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(vendor);
CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product);
DROP INDEX IF EXISTS idx_cves_affected_products;
CREATE INDEX IF NOT EXISTS idx_cves_affected_products_trgm ON cves USING GIN ((affected_products::text) gin_trgm_ops);

CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_user_status ON user_cve_status (user_id, cve_id) WHERE team_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_team_status ON user_cve_status (team_id, cve_id) WHERE team_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_user_notes ON cve_notes (user_id, cve_id) WHERE team_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_team_notes ON cve_notes (team_id, cve_id) WHERE team_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_user_status_covering ON user_cve_status (user_id, cve_id, status);
CREATE INDEX IF NOT EXISTS idx_team_status_covering ON user_cve_status (team_id, cve_id, status);
CREATE INDEX IF NOT EXISTS idx_user_notes_covering ON cve_notes (user_id, cve_id);
CREATE INDEX IF NOT EXISTS idx_team_notes_covering ON cve_notes (team_id, cve_id);

CREATE INDEX IF NOT EXISTS idx_cves_description_trgm ON cves USING GIN (description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cves_vendor_trgm ON cves USING GIN (vendor gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cves_product_trgm ON cves USING GIN (product gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id_trgm ON cves USING GIN (cve_id gin_trgm_ops);

CREATE TABLE IF NOT EXISTS cve_threat_associations (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    entity_name VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    source VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_threats_unique ON cve_threat_associations(cve_id, entity_name, entity_type);
CREATE INDEX IF NOT EXISTS idx_cve_threats_cve_id ON cve_threat_associations(cve_id);

-- +goose Down
DROP TABLE IF EXISTS cve_threat_associations CASCADE;
DROP TABLE IF EXISTS user_activity_logs CASCADE;
DROP TABLE IF EXISTS alert_history CASCADE;
DROP TABLE IF EXISTS cve_notes CASCADE;
DROP TABLE IF EXISTS user_cve_status CASCADE;
DROP TABLE IF EXISTS browser_push_subscriptions CASCADE;
DROP TABLE IF EXISTS notification_delivery_logs CASCADE;
DROP TABLE IF EXISTS user_subscriptions CASCADE;
DROP TABLE IF EXISTS asset_keywords CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS team_members CASCADE;
DROP TABLE IF EXISTS email_change_requests CASCADE;
DROP TABLE IF EXISTS worker_sync_stats CASCADE;
DROP TABLE IF EXISTS sync_state CASCADE;
DROP TABLE IF EXISTS cves CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS teams CASCADE;
DROP FUNCTION IF EXISTS calculate_cve_priority() CASCADE;
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;
