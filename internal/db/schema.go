package db

const schemaSQL = `
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    cvss_score NUMERIC(4,1),
    vector_string TEXT,
    cisa_kev BOOLEAN DEFAULT FALSE,
    epss_score NUMERIC(6,5),
    cwe_id VARCHAR(50),
    cwe_name TEXT,
    github_poc_count INTEGER DEFAULT 0,
    osint_data JSONB DEFAULT '{}',
    published_date TIMESTAMP WITH TIME ZONE,
    updated_date TIMESTAMP WITH TIME ZONE,
    "references" TEXT[],
    configurations JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

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

-- 2. Create dependent tables
CREATE TABLE IF NOT EXISTS team_members (
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member', -- 'owner', 'admin', 'member'
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100),
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
    enable_email BOOLEAN DEFAULT TRUE,
    enable_webhook BOOLEAN DEFAULT TRUE,
    filter_logic TEXT DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_user_subscriptions_user_xor_team CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE TABLE IF NOT EXISTS user_cve_status (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_user_cve_status_user_xor_team CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE TABLE IF NOT EXISTS cve_notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
    notes TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_cve_notes_user_xor_team CHECK ((user_id IS NULL) <> (team_id IS NULL))
);

CREATE TABLE IF NOT EXISTS alert_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
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

-- 3. Ensure team_id columns exist for all relevant tables (Upgrades)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'assets') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'assets' AND column_name = 'team_id') THEN
            ALTER TABLE assets ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'user_subscriptions') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'user_subscriptions' AND column_name = 'team_id') THEN
            ALTER TABLE user_subscriptions ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'user_cve_status') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'user_cve_status' AND column_name = 'team_id') THEN
            ALTER TABLE user_cve_status ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE;
        END IF;
        -- Handle potential PK change if it was (user_id, cve_id)
        IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE table_name = 'user_cve_status' AND constraint_type = 'PRIMARY KEY') THEN
             IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'user_cve_status' AND column_name = 'id') THEN
                 ALTER TABLE user_cve_status DROP CONSTRAINT IF EXISTS user_cve_status_pkey;
                 ALTER TABLE user_cve_status ADD COLUMN id SERIAL PRIMARY KEY;
             END IF;
        END IF;
    END IF;

    -- Rename user_cve_notes to cve_notes if it exists
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'user_cve_notes') AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cve_notes') THEN
        ALTER TABLE user_cve_notes RENAME TO cve_notes;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cve_notes') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cve_notes' AND column_name = 'team_id') THEN
            ALTER TABLE cve_notes ADD COLUMN team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE;
        END IF;
        -- Add id column if missing (it was (user_id, cve_id) in older versions)
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cve_notes' AND column_name = 'id') THEN
            ALTER TABLE cve_notes DROP CONSTRAINT IF EXISTS user_cve_notes_pkey;
            ALTER TABLE cve_notes ADD COLUMN id SERIAL PRIMARY KEY;
        END IF;
    END IF;

    -- Add Quota Columns
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'max_subscriptions') THEN
        ALTER TABLE users ADD COLUMN max_subscriptions INTEGER DEFAULT 5;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'max_assets') THEN
        ALTER TABLE users ADD COLUMN max_assets INTEGER DEFAULT 10;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'onboarding_completed') THEN
        ALTER TABLE users ADD COLUMN onboarding_completed BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'teams' AND column_name = 'max_subscriptions') THEN
        ALTER TABLE teams ADD COLUMN max_subscriptions INTEGER DEFAULT 10;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'teams' AND column_name = 'max_assets') THEN
        ALTER TABLE teams ADD COLUMN max_assets INTEGER DEFAULT 20;
    END IF;
END $$;

-- 4. Automated updated_at refresh
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

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

-- Ensure updated_at column and other recent columns exist for cves if table was already created
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cves') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cves' AND column_name = 'updated_at') THEN
            ALTER TABLE cves ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cves' AND column_name = 'vector_string') THEN
            ALTER TABLE cves ADD COLUMN vector_string TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cves' AND column_name = 'references') THEN
            ALTER TABLE cves ADD COLUMN "references" TEXT[];
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cves' AND column_name = 'configurations') THEN
            ALTER TABLE cves ADD COLUMN configurations JSONB DEFAULT '[]';
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'user_activity_logs') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'user_activity_logs' AND column_name = 'retention_expires_at') THEN
            ALTER TABLE user_activity_logs ADD COLUMN retention_expires_at TIMESTAMP WITH TIME ZONE;
        END IF;
    END IF;
END $$;

-- 5. Indexes
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_user_id_created_at ON user_activity_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_created_at ON user_activity_logs (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_change_requests_old_token ON email_change_requests (old_email_token);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_change_requests_new_token ON email_change_requests (new_email_token);
CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves (published_date DESC);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_score ON cves (cvss_score);
CREATE INDEX IF NOT EXISTS idx_cves_updated_date ON cves (updated_date DESC);
CREATE INDEX IF NOT EXISTS idx_assets_team_id ON assets(team_id);
CREATE INDEX IF NOT EXISTS idx_user_cve_status_team_id ON user_cve_status(team_id);
CREATE INDEX IF NOT EXISTS idx_cve_notes_team_id ON cve_notes(team_id);

-- Partial Unique Indexes for status and notes
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_user_status ON user_cve_status (user_id, cve_id) WHERE team_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_team_status ON user_cve_status (team_id, cve_id) WHERE team_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_user_notes ON cve_notes (user_id, cve_id) WHERE team_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_team_notes ON cve_notes (team_id, cve_id) WHERE team_id IS NOT NULL;
`
