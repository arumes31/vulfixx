CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_email_verified BOOLEAN DEFAULT FALSE,
    email_verify_token VARCHAR(255),
    totp_secret VARCHAR(255),
    is_totp_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    cvss_score NUMERIC(4,1),
    cisa_kev BOOLEAN DEFAULT FALSE,
    published_date TIMESTAMP WITH TIME ZONE,
    updated_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    keyword VARCHAR(255),
    min_severity NUMERIC(4,1),
    webhook_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_cve_status (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL, -- e.g., 'resolved', 'ignored'
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, cve_id)
);

CREATE TABLE IF NOT EXISTS alert_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    cve_id INTEGER REFERENCES cves(id) ON DELETE CASCADE,
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, cve_id)
);
