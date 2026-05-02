-- Add missing GreyNoise columns if they don't exist
ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_hits INTEGER DEFAULT 0;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_classification VARCHAR(50);

-- Ensure other potentially missing columns from recent updates are also present
ALTER TABLE cves ADD COLUMN IF NOT EXISTS osv_data JSONB DEFAULT '{}';
ALTER TABLE cves ADD COLUMN IF NOT EXISTS osint_data JSONB DEFAULT '{}';
ALTER TABLE cves ADD COLUMN IF NOT EXISTS vendor VARCHAR(255);
ALTER TABLE cves ADD COLUMN IF NOT EXISTS product VARCHAR(255);
ALTER TABLE cves ADD COLUMN IF NOT EXISTS affected_products JSONB DEFAULT '[]';
ALTER TABLE cves ADD COLUMN IF NOT EXISTS osv_last_updated TIMESTAMP WITH TIME ZONE;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_last_updated TIMESTAMP WITH TIME ZONE;

-- Create indexes for efficient synchronization tracking
CREATE INDEX IF NOT EXISTS idx_cves_osv_last_updated ON cves (osv_last_updated ASC NULLS FIRST);
CREATE INDEX IF NOT EXISTS idx_cves_greynoise_last_updated ON cves (greynoise_last_updated ASC NULLS FIRST);
