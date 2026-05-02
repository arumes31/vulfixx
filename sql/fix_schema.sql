-- Add missing GreyNoise columns if they don't exist
ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_hits INTEGER DEFAULT 0;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS greynoise_classification VARCHAR(50);

-- Ensure other potentially missing columns from recent updates are also present
ALTER TABLE cves ADD COLUMN IF NOT EXISTS osv_data JSONB DEFAULT '{}';
ALTER TABLE cves ADD COLUMN IF NOT EXISTS osint_data JSONB DEFAULT '{}';
ALTER TABLE cves ADD COLUMN IF NOT EXISTS vendor VARCHAR(255);
ALTER TABLE cves ADD COLUMN IF NOT EXISTS product VARCHAR(255);
ALTER TABLE cves ADD COLUMN IF NOT EXISTS affected_products JSONB DEFAULT '[]';
