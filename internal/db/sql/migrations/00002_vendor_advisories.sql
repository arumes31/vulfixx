-- +goose Up
-- Add vendor_advisories column to store structured advisory data from vendor PSIRTs
ALTER TABLE cves ADD COLUMN IF NOT EXISTS vendor_advisories JSONB DEFAULT '{}';

-- Add GIN index for efficient JSONB queries on vendor_advisories
CREATE INDEX IF NOT EXISTS idx_cves_vendor_advisories_gin ON cves USING GIN (vendor_advisories);

-- Migrate existing FortiGuard data from osint_data to vendor_advisories
-- Only migrate rows that have fortiguard_advisory_id in osint_data
-- and either vendor_advisories is empty or doesn't have fortiguard key
UPDATE cves
SET vendor_advisories = jsonb_build_object(
    'fortiguard', jsonb_build_object(
        'advisory_id', osint_data->>'fortiguard_advisory_id',
        'advisory_url', osint_data->>'fortiguard_advisory_url',
        'severity', osint_data->>'fortiguard_severity',
        'cvss_score', CASE
            WHEN osint_data->>'fortiguard_cvss_score' ~ '^[0-9]+(\.[0-9]+)?$'
            THEN (osint_data->>'fortiguard_cvss_score')::numeric
            ELSE NULL
        END,
        'cvss_vector', osint_data->>'fortiguard_cvss_vector',
        'impact', osint_data->>'fortiguard_impact',
        'fix', osint_data->>'fortiguard_fix',
        'workaround', osint_data->>'fortiguard_workaround',
        'affected_products', COALESCE(osint_data->'fortiguard_affected_products', '[]'::jsonb),
        'last_scraped', osint_data->>'fortiguard_last_scraped'
    )
)
WHERE osint_data ? 'fortiguard_advisory_id'
  AND (vendor_advisories = '{}'::jsonb OR vendor_advisories ? 'fortiguard' = false);

-- Remove migrated FortiGuard keys from osint_data to avoid duplication
UPDATE cves
SET osint_data = osint_data - array(
    SELECT key FROM jsonb_object_keys(osint_data) AS key
    WHERE key LIKE 'fortiguard_%'
)
WHERE osint_data ? 'fortiguard_advisory_id';

-- +goose Down
-- Remove vendor_advisories column
DROP INDEX IF EXISTS idx_cves_vendor_advisories_gin;
ALTER TABLE cves DROP COLUMN IF EXISTS vendor_advisories;