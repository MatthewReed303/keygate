-- Plans: offline (air-gapped) plans, whose signed tokens carry no
-- check-in interval: exp is valid_until + grace_days, or 0 (no expiry)
-- for a perpetual licence. token_ttl_days does not apply to them.
ALTER TABLE plans ADD COLUMN IF NOT EXISTS offline BOOLEAN NOT NULL DEFAULT FALSE;
