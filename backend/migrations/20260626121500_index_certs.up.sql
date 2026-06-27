BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_certs_signer_name ON certs (signer_name);
CREATE INDEX IF NOT EXISTS idx_certs_not_before_desc ON certs (not_before DESC);
CREATE INDEX IF NOT EXISTS idx_certs_not_after ON certs (not_after);
CREATE INDEX IF NOT EXISTS idx_certs_revoked ON certs (revoked);

CREATE INDEX IF NOT EXISTS idx_certs_serial_trgm ON certs USING gin (serial gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_certs_signer_name_trgm ON certs USING gin (signer_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_certs_cn_trgm ON certs USING gin (cn gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_certs_comment_trgm ON certs USING gin (comment gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_certs_sans_gin ON certs USING gin (sans);
CREATE INDEX IF NOT EXISTS idx_keys_environment_trgm ON keys USING gin (environment gin_trgm_ops);

COMMIT;