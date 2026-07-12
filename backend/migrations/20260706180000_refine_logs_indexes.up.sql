BEGIN;

DROP INDEX IF EXISTS logs_level_idx;

-- Partial indexes for each level (only store rows matching that level)
CREATE INDEX IF NOT EXISTS logs_level_error_idx ON logs (log_time DESC) WHERE level = 'ERROR';
CREATE INDEX IF NOT EXISTS logs_level_warn_idx ON logs (log_time DESC) WHERE level = 'WARN';
CREATE INDEX IF NOT EXISTS logs_level_info_idx ON logs (log_time DESC) WHERE level = 'INFO';

-- Partial indexes for common message patterns
CREATE INDEX IF NOT EXISTS logs_msg_secret_read_idx ON logs (log_time DESC) WHERE msg ILIKE '%secret read%';
CREATE INDEX IF NOT EXISTS logs_msg_certificate_signed_idx ON logs (log_time DESC) WHERE msg ILIKE '%certificate signed%';

COMMIT;