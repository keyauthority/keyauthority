BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

ALTER TABLE logs
  ADD COLUMN IF NOT EXISTS log_time TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS level TEXT,
  ADD COLUMN IF NOT EXISTS msg TEXT,
  ADD COLUMN IF NOT EXISTS log_user TEXT,
  ADD COLUMN IF NOT EXISTS environment TEXT;

-- Backfill without the immutability trigger blocking updates
ALTER TABLE logs DISABLE TRIGGER USER;

UPDATE logs
SET
  log_time = COALESCE(log_time, (entry->>'time')::timestamptz),
  level = COALESCE(level, entry->>'level'),
  msg = COALESCE(msg, entry->>'msg'),
  log_user = COALESCE(log_user, entry->'token'->>'user'),
  environment = COALESCE(environment, entry->>'environment')
WHERE log_time IS NULL
   OR level IS NULL
   OR msg IS NULL
   OR log_user IS NULL
   OR environment IS NULL;

ALTER TABLE logs ENABLE TRIGGER USER;

CREATE INDEX IF NOT EXISTS logs_log_time_idx ON logs (log_time DESC);
CREATE INDEX IF NOT EXISTS logs_level_idx ON logs (level);
CREATE INDEX IF NOT EXISTS logs_log_user_trgm_idx ON logs USING GIN (log_user gin_trgm_ops);
CREATE INDEX IF NOT EXISTS logs_msg_trgm_idx ON logs USING GIN (msg gin_trgm_ops);
CREATE INDEX IF NOT EXISTS logs_environment_trgm_idx ON logs USING GIN (environment gin_trgm_ops);

COMMIT;