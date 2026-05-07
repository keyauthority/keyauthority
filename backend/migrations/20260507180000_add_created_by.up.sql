BEGIN;

ALTER TABLE keys
ADD COLUMN created_by TEXT DEFAULT 'unknown';

UPDATE keys
SET created_by = 'unknown'
WHERE created_by IS NULL;

ALTER TABLE keys
ALTER COLUMN created_by SET NOT NULL;

COMMIT;