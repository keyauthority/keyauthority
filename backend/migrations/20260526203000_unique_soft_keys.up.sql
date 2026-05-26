BEGIN;

ALTER TABLE keys
ADD CONSTRAINT unique_software_key UNIQUE (software_key);

COMMIT;