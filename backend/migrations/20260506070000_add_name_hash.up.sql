BEGIN;

ALTER TABLE signers
ADD COLUMN name_hash TEXT
GENERATED ALWAYS AS (
  LEFT(
    TRANSLATE(
      ENCODE(DIGEST(name, 'sha256'), 'base64'),
      '+/=',
      '-_'
    ),
    32
  )
) STORED;

ALTER TABLE signers
ADD CONSTRAINT unique_name_hash UNIQUE (name_hash);

COMMIT;