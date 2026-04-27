BEGIN;

ALTER TABLE keys
ADD COLUMN hsm_config_hash BYTEA
GENERATED ALWAYS AS (
  CASE
    WHEN NULLIF(BTRIM(config->>'pkcs11URI'), '') IS NOT NULL
      THEN digest(config::text, 'sha256')
    ELSE NULL
  END
) STORED;

ALTER TABLE keys
ADD CONSTRAINT unique_hsm_config_hash UNIQUE (hsm_config_hash);

COMMIT;