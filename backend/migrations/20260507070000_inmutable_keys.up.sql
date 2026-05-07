BEGIN;

CREATE OR REPLACE FUNCTION prevent_keys_update()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'keys rows are immutable; UPDATE is not allowed';
END;
$$ LANGUAGE plpgsql;

-- DROP TRIGGER IF EXISTS trg_prevent_keys_update ON keys;
CREATE TRIGGER trg_prevent_keys_update
BEFORE UPDATE ON keys
FOR EACH ROW
EXECUTE FUNCTION prevent_keys_update();

COMMIT;