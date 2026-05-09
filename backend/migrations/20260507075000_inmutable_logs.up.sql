BEGIN;

CREATE OR REPLACE FUNCTION prevent_recent_logs_mutation()
RETURNS trigger AS $$
DECLARE
  log_time TIMESTAMPTZ;
BEGIN
  BEGIN
    log_time := (OLD.entry->>'time')::timestamptz;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'logs.entry.time is missing or invalid; mutation denied';
  END;

  IF log_time > (now() - interval '6 months') THEN
    RAISE EXCEPTION 'logs rows newer than 6 months are immutable; % is not allowed', TG_OP;
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- DROP TRIGGER IF EXISTS trg_prevent_logs_update ON logs;
-- DROP TRIGGER IF EXISTS trg_prevent_logs_delete ON logs;
CREATE TRIGGER trg_prevent_logs_update
BEFORE UPDATE ON logs
FOR EACH ROW
EXECUTE FUNCTION prevent_recent_logs_mutation();

CREATE TRIGGER trg_prevent_logs_delete
BEFORE DELETE ON logs
FOR EACH ROW
EXECUTE FUNCTION prevent_recent_logs_mutation();

COMMIT;