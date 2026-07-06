BEGIN;

CREATE OR REPLACE FUNCTION estimate_table_count(table_name TEXT)
RETURNS bigint AS $$
  SELECT reltuples::bigint FROM pg_class WHERE relname = table_name;
$$ LANGUAGE sql VOLATILE;

COMMIT;