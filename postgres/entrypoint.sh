#!/bin/bash
set -euo pipefail

POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-$POSTGRES_USER}"

# Ensure UID mapping
if ! getent passwd "$(id -u)" >/dev/null 2>&1; then
  export NSS_WRAPPER_PASSWD=/tmp/passwd.nss_wrapper
  export NSS_WRAPPER_GROUP=/etc/group
  cp /etc/passwd "${NSS_WRAPPER_PASSWD}"
  echo "${POSTGRES_USER}:x:$(id -u):$(id -g):dynamic uid:${HOME:-/tmp}:/sbin/nologin" >> "${NSS_WRAPPER_PASSWD}"
  export LD_PRELOAD=/usr/lib64/libnss_wrapper.so
fi

# Create the data dir with appropriate permissions
mkdir -p "$PGDATA"
chmod 0700 "$PGDATA"

# Create other dirs with appropriate permissions
mkdir -p /run/postgresql /usr/share/zoneinfo

# Initialize the database if it doesn't exist
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "Initializing database \"$POSTGRES_DB\"..."
  initdb -D "$PGDATA" --username="$POSTGRES_USER" --auth-local=trust --auth-host=scram-sha-256
  echo "host all all all scram-sha-256" >> "$PGDATA/pg_hba.conf"
  echo "listen_addresses = '*'" >> "$PGDATA/postgresql.conf"

  pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w start

  if [ -n "$POSTGRES_DB" ] && [ "$POSTGRES_DB" != "postgres" ]; then
    createdb -U "$POSTGRES_USER" -T template1 "$POSTGRES_DB"
  fi

  if [ -n "${POSTGRES_PASSWORD:-}" ]; then
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
      -c "ALTER USER \"$POSTGRES_USER\" PASSWORD '$POSTGRES_PASSWORD';"
  fi

  pg_ctl -D "$PGDATA" -m fast -w stop
fi

# If args start with "-", assume they are postgres flags and prepend the binary.
if [ "${1:-}" != "" ] && [ "${1#-}" != "$1" ]; then
  set -- postgres "$@"
fi

# Default command when no args are provided.
if [ "$#" -eq 0 ]; then
  set -- postgres
fi

exec "$@"