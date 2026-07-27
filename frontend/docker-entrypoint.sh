#!/bin/sh
set -e

# Extract Keycloak URL from config and substitute into nginx config
KEYCLOAK_URL=$(jq -r '.url' /usr/share/nginx/html/config/keycloak.json)
export KEYCLOAK_URL

envsubst '${KEYCLOAK_URL}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

exec "$@"