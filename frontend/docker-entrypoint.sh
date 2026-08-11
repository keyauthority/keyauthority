#!/bin/sh
set -e

# Extract URLs from config
KEYCLOAK_URL=$(jq -r '.url' /usr/share/nginx/html/config/keycloak.json)
API_URL=$(jq -r '.baseURL' /usr/share/nginx/html/config/axios.json)

# CSP source expressions are safest as origins (scheme://host[:port])
KEYCLOAK_ORIGIN=$(printf '%s' "$KEYCLOAK_URL" | sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*://[^/]+).*$#\1#')
API_ORIGIN=$(printf '%s' "$API_URL" | sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*://[^/]+).*$#\1#')

# Substitute into nginx config CSP
CSP="default-src 'self'; style-src 'self' https://fonts.googleapis.com 'sha256-AVTm08UMHPqpttgoudpSsvenKKfidtwuSnUVJLIuqcA='; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ${API_ORIGIN} ${KEYCLOAK_ORIGIN}; frame-src 'self' ${KEYCLOAK_ORIGIN}; form-action 'self'; frame-ancestors 'none';"
export CSP

envsubst '${CSP}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

exec "$@"