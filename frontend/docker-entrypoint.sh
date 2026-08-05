#!/bin/sh
set -e

# Extract Keycloak URL from config and substitute into nginx config CSP
KEYCLOAK_URL=$(jq -r '.url' /usr/share/nginx/html/config/keycloak.json)
CSP="default-src 'self'; style-src 'self' https://fonts.googleapis.com 'sha256-AVTm08UMHPqpttgoudpSsvenKKfidtwuSnUVJLIuqcA='; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src *; frame-src 'self' ${KEYCLOAK_URL}; form-action 'self'; frame-ancestors 'none';"
export CSP

envsubst '${CSP}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

exec "$@"