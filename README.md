# KeyAuthority

This repository contains KeyAuthority source code, with its four main components:
- PostgreSQL database (in `./postgres`)
- Keycloak identity and access management (in `./keycloak`)
- Backend service (in `./backend`)
- Frontend web application (in `./frontend`)

## Deploy KeyAuthority on local Docker

To deploy KeyAuthority locally using Docker, follow these steps for each component. Make sure you have Docker installed on your machine.

```shell
#@ PostgreSQL
# open a terminal at ./postgres
make docker-run IMG_REGISTRY=keyauthoritydh

#@ Keycloak
# open a terminal at ./keycloak
make docker-create-db
make docker-run IMG_REGISTRY=keyauthoritydh
# ...wait for Keycloak to be ready
# ...create realm.json using KeyAuthority Helm chart and make sure that:
#    'sslRequired' is 'none'
#    'keyauthority-discovery' client secret matches one in shared.env
#    'keyauthority-frontend' rootUrl, adminUrl, redirectUris, and webOrigins point to http://localhost:3000
make docker-remove-ssl-requirement
make docker-run-provisioner

#@ Backend
# open a terminal at ./backend
make docker-create-db
make docker-run \
  ENTERPRISE=true \
  IMG_REGISTRY=registry.digitalocean.com/keyauthority \
  TAG_SUFFIX="-beta$(git rev-parse --short HEAD)"

#@ Frontend
# open a terminal at ./frontend
make docker-run IMG_REGISTRY=keyauthoritydh
```

Adjust the `IMG_REGISTRY` and `TAG_SUFFIX` variables as needed to point to your image registry and to use appropriate tags for your images.

After running all components, you can access the KeyAuthority frontend at [http://localhost:3000](http://localhost:3000).
