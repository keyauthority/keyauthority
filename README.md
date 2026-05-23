# KeyAuthority

This repository contains KeyAuthority source code, with its four main components:
- PostgreSQL database (in `./postgres`)
- Keycloak identity and access management (in `./keycloak`)
- Backend service (in `./backend`)
- Frontend web application (in `./frontend`)

## Deploy KeyAuthority on local Docker

To deploy KeyAuthority locally using Docker, follow these steps:

```shell
#@ PostgreSQL
# open a terminal at ./postgres
make docker-run

#@ Keycloak
# open a terminal at ./keycloak
make docker-create-db
make docker-run
# ...wait for Keycloak to be ready
# ...create realm.json using KeyAuthority Helm chart and make sure that:
#    'sslRequired' is 'none'
#    'keyauthority-discovery' client secret matches one in shared.env
#    'keyauthority-frontend' rootUrl, adminUrl, redirectUris, and webOrigins point to http://localhost:3000
make docker-remove-ssl-requirement
make docker-stop
make docker-run
make docker-run-provisioner

#@ Backend
# open a terminal at ./backend
make docker-create-db
make docker-run ENTERPRISE=true

#@ Frontend
# open a terminal at ./frontend
make docker-run
```

Use the `BETA_VERSION` env var for beta images. For example, `BETA_VERSION=$(git rev-parse --short HEAD) make docker-run` will run the beta version of the component (assuming the image was built following the last git commit).

After running all components, you can access the KeyAuthority frontend at [http://localhost:3000](http://localhost:3000).
