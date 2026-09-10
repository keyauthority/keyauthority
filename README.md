# KeyAuthority

This repository contains the source code for KeyAuthority, which is a platform for managing private Certificate Authorities, X.509 certificates, and application secrets across your Kubernetes environments. The tool simplifies certificate lifecycle management and secure secret distribution for applications and microservices.

To learn how to deploy KeyAuthority to your Kubernetes cluster using Helm, visit our [Artifact Hub page](https://artifacthub.io/packages/helm/keyauthority/keyauthority).

## Architecture Overview

The following diagram illustrates the architecture of KeyAuthority, showing its components and their interactions. KeyAuthority components are the frontend, the backend, the identity provider (Keycloak), and the database. The diagram also shows the interactions with humans, machines, and the HSM. Dashed lines indicate KeyAuthority's internal interactions, whereas solid lines represent interactions with external actors.

![KeyAuthority Architecture](arch.png)

## Folder Layout

- PostgreSQL database in `./postgres`
- Keycloak identity and access management in `./keycloak`
- Backend service in `./backend`
- Frontend web application in `./frontend`
- Init tooling in `./tools`

## Dev deployment on local Docker

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

After running all components, you can access the frontend at [http://localhost:3000](http://localhost:3000).
