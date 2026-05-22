# IMG definition
IMG_REGISTRY ?= registry.digitalocean.com/keyauthority
IMG_NAME=$(IMG_REGISTRY)/keycloak
KC_VERSION=$(shell cat ./VERSION | cut -d'-' -f1)
IMG_TAG=$(shell cat ./VERSION)$(TAG_SUFFIX)
IMG=$(IMG_NAME):$(IMG_TAG)

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: docker-buildx

# Helper target to load shared environment variables
.PHONY: load-shared-env
load-shared-env:
	$(eval include ../shared.env)
	$(eval export)

# Helper target to print the image name and tag
.PHONY: print-img
print-img: ## Print the image name and tag that will be used for building and pushing.
	@echo $(IMG)

##@ Build

.PHONY: check-image-exists
check-image-exists: ## Check if image already exists in registry
	@if $(CONTAINER_TOOL) manifest inspect $(IMG) >/dev/null 2>&1; then \
		echo "Error: Image $(IMG) already exists in registry."; \
		exit 1; \
	fi

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: keycloakify-prep keycloakify-build-theme ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg KC_VERSION=$(KC_VERSION) -t $(IMG) .

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
# PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
PLATFORMS ?= linux/amd64
BUILDER ?=
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	@if [ -z "$(BUILDER)" ]; then \
		$(CONTAINER_TOOL) buildx create --name keyauthority-builder; \
		$(CONTAINER_TOOL) buildx use keyauthority-builder; \
		$(CONTAINER_TOOL) buildx build --push --build-arg KC_VERSION=$(KC_VERSION) --platform=$(PLATFORMS) --tag $(IMG) -f Dockerfile.cross .; \
		$(CONTAINER_TOOL) buildx rm keyauthority-builder; \
	else \
		$(CONTAINER_TOOL) buildx build --push --build-arg KC_VERSION=$(KC_VERSION) --platform=$(PLATFORMS) --tag $(IMG) -f Dockerfile.cross .; \
	fi
	rm Dockerfile.cross

##@ Create database
POSTGRES_DB ?= keycloak
POSTGRES_CONTAINER_NAME ?= postgres
.PHONY: docker-create-db
docker-create-db: load-shared-env
	docker exec -it \
		$(POSTGRES_CONTAINER_NAME) /bin/bash -c "PGPASSWORD=$(POSTGRES_PASSWORD) psql -h host.docker.internal -U $(POSTGRES_USER) -p $(POSTGRES_PORT) -d postgres -c \"CREATE DATABASE $(POSTGRES_DB);\""

##@ Run locally on docker
.PHONY: docker-run
docker-run: load-shared-env
	docker run -d --rm -p $(KC_PORT):8080 \
		--name keycloak \
		--user 65535:4001 \
		-e KC_BOOTSTRAP_ADMIN_USERNAME=$(KC_ADMIN_USER) \
		-e KC_BOOTSTRAP_ADMIN_PASSWORD=$(KC_ADMIN_PASSWORD) \
		-e KC_HTTP_ENABLED=true \
		-e KC_HOSTNAME_STRICT=false \
		-e KC_DB_USERNAME=$(POSTGRES_USER) \
		-e KC_DB_PASSWORD=$(POSTGRES_PASSWORD) \
		-e KC_DB_URL=jdbc:postgresql://host.docker.internal:$(POSTGRES_PORT)/$(POSTGRES_DB) \
		$(IMG)

##@ Stop and remove local docker container
.PHONY: docker-stop
docker-stop:
	docker rm -f keycloak || true

##@ First time preparation
docker-remove-ssl-requirement: load-shared-env
	@echo "Removing SSL requirement for 'master' realm..."
	docker exec -it $(POSTGRES_CONTAINER_NAME) /bin/bash \
		-c "export PGPASSWORD=$(POSTGRES_PASSWORD) && psql \
			-U $(POSTGRES_USER) \
			-d $(POSTGRES_DB) \
			-c \"UPDATE realm SET ssl_required = 'NONE' WHERE name = 'master';\""

.PHONY: docker-run-provisioner
docker-run-provisioner: load-shared-env
	@echo "Importing realm configuration..."
	mkdir -p /tmp/keycloak/config
	envsubst < realm.json > /tmp/keycloak/config/realm.json
	docker run --rm \
		-v "/tmp/keycloak/config:/config" \
		-e KEYCLOAK_URL=http://host.docker.internal:$(KC_PORT) \
		-e KEYCLOAK_USER=$(KC_ADMIN_USER) \
		-e KEYCLOAK_PASSWORD=$(KC_ADMIN_PASSWORD) \
		-e IMPORT_FILES_LOCATIONS=/config/* \
		bitnamilegacy/keycloak-config-cli

##@ Theming
.PHONY: keycloakify-prep
keycloakify-prep:
	cd theming/keyauthority-theme && npm install && npm upgrade

.PHONY: keycloakify-eject
keycloakify-eject:
	cd theming/keyauthority-theme && npx keycloakify eject-page

.PHONY: keycloakify-add-story
keycloakify-add-story:
	cd theming/keyauthority-theme && npx keycloakify add-story

.PHONY: keycloakify-run-theme
keycloakify-run-theme:
	cd theming/keyauthority-theme && npm run storybook

.PHONY: keycloakify-build-theme
keycloakify-build-theme: 
	cd theming/keyauthority-theme && npm run build-keycloak-theme

##@ Prettify
.PHONY: pretty
pretty:
	npx prettier --write "theming"

##@ Scan
.PHONY: scan
scan:
	trivy image $(IMG)