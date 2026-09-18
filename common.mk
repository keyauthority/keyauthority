# Shared logic for all service Makefiles. Include with:
#   include ../common.mk
# Requires each Makefile to set IMG_REPOSITORY (and optionally CONTAINER_NAME) before including.

IMG_REGISTRY ?= docker.io/keyauthoritydh
VERSION ?= $(shell cat ./VERSION)

BETA_VERSION ?=
IMG_TAG=$(VERSION)$(if $(BETA_VERSION),-$(BETA_VERSION),)
IMG=$(IMG_REGISTRY)/$(IMG_REPOSITORY)$(if $(BETA_VERSION),-beta):$(IMG_TAG)

CONTAINER_TOOL ?= docker

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
BUILDER ?=

# --- Shared env vars (git-ignored, generated once) ---
ENV_FILE ?= $(CURDIR)/../.config/shared.env

.PHONY: load-shared-env
load-shared-env:
	@mkdir -p $(dir $(ENV_FILE))
	@if [ ! -f $(ENV_FILE) ]; then \
		echo "## Postgres" >> $(ENV_FILE); \
		echo "POSTGRES_USER=keyauthority" >> $(ENV_FILE); \
		echo "POSTGRES_PASSWORD=$$(openssl rand -hex 16)" >> $(ENV_FILE); \
		echo "POSTGRES_PORT=5432" >> $(ENV_FILE); \
		echo "POSTGRES_CONTAINER_NAME=postgres" >> $(ENV_FILE); \
		echo "## Keycloak" >> $(ENV_FILE); \
		echo "KC_PORT=8080" >> $(ENV_FILE); \
		echo "KC_ADMIN_USER=admin" >> $(ENV_FILE); \
		echo "KC_ADMIN_PASSWORD=admin" >> $(ENV_FILE); \
		echo "KC_REALM=local" >> $(ENV_FILE); \
		echo "KC_EXCHANGE_CLIENT_ID=keyauthority-exchange" >> $(ENV_FILE); \
		echo "KC_EXCHANGE_CLIENT_SECRET=$$(openssl rand -hex 16)" >> $(ENV_FILE); \
		echo "## Backend" >> $(ENV_FILE); \
		echo "BACKEND_PORT=8081" >> $(ENV_FILE); \
		echo "## Frontend" >> $(ENV_FILE); \
		echo "FRONTEND_PORT=3000" >> $(ENV_FILE); \
		chmod 600 $(ENV_FILE); \
		echo "Created env variables"; \
	else \
		echo "Env variables already exist, skipping."; \
	fi

-include $(ENV_FILE)
export

# --- Common targets ---

.PHONY: print-img
print-img: ## Print the image name and tag that will be used for building and pushing.
	@echo $(IMG)

.PHONY: check-image-exists
check-image-exists: ## Check if image already exists in registry
	@if $(CONTAINER_TOOL) manifest inspect $(IMG) >/dev/null 2>&1; then \
		echo "Error: Image $(IMG) already exists in registry."; \
		exit 1; \
	fi

.PHONY: scan
scan: ## Scan the built image with trivy
	trivy image $(IMG)

# Generic buildx target. Callers can override BUILD_ARGS, e.g.:
#   BUILD_ARGS="--build-arg VERSION=$(IMG_TAG)"
BUILD_ARGS ?=
.PHONY: docker-buildx
docker-buildx: check-image-exists ## Build and push docker image for cross-platform support
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	@if [ -z "$(BUILDER)" ]; then \
		$(CONTAINER_TOOL) buildx create --name keyauthority-builder; \
		$(CONTAINER_TOOL) buildx use keyauthority-builder; \
		$(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) $(BUILD_ARGS) --tag $(IMG) -f Dockerfile.cross .; \
		$(CONTAINER_TOOL) buildx rm keyauthority-builder; \
	else \
		$(CONTAINER_TOOL) buildx build --push --builder $(BUILDER) --platform=$(PLATFORMS) $(BUILD_ARGS) --tag $(IMG) -f Dockerfile.cross .; \
	fi
	rm Dockerfile.cross

# Generic docker-stop, override CONTAINER_NAME per-Makefile.
CONTAINER_NAME ?=
.PHONY: docker-stop
docker-stop: ## Stop and remove local docker container
	$(CONTAINER_TOOL) rm -f $(CONTAINER_NAME) || true