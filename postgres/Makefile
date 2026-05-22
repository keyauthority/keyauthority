IMG_REGISTRY ?= docker.io/keyauthoritydh
IMG_REPOSITORY ?= postgres
VERSION ?= $(shell cat ./VERSION)

# if BETA_VERSION is empty then use IMG_TAG=VERSION, 
# otherwise use IMG_TAG=VERSION-betaBETA_VERSION
BETA_VERSION ?=
IMG_TAG=$(VERSION)$(if $(BETA_VERSION),-beta$(BETA_VERSION),)

# if BETA_VERSION is empty then use IMG=$(IMG_REGISTRY)/$(IMG_REPOSITORY):$(IMG_TAG)
# otherwise use IMG=$(IMG_REGISTRY)/$(IMG_REPOSITORY)-beta:$(IMG_TAG)
IMG=$(IMG_REGISTRY)/$(IMG_REPOSITORY)$(if $(BETA_VERSION),-beta):$(IMG_TAG)

# further build arguments
PG_MAJOR=$(shell echo $(VERSION) | cut -d'-' -f1 | cut -d'.' -f1)

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
print-img:
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
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg PG_MAJOR=$(PG_MAJOR) -t $(IMG) .

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
docker-buildx: check-image-exists ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	@if [ -z "$(BUILDER)" ]; then \
		$(CONTAINER_TOOL) buildx create --name keyauthority-builder; \
		$(CONTAINER_TOOL) buildx use keyauthority-builder; \
		$(CONTAINER_TOOL) buildx build --push --build-arg PG_MAJOR=$(PG_MAJOR) --platform=$(PLATFORMS) --tag $(IMG) -f Dockerfile.cross .; \
		$(CONTAINER_TOOL) buildx rm keyauthority-builder; \
	else \
		$(CONTAINER_TOOL) buildx build --push --build-arg PG_MAJOR=$(PG_MAJOR) --platform=$(PLATFORMS) --tag $(IMG) -f Dockerfile.cross .; \
	fi
	rm Dockerfile.cross

##@ Run locally on docker
DATA_VOLUME ?= postgres-data

.PHONY: docker-run
docker-run: load-shared-env
	$(CONTAINER_TOOL) volume create $(DATA_VOLUME) || true
	$(CONTAINER_TOOL) run -d --rm -p $(POSTGRES_PORT):5432 \
			--name postgres \
			--user 65535:4001 \
			-v $(DATA_VOLUME):/var/lib/postgresql \
			-e PGDATA=/var/lib/postgresql/data \
			-e POSTGRES_USER=$(POSTGRES_USER) \
			-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
			$(IMG)

.PHONY: docker-stop
docker-stop:
	$(CONTAINER_TOOL) rm -f postgres || true

.PHONY: scan
scan:
	trivy image $(IMG)