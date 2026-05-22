# IMG definition
IMG_REGISTRY ?= registry.digitalocean.com/keyauthority
IMG_NAME=$(IMG_REGISTRY)/frontend
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
	$(CONTAINER_TOOL) build --build-arg VERSION=$(IMG_TAG) -t $(IMG) .

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
		$(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --build-arg VERSION=$(IMG_TAG) --tag $(IMG) -f Dockerfile.cross .; \
		$(CONTAINER_TOOL) buildx rm keyauthority-builder; \
	else \
		$(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --build-arg VERSION=$(IMG_TAG) --tag $(IMG) -f Dockerfile.cross .; \
	fi
	rm Dockerfile.cross

##@ Install & upgrade packages
.PHONY: npm
npm:
	npm install
	npm upgrade

##@ Run locally
.PHONY: run
run:
	npm start

##@ Run locally on docker
FRONTEND_PORT ?= 3000
.PHONY: docker-run
docker-run: load-shared-env
	docker run -d --rm -p $(FRONTEND_PORT):8080 \
		--name frontend \
		--user 65535:4001 \
		$(IMG)

##@ Stop and remove local docker container
.PHONY: docker-stop
docker-stop:
	docker rm -f frontend || true

##@ Prettify
.PHONY: pretty
pretty:
	npx prettier --write "src"

##@ Scan
.PHONY: scan
scan:
	trivy image $(IMG)