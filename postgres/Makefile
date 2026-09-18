IMG_REPOSITORY ?= postgres
CONTAINER_NAME ?= postgres

# further build arguments
PG_MAJOR=$(shell echo $(VERSION) | cut -d'-' -f1 | cut -d'.' -f1)

include ../common.mk

.PHONY: all
all: docker-buildx

##@ Build

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg PG_MAJOR=$(PG_MAJOR) -t $(IMG) .

.PHONY: docker-buildx
docker-buildx: BUILD_ARGS = --build-arg PG_MAJOR=$(PG_MAJOR)

##@ Run locally on docker
DATA_VOLUME ?= postgres-data

.PHONY: docker-run
docker-run: load-shared-env
	$(CONTAINER_TOOL) volume create $(DATA_VOLUME) || true
	$(CONTAINER_TOOL) run -d --rm -p $(POSTGRES_PORT):5432 \
		--name $(CONTAINER_NAME) \
		--user 65535:4001 \
		-v $(DATA_VOLUME):/var/lib/postgresql \
		-e PGDATA=/var/lib/postgresql/data \
		-e POSTGRES_USER=$(POSTGRES_USER) \
		-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
		$(IMG)