IMG_REPOSITORY ?= frontend
CONTAINER_NAME ?= frontend

include ../common.mk

.PHONY: all
all: docker-buildx

##@ Build
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg VERSION=$(IMG_TAG) -t $(IMG) .

.PHONY: docker-buildx
docker-buildx: BUILD_ARGS = --build-arg VERSION=$(IMG_TAG)

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
docker-run:
	docker run -d --rm -p $(FRONTEND_PORT):8080 \
		--name $(CONTAINER_NAME) \
		--user 65535:4001 \
		$(IMG)

##@ Prettify
.PHONY: pretty
pretty:
	npx prettier --write "src"