IMG_REPOSITORY ?= tools
CONTAINER_NAME ?= tools

include ../common.mk

.PHONY: all
all: docker-buildx

.PHONY: docker-build
docker-build:
    $(CONTAINER_TOOL) build -t $(IMG) .

##@ Run locally on docker
.PHONY: docker-run
docker-run:
    docker run -d --rm \
        --name $(CONTAINER_NAME) \
        --user 1001:4001 \
        $(IMG) sleep infinity