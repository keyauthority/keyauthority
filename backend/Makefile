IMG_REPOSITORY ?= backend
CONTAINER_NAME ?= backend

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

include ../common.mk

.PHONY: all
all: build

##@ Development

.PHONY: tidy
tidy: ## Run go mod tidy.
	go mod tidy

.PHONY: update-deps
update-deps: ## Update dependencies to latest versions.
	go get -u ./...
	go mod tidy

.PHONY: upgrade-deps
upgrade-deps: update-deps

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

##@ Build

.PHONY: build
build: fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg VERSION=$(IMG_TAG) -t $(IMG) .

.PHONY: docker-buildx
docker-buildx: BUILD_ARGS = --build-arg VERSION=$(IMG_TAG)

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
GOLANGCI_LINT_VERSION ?= v1.63.4

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

##@ Swagger
SWAGGER_VERSION = 5.32.12
SWAGGER_DIR = ./swagger
.PHONY: download-swagger
download-swagger:
	mkdir -p $(SWAGGER_DIR)/tmp
	wget -q -O $(SWAGGER_DIR)/tmp/swagger-ui.zip https://github.com/swagger-api/swagger-ui/archive/refs/tags/v$(SWAGGER_VERSION).zip && \
	unzip -q $(SWAGGER_DIR)/tmp/swagger-ui.zip -d $(SWAGGER_DIR)/tmp && \
	cp $(SWAGGER_DIR)/tmp/swagger-ui-$(SWAGGER_VERSION)/dist/swagger-ui.css $(SWAGGER_DIR) && \
	cp $(SWAGGER_DIR)/tmp/swagger-ui-$(SWAGGER_VERSION)/dist/swagger-ui-bundle.js $(SWAGGER_DIR) && \
	cp $(SWAGGER_DIR)/tmp/swagger-ui-$(SWAGGER_VERSION)/dist/swagger-ui-standalone-preset.js $(SWAGGER_DIR) && \
	rm -rf $(SWAGGER_DIR)/tmp

.PHONY: serve-swagger
serve-swagger:
	cd $(SWAGGER_DIR) && python3 -m http.server 8006

##@ Create database
POSTGRES_DB ?= backend
.PHONY: docker-create-db
docker-create-db: load-shared-env
	docker exec -it \
		$(POSTGRES_CONTAINER_NAME) /bin/bash -c "PGPASSWORD=$(POSTGRES_PASSWORD) psql -h host.docker.internal -U $(POSTGRES_USER) -p $(POSTGRES_PORT) -c \"CREATE DATABASE $(POSTGRES_DB);\""

##@ Run locally on docker
PWD = $(shell pwd)
CORS_ORIGIN ?= http://localhost:$(FRONTEND_PORT)
BACKEND_PORT ?= 8081
METRICS_PORT ?= 9000
INVENTORY_REFRESH_INTERVAL ?= 1m
LOG_LEVEL ?= debug
SOFTWARE_KEY_PASSPHRASE ?= passphrase
KC_URL = http://host.docker.internal:$(KC_PORT)

.PHONY: docker-run
docker-run: load-shared-env
	docker run -d --rm -p $(BACKEND_PORT):8081 \
		--name $(CONTAINER_NAME) \
		--user 65535:4001 \
		-v "$(PWD)/ignore/softhsm/etc/softhsm:/etc/softhsm" \
		-e HTTP_PORT=8081 \
		-e METRICS_PORT=$(METRICS_PORT) \
		-e INVENTORY_REFRESH_INTERVAL=$(INVENTORY_REFRESH_INTERVAL) \
		-e CORS_ORIGIN=$(CORS_ORIGIN) \
		-e LOG_LEVEL=$(LOG_LEVEL) \
		-e LOG_DB_ENABLED=true \
		-e LOG_DB_BATCH_SIZE=10 \
		-e LOG_DB_FLUSH_INTERVAL=2s \
		-e SOFTWARE_KEY_PASSPHRASE=$(SOFTWARE_KEY_PASSPHRASE) \
		-e KEYCLOAK_URL=$(KC_URL) \
		-e KEYCLOAK_REALM=$(KC_REALM) \
		-e KC_EXCHANGE_CLIENT_ID=$(KC_EXCHANGE_CLIENT_ID) \
		-e KC_EXCHANGE_CLIENT_SECRET=$(KC_EXCHANGE_CLIENT_SECRET) \
		-e POSTGRESQL_HOST=host.docker.internal \
		-e POSTGRESQL_USER=$(POSTGRES_USER) \
		-e POSTGRESQL_PASSWORD=$(POSTGRES_PASSWORD) \
		-e POSTGRESQL_DATABASE=$(POSTGRES_DB) \
		-e POSTGRESQL_PORT_NUMBER=$(POSTGRES_PORT) \
		-e SOFTHSM2_CONF=/etc/softhsm/softhsm.conf \
		$(IMG)

.PHONY: run
run: load-shared-env
	HTTP_PORT=$(BACKEND_PORT) \
	METRICS_PORT=$(METRICS_PORT) \
	INVENTORY_REFRESH_INTERVAL=$(INVENTORY_REFRESH_INTERVAL) \
	CORS_ORIGIN=$(CORS_ORIGIN) \
	LOG_LEVEL=$(LOG_LEVEL) \
	LOG_DB_ENABLED=true \
	LOG_DB_BATCH_SIZE=10 \
	LOG_DB_FLUSH_INTERVAL=2s \
	SOFTWARE_KEY_PASSPHRASE=$(SOFTWARE_KEY_PASSPHRASE) \
	KEYCLOAK_URL=http://localhost:$(KC_PORT) \
	KEYCLOAK_REALM=$(KC_REALM) \
	KEYCLOAK_EXCHANGE_CLIENT_ID=$(KC_EXCHANGE_CLIENT_ID) \
	KEYCLOAK_EXCHANGE_CLIENT_SECRET=$(KC_EXCHANGE_CLIENT_SECRET) \
	POSTGRESQL_HOST=localhost \
	POSTGRESQL_USER=$(POSTGRES_USER) \
	POSTGRESQL_PASSWORD=$(POSTGRES_PASSWORD) \
	POSTGRESQL_DATABASE=$(POSTGRES_DB) \
	POSTGRESQL_PORT_NUMBER=$(POSTGRES_PORT) \
	SOFTHSM2_CONF=./ignore/softhsm/etc/softhsm/softhsm.conf \
	go run cmd/server/main.go

##@ Pretty
.PHONY: pretty
pretty: fmt
	npx prettier --write "**/*.yaml"

##@ Scan
.PHONY: scan-all
scan-all: scan scan-code

.PHONY: scan-code
scan-code:
	go test ./...
	go vet ./...
	govulncheck ./...
	staticcheck ./... || true
	semgrep scan --config=./.semgrep .