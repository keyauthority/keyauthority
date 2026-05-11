# IMG definition
IMG_REGISTRY ?= registry.digitalocean.com/keyauthority
ENTERPRISE ?= false
ifeq (${ENTERPRISE},true)
IMG_NAME=$(IMG_REGISTRY)/backend-enterprise
else
IMG_NAME=$(IMG_REGISTRY)/backend
endif
IMG_TAG=$(shell cat ./VERSION)$(TAG_SUFFIX)
IMG=$(IMG_NAME):$(IMG_TAG)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

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
all: build

# Helper target to load shared environment variables
.PHONY: load-shared-env
load-shared-env:
	$(eval include ../shared.env)
	$(eval export)

# Helper target to print the image name and tag
.PHONY: print-img
print-img: ## Print the image name and tag that will be used for building and pushing.
	@echo $(IMG)

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

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
.PHONY: test-e2e
test-e2e: manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	@command -v kind >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@kind get clusters | grep -q 'kind' || { \
		echo "No Kind cluster is running. Please start a Kind cluster before running the e2e tests."; \
		exit 1; \
	}
	go test ./test/e2e/ -v -ginkgo.v

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

.PHONY: check-image-exists
check-image-exists: ## Check if image already exists in registry
	@if $(CONTAINER_TOOL) manifest inspect $(IMG) >/dev/null 2>&1; then \
		echo "Error: Image $(IMG) already exists in registry."; \
		exit 1; \
	fi

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg ENTERPRISE=${ENTERPRISE} --build-arg VERSION=$(IMG_TAG) -t $(IMG) .

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
# PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
PLATFORMS ?= linux/amd64
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	$(CONTAINER_TOOL) buildx create --name keyauthority-builder
	$(CONTAINER_TOOL) buildx use keyauthority-builder
	$(CONTAINER_TOOL) buildx build --push --build-arg ENTERPRISE=${ENTERPRISE} --build-arg VERSION=$(IMG_TAG) --platform=$(PLATFORMS) --tag $(IMG) -f Dockerfile.cross .
	$(CONTAINER_TOOL) buildx rm keyauthority-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.5.0
CONTROLLER_TOOLS_VERSION ?= v0.17.2
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')
GOLANGCI_LINT_VERSION ?= v1.63.4

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

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
SWAGGER_VERSION = 5.32.5
SWAGGER_DIR = ./swagger
.PHONY: download-swagger
download-swagger:
	mkdir -p $(SWAGGER_DIR)
	curl https://unpkg.com/swagger-ui@$(SWAGGER_VERSION)/dist/swagger-ui.css -o $(SWAGGER_DIR)/swagger-ui.css
	curl https://unpkg.com/swagger-ui@$(SWAGGER_VERSION)/dist/swagger-ui-bundle.js -o $(SWAGGER_DIR)/swagger-ui-bundle.js
	curl https://unpkg.com/swagger-ui@$(SWAGGER_VERSION)/dist/swagger-ui-standalone-preset.js -o $(SWAGGER_DIR)/swagger-ui-standalone-preset.js

.PHONY: serve-swagger
serve-swagger:
	cd $(SWAGGER_DIR) && python3 -m http.server 8006

##@ Create database
POSTGRES_DB ?= backend
POSTGRES_CONTAINER_NAME ?= postgres
.PHONY: docker-create-db
docker-create-db: load-shared-env
	docker exec -it \
		$(POSTGRES_CONTAINER_NAME) /bin/bash -c "PGPASSWORD=$(POSTGRES_PASSWORD) psql -h host.docker.internal -U $(POSTGRES_USER) -p $(POSTGRES_PORT) -d postgres -c \"CREATE DATABASE $(POSTGRES_DB);\""

##@ Run locally on docker
PWD = $(shell pwd)
CORS_ORIGIN ?= http://localhost:$(FRONTEND_PORT)
BACKEND_PORT ?= 8081
LOG_LEVEL ?= debug
RESPOND_WITH_ERROR_DETAILS ?= true
SOFTWARE_KEY_PASSPHRASE ?= passphrase
# KC_URL ?= http://localhost:$(KC_PORT)
KC_URL = http://host.docker.internal:$(KC_PORT)

.PHONY: docker-run
docker-run: load-shared-env
	docker run -d --rm -p $(BACKEND_PORT):8080 \
		--name backend \
		--user 65535:4001 \
		-v "$(PWD)/ignore/primus/etc/primus:/etc/primus" \
		-v "$(PWD)/ignore/softhsm/etc/softhsm:/etc/softhsm" \
		-e PORT=8080 \
		-e CORS_ORIGIN=$(CORS_ORIGIN) \
		-e RESPOND_WITH_ERROR_DETAILS=$(RESPOND_WITH_ERROR_DETAILS) \
		-e LOG_LEVEL=$(LOG_LEVEL) \
		-e LOG_DB_ENABLED=true \
		-e LOG_DB_BATCH_SIZE=10 \
		-e LOG_DB_FLUSH_INTERVAL=2s \
		-e SOFTWARE_KEY_PASSPHRASE=$(SOFTWARE_KEY_PASSPHRASE) \
		-e KEYCLOAK_URL=$(KC_URL) \
		-e KEYCLOAK_REALM=$(KC_REALM) \
		-e KEYCLOAK_DISCOVERY_CLIENT_ID=$(KC_DISCOVERY_CLIENT_ID) \
		-e KEYCLOAK_DISCOVERY_CLIENT_SECRET=$(KC_DISCOVERY_CLIENT_SECRET) \
		-e POSTGRESQL_HOST=host.docker.internal \
		-e POSTGRESQL_USER=$(POSTGRES_USER) \
		-e POSTGRESQL_PASSWORD=$(POSTGRES_PASSWORD) \
		-e POSTGRESQL_DATABASE=$(POSTGRES_DB) \
		-e POSTGRESQL_PORT_NUMBER=$(POSTGRES_PORT) \
		-e SOFTHSM2_CONF=/etc/softhsm/softhsm.conf \
		-e SOFTHSM_SO_PIN=1234 \
		-e SOFTHSM_PIN=5678 \
		$(IMG)

.PHONY: run
run: load-shared-env
	PORT=$(BACKEND_PORT) \
	CORS_ORIGIN=$(CORS_ORIGIN) \
	LOG_LEVEL=$(LOG_LEVEL) \
	RESPOND_WITH_ERROR_DETAILS=$(RESPOND_WITH_ERROR_DETAILS) \
	LOG_DB_ENABLED=true \
	LOG_DB_BATCH_SIZE=10 \
	LOG_DB_FLUSH_INTERVAL=2s \
	SOFTWARE_KEY_PASSPHRASE=$(SOFTWARE_KEY_PASSPHRASE) \
	KEYCLOAK_URL=http://localhost:$(KC_PORT) \
	KEYCLOAK_REALM=$(KC_REALM) \
	KEYCLOAK_DISCOVERY_CLIENT_ID=$(KC_DISCOVERY_CLIENT_ID) \
	KEYCLOAK_DISCOVERY_CLIENT_SECRET=$(KC_DISCOVERY_CLIENT_SECRET) \
	POSTGRESQL_HOST=localhost \
	POSTGRESQL_USER=$(POSTGRES_USER) \
	POSTGRESQL_PASSWORD=$(POSTGRES_PASSWORD) \
	POSTGRESQL_DATABASE=$(POSTGRES_DB) \
	POSTGRESQL_PORT_NUMBER=$(POSTGRES_PORT) \
	SOFTHSM2_CONF=./ignore/softhsm/etc/softhsm/softhsm.conf \
	SOFTHSM_SO_PIN=1234 \
	SOFTHSM_PIN=5678 \
	go run cmd/main.go

##@ Stop and remove local docker container
.PHONY: docker-stop
docker-stop:
	docker rm -f backend || true

##@ Pretty
.PHONY: pretty
pretty: fmt
	npx prettier --write "**/*.yaml"

##@ Scan
.PHONY: scan
scan:
	trivy image $(IMG)