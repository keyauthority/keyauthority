IMG_REPOSITORY ?= keycloak
CONTAINER_NAME ?= keycloak

# further build arguments
KC_VERSION=$(shell echo $(VERSION) | cut -d'-' -f1)

# Agent build settings
AGENT_DIR ?= agent
AGENT_JAR ?= $(AGENT_DIR)/target/multiaudience-agent.jar

# SPI build settings
SPI_DIR ?= providers/custom-jwt-ag
SPI_JAR ?= $(SPI_DIR)/target/custom-jwt-ag.jar

include ../common.mk

.PHONY: all
all: docker-buildx

##@ Build

.PHONY: agent-build
agent-build: ## Build Java agent jar used by Dockerfile
	cd $(AGENT_DIR) && mvn -B -ntp -DskipTests package

.PHONY: agent-clean
agent-clean: ## Clean Java agent build artifacts
	cd $(AGENT_DIR) && mvn -q clean

.PHONY: spi-build
spi-build: ## Build Java SPI jar used by Dockerfile
	cd $(SPI_DIR) && mvn -B -ntp -DskipTests package

.PHONY: spi-clean
spi-clean: ## Clean Java SPI build artifacts
	cd $(SPI_DIR) && mvn -q clean

.PHONY: docker-build
docker-build: agent-build spi-build keycloakify-prep keycloakify-build-theme ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg KC_VERSION=$(KC_VERSION) -t $(IMG) .

# Extend the generic docker-buildx from common.mk with extra prerequisites
# and the custom build-arg, without redefining its recipe.
docker-buildx: BUILD_ARGS = --build-arg KC_VERSION=$(KC_VERSION)
docker-buildx: keycloakify-prep keycloakify-build-theme

##@ Create database
POSTGRES_DB ?= keycloak
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
		-e KC_LOG_LEVEL=info \
		-e KC_DB_USERNAME=$(POSTGRES_USER) \
		-e KC_DB_PASSWORD=$(POSTGRES_PASSWORD) \
		-e KC_DB_URL=jdbc:postgresql://host.docker.internal:$(POSTGRES_PORT)/$(POSTGRES_DB) \
		$(IMG)

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
	# npx prettier --write "agent/pom.xml" --plugin @prettier/plugin-xml
	# npx prettier --write "agent/src/**/*.java" --plugin prettier-plugin-java