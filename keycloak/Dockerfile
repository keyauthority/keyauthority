ARG KC_VERSION=26.5.0
ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.2-1780550715
ARG RUNTIME_GID=4001

# Stage 1: Build patched keycloak-services from source
FROM maven:3.9.16-eclipse-temurin-21 AS kc-src
ARG KC_VERSION
ARG JAVA_FILE=services/src/main/java/org/keycloak/services/clientpolicy/executor/SecureClientAuthenticationAssertionExecutor.java
RUN apt-get update && apt-get install -y \
    --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${KC_VERSION} https://github.com/keycloak/keycloak.git /src/keycloak
WORKDIR /src/keycloak

# Minimal patch: allow multiple audiences (https://github.com/keycloak/keycloak/pull/41133)
# Fail early if patch target is not found
RUN grep -q 'token.getAudience().length != 1' ${JAVA_FILE} || (echo "ERROR: Patch target not found" && exit 1)
# Apply patch to allow multiple audiences (reject only null/empty)
RUN sed -i 's/token.getAudience().length != 1/token.getAudience().length == 0/' ${JAVA_FILE}
# Build only services module with its dependencies (not full Keycloak)
RUN mvn -pl services -am -DskipTests -T 1C clean package

# Stage 2: Prepare Keyauthority theme
FROM alpine:3.22 AS theme
RUN apk add unzip
COPY theming/keyauthority-theme/dist_keycloak/keycloak-theme-for-kc-all-other-versions.jar keycloak-themes.jar
RUN unzip keycloak-themes.jar -d keycloak-themes

# Stage 3: Builder
FROM quay.io/keycloak/keycloak:${KC_VERSION} AS builder
ARG KC_VERSION
ARG THEME_NAME=keyauthority
COPY --chmod=777 --chown=root:root --from=theme \
    keycloak-themes/theme/keyauthority-theme/login/ /opt/keycloak/themes/${THEME_NAME}/login/

# Replace stock services jar with patched one
COPY --from=kc-src /src/keycloak/services/target/keycloak-services-${KC_VERSION}.jar \
    /opt/keycloak/lib/lib/main/keycloak-services-${KC_VERSION}.jar

# Set Keycloak environment variables
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV LANG=en_US.UTF-8

# Build optimized image
RUN /opt/keycloak/bin/kc.sh build

# Remove unnecessary database drivers to reduce CVEs
RUN find /opt/keycloak/lib -name "*mssql*" -delete
RUN find /opt/keycloak/lib -name "*mysql*" -delete
RUN find /opt/keycloak/lib -name "*oracle*" -delete
RUN find /opt/keycloak/lib -name "*mariadb*" -delete
RUN find /opt/keycloak/lib -name "*h2database*" -delete

# Final Stage: Create the runtime image
FROM registry.access.redhat.com/ubi${UBI_MAJOR_VERSION}/ubi-minimal:${UBI_VERSION}
ARG RUNTIME_GID

# Install Java
RUN microdnf install -y java-25-openjdk-headless && \
    microdnf clean all

# Copy Keycloak optimized build
COPY --from=builder /opt/keycloak /opt/keycloak
RUN chgrp -R ${RUNTIME_GID} /opt/keycloak && \
    chmod -R g+rwX /opt/keycloak

# Set Keycloak environment variables
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV LANG=en_US.UTF-8
ENV JAVA_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED"

EXPOSE 8080 8443 9000
USER 1001
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]
