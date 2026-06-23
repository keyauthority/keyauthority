ARG KC_VERSION=26.5.0
ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.2-1780550715
ARG RUNTIME_GID=4001

# Stage 1: Build Java agent (runtime bytecode patch)
FROM maven:3.9.16-eclipse-temurin-21 AS agent-build
WORKDIR /agent
COPY agent/pom.xml /agent/pom.xml
COPY agent/src /agent/src
RUN mvn -q -DskipTests package

# Stage 2: Prepare Keyauthority theme
FROM alpine:3.22 AS theme
RUN apk add --no-cache unzip
COPY theming/keyauthority-theme/dist_keycloak/keycloak-theme-for-kc-all-other-versions.jar /tmp/keycloak-themes.jar
RUN unzip /tmp/keycloak-themes.jar -d /tmp/keycloak-themes

# Stage 3: Keycloak builder
FROM quay.io/keycloak/keycloak:${KC_VERSION} AS builder
ARG THEME_NAME=keyauthority
COPY --chmod=777 --chown=root:root --from=theme \
    /tmp/keycloak-themes/theme/keyauthority-theme/login/ /opt/keycloak/themes/${THEME_NAME}/login/

# Build optimized image
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV LANG=en_US.UTF-8
RUN /opt/keycloak/bin/kc.sh build

# Remove unnecessary database drivers to reduce CVEs
RUN find /opt/keycloak/lib -name "*mssql*" -delete
RUN find /opt/keycloak/lib -name "*mysql*" -delete
RUN find /opt/keycloak/lib -name "*oracle*" -delete
RUN find /opt/keycloak/lib -name "*mariadb*" -delete
RUN find /opt/keycloak/lib -name "*h2database*" -delete

# Final Stage: Runtime image
FROM registry.access.redhat.com/ubi${UBI_MAJOR_VERSION}/ubi-minimal:${UBI_VERSION}
ARG RUNTIME_GID

# Install Java
RUN microdnf install -y java-25-openjdk-headless && \
    microdnf clean all

# Copy optimized Keycloak
COPY --from=builder /opt/keycloak /opt/keycloak

# Copy Java agent
COPY --from=agent-build /agent/target/keycloak-multiaudience-agent-1.0.0.jar /opt/keycloak/keycloak-multiaudience-agent.jar

RUN chgrp -R ${RUNTIME_GID} /opt/keycloak && \
    chmod -R g+rwX /opt/keycloak

ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV LANG=en_US.UTF-8
ENV JAVA_OPTS_APPEND="-javaagent:/opt/keycloak/keycloak-multiaudience-agent.jar --add-opens java.base/java.lang=ALL-UNNAMED"

EXPOSE 8080 8443 9000
USER 1001
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]