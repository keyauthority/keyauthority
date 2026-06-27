ARG KC_VERSION=26.5.0
ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.2-1780550715
ARG RUNTIME_GID=4001

# Stage 1: Prepare Keyauthority theme
FROM alpine:3.22 AS theme
RUN apk add --no-cache unzip
COPY theming/keyauthority-theme/dist_keycloak/keycloak-theme-for-kc-all-other-versions.jar /tmp/keycloak-themes.jar
RUN unzip /tmp/keycloak-themes.jar -d /tmp/keycloak-themes

# Stage 2: Keycloak builder
FROM quay.io/keycloak/keycloak:${KC_VERSION} AS builder
ARG THEME_NAME=keyauthority

COPY --chmod=777 --chown=root:root --from=theme \
    /tmp/keycloak-themes/theme/keyauthority-theme/login/ /opt/keycloak/themes/${THEME_NAME}/login/

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

RUN microdnf install -y java-25-openjdk-headless && \
    microdnf clean all

COPY --from=builder /opt/keycloak /opt/keycloak
# Agent jar must be prebuilt
COPY agent/target/multiaudience-agent.jar /opt/keycloak/multiaudience-agent.jar

RUN chgrp -R ${RUNTIME_GID} /opt/keycloak && \
    chmod -R g+rwX /opt/keycloak

ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV LANG=en_US.UTF-8
ENV JAVA_OPTS_APPEND="-javaagent:/opt/keycloak/multiaudience-agent.jar --add-opens java.base/java.lang=ALL-UNNAMED"

EXPOSE 8080 8443 9000
USER 1001
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--optimized"]