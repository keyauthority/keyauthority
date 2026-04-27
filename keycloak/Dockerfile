ARG KC_VERSION=26.5.0
ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.1-1766033715
ARG RUNTIME_GID=4001

# Stage 1: Prepare Keycloak theme
FROM debian:bookworm AS theme
COPY theming/keyauthority-theme/dist_keycloak/keycloak-theme-for-kc-all-other-versions.jar keycloak-themes.jar
RUN apt-get update && apt-get install -y unzip && \
    unzip keycloak-themes.jar -d keycloak-themes

# Stage 2: Builder
FROM quay.io/keycloak/keycloak:${KC_VERSION} AS builder
ARG THEME_NAME=keyauthority
COPY --chmod=777 --chown=root:root --from=theme \
    keycloak-themes/theme/keyauthority-theme/login/ opt/keycloak/themes/${THEME_NAME}/login/

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
