ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.1-1766033715

FROM registry.access.redhat.com/ubi${UBI_MAJOR_VERSION}/ubi-minimal:${UBI_VERSION}

# Install packages
RUN microdnf install -y \
    ca-certificates \
    nc \
    jq \
    openssl \
    postgresql \
    && microdnf clean all

USER 1001