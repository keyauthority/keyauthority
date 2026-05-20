ARG PG_MAJOR=18
ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.2-1777462752
ARG RUNTIME_GID=4001

FROM registry.access.redhat.com/ubi${UBI_MAJOR_VERSION}/ubi-minimal:${UBI_VERSION}
ARG TARGETOS
ARG TARGETARCH
ARG UBI_MAJOR_VERSION
ARG PG_MAJOR
ARG RUNTIME_GID

# Install PostgreSQL
RUN case "${TARGETOS:-linux}/${TARGETARCH}" in \
      "linux/amd64") REPO_ARCH=x86_64 ;; \
      "linux/arm64") REPO_ARCH=aarch64 ;; \
      *) echo "Unsupported architecture: ${TARGETOS:-linux}/${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -sSL https://download.postgresql.org/pub/repos/yum/reporpms/EL-${UBI_MAJOR_VERSION}-${REPO_ARCH}/pgdg-redhat-repo-latest.noarch.rpm \
      -o /tmp/pgdg.rpm && \
    rpm -ivh /tmp/pgdg.rpm && \
    microdnf install -y \
      postgresql${PG_MAJOR} \
      postgresql${PG_MAJOR}-server \
      postgresql${PG_MAJOR}-contrib \
      nss_wrapper && \
    microdnf clean all && \
    rm -f /tmp/pgdg.rpm

# Set up the entrypoint script, user, group, and directories
COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    DIRS="/var/lib/postgresql /run/postgresql /usr/share/zoneinfo" && \
    mkdir -p $DIRS && \
    chgrp -R ${RUNTIME_GID} $DIRS && \
    chmod -R g+rwX $DIRS

ENV PG_MAJOR=${PG_MAJOR}
ENV PATH=/usr/pgsql-${PG_MAJOR}/bin:$PATH
ENV PGDATA=/var/lib/postgresql/data

ENTRYPOINT ["entrypoint.sh"]
STOPSIGNAL SIGINT
EXPOSE 5432
USER 1001
CMD ["postgres"]