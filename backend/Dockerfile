# Global arguments
ARG DEBIAN_VERSION=trixie
ARG GO_VERSION=1.26
ARG PRIMUS_VERSION=2.6.2
ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.1-1778058333
ARG RUNTIME_GID=4001

# Stage 1: Build the Go server binary
FROM golang:${GO_VERSION} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG ENTERPRISE

WORKDIR /workspace

# Install cross-compilation tools for CGO
RUN apt-get update && apt-get install -y \
  gcc-aarch64-linux-gnu \
  libc6-dev-arm64-cross && \
  rm -rf /var/lib/apt/lists/*

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/main.go cmd/main.go
COPY internal/ internal/
COPY migrations/ migrations/
COPY swagger/ swagger/

# Build with proper cross-compilation setup
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
      export CC=aarch64-linux-gnu-gcc; \
    fi && \
    CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o server \
    -ldflags "-X main.version=${VERSION} -X main.enterprise=${ENTERPRISE}" cmd/main.go

# Stage 2: Prepare Primus files
FROM debian:${DEBIAN_VERSION} AS primus
ARG TARGETOS
ARG TARGETARCH
ARG PRIMUS_VERSION
ARG ENTERPRISE

WORKDIR /primus
# Only copy and extract if ENTERPRISE=true
RUN if [ "${ENTERPRISE}" = "true" ]; then \
      apt-get update && apt-get install -y unzip tar; \
    fi
COPY ./primus/PrimusAPI_PKCS11-v${PRIMUS_VERSION}.zip* ./
RUN if [ "${ENTERPRISE}" = "true" ] && [ -f "PrimusAPI_PKCS11-v${PRIMUS_VERSION}.zip" ]; then \
      unzip -q PrimusAPI_PKCS11-v${PRIMUS_VERSION}.zip && \
      case "${TARGETOS:-linux}/${TARGETARCH}" in \
        "linux/amd64") \
          tar -xzf ./PrimusAPI_PKCS11-X-${PRIMUS_VERSION}-rhel8-x86_64.tar.gz -C /usr/local ;; \
        "linux/arm64") \
          tar -xzf ./PrimusAPI_PKCS11-X-${PRIMUS_VERSION}-rhel8-aarch64.tar.gz -C /usr/local ;; \
        *) \
          echo "Primus not available for ${TARGETOS:-linux}/${TARGETARCH}" ;; \
      esac && \
      rm PrimusAPI_PKCS11-v${PRIMUS_VERSION}.zip; \
    else \
      # create an empty /usr/local/primus directory to avoid errors in the final stage \
      mkdir -p /usr/local/primus; \
    fi

# Stage 3: Install pkcs11-tool and softhsm2-util
FROM fedora AS tools
RUN dnf install -y opensc softhsm which findutils && \
    dnf clean all

RUN mkdir -p /fedora-tools/lib64 && \
    for b in /usr/bin/pkcs11-tool /usr/bin/softhsm2-util; do \
      ldd "$b" | awk '/=> \// { print $3 } /^\/.* / { print $1 }'; \
    done | sort -u | while read -r lib; do \
      case "$(basename "$lib")" in \
        libopensc.so*|libeac.so*) \
          cp -L "$lib" /fedora-tools/lib64/ ;; \
      esac; \
    done

# Final Stage: Create the runtime image
FROM registry.access.redhat.com/ubi${UBI_MAJOR_VERSION}/ubi-minimal:${UBI_VERSION}
ARG RUNTIME_GID

# Install shadow-utils for groupadd
RUN microdnf install -y shadow-utils && \
    microdnf clean all

# pkcs11-tool and softhsm2-util dependencies
COPY --from=tools /fedora-tools/lib64/libopensc.so* /lib64/
COPY --from=tools /fedora-tools/lib64/libeac.so* /lib64/
COPY --from=tools /lib64/pkcs11/ /lib64/pkcs11/
COPY --from=tools /lib64/softhsm/ /lib64/softhsm/
COPY --from=tools /usr/lib64/pkcs11/ /lib64/pkcs11/
COPY --from=tools /usr/lib64/softhsm/ /lib64/softhsm/
COPY --from=tools /usr/bin/pkcs11-tool /usr/bin/pkcs11-tool
COPY --from=tools /usr/bin/softhsm2-util /usr/bin/softhsm2-util

# Verify that all required shared libraries are present
RUN for b in pkcs11-tool softhsm2-util; do \
      echo "Checking shared libraries for $b:"; \
      ldd /usr/bin/$b | grep "not found" && \
      echo "Some libraries are missing for $b!" && exit 1 || echo "All libraries found for $b."; \
    done

# Primus files
COPY --from=primus /usr/local/primus /usr/local/primus
RUN chgrp -R ${RUNTIME_GID} /usr/local/primus && \
    chmod -R g+rwX /usr/local/primus

# Go server binary
COPY --from=builder /workspace/server /usr/bin/server

ENV PATH="/usr/local/primus/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/primus/lib"

USER 1001
CMD ["server"]