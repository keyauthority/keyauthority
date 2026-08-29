ARG DEBIAN_VERSION=trixie
ARG GO_VERSION=1.27
ARG PRIMUS_VERSION=2.7.0
ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.2-1785778687
ARG RUNTIME_GID=4001

# Stage 1: Build the Go server binary
FROM golang:${GO_VERSION} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION

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
COPY cmd/ cmd/
COPY internal/ internal/
COPY migrations/ migrations/
COPY swagger/ swagger/

# Build with proper cross-compilation setup
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
      export CC=aarch64-linux-gnu-gcc; \
    fi && \
    CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o server \
    -ldflags "-X main.version=${VERSION}" cmd/server/main.go

# Stage 2: Install pkcs11-tool and softhsm2-util
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

# Go server binary
COPY --from=builder /workspace/server /usr/bin/server

ENV PATH="/usr/local/primus/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/primus/lib"

EXPOSE 8081 8443 9000
USER 1001
CMD ["server"]