ARG UBI_MAJOR_VERSION=10
ARG UBI_VERSION=10.2-1784094212
ARG RUNTIME_GID=4001

FROM node:trixie AS builder
ARG VERSION

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN echo "export const appVersion = \"${VERSION}\";" > src/version.js
ENV NODE_OPTIONS="--localstorage-file=/tmp/localstorage"
RUN npm run build

# Final Stage: Serve with nginx
FROM registry.access.redhat.com/ubi${UBI_MAJOR_VERSION}/ubi-minimal:${UBI_VERSION}
ARG RUNTIME_GID

# Install nginx
RUN microdnf install -y nginx && \
    microdnf clean all

# Copy built frontend from builder stage, nginx config, and set permissions
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
RUN DIRS="/usr/share/nginx/html /var/log/nginx /var/lib/nginx /tmp/nginx" && \
    mkdir -p $DIRS && \
    chgrp -R ${RUNTIME_GID} $DIRS && \
    chmod -R g+rwX $DIRS

EXPOSE 8080
HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1
USER 1001
CMD ["nginx", "-g", "daemon off;"]