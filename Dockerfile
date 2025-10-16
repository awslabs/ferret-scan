# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Ultra-minimal scratch Dockerfile without AWS SDK
# Target: Absolute smallest possible image (~5-10MB)

# Builder stage
FROM public.ecr.aws/docker/library/golang:1.25.1-alpine AS builder

# Install minimal build dependencies
# Add ca-certificates back if you uncomment the COPY line below
RUN apk add --no-cache git ca-certificates

# Set Go environment - critical for module downloads
ENV GOPROXY=direct
RUN go env -w GOPROXY=direct

# Create app directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies with memory optimization
RUN go mod download

# Copy source code
COPY . .

# Note: No entrypoint script needed for scratch image

# Build arguments
ARG VERSION=0.0.0-development
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Build ultra-minimal static binary (single executable)
# -s -w removes symbol table and debug info
# -extldflags '-static' forces static linking
# CGO_ENABLED=0 removes C dependencies
# Memory optimization: limit parallel builds and clean cache after
RUN CGO_ENABLED=0 GOOS=linux GOMAXPROCS=2 go build \
    -a -installsuffix cgo -p 2 \
    -ldflags="-s -w -extldflags '-static' \
              -X 'ferret-scan/internal/version.Version=${VERSION}' \
              -X 'ferret-scan/internal/version.GitCommit=${GIT_COMMIT}' \
              -X 'ferret-scan/internal/version.BuildDate=${BUILD_DATE}'" \
    -o ferret-scan cmd/main.go && \
    go clean -cache -testcache -modcache

# Create directory structure and user for scratch image
# The scratch base image is completely empty, so we need to create everything manually
RUN mkdir -p /scratch-fs/tmp && chmod 1777 /scratch-fs/tmp
RUN mkdir -p /scratch-fs/home/ferret/.ferret-scan && chmod 755 /scratch-fs/home/ferret/.ferret-scan
RUN mkdir -p /scratch-fs/home/ferret/tmp && chmod 755 /scratch-fs/home/ferret/tmp
RUN mkdir -p /scratch-fs/etc

# Create user files for scratch image (ferret user with UID 1000)
RUN echo 'ferret:x:1000:1000:ferret:/home/ferret:/bin/sh' > /scratch-fs/etc/passwd
RUN echo 'ferret:x:1000:' > /scratch-fs/etc/group

# Set proper ownership for ferret user directories
RUN chown -R 1000:1000 /scratch-fs/home/ferret

# Final stage - scratch (absolute minimum)
FROM scratch

# Copy CA certificates for HTTPS calls (uncomment if needed for AWS SDK or external APIs)
# COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Create necessary directories and user files in scratch image
# Copy the directory structure we created in the builder stage
COPY --from=builder /scratch-fs/tmp /tmp
COPY --from=builder /scratch-fs/home/ferret /home/ferret
COPY --from=builder /scratch-fs/etc/passwd /etc/passwd
COPY --from=builder /scratch-fs/etc/group /etc/group

# Copy static binary (single executable)
COPY --from=builder /app/ferret-scan /ferret-scan

# Note: No entrypoint script needed - using direct binary execution

# Copy web template (required for web UI)
COPY --from=builder /app/web/template.html /web/template.html

# Copy all documentation for web UI access
COPY --from=builder /app/docs /docs

# Minimal environment variables
ENV FERRET_CONTAINER_MODE=true
ENV FERRET_QUIET_MODE=true
# Use ferret user's temp directory instead of /tmp
ENV TMPDIR=/home/ferret/tmp
# Uncomment if you enable CA certificates above
# ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Switch to ferret user (UID 1000)
USER ferret

# Expose port
EXPOSE 8080

# Default to CLI mode - users specify their own arguments
ENTRYPOINT ["/ferret-scan"]

# Build: docker build -t ferret-scan .
# Run CLI Mode: docker run --rm -v $(pwd):/data ferret-scan --file /data/sample.txt
# Run Web Mode: docker run --rm -p 8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --web --port 8080
# Run Custom Web Port: docker run --rm -p 9000:9000 ferret-scan --web --port 9000
# Run Help: docker run --rm ferret-scan --help
# Size: Expected ~5-10MB (single executable, no AWS SDK bloat)