# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Ultra-minimal scratch Dockerfile without AWS SDK
# Target: Absolute smallest possible image (~5-10MB)

# Builder stage
# Pinned to digest for supply-chain integrity (TM-10). The trailing tag
# is informational; the @sha256:... digest is what determines what's
# pulled. To update, run:
#   crane digest public.ecr.aws/docker/library/golang:1.27.3-alpine
# or use `docker manifest inspect` and replace both the tag and digest.
# Keep in sync with .go-version; `make check-go-version` enforces it and
# `make sync-go-version` rewrites both the tag and the digest.
#
# History of why this pin moved, kept because each step was a security fix rather than
# housekeeping: 1.26.5 fixed CVE-2026-39822 (os symlink root escape) and CVE-2026-42505
# (crypto/tls ECH privacy leak); 1.26.6 fixed CVE-2026-46600 and CVE-2026-39821, both
# rated HIGH against the 1.26.5 stdlib and both flagged by Trivy on main.
FROM public.ecr.aws/docker/library/golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

# Install minimal build dependencies
# Add ca-certificates back if you uncomment the COPY line below
RUN apk add --no-cache git ca-certificates

# Module source. The default asks proxy.golang.org first and falls back to
# the upstream VCS host on ANY proxy error ('|' rather than ',', which only
# falls back on 404/410). This used to be GOPROXY=direct, which made every
# image build depend on every upstream host being up: on 2026-10-13 both
# dependabot PRs failed this build on an HTTP 502 from gopkg.in while the
# proxy, which the Go test jobs use, served the same modules fine.
#
# Integrity is unchanged either way: go.sum pins every module's hash, and
# GOSUMDB=sum.golang.org is left at its default.
#
# A network that blocks proxy.golang.org can still build, because '|direct'
# falls back. But if the block makes the lookup hang rather than fail, every
# module waits for that timeout, so pass the network's own setting instead:
#   --build-arg GOPROXY=direct
# scripts/container-build.sh does that automatically when the builder has
# set GOPROXY explicitly (go env -changed).
ARG GOPROXY=https://proxy.golang.org|direct
ENV GOPROXY=${GOPROXY}

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
              -X 'github.com/awslabs/ferret-scan/v2/internal/version.Version=${VERSION}' \
              -X 'github.com/awslabs/ferret-scan/v2/internal/version.GitCommit=${GIT_COMMIT}' \
              -X 'github.com/awslabs/ferret-scan/v2/internal/version.BuildDate=${BUILD_DATE}'" \
    -o ferret-scan ./cmd && \
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

# Create necessary directories and user files in scratch image.
#
# One COPY of the whole tree, so tmp/ and home/ferret/ arrive as copied entries and keep the mode
# and owner the builder gave them. COPY of a directory copies its contents, and the destination
# directory it creates for them is root:root 0755 whatever the source was: copied one by one,
# /tmp lost its 1777 and /home/ferret its 1000:1000, so user ferret could write neither (#776).
# --chmod/--chown on those COPYs is not a fix: measured under docker 25's BuildKit, --chmod=1777
# left /tmp at 0755, and --chown=1000:1000 handed /home itself to ferret as well.
COPY --from=builder /scratch-fs/ /

# Copy static binary (single executable with embedded web template)
COPY --from=builder /app/ferret-scan /ferret-scan

# Minimal environment variables
ENV FERRET_CONTAINER_MODE=true
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
