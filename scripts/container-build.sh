#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Script to build container image with proper version information
# Supports both Docker and Finch (AWS's container runtime)

set -e

# Detect available container runtime
CONTAINER_CMD=""
if command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
    echo "Using Docker as container runtime"
elif command -v finch >/dev/null 2>&1; then
    CONTAINER_CMD="finch"
    echo "Using Finch as container runtime"
else
    echo "Error: Neither Docker nor Finch found. Please install one of them:"
    echo "  Docker: https://docs.docker.com/get-docker/"
    echo "  Finch: https://github.com/runfinch/finch"
    exit 1
fi

# Get version information
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Get version from git tags, fallback to development version
if [ -z "$VERSION" ]; then
    # Try to get version from git describe
    if ! VERSION=$(git describe --tags --exact-match HEAD 2>/dev/null); then
        if ! VERSION=$(git describe --tags 2>/dev/null); then
            # No tags found, use development version
            VERSION="0.0.0-development"
        fi
    fi
fi

echo "Building container image with version information:"
echo "  Version: $VERSION"
echo "  Git Commit: $GIT_COMMIT"
echo "  Build Date: $BUILD_DATE"
echo "  Container Runtime: $CONTAINER_CMD"

# Build the container image with build args
$CONTAINER_CMD build \
    --build-arg VERSION="$VERSION" \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    --build-arg BUILD_DATE="$BUILD_DATE" \
    -t ferret-scan:latest \
    -t ferret-scan:$VERSION \
    .

echo "Container image built successfully with $CONTAINER_CMD!"
echo "Run with: $CONTAINER_CMD run --rm -p 8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --web"
echo "Note: The --web flag starts the web interface mode. Refer to documentation for more details."