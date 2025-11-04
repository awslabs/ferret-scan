#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


set -e

echo "Building ferret-scan Python package..."

# Clean previous builds
rm -rf build/ dist/ -- *.egg-info/

# Create binaries directory
mkdir -p ferret_scan/binaries

# Build Go binaries for different platforms
echo "Building Go binaries..."

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_DIR="$SCRIPT_DIR/ferret_scan/binaries"

echo "Project root: $PROJECT_ROOT"
echo "Binary dir: $BINARY_DIR"

# Build from project root
cd "$PROJECT_ROOT"

# Get version information - respect SETUPTOOLS_SCM_PRETEND_VERSION if set
if [[ -n "$SETUPTOOLS_SCM_PRETEND_VERSION" ]]; then
    VERSION="$SETUPTOOLS_SCM_PRETEND_VERSION"
    echo "Using explicit version from SETUPTOOLS_SCM_PRETEND_VERSION: $VERSION"
else
    VERSION=$(git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo "1.1.0-development")
    echo "Using Git-derived version: $VERSION"
fi

GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "Building with version: $VERSION"
echo "Git commit: $GIT_COMMIT"
echo "Build date: $BUILD_DATE"

# Set up ldflags with version information
LDFLAGS="-s -w -X 'ferret-scan/internal/version.Version=$VERSION' -X 'ferret-scan/internal/version.GitCommit=$GIT_COMMIT' -X 'ferret-scan/internal/version.BuildDate=$BUILD_DATE'"

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$BINARY_DIR/ferret-scan-linux-amd64" ./cmd/main.go

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$BINARY_DIR/ferret-scan-linux-arm64" ./cmd/main.go

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$BINARY_DIR/ferret-scan-darwin-amd64" ./cmd/main.go

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$BINARY_DIR/ferret-scan-darwin-arm64" ./cmd/main.go

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$BINARY_DIR/ferret-scan-windows-amd64.exe" ./cmd/main.go

# Windows ARM64
GOOS=windows GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$BINARY_DIR/ferret-scan-windows-arm64.exe" ./cmd/main.go

# Return to python-package directory
cd "$SCRIPT_DIR"

echo "Built binaries:"
ls -la ferret_scan/binaries/

# Build Python package
echo "Building Python package..."
python3 -m pip install --upgrade build
python3 -m build

echo "Package built successfully!"
echo "Files created:"
ls -la dist/

echo ""
echo "To install locally for testing:"
echo "  pip install dist/ferret_scan-1.2.1-py3-none-any.whl"
echo ""
echo "To publish to PyPI:"
echo "  python3 -m pip install --upgrade twine"
echo "  python3 -m twine upload dist/*"
