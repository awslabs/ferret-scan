#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Install Go-native release tools
# GoReleaser for automated releases

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

echo "🚀 Installing Go-native release tools..."
echo "======================================"

# Check if Go is installed
if ! command -v go >/dev/null 2>&1; then
    print_error "Go is not installed. Please install Go first."
    exit 1
fi

print_status "Go is installed: $(go version)"

# Install GoReleaser
echo ""
echo "📦 Installing GoReleaser..."
if command -v goreleaser >/dev/null 2>&1; then
    print_status "GoReleaser already installed: $(goreleaser --version | head -1)"
else
    # Detect OS and install accordingly
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS - use Homebrew
        if command -v brew >/dev/null 2>&1; then
            echo "Installing GoReleaser via Homebrew..."
            brew install goreleaser/tap/goreleaser
            print_status "GoReleaser installed via Homebrew"
        else
            print_warning "Homebrew not found, trying go install..."
            go install github.com/goreleaser/goreleaser@latest
            print_status "GoReleaser installed via go install"
        fi
    else
        # Linux/other - use official installer
        if curl -sfL https://goreleaser.com/static/run | sh -s -- --version >/dev/null 2>&1; then
            print_status "GoReleaser installed successfully"
        else
            print_warning "GoReleaser installer failed, trying go install..."
            go install github.com/goreleaser/goreleaser@latest
            print_status "GoReleaser installed via go install"
        fi
    fi
fi

# Verify installations
echo ""
echo "🔍 Verifying installations..."

if command -v goreleaser >/dev/null 2>&1; then
    print_status "GoReleaser: $(goreleaser --version | head -1)"
else
    print_error "GoReleaser installation failed"
    exit 1
fi

# Test GoReleaser configuration
echo ""
echo "🧪 Testing GoReleaser configuration..."
if [ -f ".goreleaser.yml" ]; then
    if goreleaser check; then
        print_status "GoReleaser configuration is valid"
    else
        print_warning "GoReleaser configuration has issues (check output above)"
    fi
else
    print_warning ".goreleaser.yml not found in current directory"
fi

echo ""
print_status "Installation completed!"
echo ""
echo "📋 Next steps:"
echo "1. Test snapshot build: make release-snapshot"
echo "2. Add your CHANGELOG.md entry by hand, in the PR that makes the change"
echo "3. Create a release tag to trigger full release"
echo ""
echo "💡 Useful commands:"
echo "  goreleaser build --snapshot --clean  # Build without releasing"
echo "  goreleaser check                     # Validate configuration"
