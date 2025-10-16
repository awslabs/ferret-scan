#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Initialize version tagging for the project
# Creates the initial v0.1.0 tag if no tags exist

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

echo "🏷️  Version Initialization"
echo "========================="

# Check if any tags exist
if git tag -l | grep -q "^v"; then
    EXISTING_TAG=$(git describe --tags --abbrev=0)
    print_warning "Tags already exist in this repository"
    print_info "Latest tag: $EXISTING_TAG"
    echo ""
    print_info "If you want to create a new release, use:"
    print_info "  ./scripts/create-release.sh"
    exit 0
fi

print_info "No version tags found in repository"
print_info "Creating initial version tag: v0.1.0"

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    print_warning "You have uncommitted changes:"
    git status --short
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Initialization cancelled"
        exit 0
    fi
fi

# Create initial tag
print_info "Creating initial tag v0.1.0..."
git tag -a v0.1.0 -m "Initial release v0.1.0

This is the first tagged version of Ferret Scan.
Automated versioning and releases are now enabled."

print_status "Tag v0.1.0 created locally"

# Ask if user wants to push
echo ""
read -p "Push tag to origin? (Y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    print_info "Tag created locally but not pushed"
    print_info "Push manually with: git push origin v0.1.0"
    exit 0
fi

# Push tag
print_info "Pushing tag to origin..."
git push origin v0.1.0

print_status "🚀 Initial tag v0.1.0 pushed successfully!"
print_info "Automated versioning is now active"

echo ""
print_info "Next steps:"
echo "  • Future commits to main/master will automatically create new versions"
echo "  • Use conventional commit messages for automatic version bumping:"
echo "    - feat: new feature (minor version bump)"
echo "    - fix: bug fix (patch version bump)"
echo "    - BREAKING CHANGE: breaking change (major version bump)"
echo "  • Manual releases: ./scripts/create-release.sh [version]"
echo "  • Check version status: ./scripts/version-helper.sh status"