#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Comprehensive version synchronization script
# Ensures Go version consistency across all project files

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Files to check/update
GO_VERSION_FILE=".go-version"
GO_MOD_FILE="go.mod"
GITLAB_CI_FILE=".gitlab-ci.yml"
DOCKERFILE="Dockerfile"
README_FILE="README.md"

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ️${NC} $1"
}

# Read Go version from .go-version
if [[ ! -f "$GO_VERSION_FILE" ]]; then
    print_error "$GO_VERSION_FILE not found"
    exit 1
fi

GO_VERSION=$(cat "$GO_VERSION_FILE" | tr -d '\n\r')
GO_MAJOR_MINOR=$(echo "$GO_VERSION" | cut -d. -f1,2)

print_info "Target Go version: $GO_VERSION"
print_info "Go major.minor: $GO_MAJOR_MINOR"

# Check current Go installation
check_local_go() {
    if command -v go >/dev/null 2>&1; then
        CURRENT_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
        if [[ "$CURRENT_VERSION" == "$GO_VERSION" ]]; then
            print_status "Local Go version matches: $CURRENT_VERSION"
        else
            print_warning "Local Go version mismatch:"
            echo "  Expected: $GO_VERSION"
            echo "  Current:  $CURRENT_VERSION"
        fi
    else
        print_warning "Go not installed locally"
    fi
}

# Update go.mod
update_go_mod() {
    if [[ -f "$GO_MOD_FILE" ]]; then
        print_info "Updating $GO_MOD_FILE..."

        # Read current version from go.mod
        CURRENT_GO_MOD=$(grep "^go " "$GO_MOD_FILE" | awk '{print $2}')

        if [[ "$CURRENT_GO_MOD" == "$GO_MAJOR_MINOR" ]]; then
            print_status "$GO_MOD_FILE already up to date ($CURRENT_GO_MOD)"
        else
            # Update go.mod
            if command -v go >/dev/null 2>&1; then
                go mod edit -go="$GO_MAJOR_MINOR"
                print_status "Updated $GO_MOD_FILE: $CURRENT_GO_MOD → $GO_MAJOR_MINOR"
            else
                # Fallback: manual sed replacement
                sed -i.bak "s/^go .*/go $GO_MAJOR_MINOR/" "$GO_MOD_FILE"
                rm -f "$GO_MOD_FILE.bak"
                print_status "Updated $GO_MOD_FILE: $CURRENT_GO_MOD → $GO_MAJOR_MINOR (manual)"
            fi
        fi
    else
        print_warning "$GO_MOD_FILE not found"
    fi
}

# Update GitLab CI
update_gitlab_ci() {
    if [[ -f "$GITLAB_CI_FILE" ]]; then
        print_info "Updating $GITLAB_CI_FILE..."

        # Check if variables section exists
        if grep -q "GO_VERSION:" "$GITLAB_CI_FILE"; then
            # Update existing GO_VERSION
            sed -i.bak "s/GO_VERSION: .*/GO_VERSION: \"$GO_VERSION\"/" "$GITLAB_CI_FILE"
            print_status "Updated GO_VERSION in $GITLAB_CI_FILE"
        else
            print_warning "GO_VERSION variable not found in $GITLAB_CI_FILE"
        fi

        if grep -q "GO_DOCKER_IMAGE:" "$GITLAB_CI_FILE"; then
            # Update existing GO_DOCKER_IMAGE
            sed -i.bak "s/GO_DOCKER_IMAGE: .*/GO_DOCKER_IMAGE: \"golang:$GO_VERSION-alpine\"/" "$GITLAB_CI_FILE"
            print_status "Updated GO_DOCKER_IMAGE in $GITLAB_CI_FILE"
        else
            print_warning "GO_DOCKER_IMAGE variable not found in $GITLAB_CI_FILE"
        fi

        # Clean up backup file
        rm -f "$GITLAB_CI_FILE.bak"
    else
        print_warning "$GITLAB_CI_FILE not found"
    fi
}

# Update Dockerfile if it exists
update_dockerfile() {
    if [[ -f "$DOCKERFILE" ]]; then
        print_info "Updating $DOCKERFILE..."

        # Update FROM golang:x.x.x-alpine lines
        if grep -q "FROM golang:" "$DOCKERFILE"; then
            sed -i.bak "s/FROM golang:[0-9]\+\.[0-9]\+\.[0-9]\+-alpine/FROM golang:$GO_VERSION-alpine/g" "$DOCKERFILE"
            sed -i.bak "s/FROM golang:[0-9]\+\.[0-9]\+\.[0-9]\+/FROM golang:$GO_VERSION/g" "$DOCKERFILE"
            print_status "Updated Dockerfile Go version"
            rm -f "$DOCKERFILE.bak"
        else
            print_info "No Go base image found in $DOCKERFILE"
        fi
    else
        print_info "$DOCKERFILE not found (optional)"
    fi
}

# Update README if it contains Go version references
update_readme() {
    if [[ -f "$README_FILE" ]]; then
        print_info "Checking $README_FILE for Go version references..."

        # Look for common Go version patterns in README
        if grep -q "Go [0-9]\+\.[0-9]\+\.[0-9]\+" "$README_FILE" || \
           grep -q "golang:[0-9]\+\.[0-9]\+\.[0-9]\+" "$README_FILE"; then
            print_warning "Found Go version references in $README_FILE"
            print_info "Please manually update README.md with Go $GO_VERSION"
        else
            print_info "No Go version references found in $README_FILE"
        fi
    else
        print_info "$README_FILE not found (optional)"
    fi
}

# Generate summary report
generate_report() {
    echo ""
    echo "📊 Version Synchronization Report"
    echo "=================================="
    echo "Target Go Version: $GO_VERSION"
    echo ""

    # Check each file
    if [[ -f "$GO_MOD_FILE" ]]; then
        GO_MOD_VERSION=$(grep "^go " "$GO_MOD_FILE" | awk '{print $2}')
        echo "go.mod: $GO_MOD_VERSION"
    fi

    if [[ -f "$GITLAB_CI_FILE" ]]; then
        if grep -q "GO_VERSION:" "$GITLAB_CI_FILE"; then
            CI_VERSION=$(grep "GO_VERSION:" "$GITLAB_CI_FILE" | sed 's/.*GO_VERSION: *"\([^"]*\)".*/\1/')
            echo "GitLab CI: $CI_VERSION"
        fi
    fi

    if [[ -f "$DOCKERFILE" ]]; then
        if grep -q "FROM golang:" "$DOCKERFILE"; then
            DOCKER_VERSION=$(grep "FROM golang:" "$DOCKERFILE" | head -1 | sed 's/.*golang:\([0-9.]*\).*/\1/')
            echo "Dockerfile: $DOCKER_VERSION"
        fi
    fi

    echo ""
    print_info "Next steps:"
    echo "1. Review changes: git diff"
    echo "2. Test build: make build"
    echo "3. Commit changes: git add . && git commit -m 'chore: sync Go version to $GO_VERSION'"
}

# Main execution
main() {
    echo "🔄 Go Version Synchronization"
    echo "============================="
    echo ""

    check_local_go
    echo ""

    update_go_mod
    update_gitlab_ci
    update_dockerfile
    update_readme

    generate_report
}

# Run main function
main "$@"
