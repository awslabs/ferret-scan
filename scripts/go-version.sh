#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Go version management script
# Ensures consistent Go version across all environments

set -euo pipefail

# Read Go version from .go-version file
GO_VERSION_FILE=".go-version"
DOCKERFILE_GO="Dockerfile"
MAKEFILE="Makefile"

if [[ ! -f "$GO_VERSION_FILE" ]]; then
    echo "Error: $GO_VERSION_FILE not found"
    exit 1
fi

GO_VERSION=$(cat "$GO_VERSION_FILE" | tr -d '\n\r')

echo "Go version from $GO_VERSION_FILE: $GO_VERSION"

# Function to update go.mod
update_go_mod() {
    if [[ -f "go.mod" ]]; then
        # Extract major.minor version for go.mod (e.g., 1.24.1 -> 1.24)
        GO_MOD_VERSION=$(echo "$GO_VERSION" | cut -d. -f1,2)
        echo "Updating go.mod to use Go $GO_MOD_VERSION"

        # Update go.mod file
        if command -v go >/dev/null 2>&1; then
            go mod edit -go="$GO_MOD_VERSION"
            echo "✅ Updated go.mod"
        else
            echo "⚠️  Go not installed, skipping go.mod update"
        fi
    fi
}

# Function to check current Go version
check_go_version() {
    if command -v go >/dev/null 2>&1; then
        CURRENT_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
        echo "Current Go version: $CURRENT_VERSION"

        if [[ "$CURRENT_VERSION" != "$GO_VERSION" ]]; then
            echo "⚠️  Version mismatch!"
            echo "   Expected: $GO_VERSION"
            echo "   Current:  $CURRENT_VERSION"
            echo ""
            echo "Consider using a Go version manager like:"
            echo "  - g: https://github.com/stefanmaric/g"
            echo "  - gvm: https://github.com/moovweb/gvm"
            echo "  - Or download from: https://golang.org/dl/"
            return 1
        else
            echo "✅ Go version matches"
        fi
    else
        echo "⚠️  Go not installed"
        return 1
    fi
}

# Function to update Dockerfile
update_dockerfile() {
    if [[ -f "Dockerfile" ]]; then
        echo "Updating Dockerfile to use Go $GO_VERSION"

        # Update golang base image
        sed -i.bak "s|FROM golang:[0-9]\+\.[0-9]\+\.[0-9]\+-alpine|FROM golang:${GO_VERSION}-alpine|g" Dockerfile

        if [[ $? -eq 0 ]]; then
            echo "✅ Updated Dockerfile"
            rm -f Dockerfile.bak
        else
            echo "⚠️  Failed to update Dockerfile"
        fi
    fi
}

# Function to update GitLab CI
update_gitlab_ci() {
    if [[ -f ".gitlab-ci.yml" ]]; then
        echo "Updating .gitlab-ci.yml to use Go $GO_VERSION"

        # Update GO_VERSION variable
        sed -i.bak "s|GO_VERSION: \"[0-9]\+\.[0-9]\+\.[0-9]\+\"|GO_VERSION: \"${GO_VERSION}\"|g" .gitlab-ci.yml

        # Update GO_DOCKER_IMAGE variable
        sed -i.bak "s|GO_DOCKER_IMAGE: \"golang:[0-9]\+\.[0-9]\+\.[0-9]\+-alpine\"|GO_DOCKER_IMAGE: \"golang:${GO_VERSION}-alpine\"|g" .gitlab-ci.yml

        if [[ $? -eq 0 ]]; then
            echo "✅ Updated .gitlab-ci.yml"
            rm -f .gitlab-ci.yml.bak
        else
            echo "⚠️  Failed to update .gitlab-ci.yml"
        fi
    fi
}

# Function to update GitHub workflows
update_github_workflows() {
    if [[ -d ".github/workflows" ]]; then
        echo "Updating GitHub workflows to use Go $GO_VERSION"

        for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
            if [[ -f "$workflow" ]]; then
                # Update go-version in setup-go actions
                sed -i.bak "s|go-version: '[0-9]\+\.[0-9]\+\(\.[0-9]\+\)\?'|go-version: '${GO_VERSION}'|g" "$workflow"

                if [[ $? -eq 0 ]]; then
                    echo "✅ Updated $(basename "$workflow")"
                    rm -f "${workflow}.bak"
                else
                    echo "⚠️  Failed to update $(basename "$workflow")"
                fi
            fi
        done
    fi
}

# Function to generate Docker image tag
docker_image_tag() {
    echo "golang:${GO_VERSION}-alpine"
}

# Function to generate CI variables
ci_variables() {
    echo "GO_VERSION=$GO_VERSION"
    echo "GO_DOCKER_IMAGE=golang:${GO_VERSION}-alpine"
}

# Main command handling
case "${1:-check}" in
    "check")
        check_go_version
        ;;
    "update-mod")
        update_go_mod
        ;;
    "docker-tag")
        docker_image_tag
        ;;
    "ci-vars")
        ci_variables
        ;;
    "all")
        check_go_version
        update_go_mod
        update_dockerfile
        update_gitlab_ci
        update_github_workflows
        ;;
    *)
        echo "Usage: $0 {check|update-mod|docker-tag|ci-vars|all}"
        echo ""
        echo "Commands:"
        echo "  check      - Check if current Go version matches .go-version"
        echo "  update-mod - Update go.mod with version from .go-version"
        echo "  docker-tag - Output Docker image tag for CI"
        echo "  ci-vars    - Output CI environment variables"
        echo "  all        - Run check and update all files (go.mod, Dockerfile, CI configs)"
        exit 1
        ;;
esac
