#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Manual release creation script
# Usage: ./scripts/create-release.sh [version]

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

# Check if we're on main/master branch
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
    print_error "Must be on main or master branch to create releases"
    print_info "Current branch: $CURRENT_BRANCH"
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    print_error "You have uncommitted changes. Please commit or stash them first."
    git status --short
    exit 1
fi

# Get current version
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.1.0")
print_info "Current version: $LAST_TAG"

# Get commits since last tag
COMMITS=$(git log ${LAST_TAG}..HEAD --oneline --no-merges)
if [ -z "$COMMITS" ]; then
    print_warning "No new commits since last tag. Nothing to release."
    exit 0
fi

print_info "Commits since last tag:"
echo "$COMMITS" | head -10

# Determine version bump or use provided version
if [ -n "${1:-}" ]; then
    NEW_VERSION="$1"
    # Add 'v' prefix if not present
    if [[ ! "$NEW_VERSION" =~ ^v ]]; then
        NEW_VERSION="v$NEW_VERSION"
    fi
    print_info "Using provided version: $NEW_VERSION"
else
    # Auto-determine version bump
    if echo "$COMMITS" | grep -q "BREAKING CHANGE\|feat!\|fix!\|perf!"; then
        BUMP="major"
        print_info "🚨 Major version bump detected (breaking changes)"
    elif echo "$COMMITS" | grep -q "feat:"; then
        BUMP="minor"
        print_info "✨ Minor version bump detected (new features)"
    elif echo "$COMMITS" | grep -q "fix:\|perf:\|refactor:"; then
        BUMP="patch"
        print_info "🔧 Patch version bump detected (fixes/improvements)"
    else
        BUMP="patch"
        print_warning "No conventional commits found, defaulting to patch bump"
    fi

    # Calculate new version
    CURRENT_VERSION=${LAST_TAG#v}
    # Remove any pre-release suffixes
    CLEAN_VERSION=$(echo "$CURRENT_VERSION" | sed 's/-.*$//')

    if [[ "$CLEAN_VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
        MAJOR=${BASH_REMATCH[1]}
        MINOR=${BASH_REMATCH[2]}
        PATCH=${BASH_REMATCH[3]}
    else
        # Fallback for malformed versions
        MAJOR=0
        MINOR=1
        PATCH=0
    fi

    case $BUMP in
        major) NEW_VERSION="v$((MAJOR+1)).0.0" ;;
        minor) NEW_VERSION="v${MAJOR}.$((MINOR+1)).0" ;;
        patch) NEW_VERSION="v${MAJOR}.${MINOR}.$((PATCH+1))" ;;
    esac
fi

print_info "🎯 New version will be: $NEW_VERSION"

# Confirm with user
echo ""
read -p "Create and push tag $NEW_VERSION? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Release cancelled"
    exit 0
fi

# Create annotated tag
CHANGELOG_ENTRY=$(echo "$COMMITS" | head -10)
git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION

Changes in this release:
$CHANGELOG_ENTRY"

print_status "Tag $NEW_VERSION created locally"

# Push tag
print_info "Pushing tag to origin..."
git push origin "$NEW_VERSION"

print_status "🚀 Tag $NEW_VERSION pushed successfully!"
print_info "GitLab CI will now build and release automatically"
print_info "Monitor progress at: https://code.aws.dev/personal_projects/alias_a/adifabio/Ferret-Scan/-/pipelines"

echo ""
print_info "Release process initiated! The following will happen automatically:"
echo "  1. GitLab CI will detect the new tag"
echo "  2. GoReleaser will build binaries for Linux and macOS"
echo "  3. Release will be created with changelog"
echo "  4. Binaries will be attached to the release"
