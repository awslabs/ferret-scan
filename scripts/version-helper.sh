#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Version management helper script
# Helps with version bumping and release management

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

# Get current version
get_current_version() {
    local tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    # Clean up any pre-release suffixes (e.g., v0.1.0-beta -> v0.1.0)
    echo "$tag" | sed 's/-.*$//'
}

# Get commits since last tag: subject lines PLUS bodies.
#
# --oneline shows subjects only, so a "BREAKING CHANGE:" footer — the conventional-commits way to
# mark a breaking change without the ! shorthand — never reached the grep below. The format keeps
# the short sha in front of each SUBJECT so the type regexes can anchor on it; body lines carry no
# sha, so a body line beginning "feat:" cannot be mistaken for a commit type.
get_commits_since_tag() {
    local last_tag=$(get_current_version)
    git log ${last_tag}..HEAD --no-merges --format='%h %s%n%b'
}

# Determine version bump type from conventional-commit subjects.
#
# The previous greps matched only UNSCOPED prefixes ("feat:", "fix!"), and every commit in this
# repository uses the scoped form ("fix(scope):", "fix(json, yaml, csv)!:"). Measured on
# 2026-09-23: twelve commits sat between v2.5.0 and HEAD, one of them breaking-flagged, and this
# function answered "none" — `make version-next` proposed the CURRENT tag. The release that
# followed was hand-cut as v2.5.1, shipping a breaking change under a patch bump.
#
# The scope group `(\([^)]*\))?` accepts both forms. Anchoring to the start of the subject
# (--oneline puts the short sha first, so after "<sha> ") stops a prefix inside prose — a subject
# QUOTING "feat:" — from counting as one. `!` before the colon is breaking regardless of type,
# per the conventional-commits spec.
determine_bump_type() {
    local commits=$(get_commits_since_tag)
    local subject_re='^[0-9a-f]+ '

    if echo "$commits" | grep -qE "BREAKING CHANGE|${subject_re}[a-z]+(\([^)]*\))?!:"; then
        echo "major"
    elif echo "$commits" | grep -qE "${subject_re}feat(\([^)]*\))?:"; then
        echo "minor"
    elif echo "$commits" | grep -qE "${subject_re}(fix|perf|refactor)(\([^)]*\))?:"; then
        echo "patch"
    else
        echo "none"
    fi
}

# Calculate next version
calculate_next_version() {
    local current_version=$(get_current_version)
    local bump_type=$(determine_bump_type)
    local version_number=${current_version#v}

    # Handle version parsing more robustly
    if [[ "$version_number" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
        local MAJOR=${BASH_REMATCH[1]}
        local MINOR=${BASH_REMATCH[2]}
        local PATCH=${BASH_REMATCH[3]}
    else
        # Fallback for malformed versions
        local MAJOR=0
        local MINOR=1
        local PATCH=0
    fi

    case $bump_type in
        major) echo "v$((MAJOR+1)).0.0" ;;
        minor) echo "v${MAJOR}.$((MINOR+1)).0" ;;
        patch) echo "v${MAJOR}.${MINOR}.$((PATCH+1))" ;;
        none) echo "$current_version" ;;
    esac
}

# Show version status
show_status() {
    echo "📊 Version Status"
    echo "================="

    local current_version=$(get_current_version)
    local next_version=$(calculate_next_version)
    local bump_type=$(determine_bump_type)

    print_info "Current version: $current_version"
    print_info "Next version: $next_version"
    print_info "Bump type: $bump_type"

    echo ""
    echo "📝 Commits since last tag:"
    get_commits_since_tag | grep -E '^[0-9a-f]+ ' | head -10

    if [ "$bump_type" = "none" ]; then
        print_warning "No significant changes found - no release needed"
    else
        print_status "Ready for $bump_type release: $next_version"
    fi
}

# Create release tag
create_tag() {
    local version="$1"
    local current_version=$(get_current_version)

    if [ "$version" = "$current_version" ]; then
        print_warning "Version $version already exists"
        return 1
    fi

    print_info "Creating tag: $version"

    # Create annotated tag with changelog
    local commits=$(get_commits_since_tag | grep -E '^[0-9a-f]+ ' | head -10)
    git tag -a "$version" -m "Release $version

Changes in this release:
$commits"

    print_status "Tag $version created locally"
    print_info "Push with: git push origin $version"
}

# Push tag and trigger release
push_and_release() {
    local version="$1"

    if ! git tag -l | grep -q "^$version$"; then
        print_error "Tag $version does not exist locally"
        return 1
    fi

    print_info "Pushing tag: $version"
    git push origin "$version"

    print_status "Tag pushed! GitLab CI will now build and release automatically"
    print_info "Monitor progress at: $CI_PIPELINE_URL"
}

# Main command handling
case "${1:-status}" in
    "status")
        show_status
        ;;
    "next")
        calculate_next_version
        ;;
    "bump")
        local next_version=$(calculate_next_version)
        local bump_type=$(determine_bump_type)

        if [ "$bump_type" = "none" ]; then
            print_warning "No significant changes found - no release needed"
            exit 0
        fi

        create_tag "$next_version"
        ;;
    "release")
        local next_version=$(calculate_next_version)
        local bump_type=$(determine_bump_type)

        if [ "$bump_type" = "none" ]; then
            print_warning "No significant changes found - no release needed"
            exit 0
        fi

        create_tag "$next_version"
        push_and_release "$next_version"
        ;;
    "tag")
        if [ -z "${2:-}" ]; then
            print_error "Usage: $0 tag <version>"
            exit 1
        fi
        create_tag "$2"
        ;;
    "push")
        if [ -z "${2:-}" ]; then
            local next_version=$(calculate_next_version)
            push_and_release "$next_version"
        else
            push_and_release "$2"
        fi
        ;;
    *)
        echo "🏷️  Version Helper"
        echo "================="
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  status    - Show current version status and next version"
        echo "  next      - Show next version number"
        echo "  bump      - Create next version tag locally"
        echo "  release   - Create and push next version tag (triggers CI)"
        echo "  tag <ver> - Create specific version tag locally"
        echo "  push [ver]- Push version tag (triggers CI release)"
        echo ""
        echo "Examples:"
        echo "  $0 status           # Show version status"
        echo "  $0 release          # Create and release next version"
        echo "  $0 tag v1.2.3       # Create specific version tag"
        echo "  $0 push v1.2.3      # Push specific version tag"
        exit 1
        ;;
esac
