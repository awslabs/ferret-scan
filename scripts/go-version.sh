#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Go version management script.
#
# `.go-version` is the single source of truth for the Go toolchain version.
# This script propagates it to every other place the version is pinned, and
# `check` cross-validates that they all agree (so drift fails CI/pre-commit
# instead of silently shipping a stale, possibly-vulnerable toolchain).
#
# Pinned locations:
#   - go.mod                 (major.minor only, e.g. 1.26)
#   - Dockerfile             (golang:<version>-alpine tag AND @sha256 digest)
#   - .gitlab-ci.yml         (GO_VERSION + GO_DOCKER_IMAGE)
#   - GitHub Actions         (use go-version-file: .go-version, so no literal
#                             version to sync — we assert that instead)
#
# The Dockerfile is digest-pinned for supply-chain integrity (TM-10): the
# @sha256:... is what actually determines the pulled image, the tag is
# informational. Updating the tag without the digest is a no-op at build
# time, so `update` resolves and rewrites the digest too (needs network +
# crane/docker/curl). `check` verifies the *tag* matches .go-version and
# warns if the digest can't be verified offline.

set -euo pipefail

GO_VERSION_FILE=".go-version"
DOCKERFILE="Dockerfile"
GITLAB_CI=".gitlab-ci.yml"
GITHUB_WORKFLOWS_DIR=".github/workflows"

# Public registry the Dockerfile pulls the builder image from.
GOLANG_REGISTRY="public.ecr.aws/docker/library/golang"

if [[ ! -f "$GO_VERSION_FILE" ]]; then
    echo "❌ $GO_VERSION_FILE not found (must run from repo root)" >&2
    exit 1
fi

GO_VERSION=$(tr -d '[:space:]' < "$GO_VERSION_FILE")
GO_MAJOR_MINOR=$(echo "$GO_VERSION" | cut -d. -f1,2)
GOLANG_TAG="${GO_VERSION}-alpine"

# Track failures across all checks so `check` reports everything at once
# rather than exiting on the first mismatch.
CHECK_FAILED=0
fail()  { echo "❌ $1" >&2; CHECK_FAILED=1; }
ok()    { echo "✅ $1"; }
warn()  { echo "⚠️  $1" >&2; }
info()  { echo "ℹ️  $1"; }

# ---------------------------------------------------------------------------
# Digest resolution: golang:<version>-alpine -> sha256 index digest.
# Tries crane, then docker, then the registry HTTP API (anonymous token).
# Prints the digest on stdout, or nothing (and returns 1) if it can't.
# ---------------------------------------------------------------------------
resolve_digest() {
    local ref="${GOLANG_REGISTRY}:${GOLANG_TAG}"

    if command -v crane >/dev/null 2>&1; then
        crane digest "$ref" 2>/dev/null && return 0
    fi

    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        docker manifest inspect "$ref" >/dev/null 2>&1 \
            && docker buildx imagetools inspect "$ref" 2>/dev/null \
                | awk '/Digest:/ {print $2; exit}' \
            && return 0
    fi

    # Registry HTTP API fallback: anonymous bearer token + manifest HEAD.
    if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        local repo="docker/library/golang" token digest
        token=$(curl -sf "https://public.ecr.aws/token/?scope=repository:${repo}:pull" 2>/dev/null \
            | jq -r '.token' 2>/dev/null)
        if [[ -n "$token" && "$token" != "null" ]]; then
            digest=$(curl -sfI "https://public.ecr.aws/v2/${repo}/manifests/${GOLANG_TAG}" \
                -H "Authorization: Bearer ${token}" \
                -H "Accept: application/vnd.oci.image.index.v1+json" \
                -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" 2>/dev/null \
                | awk -F': ' 'tolower($1)=="docker-content-digest" {gsub(/[[:space:]]/,"",$2); print $2}')
            if [[ -n "$digest" ]]; then
                echo "$digest"
                return 0
            fi
        fi
    fi

    return 1
}

# ---------------------------------------------------------------------------
# Updaters
# ---------------------------------------------------------------------------
update_go_mod() {
    [[ -f go.mod ]] || { warn "go.mod not found"; return; }
    if command -v go >/dev/null 2>&1; then
        go mod edit -go="$GO_MAJOR_MINOR"
    else
        sed -i.bak "s/^go .*/go $GO_MAJOR_MINOR/" go.mod && rm -f go.mod.bak
    fi
    ok "go.mod -> go $GO_MAJOR_MINOR"
}

update_dockerfile() {
    [[ -f "$DOCKERFILE" ]] || { warn "$DOCKERFILE not found"; return; }

    # Rewrite the FROM tag (and the informational tag in the comment), keeping
    # the registry prefix. NOTE: the previous script anchored on "FROM golang:"
    # which never matched the registry-qualified "FROM <registry>/golang:" line
    # — that bug is why the Dockerfile silently drifted. This matches the real
    # line.
    local esc_registry; esc_registry=$(echo "$GOLANG_REGISTRY" | sed 's/[.[\*^$/]/\\&/g')
    sed -i.bak -E "s#(${esc_registry}):[0-9]+\.[0-9]+\.[0-9]+-alpine#\1:${GOLANG_TAG}#g" "$DOCKERFILE"
    rm -f "${DOCKERFILE}.bak"

    # Resolve and rewrite the digest — the load-bearing pin (TM-10).
    local digest
    if digest=$(resolve_digest); then
        sed -i.bak -E "s#(${esc_registry}:${GO_VERSION}-alpine)@sha256:[a-f0-9]{64}#\1@${digest}#g" "$DOCKERFILE"
        rm -f "${DOCKERFILE}.bak"
        ok "$DOCKERFILE -> golang:${GOLANG_TAG} @ ${digest}"
    else
        warn "$DOCKERFILE tag updated to ${GOLANG_TAG}, but could NOT resolve the @sha256 digest"
        warn "  (no crane/docker, or no network). The digest is the real pin — update it manually:"
        warn "    crane digest ${GOLANG_REGISTRY}:${GOLANG_TAG}"
        # Tag-without-digest is a build-time no-op, so treat as a failure.
        CHECK_FAILED=1
    fi
}

update_gitlab_ci() {
    [[ -f "$GITLAB_CI" ]] || { warn "$GITLAB_CI not found"; return; }
    sed -i.bak -E "s/(GO_VERSION:[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+(\")/\1${GO_VERSION}\2/" "$GITLAB_CI"
    sed -i.bak -E "s/(GO_DOCKER_IMAGE:[[:space:]]*\"golang:)[0-9]+\.[0-9]+\.[0-9]+(-alpine\")/\1${GO_VERSION}\2/" "$GITLAB_CI"
    rm -f "${GITLAB_CI}.bak"
    ok "$GITLAB_CI -> GO_VERSION=${GO_VERSION}, GO_DOCKER_IMAGE=golang:${GOLANG_TAG}"
}

# ---------------------------------------------------------------------------
# Checks (no mutation) — cross-validate every pinned location vs .go-version.
# ---------------------------------------------------------------------------
check_go_mod() {
    [[ -f go.mod ]] || return
    local v; v=$(awk '/^go / {print $2; exit}' go.mod)
    if [[ "$v" == "$GO_MAJOR_MINOR" ]]; then
        ok "go.mod: $v"
    else
        fail "go.mod: $v (expected $GO_MAJOR_MINOR from .go-version)"
    fi
}

check_dockerfile() {
    [[ -f "$DOCKERFILE" ]] || return
    local tag; tag=$(grep -oE "${GOLANG_REGISTRY}:[0-9]+\.[0-9]+\.[0-9]+-alpine" "$DOCKERFILE" | head -1 | sed "s#${GOLANG_REGISTRY}:##")
    if [[ "$tag" == "$GOLANG_TAG" ]]; then
        ok "Dockerfile tag: $tag"
    else
        fail "Dockerfile tag: ${tag:-<none>} (expected $GOLANG_TAG)"
    fi

    # Verify the digest matches the tag if we can reach a resolver; otherwise
    # warn (offline pre-commit should not hard-fail on an un-verifiable digest).
    local pinned; pinned=$(grep -oE "${GOLANG_REGISTRY}:${GO_VERSION}-alpine@sha256:[a-f0-9]{64}" "$DOCKERFILE" | head -1 | grep -oE "sha256:[a-f0-9]{64}" || true)
    if [[ -z "$pinned" ]]; then
        fail "Dockerfile: no @sha256 digest pinned for golang:${GOLANG_TAG}"
        return
    fi
    local actual
    if actual=$(resolve_digest); then
        if [[ "$pinned" == "$actual" ]]; then
            ok "Dockerfile digest: $pinned (matches registry)"
        else
            fail "Dockerfile digest: $pinned (registry has $actual for ${GOLANG_TAG})"
        fi
    else
        warn "Dockerfile digest: $pinned (could not verify against registry — offline)"
    fi
}

check_gitlab_ci() {
    [[ -f "$GITLAB_CI" ]] || return
    local v img
    v=$(grep -E "GO_VERSION:" "$GITLAB_CI" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    img=$(grep -E "GO_DOCKER_IMAGE:" "$GITLAB_CI" | head -1 | sed -E 's/.*"golang:([^"]+)".*/\1/')
    if [[ "$v" == "$GO_VERSION" ]]; then
        ok ".gitlab-ci.yml GO_VERSION: $v"
    else
        fail ".gitlab-ci.yml GO_VERSION: ${v:-<none>} (expected $GO_VERSION)"
    fi
    if [[ "$img" == "$GOLANG_TAG" ]]; then
        ok ".gitlab-ci.yml GO_DOCKER_IMAGE: golang:$img"
    else
        fail ".gitlab-ci.yml GO_DOCKER_IMAGE: golang:${img:-<none>} (expected golang:$GOLANG_TAG)"
    fi
}

# GitHub workflows should reference .go-version, not a literal version. Assert
# that (a literal go-version: pin would silently bypass the single source).
check_github_workflows() {
    [[ -d "$GITHUB_WORKFLOWS_DIR" ]] || return
    local literal
    literal=$(grep -rEln "go-version:[[:space:]]*['\"]?[0-9]+\.[0-9]+" "$GITHUB_WORKFLOWS_DIR" 2>/dev/null || true)
    if [[ -n "$literal" ]]; then
        fail "GitHub workflows pin a literal Go version (use 'go-version-file: .go-version'):"
        echo "${literal//$'\n'/$'\n'      }" | sed '1s/^/      /' >&2
    else
        ok "GitHub workflows: use go-version-file (.go-version), no literal pins"
    fi
}

check_local_go() {
    if command -v go >/dev/null 2>&1; then
        local cur; cur=$(go version | grep -oE 'go[0-9]+\.[0-9]+\.[0-9]+' | sed 's/go//')
        if [[ "$cur" == "$GO_VERSION" ]]; then
            ok "local toolchain: go$cur"
        else
            warn "local toolchain: go$cur (does not match .go-version $GO_VERSION; not a CI failure)"
        fi
    else
        warn "local toolchain: go not installed"
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
case "${1:-check}" in
    check)
        info "Source of truth (.go-version): $GO_VERSION  (go.mod: $GO_MAJOR_MINOR)"
        check_local_go
        check_go_mod
        check_dockerfile
        check_gitlab_ci
        check_github_workflows
        if [[ "$CHECK_FAILED" -ne 0 ]]; then
            echo "" >&2
            echo "❌ Go version is out of sync. Run: make sync-go-version" >&2
            exit 1
        fi
        echo ""
        ok "All Go version pins are consistent with .go-version ($GO_VERSION)"
        ;;
    all|sync|update)
        info "Syncing all Go version pins to .go-version: $GO_VERSION"
        update_go_mod
        update_dockerfile
        update_gitlab_ci
        check_github_workflows   # workflows are not mutated; just assert
        if [[ "$CHECK_FAILED" -ne 0 ]]; then
            echo "" >&2
            echo "⚠️  Sync completed with warnings (see above — likely an unresolved Docker digest)." >&2
            exit 1
        fi
        echo ""
        ok "Synced. Review with: git diff"
        ;;
    docker-tag)
        echo "${GOLANG_REGISTRY}:${GOLANG_TAG}"
        ;;
    ci-vars)
        echo "GO_VERSION=$GO_VERSION"
        echo "GO_DOCKER_IMAGE=golang:${GOLANG_TAG}"
        ;;
    *)
        cat <<USAGE
Usage: $0 {check|all|docker-tag|ci-vars}

  check       Cross-validate every Go version pin against .go-version (CI-safe).
  all|sync    Propagate .go-version to go.mod, Dockerfile (tag + digest),
              and .gitlab-ci.yml. Asserts GitHub workflows use go-version-file.
  docker-tag  Print the golang builder image tag.
  ci-vars     Print GO_VERSION / GO_DOCKER_IMAGE for CI.

.go-version is the single source of truth. To bump Go:
  echo "1.26.5" > .go-version && make sync-go-version && git diff
USAGE
        exit 1
        ;;
esac
