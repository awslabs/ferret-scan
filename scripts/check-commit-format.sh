#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Script to check if commit messages follow conventional commits format
# Usage: ./scripts/check-commit-format.sh [commit-range]
# Example: ./scripts/check-commit-format.sh HEAD~5..HEAD
#
# Exit status: 0 when every commit in the range follows the format, 1 when at least one does not,
# 2 when git cannot read the range. Merge commits are skipped: git writes their subjects, and
# scripts/version-helper.sh skips them too when it reads commit types to propose a version.

set -euo pipefail

# Default to checking the last commit if no range provided
COMMIT_RANGE="${1:-HEAD~1..HEAD}"

echo "Checking commit messages in range: $COMMIT_RANGE"
echo "----------------------------------------"

# Read the whole range before checking it, so a range git cannot read (a typo, or HEAD~1 in a
# one-commit or shallow clone) is an error. Piped straight into the loop, git's failure was lost
# and the empty loop passed. Feeding the loop from a here-string also ends every line with a
# newline; `git log --pretty=format:` left the last line without one, and `read` skipped it.
if ! commits=$(git log --no-merges --format='%h %s' "$COMMIT_RANGE"); then
    echo "❌ git cannot read the commit range: $COMMIT_RANGE" >&2
    exit 2
fi
merges=$(git rev-list --merges --count "$COMMIT_RANGE")

checked=0
invalid=0
if [ -n "$commits" ]; then
    while read -r commit_hash commit_message; do
        checked=$((checked + 1))
        echo "Checking: $commit_hash $commit_message"

        # Check if commit message follows conventional commits format
        if grep -qE '^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?(!)?: .+' <<< "$commit_message"; then
            echo "  ✅ Valid conventional commit format"
        else
            invalid=$((invalid + 1))
            echo "  ❌ Invalid format - should be: type(scope): description"
            echo "     Valid types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
            echo "     Example: feat(validator): add new credit card pattern"
        fi
        echo ""
    done <<< "$commits"
fi

echo "Checked $checked commit(s); $invalid do not follow the format."
if [ "$merges" -gt 0 ]; then
    echo "Skipped $merges merge commit(s)."
fi
echo ""
echo "For more information on conventional commits, see:"
echo "https://conventionalcommits.org/"

if [ "$invalid" -gt 0 ]; then
    exit 1
fi
