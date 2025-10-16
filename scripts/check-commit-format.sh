#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Script to check if commit messages follow conventional commits format
# Usage: ./scripts/check-commit-format.sh [commit-range]
# Example: ./scripts/check-commit-format.sh HEAD~5..HEAD

set -e

# Default to checking the last commit if no range provided
COMMIT_RANGE="${1:-HEAD~1..HEAD}"

echo "Checking commit messages in range: $COMMIT_RANGE"
echo "----------------------------------------"

# Get commit messages in the range
git log --pretty=format:"%h %s" "$COMMIT_RANGE" | while read -r commit_hash commit_message; do
    echo "Checking: $commit_hash $commit_message"
    
    # Check if commit message follows conventional commits format
    if echo "$commit_message" | grep -qE '^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?(!)?: .+'; then
        echo "  ✅ Valid conventional commit format"
    else
        echo "  ❌ Invalid format - should be: type(scope): description"
        echo "     Valid types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
        echo "     Example: feat(validator): add new credit card pattern"
    fi
    echo ""
done

echo "Commit format check complete!"
echo ""
echo "For more information on conventional commits, see:"
echo "https://conventionalcommits.org/"