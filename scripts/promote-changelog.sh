#!/usr/bin/env bash
# promote-changelog.sh <vX.Y.Z> [path-to-CHANGELOG.md]
#
# Cuts the hand-written `## [Unreleased]` section into `## [<tag>] - <date>` and inserts a fresh,
# empty `## [Unreleased]` above it. ADDITIVE TEXT SURGERY ONLY: every promoted line is preserved
# byte-for-byte. #646 removed git-chglog for regenerating this file from commit subjects and
# replacing ~43,000 words of measurements with one-liners; this script exists so that mistake has a
# named alternative (#647).
#
# Exit codes: 0 promoted, or nothing to do (idempotent re-run / empty section); 1 on any state this
# script does not positively recognize. The [Unreleased] anchor is load-bearing -- every open PR
# inserts bullets under it -- so an unmatched anchor is a hard failure, never a silent guess.
set -euo pipefail

TAG="${1:-}"
FILE="${2:-CHANGELOG.md}"

if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 vX.Y.Z [CHANGELOG.md] -- got '${TAG}'" >&2
    exit 1
fi
if [[ ! -f "$FILE" ]]; then
    echo "promote-changelog: $FILE not found" >&2
    exit 1
fi

# Idempotence: a re-pushed tag or a re-run job must not create a second heading.
if grep -qE "^## \[${TAG//./\\.}\]" "$FILE"; then
    echo "promote-changelog: a heading for ${TAG} already exists; nothing to do"
    exit 0
fi

if ! grep -qE '^## \[Unreleased\]$' "$FILE"; then
    echo "promote-changelog: no '## [Unreleased]' heading found in $FILE -- refusing to guess where to cut" >&2
    exit 1
fi

# Empty [Unreleased] (no bullets and no section headers before the next version heading) is a
# release with no changelog-worthy changes: promoting it would create an empty version section.
CONTENT=$(awk '/^## \[Unreleased\]$/{f=1;next} f&&/^## \[/{exit} f' "$FILE" | grep -cE '^(### |- )' || true)
if [[ "$CONTENT" -eq 0 ]]; then
    echo "promote-changelog: [Unreleased] is empty; nothing to promote for ${TAG}"
    exit 0
fi

DATE=$(date -u +%Y-%m-%d)
TMP=$(mktemp)
awk -v tag="$TAG" -v date="$DATE" '
    /^## \[Unreleased\]$/ && !done {
        print "## [Unreleased]"
        print ""
        print "## [" tag "] - " date
        done=1
        next
    }
    { print }
' "$FILE" > "$TMP"

# Refuse to write a result that lost content: the new file must be exactly two lines longer
# (the fresh heading and its blank line), with every original line still present in order.
OLD_LINES=$(wc -l < "$FILE"); NEW_LINES=$(wc -l < "$TMP")
if [[ $((NEW_LINES - OLD_LINES)) -ne 2 ]]; then
    echo "promote-changelog: surgery produced ${NEW_LINES} lines from ${OLD_LINES} (expected +2) -- refusing to write" >&2
    rm -f "$TMP"
    exit 1
fi
mv "$TMP" "$FILE"
echo "promote-changelog: promoted [Unreleased] (${CONTENT} entries/sections) to [${TAG}] - ${DATE}"
