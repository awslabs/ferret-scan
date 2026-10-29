#!/usr/bin/env bash
# promote-changelog.sh <vX.Y.Z> [path-to-CHANGELOG.md]
#
# Cuts the release notes collected for the next release into a `## [<tag>] - <date>` section of
# CHANGELOG.md, inserted right below the `## [Unreleased]` heading and the paragraph under it, and
# `git rm`s what it rendered. The notes are one fragment file per pull request in changelog.d/,
# beside CHANGELOG.md (#821), plus any old-style bullets a pull request still added under
# [Unreleased], which are merged in by heading ahead of the fragments. changelog.d/README.md stays.
#
# ADDITIVE TEXT SURGERY ONLY: every bullet line is copied byte for byte, and every line outside the
# [Unreleased] block is untouched. #646 removed git-chglog for regenerating this file from commit
# subjects and replacing ~43,000 words of measurements with one-liners; this script exists so that
# mistake has a named alternative (#647).
#
# The parsing and rendering live in internal/tools/changelogrender (Go, unit-tested), so this needs
# the Go toolchain. This script owns the guarantees around it. The renderer prints the section, then
# writes the promotion into a copy of the file, and the copy replaces CHANGELOG.md only if it is
# byte-identical to the file this script assembles on its own -- the original's lines before the
# old-style entries, the printed section, the original's lines from the next release heading on --
# and has the line count that implies. Two implementations of one cut must agree before anything
# is written.
#
# Exit codes: 0 promoted, or nothing to do (idempotent re-run / nothing collected); 1 on any state
# this script does not positively recognize, a malformed fragment included, so a release never
# drops a note silently. The [Unreleased] anchor is load-bearing -- the section goes below it -- so
# an unmatched anchor is a hard failure, never a silent guess.
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

FILE="$(cd "$(dirname "$FILE")" && pwd)/$(basename "$FILE")"
FRAGS="$(dirname "$FILE")/changelog.d"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Where the cut goes, as 1-based line numbers: H the [Unreleased] heading; E the next release
# heading, or one past the last line; L the first old-style line under H -- a heading, a list item
# or an indented line, the rule of changelogfrag.EntryShaped -- or E when there is none. Lines L to
# E-1 leave, and the section takes their place. This is the script's own reading of the file,
# independent of the renderer's; the guard below holds the two to the same answer.
read -r H L E < <(awk '
    function entry(s) { return s ~ /^#/ || s ~ /^[-*+]( |$)/ || s ~ /^[0-9]+[.)]( |$)/ || s ~ /^[ \t]+[^ \t]/ }
    !h && /^## \[Unreleased\]$/ { h = NR; next }
    h && /^## \[/ { e = NR; exit }
    h && !l && entry($0) { l = NR }
    END { if (!e) e = NR + 1; if (!l) l = e; print h, l, e }
' "$FILE")
if ! [[ "${H:-}" =~ ^[0-9]+$ && "${L:-}" =~ ^[0-9]+$ && "${E:-}" =~ ^[0-9]+$ ]]; then
    echo "promote-changelog: could not locate the [Unreleased] block in $FILE" >&2
    exit 1
fi
LEGACY=$((E - L))

# Everything in changelog.d/ but its README is a fragment to render -- or a file the renderer
# refuses, which stops the release, never a skip.
FRAGMENTS=()
if [[ -d "$FRAGS" ]]; then
    while IFS= read -r -d '' f; do
        FRAGMENTS+=("$f")
    done < <(find "$FRAGS" -mindepth 1 -maxdepth 1 ! -name README.md -print0)
fi
NFRAGS=${#FRAGMENTS[@]}

if [[ "$LEGACY" -eq 0 && "$NFRAGS" -eq 0 ]]; then
    echo "promote-changelog: [Unreleased] is empty and changelog.d/ holds no fragments; nothing to promote for ${TAG}"
    exit 0
fi

if ! command -v go >/dev/null 2>&1; then
    echo "promote-changelog: rendering needs the Go toolchain, and 'go' is not on PATH" >&2
    exit 1
fi

# The fragments leave in the promote commit. Inside a git work tree that is `git rm`, which stages
# the deletion, so every fragment must be committed: a file git cannot remove would stay behind and
# be rendered again by the next release. Checked before anything is written.
IN_GIT=false
if [[ "$NFRAGS" -gt 0 ]] && git -C "$FRAGS" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    IN_GIT=true
    if ! git -C "$FRAGS" ls-files --error-unmatch -- "${FRAGMENTS[@]}" >/dev/null 2>&1; then
        echo "promote-changelog: changelog.d/ holds a file git does not track; commit or remove it, then re-run:" >&2
        git -C "$FRAGS" ls-files --others -- "${FRAGMENTS[@]}" >&2 || true
        exit 1
    fi
fi

DATE=$(date -u +%Y-%m-%d)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; rm -f "${FILE}.promote.$$"' EXIT

render() {
    (cd "$ROOT" && go run ./internal/tools/changelogrender -dir "$FRAGS" -tag "$TAG" -date "$DATE" "$@")
}

if ! render -changelog "$FILE" > "$WORK/section"; then
    echo "promote-changelog: the renderer refused (above); $FILE and changelog.d/ are untouched" >&2
    exit 1
fi
cp -p "$FILE" "$WORK/CHANGELOG.md"
if ! render -changelog "$WORK/CHANGELOG.md" -write 2> "$WORK/write.log"; then
    cat "$WORK/write.log" >&2
    echo "promote-changelog: the renderer could not write the promotion (above); $FILE and changelog.d/ are untouched" >&2
    exit 1
fi

# The guard. The new file must be exactly one line count -- the old one, less the old-style lines,
# plus the rendered section -- and byte-identical to the cut assembled here from the printed section.
{
    head -n $((L - 1)) "$FILE"
    cat "$WORK/section"
    tail -n +"$E" "$FILE"
} > "$WORK/expected"
OLD_LINES=$(wc -l < "$FILE"); NEW_LINES=$(wc -l < "$WORK/CHANGELOG.md"); SECTION_LINES=$(wc -l < "$WORK/section")
if (( SECTION_LINES == 0 || NEW_LINES != OLD_LINES - LEGACY + SECTION_LINES )); then
    echo "promote-changelog: surgery produced $((NEW_LINES)) lines from $((OLD_LINES)) (expected $((OLD_LINES)) - ${LEGACY} old-style + $((SECTION_LINES)) rendered) -- refusing to write" >&2
    exit 1
fi
if ! cmp -s "$WORK/expected" "$WORK/CHANGELOG.md"; then
    echo "promote-changelog: the renderer's file differs from the cut assembled here -- refusing to write:" >&2
    diff "$WORK/expected" "$WORK/CHANGELOG.md" | head -20 >&2 || true
    exit 1
fi

# Same directory, so the rename is atomic; cp -p carries the original's mode through.
cp -p "$WORK/CHANGELOG.md" "${FILE}.promote.$$"
mv "${FILE}.promote.$$" "$FILE"

if [[ "$NFRAGS" -gt 0 ]]; then
    if $IN_GIT; then
        if ! git -C "$FRAGS" rm -q -f -- "${FRAGMENTS[@]}"; then
            echo "promote-changelog: promoted $FILE, but 'git rm' of the fragments failed; remove them before the next release, or it renders them again" >&2
            exit 1
        fi
    else
        rm -f -- "${FRAGMENTS[@]}"
    fi
fi
echo "promote-changelog: promoted ${NFRAGS} fragment(s) and ${LEGACY} old-style line(s) under [Unreleased] to [${TAG}] - ${DATE}"
