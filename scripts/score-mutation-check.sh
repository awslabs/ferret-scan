#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Prove `make score` is not vacuous.
#
# A quality gate has one dangerous failure mode: it keeps printing a number that no
# longer means anything. The only way to know it still bites is to break the product
# on purpose and watch it go red. This script does that for each of the four layers,
# then restores the tree.
#
# Every mutation below is REAL and plausible -- a change a reviewer could wave
# through -- not a syntax error. Each one must COMPILE, because a build failure
# proves nothing about the gate.
#
# Run manually (it edits and restores source files):
#     make score-mutation-check
#
# It is deliberately NOT in CI: it mutates tracked files, and a crash mid-run would
# leave the tree dirty. CI runs `make score` against the committed baseline instead.

set -uo pipefail
cd "$(dirname "$0")/.."

GO="GOFLAGS=-mod=mod GOPROXY=off go"
BACKUP="$(mktemp -d)"
FAILED=0

# Files this script edits. Backed up verbatim and restored unconditionally.
TARGETS=(
  internal/validators/ssn/validator.go
  internal/redactors/overlap.go
)

restore() {
  for f in "${TARGETS[@]}"; do
    if [[ -f "$BACKUP/$(basename "$f")" ]]; then
      cp "$BACKUP/$(basename "$f")" "$f"
    fi
  done
  echo
  echo "tree restored; verifying it is clean..."
  if ! git diff --quiet -- "${TARGETS[@]}"; then
    echo "  !! FILES STILL MODIFIED -- inspect before committing:"
    git --no-pager diff --stat -- "${TARGETS[@]}"
    exit 1
  fi
  echo "  clean."
}
trap restore EXIT

for f in "${TARGETS[@]}"; do
  cp "$f" "$BACKUP/$(basename "$f")"
done

# score_is <expected: red|green> <label>
score_is() {
  local want="$1" label="$2" out rc
  out="$(eval "$GO test -count=1 -run 'TestScoreCorpus|TestContainerResidue' ./internal/scorecorpus/" 2>&1)"
  rc=$?

  local got="green"
  [[ $rc -ne 0 ]] && got="red"

  if [[ "$got" == "$want" ]]; then
    printf '  PASS  %-46s gate=%s\n' "$label" "$got"
    if [[ "$got" == "red" ]]; then
      echo "$out" | grep -E 'REGRESSION|SURVIVES|MISSED' | sed 's/^/          /' | head -4
    fi
  else
    printf '  FAIL  %-46s gate=%s want=%s\n' "$label" "$got" "$want"
    FAILED=1
  fi
}

compiles() {
  if ! eval "$GO build ./... " >/dev/null 2>&1; then
    printf '  SKIP  %-46s mutation does not compile (invalid proof)\n' "$1"
    FAILED=1
    return 1
  fi
  return 0
}

echo "=== control: the gate must be GREEN on an unmodified tree ==="
score_is green "control (no mutation)"

echo
echo "=== M1 validator layer: a plausible 'fixed-width report noise' filter ==="
echo "    (this mutation passes the ENTIRE test suite at rc=0 -- measured)"
python3 - <<'PY'
p = 'internal/validators/ssn/validator.go'
s = open(p).read()
old = "\t\tidxMatches := v.regex.FindAllStringIndex(line, -1)"
new = ("\t\tif strings.Contains(line, \"   \") {\n"
       "\t\t\tcontinue // MUTATION: skip fixed-width report noise\n"
       "\t\t}\n" + old)
assert s.count(old) == 1, "anchor moved; update the script"
open(p, 'w').write(s.replace(old, new))
PY
if compiles "M1 fixed-width veto"; then
  score_is red "M1 fixed-width veto (recall + sink)"
fi
cp "$BACKUP/validator.go" internal/validators/ssn/validator.go

echo
echo "=== M2 redaction layer: revert PR #250 (cross-part span subsumption) ==="
echo "    (detection is BIT-IDENTICAL under this mutation -- only the artifact moves)"
python3 - <<'PY'
p = 'internal/redactors/overlap.go'
s = open(p).read()
old = "\t\tk := lineKey{number: number, text: text}"
new = "\t\tk := lineKey{number: number, text: \"\"} // MUTATION: revert PR #250"
assert s.count(old) == 1, "anchor moved; update the script"
open(p, 'w').write(s.replace(old, new))
PY
if compiles "M2 revert #250"; then
  score_is red "M2 revert #250 (container sink only)"
fi
cp "$BACKUP/overlap.go" internal/redactors/overlap.go

echo
echo "=== summary ==="
if [[ $FAILED -eq 0 ]]; then
  echo "  all mutations behaved as expected: the gate discriminates."
else
  echo "  !! at least one mutation did not move the gate."
  echo "     A mutation the gate does not catch is a regression class it cannot"
  echo "     protect against. Add a case that covers it before trusting the number."
fi
exit $FAILED
