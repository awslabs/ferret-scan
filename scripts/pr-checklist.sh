#!/usr/bin/env bash
#
# pr-checklist.sh — run the TEST_PLAN dimensions and print an explicit
# RAN / N-A line for every one of them.
#
# Why this exists: the dimensions were already written down in
# docs/testing/TEST_PLAN.md and were still being skipped, because "run the
# tests" collapses in practice to `go test ./...` and stops there. A reviewer
# cannot tell the difference between "redaction was verified" and "redaction was
# not considered" unless the run SAYS so. This script makes the omission
# visible: every dimension prints a line, and the ones it cannot decide for you
# print NEEDS-MANUAL rather than nothing.
#
# It is deliberately not wired into CI as a gate. CI already runs the suite, and
# `make test-ci` already does the race + uncached pass this script also performs.
# What neither of those does is ENUMERATE — they tell you the suite is green, not
# which dimensions were considered. The sink dimensions in particular (redaction,
# suppression) cannot be covered by a generic suite run at all, because they need
# a fixture that exercises the specific change. Run this, paste the output in the
# PR.
#
# Usage:
#   scripts/pr-checklist.sh                 # compare against origin/main
#   scripts/pr-checklist.sh <base-ref>      # compare against another base
#
set -uo pipefail

BASE="${1:-origin/main}"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-off}"   # the dev laptop blocks the proxy; offline by default

pass=0 fail=0 manual=0
line() { printf '%-34s %s\n' "$1" "$2"; }
ok()   { line "$1" "RAN — $2";          pass=$((pass+1)); }
bad()  { line "$1" "FAIL — $2";         fail=$((fail+1)); }
na()   { line "$1" "N/A — $2"; }
todo() { line "$1" "NEEDS-MANUAL — $2"; manual=$((manual+1)); }

# Snapshot the tree state BEFORE we touch anything. The "tree clean" check at the
# end must report only files THIS SCRIPT dirtied — flagging the caller's own
# work-in-progress edits would be a false positive (and it was, the first time).
dirty_before=$(git status --porcelain | grep -v '^??' | awk '{print $2}' | sort)

echo "=== scope ==="
changed=$(git diff --name-only "$BASE"...HEAD 2>/dev/null)
if [ -z "$changed" ]; then
  echo "no changes vs $BASE — nothing to check"; exit 0
fi
prod=$(echo "$changed" | grep -E '\.go$' | grep -v '_test\.go$' || true)
n_prod=$(echo "$prod" | grep -c . || true)
echo "$changed" | while IFS= read -r f; do printf '  %s\n' "$f"; done
echo "  production (non-test) .go files: $n_prod"
echo

echo "=== dimensions ==="

# 1. build / vet / gofmt
unf=$(gofmt -l ./cmd ./internal ./pkg 2>/dev/null)
if [ -n "$unf" ]; then bad "1 gofmt" "$(echo "$unf" | tr '\n' ' ')"; else ok "1 gofmt" "clean"; fi
if go vet ./... >/tmp/_vet 2>&1; then ok "1 go vet" "clean"; else bad "1 go vet" "see /tmp/_vet"; fi
if go build ./... >/tmp/_build 2>&1; then ok "1 go build" "ok"; else bad "1 go build" "see /tmp/_build"; fi

# 2. full suite, uncached. -count=1 matters: a cached PASS proves nothing about
#    the current tree.
if go test -count=1 ./cmd/... ./internal/... ./pkg/... >/tmp/_suite 2>&1; then
  ok "2 full suite (-count=1)" "$(grep -c '^ok' /tmp/_suite) packages ok"
else
  bad "2 full suite (-count=1)" "$(grep -E '^(FAIL|---)' /tmp/_suite | head -3 | tr '\n' ' ')"
fi

# 3. golden corpus. Regenerating and finding no diff is the assertion; a change
#    here means behavior moved, which may be intended but must be reviewed.
if [ -d internal/goldencorpus/testdata ]; then
  UPDATE_GOLDEN=1 go test -count=1 ./internal/goldencorpus/ >/dev/null 2>&1
  gd=$(git diff --name-only -- internal/goldencorpus/testdata/ | grep -c . || true)
  if [ "$gd" -eq 0 ]; then ok "3 golden regen" "0 files changed"
  else
    bad "3 golden regen" "$gd files changed — REVIEW EVERY DIFF, then commit deliberately"
    git diff --name-only -- internal/goldencorpus/testdata/ | sed 's/^/      /'
  fi
fi

# 4/5. The sinks. These are the two that keep getting skipped, and they are the
#      two where a miss is a cleartext leak rather than a cosmetic defect:
#      offsets feed the redactor, and confidence/position feed the suppression
#      hash. The script cannot invent a fixture that exercises YOUR change, so
#      it refuses to mark them done.
if [ "$n_prod" -eq 0 ]; then
  na "4 redaction" "no production code changed"
  na "5 suppression" "no production code changed"
else
  todo "4 redaction" "scan a fixture with --enable-redaction for EVERY strategy; for
                                   xlsx/docx read the part INSIDE the zip (grepping the
                                   compressed bytes returns 0 and looks like a pass)"
  todo "5 suppression" "generate with the PARENT binary, apply with YOURS — same-binary
                                   round-tripping passes even when the hash inputs changed"
fi

# 6. timing / complexity, only if the change could touch a per-line or per-match loop.
if [ "$n_prod" -eq 0 ]; then
  na "6 timing / O(n^2)" "no production code changed"
else
  todo "6 timing / O(n^2)" "scaling curve at N/2N/4N with a NON-VACUITY floor (assert
                                   findings > 0 at every size) and distinct values (identical
                                   repeats let a quadratic measure as linear)"
fi

# 7. output formats.
if [ "$n_prod" -eq 0 ]; then
  na "7 all 7 formats" "no production code changed"
else
  todo "7 all 7 formats" "text json yaml csv junit gitlab-sast sarif"
fi

# 8. web.
if echo "$changed" | grep -qE 'internal/web|\.html$|\.css$|\.js$'; then
  todo "8 web / CSP" "web assets changed"
else
  na "8 web / CSP" "no web/template/asset file touched"
fi

# 10. non-vacuity — a new test must fail on the pre-change code.
if echo "$changed" | grep -q '_test\.go$'; then
  todo "10 non-vacuity" "new tests MUST fail on the parent commit; prove it by reverting
                                   the production change (or the guard) and re-running"
else
  na "10 non-vacuity" "no test files added"
fi

# 11. cross-platform: compile-only, cheap, catches path/build-tag mistakes.
xp=ok
for goos in linux darwin windows; do
  GOOS=$goos go vet ./... >/dev/null 2>&1 || xp="failed on $goos"
done
if [ "$xp" = ok ]; then ok "11 cross-platform vet" "linux darwin windows"; else bad "11 cross-platform vet" "$xp"; fi

# 12. flake: three uncached repeats of the packages this change touches.
pkgs=$(echo "$changed" | grep '\.go$' | xargs -n1 dirname 2>/dev/null | sort -u | sed 's|^|./|' | tr '\n' ' ')
if [ -n "${pkgs// /}" ]; then
  flake=ok
  for _ in 1 2 3; do
    # shellcheck disable=SC2086  # pkgs is an intentional word-split list
    go test -count=1 $pkgs >/dev/null 2>&1 || flake="a repeat failed"
  done
  if [ "$flake" = ok ]; then ok "12 flake (3 repeats)" "$pkgs"; else bad "12 flake" "$flake"; fi
fi

# 13. race, WHOLE module. Racing only the package you touched misses the
#     concurrency the worker pool introduces around it.
if go test -race -count=1 ./cmd/... ./internal/... ./pkg/... >/tmp/_race 2>&1; then
  ok "13 race (whole module)" "$(grep -c '^ok' /tmp/_race) packages ok"
else
  bad "13 race (whole module)" "$(grep -E '^(FAIL|WARNING: DATA RACE)' /tmp/_race | head -3 | tr '\n' ' ')"
fi

# -short, because CI uses it and a -short-only skip can hide a broken test.
if go test -short -count=1 ./cmd/... ./internal/... ./pkg/... >/dev/null 2>&1; then
  ok "-- -short mode" "ok"
else
  bad "-- -short mode" "fails under -short"
fi

# Leave the tree as we found it.
git checkout -- internal/goldencorpus/testdata/ 2>/dev/null || true
dirty_after=$(git status --porcelain | grep -v '^??' | awk '{print $2}' | sort)
new_dirty=$(comm -13 <(echo "$dirty_before") <(echo "$dirty_after") | grep -c . || true)
if [ "$new_dirty" -eq 0 ]; then
  ok "-- tree clean" "this run dirtied nothing"
else
  bad "-- tree clean" "$new_dirty file(s) left modified BY THIS RUN: $(comm -13 <(echo "$dirty_before") <(echo "$dirty_after") | tr '\n' ' ')"
fi

echo
echo "=== summary: $pass ran, $fail failed, $manual need manual work ==="
if [ "$manual" -gt 0 ]; then
  echo "The NEEDS-MANUAL items are not optional. A sink dimension left unrun is how a"
  echo "cleartext leak ships. See docs/testing/TEST_PLAN.md."
fi
if [ "$fail" -gt 0 ]; then exit 1; fi
exit 0
