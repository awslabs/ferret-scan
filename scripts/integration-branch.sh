#!/usr/bin/env bash
#
# integration-branch.sh — merge every open PR into one throwaway branch and test
# the union.
#
# Why this exists: "does each PR merge cleanly?" and "does the merged result
# work?" are different questions, and only the first one is cheap. Every PR in
# this repo is tested against main in isolation, so a pair of PRs can both be
# green, merge without a single textual conflict, and still turn the suite red
# once both are present.
#
# That happened: one PR added a golden case that snapshotted a duplicate MRZ
# finding, another PR made the duplicate stop happening. Different files, clean
# merge, individually green, red together. GitHub reports "no conflicts" for both
# — it only knows about text.
#
# So this script does the thing CI structurally cannot: it builds the union and
# runs the gates on it. Two modes:
#
#   --serial   (default) merge in PR-number order, report the first branch that
#              conflicts and with which files. This is the merge-queue rehearsal:
#              it answers "if we land these in order, where does it break?"
#   --pairwise every unordered pair against main. Slower (N^2/2 merges), but it
#              localizes a conflict to a PAIR instead of blaming whichever branch
#              happened to be merged later.
#
# The integration branch is left behind (default name below) so it can be pushed
# and pointed at, and so the next run can diff against it.
#
# Usage:
#   scripts/integration-branch.sh                  # serial, test the union
#   scripts/integration-branch.sh --pairwise       # add pairwise conflict matrix
#   scripts/integration-branch.sh --no-test        # merges only, skip the suite
#   scripts/integration-branch.sh --branch my-name
#
set -uo pipefail

BASE="origin/main"
BRANCH="integration/all-open-prs"
MODE=serial
RUN_TESTS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --pairwise) MODE=pairwise ;;
    --serial)   MODE=serial ;;
    --no-test)  RUN_TESTS=0 ;;
    --branch)   shift; BRANCH="${1:?--branch needs a value}" ;;
    --base)     shift; BASE="${1:?--base needs a value}" ;;
    -h|--help)  sed -n '3,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-off}"   # the dev laptop blocks the proxy

command -v gh >/dev/null || { echo "gh CLI is required to enumerate open PRs" >&2; exit 2; }

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root" || exit 2

echo "== fetching =="
git fetch -q origin '+refs/heads/*:refs/remotes/origin/*' || exit 2

# PR-number order, because that is the order they will realistically land in and
# it makes the run reproducible.
prs=$(gh pr list --state open --limit 200 --json number,headRefName \
        --jq '.[] | "\(.number):\(.headRefName)"' | sort -t: -k1 -n)
if [ -z "$prs" ]; then echo "no open PRs"; exit 0; fi
n_prs=$(echo "$prs" | grep -c .)
echo "== $n_prs open PRs =="

# Work in a detached worktree so the caller's checkout, index and in-progress
# edits are never touched. A conflicted merge in the main worktree would leave
# the user's tree in a MERGING state, which is a rude thing for a check to do.
wt=$(mktemp -d "${TMPDIR:-/tmp}/ferret-integration-XXXXXX")
cleanup() { git worktree remove --force "$wt" >/dev/null 2>&1 || true; }
trap cleanup EXIT
git worktree add -q --detach "$wt" "$BASE" || exit 2

conflicts=0
merged_ok=0

echo
echo "== serial merge from $BASE (PR-number order) =="
(
  cd "$wt" || exit 2
  while IFS=: read -r num branch; do
    if git merge -q --no-edit --no-ff "origin/$branch" >/dev/null 2>&1; then
      printf '  %-6s ok        %s\n' "$num" "$branch"
    else
      files=$(git diff --name-only --diff-filter=U | tr '\n' ' ')
      printf '  %-6s CONFLICT  %-45s [%s]\n' "$num" "$branch" "$files"
      git merge --abort
      echo "$num" >> "$wt/.conflicted"
    fi
  done <<< "$prs"
)
[ -f "$wt/.conflicted" ] && conflicts=$(grep -c . "$wt/.conflicted")
merged_ok=$((n_prs - conflicts))
echo "  -> $merged_ok merged, $conflicts conflicted"

if [ "$MODE" = pairwise ]; then
  echo
  echo "== pairwise conflict matrix (each pair against $BASE) =="
  echo "   Localizes a conflict to a PAIR. Serial order blames whichever branch"
  echo "   merged second, which is not necessarily the one that should change."
  pw=$(mktemp -d "${TMPDIR:-/tmp}/ferret-pairwise-XXXXXX")
  git worktree add -q --detach "$pw" "$BASE" || exit 2
  found=0
  # Index a file by line number rather than nesting two `while read` loops over
  # the same heredoc: the inner loop would drain the outer loop's stdin and the
  # matrix would silently cover only the first row. Not `mapfile`, because macOS
  # ships bash 3.2 where it does not exist — the script would have reported
  # "0 conflicting pairs" for every input, the worst failure mode for a check.
  pr_file=$(mktemp "${TMPDIR:-/tmp}/ferret-pairs-XXXXXX")
  printf '%s\n' "$prs" > "$pr_file"
  n=$(grep -c . "$pr_file")
  i=0
  while [ "$i" -lt "$n" ]; do
    i=$((i + 1))
    pair_a=$(sed -n "${i}p" "$pr_file")
    a="${pair_a%%:*}"; abr="${pair_a#*:}"
    j=$i
    while [ "$j" -lt "$n" ]; do
      j=$((j + 1))
      pair_b=$(sed -n "${j}p" "$pr_file")
      b="${pair_b%%:*}"; bbr="${pair_b#*:}"
      rc_pair=0
      (
        cd "$pw" || exit 2
        git reset -q --hard >/dev/null 2>&1; git clean -qfd >/dev/null 2>&1
        git checkout -q --detach "$BASE"
        # If A alone does not merge, the serial pass already reported it; a pair
        # result would be noise on top of a known-broken branch.
        git merge -q --no-edit --no-ff "origin/$abr" >/dev/null 2>&1 || exit 0
        if ! git merge -q --no-edit --no-ff "origin/$bbr" >/dev/null 2>&1; then
          printf '  #%s <-> #%s  [%s]\n' "$a" "$b" "$(git diff --name-only --diff-filter=U | tr '\n' ' ')"
          git merge --abort
          exit 7
        fi
      ) || rc_pair=$?
      [ "$rc_pair" -eq 7 ] && found=$((found + 1))
    done
  done
  git worktree remove --force "$pw" >/dev/null 2>&1
  rm -f "$pr_file"
  echo "  -> $found conflicting pair(s)"
fi

# Publish the union locally regardless of test outcome: a red integration branch
# is exactly the thing worth looking at.
head=$(cd "$wt" && git rev-parse HEAD)
git branch -f "$BRANCH" "$head"
echo
echo "== integration branch: $BRANCH ($(git rev-parse --short "$BRANCH")) =="

if [ "$RUN_TESTS" -eq 0 ]; then
  echo "   --no-test: skipping the suite"
  exit 0
fi

echo
echo "== gates on the UNION (this is the part CI never runs) =="
rc=0
(
  cd "$wt" || exit 2
  unf=$(gofmt -l ./cmd ./internal ./pkg 2>/dev/null)
  if [ -n "$unf" ]; then echo "  gofmt   FAIL: $(echo "$unf" | tr '\n' ' ')"; exit 1; fi
  echo "  gofmt   ok"
  go build ./... >/tmp/_int_build 2>&1 || { echo "  build   FAIL (see /tmp/_int_build)"; exit 1; }
  echo "  build   ok"
  go vet ./... >/tmp/_int_vet 2>&1   || { echo "  vet     FAIL (see /tmp/_int_vet)"; exit 1; }
  echo "  vet     ok"

  # -count=1: a cached PASS from a single-PR run proves nothing about the union.
  if go test -count=1 ./cmd/... ./internal/... ./pkg/... >/tmp/_int_suite 2>&1; then
    echo "  suite   ok ($(grep -c '^ok' /tmp/_int_suite) packages)"
  else
    echo "  suite   FAIL:"
    grep -E '^(FAIL|[[:space:]]+--- FAIL|--- FAIL)' /tmp/_int_suite | head -20 | sed 's/^/            /'
    echo "            ^ green individually, red together = a SEMANTIC cross-PR conflict."
    echo "            Resolve it on the branch that lands LATER, not by regenerating blind."
    exit 1
  fi

  # The golden corpus is where cross-PR behavior collisions actually surface: two
  # PRs can each be consistent with their own snapshot and disagree about the
  # union's.
  if [ -d internal/goldencorpus/testdata ]; then
    UPDATE_GOLDEN=1 go test -count=1 ./internal/goldencorpus/ >/dev/null 2>&1
    gd=$(git status --porcelain internal/goldencorpus/testdata/ | grep -c . || true)
    if [ "$gd" -eq 0 ]; then echo "  golden  ok (union moves no snapshot)"
    else
      echo "  golden  DRIFT: $gd file(s) differ on the union"
      git status --porcelain internal/goldencorpus/testdata/ | sed 's/^/            /' | head -10
      exit 1
    fi
  fi

  if go test -race -count=1 ./cmd/... ./internal/... ./pkg/... >/tmp/_int_race 2>&1; then
    echo "  race    ok"
  else
    echo "  race    FAIL: $(grep -E 'DATA RACE|^FAIL' /tmp/_int_race | head -3 | tr '\n' ' ')"
    exit 1
  fi
) || rc=1

echo
if [ "$conflicts" -gt 0 ] || [ "$rc" -ne 0 ]; then
  echo "== NOT clean: $conflicts textual conflict(s), union gates $([ $rc -eq 0 ] && echo passed || echo FAILED) =="
  exit 1
fi
echo "== clean: all $n_prs open PRs merge in series and the union passes every gate =="
