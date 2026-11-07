#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# self-scan.sh — ferret-scan's scan of its own repository (#927): one script for `make self-scan` and
# for CI. docs/testing/SELF_SCAN.md is the guide; this header is the contract.
#
# Two gates, both through the committed profile .ferret-scan/selfscan.yaml (its excludes, each with its
# reason) and the suppression ledger the profile names, at --confidence high, --fail-on-incomplete,
# --limit 0:
#
#   shippable  every file the profile does not exclude that is not *_test.go: Go sources, scripts,
#              workflows, configs, docs. EVERY check.
#   tests      every *_test.go the profile does not exclude: --checks SECRETS only. Synthetic PII in a
#              test is the test's job; a real credential is never a fixture, so a credential in a test
#              is gated like a credential anywhere else.
#
# Counts come from each report's `stats` (`jq -e '.stats.high | numbers'`), never from `results`, and
# stats.suppressed is printed beside them, so a suppressed finding is visible as a suppression (TM-11).
#
# Excluded is not unscanned: a third pass, report-only, scans the paths the profile excluded at MEDIUM
# and above, with no suppressions, and prints the counts by path. It never fails the gate.
#
# Each gate scans a copy of its files laid out at their repository paths (the scan root is the copy,
# so the profile's root-relative excludes and the reported file names read as they do from the
# repository root), which is how `tree` and `changed` go through exactly the same gates.
#
# Usage:
#   scripts/self-scan.sh [--scope tree|changed] [--files LIST] [--base REF] [--mode block|report]
#                        [--suppressions FILE] [--out DIR] [--regenerate FILE] [--print-state]
#
#   --scope tree      the checkout: tracked files plus untracked files git does not ignore (default)
#   --scope changed   the files --files names; without --files, the files that differ from the merge
#                     base of HEAD and --base REF (committed, staged, unstaged, and untracked files)
#   --files LIST      a file of repository-relative paths, one per line, any extension (CI writes it
#                     with `git diff --name-only --diff-filter=ACMR`); implies --scope changed
#   --base REF        also build REF (`git archive` into a scratch directory, as scripts/corpus-ab.sh
#                     does), run the same gates over REF's files with THIS checkout's profile and ledger,
#                     and print the findings that are new, lost and changed against REF, by file class,
#                     keyed on (file, validator, type, line, sha256(text)). The text is hashed in memory
#                     and shown as 12 hex digits; it is never printed or written. Needs python3.
#   --mode block      HIGH > 0 fails, exit 1 (the default, and what CI runs)
#   --mode report     HIGH is reported and does not fail; a scan that fails or is incomplete still exits 2
#   --suppressions F  read F instead of the ledger the profile names (to try a candidate ledger)
#   --out DIR         write the reports to DIR (default: a new directory under $TMPDIR, kept, printed)
#   --regenerate F    write a candidate ledger to F: the current ledger, a disabled rule for every
#                     HIGH finding of either gate that no rule covers, the rules the binary re-anchored
#                     or migrated rewritten, and every other rule kept byte for byte. Prints the new,
#                     rewritten and stale rules. Review F, then copy it over the ledger. Needs python3.
#   --print-state     print the checkout state a green tree run records, and exit (scripts/pr-checklist.sh)
#
# Environment: FERRET_BIN, a binary to use instead of building ./cmd; FERRET_BASE_BIN, likewise for
# --base; GOFLAGS (default -mod=mod).
#
# Exit status: 0 green; 1 HIGH present in block mode; 2 a scan failed or did not fully examine a file, a
# count was missing or not a number, or the arguments or setup were wrong. Every run that gets as far as
# scanning writes <out>/summary.env (high, suppressed, not_examined, scope, mode, exit) and keeps the
# reports there; the matched text is in none of them. A green block-mode run of the whole tree is
# recorded in $(git rev-parse --git-dir)/self-scan.ok for scripts/pr-checklist.sh.
#
# Needs bash (3.2 is enough), git, tar and jq, plus go unless FERRET_BIN is set. CI runs it on ubuntu
# only; it is written for macOS's bash 3.2 and BSD tar as well.
#
set -uo pipefail

die() {
    echo "self-scan: $*" >&2
    exit 2
}

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run this inside a ferret-scan checkout"
cd "$repo" || die "cannot enter $repo"

# checkout_state prints a tree object for the checkout as it is on disk: tracked and untracked files,
# ignored files excluded. It names the CONTENT that was scanned, so committing exactly what was scanned
# keeps the marker valid and any edit invalidates it. A private index is used; the real one is untouched.
# The same definition as scripts/surface-parity.sh's.
checkout_state() {
    local idx
    idx="$(mktemp "${TMPDIR:-/tmp}/self-scan-index.XXXXXX")" || return 1
    GIT_INDEX_FILE="$idx" git read-tree HEAD &&
        GIT_INDEX_FILE="$idx" git add -A &&
        GIT_INDEX_FILE="$idx" git write-tree
    local rc=$?
    rm -f "$idx"
    return "$rc"
}

usage() {
    sed -n '/^# Usage:/,/^# Exit status:/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
}

scope="" files="" base="" mode="block" ledger_arg="" out="" regenerate=""
while [ $# -gt 0 ]; do
    case "$1" in
        --scope | --files | --base | --mode | --suppressions | --out | --regenerate)
            [ $# -ge 2 ] || die "$1 needs a value"
            case "$1" in
                --scope) scope="$2" ;;
                --files) files="$2" ;;
                --base) base="$2" ;;
                --mode) mode="$2" ;;
                --suppressions) ledger_arg="$2" ;;
                --out) out="$2" ;;
                --regenerate) regenerate="$2" ;;
            esac
            shift 2
            ;;
        --print-state)
            checkout_state || die "could not compute the checkout state"
            exit 0
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown argument '$1' (see --help)" ;;
    esac
done

case "$mode" in block | report) ;; *) die "--mode is '$mode'; it must be block or report" ;; esac
if [ -n "$files" ]; then
    [ -z "$scope" ] || [ "$scope" = changed ] || die "--files names the changed files; it cannot go with --scope $scope"
    scope=changed
fi
scope="${scope:-tree}"
case "$scope" in tree | changed) ;; *) die "--scope is '$scope'; it must be tree or changed" ;; esac
if [ "$scope" = changed ] && [ -z "$files" ] && [ -z "$base" ]; then
    die "--scope changed needs --files LIST, or --base REF to diff against"
fi
if [ -n "$files" ] && [ ! -f "$files" ]; then
    die "--files $files is not a file"
fi

for tool in git tar jq; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
if [ -n "$base" ] || [ -n "$regenerate" ]; then
    command -v python3 >/dev/null 2>&1 || die "python3 is required for --base and --regenerate"
fi

profile="$repo/.ferret-scan/selfscan.yaml"
[ -f "$profile" ] || die "the profile $profile is missing"

# The ledger is the profile's suppressions.file, read with the one shape this committed file uses:
# a top-level `suppressions:` block holding `file: <path>`.
ledger_rel="$(awk '
    /^suppressions:[[:space:]]*$/ { inblock = 1; next }
    inblock && /^[^[:space:]#]/ { inblock = 0 }
    inblock && $1 == "file:" { v = $2; gsub(/^["\047]|["\047]$/, "", v); print v; exit }
' "$profile")"
if [ -n "$ledger_arg" ]; then
    ledger="$ledger_arg"
else
    [ -n "$ledger_rel" ] || die "$profile names no suppressions.file"
    ledger="$ledger_rel"
fi
case "$ledger" in /*) ;; *) ledger="$repo/$ledger" ;; esac
[ -f "$ledger" ] || die "the suppression ledger $ledger is missing; without it every reviewed finding would be reported"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/self-scan.XXXXXX")" || die "mktemp failed"
tmp="$(cd "$tmp" && pwd -P)" || die "cannot resolve $tmp"
trap 'rm -rf "$tmp"' EXIT
if [ -n "$out" ]; then
    mkdir -p "$out" || die "cannot create $out"
else
    out="$(mktemp -d "${TMPDIR:-/tmp}/self-scan-out.XXXXXX")" || die "mktemp failed"
fi
out="$(cd "$out" && pwd -P)" || die "cannot resolve $out"

# ---------------------------------------------------------------------------------------------------
# Binaries

absolute() {
    case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$repo/$1" ;; esac
}

mkdir -p "$tmp/bin"
if [ -n "${FERRET_BIN:-}" ]; then
    bin="$(absolute "$FERRET_BIN")"
    [ -x "$bin" ] || die "FERRET_BIN=$FERRET_BIN is not an executable file"
else
    command -v go >/dev/null 2>&1 || die "go is required to build ./cmd (or set FERRET_BIN)"
    export GOFLAGS="${GOFLAGS:--mod=mod}"
    bin="$tmp/bin/ferret-scan"
    echo "self-scan: building ./cmd"
    go build -trimpath -o "$bin" ./cmd >"$out/build.log" 2>&1 || {
        cat "$out/build.log" >&2
        die "building ./cmd failed"
    }
fi

base_sha=""
if [ -n "$base" ]; then
    base_sha="$(git rev-parse --verify --quiet "${base}^{commit}")" || die "--base '$base' is not a commit"
fi

# ---------------------------------------------------------------------------------------------------
# File lists (NUL-separated, sorted, repository-relative)

# split_list <root> <list>: keep the entries that are files under <root>, and write them to
# <list>.shippable and <list>.tests. A file that cannot be read goes to <list>.unreadable: it cannot
# be copied, let alone scanned, and the run fails closed on it below.
split_list() {
    local root="$1" list="$2" f
    : >"$list.shippable"
    : >"$list.tests"
    : >"$list.unreadable"
    while IFS= read -r -d '' f; do
        [ -f "$root/$f" ] || [ -L "$root/$f" ] || continue
        if [ -f "$root/$f" ] && [ ! -r "$root/$f" ]; then
            printf '%s\0' "$f" >>"$list.unreadable"
            continue
        fi
        case "$f" in
            *_test.go) printf '%s\0' "$f" >>"$list.tests" ;;
            *) printf '%s\0' "$f" >>"$list.shippable" ;;
        esac
    done <"$list"
}

# read_files_list <LIST> <out>: the --files list, validated. A name this checkout cannot scan as given
# is an error rather than a skip: a changed file that is silently not scanned passes the gate.
read_files_list() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [ -n "$line" ] || continue
        case "$line" in
            \"*) die "--files: '$line' is a name git quoted; write the list with git -c core.quotePath=false" ;;
            /* | .. | ../* | */../* | */..) die "--files: '$line' is not a path inside the repository" ;;
        esac
        line="${line#./}"
        { [ -f "$line" ] || [ -L "$line" ]; } || die "--files: '$line' is not a file in this checkout"
        printf '%s\0' "$line"
    done <"$1" >"$2.unsorted"
    sort -zu "$2.unsorted" >"$2"
}

head_list="$tmp/head.lst"
if [ "$scope" = tree ]; then
    git ls-files -z --cached --others --exclude-standard | sort -zu >"$head_list" ||
        die "git ls-files failed"
elif [ -n "$files" ]; then
    read_files_list "$files" "$head_list"
else
    merge_base="$(git merge-base "$base_sha" HEAD)" || die "no merge base between $base and HEAD"
    {
        git -c core.quotePath=false diff --name-only -z --diff-filter=ACMR "$merge_base" &&
            git ls-files -z --others --exclude-standard
    } | sort -zu >"$head_list" || die "listing the changed files failed"
fi
split_list "$repo" "$head_list"

# stage <root> <list> <dest>: copy the listed files under <root> to the same paths under <dest>.
stage() {
    mkdir -p "$3" || return 1
    [ -s "$2" ] || return 0
    (cd "$1" && tar -c -f - --null -T "$2") | tar -x -f - -C "$3"
}

for g in shippable tests; do
    stage "$repo" "$head_list.$g" "$tmp/head/$g" || die "staging the $g files failed"
done

# ---------------------------------------------------------------------------------------------------
# Gates

gate_checks() {
    case "$1" in shippable) echo all ;; tests) echo SECRETS ;; esac
}

status=0
fail_closed() {
    echo "  ❌ $*"
    status=2
}

# run_gate <side> <gate> <binary> <ledger> [extra flags...]: one gate over the staged copy, report in
# $out/<side>-<gate>.json. Reads the counts into g_high, g_suppressed, g_processed, g_not_examined.
run_gate() {
    local side="$1" gate="$2" b="$3" rules="$4"
    shift 4
    local dir="$tmp/$side/$gate" report="$out/$side-$gate.json" errlog="$out/$side-$gate.stderr.log"
    local n rc=0
    n="$(tr -cd '\0' <"$tmp/$side.lst.$gate" | wc -c | tr -d ' ')"
    g_high=0 g_suppressed=0 g_processed=0 g_not_examined=0
    if [ "$n" -eq 0 ]; then
        echo '{"stats":{"high":0,"medium":0,"low":0,"suppressed":0,"files_processed":0},"results":[]}' >"$report"
        : >"$errlog"
        printf '  %-10s no files in scope\n' "$gate"
        return 0
    fi
    (cd "$dir" && "$b" --file . --recursive --config "$profile" --suppression-file "$rules" \
        --checks "$(gate_checks "$gate")" --confidence high --fail-on-incomplete --limit 0 \
        --format json --no-color --quiet --show-suppressed "$@") >"$report" 2>"$errlog" || rc=$?
    # The exclusions feed the report-only pass and are counted, not echoed one per path.
    grep -v ': excluded by --exclude pattern$' "$errlog" | sed 's/^/    | /'
    if [ "$rc" -ne 0 ]; then
        fail_closed "$gate: ferret-scan exited $rc (3 is --fail-on-incomplete: a file was not fully examined); stderr: $errlog"
    fi
    g_high="$(jq -e '.stats.high | numbers' "$report")" || {
        fail_closed "$gate: .stats.high is missing or not a number in $report"
        g_high=0
    }
    g_suppressed="$(jq -e '.stats.suppressed | numbers' "$report")" || {
        fail_closed "$gate: .stats.suppressed is missing or not a number in $report"
        g_suppressed=0
    }
    g_processed="$(jq -e '.stats.files_processed | numbers' "$report")" || {
        fail_closed "$gate: .stats.files_processed is missing or not a number in $report"
        g_processed=0
    }
    g_not_examined="$(jq -e '.stats.files_not_examined // 0 | numbers' "$report")" || {
        fail_closed "$gate: .stats.files_not_examined is not a number in $report"
        g_not_examined=0
    }
    if [ "$g_not_examined" -gt 0 ]; then
        fail_closed "$gate: $g_not_examined file(s) were not fully examined, so findings may be missing"
    fi
    local excluded
    excluded="$(grep -c ': excluded by --exclude pattern$' "$errlog")"
    printf '  %-10s %5d files listed, %5d scanned, %3d paths excluded by the profile   HIGH %d   suppressed %d\n' \
        "$gate" "$n" "$g_processed" "$excluded" "$g_high" "$g_suppressed"
}

if [ -n "$regenerate" ]; then
    cp "$ledger" "$tmp/candidate.yaml" || die "cannot copy $ledger"
    gate_ledger="$tmp/candidate.yaml"
else
    gate_ledger="$ledger"
fi

echo "self-scan: scope $scope, mode $mode, profile ${profile#"$repo"/}, ledger ${ledger#"$repo"/}"
unreadable="$(tr -cd '\0' <"$head_list.unreadable" | wc -c | tr -d ' ')"
if [ "$unreadable" -gt 0 ]; then
    echo "  NOT FULLY EXAMINED: $unreadable file(s) could not be read, so they were not scanned:"
    tr '\0' '\n' <"$head_list.unreadable" | sed 's/^/    /'
    fail_closed "$unreadable file(s) could not be read"
fi
not_examined="$unreadable"
if [ -n "$regenerate" ]; then
    # Two generation passes. In one pass, a second finding on the same line that matches a rule just
    # written there through an older hash formula takes that rule over (the generator migrates it), and
    # the first finding is left with none; the second pass writes the rule it lacks. A pass that has
    # nothing to add changes nothing, so the second is a no-op on most trees.
    echo "self-scan: --regenerate pass 1 of 2"
    for g in shippable tests; do
        run_gate head "$g" "$bin" "$gate_ledger" --generate-suppressions
    done
    echo "self-scan: --regenerate pass 2 of 2"
fi
total_high=0
total_suppressed=0
for g in shippable tests; do
    if [ -n "$regenerate" ]; then
        run_gate head "$g" "$bin" "$gate_ledger" --generate-suppressions
    else
        run_gate head "$g" "$bin" "$gate_ledger"
    fi
    total_high=$((total_high + g_high))
    total_suppressed=$((total_suppressed + g_suppressed))
    not_examined=$((not_examined + g_not_examined))
    if [ "$g_high" -gt 0 ]; then
        echo "    HIGH findings ($g, not suppressed; type, file:line, validator, confidence):"
        jq -r '.results[] | select(.confidence_level == "HIGH")
            | "      \(.type)  \(.filename):\(.line_number)  \(.validator)  \(.confidence)"' \
            "$out/head-$g.json" | sort | head -n 100
        if [ "$g_high" -gt 100 ]; then echo "      ... the first 100 of $g_high; all are in $out/head-$g.json"; fi
    fi
done

# ---------------------------------------------------------------------------------------------------
# Excluded is not unscanned: report-only, MEDIUM and above, no suppressions

echo "self-scan: excluded paths (report-only: all checks, MEDIUM and above, no suppressions)"
for g in shippable tests; do
    errlog="$out/head-$g.stderr.log"
    [ -f "$errlog" ] || continue
    sed -n 's/^Warning: Skipping \(.*\): excluded by --exclude pattern$/\1/p' "$errlog" |
        while IFS= read -r p; do printf '%s\n' "${p#"$tmp/head/$g"/}"; done >"$tmp/excluded.$g"
    [ -s "$tmp/excluded.$g" ] || continue
    echo "  $g gate: $(grep -c . "$tmp/excluded.$g") path(s) excluded by the profile"
    n=0
    # One scan per excluded path, so each count is that report's own stats.
    while IFS= read -r p; do
        n=$((n + 1))
        report="$out/head-$g-excluded-$n.json"
        rc=0
        (cd "$tmp/head/$g" && "$bin" --file "$p" --recursive --config /dev/null \
            --suppression-file "$tmp/no-rules.yaml" --checks all --confidence high,medium --limit 0 \
            --format json --no-color --quiet) >"$report" 2>"$report.stderr.log" || rc=$?
        h="$(jq -e '.stats.high | numbers' "$report")" || h="?"
        m="$(jq -e '.stats.medium | numbers' "$report")" || m="?"
        note=""
        if [ "$rc" -ne 0 ]; then note="  (ferret-scan exited $rc; report-only, so the gate is unaffected)"; fi
        printf '    %6s HIGH %6s MEDIUM  %s%s\n' "$h" "$m" "$p" "$note"
    done <"$tmp/excluded.$g"
done

# ---------------------------------------------------------------------------------------------------
# --base: the same gates over REF, and what moved

# hash_rows <side> <gate>: rows for every HIGH or MEDIUM finding, suppressed or not, as
# file, validator, type, line, sha256(text)[:12], confidence, suppressed. The binary's output carries the
# matched text (--show-match) and goes straight into python, which keeps only the digest.
hash_rows() {
    local side="$1" gate="$2" b="$3" rc=0
    local dir="$tmp/$side/$gate" rows="$out/$side-$gate.rows.tsv"
    if [ ! -s "$tmp/$side.lst.$gate" ]; then
        : >"$rows"
        return 0
    fi
    (cd "$dir" && "$b" --file . --recursive --config "$profile" --suppression-file "$ledger" \
        --checks "$(gate_checks "$gate")" --confidence high,medium --fail-on-incomplete --limit 0 \
        --format json --no-color --quiet --show-suppressed --show-match) 2>"$out/$side-$gate.rows.stderr.log" |
        python3 -c '
import hashlib, json, sys
doc = json.load(sys.stdin)
def digest(text):
    return hashlib.sha256((text or "").encode("utf-8", "surrogatepass")).hexdigest()[:12]
out = sys.stdout
for r in doc.get("results") or []:
    out.write("\t".join([r["filename"], r["validator"], r["type"], str(r["line_number"]),
                         digest(r.get("text")), str(r["confidence"]), "0"]) + "\n")
for s in doc.get("suppressed") or []:
    f = s["finding"]
    if f["Confidence"] >= 60:
        out.write("\t".join([f["Filename"], f["Validator"], f["Type"], str(f["LineNumber"]),
                             digest(f.get("Text")), str(f["Confidence"]), "1"]) + "\n")
' >"$rows"
    local codes=("${PIPESTATUS[@]}")
    rc="${codes[0]}"
    if [ "$rc" -ne 0 ] || [ "${codes[1]}" -ne 0 ]; then
        fail_closed "--base $side $gate: the comparison scan failed (ferret-scan $rc, digest ${codes[1]})"
    fi
}

if [ -n "$base" ]; then
    echo "self-scan: --base $base (${base_sha:0:12}): the same gates over its files, this checkout's profile and ledger"
    mkdir -p "$tmp/base-src"
    git archive --format=tar "$base_sha" | tar -x -f - -C "$tmp/base-src" || die "git archive $base failed"
    if [ -n "${FERRET_BASE_BIN:-}" ]; then
        base_bin="$(absolute "$FERRET_BASE_BIN")"
        [ -x "$base_bin" ] || die "FERRET_BASE_BIN=$FERRET_BASE_BIN is not an executable file"
    else
        command -v go >/dev/null 2>&1 || die "go is required to build $base (or set FERRET_BASE_BIN)"
        export GOFLAGS="${GOFLAGS:--mod=mod}"
        base_bin="$tmp/bin/ferret-scan-base"
        echo "self-scan: building $base"
        (cd "$tmp/base-src" && go build -trimpath -o "$base_bin" ./cmd) >"$out/build-base.log" 2>&1 || {
            cat "$out/build-base.log" >&2
            die "building $base failed"
        }
    fi
    base_list="$tmp/base.lst"
    if [ "$scope" = tree ]; then
        git ls-tree -r -z --name-only "$base_sha" | sort -zu >"$base_list" || die "git ls-tree $base failed"
    else
        cp "$head_list" "$base_list"
    fi
    split_list "$tmp/base-src" "$base_list"
    for g in shippable tests; do
        stage "$tmp/base-src" "$base_list.$g" "$tmp/base/$g" || die "staging the $g files of $base failed"
        run_gate base "$g" "$base_bin" "$ledger"
        hash_rows base "$g" "$base_bin"
        hash_rows head "$g" "$bin"
    done
    if ! python3 - "$out" <<'PY'; then
import collections, os, sys

out = sys.argv[1]

def file_class(name):
    if name.endswith("_test.go"):
        return "*_test.go"
    if name.startswith("internal/validators/") and name.endswith(".go"):
        return "validators .go"
    if name.endswith(".go"):
        return "other .go"
    if name.startswith("docs/"):
        return "docs/"
    if name.endswith(".md"):
        return "other .md"
    if name.endswith((".sh", ".py", ".ps1")):
        return "scripts"
    if name.endswith((".yml", ".yaml", ".json", ".toml", ".env", ".conf", ".cfg", ".ini")):
        return "configs"
    return "other"

def load(side):
    rows = []
    for gate in ("shippable", "tests"):
        path = os.path.join(out, f"{side}-{gate}.rows.tsv")
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                f, v, t, ln, h, conf, supp = line.rstrip("\n").split("\t")
                rows.append((f, v, t, int(ln), h, float(conf), supp == "1"))
    return rows

def band(conf):
    return "HIGH" if conf >= 90 else "MEDIUM"

base, head = load("base"), load("head")
by_key = collections.defaultdict(lambda: ([], []))
for r in base:
    by_key[r[:5]][0].append(r)
for r in head:
    by_key[r[:5]][1].append(r)

new, lost, changed = [], [], []
for key in sorted(by_key):
    b, h = (sorted(x, key=lambda r: (r[5], r[6])) for x in by_key[key])
    for rb, rh in zip(b, h):
        if band(rb[5]) != band(rh[5]) or rb[6] != rh[6] or rb[5] != rh[5]:
            if "HIGH" in (band(rb[5]), band(rh[5])):
                changed.append((rb, rh, ""))
    lost.extend(b[len(h):])
    new.extend(h[len(b):])

# A finding whose line moved is the same finding: pair what is left by (file, validator, type, text).
def pair_moves(lost, new):
    pool = collections.defaultdict(list)
    for r in lost:
        pool[(r[0], r[1], r[2], r[4])].append(r)
    still_new = []
    for r in new:
        k = (r[0], r[1], r[2], r[4])
        if pool[k]:
            rb = pool[k].pop(0)
            if "HIGH" in (band(rb[5]), band(r[5])):
                changed.append((rb, r, "moved"))
        else:
            still_new.append(r)
    still_lost = [r for v in pool.values() for r in v]
    return still_lost, still_new

lost, new = pair_moves(lost, new)
new = [r for r in new if band(r[5]) == "HIGH"]
lost = [r for r in lost if band(r[5]) == "HIGH"]

def describe(r):
    supp = "  suppressed" if r[6] else ""
    return f"{r[2]}  {r[0]}:{r[3]}  {r[1]}  {r[5]:g}  #{r[4]}{supp}"

classes = collections.OrderedDict()
for name, items, cls in (("new", new, lambda r: file_class(r[0])), ("lost", lost, lambda r: file_class(r[0])),
                         ("changed", changed, lambda c: file_class(c[1][0]))):
    for it in items:
        classes.setdefault(cls(it), collections.Counter())[name] += 1

print(f"  HIGH findings against the base: {len(new)} new, {len(lost)} lost, {len(changed)} changed "
      "(keyed on file, validator, type, line, sha256(text); a line move counts as changed)")
if classes:
    print(f"    {'file class':<16} {'new':>5} {'lost':>5} {'changed':>8}")
    for cls in sorted(classes):
        c = classes[cls]
        print(f"    {cls:<16} {c['new']:>5} {c['lost']:>5} {c['changed']:>8}")
for title, items in (("new", new), ("lost", lost)):
    if items:
        print(f"  {title} (type, file:line, validator, confidence, #sha256(text)[:12]):")
        for r in sorted(items, key=lambda r: (file_class(r[0]), r[0], r[3])):
            print(f"    {describe(r)}")
if changed:
    print("  changed (base -> this checkout):")
    for rb, rh, why in sorted(changed, key=lambda c: (file_class(c[1][0]), c[1][0], c[1][3])):
        what = []
        if why:
            what.append(f"line {rb[3]} -> {rh[3]}")
        if rb[5] != rh[5]:
            what.append(f"confidence {rb[5]:g} -> {rh[5]:g}")
        if rb[6] != rh[6]:
            what.append("now suppressed" if rh[6] else "no longer suppressed")
        print(f"    {describe(rh)}  ({', '.join(what)})")
PY
        fail_closed "--base: the comparison could not be computed"
    fi
fi

# ---------------------------------------------------------------------------------------------------
# --regenerate: the candidate ledger

if [ -n "$regenerate" ] && [ "$status" -eq 0 ]; then
    python3 - "$ledger" "$tmp/candidate.yaml" "$regenerate" <<'PY' || fail_closed "--regenerate: the candidate ledger could not be written"
import re, sys

orig_path, regen_path, out_path = sys.argv[1:4]
RULE = re.compile(r"^(\s*)- id:\s*(\S+)\s*$")

def split(path):
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if re.match(r"^rules:\s*$", l)), None)
    if start is None:
        sys.exit(f"{path}: no top-level rules: key")
    header, blocks, indent = lines[: start + 1], [], None
    for line in lines[start + 1:]:
        m = RULE.match(line)
        if m and (indent is None or len(m.group(1)) == indent):
            indent = len(m.group(1))
            blocks.append([m.group(2), [line]])
        elif blocks and (not line.strip() or line.startswith(" " * (indent + 1))):
            blocks[-1][1].append(line)
        else:
            sys.exit(f"{path}: a line this script does not understand after the rules began: {line!r}")
    return header, blocks

def field(block, key):
    for line in block:
        m = re.match(r'^\s+' + key + r':\s*"?([^"#\s]*)"?', line)
        if m:
            return m.group(1)
    return ""

header, orig_blocks = split(orig_path)
_, regen_blocks = split(regen_path)
orig = {rid: block for rid, block in orig_blocks}
regen_ids = {rid for rid, _ in regen_blocks}
missing = [rid for rid in orig if rid not in regen_ids]
if missing:
    sys.exit(f"the regenerated file lost rules {missing[:5]}; refusing to write a candidate")

def number(rid):
    m = re.match(r"^SUP-(\d+)$", rid)
    return int(m.group(1)) if m else 0

kept, rewritten, stale, new, dropped = [], [], [], [], 0
result = []
next_id = max([number(rid) for rid in orig] + [0]) + 1
for rid, block in regen_blocks:
    if rid in orig:
        ob = orig[rid]
        if field(block, "hash") == field(ob, "hash") and field(block, "line_number") == field(ob, "line_number"):
            result.append(ob)
            kept.append(rid)
            if field(block, "last_seen_at") == field(ob, "last_seen_at"):
                stale.append(rid)
        else:
            result.append(block)
            rewritten.append(rid)
    elif float(field(block, "confidence") or 0) >= 90:
        # The binary numbered this rule after every rule it generated, the dropped ones included; the
        # candidate numbers the rules it keeps in order instead.
        new_id = f"SUP-{next_id:08d}"
        next_id += 1
        indent = RULE.match(block[0]).group(1)
        block = [f"{indent}- id: {new_id}\n"] + block[1:]
        result.append(block)
        new.append(new_id)
    else:
        dropped += 1

with open(out_path, "w", encoding="utf-8") as fh:
    fh.write("".join(header))
    for block in result:
        fh.write("".join(block))

def label(rid, block):
    return (f"{rid}  {field(block, 'finding_type')}  {field(block, 'filename')}:{field(block, 'line_number')}"
            f"  confidence {field(block, 'confidence')}")

blocks = {}
for block in result:
    m = RULE.match(block[0])
    blocks[m.group(2)] = block
print(f"self-scan: candidate ledger {out_path}: {len(kept)} rules kept as they were, {len(rewritten)} rewritten "
      f"(re-anchored or migrated by the binary), {len(new)} new and DISABLED (review each), {dropped} generated "
      f"rules for findings below HIGH dropped, {len(stale)} kept rules matched nothing in this run")
for title, ids in (("new, disabled until reviewed", new), ("rewritten", rewritten), ("stale (no finding matched)", stale)):
    if ids:
        print(f"  {title}:")
        for rid in ids:
            print(f"    {label(rid, blocks[rid])}")
PY
fi

# ---------------------------------------------------------------------------------------------------
# Verdict

echo "self-scan: HIGH $total_high (not suppressed), suppressed $total_suppressed; reports in $out"
marker="$(git rev-parse --git-dir)/self-scan.ok"
if [ "$scope" = tree ] && [ -z "$regenerate" ]; then rm -f "$marker"; fi

# summary.env: the run's verdict as NAME=value lines, for a caller that reads it (CI).
summary() {
    printf 'high=%s\nsuppressed=%s\nnot_examined=%s\nscope=%s\nmode=%s\nexit=%s\n' \
        "$total_high" "$total_suppressed" "$not_examined" "$scope" "$mode" "$1" >"$out/summary.env"
    exit "$1"
}
if [ "$status" -ne 0 ]; then
    echo "self-scan: FAILED CLOSED: a scan did not complete or a count could not be read (exit 2)"
    summary 2
fi
if [ -n "$regenerate" ]; then
    summary 0
fi
if [ "$total_high" -gt 0 ]; then
    if [ "$mode" = block ]; then
        echo "self-scan: BLOCKED: $total_high HIGH finding(s). Each one is a decision: a real value is removed;"
        echo "  a detector false positive is fixed in the validator, with a 'detector FP: #NNN' rule meanwhile;"
        echo "  a fixture takes a reserved value or a 'fixture: <why>' rule. See docs/testing/SELF_SCAN.md."
        summary 1
    fi
    echo "self-scan: $total_high HIGH finding(s) reported; --mode report, so they do not fail this run"
    summary 0
fi
if [ "$scope" = tree ] && [ "$mode" = block ]; then
    state="$(checkout_state)" &&
        printf 'state=%s\nbase=%s\nwhen=%s\n' "$state" "${base:+$base@${base_sha:0:12}}" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$marker" &&
        echo "self-scan: green; recorded for scripts/pr-checklist.sh in $marker"
fi
echo "self-scan: green"
summary 0
