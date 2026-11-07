#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# surface-parity.sh -- hold the web UI and the container to the CLI's contract (#907).
#
# The same inputs go through the four surfaces ferret-scan ships, and the results are diffed:
#
#   1 cli            the host binary, built from this checkout
#   2 web            that binary's --web, bound to 127.0.0.1
#   3 container-cli  the image in CLI mode: docker create + docker cp, no bind mount, no -p
#   4 container-web  the image's --web, published on 127.0.0.1 only
#
# Usage:
#   scripts/surface-parity.sh [--image REF] [--surfaces LIST] [--include-private] [--keep]
#   make surface-parity [SURFACE_PARITY_ARGS="--surfaces host"] [CORPUS=/abs/dir]
#
#   --image REF        Use a prebuilt image instead of building ferret-scan:surface-parity from this
#                      checkout. Set VERSION and GIT_COMMIT to the values the image was built with,
#                      or the version fact fails (CI passes the smoke image and its build arguments).
#   --surfaces LIST    Comma list of cli, web, container-cli, container-web; `host` is cli,web and
#                      `container` is container-cli,container-web. Default: all four.
#   --include-private  Also scan $CORPUS/private/, printing AGGREGATES ONLY: counts by type and
#                      timings, never a file name, a path below private/ or a matched value.
#   --keep             Keep the work directory (raw and normalised outputs) and print its path.
#   --print-state      Print the checkout state a green run records, and exit (pr-checklist.sh).
#
# Environment:
#   CORPUS=DIR         Also run every file under DIR through every surface; DIR/private/ is skipped
#                      unless --include-private.
#   CONTAINER_CMD      docker (default) or finch.
#   VERSION, GIT_COMMIT  Stamped into the host binary and into the image this script builds.
#                      Default: `git describe --tags --always` and `git rev-parse --short HEAD`.
#
# Every surface runs with --config /dev/null --confidence all --limit 0 --format json --show-match,
# every check, preprocessors on (the default), and a suppression file that does not exist, so no
# user configuration and no suppression rule reaches any surface.
#
# Network exposure: the host web server binds 127.0.0.1 explicitly; the container's port is published
# as 127.0.0.1:<port>:8080 and the script refuses any other form. After each start it prints the
# listeners (`ss -ltn`, or lsof where ss is absent) and `docker port`, and fails if any address other
# than 127.0.0.1 appears. Inside the container the server binds 0.0.0.0 (FERRET_CONTAINER_MODE=true);
# the loopback publish is the boundary.
#
# Exit status: 0 when every assertion held; 1 on any unexplained difference, surviving value or
# failed runtime fact (a non-loopback listener included); 2 on a usage or setup error. A green run of
# all four surfaces writes $(git rev-parse --git-dir)/surface-parity.ok with the checkout state, which
# scripts/pr-checklist.sh reads; any other outcome removes it.
#
# Work directory layout (read by scripts/surface-parity/spreport):
#   bin/                      the host binary and spreport
#   inputs/golden/            the golden-corpus inputs (TestDumpInputs)
#   sets.tsv                  set<TAB>host root<TAB>aggregate-only (0|1)
#   raw/facts.tsv             PASS|FAIL|INFO<TAB>fact<TAB>value
#   raw/<set>/files.tsv       NNNNN<TAB>path relative to the set root
#   raw/<set>/cli.json|.meta|.err            surface 1, one recursive run
#   raw/<set>/container-cli.json|.meta|.err  surface 3, one recursive run
#   raw/<set>/web/NNNNN.json, web.times.tsv  surface 2, one /scan per file
#   raw/<set>/container-web/..., container-web.times.tsv
#   raw/<set>/export/<surface>/<chunk>.<show>.<format>[.code]   /export bodies
#   raw/<set>/redact/<strategy>__<dir>/run.json|run.meta|extracted/   container redaction runs
#
# Full documentation: docs/testing/SURFACE_PARITY.md.

set -euo pipefail

die() {
    echo "surface-parity: $*" >&2
    exit 2
}

repo="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run this inside a ferret-scan checkout"
cd "$repo"

# checkout_state prints a tree object for the checkout as it is on disk: tracked and untracked files,
# ignored files excluded. It names the CONTENT that was tested, so committing what was tested keeps
# the marker valid and any edit invalidates it. A private index is used; the real one is untouched.
checkout_state() {
    local idx
    idx="$(mktemp "${TMPDIR:-/tmp}/surface-parity-index.XXXXXX")"
    GIT_INDEX_FILE="$idx" git read-tree HEAD
    GIT_INDEX_FILE="$idx" git add -A
    GIT_INDEX_FILE="$idx" git write-tree
    rm -f "$idx"
}

image=""
surfaces_arg="all"
include_private=0
keep=0
while [ $# -gt 0 ]; do
    case "$1" in
        --image) [ $# -ge 2 ] || die "--image needs a value"; image="$2"; shift 2 ;;
        --image=*) image="${1#*=}"; shift ;;
        --surfaces) [ $# -ge 2 ] || die "--surfaces needs a value"; surfaces_arg="$2"; shift 2 ;;
        --surfaces=*) surfaces_arg="${1#*=}"; shift ;;
        --include-private) include_private=1; shift ;;
        --keep) keep=1; shift ;;
        --print-state) checkout_state; exit 0 ;;
        -h | --help) awk 'NR >= 6 && /^set -euo pipefail/ { exit } NR >= 6' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

surfaces=""
for s in $(echo "$surfaces_arg" | tr ',' ' '); do
    case "$s" in
        all) surfaces="$surfaces,cli,web,container-cli,container-web" ;;
        host) surfaces="$surfaces,cli,web" ;;
        container) surfaces="$surfaces,container-cli,container-web" ;;
        cli | web | container-cli | container-web) surfaces="$surfaces,$s" ;;
        *) die "unknown surface '$s' (cli, web, container-cli, container-web, host, container, all)" ;;
    esac
done
surfaces="${surfaces#,}"
has() { case ",$surfaces," in *",$1,"*) return 0 ;; esac; return 1; }
uses_container() { has container-cli || has container-web; }

CONTAINER_CMD="${CONTAINER_CMD:-docker}"
for tool in go jq curl tar; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
if uses_container; then
    command -v "$CONTAINER_CMD" >/dev/null 2>&1 || die "$CONTAINER_CMD is required for the container surfaces"
fi
if has web || has container-web; then
    command -v ss >/dev/null 2>&1 || command -v lsof >/dev/null 2>&1 || die "ss or lsof is required to verify listeners"
fi
if [ "$include_private" = 1 ] && [ -z "${CORPUS:-}" ]; then
    die "--include-private needs CORPUS=<dir> with a private/ subdirectory"
fi

marker="$(git rev-parse --git-dir)/surface-parity.ok"
rm -f "$marker"

work="$(mktemp -d "${TMPDIR:-/tmp}/surface-parity.XXXXXX")"
web_pid=""
cids=()
cleanup() {
    if [ -n "$web_pid" ]; then
        kill "$web_pid" 2>/dev/null || true
        wait "$web_pid" 2>/dev/null || true
    fi
    for cid in ${cids[@]+"${cids[@]}"}; do
        "$CONTAINER_CMD" rm -f "$cid" >/dev/null 2>&1 || true
    done
    if [ "$keep" = 1 ]; then
        echo "surface-parity: work directory kept at $work"
    else
        rm -rf "$work"
    fi
}
trap cleanup EXIT

mkdir -p "$work/bin" "$work/raw" "$work/inputs"
facts="$work/raw/facts.tsv"
: > "$facts"
fact() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$facts"; }

# now prints the wall clock in seconds with sub-second precision where the platform has it.
now() {
    if [ -n "${EPOCHREALTIME:-}" ]; then
        echo "$EPOCHREALTIME"
    else
        date +%s.%N 2>/dev/null | sed 's/\.N$//' || date +%s
    fi
}
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'; }

# listeners prints the local address of every TCP listener on port $1, one per line.
listeners() {
    if command -v ss >/dev/null 2>&1; then
        ss -Hltn "sport = :$1" 2>/dev/null | awk '{ print $4 }'
    else
        lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 { print $9 }'
    fi
}
free_port() {
    local p _
    for _ in $(seq 1 50); do
        p=$((20000 + RANDOM % 30000))
        if [ -z "$(listeners "$p")" ]; then
            echo "$p"
            return 0
        fi
    done
    die "no free TCP port found"
}
# check_loopback_listeners records whether every listener on port $2 is on 127.0.0.1. $3=allow-none
# accepts zero visible listeners (a container port with the docker userland proxy disabled).
check_loopback_listeners() {
    local label="$1" port="$2" allow_none="${3:-}" lines bad
    lines="$(listeners "$port" | tr '\n' ' ' | sed 's/ *$//')"
    echo "  $label listeners on :$port: ${lines:-<none visible>}"
    if [ -z "$lines" ]; then
        if [ "$allow_none" = allow-none ]; then
            fact INFO "$label listener :$port" "none visible to ss/lsof (docker port below is authoritative)"
        else
            fact FAIL "$label listener :$port" "nothing is listening"
        fi
        return
    fi
    bad="$(listeners "$port" | grep -v '^127\.0\.0\.1:' || true)"
    if [ -n "$bad" ]; then
        fact FAIL "$label listener :$port" "non-loopback listener: $(echo "$bad" | tr '\n' ' ')"
    else
        fact PASS "$label listener :$port" "$lines"
    fi
}

ldpkg="github.com/awslabs/ferret-scan/v2/internal/version"
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo 0.0.0-development)}"
GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD)}"
bin="$work/bin/ferret-scan"
spreport="$work/bin/spreport"

echo "=== surface-parity: surfaces $surfaces ==="
echo "checkout $(git rev-parse --short HEAD), version $VERSION, commit $GIT_COMMIT"

echo "--- building the host binary and the report tool"
go build -ldflags "-X $ldpkg.Version=$VERSION -X $ldpkg.GitCommit=$GIT_COMMIT" -o "$bin" ./cmd \
    || die "go build ./cmd failed"
go build -o "$spreport" ./scripts/surface-parity/spreport || die "go build spreport failed"

if uses_container && [ -z "$image" ]; then
    image="ferret-scan:surface-parity"
    echo "--- building $image from this checkout"
    build_args=(--build-arg "VERSION=$VERSION" --build-arg "GIT_COMMIT=$GIT_COMMIT"
        --build-arg "BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)")
    # Same rule as scripts/container-build.sh: a builder who configured GOPROXY gets it in the image.
    if [ -n "$(go env -changed GOPROXY 2>/dev/null)" ]; then
        build_args+=(--build-arg "GOPROXY=$(go env GOPROXY)")
    fi
    t0="$(now)"
    if ! "$CONTAINER_CMD" build "${build_args[@]}" -t "$image" . > "$work/image-build.log" 2>&1; then
        tail -n 30 "$work/image-build.log" >&2
        die "image build failed"
    fi
    echo "  built in $(elapsed "$t0" "$(now)")s"
fi

echo "--- materialising the golden-corpus inputs"
mkdir -p "$work/inputs/golden"
# Physical paths throughout (pwd -P), so a symlinked temp directory (macOS /var -> /private/var) is
# spelled the same in the scan arguments and in the paths the report strips.
golden_root="$(cd "$work/inputs/golden" && pwd -P)"
if ! GOLDEN_DUMP_DIR="$golden_root" go test -count=1 -run '^TestDumpInputs$' \
    ./internal/goldencorpus/ > "$work/dump.log" 2>&1; then
    cat "$work/dump.log" >&2
    die "TestDumpInputs failed"
fi
printf 'golden\t%s\t0\n' "$golden_root" > "$work/sets.tsv"
if [ -n "${CORPUS:-}" ]; then
    [ -d "$CORPUS" ] || die "CORPUS=$CORPUS is not a directory"
    corpus_root="$(cd "$CORPUS" && pwd -P)"
    printf 'corpus\t%s\t0\n' "$corpus_root" >> "$work/sets.tsv"
    if [ "$include_private" = 1 ]; then
        [ -d "$corpus_root/private" ] || die "--include-private: $CORPUS/private is not a directory"
        printf 'private\t%s\t1\n' "$corpus_root/private" >> "$work/sets.tsv"
    fi
fi

# Options every surface runs with. The suppression file never exists: it keeps a rule file in the
# user's config directory from suppressing anything on one surface and not another.
scan_opts=(--config /dev/null --confidence all --limit 0 --format json --show-match --quiet --no-color --checks all)
host_supp="$work/no-such-suppressions.yaml"
ctr_supp="/home/ferret/tmp/no-such-suppressions.yaml"
# The CLI infers a pre-commit run from these and then overrides --format; blank them, as
# internal/scorecorpus/executable_test.go does.
precommit_off=(PRE_COMMIT= _PRE_COMMIT_RUNNING= PRE_COMMIT_HOOK= GIT_HOOK_TYPE= MSYSTEM= MINGW_PREFIX= GIT_EXEC_PATH= GITHUB_DESKTOP=)

# ---------------------------------------------------------------------------------------------
# runtime facts

host_version="$("$bin" --version 2>&1 | head -n 1)"
fact INFO "host --version" "$host_version"
# version_and_commit reduces a --version line to "<version> <commit>": the fields both binaries are
# stamped with. built:, go: and platform: are recorded but not compared, because the host binary is
# built here without a date and may be built for another OS or with another Go toolchain.
version_and_commit() { echo "$1" | sed -n 's/^ferret-scan \([^ ]*\) (commit: \([^,]*\),.*/\1 \2/p'; }
if uses_container; then
    ctr_version="$("$CONTAINER_CMD" run --rm "$image" --version 2>&1 < /dev/null | head -n 1)" || true
    fact INFO "container --version" "$ctr_version"
    if [ -n "$(version_and_commit "$host_version")" ] \
        && [ "$(version_and_commit "$host_version")" = "$(version_and_commit "$ctr_version")" ]; then
        fact PASS "version string" "container equals host: $(version_and_commit "$ctr_version") (built:, go:, platform: not compared)"
    else
        fact FAIL "version string" "container '$ctr_version' != host '$host_version'"
    fi
    user="$("$CONTAINER_CMD" image inspect --format '{{.Config.User}}' "$image")"
    tmpdir_env="$("$CONTAINER_CMD" image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" | sed -n 's/^TMPDIR=//p')"
    probe="$("$CONTAINER_CMD" create "$image" --version < /dev/null)"
    cids+=("$probe")
    uid="$("$CONTAINER_CMD" cp "$probe:/etc/passwd" - 2>/dev/null | tar -xOf - 2>/dev/null | awk -F: -v u="$user" '$1 == u { print $3 }')"
    "$CONTAINER_CMD" rm -f "$probe" >/dev/null < /dev/null
    case "$user:$uid" in
        :* | root:* | 0:* | *:0 | *:) fact FAIL "image user" "User='$user' uid='$uid': the image must run as a non-root user" ;;
        *) fact PASS "image user" "User=$user uid=$uid (Dockerfile USER)" ;;
    esac
    if [ -n "$tmpdir_env" ]; then
        fact INFO "image TMPDIR" "$tmpdir_env"
    else
        fact FAIL "image TMPDIR" "the image sets no TMPDIR"
    fi
fi

# ---------------------------------------------------------------------------------------------
# surfaces 1 and 3: one recursive CLI run per input set

exclude_for() { [ "$1" = corpus ] && echo "--exclude private/" || true; }

run_host_cli() { # set root
    local set="$1" root="$2" out="$work/raw/$1" t0 rc
    t0="$(now)"
    # The working directory is / on both CLI surfaces: the image sets no WORKDIR.
    # shellcheck disable=SC2046 # exclude_for is an intentional word list
    (cd / && env "${precommit_off[@]}" "$bin" "${scan_opts[@]}" --suppression-file "$host_supp" \
        --file "$root" --recursive $(exclude_for "$set")) < /dev/null > "$out/cli.json" 2> "$out/cli.err" && rc=0 || rc=$?
    printf 'exit=%s\nseconds=%s\n' "$rc" "$(elapsed "$t0" "$(now)")" > "$out/cli.meta"
}

# stage_tar writes a tar of the set to stdout with every entry under in/, so `docker cp - cid:/home/ferret`
# lands it at /home/ferret/in. The private/ subtree of the corpus set is left out of the archive.
# docker cp makes the copies root-owned with the archived modes, so GNU tar is told to archive every
# entry world-readable: the image's user must be able to read what the host user could.
stage_tar() { # set root
    local stage="$work/stage/$1" modes=()
    mkdir -p "$stage"
    ln -sfn "$2" "$stage/in"
    if tar --version 2>/dev/null | grep -q 'GNU tar'; then
        modes=(--mode=a+rX)
    fi
    if [ "$1" = corpus ]; then
        tar -C "$stage" ${modes[@]+"${modes[@]}"} -chf - --exclude=in/private in
    else
        tar -C "$stage" ${modes[@]+"${modes[@]}"} -chf - in
    fi
}

run_container_cli() { # set root
    local set="$1" root="$2" out="$work/raw/$1" cid t0 rc
    # shellcheck disable=SC2046
    cid="$("$CONTAINER_CMD" create "$image" "${scan_opts[@]}" --suppression-file "$ctr_supp" \
        --file /home/ferret/in --recursive $(exclude_for "$set") < /dev/null)"
    cids+=("$cid")
    stage_tar "$set" "$root" | "$CONTAINER_CMD" cp - "$cid:/home/ferret"
    t0="$(now)"
    "$CONTAINER_CMD" start -a "$cid" < /dev/null > "$out/container-cli.json" 2> "$out/container-cli.err" && rc=0 || rc=$?
    printf 'exit=%s\nseconds=%s\n' "$rc" "$(elapsed "$t0" "$(now)")" > "$out/container-cli.meta"
    "$CONTAINER_CMD" rm -f "$cid" > /dev/null < /dev/null
}

# Redaction inside the container, the way a user runs it: the image's own user, no --user, no extra
# environment, into /tmp/out and /home/ferret/out, under both deterministic strategies.
run_container_redaction() { # set root strategy outdir label
    local set="$1" root="$2" st="$3" od="$4" label="$5" dir cid rc
    dir="$work/raw/$set/redact/${st}__$label"
    mkdir -p "$dir/extracted"
    # shellcheck disable=SC2046
    cid="$("$CONTAINER_CMD" create "$image" --config /dev/null --confidence all --limit 0 --format json \
        --quiet --no-color --checks all --suppression-file "$ctr_supp" --file /home/ferret/in --recursive \
        $(exclude_for "$set") --enable-redaction --redaction-strategy "$st" --redaction-output-dir "$od" < /dev/null)"
    cids+=("$cid")
    stage_tar "$set" "$root" | "$CONTAINER_CMD" cp - "$cid:/home/ferret"
    "$CONTAINER_CMD" start -a "$cid" < /dev/null > "$dir/run.json" 2> "$dir/run.err" && rc=0 || rc=$?
    printf 'exit=%s\n' "$rc" > "$dir/run.meta"
    "$CONTAINER_CMD" cp "$cid:$od" - 2> /dev/null < /dev/null | tar -xf - -C "$dir/extracted" 2> /dev/null || true
    "$CONTAINER_CMD" rm -f "$cid" > /dev/null < /dev/null
}

# ---------------------------------------------------------------------------------------------
# surfaces 2 and 4: one /scan per file, then /export of what was scanned

# formq escapes a value for a double-quoted curl -F parameter.
formq() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

scan_files() { # surface base_url set root
    local sf="$1" url="$2" set="$3" root="$4" out="$work/raw/$3" idx rel abs name t0 res
    mkdir -p "$out/$sf"
    : > "$out/$sf.times.tsv"
    t0="$(now)"
    while IFS="$(printf '\t')" read -r idx rel; do
        abs="$root/$rel"
        name="$(basename "$rel")"
        res="$(curl -sS -o "$out/$sf/$idx.json" -w '%{http_code}\t%{time_total}' --max-time 600 \
            -F "files=@\"$(formq "$abs")\";filename=\"$(formq "$name")\"" \
            --form-string "relative_path=$rel" --form-string checks=all --form-string confidence=all \
            --form-string verbose=false --form-string recursive=false "$url/scan" \
            < /dev/null 2>> "$out/$sf.curl.err")" || res="$(printf '000\t0')"
        printf '%s\t%s\t%s\n' "$idx" "$(echo "$res" | cut -f2)" "$(echo "$res" | cut -f1)" >> "$out/$sf.times.tsv"
    done < "$out/files.tsv"
    printf 'seconds=%s\n' "$(elapsed "$t0" "$(now)")" > "$out/$sf.meta"
}

# export_files posts the surface's own /scan results back to /export, as the UI's Export button does,
# in every format the server lists, with the UI's default switches (show_match and verbose off) and
# with both on. Results are chunked by size so a request body stays under 900,000 bytes: the server
# refuses a JSON body over 1 MiB (maxJSONRequestBytes). One finding bigger than that on its own is
# a chunk of its own, and the server's refusal is recorded rather than worked around.
export_files() { # surface base_url set
    local sf="$1" url="$2" set="$3" out="$work/raw/$3" chunks="$work/raw/$3/chunks-$1" fmt show chunk name
    mkdir -p "$out/export/$sf" "$chunks"
    for f in "$out/$sf"/*.json; do
        [ -e "$f" ] || continue
        jq -c '(.results // [])[]' "$f" 2> /dev/null || true
    done > "$chunks/findings.jsonl"
    LC_ALL=C awk -v d="$chunks" -v max=900000 '
        { n = length($0) + 1
          if (size > 0 && size + n > max) { close(f); size = 0 }
          if (size == 0) { chunk++; f = sprintf("%s/%04d.jsonl", d, chunk) }
          print > f; size += n }' "$chunks/findings.jsonl"
    for chunk in "$chunks"/[0-9]*.jsonl; do
        [ -e "$chunk" ] || continue
        name="$(basename "$chunk" .jsonl)"
        for show in false true; do
            for fmt in $formats; do
                jq -s -c --arg f "$fmt" --argjson s "$show" '{format: $f, results: ., show_match: $s, verbose: $s}' "$chunk" \
                    | curl -sS -o "$out/export/$sf/$name.$show.$fmt" -w '%{http_code}' --max-time 120 \
                        -H 'Content-Type: application/json' --data-binary @- "$url/export" \
                        > "$out/export/$sf/$name.$show.$fmt.code" 2>> "$out/$sf.curl.err" \
                    || echo 000 > "$out/export/$sf/$name.$show.$fmt.code"
            done
        done
    done
}

# check_web records the facts every web surface must hold: /health answers with the host binary's
# version, the page carries the security headers (TM-03, TM-05 script-src, TM-06 recorded), and the
# server lists the formats /export serves.
check_web() { # surface base_url
    local sf="$1" url="$2" hdr csp xfo xcto rp ver list
    curl -sS --max-time 30 "$url/health" > "$work/raw/health.$sf.json"
    ver="$(jq -r '.version' "$work/raw/health.$sf.json")"
    if [ "$ver" = "$VERSION" ]; then fact PASS "$sf /health version" "$ver"; else fact FAIL "$sf /health version" "'$ver', want '$VERSION'"; fi
    # The fields both binaries are stamped with; timestamp, build_date, go_version and platform are not
    # compared, for the reasons given at version_and_commit.
    jq -S '{status, service, version, commit: .build_info.commit}' "$work/raw/health.$sf.json" > "$work/raw/health.$sf.normalized.json"
    hdr="$(curl -sS --max-time 30 -D - -o /dev/null "$url/" | tr -d '\r')"
    csp="$(echo "$hdr" | sed -n 's/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: //p')"
    xfo="$(echo "$hdr" | sed -n 's/^[Xx]-[Ff]rame-[Oo]ptions: //p')"
    xcto="$(echo "$hdr" | sed -n 's/^[Xx]-[Cc]ontent-[Tt]ype-[Oo]ptions: //p')"
    rp="$(echo "$hdr" | sed -n 's/^[Rr]eferrer-[Pp]olicy: //p')"
    printf 'csp=%s\nxfo=%s\nxcto=%s\nrp=%s\n' "$csp" "$xfo" "$xcto" "$rp" > "$work/raw/headers.$sf.txt"
    script_src="$(echo "$csp" | tr ';' '\n' | sed -n 's/^ *script-src //p')"
    if [ "$script_src" = "'self'" ]; then fact PASS "$sf CSP script-src" "'self' (TM-05)"; else fact FAIL "$sf CSP script-src" "'$script_src', want 'self' with no 'unsafe-inline'"; fi
    if [ "$xfo" = DENY ] && [ "$xcto" = nosniff ] && [ "$rp" = no-referrer ]; then
        fact PASS "$sf TM-03 headers" "X-Frame-Options=$xfo X-Content-Type-Options=$xcto Referrer-Policy=$rp"
    else
        fact FAIL "$sf TM-03 headers" "X-Frame-Options='$xfo' X-Content-Type-Options='$xcto' Referrer-Policy='$rp'"
    fi
    fact INFO "$sf CSP style-src" "$(echo "$csp" | tr ';' '\n' | sed -n 's/^ *style-src //p') (TM-06 open)"
    list="$(curl -sS --max-time 30 -H 'Content-Type: application/json' --data '{"format":"surface-parity-no-such-format","results":[]}' \
        "$url/export" | jq -r '.error' | sed -n 's/.*Available formats: //p' | tr -d ' ' | tr ',' ' ')"
    echo "$list" > "$work/raw/formats.$sf.txt"
    if [ -n "$list" ]; then fact PASS "$sf /export formats" "$list"; else fact FAIL "$sf /export formats" "could not read the server's format list"; fi
}

wait_health() { # base_url label
    local _
    for _ in $(seq 1 120); do
        if curl -sS -o /dev/null --max-time 2 "$1/health" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    die "$2 did not answer /health within 60s"
}

# ---------------------------------------------------------------------------------------------
# run

while IFS="$(printf '\t')" read -r set root _; do
    mkdir -p "$work/raw/$set"
    if [ "$set" = corpus ]; then
        (cd "$root" && find . -path ./private -prune -o -type f -print)
    else
        (cd "$root" && find . -type f -print)
    fi | sed 's|^\./||' | LC_ALL=C sort | awk '{ printf "%05d\t%s\n", NR, $0 }' > "$work/raw/$set/files.tsv"
    if grep -q "$(printf '\t').*$(printf '\t')" "$work/raw/$set/files.tsv"; then
        die "$set: a file name contains a tab; this script keys inputs by a tab-separated path"
    fi
    echo "--- input set $set: $(wc -l < "$work/raw/$set/files.tsv" | tr -d ' ') files"
done < "$work/sets.tsv"

if has cli; then
    echo "--- surface 1: host CLI"
    while IFS="$(printf '\t')" read -r set root _; do run_host_cli "$set" "$root"; done < "$work/sets.tsv"
fi

if has container-cli; then
    echo "--- surface 3: container CLI ($image)"
    while IFS="$(printf '\t')" read -r set root _; do run_container_cli "$set" "$root"; done < "$work/sets.tsv"
    echo "--- container redaction: simple and format_preserving into /tmp/out and /home/ferret/out"
    while IFS="$(printf '\t')" read -r set root _; do
        for st in simple format_preserving; do
            run_container_redaction "$set" "$root" "$st" /tmp/out tmp-out
            run_container_redaction "$set" "$root" "$st" /home/ferret/out home-out
        done
    done < "$work/sets.tsv"
    # A write into the image's TMPDIR, the directory the web upload path writes its temp files to.
    golden_root="$(head -n 1 "$work/sets.tsv" | cut -f2)"
    run_container_redaction golden "$golden_root" simple "${tmpdir_env:-/home/ferret/tmp}/surface-parity-out" tmpdir-out
    if [ "$(sed -n 's/^exit=//p' "$work/raw/golden/redact/simple__tmpdir-out/run.meta")" = 0 ] \
        && [ -n "$(find "$work/raw/golden/redact/simple__tmpdir-out/extracted" -type f | head -n 1)" ]; then
        fact PASS "write into TMPDIR" "redaction into ${tmpdir_env:-/home/ferret/tmp}/surface-parity-out exited 0 and wrote files"
    else
        fact FAIL "write into TMPDIR" "redaction into ${tmpdir_env:-/home/ferret/tmp}/surface-parity-out did not exit 0 with files written"
    fi
fi

formats=""
if has web; then
    echo "--- surface 2: host --web on 127.0.0.1"
    port="$(free_port)"
    "$bin" --web --bind 127.0.0.1 --port "$port" --config /dev/null --suppression-file "$host_supp" \
        > "$work/host-web.log" 2>&1 &
    web_pid=$!
    url=""
    for _ in $(seq 1 120); do
        actual="$(sed -n 's/^Ferret Scan Web UI started on 127\.0\.0\.1:\([0-9][0-9]*\)$/\1/p' "$work/host-web.log" | head -n 1)"
        if [ -n "$actual" ]; then url="http://127.0.0.1:$actual"; break; fi
        kill -0 "$web_pid" 2>/dev/null || { cat "$work/host-web.log" >&2; die "the host web server exited"; }
        sleep 0.5
    done
    [ -n "$url" ] || die "the host web server printed no startup line"
    [ "$actual" = "$port" ] || fact INFO "host web port" "asked for $port, the server chose $actual"
    wait_health "$url" "host web"
    check_loopback_listeners "host web" "$actual"
    check_web web "$url"
    formats="$(cat "$work/raw/formats.web.txt")"
    while IFS="$(printf '\t')" read -r set root _; do
        scan_files web "$url" "$set" "$root"
        export_files web "$url" "$set"
    done < "$work/sets.tsv"
    kill "$web_pid" 2>/dev/null || true
    wait "$web_pid" 2>/dev/null || true
    web_pid=""
fi

if has container-web; then
    echo "--- surface 4: container --web published on 127.0.0.1"
    port="$(free_port)"
    publish="127.0.0.1:$port:8080"
    case "$publish" in
        127.0.0.1:*) ;;
        *) die "refusing to publish '$publish': the host side must be 127.0.0.1" ;;
    esac
    cid="$("$CONTAINER_CMD" run -d -p "$publish" "$image" --web --port 8080 --config /dev/null \
        --suppression-file "$ctr_supp" < /dev/null)"
    cids+=("$cid")
    url="http://127.0.0.1:$port"
    wait_health "$url" "container web"
    dp="$("$CONTAINER_CMD" port "$cid")"
    echo "  docker port: $(echo "$dp" | tr '\n' ' ')"
    if [ -n "$dp" ] && ! echo "$dp" | grep -v -- "-> 127\.0\.0\.1:" | grep -q .; then
        fact PASS "container publish" "$(echo "$dp" | tr '\n' ' ')"
    else
        fact FAIL "container publish" "docker port shows a non-loopback mapping: $(echo "$dp" | tr '\n' ' ')"
    fi
    check_loopback_listeners "container web" "$port" allow-none
    check_web container-web "$url"
    [ -n "$formats" ] || formats="$(cat "$work/raw/formats.container-web.txt")"
    if has web && [ "$(cat "$work/raw/formats.web.txt")" != "$(cat "$work/raw/formats.container-web.txt")" ]; then
        fact FAIL "/export formats" "web lists '$(cat "$work/raw/formats.web.txt")', container-web '$(cat "$work/raw/formats.container-web.txt")'"
    fi
    if has web; then
        for f in health headers; do
            a="$work/raw/$f.web.txt"; b="$work/raw/$f.container-web.txt"
            [ "$f" = health ] && a="$work/raw/health.web.normalized.json" && b="$work/raw/health.container-web.normalized.json"
            if cmp -s "$a" "$b"; then fact PASS "$f web == container-web" "identical"; else fact FAIL "$f web == container-web" "$(diff "$a" "$b" | tr '\n' ' ' | cut -c1-300)"; fi
        done
    fi
    while IFS="$(printf '\t')" read -r set root _; do
        scan_files container-web "$url" "$set" "$root"
        export_files container-web "$url" "$set"
    done < "$work/sets.tsv"
fi

echo
rc=0
"$spreport" -work "$work" -surfaces "$surfaces" -allowlist "$repo/scripts/surface-parity/allowlist.tsv" || rc=$?
if [ "$rc" = 0 ] && [ "$surfaces" = "cli,web,container-cli,container-web" ]; then
    printf 'state=%s\nsurfaces=%s\nwhen=%s\n' "$(checkout_state)" "$surfaces" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$marker"
    echo "surface-parity: green on all four surfaces; recorded for scripts/pr-checklist.sh in $marker"
elif [ "$rc" = 0 ]; then
    echo "surface-parity: green on $surfaces (a partial run records nothing for pr-checklist.sh)"
fi
exit "$rc"
