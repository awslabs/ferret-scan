#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Smoke-test redaction inside a built container image.
#
#   scripts/container-redaction-smoke.sh [IMAGE]     IMAGE defaults to ferret-scan:latest
#
# Runs --enable-redaction in the image the way a user does: as the image's own user, with no
# --user and no extra environment. Each run must exit 0 and write a redacted copy that no longer
# holds the value. There are two runs, one writing under /tmp and one under the user's home,
# because the image once shipped with neither writable by its user, and with every redaction
# panicking at exit 2 before it read its input (#776). The CI image test ran only --version and
# --help, so nothing caught it.
#
# Nothing is bind-mounted. Input goes in, and output comes out, through `cp` on a created
# container, so the result does not depend on the host's uid or on a host directory's mode.
#
# CONTAINER_CMD selects the runtime (default docker).

set -euo pipefail

IMAGE="${1:-ferret-scan:latest}"
CONTAINER_CMD="${CONTAINER_CMD:-docker}"
# A reserved documentation address (RFC 2606): the fixture holds nothing real.
VALUE="user00001@example.com"

work="$(mktemp -d)"
cid=""
cleanup() {
    if [ -n "$cid" ]; then
        "$CONTAINER_CMD" rm -f "$cid" >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

printf 'contact: %s\n' "$VALUE" > "$work/sample.txt"

for out_dir in /tmp/out /home/ferret/out; do
    # --fail-on-incomplete: without it, a redacted copy that could not be written is a warning
    # at exit 0, so the exit status alone would not show that redaction worked.
    cid="$("$CONTAINER_CMD" create "$IMAGE" \
        --file /home/ferret/sample.txt --checks EMAIL \
        --enable-redaction --redaction-output-dir "$out_dir" --fail-on-incomplete --quiet)"
    "$CONTAINER_CMD" cp "$work/sample.txt" "$cid:/home/ferret/sample.txt"

    if ! "$CONTAINER_CMD" start -a "$cid" > "$work/run.log" 2>&1; then
        cat "$work/run.log" >&2
        echo "❌ redaction into $out_dir failed in $IMAGE" >&2
        exit 1
    fi

    rm -rf "$work/extracted" && mkdir "$work/extracted"
    if ! "$CONTAINER_CMD" cp "$cid:$out_dir" - 2>/dev/null | tar -xf - -C "$work/extracted" 2>/dev/null; then
        echo "❌ redaction into $out_dir exited 0 but $out_dir does not exist in the container" >&2
        exit 1
    fi
    copy="$(find "$work/extracted" -type f -name sample.txt | head -n 1)"
    if [ -z "$copy" ]; then
        echo "❌ redaction into $out_dir exited 0 but wrote no redacted copy" >&2
        exit 1
    fi
    if grep -qF "$VALUE" "$copy"; then
        echo "❌ the redacted copy in $out_dir still holds the value" >&2
        exit 1
    fi
    echo "✅ redaction into $out_dir: exit 0, value removed"

    "$CONTAINER_CMD" rm -f "$cid" >/dev/null
    cid=""
done
