#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Check, or regenerate, the embedded E.164 calling-code table against libphonenumber (#889).
#
# internal/validators/phone/e164_codes.go is generated from libphonenumber's PhoneNumberMetadata.xml
# (Apache-2.0) by TestE164CodesMatchMetadata in e164_codes_gen_test.go. The phone validator's E.164
# gate reads only that table: a calling code missing from it, or a national length it does not list,
# is a "+CC"/"00CC" number held at LOW or not reported, so the table is only honest while it is
# current. This script is the one command that downloads the source and runs the generator, the way
# scripts/check-tlds.sh does for the email validator's TLD snapshot.
#
# Like check-tlds.sh it WARNS and exits 0 when it cannot reach the network: an offline developer must
# not be blocked by an external file nobody can read. Drift found online exits 1.
#
# Usage (from the repository root):
#   scripts/refresh-e164.sh check  [--version vX.Y.Z | --xml FILE]   compare, exit 1 on drift (default)
#   scripts/refresh-e164.sh update [--version vX.Y.Z | --xml FILE]   rewrite e164_codes.go
#
# --version picks a libphonenumber release tag (default: the tag e164_codes.go records, so `check`
# with no flag re-verifies the committed table against the exact file it was generated from).
# --xml reads a local copy instead of downloading; the table then records the default source URL
# unless E164_METADATA_SOURCE says otherwise.
set -uo pipefail

GEN_TEST="internal/validators/phone/e164_codes_gen_test.go"
TABLE="internal/validators/phone/e164_codes.go"
RAW="https://raw.githubusercontent.com/google/libphonenumber"

warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
usage() { sed -n '17,25p' "$0" | sed 's/^# \{0,1\}//'; }

MODE="check"
VERSION=""
XML=""
while [ $# -gt 0 ]; do
  case "$1" in
    check | update) MODE="$1" ;;
    --version) [ $# -ge 2 ] || die "--version needs a tag"; VERSION="$2"; shift ;;
    --xml) [ $# -ge 2 ] || die "--xml needs a file"; XML="$2"; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

[ -f "$GEN_TEST" ] && [ -f "$TABLE" ] || die "$GEN_TEST not found; run from the repository root"
[ -z "$VERSION" ] || [ -z "$XML" ] || die "--version and --xml are exclusive"
if [ -n "$VERSION" ] && ! printf '%s' "$VERSION" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  die "--version must look like v9.0.43, got: $VERSION"
fi

# The tag the committed table was generated from, read from its "read <date> from <url>" line.
recorded_url=$(grep -m1 -oE "read [0-9]{4}-[0-9]{2}-[0-9]{2} from https://[^ ]+" "$TABLE" | sed 's/^read [0-9-]* from //')
recorded_tag=$(printf '%s' "$recorded_url" | grep -oE '/v[0-9]+\.[0-9]+\.[0-9]+/' | tr -d /)
[ -n "$recorded_tag" ] || die "could not read the source tag from $TABLE"

source_url=""
if [ -z "$XML" ]; then
  source_url="$RAW/${VERSION:-$recorded_tag}/resources/PhoneNumberMetadata.xml"
  XML=$(mktemp "${TMPDIR:-/tmp}/e164-metadata.XXXXXX.xml") || die "mktemp failed"
  trap 'rm -f -- "$XML"' EXIT
  curl -sSf --max-time 60 -o "$XML" "$source_url"
  rc=$?
  # 22 is an HTTP error (a tag that does not exist): that is the caller's mistake, not the network.
  [ $rc -ne 22 ] || die "$source_url: HTTP error; is ${VERSION:-$recorded_tag} a libphonenumber release tag?"
  if [ $rc -ne 0 ]; then
    warn "could not download $source_url (curl exit $rc) -- $TABLE NOT verified (offline?)"
    exit 0
  fi
fi
[ -s "$XML" ] || die "$XML is empty"

export GOFLAGS="${GOFLAGS:--mod=mod}"
export E164_METADATA_XML="$XML"
[ -z "$source_url" ] || export E164_METADATA_SOURCE="${E164_METADATA_SOURCE:-$source_url}"

if [ "$MODE" = "update" ]; then
  # The generator writes e164_codes.go into its package directory; gofmt keeps the literal stable.
  UPDATE_E164_CODES=1 go test -count=1 -run '^TestE164CodesMatchMetadata$' -v ./internal/validators/phone/ |
    grep -E 'wrote|FAIL|ok ' || die "generator failed"
  gofmt -w "$TABLE"
  if git diff --quiet -- "$TABLE"; then
    printf '%s is unchanged\n' "$TABLE"
  else
    git --no-pager diff --stat -- "$TABLE"
    printf 'regenerated %s; run go test ./internal/validators/phone/ and review the diff\n' "$TABLE"
  fi
  exit 0
fi

out=$(go test -count=1 -run '^TestE164CodesMatchMetadata$' -v ./internal/validators/phone/ 2>&1)
rc=$?
printf '%s\n' "$out" | grep -E 'matches the download|drifted|^ +[-+~] |FAIL|SKIP' || true
if [ $rc -ne 0 ]; then
  printf 'drift: run scripts/refresh-e164.sh update%s\n' "${VERSION:+ --version $VERSION}" >&2
  exit 1
fi
exit 0
