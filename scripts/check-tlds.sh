#!/usr/bin/env bash
# Check the embedded IANA TLD snapshot against the live root zone.
#
# Modelled on scripts/go-version.sh, including the part that matters most: it WARNS and exits 0 when
# it cannot reach the network. An offline developer or pre-commit hook must not be blocked by an
# un-verifiable external registry, and a check that hard-fails offline gets switched off.
#
# Why this exists at all. internal/validators/email/tlds.go embeds the IANA root zone, and an address
# whose TLD is not in it is capped into the LOW band. That cap is only honest while the snapshot is
# current: if ICANN delegates a gTLD and this list does not know it, real corporate email on that TLD
# is demoted below the band a reviewer looks at. The list was previously hand-maintained, labelled
# "Complete IANA TLD list", and was 48% complete -- 684 entries against 1438, missing every one of the
# 151 internationalised TLDs. Nobody noticed because nothing checked.
#
# Usage:
#   scripts/check-tlds.sh check     compare and warn on drift (default)
#   scripts/check-tlds.sh update    print the regenerated Go file to stdout
set -uo pipefail

IANA_URL="https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TLD_FILE="internal/validators/email/tlds.go"
MODE="${1:-check}"

warn() { printf 'WARNING: %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }

embedded_count() {
  grep -oE '"[a-z0-9-]+": \{\}' "$TLD_FILE" 2>/dev/null | wc -l | tr -d ' '
}

embedded_version() {
  grep -oE '# Version [0-9]+' "$TLD_FILE" 2>/dev/null | head -1
}

# The embedded TLDs themselves, one per line, sorted -- the thing drift is actually about.
#
# Same pattern embedded_count counts, capturing the name instead of tallying it, so the two can never
# disagree about what an entry is.
embedded_tlds() {
  grep -oE '"[a-z0-9-]+": \{\}' "$TLD_FILE" 2>/dev/null | sed -E 's/^"([a-z0-9-]+)".*/\1/' | sort -u
}

if [ ! -f "$TLD_FILE" ]; then
  warn "$TLD_FILE not found; run from the repository root"
  exit 0
fi

live=$(curl -sf --max-time 20 "$IANA_URL" 2>/dev/null || true)
if [ -z "$live" ]; then
  # Offline is not a failure. Same choice go-version.sh makes for an un-verifiable digest.
  warn "could not reach IANA ($IANA_URL) -- TLD snapshot NOT verified (offline?)"
  warn "  embedded: $(embedded_count) TLDs, $(embedded_version)"
  exit 0
fi

live_version=$(printf '%s\n' "$live" | head -1 | grep -oE '# Version [0-9]+')
live_count=$(printf '%s\n' "$live" | grep -vc '^#')
have=$(embedded_count)

if [ "$MODE" = "update" ]; then
  warn "regenerating from $live_version ($live_count TLDs)"
  printf '%s\n' "$live" | grep -v '^#' | tr 'A-Z' 'a-z' | sort -u
  exit 0
fi

info "IANA:     $live_version, $live_count TLDs"
info "embedded: $(embedded_version), $have TLDs"

# Drift is decided by the TLD SET, never by the version serial.
#
# IANA bumps that serial roughly daily -- it is a publication timestamp, not a content hash -- so
# comparing it reported drift every single week regardless of content. Observed 2026-09-07: "embedded
# 1438 vs IANA 1438", an identical TLD count, flagged as drifted purely because the header read
# 2026090601 against 2026090400. That is a weekly false alarm, and a check that cries wolf weekly is a
# check nobody reads.
#
# Counts alone are not enough either: one TLD delegated and one withdrawn in the same week leaves the
# count unchanged while the set has moved, and it is the SET that decides whether a real address gets
# capped into the LOW band. So compare the names, and say which ones.
#
# Lowercased with the same expression update mode uses (line above), because that is what produced the
# embedded list -- comparing against a differently-normalised copy would report every IDN as drift.
# shellcheck disable=SC2018,SC2019 # IANA publishes ASCII only (IDNs as punycode), and an explicit
# A-Z range is locale-independent where [:upper:] is not -- determinism matters more than accents here.
live_tlds=$(printf '%s\n' "$live" | grep -v '^#' | tr 'A-Z' 'a-z' | sort -u)
added=$(comm -13 <(embedded_tlds) <(printf '%s\n' "$live_tlds"))
removed=$(comm -23 <(embedded_tlds) <(printf '%s\n' "$live_tlds"))

if [ -z "$added" ] && [ -z "$removed" ]; then
  info "✅ TLD snapshot is current ($have TLDs match the root zone exactly)"
  if [ "$(embedded_version)" != "$live_version" ]; then
    # Worth saying, worth not failing over: the set is identical and only the publication serial moved.
    info "   (IANA serial has moved on to $live_version; the TLD set is unchanged, so nothing to do)"
  fi
  exit 0
fi

# Drift is a WARNING, not an error. A newly delegated TLD demotes real email by one band; it does not
# break the build, and failing here would block every commit until someone regenerates a data file.
warn "TLD snapshot has drifted from the IANA root zone"
warn "  embedded $have vs IANA $live_count"
[ -n "$added" ] && warn "  delegated since the snapshot ($(printf '%s\n' "$added" | wc -l | tr -d ' ')): $(printf '%s\n' "$added" | tr '\n' ' ')"
[ -n "$removed" ] && warn "  withdrawn since the snapshot ($(printf '%s\n' "$removed" | wc -l | tr -d ' ')): $(printf '%s\n' "$removed" | tr '\n' ' ')"
warn "  emails on TLDs delegated since the snapshot are capped into the LOW band"
warn "  refresh: scripts/check-tlds.sh update   (then regenerate $TLD_FILE)"
exit 0
