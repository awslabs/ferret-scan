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

if [ "$have" = "$live_count" ] && [ "$(embedded_version)" = "$live_version" ]; then
  info "✅ TLD snapshot is current"
  exit 0
fi

# Drift is a WARNING, not an error. A newly delegated TLD demotes real email by one band; it does not
# break the build, and failing here would block every commit until someone regenerates a data file.
warn "TLD snapshot has drifted from the IANA root zone"
warn "  embedded $have vs IANA $live_count"
warn "  emails on TLDs delegated since the snapshot are capped into the LOW band"
warn "  refresh: scripts/check-tlds.sh update   (then regenerate $TLD_FILE)"
exit 0
