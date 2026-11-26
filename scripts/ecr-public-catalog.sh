#!/usr/bin/env bash
# The ECR Public Gallery page of the container image (https://gallery.ecr.aws/awslabs/ferret-scan)
# from the files under docs/ecr-public/, so the page is written in this repository and reviewed like
# any other document, instead of typed into the registry console where nothing re-reads it.
#
#   docs/ecr-public/catalog.json   description (search result text), architectures, operatingSystems
#   docs/ecr-public/about.md       the "About" tab, markdown
#   docs/ecr-public/usage.md       the "Usage" tab, markdown
#
# Usage:
#   scripts/ecr-public-catalog.sh check            validate the files against the API's limits; no network
#   scripts/ecr-public-catalog.sh diff             compare the files with the live page; anonymous, no
#                                                  AWS credentials (the gallery's public API); exit 1 on drift
#   scripts/ecr-public-catalog.sh apply            write the files to the registry, then read them back
#
# `apply` needs AWS credentials for the account that owns the registry alias, with
# ecr-public:GetRepositoryCatalogData and ecr-public:PutRepositoryCatalogData on the repository, and
# runs in us-east-1 (the only Region ECR Public has). PutRepositoryCatalogData replaces the whole
# catalog object, and the logo is not in the files, so `apply` downloads the live logo and sends it
# back unchanged; without that the put would drop it.
#
# Environment: ECR_PUBLIC_ALIAS (default awslabs), ECR_PUBLIC_REPOSITORY (default ferret-scan),
# AWS_PROFILE as usual for the AWS CLI.
set -euo pipefail

alias_name="${ECR_PUBLIC_ALIAS:-awslabs}"
repo="${ECR_PUBLIC_REPOSITORY:-ferret-scan}"
region=us-east-1
gallery_api="https://api.${region}.gallery.ecr.aws"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${root}/docs/ecr-public"
for f in catalog.json about.md usage.md; do
  [ -f "${src}/${f}" ] || { echo "missing ${src}/${f}" >&2; exit 2; }
done

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf -- "${tmp}"' EXIT

# desired.json: the catalogData object the files describe (no logo).
python3 - "${src}" "${tmp}/desired.json" <<'PY'
import json, sys
src, out = sys.argv[1], sys.argv[2]
with open(f"{src}/catalog.json") as f:
    data = json.load(f)
with open(f"{src}/about.md") as f:
    data["aboutText"] = f.read()
with open(f"{src}/usage.md") as f:
    data["usageText"] = f.read()
with open(out, "w") as f:
    json.dump(data, f)
PY

check() {
  python3 - "${tmp}/desired.json" <<'PY'
import json, sys
# Limits and badge values: RepositoryCatalogDataInput in the ECR Public API reference.
limits = {"description": 1024, "aboutText": 25600, "usageText": 25600}
badges = {"architectures": {"ARM", "ARM 64", "x86", "x86-64"}, "operatingSystems": {"Linux", "Windows"}}
with open(sys.argv[1]) as f:
    d = json.load(f)
bad = 0
for key, limit in limits.items():
    n = len(d.get(key, ""))
    ok = n <= limit and n > 0
    print(f"{key:17} {n:6} chars (limit {limit}) {'ok' if ok else 'FAIL'}")
    bad += not ok
for key, allowed in badges.items():
    vals = d.get(key, [])
    extra = [v for v in vals if v not in allowed]
    print(f"{key:17} {vals} {'ok' if vals and not extra else 'FAIL: ' + str(extra)}")
    bad += (not vals) or bool(extra)
for key in ("aboutText", "usageText"):
    if "\t" in d[key]:
        print(f"{key}: contains a tab; the gallery renders markdown, use spaces"); bad += 1
sys.exit(1 if bad else 0)
PY
}

# live.json: the catalogData the gallery shows now. Anonymous: the gallery's own API, the one the
# web page calls. It lists every repository under the alias; keep ours.
fetch_live() {
  curl -sS -X POST "${gallery_api}/describeRepositoryCatalogData" \
    -H 'Content-Type: application/json' \
    -d "{\"registryAliasName\":\"${alias_name}\"}" > "${tmp}/gallery.json"
  python3 - "${tmp}/gallery.json" "${repo}" "${tmp}/live.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
repos = [r for r in d.get("repositories", []) if r.get("repositoryName") == sys.argv[2]]
if not repos:
    print(f"repository {sys.argv[2]} not found under the alias: {d}", file=sys.stderr); sys.exit(2)
with open(sys.argv[3], "w") as f:
    json.dump(repos[0].get("catalogData", {}), f)
PY
}

# compare DESIRED LIVE: one line per field, exit 1 when any differs.
compare() {
  python3 - "$1" "$2" <<'PY'
import difflib, json, sys
with open(sys.argv[1]) as f:
    want = json.load(f)
with open(sys.argv[2]) as f:
    have = json.load(f)
drift = 0
for key in ("description", "architectures", "operatingSystems", "aboutText", "usageText"):
    w, h = want.get(key), have.get(key)
    if isinstance(w, list):
        w, h = sorted(w), sorted(h or [])
    if w == h:
        print(f"{key:17} same")
        continue
    drift += 1
    print(f"{key:17} DIFFERS")
    if isinstance(w, str):
        for line in difflib.unified_diff((h or "").splitlines(), w.splitlines(), "live", "files", lineterm="", n=1):
            print("    " + line)
    else:
        print(f"    live:  {h}\n    files: {w}")
print("logo             " + ("kept (live logoUrl present)" if have.get("logoUrl") else "none on the live page"))
sys.exit(1 if drift else 0)
PY
}

case "${1:-}" in
  check)
    check
    ;;
  diff)
    check >/dev/null
    fetch_live
    compare "${tmp}/desired.json" "${tmp}/live.json"
    ;;
  apply)
    check
    command -v aws >/dev/null || { echo "the AWS CLI is required for apply" >&2; exit 2; }
    aws ecr-public get-repository-catalog-data --region "${region}" --repository-name "${repo}" \
      --query catalogData --output json > "${tmp}/before.json"
    logo_url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("logoUrl") or "")' "${tmp}/before.json")"
    if [ -n "${logo_url}" ]; then
      curl -sS -o "${tmp}/logo.bin" "${logo_url}"
      echo "logo: keeping the live one ($(wc -c < "${tmp}/logo.bin" | tr -d ' ') bytes)"
    else
      echo "logo: none on the live page; none sent"
    fi
    python3 - "${tmp}/desired.json" "${tmp}/logo.bin" "${repo}" "${tmp}/input.json" <<'PY'
import base64, json, os, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
if os.path.exists(sys.argv[2]):
    with open(sys.argv[2], "rb") as f:
        data["logoImageBlob"] = base64.b64encode(f.read()).decode("ascii")
with open(sys.argv[4], "w") as f:
    json.dump({"repositoryName": sys.argv[3], "catalogData": data}, f)
PY
    aws ecr-public put-repository-catalog-data --region "${region}" \
      --cli-input-json "file://${tmp}/input.json" --query catalogData.repositoryName --output text
    aws ecr-public get-repository-catalog-data --region "${region}" --repository-name "${repo}" \
      --query catalogData --output json > "${tmp}/after.json"
    echo "read back from the registry:"
    compare "${tmp}/desired.json" "${tmp}/after.json"
    echo "https://gallery.ecr.aws/${alias_name}/${repo} (the page may cache for a few minutes)"
    ;;
  *)
    sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
