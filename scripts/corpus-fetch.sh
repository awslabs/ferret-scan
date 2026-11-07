#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# corpus-fetch.sh — fill a LOCAL, never-committed corpus of real public files, one directory per
# file format: the public half of the standing real-file instrument that scripts/corpus-ab.sh,
# scripts/corpus-triage.sh and `make corpus-baseline` read (CORPUS_PLAN.md in the corpus root).
#
# Why: the real-world A/B sets used so far (this repository, the Go module cache, GOROOT) are text
# and code only. No PDF, Office document, image, audio or video file had ever been in an A/B, so a
# change to an extractor or a redactor was measured on synthetic fixtures alone. This script fetches
# licence-clean public files in every format the router supports, records where each came from, and
# never sends a credential anywhere.
#
# Where the files go: --corpus DIR, else $FERRET_CORPUS_DIR, else ../ferret-corpus next to this
# repository. Layout:
#
#   by-format/<ext>/<source>--<name>   the files (lower-case extension directory), read-only
#   MANIFEST.tsv                       path, source URL, sha256, bytes, licence, retrieved date
#   MANIFEST.failed.tsv                what the LAST run could not fetch, and why
#   MANIFEST.plan.tsv                  the locked selection; re-runs fetch from it, not from search
#
# Nothing else in the corpus root is touched: private/, baselines/, triage/, runs/ and any README
# belong to the operator or to the other scripts, and this script never lists, reads or writes them.
#
# No credential material, by the corpus rule: a file is never stored, and one already stored is
# swept out of by-format/, MANIFEST.tsv and the plan, when it is an .env file, a key or certificate
# file (.pem .key .p12 .pfx .crt .cer .der .jks .keystore .kdbx .ppk .gpg), an SSH key by name,
# anything under .ssh/, .aws/ or .gnupg/, or a file holding a PEM private-key or certificate block.
#
# After every run that wrote anything, by-format/ is made read-only (chmod -R a-w), so a scan, a
# redaction bug or a stray command cannot change the corpus a baseline was measured on. The script
# unlocks only its own tree, only while it writes.
#
# Properties:
#   - idempotent: a file whose sha256 matches its MANIFEST.tsv row is skipped without any network
#     call; a run over a complete corpus makes no requests at all.
#   - bounded: 50 MB per file, 5 GB for the whole by-format/ tree, `curl --max-time` on every
#     request, and every download checked against the size and hash the source published (git blob
#     SHA-1 for GitHub, SHA-1 for Wikimedia Commons and the Internet Archive, CRC-32 for GovDocs1).
#   - licence-clean: every source names its licence, recorded per file in MANIFEST.tsv. A source
#     that names none is not fetched (see "Not fetched" below).
#   - credential-free: curl runs with -q (no ~/.curlrc), no netrc, no tokens. The GitHub listing
#     calls are unauthenticated (about 15 per fresh plan, cached by pinned commit afterwards).
#
# Sources (licence recorded per block; selection is deterministic, evenly spread over each listing):
#   govdocs1     GovDocs1 zips 000/333/666/999, members range-read out of each zip (never the whole
#                zip): US Government works, public domain.
#   poi          Apache POI test-data/ @ pinned commit, Apache-2.0.
#   lo-sc/sw/sd  LibreOffice core sc/qa, sw/qa, sd/qa @ pinned commit, MPL-2.0.
#   pdfcpu       pdfcpu pkg/testdata, Apache-2.0.          pdfjs     pdf.js test/pdfs, Apache-2.0.
#   exifsamples  ianare/exif-samples (real EXIF/GPS), CC-BY-SA-4.0 per its README.
#   libheif      libheif test and fuzzing HEIC files, LGPL-3.0.
#   libwebp      libwebp-test-data, BSD-3-Clause (libwebp terms).
#   exiftool     ExifTool t/images (metadata-rich samples of most containers), Perl terms.
#   compose      docker/awesome-compose (YAML, TOML, JSON, conf, code), CC0-1.0.
#   tomltest / goini / gozip   TOML (MIT), INI (Apache-2.0) and ZIP (BSD-3-Clause) test files.
#   commons      Wikimedia Commons, searched through the API with a licence filter (CC0 or public
#                domain structured data) and each file's licence re-checked from its own metadata.
#   ia           Internet Archive items whose licenseurl is CC0 1.0 or the Public Domain Mark, for
#                the containers Commons does not host (mov, mp4, m4v, 3gp, m4a, avi, mkv).
#
# Not fetched: samples.ffmpeg.org. Its 00-README grants permission to download but names no
# licence, so it fails the rule above; avi/mkv/3gp come from ExifTool and the Internet Archive.
#
# Usage:
#   scripts/corpus-fetch.sh [--corpus DIR] [--dry-run] [--replan] [--only BLOCK[,BLOCK]]
#                           [--jobs N] [--cache-dir DIR] [--list-blocks]
#
#   --dry-run      build (or read) the plan and print it; download nothing, write nothing
#   --replan       ignore MANIFEST.plan.tsv and re-select from the sources (network)
#   --only         restrict planning and fetching to the named blocks
#   --cache-dir    where immutable listings (pinned git trees, zip directories) are cached
#                  (default ${XDG_CACHE_HOME:-~/.cache}/ferret-corpus-fetch)
#
# Exit status: 0 when every planned file is present and verified, 1 when anything failed (see
# MANIFEST.failed.tsv), 2 on a usage error.
#
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$here/.." && pwd)

corpus=""
pass=()
while [ $# -gt 0 ]; do
  case "$1" in
    --corpus)
      [ $# -ge 2 ] || { echo "corpus-fetch: --corpus needs a directory" >&2; exit 2; }
      corpus="$2"; shift 2 ;;
    --corpus=*) corpus="${1#--corpus=}"; shift ;;
    -h|--help) sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    *) pass+=("$1"); shift ;;
  esac
done
[ -n "$corpus" ] || corpus="${FERRET_CORPUS_DIR:-}"
[ -n "$corpus" ] || corpus="$repo_root/../ferret-corpus"

for tool in curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "corpus-fetch: $tool is required" >&2; exit 2; }
done

readonly_run=0
for arg in ${pass[@]+"${pass[@]}"}; do
  case "$arg" in --dry-run|--list-blocks) readonly_run=1 ;; esac
done
if [ "$readonly_run" -eq 0 ]; then
  if [ ! -d "$corpus" ]; then
    mkdir -p "$corpus" || { echo "corpus-fetch: cannot create $corpus" >&2; exit 2; }
    echo "corpus-fetch: created $corpus"
  fi
  corpus=$(cd "$corpus" && pwd)
  # The corpus must never be committed by accident, even when someone points --corpus inside a
  # work tree: an own .gitignore that ignores everything but itself. Created only when absent.
  if [ ! -e "$corpus/.gitignore" ]; then
    printf '*\n!.gitignore\n' > "$corpus/.gitignore"
  fi
  mkdir -p "$corpus/by-format"
fi

exec python3 - "$corpus" ${pass[@]+"${pass[@]}"} <<'PY'
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import zlib

MB = 1024 * 1024
PER_FILE_CAP = 50 * MB
TOTAL_CAP = 5 * 1024 * MB
UA = "ferret-scan-corpus-fetch/1.0 (+https://github.com/awslabs/ferret-scan; scripts/corpus-fetch.sh)"

# ---------------------------------------------------------------------------------------------
# Sources. Commits are pinned so a GitHub selection is reproducible byte for byte; the pick counts
# are per extension, spread evenly over the sorted listing. Bump a commit deliberately, then
# --replan.
# ---------------------------------------------------------------------------------------------
GITHUB = [
    dict(name="poi", repo="apache/poi", commit="519e0a3c3945364e8ea75c172fe1a15fb6d4a202",
         prefix="test-data", licence="Apache-2.0 (Apache POI test-data)", max_mb=8,
         picks=dict(docx=10, xlsx=10, pptx=10, doc=8, xls=8, ppt=8, docm=2, xlsm=2, pptm=2,
                    svg=2, png=2, jpg=2, txt=2, csv=2, xml=2)),
    dict(name="lo-sc", repo="LibreOffice/core", commit="f79dad30aa3fd495fbb9376ee881be0b058e0328",
         prefix="sc/qa", licence="MPL-2.0 (LibreOffice core QA documents)", max_mb=8,
         picks=dict(ods=12, xlsx=8, xls=8, xlsm=2, csv=4, html=2, py=2, cxx=2)),
    dict(name="lo-sw", repo="LibreOffice/core", commit="f79dad30aa3fd495fbb9376ee881be0b058e0328",
         prefix="sw/qa", licence="MPL-2.0 (LibreOffice core QA documents)", max_mb=8,
         picks=dict(odt=12, docx=8, doc=8, rtf=12, ott=3, docm=2, html=2, txt=2, pdf=2)),
    dict(name="lo-sd", repo="LibreOffice/core", commit="f79dad30aa3fd495fbb9376ee881be0b058e0328",
         prefix="sd/qa", licence="MPL-2.0 (LibreOffice core QA documents)", max_mb=8,
         picks=dict(odp=12, pptx=8, ppt=8, pptm=1, svg=4, pdf=3)),
    dict(name="pdfcpu", repo="pdfcpu/pdfcpu", commit="a21a372de6864eccd9e554df63c7950dfd1a4b47",
         prefix="pkg/testdata", licence="Apache-2.0 (pdfcpu testdata)", max_mb=8,
         picks=dict(pdf=15, json=4, webp=2, tiff=1, tif=1, png=2, jpg=2, wav=1, txt=1)),
    dict(name="pdfjs", repo="mozilla/pdf.js", commit="525815943376e377176d433cd0bb67a372dfb943",
         prefix="test/pdfs", licence="Apache-2.0 (pdf.js test corpus)", max_mb=5,
         picks=dict(pdf=20)),
    dict(name="exifsamples", repo="ianare/exif-samples", commit="5332a9cf0220e9c6c93f88a187daa90808051e10",
         prefix="", licence="CC-BY-SA-4.0 (ianare/exif-samples README)", max_mb=8,
         picks=dict(jpg=16, tiff=8, heic=2, jpeg=2)),
    dict(name="libheif", repo="strukturag/libheif", commit="12a259a5882dd99d45ec5fc77e296a3b620d1e2e",
         prefix="", licence="LGPL-3.0 (libheif repository COPYING)", max_mb=8,
         picks=dict(heic=12)),
    dict(name="libwebp", repo="webmproject/libwebp-test-data", commit="06ddd96e276c2c638a72d39d3c0f340afd61978c",
         prefix="", licence="BSD-3-Clause (libwebp-test-data, libwebp terms)", max_mb=8,
         picks=dict(webp=16, png=2, tiff=2)),
    dict(name="exiftool", repo="exiftool/exiftool", commit="9b8664dfcf2c609d3cc8925d380e98ad2a379f9b",
         prefix="t/images", licence="Artistic-1.0-Perl OR GPL-1.0-or-later (ExifTool test images)", max_mb=8,
         picks=dict(avi=2, mkv=1, mov=1, m4a=1, heic=1, webp=1, flac=1, mp3=1, wav=1, docx=1, ods=1,
                    ppt=1, rtf=1, pdf=2, gif=1, png=1, tif=2, bmp=1, jpg=6, xml=2, csv=2, json=1,
                    html=1, txt=2, log=2)),
    dict(name="compose", repo="docker/awesome-compose", commit="30f4b7f6a6c3b0c0ecf4d4efb0de203c48d11562",
         prefix="", licence="CC0-1.0 (docker/awesome-compose)", max_mb=5, name_parts=2,
         exclude=r"(^|/)(lib|node_modules|dist|vendor)/|\.min\.|LICENSE|package-lock",
         picks=dict(yaml=10, yml=3, toml=3, json=4, py=4, go=3, java=3, js=3, sql=3, sh=1,
                    properties=2, conf=3, xml=2, html=2, txt=2, jpg=2, png=2, svg=2)),
    dict(name="tomltest", repo="toml-lang/toml-test", commit="96fd088448ec0f4d9f061c730ed7854399c46faf",
         prefix="tests", include=r"^valid/", licence="MIT (toml-lang/toml-test)", max_mb=1, name_parts=2,
         picks=dict(toml=5)),
    dict(name="goini", repo="go-ini/ini", commit="e2db55b0e088fa4ee0c128aa4ade263cdc1d7f08",
         prefix="testdata", licence="Apache-2.0 (go-ini/ini testdata)", max_mb=1,
         picks=dict(ini=5)),
    dict(name="gozip", repo="golang/go", commit="3568f0bb1559a1d395f599af61ddb1c0e9b02201",
         prefix="src/archive/zip/testdata", licence="BSD-3-Clause (Go archive/zip testdata)", max_mb=1,
         picks=dict(zip=6)),
]

GOVDOCS1 = dict(
    name="govdocs1",
    base="https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles/",
    zips=["000", "333", "666", "999"],
    licence="Public domain (US Government work; GovDocs1, digitalcorpora.org)",
    max_mb=10,
    # Per zip; GovDocs1 holds no Office 2007 formats to speak of (one .pptx in 999.zip).
    picks=dict(pdf=4, doc=4, xls=4, ppt=4, html=3, jpg=3, gif=3, txt=3, csv=3, xml=3, log=3,
               rtf=2, png=2, pptx=1, java=1, sql=1),
)

# (mime, how many, max size in MB). The licence filter is Commons structured data: P275 (licence)
# = CC0, or P6216 (copyright status) = public domain. Each hit is re-checked against the licence
# its own file page states before it is accepted.
COMMONS = dict(
    name="commons",
    picks=[("audio/mpeg", 6, 15), ("audio/wav", 5, 15), ("audio/x-flac", 5, 20), ("video/webm", 3, 15),
           ("image/jpeg", 8, 12), ("image/png", 3, 8), ("image/gif", 3, 8), ("image/tiff", 3, 20),
           ("image/webp", 3, 8), ("image/svg+xml", 4, 2), ("application/pdf", 3, 10)],
)
COMMONS_EXTS = {
    "audio/mpeg": {"mp3"}, "audio/wav": {"wav"}, "audio/x-flac": {"flac"}, "video/webm": {"webm"},
    "image/jpeg": {"jpg", "jpeg"}, "image/png": {"png"}, "image/gif": {"gif"},
    "image/tiff": {"tif", "tiff"}, "image/webp": {"webp"}, "image/svg+xml": {"svg"},
    "application/pdf": {"pdf"},
}

# (archive.org format name, extension, how many, max size in MB); at most one file per item.
IA = dict(
    name="ia",
    picks=[("QuickTime", "mov", 5, 40), ("MPEG4", "mp4", 4, 40), ("MPEG4", "m4v", 2, 50),
           ("Matroska", "mkv", 3, 40), ("3GP", "3gp", 4, 40), ("Apple Lossless Audio", "m4a", 3, 30),
           ("Cinepack", "avi", 3, 40)],
    licences={"http://creativecommons.org/publicdomain/zero/1.0/": "CC0-1.0",
              "https://creativecommons.org/publicdomain/zero/1.0/": "CC0-1.0",
              "http://creativecommons.org/publicdomain/mark/1.0/": "PDM-1.0",
              "https://creativecommons.org/publicdomain/mark/1.0/": "PDM-1.0"},
    max_lookups=80,
    # Manifest rows get quoted in public reports (an anomaly is reported with its row), so items
    # whose identifier is propaganda are passed over. Format coverage is unaffected.
    exclude=r"(?i)hitler|nazi",
)

ALL_BLOCKS = [b["name"] for b in GITHUB] + [GOVDOCS1["name"], COMMONS["name"], IA["name"]]
# Blocks an older version of this script fetched. Their plan rows are dropped and their files swept.
RETIRED_BLOCKS = {"dotenv"}

# ---------------------------------------------------------------------------------------------
# No credential material (CORPUS_PLAN.md): .env files, key and certificate files, SSH key names,
# anything under .ssh/.aws/.gnupg, and any file carrying a PEM private-key or certificate block.
# ---------------------------------------------------------------------------------------------
CRED_EXTS = {"env", "pem", "key", "p12", "pfx", "crt", "cer", "der", "jks", "keystore", "kdbx", "ppk", "gpg"}
CRED_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".pgpass"}
CRED_DIRS = {".ssh", ".aws", ".gnupg"}
PEM_BLOCK = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*(?:PRIVATE KEY|CERTIFICATE|PRIVATE KEY BLOCK)-----")


def credential_name(source_path):
    """Why a source path is credential-shaped by name, or None."""
    parts = [p for p in re.split(r"[/#\\]", source_path.lower()) if p]
    if not parts:
        return None
    name = parts[-1]
    ext = name.rsplit(".", 1)[-1] if "." in name[1:] else ""
    if name.startswith(".env") or ext in CRED_EXTS:
        return f"{name}: key, certificate or .env file"
    if name in CRED_NAMES:
        return f"{name}: SSH or login credential file"
    if any(p in CRED_DIRS for p in parts[:-1]):
        return "under a .ssh/.aws/.gnupg directory"
    return None


def credential_content(path):
    """True when the file holds a PEM private-key or certificate block (read in overlapping chunks)."""
    tail = b""
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            if PEM_BLOCK.search(tail + chunk):
                return True
            tail = chunk[-64:]
    return False

PLAN_COLS = ["path", "block", "source_url", "licence", "expect_bytes", "expect_hash", "locator"]
MANIFEST_COLS = ["path", "source_url", "sha256", "bytes", "licence", "retrieved"]
FAILED_COLS = ["path", "source_url", "reason", "date"]


def log(msg):
    print(msg, flush=True)


def today():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def tsv_clean(value):
    return re.sub(r"[\t\r\n]+", " ", str(value))


# ---------------------------------------------------------------------------------------------
# HTTP: curl only, -q first so no ~/.curlrc (and nothing it might carry) is read.
# ---------------------------------------------------------------------------------------------
def curl(url, out=None, byte_range=None, max_bytes=PER_FILE_CAP, timeout=180):
    cmd = ["curl", "-q", "--silent", "--show-error", "--fail", "--location",
           "--proto", "=https", "--proto-redir", "=https",
           "--max-time", str(timeout), "--connect-timeout", "20",
           "--retry", "2", "--retry-delay", "5",
           "--user-agent", UA, "--max-filesize", str(max_bytes)]
    if byte_range is not None:
        cmd += ["--range", byte_range]
    if out is not None:
        cmd += ["--output", out]
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        return 28, b"", "timed out"
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", "replace").strip()


def curl_json(url, timeout=120):
    rc, body, err = curl(url, max_bytes=64 * MB, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"curl exit {rc}: {err or 'no detail'}")
    return json.loads(body)


# ---------------------------------------------------------------------------------------------
# Hashes and naming
# ---------------------------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_hash(path, expect):
    """expect is '<algo>:<hex>' (gitsha1, sha1, crc32) or ''; returns None when it matches."""
    if not expect:
        return None
    algo, _, want = expect.partition(":")
    size = os.path.getsize(path)
    if algo == "gitsha1":
        h = hashlib.sha1(b"blob %d\x00" % size)
    elif algo == "sha1":
        h = hashlib.sha1()
    elif algo == "crc32":
        crc = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                crc = zlib.crc32(chunk, crc)
        got = "%08x" % crc
        return None if got == want else f"crc32 {got} != {want}"
    else:
        return f"unknown hash algorithm {algo}"
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    got = h.hexdigest()
    return None if got == want.lower() else f"{algo} {got} != {want}"


def ext_of(name):
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def safe_name(name, limit=80, parts=1):
    """ASCII file name from the last `parts` path components; a dotfile (.env) takes its parent's name."""
    comps = [c for c in name.split("/") if c]
    base = comps[-1] if comps else "file"
    stem, dot, ext = base.rpartition(".")
    if not dot:
        stem, ext = base, ""
    lead = comps[-parts:-1] if parts > 1 else []
    if not stem and len(comps) > 1:
        lead = comps[-1 - max(1, parts - 1):-1]
    stem = "__".join(lead + ([stem] if stem else []))
    # A name with no ASCII letters or digits (a Bengali or Cyrillic title) keeps a stable,
    # distinct stem rather than collapsing to the same placeholder as every other one.
    stem = (re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("_.")
            or "h" + hashlib.sha1(name.encode("utf-8")).hexdigest()[:12])
    ext = re.sub(r"[^A-Za-z0-9]+", "", ext)
    stem = stem[:limit]
    return f"{stem}.{ext}" if ext else stem


def spread(items, k):
    """k items evenly spaced over a sorted list: deterministic, and not just the first k."""
    n = len(items)
    if k >= n:
        return list(items)
    return [items[(2 * i + 1) * n // (2 * k)] for i in range(k)]


# ---------------------------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------------------------
class Planner:
    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def cached(self, key, fetch):
        path = os.path.join(self.cache_dir, re.sub(r"[^A-Za-z0-9._-]+", "_", key) + ".json")
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        data = fetch()
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
        return data

    # GitHub: one unauthenticated trees call per (repo, commit, prefix), cached forever.
    def github(self, b):
        ref = f"{b['commit']}:{b['prefix']}" if b["prefix"] else b["commit"]
        url = f"https://api.github.com/repos/{b['repo']}/git/trees/{urllib.parse.quote(ref, safe=':/')}?recursive=1"
        tree = self.cached(f"gh-{b['repo']}-{b['commit']}-{b['prefix']}", lambda: curl_json(url))
        if tree.get("truncated"):
            log(f"  warning: {b['repo']}:{b['prefix']} listing is truncated by GitHub")
        inc = re.compile(b["include"]) if b.get("include") else None
        exc = re.compile(b["exclude"]) if b.get("exclude") else None
        by_ext = {}
        for e in tree.get("tree", []):
            if e.get("type") != "blob":
                continue
            p, size = e["path"], int(e.get("size") or 0)
            ext = ext_of(p)
            if ext not in b["picks"] or size <= 0 or size > b["max_mb"] * MB:
                continue
            if (inc and not inc.search(p)) or (exc and exc.search(p)) or credential_name(p):
                continue
            by_ext.setdefault(ext, []).append((p, size, e["sha"]))
        items = []
        for ext, k in sorted(b["picks"].items()):
            for p, size, sha in spread(sorted(by_ext.get(ext, [])), k):
                full = f"{b['prefix']}/{p}" if b["prefix"] else p
                raw = f"https://raw.githubusercontent.com/{b['repo']}/{b['commit']}/{urllib.parse.quote(full)}"
                items.append(dict(ext=ext, name=f"{b['name']}--{safe_name(full, parts=b.get('name_parts', 1))}",
                                  block=b["name"],
                                  source_url=raw, licence=b["licence"], expect_bytes=size,
                                  expect_hash=f"gitsha1:{sha}", locator=""))
            if len(by_ext.get(ext, [])) < k:
                log(f"  note: {b['name']} has {len(by_ext.get(ext, []))} .{ext} file(s) for {k} picks")
        return items

    # GovDocs1: read each zip's central directory with two range requests; never the whole zip.
    def zip_directory(self, url):
        def fetch():
            rc, tail, err = curl(url, byte_range="-66000", max_bytes=1 * MB, timeout=120)
            if rc != 0:
                raise RuntimeError(f"curl exit {rc}: {err}")
            at = tail.rfind(b"PK\x05\x06")
            if at < 0 or len(tail) - at < 22:
                raise RuntimeError("no end-of-central-directory record")
            _, _, _, _, count, cd_size, cd_off, _ = struct.unpack("<IHHHHIIH", tail[at:at + 22])
            if cd_off == 0xFFFFFFFF or count == 0xFFFF:
                raise RuntimeError("zip64 archive not supported")
            rc, cd, err = curl(url, byte_range=f"{cd_off}-{cd_off + cd_size - 1}", max_bytes=16 * MB)
            if rc != 0 or len(cd) != cd_size:
                raise RuntimeError(f"central directory read failed: curl exit {rc} {err}")
            members, pos = [], 0
            while pos + 46 <= len(cd) and cd[pos:pos + 4] == b"PK\x01\x02":
                (_, _, _, flags, method, _, _, crc, csize, usize, nlen, xlen, clen, _, _, _,
                 off) = struct.unpack("<IHHHHHHIIIHHHHHII", cd[pos:pos + 46])
                name = cd[pos + 46:pos + 46 + nlen].decode("cp437")
                members.append([name, flags, method, crc, csize, usize, off])
                pos += 46 + nlen + xlen + clen
            return members
        return self.cached("govdocs1-" + url.rsplit("/", 1)[-1], fetch)

    def govdocs1(self, b):
        items = []
        for z in b["zips"]:
            url = b["base"] + z + ".zip"
            by_ext = {}
            for name, flags, method, crc, csize, usize, off in self.zip_directory(url):
                ext = ext_of(name)
                if (name.endswith("/") or ext not in b["picks"] or flags & 1 or method not in (0, 8)
                        or credential_name(name)):
                    continue
                if usize <= 0 or usize > b["max_mb"] * MB or csize > b["max_mb"] * MB:
                    continue
                by_ext.setdefault(ext, []).append((name, flags, method, crc, csize, usize, off))
            for ext, k in sorted(b["picks"].items()):
                for name, _, method, crc, csize, usize, off in spread(sorted(by_ext.get(ext, [])), k):
                    loc = f"offset={off};csize={csize};method={method};namelen={len(name.encode('cp437'))}"
                    items.append(dict(ext=ext, name=f"{b['name']}--{safe_name(name)}", block=b["name"],
                                      source_url=f"{url}#{name}", licence=b["licence"],
                                      expect_bytes=usize, expect_hash="crc32:%08x" % crc, locator=loc))
        return items

    # Wikimedia Commons: licence-filtered search, oldest uploads first (a stable order), and the
    # licence each file page states is checked before a hit is accepted.
    def commons(self, b):
        api = "https://commons.wikimedia.org/w/api.php"
        items = []
        for mime, k, max_mb in b["picks"]:
            params = {
                "action": "query", "format": "json", "generator": "search", "gsrnamespace": "6",
                "gsrsearch": f"filemime:{mime} haswbstatement:P275=Q6938433|P6216=Q19652 filesize:<{max_mb * 1024}",
                "gsrsort": "create_timestamp_asc", "gsrlimit": "50", "prop": "imageinfo",
                "iiprop": "url|size|sha1|mime|extmetadata", "iiextmetadatafilter": "LicenseShortName|License",
            }
            data = curl_json(api + "?" + urllib.parse.urlencode(params))
            pages = sorted(data.get("query", {}).get("pages", {}).values(), key=lambda p: p.get("index", 0))
            got = 0
            for page in pages:
                if got >= k:
                    break
                info = (page.get("imageinfo") or [{}])[0]
                meta = info.get("extmetadata", {})
                short = meta.get("LicenseShortName", {}).get("value", "")
                code = meta.get("License", {}).get("value", "")
                if code == "cc0" or short == "CC0":
                    licence = "CC0-1.0 (Wikimedia Commons)"
                elif code == "pd" or short.lower().startswith("public domain"):
                    licence = "Public domain (Wikimedia Commons)"
                else:
                    continue
                title = page["title"].split(":", 1)[-1]
                ext = ext_of(title)
                size = int(info.get("size") or 0)
                if (ext not in COMMONS_EXTS[mime] or size <= 0 or size > max_mb * MB or not info.get("url")
                        or credential_name(title)):
                    continue
                url = info["url"].split("?", 1)[0]
                items.append(dict(ext=ext, name=f"commons--{safe_name(title)}", block=b["name"],
                                  source_url=url, licence=licence, expect_bytes=size,
                                  expect_hash=f"sha1:{info.get('sha1', '')}" if info.get("sha1") else "",
                                  locator=""))
                got += 1
            if got < k:
                log(f"  note: commons gave {got} of {k} {mime} file(s)")
        return items

    # Internet Archive: items whose own licenseurl is CC0 or the Public Domain Mark.
    def ia(self, b):
        lic_q = " OR ".join(f'licenseurl:"{u}"' for u in b["licences"] if u.startswith("http://"))
        items, used = [], set()
        for fmt, ext, k, max_mb in b["picks"]:
            q = f'({lic_q}) AND format:"{fmt}" AND item_size:[1 TO {max_mb * 4 * MB}]'
            params = [("q", q), ("fl[]", "identifier"), ("rows", "200"), ("output", "json"),
                      ("sort[]", "identifier asc")]
            docs = curl_json("https://archive.org/advancedsearch.php?" + urllib.parse.urlencode(params))
            got, lookups = 0, 0
            for d in docs.get("response", {}).get("docs", []):
                if got >= k or lookups >= b["max_lookups"]:
                    break
                ident = d["identifier"]
                if ident in used or re.search(b["exclude"], ident):
                    continue
                lookups += 1
                try:
                    md = curl_json(f"https://archive.org/metadata/{urllib.parse.quote(ident)}")
                except Exception as exc:  # one bad item must not sink the block
                    log(f"  note: ia metadata {ident}: {exc}")
                    continue
                licence = b["licences"].get(str(md.get("metadata", {}).get("licenseurl", "")).strip())
                if not licence:
                    continue
                files = sorted((f for f in md.get("files", [])
                                if f.get("source") == "original" and ext_of(f.get("name", "")) == ext
                                and not credential_name(f.get("name", ""))
                                and 0 < int(f.get("size") or 0) <= max_mb * MB), key=lambda f: f["name"])
                if not files:
                    continue
                f = files[0]
                used.add(ident)
                url = f"https://archive.org/download/{urllib.parse.quote(ident)}/{urllib.parse.quote(f['name'])}"
                items.append(dict(ext=ext, name=f"ia--{safe_name(ident, 40)}--{safe_name(f['name'], 60)}",
                                  block=b["name"], source_url=url,
                                  licence=f"{licence} (Internet Archive item {ident})",
                                  expect_bytes=int(f["size"]),
                                  expect_hash=f"sha1:{f['sha1']}" if f.get("sha1") else "", locator=""))
                got += 1
            if got < k:
                log(f"  note: ia gave {got} of {k} .{ext} file(s) for format {fmt}")
        return items


def assign_paths(items):
    """by-format/<ext>/<name>, de-duplicated deterministically."""
    seen, out = set(), []
    for it in sorted(items, key=lambda i: (i["ext"], i["name"], i["source_url"])):
        base = f"by-format/{it['ext']}/{it['name']}"
        path, n = base, 1
        while path in seen:
            n += 1
            stem, dot, ext = base.rpartition(".")
            path = f"{stem}-{n}.{ext}" if dot and "/" not in ext else f"{base}-{n}"
        seen.add(path)
        it = dict(it, path=path)
        out.append(it)
    return out


# ---------------------------------------------------------------------------------------------
# TSV files
# ---------------------------------------------------------------------------------------------
def read_tsv(path, cols):
    rows = {}
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f):
            line = line.rstrip("\n")
            if not line or (n == 0 and line.split("\t")[0] == cols[0]):
                continue
            parts = line.split("\t")
            if len(parts) != len(cols):
                continue
            rows[parts[0]] = dict(zip(cols, parts))
    return rows


def write_tsv(path, cols, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for key in sorted(rows):
            f.write("\t".join(tsv_clean(rows[key].get(c, "")) for c in cols) + "\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------------------------
class Fetcher:
    def __init__(self, corpus, cache_dir, jobs):
        self.corpus = corpus
        self.tmp_root = tempfile.mkdtemp(prefix="partial.", dir=cache_dir)
        self.jobs = jobs
        self.lock = threading.RLock()
        self.manifest = read_tsv(os.path.join(corpus, "MANIFEST.tsv"), MANIFEST_COLS)
        self.failed = {}
        self.total = 0
        bf = os.path.join(corpus, "by-format")
        for root, _, files in os.walk(bf):
            for name in files:
                self.total += os.path.getsize(os.path.join(root, name))
        self.fetched = self.skipped = 0
        # Commons and the Archive ask clients to be gentle; GitHub raw and S3 do not mind 6.
        self.gates = {"commons": threading.Semaphore(2), "ia": threading.Semaphore(2)}

    def fail(self, item, reason):
        with self.lock:
            self.failed[item["path"]] = dict(path=item["path"], source_url=item["source_url"],
                                             reason=reason, date=today())
        log(f"  FAIL {item['path']}: {reason}")

    def present(self, item):
        """True when the file is on disk and matches its manifest row: no network needed."""
        dest = os.path.join(self.corpus, item["path"])
        row = self.manifest.get(item["path"])
        if not row or row["source_url"] != item["source_url"] or not os.path.isfile(dest):
            return False
        return os.path.getsize(dest) == int(row["bytes"]) and sha256_file(dest) == row["sha256"]

    def download(self, item, tmp):
        if item["block"] == GOVDOCS1["name"]:
            return self.zip_member(item, tmp)
        rc, _, err = curl(item["source_url"], out=tmp, max_bytes=PER_FILE_CAP, timeout=600)
        if rc == 63:
            return "larger than the 50 MB per-file cap"
        if rc != 0:
            return f"curl exit {rc}: {err or 'no detail'}"
        return None

    def zip_member(self, item, tmp):
        loc = dict(kv.split("=", 1) for kv in item["locator"].split(";"))
        off, csize, method, nlen = (int(loc[k]) for k in ("offset", "csize", "method", "namelen"))
        url = item["source_url"].split("#", 1)[0]
        want = 30 + nlen + 1024 + csize
        rc, blob, err = curl(url, byte_range=f"{off}-{off + want - 1}", max_bytes=PER_FILE_CAP + 2 * MB, timeout=600)
        if rc != 0:
            return f"curl exit {rc}: {err or 'no detail'}"
        if blob[:4] != b"PK\x03\x04":
            return "no local file header at the recorded offset"
        n, x = struct.unpack("<HH", blob[26:30])
        start = 30 + n + x
        if start + csize > len(blob):
            rc, rest, err = curl(url, byte_range=f"{off + len(blob)}-{off + start + csize - 1}",
                                 max_bytes=PER_FILE_CAP + 2 * MB, timeout=600)
            if rc != 0:
                return f"curl exit {rc}: {err or 'no detail'}"
            blob += rest
        data = blob[start:start + csize]
        if method == 8:
            d = zlib.decompressobj(-15)
            data = d.decompress(data, PER_FILE_CAP + 1)
            if len(data) > PER_FILE_CAP:
                return "larger than the 50 MB per-file cap"
        with open(tmp, "wb") as f:
            f.write(data)
        return None

    def one(self, item):
        dest = os.path.join(self.corpus, item["path"])
        if self.present(item):
            with self.lock:
                self.skipped += 1
            return
        expect = int(item["expect_bytes"] or 0)
        if expect > PER_FILE_CAP:
            return self.fail(item, "larger than the 50 MB per-file cap")
        with self.lock:
            if self.total + expect > TOTAL_CAP:
                return self.fail(item, "would exceed the 5 GB corpus cap")
            self.total += expect
        gate = self.gates.get(item["block"])
        tmp = os.path.join(self.tmp_root, hashlib.sha1(item["path"].encode()).hexdigest())
        try:
            if gate:
                gate.acquire()
            try:
                err = self.download(item, tmp)
            finally:
                if gate:
                    gate.release()
            if err is None:
                size = os.path.getsize(tmp)
                if size > PER_FILE_CAP:
                    err = "larger than the 50 MB per-file cap"
                elif expect and size != expect:
                    err = f"size {size} != published {expect}"
                else:
                    err = check_hash(tmp, item["expect_hash"])
                if err is None:
                    with open(tmp, "rb") as f:
                        if f.read(64).startswith(b"version https://git-lfs"):
                            err = "git-lfs pointer, not content"
                if err is None and credential_content(tmp):
                    err = "credential-shaped content (a PEM private-key or certificate block); not stored"
            if err is not None:
                with self.lock:
                    self.total -= expect
                return self.fail(item, err)
            if os.path.isfile(dest) and item["path"] not in self.manifest:
                # Not ours: never overwrite a file this script did not record.
                if sha256_file(dest) != sha256_file(tmp):
                    with self.lock:
                        self.total -= expect
                    return self.fail(item, "a different, unrecorded file already exists there; left untouched")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            digest = sha256_file(tmp)
            shutil.move(tmp, dest)
            with self.lock:
                self.manifest[item["path"]] = dict(path=item["path"], source_url=item["source_url"],
                                                   sha256=digest, bytes=str(size), licence=item["licence"],
                                                   retrieved=today())
                self.fetched += 1
                if self.fetched % 50 == 0:
                    write_tsv(os.path.join(self.corpus, "MANIFEST.tsv"), MANIFEST_COLS, self.manifest)
            log(f"  ok   {item['path']} ({size} bytes)")
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def guarded(self, item):
        try:
            self.one(item)
        except Exception as exc:  # one broken item must not abort the run
            self.fail(item, f"{type(exc).__name__}: {exc}")

    def run(self, plan):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.jobs) as pool:
            list(pool.map(self.guarded, plan))
        write_tsv(os.path.join(self.corpus, "MANIFEST.tsv"), MANIFEST_COLS, self.manifest)
        write_tsv(os.path.join(self.corpus, "MANIFEST.failed.tsv"), FAILED_COLS, self.failed)
        try:
            os.rmdir(self.tmp_root)
        except OSError:
            pass


def set_tree_writable(root, writable):
    """Owner write on (unlock) or every write bit off (lock: chmod -R a-w) for root and below."""
    if not os.path.isdir(root):
        return
    for dp, dns, fns in os.walk(root):
        for p in [os.path.join(dp, n) for n in fns] + [dp]:
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if os.path.islink(p):
                continue
            mode = st.st_mode & 0o7777
            os.chmod(p, (mode | 0o200) if writable else (mode & ~0o222))


def sweep(corpus, plan_rows, manifest):
    """Remove credential-shaped and retired-block files from by-format/, the manifest and the plan."""
    swept = []
    for path in sorted(set(plan_rows) | set(manifest)):
        row = plan_rows.get(path) or {}
        mrow = manifest.get(path) or {}
        source = (row.get("source_url") or mrow.get("source_url") or "").split("?", 1)[0]
        source_path = urllib.parse.unquote(urllib.parse.urlparse(source.split("#", 1)[0]).path) + \
            ("/" + source.split("#", 1)[1] if "#" in source else "")
        why = None
        if row.get("block") in RETIRED_BLOCKS:
            why = f"block {row['block']} is retired"
        why = why or credential_name(source_path) or credential_name(path)
        full = os.path.join(corpus, path)
        if not why and os.path.isfile(full) and credential_content(full):
            why = "credential-shaped content (a PEM private-key or certificate block)"
        if not why:
            continue
        if os.path.isfile(full):
            os.unlink(full)
            try:
                os.rmdir(os.path.dirname(full))  # only when the format directory is now empty
            except OSError:
                pass
        plan_rows.pop(path, None)
        manifest.pop(path, None)
        swept.append((path, why))
        log(f"  swept {path}: {why}")
    return swept


def summarize(corpus, plan, manifest):
    by_ext = {}
    for item in plan:
        e = by_ext.setdefault(item["ext"], [0, 0, 0])
        e[0] += 1
        row = manifest.get(item["path"])
        if row and os.path.isfile(os.path.join(corpus, item["path"])):
            e[1] += 1
            e[2] += int(row["bytes"])
    log("")
    log(f"{'ext':<11}{'planned':>8}{'present':>9}{'bytes':>14}")
    for ext in sorted(by_ext):
        p, h, nbytes = by_ext[ext]
        log(f"{ext:<11}{p:>8}{h:>9}{nbytes:>14}")
    tp = sum(v[0] for v in by_ext.values())
    th = sum(v[1] for v in by_ext.values())
    tb = sum(v[2] for v in by_ext.values())
    log(f"{'TOTAL':<11}{tp:>8}{th:>9}{tb:>14}")
    return tp, th


def main():
    corpus = os.path.abspath(sys.argv[1])
    ap = argparse.ArgumentParser(prog="corpus-fetch.sh")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--replan", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--cache-dir", default=os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"), "ferret-corpus-fetch"))
    ap.add_argument("--list-blocks", action="store_true")
    args = ap.parse_args(sys.argv[2:])

    if args.list_blocks:
        for b in GITHUB:
            log(f"{b['name']:<12} {b['repo']}@{b['commit'][:12]}:{b['prefix'] or '/'}  {b['licence']}")
        log(f"{'govdocs1':<12} {GOVDOCS1['base']}{{{','.join(GOVDOCS1['zips'])}}}.zip  {GOVDOCS1['licence']}")
        log(f"{'commons':<12} commons.wikimedia.org API, CC0 / public-domain filter  (licence per file)")
        log(f"{'ia':<12} archive.org, licenseurl CC0 1.0 / Public Domain Mark  (licence per item)")
        return 0

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    unknown = only - set(ALL_BLOCKS)
    if unknown:
        log(f"corpus-fetch: unknown block(s): {', '.join(sorted(unknown))}; see --list-blocks")
        return 2
    wanted = only or set(ALL_BLOCKS)

    plan_path = os.path.join(corpus, "MANIFEST.plan.tsv")
    locked = read_tsv(plan_path, PLAN_COLS)
    have_blocks = {r["block"] for r in locked.values()}
    replan = {b for b in wanted if args.replan or b not in have_blocks}

    planner = Planner(args.cache_dir)
    fresh, plan_failures = [], []
    for b in GITHUB:
        if b["name"] in replan:
            log(f"plan {b['name']}: {b['repo']}@{b['commit'][:12]}:{b['prefix'] or '/'}")
            try:
                fresh += planner.github(b)
            except Exception as exc:
                plan_failures.append((b["name"], str(exc)))
    for name, fn in ((GOVDOCS1["name"], lambda: planner.govdocs1(GOVDOCS1)),
                     (COMMONS["name"], lambda: planner.commons(COMMONS)),
                     (IA["name"], lambda: planner.ia(IA))):
        if name in replan:
            log(f"plan {name}")
            try:
                fresh += fn()
            except Exception as exc:
                plan_failures.append((name, str(exc)))
    for name, why in plan_failures:
        log(f"  FAIL planning {name}: {why}")

    failed_blocks = {n for n, _ in plan_failures}
    kept = [dict(r, ext=r["path"].split("/")[1]) for r in locked.values()
            if r["block"] not in replan or r["block"] in failed_blocks]
    fresh = [dict(i, expect_bytes=str(i["expect_bytes"])) for i in fresh]
    # Every name carries its block as a prefix, so a fresh block cannot collide with a kept one.
    plan = sorted(kept + assign_paths(fresh), key=lambda i: i["path"])
    plan_rows = {i["path"]: {c: str(i.get(c, "")) for c in PLAN_COLS} for i in plan}

    todo = [i for i in plan if i["block"] in wanted]
    if args.dry_run:
        manifest = read_tsv(os.path.join(corpus, "MANIFEST.tsv"), MANIFEST_COLS)
        would_sweep = [i for i in plan if i["block"] in RETIRED_BLOCKS or credential_name(i["path"])
                       or credential_name(i["source_url"].split("?", 1)[0])]
        for i in would_sweep:
            log(f"  would sweep {i['path']}")
        todo = [i for i in todo if i not in would_sweep]
        for i in todo:
            log(f"  {i['path']}\t{i['expect_bytes']}\t{i['licence']}")
        summarize(corpus, todo, manifest)
        log("dry run: nothing downloaded, nothing written")
        return 1 if plan_failures else 0

    by_format = os.path.join(corpus, "by-format")
    set_tree_writable(by_format, True)
    try:
        manifest_path = os.path.join(corpus, "MANIFEST.tsv")
        manifest = read_tsv(manifest_path, MANIFEST_COLS)
        swept = sweep(corpus, plan_rows, manifest)
        if swept:
            write_tsv(manifest_path, MANIFEST_COLS, manifest)
        todo = [i for i in plan if i["path"] in plan_rows and i["block"] in wanted]
        write_tsv(plan_path, PLAN_COLS, plan_rows)
        fetcher = Fetcher(corpus, args.cache_dir, max(1, args.jobs))
        log(f"fetch {len(todo)} planned file(s) into {corpus}/by-format "
            f"({fetcher.total} bytes present; caps 50 MB/file, 5 GB total)")
        fetcher.run(todo)
    finally:
        set_tree_writable(by_format, False)
    planned, present = summarize(corpus, todo, fetcher.manifest)
    log(f"fetched {fetcher.fetched}, already present {fetcher.skipped}, failed {len(fetcher.failed)}"
        f" (MANIFEST.failed.tsv), swept {len(swept)} credential-shaped or retired file(s), planning failures "
        f"{len(plan_failures)}; by-format/ is read-only")
    return 1 if (fetcher.failed or plan_failures or present < planned) else 0


sys.exit(main())
PY
