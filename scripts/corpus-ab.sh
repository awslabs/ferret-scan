#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# corpus-ab.sh — the standing real-file instrument. Measures one commit (a BASELINE) or two (an A/B)
# over the local corpus: the public set (by-format/, filled by scripts/corpus-fetch.sh) and, only
# with --include-private, the operator's private set (private/). CORPUS_PLAN.md in the corpus root
# is the specification; each TEST_PLAN dimension it lists maps to one measurement here:
#
#   9   findings by type x format; BASE vs HEAD new / lost / confidence-changed outside a same-binary
#       noise floor, keyed on (path, validator, type, line, sha256(text)) as a multiset
#   FP  the triage ledgers (triage/public.tsv, triage/private.tsv): a lost TP blocks, a lost FP is a
#       win, a lost finding nobody classified needs triage, every new HIGH goes to triage
#       (scripts/corpus-triage.sh lists what is pending and records verdicts)
#   5   every file through --enable-redaction under simple and format_preserving: exit codes,
#       files_not_redacted, and survivors, in a file the run did NOT disclose as unredacted: a
#       reported value the re-scan of the redacted copy finds again ("silent"), or one present
#       verbatim in its bytes, zip parts decompressed ("raw"). Any survivor is P0.
#   4   every file timed alone (CPU and wall), bucketed by size doubling from 1 KB; time/byte over 3x
#       its bucket's median is an outlier; the slowest 20 public files are the standing timing
#       fixtures, re-timed best of --fixture-runs; an A/B reports any bucket whose median CPU rose
#       over 1.25x. BASE and HEAD are timed back to back per file, so both see the same host load.
#   6   suppression rules written by BASE (--generate-suppressions), enabled, applied by HEAD:
#       stats.suppressed must equal the findings both report and the suppressed list; public findings
#       also get synthetic v1 and v2 rules (the legacy hash formulas, recomputed here and checked
#       against the binary's own v5 hashes first) to measure that compatibility at scale
#   7   one run in each output format, structurally checked (json, yaml, csv, text, junit,
#       gitlab-sast, sarif), and BASE vs HEAD byte identity after masking times
#   11  3 runs of one binary (--runs), byte-identical after masking durations, or what moved
#   NE  every file not fully examined, by cause and format (from the per-file runs of dimension 4)
#   P0  every panic (fatal or recovered), hang, timeout, crash, output-cap and non-zero exit
#   12  not here: scripts/surface-parity.sh CORPUS=<dir> runs the container half
#
# The private set is never named. It is read only with --include-private; everything printed,
# logged or written about it is an aggregate per finding type and format (a known extension, else
# "other") plus timings and size buckets: never a path, a value or a finding text. Private finding
# keys are sha256-hashed before they reach triage/private.tsv, the only place they are written.
# Credential-shaped files there (.env, keys, certificates, .ssh/.aws/.gnupg) are excluded and only
# counted. Redacted copies and suppression files of private documents live in a 0700 directory
# that is removed when the run ends. Before exit, every file the run wrote is searched for the
# private paths (and the aggregate artefacts for private values); a hit fails the run.
#
# Usage:
#   scripts/corpus-ab.sh BASE HEAD [options]          an A/B (e.g. origin/main my-branch)
#   scripts/corpus-ab.sh --baseline [REF] [options]   record REF (default origin/main) as
#                                                     <corpus>/baselines/<sha>.json
# Options:
#   --corpus DIR          corpus root (else $FERRET_CORPUS_DIR, else ../ferret-corpus); exit 2 if
#                         it has no by-format/ (run scripts/corpus-fetch.sh)
#   --include-private     also measure <corpus>/private (aggregates only)
#   --only LIST           dimensions to run, from 9,11,7,4,ne,p0,5,6 (default: all)
#   --private-dims LIST   dimensions for the private set (default: the same as --only)
#   --formats LIST        restrict the public set to these by-format/ directories
#   --runs N              runs of the measured binary for dimension 11 (default 3)
#   --jobs N              parallel single-file runs in dimension 4 (default 4)
#   --fixture-runs N      timing-fixture runs per binary, best kept (default 3)
#   --timeout SECS        per tree invocation (default 3600); --file-timeout SECS per file (600)
#   --lanes N             measure the public and private sets concurrently (default 2 when the
#                         private set is included)
#   --out DIR             run directory (default <corpus>/runs/<UTC>-<base>-<head>.XXXX)
#   --keep-redacted       keep the public redacted copies (private ones are always removed)
#
# Every binary runs from an empty working directory with FERRET_CONFIG_DIR pointing at an empty
# directory, so neither a project's .ferret-scan-suppressions.yaml nor the user's own config or
# suppressions can change what is measured. Flags: --checks all --confidence all --limit 0
# --config /dev/null --quiet --no-color, plus --show-match on tree runs (each value is hashed in
# memory; public raw outputs are kept gzipped in the run directory, private ones never written).
#
# Long: on the ~640-file public set one tree pass takes 1-3 minutes and a full A/B several dozen
# passes; the private set multiplies that by its size. Run it in the background and follow the log
# named on the first line. Exit status: A/B 0 clean, 1 a blocker (lost TP, a new P0 or survivor in
# HEAD, a suppression or determinism regression), 3 lost findings nobody has classified (run
# scripts/corpus-triage.sh); baseline 0 when recorded; 2 a setup error; 1 a failed privacy audit.
#
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$here/.." && pwd)

usage() { sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; }

mode=ab base_ref="" head_ref="" corpus="" out="" pass=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --baseline)
      mode=baseline; shift
      if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then base_ref="$1"; shift; fi ;;
    --corpus) [ $# -ge 2 ] || { echo "corpus-ab: --corpus needs a directory" >&2; exit 2; }; corpus="$2"; shift 2 ;;
    --corpus=*) corpus="${1#--corpus=}"; shift ;;
    --out) [ $# -ge 2 ] || { echo "corpus-ab: --out needs a directory" >&2; exit 2; }; out="$2"; shift 2 ;;
    --out=*) out="${1#--out=}"; shift ;;
    --include-private|--keep-redacted) pass+=("$1"); shift ;;
    --only|--private-dims|--formats|--runs|--jobs|--fixture-runs|--timeout|--file-timeout|--lanes)
      [ $# -ge 2 ] || { echo "corpus-ab: $1 needs a value" >&2; exit 2; }
      pass+=("$1" "$2"); shift 2 ;;
    --only=*|--private-dims=*|--formats=*|--runs=*|--jobs=*|--fixture-runs=*|--timeout=*|--file-timeout=*|--lanes=*)
      pass+=("$1"); shift ;;
    -*) echo "corpus-ab: unknown option $1" >&2; usage >&2; exit 2 ;;
    *)
      if [ "$mode" = baseline ]; then echo "corpus-ab: --baseline takes one REF" >&2; exit 2
      elif [ -z "$base_ref" ]; then base_ref="$1"
      elif [ -z "$head_ref" ]; then head_ref="$1"
      else echo "corpus-ab: unexpected argument $1" >&2; exit 2; fi
      shift ;;
  esac
done
if [ "$mode" = baseline ]; then
  [ -n "$base_ref" ] || base_ref=origin/main
  head_ref="$base_ref"
elif [ -z "$base_ref" ] || [ -z "$head_ref" ]; then
  echo "corpus-ab: need BASE and HEAD (scripts/corpus-ab.sh origin/main HEAD), or --baseline [REF]" >&2
  exit 2
fi

[ -n "$corpus" ] || corpus="${FERRET_CORPUS_DIR:-}"
[ -n "$corpus" ] || corpus="$repo_root/../ferret-corpus"
if [ ! -d "$corpus/by-format" ]; then
  echo "corpus-ab: no corpus at $corpus (by-format/ is missing)." >&2
  echo "corpus-ab: fetch one with scripts/corpus-fetch.sh (or make corpus-fetch), or pass --corpus DIR." >&2
  exit 2
fi
corpus=$(cd "$corpus" && pwd)

for tool in git go python3 tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "corpus-ab: $tool is required" >&2; exit 2; }
done

base_sha=$(git -C "$repo_root" rev-parse --verify --quiet "${base_ref}^{commit}") ||
  { echo "corpus-ab: BASE '$base_ref' is not a commit" >&2; exit 2; }
head_sha=$(git -C "$repo_root" rev-parse --verify --quiet "${head_ref}^{commit}") ||
  { echo "corpus-ab: HEAD '$head_ref' is not a commit" >&2; exit 2; }

if [ -n "$out" ]; then
  mkdir -p "$out" || { echo "corpus-ab: cannot create $out" >&2; exit 2; }
else
  # Next to the corpus, which is outside every repository and ignored by its own .gitignore.
  mkdir -p "$corpus/runs" || { echo "corpus-ab: cannot create $corpus/runs" >&2; exit 2; }
  out=$(mktemp -d "$corpus/runs/$(date -u +%Y%m%dT%H%M%SZ)-${base_sha:0:12}-${head_sha:0:12}.XXXX") ||
    { echo "corpus-ab: mktemp failed" >&2; exit 2; }
fi
out=$(cd "$out" && pwd)
log="$out/ab.log"
echo "corpus-ab: $mode run in $out (log: $log)"

export GOFLAGS="${GOFLAGS:--mod=mod}"

build() { # build <sha> <binary>
  local sha="$1" bin="$2" src="$out/src-${1:0:12}"
  if [ -x "$bin" ]; then return 0; fi
  mkdir -p "$src" &&
    git -C "$repo_root" archive --format=tar "$sha" | tar -x -C "$src" &&
    (cd "$src" && go build -trimpath -o "$bin" ./cmd)
}

mkdir -p "$out/bin"
base_bin="$out/bin/ferret-scan-${base_sha:0:12}"
head_bin="$out/bin/ferret-scan-${head_sha:0:12}"
echo "corpus-ab: building BASE $base_ref (${base_sha:0:12})" | tee -a "$log"
build "$base_sha" "$base_bin" >>"$log" 2>&1 || { echo "corpus-ab: BASE build failed, see $log" >&2; exit 2; }
if [ "$head_sha" != "$base_sha" ]; then
  echo "corpus-ab: building HEAD $head_ref (${head_sha:0:12})" | tee -a "$log"
  build "$head_sha" "$head_bin" >>"$log" 2>&1 || { echo "corpus-ab: HEAD build failed, see $log" >&2; exit 2; }
fi

python3 - "$mode" "$corpus" "$out" "$base_ref" "$base_sha" "$base_bin" "$head_ref" "$head_sha" "$head_bin" \
  ${pass[@]+"${pass[@]}"} <<'PY' 2>&1 | tee -a "$log"
import argparse
import collections
import concurrent.futures
import csv
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import xml.etree.ElementTree as ET
import zipfile

MB = 1 << 20
FLAGS = ["--checks", "all", "--confidence", "all", "--limit", "0", "--config", "/dev/null", "--quiet", "--no-color"]
OTHER_FORMATS = ["text", "csv", "yaml", "junit", "gitlab-sast", "sarif"]
STRATEGIES = ["simple", "format_preserving"]
DIMS = ["9", "11", "7", "4", "ne", "p0", "5", "6"]
# Containers whose text may be stored as UTF-16 (OLE streams, media tags): the raw survivor check
# searches those encodings too.
WIDE = {"doc", "xls", "ppt", "mp3", "wav", "flac", "m4a", "mp4", "mov", "m4v", "3gp", "3g2", "avi", "mkv",
        "webm", "jpg", "jpeg", "jpe", "png", "gif", "tif", "tiff", "bmp", "webp", "heic", "pdf"}
KNOWN = set("pdf docx docm xlsx xlsm pptx pptm odt ods odp ott ots otp doc xls ppt rtf svg jpg jpeg jpe png gif "
            "tif tiff bmp webp heic heif mp3 wav flac m4a mp4 mov m4v 3gp 3g2 avi mkv webm zip txt csv tsv json "
            "yaml yml xml html htm md log ini toml cfg conf properties py go java js ts sql sh cxx".split())
CRED_EXTS = {"env", "pem", "key", "p12", "pfx", "crt", "cer", "der", "jks", "keystore", "kdbx", "ppk", "gpg"}
CRED_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".pgpass"}
CRED_DIRS = {".ssh", ".aws", ".gnupg"}
CRED_EXCLUDE = ",".join(["*." + e for e in sorted(CRED_EXTS)] + [".env", ".env.*"] + sorted(CRED_NAMES) +
                        sorted(CRED_DIRS))
PANIC_RE = re.compile(r"(?m)^(panic: |fatal error: )|^goroutine \d+ \[")
RECOVERED_RE = re.compile(r"(?i)panic")
LABEL_ONLY = re.compile(r"^\s*[A-Za-z][\w .()/-]{0,40}:\s*$")
GITLAB_SEVERITIES = {"Info", "Unknown", "Low", "Medium", "High", "Critical"}
SARIF_LEVELS = {"none", "note", "warning", "error"}
# What is masked before outputs are compared byte for byte: the run's duration, the scan start and end
# times, junit time attributes, and wall-clock stamps in finding metadata (reconstruction_timestamp,
# seconds since the epoch, on legal-notice findings).
JSON_STAMP = (rb'("[A-Za-z_]*[Tt]imestamp" *: *)"?[0-9]{9,13}"?', rb'\1"-"')
MASKS = {
    "json": [(rb'"duration_seconds": *[-0-9.eE+]+', b'"duration_seconds": 0'), JSON_STAMP],
    "yaml": [(rb"duration_seconds: *[-0-9.eE+]+", b"duration_seconds: 0"),
             (rb"([A-Za-z_]*[Tt]imestamp *: *)['\"]?[0-9]{9,13}['\"]?", rb"\1-")],
    "gitlab-sast": [(rb'"(start_time|end_time)": *"[^"]*"', rb'"\1": "-"'), JSON_STAMP],
    "junit": [(rb'\b(time|timestamp)="[^"]*"', rb'\1="-"')],
    "sarif": [(rb'"(startTimeUtc|endTimeUtc)": *"[^"]*"', rb'"\1": "-"'), JSON_STAMP],
    "text": [(rb"(?im)^(.*\b(duration|elapsed|took|scan time)\b.*?)\d+(\.\d+)?\s*(ms|s|m)\b", rb"\1<t>")],
    "csv": [],
}

OUT_LOCK = threading.Lock()
CHILDREN = set()      # live child process groups, killed on SIGTERM/SIGINT
PRIVATE_DIRS = []     # 0700 directories holding private derivatives; removed on every exit


def log(msg=""):
    with OUT_LOCK:
        print(msg, flush=True)


def sha(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def bucket(n):
    k = 0
    while (1024 << k) < n:
        k += 1
    return k


def bucket_label(k):
    b = 1024 << k
    return f"<={b >> 20}MB" if b >= MB else f"<={b >> 10}KB"


def quantile(values, q):
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def credential_name(path):
    parts = [p for p in re.split(r"[/\\]", path.lower()) if p]
    if not parts:
        return False
    name = parts[-1]
    ext = name.rsplit(".", 1)[-1] if "." in name[1:] else ""
    return (name.startswith(".env") or ext in CRED_EXTS or name in CRED_NAMES
            or any(p in CRED_DIRS for p in parts[:-1]))


def round_floats(obj, places=4):
    """Every float rounded: a timing printed with 17 digits is noise, and its digit runs can equal a value."""
    if isinstance(obj, float):
        return round(obj, places)
    if isinstance(obj, dict):
        return {k: round_floats(v, places) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [round_floats(v, places) for v in obj]
    return obj


def md_table(head, rows):
    out = ["| " + " | ".join(str(h) for h in head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def mask(fmt, raw):
    for pat, rep in MASKS.get(fmt, []):
        raw = re.sub(pat, rep, raw)
    return raw


def masked_value(text):
    t = re.sub(r"\s+", " ", text)
    if len(t) <= 4:
        return "*" * len(t)
    shown = t[:2] + "*" * min(len(t) - 4, 30) + t[-2:]
    return f"{shown} ({len(t)})"


# -------------------------------------------------------------------------------------------------
# Running a binary: wall and CPU time, peak RSS, a timeout that kills the whole process group, and
# an optional stdout file with a size cap. Peak RSS is sampled from /proc/<pid>/status VmHWM where
# there is one: wait4's ru_maxrss on Linux keeps the forked parent's high-water mark from before exec.
# -------------------------------------------------------------------------------------------------
def run(cmd, timeout, env, cwd, stdout_path=None, stdout_cap=None):
    start = time.monotonic()
    out_f = open(stdout_path, "wb") if stdout_path else None
    proc = subprocess.Popen(cmd, stdout=out_f or subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, start_new_session=True, env=env, cwd=cwd)
    with OUT_LOCK:
        CHILDREN.add(proc.pid)
    bufs, peak, done, fired = {}, [0], threading.Event(), []

    def drain(name, stream):
        bufs[name] = stream.read()

    def kill(reason):
        fired.append(reason)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass

    def sample():
        status = f"/proc/{proc.pid}/status"
        while not done.is_set():
            try:
                with open(status) as f:
                    for line in f:
                        if line.startswith("VmHWM:"):
                            peak[0] = max(peak[0], int(line.split()[1]) * 1024)
                            break
            except (OSError, ValueError):
                return
            if stdout_cap and stdout_path:
                try:
                    if os.path.getsize(stdout_path) > stdout_cap:
                        kill("output cap")
                        return
                except OSError:
                    pass
            done.wait(0.1)

    threads = [] if out_f else [threading.Thread(target=drain, args=("out", proc.stdout))]
    threads.append(threading.Thread(target=drain, args=("err", proc.stderr)))
    sampling = os.path.isdir("/proc/self") and hasattr(os, "waitid")
    if sampling:
        threads.append(threading.Thread(target=sample))
    for t in threads:
        t.start()
    timer = threading.Timer(timeout, kill, args=("timeout",))
    timer.start()
    if sampling:
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
    done.set()
    _, status, usage = os.wait4(proc.pid, 0)
    timer.cancel()
    for t in threads:
        t.join()
    if out_f:
        out_f.close()
    with OUT_LOCK:
        CHILDREN.discard(proc.pid)
    code = os.waitstatus_to_exitcode(status)
    proc.returncode = code
    rss = peak[0] or usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    return dict(code=code, wall=time.monotonic() - start, cpu=usage.ru_utime + usage.ru_stime, rss=rss,
                timed_out="timeout" in fired, capped="output cap" in fired, out=bufs.get("out", b""),
                err=bufs.get("err", b"").decode("utf-8", "replace"))


def classify(res, produced):
    if res["timed_out"]:
        return "timeout"
    if res.get("capped"):
        return "output-cap"
    if PANIC_RE.search(res["err"]):
        return "panic"
    if res["code"] < 0:
        return f"killed(signal {-res['code']})"
    if not produced:
        return f"no-output(exit {res['code']})"
    if res["code"] != 0:
        return f"exit {res['code']}"
    return "ok"


def recovered(err):
    """stderr lines naming a panic the process survived (a recover() turned it into an error)."""
    return sum(1 for line in err.splitlines() if RECOVERED_RE.search(line) and not PANIC_RE.search(line))


def parse_json(raw):
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def parse_footer(err):
    """The tool's not-examined report: up to 8 files are listed under their cause; above, a tally."""
    files, tally, cause, inside = [], collections.Counter(), None, False
    for line in err.splitlines():
        if line.startswith("NOT FULLY EXAMINED:"):
            inside = True
            continue
        if not inside:
            continue
        m = re.match(r"^  (\S.*?) \((\d+)\)$", line)
        if m:
            cause = m.group(1)
            tally[cause] += int(m.group(2))
            continue
        m = re.match(r"^    (\S.*?)  (.*)$", line)
        if m and cause:
            files.append((m.group(1), cause, m.group(2)))
            continue
        if line.startswith("  ") and ": " in line and not line.startswith("    "):
            pairs = [re.match(r"^(.*): (\d+)$", p.strip()) for p in line.strip().split("  ·  ")]
            if pairs and all(pairs):
                for p in pairs:
                    tally[p.group(1)] += int(p.group(2))
                continue
        if not line.startswith("  "):
            inside = False
    return files, tally


def ne_cause(cause, detail):
    d = (detail or "").lower()
    if cause == "coverage cut short":
        if "page budget" in d:
            return "cut short: page budget"
        if "could not be read" in d:
            return "cut short: pages unreadable"
        if "cap" in d or "too large" in d or "exceeds" in d:
            return "cut short: size cap"
        if "timeout" in d or "timed out" in d or "deadline" in d:
            return "cut short: timeout"
        if "budget" in d:
            return "cut short: budget"
        return "cut short: other"
    if cause.startswith("no body text"):
        return "no body text"
    if cause == "file too large to scan":
        return "size cap"
    return cause


def findings(doc):
    """[(key, confidence, level, text)]; key = (path, validator, type, line, sha256(text))."""
    out = []
    for r in (doc or {}).get("results") or []:
        text = str(r.get("text", ""))
        key = (str(r.get("filename", "")), str(r.get("validator", "")), str(r.get("type", "")),
               int(r.get("line_number") or 0), sha(text))
        out.append((key, round(float(r.get("confidence") or 0), 2), str(r.get("confidence_level", "")), text))
    return out


def multiset(fl):
    c = collections.Counter()
    for key, _, _, _ in fl:
        c[key] += 1
    return c


def diff(a, b):
    """Multiset diff of two findings lists: (kind, key, base_conf, head_conf, level)."""
    ma, mb = collections.defaultdict(list), collections.defaultdict(list)
    lv = {}
    for key, conf, level, _ in a:
        ma[key].append(conf)
        lv.setdefault(key, level)
    for key, conf, level, _ in b:
        mb[key].append(conf)
        lv[key] = level
    rows = []
    for key in set(ma) | set(mb):
        x, y = sorted(ma.get(key, [])), sorted(mb.get(key, []))
        common = min(len(x), len(y))
        rows += [("changed", key, x[i], y[i], lv[key]) for i in range(common) if x[i] != y[i]]
        rows += [("new", key, None, y[i], lv[key]) for i in range(common, len(y))]
        rows += [("lost", key, x[i], None, lv[key]) for i in range(common, len(x))]
    return rows


def key_string(key):
    return "\t".join([key[0], key[1], key[2], str(key[3]), key[4]])


def key_id(key):
    return hashlib.sha256(key_string(key).encode("utf-8", "surrogatepass")).hexdigest()


def output_blobs(path):
    """A redacted output's searchable bytes: every zip part decompressed, else the file itself."""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                return [z.read(i) for i in z.infolist() if i.file_size <= 64 * MB]
        with open(path, "rb") as f:
            return [f.read(64 * MB)]
    except Exception:
        return []


def forms(value, wide):
    v = value.encode("utf-8", "surrogatepass")
    out = {v, value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").encode("utf-8", "surrogatepass")}
    if wide:
        out |= {value.encode("utf-16-le", "surrogatepass"), value.encode("utf-16-be", "surrogatepass")}
    return out


def present(value, blobs, wide):
    return any(f in b for f in forms(value, wide) for b in blobs)


def occurrences(value, blobs, wide):
    return sum(b.count(f) for f in forms(value, wide) for b in blobs)


def eligible(text):
    """A reported value long or structured enough that finding it again is not a coincidence."""
    t = text.strip()
    return not LABEL_ONLY.match(t) and (len(t) >= 8 or (len(t) >= 6 and re.search(r"[\d@]", t)))


GO_SPACE = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a" \
           "\u2028\u2029\u202f\u205f\u3000"


def h16(s):
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:16] if s else ""


def suppression_hash(r, version):
    """internal/suppressions/suppression.go findingHashVersion, for versions 1, 2 and 5."""
    full = (r.get("full_line") or "").strip(GO_SPACE).encode("utf-8", "surrogatepass")[:8192]
    comps = [r["type"].encode()]
    if version == 1:
        comps.append(("%.2f" % float(r["confidence"])).encode())
    base = str(r["filename"]).replace("\\", "/").rsplit("/", 1)[-1]
    comps += [full, base.encode("utf-8", "surrogatepass"), str(r["line_number"]).encode()]
    before, after, text = r.get("before_text") or "", r.get("after_text") or "", r.get("text") or ""
    if version == 5:
        before, after, text = before.lstrip(GO_SPACE), after.rstrip(GO_SPACE), text.strip(GO_SPACE)
    comps += [h16(before + after).encode(), h16(text).encode()]
    return hashlib.sha256(b"|".join(comps)).hexdigest()


def write_rules(path, hashes):
    lines = ['version: "1.0"', "rules:"]
    for i, h in enumerate(hashes, 1):
        lines += [f"    - id: SUP-{i:08d}", f"      hash: {h}", "      reason: corpus-ab synthetic rule",
                  "      enabled: true", "      created_at: 2026-01-01T00:00:00Z"]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


# -------------------------------------------------------------------------------------------------
# Structural checks of each output format. Problems are fixed phrases plus counts: never content,
# so they can be reported for the private set as they are.
# -------------------------------------------------------------------------------------------------
def validate(fmt, raw):
    problems, count = [], None
    try:
        if fmt == "json":
            d = json.loads(raw)
            if not isinstance(d, dict) or not isinstance(d.get("results"), list) or not isinstance(d.get("stats"), dict):
                problems.append("not an object with stats and results")
            else:
                count = len(d["results"])
        elif fmt == "yaml":
            try:
                import yaml  # optional: PyYAML
            except ImportError:
                return ["not parsed: PyYAML is not installed"], None
            d = yaml.safe_load(raw)
            if not isinstance(d, dict) or not isinstance(d.get("results"), list):
                problems.append("not a mapping with results")
            else:
                count = len(d["results"])
        elif fmt == "csv":
            rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
            if not rows:
                problems.append("empty")
            else:
                bad = sum(1 for r in rows[1:] if len(r) != len(rows[0]))
                if bad:
                    problems.append(f"{bad} row(s) whose field count differs from the header's {len(rows[0])}")
                count = len(rows) - 1
        elif fmt == "text":
            raw.decode("utf-8")
            if not raw.strip():
                problems.append("empty")
        elif fmt == "junit":
            root = ET.fromstring(raw)
            if root.tag != "testsuites":
                problems.append(f"root element is {root.tag}, not testsuites")
            count = 0
            for ts in root.iter("testsuite"):
                cases = ts.findall("testcase")
                failed = sum(1 for c in cases if c.find("failure") is not None)
                count += len(cases)
                for attr, want in (("tests", len(cases)), ("failures", failed)):
                    try:
                        if int(ts.get(attr, "-1")) != want:
                            problems.append(f"testsuite {attr}={ts.get(attr)} but {want} counted")
                    except ValueError:
                        problems.append(f"testsuite {attr} is not an integer")
                for el in [ts] + cases:
                    try:
                        float(el.get("time", "0"))
                    except ValueError:
                        problems.append("a time attribute is not a number")
                        break
        elif fmt == "gitlab-sast":
            d = json.loads(raw)
            for k in ("version", "vulnerabilities", "scan"):
                if k not in d:
                    problems.append(f"missing {k}")
            scan = d.get("scan") or {}
            for k in ("analyzer", "scanner", "type", "start_time", "end_time", "status"):
                if k not in scan:
                    problems.append(f"scan.{k} missing")
            vulns = d.get("vulnerabilities") or []
            count = len(vulns)
            ids = [v.get("id") for v in vulns]
            if len(set(ids)) != len(ids):
                problems.append("duplicate vulnerability ids")
            bad = collections.Counter()
            for v in vulns:
                if not v.get("identifiers"):
                    bad["no identifiers"] += 1
                if not (v.get("location") or {}).get("file"):
                    bad["no location.file"] += 1
                if v.get("severity") not in GITLAB_SEVERITIES:
                    bad["severity outside the schema enum"] += 1
                if not v.get("name") and not v.get("message"):
                    bad["no name or message"] += 1
            problems += [f"{n} vulnerability(ies): {k}" for k, n in sorted(bad.items())]
        elif fmt == "sarif":
            d = json.loads(raw)
            if d.get("version") != "2.1.0":
                problems.append("version is not 2.1.0")
            if not d.get("$schema"):
                problems.append("no $schema")
            runs = d.get("runs")
            if not isinstance(runs, list) or not runs:
                problems.append("runs is not a non-empty array")
                runs = []
            count = 0
            bad = collections.Counter()
            for r in runs:
                driver = (r.get("tool") or {}).get("driver") or {}
                if not driver.get("name"):
                    problems.append("a run has no tool.driver.name")
                rule_ids = [x.get("id") for x in driver.get("rules") or []]
                if len(set(rule_ids)) != len(rule_ids):
                    problems.append("duplicate rule ids")
                results = r.get("results")
                if not isinstance(results, list):
                    problems.append("a run's results is not an array")
                    continue
                count += len(results)
                known = set(rule_ids)
                for x in results:
                    if not isinstance(x.get("ruleId"), str) or (known and x.get("ruleId") not in known):
                        bad["ruleId missing or not a declared rule"] += 1
                    if not ((x.get("message") or {}).get("text") or (x.get("message") or {}).get("id")):
                        bad["no message.text"] += 1
                    if x.get("level", "warning") not in SARIF_LEVELS:
                        bad["level outside none/note/warning/error"] += 1
                    rank = x.get("rank", 0)
                    if not isinstance(rank, (int, float)) or not -1 <= rank <= 100:
                        bad["rank outside [-1, 100]"] += 1
                    for loc in x.get("locations") or []:
                        pl = loc.get("physicalLocation") or {}
                        uri = (pl.get("artifactLocation") or {}).get("uri")
                        if not uri:
                            bad["no artifactLocation.uri"] += 1
                        elif uri.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", uri):
                            bad["absolute artifactLocation.uri"] += 1
                        reg = pl.get("region") or {}
                        sl, sc, ec = reg.get("startLine"), reg.get("startColumn"), reg.get("endColumn")
                        if sl is not None and (not isinstance(sl, int) or sl < 1):
                            bad["region.startLine < 1"] += 1
                        if sc is not None and (not isinstance(sc, int) or sc < 1):
                            bad["region.startColumn < 1"] += 1
                        if ec is not None and isinstance(sc, int) and (not isinstance(ec, int) or ec < sc):
                            bad["region.endColumn < startColumn"] += 1
            problems += [f"{n} result(s): {k}" for k, n in sorted(bad.items())]
    except Exception as exc:  # the type only: a parser message can quote the document
        problems.append(f"does not parse ({type(exc).__name__})")
    return problems, count


# -------------------------------------------------------------------------------------------------
# The triage ledgers. Append-only TSVs; the latest row for a key wins.
# -------------------------------------------------------------------------------------------------
PUB_COLS = ["path", "validator", "type", "line", "text_sha256", "verdict", "note", "date", "run"]
PRIV_COLS = ["key_sha256", "type", "format", "level", "verdict", "note", "date", "run"]


def tsv_cell(v):
    return re.sub(r"[\t\r\n]+", " ", str(v))


class Ledger:
    def __init__(self, corpus, run_name):
        self.dir = os.path.join(corpus, "triage")
        self.run = run_name
        self.public, self.private = {}, {}
        for name, cols, store, keyf in (
                ("public.tsv", PUB_COLS, self.public,
                 lambda r: (r["path"], r["validator"], r["type"], int(r["line"] or 0), r["text_sha256"])),
                ("private.tsv", PRIV_COLS, self.private, lambda r: r["key_sha256"])):
            p = os.path.join(self.dir, name)
            if not os.path.exists(p):
                continue
            with open(p, encoding="utf-8") as f:
                for n, line in enumerate(f):
                    parts = line.rstrip("\n").split("\t")
                    if n == 0 and parts[0] == cols[0]:
                        continue
                    if len(parts) == len(cols):
                        row = dict(zip(cols, parts))
                        try:
                            store[keyf(row)] = row
                        except ValueError:
                            pass

    def verdict(self, key=None, hashed=None):
        row = self.private.get(hashed) if hashed else self.public.get(key)
        v = (row or {}).get("verdict", "").strip().upper()
        return {"TP": "TP", "FP": "FP", "UNSURE": "unsure"}.get(v)

    def add_private_pending(self, rows):
        """rows: [(key_sha256, type, format, level)] not yet in the ledger at all."""
        fresh = [r for r in rows if r[0] not in self.private]
        if not fresh:
            return 0
        os.makedirs(self.dir, exist_ok=True)
        p = os.path.join(self.dir, "private.tsv")
        new_file = not os.path.exists(p)
        with open(p, "a", encoding="utf-8") as f:
            if new_file:
                f.write("\t".join(PRIV_COLS) + "\n")
            for h, t, fmt, lv in fresh:
                f.write("\t".join(tsv_cell(x) for x in (h, t, fmt, lv, "", "", datetime.date.today(), self.run)) + "\n")
                self.private[h] = dict(key_sha256=h, verdict="")
        return len(fresh)


# -------------------------------------------------------------------------------------------------
class FileSet:
    def __init__(self, name, root, private, subset=None, link_root=None):
        self.name, self.private, self.src_root = name, private, root
        self.files, self.excluded = {}, collections.Counter()
        self.flags = ["--exclude", CRED_EXCLUDE] if private else []
        self.root = root
        if subset:
            # A subset of the public formats: a tree of hard links, so paths keep their form.
            self.root = link_root
            for fmt in sorted(subset):
                src = os.path.join(root, fmt)
                for dp, _, fns in os.walk(src):
                    dst = os.path.join(link_root, os.path.relpath(dp, root))
                    os.makedirs(dst, exist_ok=True)
                    for n in fns:
                        try:
                            os.link(os.path.join(dp, n), os.path.join(dst, n))
                        except OSError:  # another filesystem (--out elsewhere): a copy
                            shutil.copy2(os.path.join(dp, n), os.path.join(dst, n))
        for dp, dns, fns in os.walk(self.root):
            if private:
                kept = [d for d in dns if d.lower() not in CRED_DIRS]
                self.excluded["credential directory"] += len(dns) - len(kept)
                dns[:] = kept
            for n in fns:
                p = os.path.join(dp, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    self.excluded["unreadable"] += 1
                    continue
                if os.path.islink(p):
                    self.excluded["symlink"] += 1
                    continue
                if not os.path.isfile(p):
                    continue
                rel = os.path.relpath(p, self.root)
                if private and credential_name(rel):
                    self.excluded["credential-shaped"] += 1
                    continue
                if private and st.st_mode & 0o222:
                    self.excluded["writable (the plan says chmod -R a-w after every copy)"] += 1
                self.files[rel] = dict(abs=p, fmt=self.fmt_of(rel), bytes=st.st_size, bucket=bucket(st.st_size))
        self.text_cache = set()  # private finding texts, for the privacy audit only

    def container(self, name):
        """The corpus file a finding belongs to. A finding inside an embedded document is reported as
        '<container basename> -> <part>', without the container's directory."""
        if " -> " not in name:
            return name
        base = name.split(" -> ", 1)[0]
        if not hasattr(self, "_by_base"):
            seen = collections.Counter(os.path.basename(r) for r in self.files)
            self._by_base = {os.path.basename(r): r for r in self.files if seen[os.path.basename(r)] == 1}
        return self._by_base.get(base, base)

    def fmt_of(self, rel):
        rel = self.container(rel)
        if not self.private and os.sep in rel:
            return rel.split(os.sep, 1)[0]
        name = rel.rsplit(os.sep, 1)[-1].lower()
        ext = name.rsplit(".", 1)[-1] if "." in name[1:] else ""
        return ext if ext in KNOWN else "other"

    def size_of(self, rel):
        return (self.files.get(rel) or {}).get("bytes", 0)


class Measure:
    def __init__(self, a):
        self.a = a
        self.same = a.base_sha == a.head_sha
        self.labels = ["base"] if self.same else ["base", "head"]
        self.measured = "base" if self.same else "head"
        self.bins = {"base": a.base_bin, "head": a.base_bin if self.same else a.head_bin}
        self.cwd = os.path.join(a.out, "cwd")
        os.makedirs(self.cwd, exist_ok=True)
        cfg = os.path.join(a.out, "config-home")
        os.makedirs(cfg, exist_ok=True)
        self.env = dict(os.environ, FERRET_CONFIG_DIR=cfg)
        self.dims = self.parse_dims(a.only)
        self.private_dims = self.parse_dims(a.private_dims) if a.private_dims else set(self.dims)
        self.pub_dir = os.path.join(a.out, "public")
        os.makedirs(os.path.join(self.pub_dir, "raw"), exist_ok=True)
        self.ledger = Ledger(a.corpus, os.path.basename(a.out))
        self.sets = []
        subset = {f.strip() for f in a.formats.split(",") if f.strip()} if a.formats else None
        self.sets.append(FileSet("public", os.path.join(a.corpus, "by-format"), False, subset,
                                 os.path.join(a.out, "public-subset") if subset else None))
        self.private_tmp = None
        if a.include_private:
            proot = os.path.join(a.corpus, "private")
            if os.path.isdir(proot):
                self.private_tmp = tempfile.mkdtemp(prefix="private.", dir=a.out)
                os.chmod(self.private_tmp, 0o700)
                PRIVATE_DIRS.append(self.private_tmp)
                self.sets.append(FileSet("private", proot, True))
            else:
                log("corpus-ab: --include-private given but the corpus has no private/ directory")
        self.state = {s.name: dict(runs={}, fl={}, formats={}, single={}, fixtures={}, redaction={}, supp={},
                                   p0=[], notes=[]) for s in self.sets}
        self.started = time.time()
        self.load = [os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)]

    @staticmethod
    def parse_dims(text):
        if not text or text.strip().lower() == "all":
            return set(DIMS)
        dims = {d.strip().lower() for d in text.split(",") if d.strip()}
        unknown = dims - set(DIMS)
        if unknown:
            raise SystemExit(f"corpus-ab: unknown dimension(s) {sorted(unknown)}; use {','.join(DIMS)}")
        return dims

    def want(self, fs, *dims):
        have = self.private_dims if fs.private else self.dims
        return any(d in have for d in dims)

    def tmpdir(self, fs, prefix):
        parent = self.private_tmp if fs.private else self.pub_dir
        d = tempfile.mkdtemp(prefix=prefix + ".", dir=parent)
        if fs.private:
            os.chmod(d, 0o700)
        return d

    def save_public(self, name, data):
        with gzip.open(os.path.join(self.pub_dir, name + ".gz"), "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8", "replace"))

    def p0(self, fs, where, status, rel=None, detail=""):
        e = dict(where=where, status=status)
        if fs.private:
            if rel is not None:
                e.update(format=fs.files[rel]["fmt"], size=bucket_label(fs.files[rel]["bucket"]))
        else:
            e.update(path=rel or "-", detail=re.sub(r"\s+", " ", detail)[-300:])
        with OUT_LOCK:
            self.state[fs.name]["p0"].append(e)

    @staticmethod
    def private_stats(fs, stats):
        """The binary's stats with skipped_types re-keyed by known format: an extension is part of a name."""
        if not fs.private or not stats.get("skipped_types"):
            return stats
        out = dict(stats)
        keyed = collections.Counter()
        for ext, n in stats["skipped_types"].items():
            e = str(ext).lower().lstrip(".")
            keyed["." + e if e in KNOWN else "other"] += int(n or 0)
        out["skipped_types"] = dict(keyed)
        return out

    # -- tree runs ----------------------------------------------------------------------------
    def tree(self, fs, label, binary, fmt, extra=(), root=None, keep=True):
        cmd = [binary, "--file", root or fs.root, "--recursive"] + FLAGS + ["--format", fmt, "--show-match"] + \
            fs.flags + list(extra)
        res = run(cmd, self.a.timeout, self.env, self.cwd)
        raw = res.pop("out")
        doc = parse_json(raw) if fmt == "json" else None
        res["status"] = classify(res, doc is not None if fmt == "json" else bool(raw.strip()))
        res["masked"] = hashlib.sha256(mask(fmt, raw)).hexdigest()
        res["bytes"] = len(raw)
        res["recovered"] = recovered(res["err"])
        res["tally"] = dict(parse_footer(res["err"])[1])
        res["stats"] = self.private_stats(fs, (doc or {}).get("stats") or {})
        if not fs.private and keep:
            self.save_public(f"raw/{label}.{fmt}", raw)
            self.save_public(f"raw/{label}.{fmt}.stderr", res["err"])
        err = res.pop("err")
        if res["status"] != "ok" or res["recovered"]:
            self.p0(fs, f"tree {label} {fmt}", res["status"] if res["status"] != "ok" else
                    f"{res['recovered']} recovered panic line(s)", detail="" if fs.private else err[-400:])
        st = res["stats"]
        log(f"   [{fs.name}] {label:<9} {fmt:<11} {res['wall']:7.1f}s cpu {res['cpu']:7.1f}s rss "
            f"{res['rss'] / MB:6.0f} MB  findings {st.get('total_findings', '-'):>6}  not-examined "
            f"{st.get('files_not_examined', 0):>4}  {res['status']}")
        return res, raw, doc

    def json_passes(self, fs, st):
        n = max(1, self.a.runs if self.want(fs, "11") else 1)
        if self.same:
            labels = [f"base{i}" for i in range(1, max(n, 2 if self.want(fs, "9") else 1) + 1)]
        else:
            labels = ["base1", "base2"] + [f"head{i}" for i in range(1, n + 1)]
        st["r5"] = os.path.join(self.private_tmp if fs.private else self.pub_dir, "suppressions-v5.yaml")
        for lab in labels:
            extra = ["--generate-suppressions", "--suppression-file", st["r5"]] if (lab == "base1" and self.want(fs, "6")) else []
            res, raw, doc = self.tree(fs, lab, self.bins["base" if lab.startswith("base") else "head"], "json", extra)
            if lab == labels[0] and self.want(fs, "7"):
                problems, count = validate("json", raw)
                st["formats"].setdefault(self.measured if self.same else "base", {})["json"] = dict(
                    status=res["status"], problems=problems, count=count, masked=res["masked"], bytes=res["bytes"])
            fl = findings(doc)
            if fs.private:
                for _, _, _, text in fl:
                    if len(text.strip()) >= 10:
                        fs.text_cache.add(text.strip())
                fl = [(k, c, lv, None) for k, c, lv, _ in fl]
            st["runs"][lab] = res
            st["fl"][lab] = fl
        if not self.same and self.want(fs, "7") and "head1" in st["runs"]:
            # json is a format of its own for dimension 7: HEAD's first run.
            res = st["runs"]["head1"]
            raw_ok = res["status"] == "ok"
            st["formats"].setdefault("head", {})["json"] = dict(status=res["status"], problems=[] if raw_ok else ["no output"],
                                                                 count=len(st["fl"]["head1"]), masked=res["masked"],
                                                                 bytes=res["bytes"])

    # -- dimension 4 / NE / P0: every file alone ---------------------------------------------------
    def single(self, fs, label, rel):
        f = fs.files[rel]
        cmd = [self.bins[label], "--file", f["abs"]] + FLAGS + ["--format", "json"] + fs.flags
        res = run(cmd, self.a.file_timeout, self.env, self.cwd)
        doc = parse_json(res["out"])
        status = classify(res, doc is not None)
        stats = (doc or {}).get("stats") or {}
        cause, detail = None, ""
        if status != "ok":
            cause = status
        elif stats.get("files_skipped"):
            cause = "unsupported type"
        else:
            files, tally = parse_footer(res["err"])
            if files:
                cause, detail = ne_cause(files[0][1], files[0][2]), files[0][2]
            elif tally:
                cause = ne_cause(next(iter(tally)), "")
            elif stats.get("files_not_examined"):
                cause = "not examined (no cause printed)"
        rec = dict(wall=res["wall"], cpu=res["cpu"], rss=res["rss"], code=res["code"], status=status, cause=cause,
                   findings=stats.get("total_findings"), recovered=recovered(res["err"]))
        if not fs.private:
            rec["detail"] = re.sub(r"\s+", " ", detail)[:300]
            if status != "ok" or rec["recovered"]:
                rec["stderr_tail"] = res["err"][-600:]
        return rec

    def single_pass(self, fs, st):
        rels = sorted(fs.files)
        total, done, t0 = len(rels), 0, time.monotonic()
        out = {lab: {} for lab in self.labels}
        lock = threading.Lock()

        def work(i, rel):
            order = self.labels if i % 2 == 0 else list(reversed(self.labels))
            return rel, {lab: self.single(fs, lab, rel) for lab in order}

        log(f"   [{fs.name}] per-file runs: {total} file(s) x {len(self.labels)} binary(ies), {self.a.jobs} at a time")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.a.jobs) as pool:
            futs = [pool.submit(work, i, rel) for i, rel in enumerate(rels)]
            for fut in concurrent.futures.as_completed(futs):
                try:
                    rel, recs = fut.result()
                except Exception as exc:
                    log(f"   [{fs.name}] per-file run failed: {type(exc).__name__}")
                    continue
                with lock:
                    for lab, rec in recs.items():
                        out[lab][rel] = rec
                    done += 1
                    if done % max(50, total // 10) == 0 or done == total:
                        log(f"   [{fs.name}] per-file {done}/{total}  {time.monotonic() - t0:6.0f}s")
        st["single"] = out
        for lab, recs in out.items():
            for rel, rec in recs.items():
                if rec["status"] != "ok" or rec["recovered"]:
                    self.p0(fs, f"single {lab}", rec["status"] if rec["status"] != "ok" else
                            f"{rec['recovered']} recovered panic line(s)", rel, rec.get("stderr_tail", ""))
        if fs.private:
            return
        # The standing timing fixtures: the baseline's list when it exists, else this run's slowest.
        fixtures = []
        bl = os.path.join(self.a.corpus, "baselines", self.a.base_sha + ".json")
        if os.path.exists(bl):
            try:
                with open(bl) as f:
                    fixtures = [x["path"] for x in json.load(f)["public"]["timing"]["fixtures"] if x["path"] in fs.files]
            except (OSError, ValueError, KeyError, TypeError):
                fixtures = []
        if not fixtures:
            ok = [(r["cpu"], rel) for rel, r in out["base"].items() if r["status"] == "ok"]
            fixtures = [rel for _, rel in sorted(ok, reverse=True)[:20]]
        fixtures = [rel for rel in fixtures if all(rel in out[lab] for lab in self.labels)]
        best = {lab: {rel: dict(cpu=[out[lab][rel]["cpu"]], wall=[out[lab][rel]["wall"]]) for rel in fixtures}
                for lab in self.labels}
        extra_runs = max(0, self.a.fixture_runs - 1)
        if fixtures and extra_runs:
            log(f"   [{fs.name}] timing fixtures: {len(fixtures)} file(s), {extra_runs} more run(s) per binary")
            jobs = [(rel, k) for rel in fixtures for k in range(extra_runs)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.a.jobs) as pool:
                for rel, recs in pool.map(lambda j: (j[0], {lab: self.single(fs, lab, j[0]) for lab in
                                                            (self.labels if j[1] % 2 else list(reversed(self.labels)))}), jobs):
                    for lab, rec in recs.items():
                        best[lab][rel]["cpu"].append(rec["cpu"])
                        best[lab][rel]["wall"].append(rec["wall"])
        st["fixtures"] = {lab: {rel: dict(cpu=min(v["cpu"]), wall=min(v["wall"]), runs=len(v["cpu"]))
                                for rel, v in d.items()} for lab, d in best.items()}

    # -- dimension 5: redaction -------------------------------------------------------------------
    def redact(self, fs, label, strategy):
        od = self.tmpdir(fs, f"redacted-{label}-{strategy}")
        try:
            res, raw, doc = self.tree(fs, f"{label}-redact", self.bins[label], "json",
                                      ["--enable-redaction", "--redaction-strategy", strategy,
                                       "--redaction-output-dir", od], keep=False)
            if not fs.private:
                self.save_public(f"raw/{label}-redact-{strategy}.json", raw)
            st = (doc or {}).get("stats") or {}
            unred = (doc or {}).get("unredacted") or []
            in_roots = {os.path.abspath(fs.root), os.path.realpath(fs.root)}
            mirror = od + os.path.abspath(fs.root)

            def strip(p, roots):
                for r in roots:
                    if p.startswith(r + os.sep):
                        return p[len(r) + 1:]
                return None

            undisclosed = {strip(u.get("path", ""), in_roots) for u in unred}
            want, texts = collections.defaultdict(collections.Counter), collections.defaultdict(dict)
            for key, conf, level, text in findings(doc):
                if not LABEL_ONLY.match(text.strip()):
                    rel = fs.container(key[0])
                    want[rel][(key[2], key[4])] += 1
                    texts[rel][(key[2], key[4])] = text
            outputs = {}
            for dp, _, fns in os.walk(od):
                for n in fns:
                    rel = strip(os.path.join(dp, n), {od + r for r in in_roots})
                    if rel:
                        outputs[rel] = os.path.join(dp, n)
            per_fmt = collections.defaultdict(lambda: collections.Counter())
            for rel, f in fs.files.items():
                per_fmt[f["fmt"]]["files"] += 1
            for rel in outputs:
                per_fmt[fs.fmt_of(rel)]["written"] += 1
            causes = collections.defaultdict(collections.Counter)
            for u in unred:
                rel = strip(u.get("path", ""), in_roots)
                fmt = fs.fmt_of(rel) if rel else "other"
                per_fmt[fmt]["not_redacted"] += 1
                per_fmt[fmt]["values_not_redacted"] += int(u.get("reported_values") or 0)
                causes[fmt][str(u.get("cause", "?"))] += 1
            survivors, sv_types = [], collections.Counter()
            if outputs:
                rres, rraw, rdoc = self.tree(fs, f"{label}-rescan", self.bins[label], "json", root=mirror, keep=False)
                got = collections.defaultdict(collections.Counter)
                for key, conf, level, text in findings(rdoc):
                    got[fs.container(key[0])][(key[2], key[4])] += 1
                for rel, path in sorted(outputs.items()):
                    if rel in undisclosed:
                        continue
                    fmt = fs.fmt_of(rel)
                    wide = fmt in WIDE
                    blobs = output_blobs(path)
                    same = [k for k in want.get(rel, {}) if got[rel].get(k)]
                    silent = sum(min(want[rel][k], got[rel][k]) for k in same)
                    verbatim = sum(min(want[rel][k], got[rel][k]) for k in same if present(texts[rel][k], blobs, wide))
                    vals = {t for t in texts.get(rel, {}).values() if eligible(t)}
                    raw_found = [v for v in vals if present(v, blobs, wide)]
                    unreported = 0
                    if raw_found:
                        inblobs = output_blobs(fs.files[rel]["abs"]) if rel in fs.files else []
                        reported = collections.Counter(texts[rel][k] for k in want[rel] for _ in range(want[rel][k]))
                        unreported = sum(1 for v in raw_found if occurrences(v, inblobs, wide) > reported[v])
                    if silent or raw_found:
                        per_fmt[fmt]["silent"] += silent
                        per_fmt[fmt]["verbatim"] += verbatim
                        per_fmt[fmt]["raw"] += len(raw_found)
                        per_fmt[fmt]["raw_unreported_in_input"] += unreported
                        per_fmt[fmt]["files_with_survivors"] += 1
                        for t in {k[0] for k in same}:
                            sv_types[(fmt, t)] += 1
                        if not fs.private:
                            survivors.append(dict(path=rel, silent=silent, verbatim=verbatim, raw=len(raw_found),
                                                  raw_also_unreported_in_input=unreported,
                                                  types=sorted({k[0] for k in same})))
                if rres["status"] != "ok":
                    self.p0(fs, f"redaction rescan {label} {strategy}", rres["status"])
            out = dict(status=res["status"], code=res["code"], wall=res["wall"], cpu=res["cpu"],
                       recovered=res["recovered"], files_not_redacted=st.get("files_not_redacted", 0),
                       values_not_redacted=st.get("values_not_redacted", 0), written=len(outputs),
                       per_format={k: dict(v) for k, v in per_fmt.items()},
                       causes={k: dict(v) for k, v in causes.items()},
                       survivor_types={f"{f}\t{t}": n for (f, t), n in sv_types.items()})
            if not fs.private:
                out["survivors"] = survivors
                out["unredacted"] = [dict(path=strip(u.get("path", ""), in_roots) or "?", cause=u.get("cause", ""),
                                          detail=re.sub(r"\s+", " ", str(u.get("detail", "")))[:240],
                                          values=u.get("reported_values", 0)) for u in unred]
            tot = collections.Counter()
            for v in per_fmt.values():
                tot.update(v)
            log(f"   [{fs.name}] redact {label} {strategy:<17} written {len(outputs):>5}  not-redacted "
                f"{st.get('files_not_redacted', 0):>4}  silent {tot['silent']:>4} (verbatim {tot['verbatim']})  raw "
                f"{tot['raw']:>4}  exit {res['code']}  {res['status']}")
            return out
        finally:
            if fs.private or not self.a.keep_redacted:
                shutil.rmtree(od, ignore_errors=True)

    def redaction(self, fs, st):
        for lab in self.labels:
            for strategy in STRATEGIES:
                st["redaction"].setdefault(lab, {})[strategy] = self.redact(fs, lab, strategy)

    # -- dimension 6: suppression -----------------------------------------------------------------
    def suppression(self, fs, st):
        r5 = st.get("r5")
        if not r5 or not os.path.exists(r5):
            st["supp"] = dict(note="BASE wrote no suppression file")
            return
        with open(r5) as f:
            text = f.read()
        rules = len(re.findall(r"(?m)^\s*- id: ", text))
        r5e = r5.replace(".yaml", ".enabled.yaml")
        with open(r5e, "w") as f:
            f.write(re.sub(r"(?m)^(\s*)enabled: false\s*$", r"\1enabled: true", text))
        base_fl = st["fl"]["base1"]
        m_fl = st["fl"]["head1" if not self.same else "base1"]
        kb, km = multiset(base_fl), multiset(m_fl)
        expected = sum((kb & km).values())
        out = dict(rules=rules, base_findings=len(base_fl), measured_findings=len(m_fl), expected_suppressed=expected)

        def apply(rule_file, label, covered=None):
            """covered: the multiset of keys the rule file was written for (default: every BASE finding)."""
            res, raw, doc = self.tree(fs, label, self.bins[self.measured], "json", ["--suppression-file", rule_file],
                                      keep=False)
            stats = (doc or {}).get("stats") or {}
            rem = findings(doc)
            kr = multiset(rem)
            unexplained = kr & kb & km & (covered if covered is not None else kb)
            by_type = collections.Counter()
            for key, n in unexplained.items():
                by_type[key[2]] += n
            r = dict(status=res["status"], suppressed_stat=stats.get("suppressed", 0), remaining=len(rem),
                     unexplained_remaining=sum(unexplained.values()), unexplained_by_type=dict(by_type),
                     uncounted=len(m_fl) - len(rem) - stats.get("suppressed", 0))
            if not fs.private:
                r["unexplained_examples"] = [dict(path=k[0], type=k[2], line=k[3]) for k in list(unexplained)[:20]]
            return r

        out["v5"] = apply(r5e, "supp-v5")
        if not fs.private:
            out.update(self.legacy_rules(fs, r5, apply, kb, km))
        st["supp"] = out
        log(f"   [{fs.name}] suppression: {rules} rule(s); v5 suppressed {out['v5']['suppressed_stat']} of "
            f"{expected} expected, unexplained remaining {out['v5']['unexplained_remaining']}")

    def legacy_rules(self, fs, r5, apply, kb, km):
        """Synthesise v1 and v2 rules from BASE's verbose findings and apply them with the measured binary."""
        path = os.path.join(self.pub_dir, "verbose-base.json")
        cmd = [self.bins["base"], "--file", fs.root, "--recursive"] + FLAGS + ["--format", "json", "--show-match",
                                                                              "--verbose"] + fs.flags
        # --verbose prints each finding's whole line, so a long-lined file can make this output large:
        # it streams to a file, capped, instead of into memory.
        res = run(cmd, self.a.timeout, self.env, self.cwd, stdout_path=path, stdout_cap=512 * MB)
        res["status"] = classify(res, os.path.getsize(path) > 0)
        log(f"   [{fs.name}] base verbose json {res['wall']:7.1f}s  {os.path.getsize(path) / MB:.0f} MB  {res['status']}")
        try:
            if res["status"] != "ok":
                return dict(legacy_note=f"verbose pass {res['status']}; v1/v2 not measured")
            with open(path, "rb") as f:
                doc = json.loads(f.read())
        finally:
            os.unlink(path)
        with open(r5) as f:
            binary_v5 = set(re.findall(r"hash:\s*([0-9a-f]{64})", f.read()))
        results = doc.get("results") or []
        agree = [r for r in results if suppression_hash(r, 5) in binary_v5]
        # Rules are only synthesised where this script reproduces the binary's own v5 hash; the
        # findings it cannot reproduce are reported, not counted against the legacy formulas.
        covered = multiset(findings(dict(results=agree)))
        out = dict(verbose_findings=len(results), python_v5_agrees=len(agree),
                   python_v5_disagrees_by_type=dict(collections.Counter(
                       r.get("type") for r in results if suppression_hash(r, 5) not in binary_v5)))
        for version in (1, 2):
            hashes = [suppression_hash(r, version) for r in agree]
            differs = sum(1 for r, h in zip(agree, hashes) if h != suppression_hash(r, 5))
            rule_file = os.path.join(self.pub_dir, f"suppressions-v{version}.yaml")
            write_rules(rule_file, hashes)
            r = apply(rule_file, f"supp-v{version}", covered)
            r["expected_suppressed"] = sum((covered & kb & km).values())
            r["rules"] = len(hashes)
            r["rules_differing_from_v5"] = differs
            if version == 1 and not self.same:
                r["note"] = "v1 hashes confidence: a finding whose confidence moved is un-suppressed by design"
            out[f"v{version}"] = r
        return out

    # -- dimension 7: output formats --------------------------------------------------------------
    def formats(self, fs, st):
        labels = [self.measured] if self.same else ["base", "head"]
        for lab in labels:
            for fmt in OTHER_FORMATS:
                res, raw, _ = self.tree(fs, f"{lab}-fmt", self.bins[lab], fmt, keep=not fs.private)
                problems, count = validate(fmt, raw)
                st["formats"].setdefault(lab, {})[fmt] = dict(status=res["status"], problems=problems, count=count,
                                                              masked=res["masked"], bytes=res["bytes"])

    # -- one set, every dimension -----------------------------------------------------------------
    def lane(self, fs):
        st = self.state[fs.name]
        log(f"== [{fs.name}] {len(fs.files)} file(s), {sum(f['bytes'] for f in fs.files.values()) / MB:.1f} MB"
            + (f"; excluded {dict(fs.excluded)}" if fs.excluded else ""))
        steps = [("json passes", ("9", "11", "6"), self.json_passes),
                 ("per-file runs", ("4", "ne", "p0"), self.single_pass),
                 ("redaction", ("5",), self.redaction),
                 ("suppression", ("6",), self.suppression),
                 ("formats", ("7",), self.formats)]
        for name, dims, fn in steps:
            if not self.want(fs, *dims):
                continue
            if fn == self.suppression and "base1" not in st["fl"]:
                continue
            t0 = time.monotonic()
            try:
                fn(fs, st)
            except Exception as exc:
                why = type(exc).__name__ if fs.private else f"{type(exc).__name__}: {exc}"
                st["notes"].append(f"{name} failed: {why}")
                log(f"   [{fs.name}] {name} FAILED: {why}")
                if not fs.private:
                    log(traceback.format_exc())
            log(f"   [{fs.name}] {name}: {time.monotonic() - t0:.0f}s")

    def go(self):
        lanes = max(1, min(self.a.lanes or (2 if len(self.sets) > 1 else 1), len(self.sets)))
        log(f"corpus-ab: {'baseline of' if self.same else 'A/B'} {self.a.base_ref} ({self.a.base_sha[:12]})"
            + ("" if self.same else f" vs {self.a.head_ref} ({self.a.head_sha[:12]})")
            + f"; sets {[s.name for s in self.sets]}; dims {sorted(self.dims)}"
            + (f"; private dims {sorted(self.private_dims)}" if len(self.sets) > 1 else "")
            + f"; load {self.load[0][0]:.0f}/{self.load[0][1]:.0f}/{self.load[0][2]:.0f}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=lanes) as pool:
            list(pool.map(self.lane, self.sets))
        self.load.append(os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0))


# -------------------------------------------------------------------------------------------------
# Analysis and report
# -------------------------------------------------------------------------------------------------
def type_format(fl, fs):
    t = collections.defaultdict(collections.Counter)
    for key, conf, level, _ in fl:
        t[(key[2], fs.fmt_of(key[0]))][level or "?"] += 1
    return t


def timing_buckets(fs, recs):
    by = collections.defaultdict(list)
    for rel, r in recs.items():
        if r["status"] == "ok":
            f = fs.files[rel]
            by[f["bucket"]].append((r["cpu"], r["wall"], max(1, f["bytes"]), rel, f["fmt"]))
    rows, outliers = [], []
    for k in sorted(by):
        xs = by[k]
        per_kb = [c / (b / 1024) for c, _, b, _, _ in xs]
        med = statistics.median(per_kb)
        out = [(rel, fmt, c, b) for (c, _, b, rel, fmt), p in zip(xs, per_kb) if p > 3 * med]
        outliers += [(k,) + o for o in out]
        rows.append(dict(bucket=bucket_label(k), files=len(xs), cpu_median=statistics.median([x[0] for x in xs]),
                         cpu_p90=quantile([x[0] for x in xs], 0.9), cpu_max=max(x[0] for x in xs),
                         wall_median=statistics.median([x[1] for x in xs]), ms_per_kb_median=med * 1000,
                         outliers=len(out)))
    return rows, outliers


def analyse(m):
    S = {}
    for fs in m.sets:
        st, P = m.state[fs.name], {}
        S[fs.name] = P
        P["files"] = len(fs.files)
        P["bytes"] = sum(f["bytes"] for f in fs.files.values())
        P["excluded"] = dict(fs.excluded)
        P["by_format_files"] = dict(collections.Counter(f["fmt"] for f in fs.files.values()))
        P["notes"] = st["notes"]
        fl = st["fl"]
        P["passes"] = {lab: dict(status=r["status"], wall=round(r["wall"], 1), cpu=round(r["cpu"], 1),
                                 rss_mb=round(r["rss"] / MB), findings=len(fl.get(lab, [])), stats=r["stats"],
                                 tally=r["tally"]) for lab, r in st["runs"].items()}
        if "base1" in fl:
            tf = type_format(fl["base1"], fs)
            P["by_type_format"] = {f"{t}\t{f}": dict(c) for (t, f), c in sorted(tf.items())}
            if not m.same and "head1" in fl:
                P["by_type_format_head"] = {f"{t}\t{f}": dict(c) for (t, f), c in
                                            sorted(type_format(fl["head1"], fs).items())}
        # noise floor and determinism
        meas = sorted(lab for lab in fl if lab.startswith(m.measured))
        base_runs = sorted(lab for lab in fl if lab.startswith("base"))
        noise_rows, base_noise = [], 0
        for group in (base_runs, meas if not m.same else []):
            for lab in group[1:]:
                rows_ = diff(fl[group[0]], fl[lab])
                noise_rows += rows_
                if group is base_runs:
                    base_noise += len(rows_)
        noise_keys = {r[1] for r in noise_rows}
        P["noise"] = dict(rows=len(noise_rows), keys=len(noise_keys), base_rows=base_noise,
                          by_type=dict(collections.Counter(r[1][2] for r in noise_rows)))
        if len(meas) >= 2:
            hashes = {lab: st["runs"][lab]["masked"] for lab in meas}
            moved = []
            for lab in meas[1:]:
                moved += diff(fl[meas[0]], fl[lab])
            P["determinism"] = dict(runs=len(meas), identical=len(set(hashes.values())) == 1,
                                    moved=len(moved),
                                    moved_by_type_format={f"{t}\t{f}": n for (t, f), n in collections.Counter(
                                        (r[1][2], fs.fmt_of(r[1][0])) for r in moved).items()})
            if not fs.private:
                P["determinism"]["moved_examples"] = sorted({(r[1][0], r[1][2]) for r in moved})[:40]
        # dimension 9 + FP ledger
        if not m.same and "base1" in fl and "head1" in fl:
            rows = diff(fl["base1"], fl["head1"])
            real = [r for r in rows if r[1] not in noise_keys]
            P["ab"] = dict(rows=len(rows), noisy=len(rows) - len(real))
            tot = collections.Counter(r[0] for r in real)
            P["ab"].update(new=tot["new"], lost=tot["lost"], changed=tot["changed"])
            cells = collections.defaultdict(collections.Counter)
            for kind, key, x, y, lv in real:
                cells[(key[2], fs.fmt_of(key[0]))][kind] += 1
            P["ab"]["by_type_format"] = {f"{t}\t{f}": dict(c) for (t, f), c in sorted(cells.items())}
            lost = collections.Counter()
            pending_pub, pending_priv = [], []
            texts = {}
            if not fs.private:
                for lab in ("base1", "head1"):
                    for key, _, _, text in fl[lab]:
                        texts[key] = text
            for kind, key, x, y, lv in real:
                if fs.private:
                    h = key_id(key)
                    v = m.ledger.verdict(hashed=h)
                    if kind == "lost":
                        lost[v or "unclassified"] += 1
                    if (kind == "lost" and not v) or (kind == "new" and lv == "HIGH" and not v):
                        pending_priv.append((h, key[2], fs.fmt_of(key[0]), lv))
                else:
                    v = m.ledger.verdict(key=key)
                    if kind == "lost":
                        lost[v or "unclassified"] += 1
                    if (kind == "lost" and not v) or (kind == "new" and lv == "HIGH" and not v):
                        pending_pub.append((kind, key, lv, x, y, masked_value(texts.get(key, ""))))
            P["ab"]["lost_by_verdict"] = dict(lost)
            if fs.private:
                P["ab"]["pending_added"] = m.ledger.add_private_pending(pending_priv)
            else:
                P["ab"]["pending"] = len(pending_pub)
                with open(os.path.join(m.pub_dir, "triage-pending.tsv"), "w", encoding="utf-8") as f:
                    f.write("id\tkind\tlevel\tpath\tvalidator\ttype\tline\ttext_sha256\tbase\thead\tmasked\n")
                    for kind, key, lv, x, y, mv in sorted(pending_pub, key=lambda r: (r[1][0], r[1][3])):
                        f.write("\t".join(tsv_cell(c) for c in (key_id(key)[:12], kind, lv, key[0], key[1], key[2],
                                                                 key[3], key[4], "" if x is None else x,
                                                                 "" if y is None else y, mv)) + "\n")
                with open(os.path.join(m.pub_dir, "diff-ab.tsv"), "w", encoding="utf-8") as f:
                    f.write("kind\tlevel\tpath\tvalidator\ttype\tline\ttext_sha256\tbase\thead\tnoise\tverdict\n")
                    for kind, key, x, y, lv in sorted(rows, key=lambda r: (r[1][0], r[1][3], r[0])):
                        f.write("\t".join(tsv_cell(c) for c in (kind, lv, key[0], key[1], key[2], key[3], key[4],
                                                                 "" if x is None else x, "" if y is None else y,
                                                                 "yes" if key in noise_keys else "",
                                                                 m.ledger.verdict(key=key) or "")) + "\n")
        if not fs.private and "base1" in fl:
            with open(os.path.join(m.pub_dir, "findings-base1.tsv"), "w", encoding="utf-8") as f:
                f.write("path\tvalidator\ttype\tline\ttext_sha256\tconfidence\tlevel\n")
                for key, conf, lv, _ in sorted(fl["base1"]):
                    f.write("\t".join(tsv_cell(c) for c in key) + f"\t{conf:g}\t{lv}\n")
        # dimension 4 / NE
        if st["single"]:
            P["timing"] = {}
            P["ne"] = {}
            for lab, recs in st["single"].items():
                rows, outliers = timing_buckets(fs, recs)
                P["timing"][lab] = dict(buckets=rows, outliers=len(outliers),
                                        cpu_total=round(sum(r["cpu"] for r in recs.values()), 1),
                                        wall_total=round(sum(r["wall"] for r in recs.values()), 1))
                if fs.private:
                    P["timing"][lab]["outliers_by_format_bucket"] = {
                        f"{o[2]}\t{bucket_label(o[0])}": n for o, n in
                        collections.Counter((k, None, fmt) for k, rel, fmt, c, b in outliers).items()}
                else:
                    P["timing"][lab]["outlier_files"] = [dict(path=rel, bucket=bucket_label(k), cpu=round(c, 2), bytes=b)
                                                         for k, rel, fmt, c, b in outliers]
                ne = collections.defaultdict(collections.Counter)
                for rel, r in recs.items():
                    if r["cause"]:
                        ne[fs.files[rel]["fmt"]][r["cause"]] += 1
                P["ne"][lab] = {f: dict(c) for f, c in sorted(ne.items())}
            if not m.same:
                cmp_rows = []
                b, h = st["single"]["base"], st["single"]["head"]
                byk = collections.defaultdict(list)
                for rel in b:
                    if rel in h and b[rel]["status"] == "ok" and h[rel]["status"] == "ok":
                        byk[fs.files[rel]["bucket"]].append((b[rel]["cpu"], h[rel]["cpu"]))
                for k in sorted(byk):
                    xs = byk[k]
                    mb_, mh = statistics.median([x[0] for x in xs]), statistics.median([x[1] for x in xs])
                    paired = statistics.median([y / x for x, y in xs if x > 0] or [1.0])
                    cmp_rows.append(dict(bucket=bucket_label(k), files=len(xs), base_median=mb_, head_median=mh,
                                         ratio=mh / mb_ if mb_ else 1.0, paired_ratio=paired,
                                         flagged=len(xs) >= 3 and mb_ > 0 and mh / mb_ > 1.25))
                P["timing"]["ab"] = cmp_rows
            if not fs.private:
                P["timing"]["fixtures"] = {lab: [dict(path=rel, format=fs.files[rel]["fmt"], bytes=fs.files[rel]["bytes"],
                                                      cpu=round(v["cpu"], 3), wall=round(v["wall"], 3), runs=v["runs"])
                                                 for rel, v in sorted(d.items(), key=lambda kv: -kv[1]["cpu"])]
                                           for lab, d in st["fixtures"].items()}
                with open(os.path.join(m.pub_dir, "per-file.tsv"), "w", encoding="utf-8") as f:
                    f.write("binary\tpath\tformat\tbytes\tbucket\tcpu_s\twall_s\trss_mb\texit\tstatus\tcause\tfindings\t"
                            "recovered\tdetail\n")
                    for lab, recs in st["single"].items():
                        for rel, r in sorted(recs.items()):
                            fi = fs.files[rel]
                            f.write("\t".join(tsv_cell(c) for c in (
                                lab, rel, fi["fmt"], fi["bytes"], bucket_label(fi["bucket"]), f"{r['cpu']:.3f}",
                                f"{r['wall']:.3f}", round(r["rss"] / MB), r["code"], r["status"], r["cause"] or "",
                                r["findings"] if r["findings"] is not None else "", r["recovered"], r.get("detail", "")))
                                + "\n")
        # dimension 5 / 6 / 7
        P["redaction"] = st["redaction"]
        P["suppression"] = st["supp"]
        P["formats"] = st["formats"]
        if st["formats"] and not m.same and "base" in st["formats"] and "head" in st["formats"]:
            P["formats_identical"] = {fmt: st["formats"]["base"][fmt]["masked"] == st["formats"]["head"][fmt]["masked"]
                                      for fmt in st["formats"]["base"] if fmt in st["formats"]["head"]}
        # P0
        p0 = st["p0"]
        if fs.private:
            P["p0"] = {f"{e['where']}\t{e['status']}\t{e.get('format', '-')}\t{e.get('size', '-')}": n
                       for e, n in collections.Counter(tuple(sorted(e.items())) for e in p0).items()
                       for e in [dict(e)]} if p0 else {}
        else:
            P["p0"] = p0
    return S


def verdict(m, S):
    """A/B exit status: 1 blocker, 3 needs triage, 0 clean."""
    if m.same:
        return 0, []
    blockers, triage = [], []
    for name, P in S.items():
        ab = P.get("ab") or {}
        if ab.get("lost_by_verdict", {}).get("TP"):
            blockers.append(f"{name}: {ab['lost_by_verdict']['TP']} lost TP finding(s)")
        if ab.get("lost_by_verdict", {}).get("unclassified"):
            triage.append(f"{name}: {ab['lost_by_verdict']['unclassified']} lost finding(s) not classified")
        base_p0 = {(e.get("path"), e.get("status")) for e in (P.get("p0") or []) if isinstance(e, dict)
                   and e["where"].startswith("single base")}
        if isinstance(P.get("p0"), list):
            new_p0 = [e for e in P["p0"] if e["where"].startswith("single head") and (e.get("path"), e["status"]) not in base_p0]
            if new_p0:
                blockers.append(f"{name}: {len(new_p0)} file(s) newly fail in HEAD")
        red = P.get("redaction") or {}
        for strategy in STRATEGIES:
            b = (red.get("base") or {}).get(strategy) or {}
            h = (red.get("head") or {}).get(strategy) or {}

            def tot(d, k):
                return sum(v.get(k, 0) for v in (d.get("per_format") or {}).values())
            if tot(h, "silent") > tot(b, "silent") or tot(h, "raw") > tot(b, "raw"):
                blockers.append(f"{name}: more redaction survivors in HEAD under {strategy}")
        sup = (P.get("suppression") or {}).get("v5") or {}
        if sup.get("unexplained_remaining", 0) > 0 or sup.get("uncounted", 0) > 0:
            blockers.append(f"{name}: suppression rules from BASE do not all suppress in HEAD, or stats.suppressed "
                            "misses some")
        det = P.get("determinism") or {}
        if det and det.get("moved") and P.get("noise", {}).get("base_rows", 0) == 0:
            blockers.append(f"{name}: HEAD runs differ where BASE runs did not")
        for row in (P.get("timing") or {}).get("ab") or []:
            if row["flagged"]:
                triage.append(f"{name}: bucket {row['bucket']} median CPU {row['ratio']:.2f}x")
    if blockers:
        return 1, [("BLOCKER", b) for b in blockers] + [("NOTE", t) for t in triage]
    return (3 if any("not classified" in t for t in triage) else 0), [("NOTE", t) for t in triage]


def render(m, S):
    R = []
    head = m.a.base_ref if m.same else f"{m.a.base_ref} ({m.a.base_sha[:12]}) vs {m.a.head_ref} ({m.a.head_sha[:12]})"
    R.append(f"# corpus {'baseline' if m.same else 'A/B'}: {head}\n")
    R.append(f"Commit(s): base {m.a.base_sha}" + ("" if m.same else f", head {m.a.head_sha}") +
             f". Load average at start {m.load[0][0]:.0f}, at end {m.load[-1][0]:.0f}. Wall "
             f"{(time.time() - m.started) / 60:.1f} min. Private set: "
             + ("included (aggregates only)" if len(m.sets) > 1 else "not read") + ".\n")
    for fs in m.sets:
        P = S[fs.name]
        R.append(f"## {fs.name} set: {P['files']} files, {P['bytes'] / MB:.1f} MB" +
                 (f" (excluded: {P['excluded']})" if P["excluded"] else "") + "\n")
        if P["notes"]:
            R.append("Notes: " + "; ".join(P["notes"]) + "\n")
        if P.get("passes"):
            R.append("### Tree passes\n")
            R.append(md_table(["run", "status", "wall s", "CPU s", "RSS MB", "findings", "not examined"],
                              [(lab, p["status"], p["wall"], p["cpu"], p["rss_mb"], p["findings"],
                                p["stats"].get("files_not_examined", 0)) for lab, p in sorted(P["passes"].items())]))
            R.append("")
        if P.get("by_type_format"):
            R.append("### 9. Findings by type x format (BASE, first run)\n")
            by_t = collections.defaultdict(lambda: [collections.Counter(), collections.Counter()])
            for k, c in P["by_type_format"].items():
                t, f = k.split("\t")
                by_t[t][0].update(c)
                by_t[t][1][f] += sum(c.values())
            rows = [(t, sum(v[0].values()), f"{v[0]['HIGH']}/{v[0]['MEDIUM']}/{v[0]['LOW']}",
                     ", ".join(f"{f} {n}" for f, n in v[1].most_common(8)) + (" ..." if len(v[1]) > 8 else ""))
                    for t, v in sorted(by_t.items(), key=lambda kv: -sum(kv[1][0].values()))]
            R.append(md_table(["type", "findings", "H/M/L", "by format"], rows))
            R.append("")
        R.append(f"Noise floor (same binary): {P['noise']['rows']} differing row(s) on {P['noise']['keys']} key(s)"
                 + (f", by type {P['noise']['by_type']}" if P["noise"]["rows"] else "") + ".\n")
        if P.get("determinism"):
            d = P["determinism"]
            R.append(f"### 11. Determinism: {d['runs']} runs of the measured binary, byte-identical after "
                     f"masking durations and timestamps: **{'yes' if d['identical'] else 'NO'}**"
                     + ("" if d["identical"] else
                        (f"; {d['moved']} finding row(s) moved: {d['moved_by_type_format']}" if d["moved"] else
                         "; every finding identical, the bytes differ elsewhere (compare the raw outputs)"))
                     + "\n")
        if P.get("ab"):
            ab = P["ab"]
            R.append(f"### 9. A/B outside the noise floor: new {ab['new']}, lost {ab['lost']}, confidence-changed "
                     f"{ab['changed']} (plus {ab['noisy']} on noisy keys); lost by ledger verdict "
                     f"{ab['lost_by_verdict'] or '{}'}\n")
            if ab["by_type_format"]:
                R.append(md_table(["type", "format", "new", "lost", "changed"],
                                  [k.split("\t") + [c.get("new", 0), c.get("lost", 0), c.get("changed", 0)]
                                   for k, c in ab["by_type_format"].items()]))
                R.append("")
        if P.get("timing"):
            for lab, t in P["timing"].items():
                if lab in ("ab", "fixtures"):
                    continue
                R.append(f"### 4. Timing buckets ({lab}; CPU seconds per file run alone; {t['outliers']} outlier(s) "
                         f"over 3x their bucket's median time/byte; total CPU {t['cpu_total']} s)\n")
                R.append(md_table(["size", "files", "median CPU s", "p90 CPU s", "max CPU s", "median wall s",
                                   "median ms/KB", "outliers"],
                                  [(r["bucket"], r["files"], f"{r['cpu_median']:.3f}", f"{r['cpu_p90']:.3f}",
                                    f"{r['cpu_max']:.2f}", f"{r['wall_median']:.3f}", f"{r['ms_per_kb_median']:.3f}",
                                    r["outliers"]) for r in t["buckets"]]))
                R.append("")
            if P["timing"].get("ab"):
                R.append("A/B bucket medians (flagged over 1.25x with 3+ files):\n")
                R.append(md_table(["size", "files", "base median CPU s", "head median CPU s", "ratio", "paired ratio",
                                   "flag"], [(r["bucket"], r["files"], f"{r['base_median']:.3f}", f"{r['head_median']:.3f}",
                                              f"{r['ratio']:.2f}", f"{r['paired_ratio']:.2f}", "**yes**" if r["flagged"] else "")
                                             for r in P["timing"]["ab"]]))
                R.append("")
            if P["timing"].get("fixtures"):
                lab = m.measured if m.measured in P["timing"]["fixtures"] else "base"
                fx = P["timing"]["fixtures"].get(lab) or []
                R.append(f"Standing timing fixtures (slowest public files, best of {fx[0]['runs'] if fx else 0}):\n")
                R.append(md_table(["path", "bytes", "CPU s", "wall s"],
                                  [(x["path"], x["bytes"], x["cpu"], x["wall"]) for x in fx]))
                R.append("")
        if P.get("ne"):
            lab = m.measured if m.measured in P["ne"] else "base"
            ne = P["ne"][lab]
            causes = sorted({c for v in ne.values() for c in v})
            R.append(f"### NE. Not examined by cause and format ({lab}; per-file runs)\n")
            R.append(md_table(["format"] + causes + ["total"],
                              [[f] + [v.get(c, 0) for c in causes] + [sum(v.values())] for f, v in ne.items()]
                              + [["TOTAL"] + [sum(v.get(c, 0) for v in ne.values()) for c in causes]
                                 + [sum(sum(v.values()) for v in ne.values())]]))
            R.append("")
        if P.get("redaction"):
            R.append("### 5. Redaction (survivors: silent = found again by a re-scan of the copy; verbatim = and still "
                     "in its bytes; raw = reported values of 8+ characters, or 6+ with a digit or @, present in the "
                     "copy; files the run disclosed as unredacted are counted under not redacted, not as survivors)\n")
            rows = []
            for lab, by_s in P["redaction"].items():
                for strategy, r in by_s.items():
                    tot = collections.Counter()
                    for v in r["per_format"].values():
                        tot.update(v)
                    rows.append((lab, strategy, r["status"], r["code"], r["written"], r["files_not_redacted"],
                                 r["values_not_redacted"], tot["silent"], tot["verbatim"], tot["raw"],
                                 tot["raw_unreported_in_input"], tot["files_with_survivors"], r["recovered"]))
            R.append(md_table(["binary", "strategy", "status", "exit", "written", "files not redacted", "values not redacted",
                               "silent", "verbatim", "raw", "raw also unreported in input", "files with survivors",
                               "recovered panics"], rows))
            R.append("")
            for lab, by_s in P["redaction"].items():
                for strategy, r in by_s.items():
                    sv = [(f, n) for f, n in sorted(r["survivor_types"].items())]
                    if sv:
                        R.append(f"Survivor files by format and type ({lab}, {strategy}): "
                                 + ", ".join(f"{k.replace(chr(9), ' ')} {n}" for k, n in sv) + "\n")
                    if not fs.private and r.get("survivors"):
                        R.append(md_table(["path", "silent", "verbatim", "raw", "raw also unreported in input", "types"],
                                          [(s["path"], s["silent"], s["verbatim"], s["raw"], s["raw_also_unreported_in_input"],
                                            ",".join(s["types"])) for s in r["survivors"]]))
                        R.append("")
        if P.get("suppression"):
            s = P["suppression"]
            R.append("### 6. Suppression (rules written by BASE, applied by the measured binary)\n")
            rows = []
            for v in ("v5", "v2", "v1"):
                if v in s and isinstance(s[v], dict) and "suppressed_stat" in s[v]:
                    x = s[v]
                    rows.append((v, x.get("rules", s.get("rules")), x.get("expected_suppressed", s.get("expected_suppressed")),
                                 x["suppressed_stat"], x["remaining"], x["unexplained_remaining"], x["uncounted"],
                                 x.get("rules_differing_from_v5", "-")))
            if rows:
                R.append(f"BASE findings {s.get('base_findings')}, measured findings {s.get('measured_findings')}, "
                         f"expected suppressed (keys both report) {s.get('expected_suppressed')}"
                         + (f"; python v5 hash agrees with the binary on {s['python_v5_agrees']} of "
                            f"{s['verbose_findings']}" if "python_v5_agrees" in s else "") + "\n")
                R.append("Unexplained remaining = a finding both binaries report that the rules did not "
                         "suppress; uncounted = a finding that vanished without stats.suppressed counting it.\n")
                R.append(md_table(["rules", "count", "expected", "stats.suppressed", "remaining", "unexplained remaining",
                                   "uncounted", "rules differing from v5"], rows))
                if s.get("python_v5_disagrees_by_type"):
                    R.append(f"\nNo v1/v2 rule was synthesised for the findings whose v5 hash this script does not "
                             f"reproduce: {s['python_v5_disagrees_by_type']}.")
                R.append("")
            for k in ("note", "legacy_note"):
                if s.get(k):
                    R.append(s[k] + "\n")
        if P.get("formats"):
            R.append("### 7. Output formats (structural checks)\n")
            rows = []
            for lab, fmts in P["formats"].items():
                for fmt, r in sorted(fmts.items()):
                    rows.append((lab, fmt, r["status"], r["bytes"], r["count"] if r["count"] is not None else "-",
                                 "; ".join(r["problems"]) or "ok"))
            R.append(md_table(["binary", "format", "status", "bytes", "records", "problems"], rows))
            if P.get("formats_identical"):
                R.append("\nBASE vs HEAD byte-identical after masking: " +
                         ", ".join(f"{k} {'yes' if v else 'NO'}" for k, v in sorted(P["formats_identical"].items())))
            R.append("")
        R.append(f"### P0 ({fs.name})\n")
        if not P["p0"]:
            R.append("none: no panic, recovered panic, hang, timeout, crash or non-zero exit in any run\n")
        elif fs.private:
            R.append(md_table(["where", "status", "format", "size", "count"],
                              [k.split("\t") + [n] for k, n in sorted(P["p0"].items())]))
            R.append("")
        else:
            R.append(md_table(["where", "status", "path", "detail"],
                              [(e["where"], e["status"], e.get("path", "-"),
                                re.sub(r"\s+", " ", e.get("detail") or "")[-160:].replace("|", "/")) for e in P["p0"]]))
            R.append("")
    R.append("12. Cross-platform (container): `scripts/surface-parity.sh CORPUS=<dir>` (not run here).\n")
    return "\n".join(R) + "\n"


def write_baseline(m, S):
    d = os.path.join(m.a.corpus, "baselines")
    os.makedirs(d, exist_ok=True)
    pub = m.state["public"]
    P = S["public"]
    doc = dict(schema=1, ref=m.a.base_ref, sha=m.a.base_sha, recorded=datetime.datetime.now(datetime.timezone.utc).isoformat(),
               run=os.path.basename(m.a.out), dims=sorted(m.dims), load=[list(x) for x in m.load],
               manifest_sha256=hashlib.sha256(open(os.path.join(m.a.corpus, "MANIFEST.tsv"), "rb").read()).hexdigest()
               if os.path.exists(os.path.join(m.a.corpus, "MANIFEST.tsv")) else None,
               public=dict(P))
    doc["public"]["findings"] = [[k[0], k[1], k[2], k[3], k[4], c, lv] for k, c, lv, _ in sorted(pub["fl"].get("base1", []))]
    if pub["single"].get("base"):
        files = m.sets[0].files
        doc["public"]["timing"] = dict(P.get("timing") or {})
        doc["public"]["timing"]["files"] = [
            dict(path=rel, format=files[rel]["fmt"], bytes=files[rel]["bytes"], cpu=round(r["cpu"], 3),
                 wall=round(r["wall"], 3), status=r["status"], cause=r["cause"])
            for rel, r in sorted(pub["single"]["base"].items())]
        doc["public"]["timing"]["fixtures"] = (P.get("timing") or {}).get("fixtures", {}).get("base", [])
    if "private" in S:
        doc["private"] = S["private"]  # aggregates only, by construction
    path = os.path.join(d, m.a.base_sha + ".json")
    with open(path + ".tmp", "w") as f:
        json.dump(round_floats(doc), f, indent=1, sort_keys=True, default=str)
    os.replace(path + ".tmp", path)
    with open(os.path.join(d, "INDEX.tsv"), "a") as f:
        f.write("\t".join([m.a.base_sha, m.a.base_ref, doc["recorded"], os.path.basename(m.a.out)]) + "\n")
    return path


def privacy_audit(m, extra_files, private_summary):
    """No private path in anything the run wrote; no private value in the aggregate artefacts.

    Not searched: bin/ and public/raw/, which only ever hold output of runs over the PUBLIC root (the
    process that produced them was never given a private path), and the private 0700 directory,
    which is removed. A path is searched in its relative form; a bare file name only when it is 12+
    characters and no public path contains it, so a common name cannot raise a false alarm.
    """
    priv = [s for s in m.sets if s.private]
    if not priv:
        return True
    fs = priv[0]
    pub_paths = "\n".join(m.sets[0].files)
    needles = {rel.encode("utf-8", "surrogatepass") for rel in fs.files if os.sep in rel or
               (len(rel) >= 12 and rel not in pub_paths)}
    public_texts = {t.strip() for fl in m.state["public"]["fl"].values() for _, _, _, t in fl if t}
    # A run of one or two repeated digits ("0000000000") identifies nothing and occurs inside numbers.
    values = [t.encode("utf-8", "surrogatepass") for t in fs.text_cache
              if t not in public_texts and not (t.isdigit() and len(set(t)) < 3)]
    skip = {os.path.join(m.a.out, "bin"), os.path.join(m.pub_dir, "raw"), m.private_tmp or "/nonexistent"}
    targets = []
    for dp, dns, fns in os.walk(m.a.out):
        dns[:] = [d for d in dns if os.path.join(dp, d) not in skip and not d.startswith("src-")]
        targets += [os.path.join(dp, n) for n in fns]
    targets += extra_files
    hits = []
    blob_parts = []
    for p in targets:
        try:
            with (gzip.open(p) if p.endswith(".gz") else open(p, "rb")) as f:
                blob_parts.append(f.read())
        except OSError:
            continue
    blob = b"\0".join(blob_parts)
    if any(n in blob for n in needles):
        for p, data in zip(targets, blob_parts):
            if any(n in data for n in needles):
                hits.append(os.path.relpath(p, m.a.corpus))
    aggregate = b"\0".join(open(p, "rb").read() for p in
                           [os.path.join(m.a.out, n) for n in ("report.md", "ab.log")] +
                           [p for p in extra_files if p.endswith("private.tsv")] if os.path.exists(p))
    aggregate += b"\0" + json.dumps(private_summary, default=str, ensure_ascii=False).encode("utf-8", "surrogatepass")
    if any(v in aggregate for v in values):
        hits.append("an aggregate artefact (report, log, ledger or private summary) holds a private value")
    for h in hits:
        log(f"PRIVACY AUDIT FAILED: private material in {h}")
    if not hits:
        log(f"privacy audit: {len(targets)} file(s) checked for {len(needles)} private path(s), and the aggregate "
            f"artefacts for {len(values)} private value(s): none found")
    return not hits


def cleanup():
    for d in PRIVATE_DIRS:
        shutil.rmtree(d, ignore_errors=True)


def on_signal(signum, frame):
    with OUT_LOCK:
        pids = list(CHILDREN)
    for pid in pids:
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass
    cleanup()
    os._exit(130)


def main():
    p = argparse.ArgumentParser(prog="corpus-ab.sh")
    for name in ("mode", "corpus", "out", "base_ref", "base_sha", "base_bin", "head_ref", "head_sha", "head_bin"):
        p.add_argument(name)
    p.add_argument("--include-private", action="store_true")
    p.add_argument("--keep-redacted", action="store_true")
    p.add_argument("--only", default="")
    p.add_argument("--private-dims", default="")
    p.add_argument("--formats", default="")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--jobs", type=int, default=4)
    p.add_argument("--fixture-runs", type=int, default=3)
    p.add_argument("--timeout", type=int, default=3600)
    p.add_argument("--file-timeout", type=int, default=600)
    p.add_argument("--lanes", type=int, default=0)
    a = p.parse_args()
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    private_read = False
    try:
        m = Measure(a)
        private_read = any(s.private for s in m.sets)
        m.go()
        S = analyse(m)
        report = render(m, S)
        with open(os.path.join(a.out, "report.md"), "w") as f:
            f.write(report)
        S = round_floats(S)
        summary = dict(mode=a.mode, base=dict(ref=a.base_ref, sha=a.base_sha), head=dict(ref=a.head_ref, sha=a.head_sha),
                       dims=sorted(m.dims), private_dims=sorted(m.private_dims) if private_read else [],
                       load=round_floats([list(x) for x in m.load], 2), sets=S)
        with open(os.path.join(a.out, "summary.json"), "w") as f:
            json.dump(summary, f, indent=1, sort_keys=True, default=str)
        extra = []
        if m.same:
            bl = write_baseline(m, S)
            extra.append(bl)
            log(f"baseline recorded: {bl}")
        for name in ("public.tsv", "private.tsv"):
            q = os.path.join(a.corpus, "triage", name)
            if os.path.exists(q):
                extra.append(q)
        log("")
        log(report)
        code, why = verdict(m, S)
        for kind, w in why:
            log(f"{kind}: {w}")
        for d in os.listdir(a.out):
            if d.startswith("src-"):
                shutil.rmtree(os.path.join(a.out, d), ignore_errors=True)
        if not privacy_audit(m, extra, S.get("private", {})):
            return 1
        log(f"done in {(time.time() - m.started) / 60:.1f} min; report {os.path.join(a.out, 'report.md')}")
        return code
    except Exception as exc:
        if not private_read:
            raise
        # A traceback can quote a private path or value (a KeyError's key, say): the type only.
        log(f"corpus-ab: internal error {type(exc).__name__} (traceback withheld: the private set was read)")
        return 2
    finally:
        cleanup()


sys.exit(main())
PY
status=${PIPESTATUS[0]}
exit "$status"
