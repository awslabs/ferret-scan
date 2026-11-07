#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# corpus-ab.sh — BASE-vs-HEAD A/B over the local real-file corpus (TEST_PLAN dimension 9), with a
# same-binary noise floor, per-format coverage and a redaction check on every binary container.
#
# What it does, in order:
#   1. builds BASE and HEAD from `git archive` into the output directory (the work tree and the
#      repository's worktree list are not touched);
#   2. scans by-format/<ext>/ one format at a time with each binary:
#        --recursive --checks all --confidence all --limit 0 --format json --config /dev/null
#      plus --show-match, so each finding can be keyed on sha256(text); the text itself is hashed
#      in memory and never written anywhere;
#   3. scans with BASE twice: the difference between those two runs is the NOISE FLOOR, and a
#      BASE-vs-HEAD difference on a key that also moves between the BASE runs is reported as noise,
#      not as a regression;
#   4. reports new / lost / confidence-changed findings BY TYPE and BY FORMAT, keyed on
#      (format, file, validator, type, line, sha256(text)) — a multiset, so two identical values on
#      one line are two findings, never a fake "changed" pair;
#   5. names every file a run did not fully examine, and why (re-running the affected format in
#      batches of 8 so the tool's own report lists each path), plus panics, crashes and timeouts;
#   6. redacts every binary-container format (office, ODF, legacy OLE, PDF, image, audio, video,
#      zip) under `simple` and `format_preserving`, reports files_not_redacted, exit codes and
#      panics/timeouts per format, then RE-SCANS the redacted output with the same binary: a value
#      it reported in the input and finds again in its own output, in a file it did not disclose as
#      unredacted, is a SILENT SURVIVOR (P0), split into "verbatim" (the text is still in the bytes)
#      and the rest (assembled across runs or cells, or decoded from a binary field). A finding whose
#      text is a field name with no value ("Author:") has nothing to redact and is counted apart.
#      For zip containers the decompressed parts, and for other binaries the raw bytes, are also
#      searched for each reported value (8+ characters, or 6+ with a digit or @, so common words do
#      not match by chance).
#
# Corpus: --corpus DIR, else $FERRET_CORPUS_DIR, else ../ferret-corpus next to this repository.
# Exit 2 if it is missing; scripts/corpus-fetch.sh creates it.
#
# private/: files the operator keeps in <corpus>/private/ are read ONLY with --include-private, and
# then only aggregate counts are reported: no file name, no per-file row, no stderr, no finding
# hash is written or printed for them, and their redacted copies are deleted after the check.
#
# Usage:
#   scripts/corpus-ab.sh BASE HEAD [--corpus DIR] [--include-private] [--out DIR]
#                        [--formats ext,ext] [--no-redaction] [--timeout SECS]
#
#   BASE HEAD        any two commit-ishes (origin/main HEAD, origin/main my-branch, a SHA twice for
#                    a pure noise-floor run). Equal commits are built once.
#   --out DIR        where binaries, per-run TSVs, redacted copies, the log and report.md go
#                    (default: a new <corpus>/runs/<UTC time>-<base>-<head>.XXXX)
#   --formats        restrict to these by-format/ directories
#   --no-redaction   skip step 6
#   --timeout SECS   per format per run (default 900); an attribution batch gets a quarter of it
#
# Long: on the ~650-file corpus one scan pass takes minutes, and the whole run several times
# that. Run it in the background and follow the log it names on its first line.
#
# Exit status: 0 no regression; 1 HEAD regressed against BASE (a lost finding outside the noise
# floor, a format that newly crashes or times out, a new silent survivor); 2 setup error.
#
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$here/.." && pwd)

usage() { sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; }

base_ref="" head_ref="" corpus="" out="" pass=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --corpus) [ $# -ge 2 ] || { echo "corpus-ab: --corpus needs a directory" >&2; exit 2; }; corpus="$2"; shift 2 ;;
    --corpus=*) corpus="${1#--corpus=}"; shift ;;
    --out) [ $# -ge 2 ] || { echo "corpus-ab: --out needs a directory" >&2; exit 2; }; out="$2"; shift 2 ;;
    --out=*) out="${1#--out=}"; shift ;;
    --include-private|--no-redaction) pass+=("$1"); shift ;;
    --formats|--timeout)
      [ $# -ge 2 ] || { echo "corpus-ab: $1 needs a value" >&2; exit 2; }
      pass+=("$1" "$2"); shift 2 ;;
    --formats=*|--timeout=*) pass+=("$1"); shift ;;
    -*) echo "corpus-ab: unknown option $1" >&2; usage >&2; exit 2 ;;
    *)
      if [ -z "$base_ref" ]; then base_ref="$1"
      elif [ -z "$head_ref" ]; then head_ref="$1"
      else echo "corpus-ab: unexpected argument $1" >&2; exit 2; fi
      shift ;;
  esac
done
if [ -z "$base_ref" ] || [ -z "$head_ref" ]; then
  echo "corpus-ab: need BASE and HEAD, e.g. scripts/corpus-ab.sh origin/main HEAD" >&2
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
  # Next to the corpus, which is already outside every repository and ignored by its own
  # .gitignore, and which a macOS temp reaper does not empty mid-run.
  mkdir -p "$corpus/runs" || { echo "corpus-ab: cannot create $corpus/runs" >&2; exit 2; }
  out=$(mktemp -d "$corpus/runs/$(date -u +%Y%m%dT%H%M%SZ)-${base_sha:0:12}-${head_sha:0:12}.XXXX") ||
    { echo "corpus-ab: mktemp failed" >&2; exit 2; }
fi
out=$(cd "$out" && pwd)
log="$out/ab.log"
echo "corpus-ab: output in $out (log: $log)"

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
else
  echo "corpus-ab: HEAD is the same commit as BASE; one binary, three scan passes" | tee -a "$log"
fi

python3 - "$corpus" "$out" "$base_ref" "$base_sha" "$base_bin" "$head_ref" "$head_sha" "$head_bin" \
  ${pass[@]+"${pass[@]}"} <<'PY' 2>&1 | tee -a "$log"
import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

MB = 1024 * 1024
SCAN_FLAGS = ["--checks", "all", "--confidence", "all", "--limit", "0", "--format", "json",
              "--config", "/dev/null", "--show-match", "--quiet"]
STRATEGIES = ["simple", "format_preserving"]
# Binary containers: the formats whose redaction rewrites a container rather than a text file.
BINARY = {"pdf", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp", "ott", "ots",
          "otp", "doc", "xls", "ppt", "jpg", "jpeg", "jpe", "png", "gif", "tif", "tiff", "bmp", "webp",
          "heic", "mp3", "wav", "flac", "m4a", "mp4", "mov", "m4v", "3gp", "3g2", "avi", "mkv",
          "webm", "zip"}
PANIC_RE = re.compile(r"(?m)^(panic: |fatal error: )|^goroutine \d+ \[")
RECOVERED_RE = re.compile(r"(?i)panic")
PRIVATE = "private"


def log(msg=""):
    print(msg, flush=True)


def sha(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


# ---------------------------------------------------------------------------------------------
# Running a binary: wall time, peak RSS, a hard timeout that kills the whole process group, and
# stdout/stderr kept in memory.
#
# Peak RSS is sampled from /proc/<pid>/status VmHWM where there is one (Linux). wait4's ru_maxrss is
# only the fallback: on Linux it keeps the high-water mark of the forked PARENT image from before
# exec, so every child of a large driver process reports at least the driver's own size.
# ---------------------------------------------------------------------------------------------
def run(cmd, timeout):
    start = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                            start_new_session=True)
    bufs, peak, done = {}, [0], threading.Event()

    def drain(name, stream):
        bufs[name] = stream.read()

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
            done.wait(0.05)

    threads = [threading.Thread(target=drain, args=("out", proc.stdout)),
               threading.Thread(target=drain, args=("err", proc.stderr))]
    sampling = os.path.isdir("/proc/self") and hasattr(os, "waitid")
    if sampling:
        threads.append(threading.Thread(target=sample))
    for t in threads:
        t.start()
    fired = []

    def kill():
        fired.append(True)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass

    timer = threading.Timer(timeout, kill)
    timer.start()
    if sampling:
        # Stop the sampler before the child is reaped, so it never reads a recycled pid's status.
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
    done.set()
    _, status, usage = os.wait4(proc.pid, 0)
    timer.cancel()
    for t in threads:
        t.join()
    code = os.waitstatus_to_exitcode(status)
    proc.returncode = code
    rss = peak[0] or usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    return dict(code=code, wall=time.monotonic() - start, rss=rss, timed_out=bool(fired),
                out=bufs.get("out", b""), err=bufs.get("err", b"").decode("utf-8", "replace"))


# ---------------------------------------------------------------------------------------------
# The tool's own not-examined report (stderr). Up to 8 files it lists each path under its cause;
# above 8 it prints a per-cause tally.
# ---------------------------------------------------------------------------------------------
def parse_footer(err):
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
            parts = [p.strip() for p in line.strip().split("  ·  ")]
            pairs = [re.match(r"^(.*): (\d+)$", p) for p in parts]
            if parts and all(pairs):
                for p in pairs:
                    tally[p.group(1)] += int(p.group(2))
                continue
        if not line.startswith("  "):
            inside = False
    return files, tally


def classify(res, parsed):
    if res["timed_out"]:
        return "timeout"
    if PANIC_RE.search(res["err"]):
        return "panic"
    if res["code"] < 0:
        return f"killed(signal {-res['code']})"
    if parsed is None:
        return f"no-json(exit {res['code']})"
    if res["code"] != 0:
        return f"exit {res['code']}"
    return "ok"


def recovered(err):
    """stderr lines that mention a panic the process survived (a recover() turned it into an error)."""
    return len([line for line in err.splitlines() if RECOVERED_RE.search(line) and not PANIC_RE.search(line)])


def parse_json(raw):
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def findings(doc, group):
    """[(key, confidence, level, text)] where key = (group, file, validator, type, line, sha256)."""
    out = []
    for r in (doc or {}).get("results", []) or []:
        text = str(r.get("text", ""))
        key = (group, str(r.get("filename", "")), str(r.get("validator", "")), str(r.get("type", "")),
               int(r.get("line_number") or 0), sha(text))
        out.append((key, float(r.get("confidence") or 0), str(r.get("confidence_level", "")), text))
    return out


# ---------------------------------------------------------------------------------------------
class AB:
    def __init__(self, a):
        self.a = a
        self.corpus = a.corpus
        self.out = a.out
        self.private = os.path.join(a.corpus, PRIVATE)
        self.groups = self.discover()

    def discover(self):
        root = os.path.join(self.corpus, "by-format")
        want = {f.strip().lower() for f in self.a.formats.split(",") if f.strip()} if self.a.formats else None
        groups = []
        for name in sorted(os.listdir(root)):
            d = os.path.join(root, name)
            if not os.path.isdir(d) or name.startswith(".") or (want and name not in want):
                continue
            files = sorted(os.path.join(dp, f) for dp, _, fs in os.walk(d) for f in fs)
            if files:
                groups.append(dict(name=name, dir=d, files=files, private=False,
                                   bytes=sum(os.path.getsize(f) for f in files)))
        if self.a.include_private and os.path.isdir(self.private):
            files = sorted(os.path.join(dp, f) for dp, _, fs in os.walk(self.private) for f in fs)
            if files:
                groups.append(dict(name=PRIVATE, dir=self.private, files=files, private=True,
                                   bytes=sum(os.path.getsize(f) for f in files)))
        # Largest first, so the first progress line already says how long the worst format takes.
        groups.sort(key=lambda g: (-g["bytes"], g["name"]))
        return groups

    # -- one scan of one group -----------------------------------------------------------------
    def scan(self, binary, group):
        res = run([binary, "--file", group["dir"], "--recursive"] + SCAN_FLAGS, self.a.timeout)
        doc = parse_json(res["out"])
        res["doc"] = doc
        res["status"] = classify(res, doc)
        res["stats"] = (doc or {}).get("stats") or {}
        res["footer_tally"] = parse_footer(res["err"])[1]
        res["recovered"] = recovered(res["err"])
        res["out"] = b""  # the raw document holds matched text: keep only what was parsed
        return res

    def scan_pass(self, label, binary):
        log(f"== scan pass {label} ({os.path.basename(binary)})")
        t0 = time.monotonic()
        results = {}
        for g in self.groups:
            res = self.scan(binary, g)
            # Keys and confidences only: the matched text has done its job once it is hashed.
            res["findings"] = [(k, c, lv, None) for k, c, lv, _ in findings(res["doc"], g["name"])]
            res["doc"] = None
            results[g["name"]] = res
            st = res["stats"]
            log(f"   {label:<6} {g['name']:<11} {len(g['files']):>4} files  {res['wall']:7.1f}s  "
                f"rss {res['rss'] / MB:7.1f} MB  findings {st.get('total_findings', '?'):>6}  "
                f"not-examined {st.get('files_not_examined', 0):>3}  {res['status']}")
            if not g["private"]:
                self.save_run(label, g, res)
        log(f"   pass {label}: {time.monotonic() - t0:.1f}s")
        return results

    def save_run(self, label, g, res):
        d = os.path.join(self.out, "runs", label)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{g['name']}.stats.json"), "w") as f:
            json.dump(dict(status=res["status"], code=res["code"], wall=res["wall"], rss=res["rss"],
                           stats=res["stats"], footer_tally=res["footer_tally"]), f, indent=1, sort_keys=True)
        with open(os.path.join(d, f"{g['name']}.stderr.txt"), "w") as f:
            f.write(res["err"])
        with open(os.path.join(d, f"{g['name']}.findings.tsv"), "w") as f:
            f.write("file\tvalidator\ttype\tline\tsha256\tconfidence\tlevel\n")
            for key, conf, level, _ in sorted(res["findings"]):
                f.write(f"{key[1]}\t{key[2]}\t{key[3]}\t{key[4]}\t{key[5]}\t{conf:g}\t{level}\n")

    # -- which file was not examined, and why ----------------------------------------------------
    def attribute(self, label, binary, results):
        rows, private_tally = [], collections.Counter()
        for g in self.groups:
            res = results[g["name"]]
            if res["status"] == "ok" and not res["stats"].get("files_not_examined"):
                continue
            per_file = {}
            batch_timeout = max(60, self.a.timeout // 4)
            files = g["files"]
            for i in range(0, len(files), 8):
                batch = files[i:i + 8]
                r = run([binary] + SCAN_FLAGS + batch, batch_timeout)
                status = classify(r, parse_json(r["out"]))
                if status != "ok":
                    for f in batch:  # isolate the file that crashes or hangs
                        r1 = run([binary] + SCAN_FLAGS + [f], batch_timeout)
                        s1 = classify(r1, parse_json(r1["out"]))
                        if s1 != "ok":
                            per_file[f] = (s1, (PANIC_RE.search(r1["err"]) and r1["err"][-400:]) or "")
                        for path, cause, detail in parse_footer(r1["err"])[0]:
                            per_file.setdefault(path, (cause, detail))
                    continue
                for path, cause, detail in parse_footer(r["err"])[0]:
                    per_file[path] = (cause, detail)
            for path, (cause, detail) in sorted(per_file.items()):
                if g["private"]:
                    private_tally[cause] += 1
                    continue
                rel = os.path.relpath(path, g["dir"]) if path.startswith("/") else path
                rows.append((g["name"], rel, cause, re.sub(r"\s+", " ", detail)[:300]))
        with open(os.path.join(self.out, f"not-examined-{label}.tsv"), "w") as f:
            f.write("format\tfile\tcause\tdetail\n")
            for r in rows:
                f.write("\t".join(r) + "\n")
        return rows, private_tally

    # -- the multiset diff -------------------------------------------------------------------------
    @staticmethod
    def diff(a, b):
        ma, mb = collections.defaultdict(list), collections.defaultdict(list)
        for res in a.values():
            for key, conf, level, _ in res["findings"]:
                ma[key].append(round(conf, 2))
        for res in b.values():
            for key, conf, level, _ in res["findings"]:
                mb[key].append(round(conf, 2))
        rows = []
        for key in set(ma) | set(mb):
            x, y = sorted(ma.get(key, [])), sorted(mb.get(key, []))
            common = min(len(x), len(y))
            for i in range(common):
                if x[i] != y[i]:
                    rows.append(("changed", key, x[i], y[i]))
            for i in range(common, len(y)):
                rows.append(("new", key, None, y[i]))
            for i in range(common, len(x)):
                rows.append(("lost", key, x[i], None))
        return rows

    def write_diff(self, name, rows, noise_keys=frozenset()):
        with open(os.path.join(self.out, f"{name}.tsv"), "w") as f:
            f.write("kind\tformat\tfile\tvalidator\ttype\tline\tsha256_12\tbase\thead\tnoise\n")
            for kind, key, x, y in sorted(rows, key=lambda r: (r[1], r[0])):
                if key[0] == PRIVATE:
                    continue
                f.write(f"{kind}\t{key[0]}\t{key[1]}\t{key[2]}\t{key[3]}\t{key[4]}\t{key[5][:12]}\t"
                        f"{'' if x is None else x}\t{'' if y is None else y}\t{'yes' if key in noise_keys else ''}\n")

    # -- redaction ------------------------------------------------------------------------------
    def redact_pass(self, label, binary):
        rows, survivors = [], []
        for g in self.groups:
            ext_ok = g["private"] or g["name"] in BINARY
            if not ext_ok:
                continue
            for strategy in STRATEGIES:
                if g["private"]:
                    od = tempfile.mkdtemp(prefix="private-redact.", dir=self.out)
                    os.chmod(od, 0o700)
                else:
                    parent = os.path.join(self.out, "redacted", label, strategy)
                    os.makedirs(parent, exist_ok=True)
                    od = tempfile.mkdtemp(prefix=g["name"] + ".", dir=parent)
                res = run([binary, "--file", g["dir"], "--recursive"] + SCAN_FLAGS +
                          ["--enable-redaction", "--redaction-strategy", strategy, "--redaction-output-dir", od],
                          self.a.timeout * 2)
                doc = parse_json(res["out"])
                res["out"] = b""
                status = classify(res, doc)
                st = (doc or {}).get("stats") or {}
                unred = (doc or {}).get("unredacted") or []
                # The redactor mirrors each input's absolute path under the output directory.
                in_roots = {os.path.abspath(g["dir"]), os.path.realpath(g["dir"])}
                out_roots = {o + r for o in {od, os.path.realpath(od)} for r in in_roots}

                def strip(p, roots):
                    for r in roots:
                        if p.startswith(r + os.sep):
                            return p[len(r) + 1:]
                    return None

                rel_of = lambda p: strip(p, out_roots)
                undisclosed = {strip(u.get("path", ""), in_roots) for u in unred}
                causes = collections.Counter(u.get("cause", "?") for u in unred)
                # What the run reported, per input file, in memory only.
                want = collections.defaultdict(collections.Counter)
                texts = collections.defaultdict(dict)
                for key, conf, level, text in findings(doc, g["name"]):
                    want[key[1]][(key[3], key[5])] += 1
                    texts[key[1]][(key[3], key[5])] = text
                outputs = {}
                for dp, _, fs in os.walk(od):
                    for fname in fs:
                        p = os.path.join(dp, fname)
                        rel = rel_of(p)
                        if rel:
                            outputs[rel] = p
                silent = verbatim = raw = labels = 0
                if outputs:
                    rr = run([binary, "--file", od, "--recursive"] + SCAN_FLAGS, self.a.timeout * 2)
                    rdoc = parse_json(rr["out"])
                    got = collections.defaultdict(collections.Counter)
                    for key, conf, level, text in findings(rdoc, g["name"]):
                        rel = rel_of(os.path.join(od, key[1]))
                        if rel:
                            got[rel][(key[3], key[5])] += 1
                    for rel, path in sorted(outputs.items()):
                        if rel in undisclosed:
                            continue
                        blobs = output_blobs(path)
                        same = [k for k in want.get(rel, {}) if k in got[rel]]
                        # A field name with no value ("Author:") has nothing to redact; it is
                        # counted, not called a survivor.
                        labels += sum(1 for k in same if LABEL_ONLY.match(texts[rel][k]))
                        same = [k for k in same if not LABEL_ONLY.match(texts[rel][k])]
                        hit = sum(min(want[rel][k], got[rel][k]) for k in same)
                        # Verbatim: the reported text is still in the bytes. Otherwise the run
                        # assembled it across runs or cells, or decoded it from a binary field.
                        verb = sum(min(want[rel][k], got[rel][k]) for k in same if present(texts[rel][k], blobs))
                        found = {t for t in texts[rel].values() if not LABEL_ONLY.match(t)
                                 and (len(t) >= 8 or (len(t) >= 6 and re.search(r"[\d@]", t)))
                                 and present(t, blobs)}
                        silent += hit
                        verbatim += verb
                        raw += len(found)
                        if (hit or found) and not g["private"]:
                            kinds = sorted({k[0] for k in same})
                            survivors.append((label, strategy, g["name"], rel, hit, verb, len(found), ",".join(kinds)))
                rows.append(dict(group=g["name"], strategy=strategy, status=status, code=res["code"],
                                 wall=res["wall"], rss=res["rss"], files=len(g["files"]), written=len(outputs),
                                 not_redacted=st.get("files_not_redacted", 0),
                                 values_not_redacted=st.get("values_not_redacted", 0),
                                 causes=dict(causes), silent=silent, verbatim=verbatim, raw=raw, labels=labels,
                                 recovered=recovered(res["err"]),
                                 unredacted=[] if g["private"] else
                                 [(strip(u.get("path", ""), in_roots) or u.get("path", ""), u.get("cause", ""),
                                   re.sub(r"\s+", " ", str(u.get("detail", "")))[:200], u.get("reported_values", 0))
                                  for u in unred]))
                log(f"   redact {label:<6} {strategy:<17} {g['name']:<10} {res['wall']:7.1f}s  written "
                    f"{len(outputs):>4}/{len(g['files']):<4} not-redacted {st.get('files_not_redacted', 0):>3}  "
                    f"silent {silent:>3} (verbatim {verbatim})  raw {raw:>3}  label-only {labels}  {status}")
                if g["private"]:
                    shutil.rmtree(od, ignore_errors=True)
        with open(os.path.join(self.out, f"redaction-{label}.tsv"), "w") as f:
            f.write("format\tstrategy\tstatus\texit\twall_s\tfiles\twritten\tfiles_not_redacted\t"
                    "values_not_redacted\tcauses\tsilent_survivors\tsilent_verbatim\traw_survivors\tlabel_only\n")
            for r in rows:
                if r["group"] == PRIVATE:
                    continue
                f.write(f"{r['group']}\t{r['strategy']}\t{r['status']}\t{r['code']}\t{r['wall']:.1f}\t{r['files']}\t"
                        f"{r['written']}\t{r['not_redacted']}\t{r['values_not_redacted']}\t"
                        f"{json.dumps(r['causes'], sort_keys=True)}\t{r['silent']}\t{r['verbatim']}\t{r['raw']}\t"
                        f"{r['labels']}\n")
        with open(os.path.join(self.out, f"redaction-survivors-{label}.tsv"), "w") as f:
            f.write("binary\tstrategy\tformat\tfile\tsilent\tverbatim\traw\ttypes\n")
            for s in survivors:
                f.write("\t".join(str(x) for x in s) + "\n")
        with open(os.path.join(self.out, f"not-redacted-{label}.tsv"), "w") as f:
            f.write("format\tstrategy\tfile\tcause\tdetail\treported_values\n")
            for r in rows:
                for rel, cause, detail, n in r["unredacted"]:
                    f.write(f"{r['group']}\t{r['strategy']}\t{rel}\t{cause}\t{detail}\t{n}\n")
        return rows, survivors


LABEL_ONLY = re.compile(r"^\s*[A-Za-z][\w .()/-]{0,40}:\s*$")


def output_blobs(path):
    """A redacted output's searchable bytes: every zip part decompressed, else the file itself."""
    blobs = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.file_size <= 64 * MB:
                        blobs.append(z.read(info))
        else:
            with open(path, "rb") as f:
                blobs.append(f.read(64 * MB))
    except Exception:
        return []
    return blobs


def present(value, blobs):
    """The value verbatim, or XML-escaped, in any blob."""
    forms = {value.encode("utf-8", "surrogatepass"),
             value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").encode("utf-8", "surrogatepass")}
    return any(fm in b for fm in forms for b in blobs)


# ---------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------
def by(rows, idx):
    c = collections.defaultdict(collections.Counter)
    for kind, key, x, y in rows:
        c[key[idx]][kind] += 1
    return c


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser()
    for name in ("corpus", "out", "base_ref", "base_sha", "base_bin", "head_ref", "head_sha", "head_bin"):
        p.add_argument(name)
    p.add_argument("--include-private", action="store_true")
    p.add_argument("--no-redaction", action="store_true")
    p.add_argument("--formats", default="")
    p.add_argument("--timeout", type=int, default=900)
    a = p.parse_args()
    same = a.base_sha == a.head_sha
    if same:
        a.head_bin = a.base_bin
    ab = AB(a)
    if not ab.groups:
        log("corpus-ab: the corpus has no files for the requested formats")
        return 2
    pub = [g for g in ab.groups if not g["private"]]
    log(f"corpus {a.corpus}: {sum(len(g['files']) for g in pub)} public files in {len(pub)} formats, "
        f"{sum(g['bytes'] for g in pub) / MB:.1f} MB" +
        ("; private/ included (aggregate counts only)" if any(g["private"] for g in ab.groups) else ""))
    with open(os.path.join(a.out, "corpus.tsv"), "w") as f:
        f.write("format\tfiles\tbytes\n")
        for g in sorted(pub, key=lambda g: g["name"]):
            f.write(f"{g['name']}\t{len(g['files'])}\t{g['bytes']}\n")

    t0 = time.monotonic()
    base1 = ab.scan_pass("base1", a.base_bin)
    first = time.monotonic() - t0
    passes = 2 + (0 if a.no_redaction else (2 if same else 4) * 2)
    log(f"   one pass took {first:.0f}s; expect roughly {first * passes / 60:.0f} more minutes")
    base2 = ab.scan_pass("base2", a.base_bin)
    head = ab.scan_pass("head", a.head_bin)

    ne_base, ne_base_priv = ab.attribute("base", a.base_bin, base1)
    ne_head, ne_head_priv = (ne_base, ne_base_priv) if same else ab.attribute("head", a.head_bin, head)

    noise = AB.diff(base1, base2)
    noise_keys = frozenset(k for _, k, _, _ in noise)
    abrows = AB.diff(base1, head)
    ab.write_diff("diff-noise", noise)
    ab.write_diff("diff-ab", abrows, noise_keys)
    real = [r for r in abrows if r[1] not in noise_keys]

    red_base = red_head = ([], [])
    if not a.no_redaction:
        log("== redaction")
        red_base = ab.redact_pass("base", a.base_bin)
        red_head = red_base if same else ab.redact_pass("head", a.head_bin)

    # ---------------- report ----------------
    R = []
    R.append(f"# corpus A/B: {a.base_ref} ({a.base_sha[:12]}) vs {a.head_ref} ({a.head_sha[:12]})\n")
    R.append(f"Corpus: {sum(len(g['files']) for g in pub)} public files, {len(pub)} formats, "
             f"{sum(g['bytes'] for g in pub) / MB:.1f} MB. Flags: `--recursive {' '.join(SCAN_FLAGS)}`, "
             "one invocation per format directory.\n")
    R.append("## Baseline per format (BASE, first pass)\n")
    ne_by = collections.defaultdict(collections.Counter)
    for fmt, _, cause, _ in ne_base:
        ne_by[fmt][cause] += 1
    rows = []
    for g in sorted(ab.groups, key=lambda g: g["name"]):
        r = base1[g["name"]]
        st = r["stats"]
        types = collections.Counter(k[3] for k, _, _, _ in r["findings"])
        top = ", ".join(f"{t} {n}" for t, n in types.most_common(6)) or "-"
        skipped = ", ".join(f"{k} {v}" for k, v in sorted((st.get("skipped_types") or {}).items())) or "-"
        tally = ne_base_priv if g["private"] else ne_by[g["name"]]
        why = ", ".join(f"{c} {n}" for c, n in sorted(tally.items())) or \
            ", ".join(f"{c} {n}" for c, n in sorted(r["footer_tally"].items())) or "-"
        name = "private (aggregate)" if g["private"] else g["name"]
        rows.append((name, len(g["files"]), f"{g['bytes'] / MB:.1f}", st.get("files_processed", "?"), skipped,
                     f"{st.get('files_not_examined', 0)} ({why})" if st.get("files_not_examined") else "0",
                     st.get("total_findings", "?"), f"{st.get('high', 0)}/{st.get('medium', 0)}/{st.get('low', 0)}",
                     top, f"{r['wall']:.1f}", f"{r['rss'] / MB:.0f}", r["status"],
                     r["recovered"] or ""))
    R.append(table(["format", "files", "MB", "processed", "skipped (type)", "not examined (why)", "findings", "H/M/L",
                    "top types", "wall s", "RSS MB", "status", "recovered panics"], rows))
    R.append("")
    R.append("## Findings by type (BASE, first pass)\n")
    tt = collections.defaultdict(lambda: [0, 0, 0, 0, set()])
    for g in ab.groups:
        for key, conf, level, _ in base1[g["name"]]["findings"]:
            e = tt[key[3]]
            e[0] += 1
            e[{"HIGH": 1, "MEDIUM": 2}.get(level, 3)] += 1
            e[4].add("private" if g["private"] else g["name"])
    R.append(table(["type", "findings", "HIGH", "MEDIUM", "LOW", "formats"],
                   [(t, e[0], e[1], e[2], e[3], len(e[4])) for t, e in sorted(tt.items(), key=lambda kv: -kv[1][0])]))
    R.append("")
    with open(os.path.join(a.out, "findings-by-type-format-base.tsv"), "w") as f:
        f.write("type\tformat\tfindings\tHIGH\tMEDIUM\tLOW\n")
        cells = collections.defaultdict(collections.Counter)
        for g in ab.groups:
            for key, conf, level, _ in base1[g["name"]]["findings"]:
                cells[(key[3], "private" if g["private"] else g["name"])][level or "?"] += 1
        for (t, fmt), c in sorted(cells.items()):
            f.write(f"{t}\t{fmt}\t{sum(c.values())}\t{c['HIGH']}\t{c['MEDIUM']}\t{c['LOW']}\n")
    for title, rs in (("Noise floor: BASE vs BASE", noise), ("A/B: BASE vs HEAD, outside the noise floor", real)):
        R.append(f"## {title}\n")
        tot = collections.Counter(k for k, _, _, _ in rs)
        R.append(f"new {tot['new']}, lost {tot['lost']}, confidence-changed {tot['changed']}"
                 + (f" (plus {len(abrows) - len(real)} rows on noisy keys)" if rs is real else "") + "\n")
        for label, idx in (("type", 3), ("format", 0)):
            c = by(rs, idx)
            if c:
                R.append(table([label, "new", "lost", "changed"],
                               [("private (aggregate)" if k == PRIVATE else k, v["new"], v["lost"], v["changed"])
                                for k, v in sorted(c.items())]))
                R.append("")
    if not same:
        R.append("## Not examined: BASE vs HEAD\n")
        sb = {(f, p): c for f, p, c, _ in ne_base}
        sh = {(f, p): c for f, p, c, _ in ne_head}
        moved = [(f, p, sb.get((f, p), "-"), sh.get((f, p), "-")) for (f, p) in sorted(set(sb) | set(sh))
                 if sb.get((f, p)) != sh.get((f, p))]
        R.append(table(["format", "file", "BASE", "HEAD"], moved) if moved else "no change\n")
        R.append("")
    R.append("## Not examined (BASE), per file\n")
    R.append(table(["format", "file", "cause", "detail"], [(f, p, c, d[:160]) for f, p, c, d in ne_base])
             if ne_base else "none\n")
    if ne_base_priv:
        R.append(f"\nprivate (aggregate): {dict(ne_base_priv)}\n")
    R.append("")
    if not a.no_redaction:
        for label, (rrows, surv) in (("BASE", red_base),) + ((("HEAD", red_head),) if not same else ()):
            R.append(f"## Redaction ({label})\n")
            R.append("Silent survivors: values the run reported, then found again in its own redacted copy of a "
                     "file it did not disclose as unredacted (\"verbatim\": the text is still in the bytes). Raw: "
                     "reported values of 8+ characters (6+ with a digit or @) present verbatim in the copy. "
                     "Label-only: a field name with no value, nothing to redact.\n")
            R.append(table(["format", "strategy", "files", "written", "files_not_redacted (cause)", "values_not_redacted",
                            "silent survivors (verbatim)", "raw survivors", "label-only", "exit", "wall s", "status",
                            "recovered panics"],
                           [("private (aggregate)" if r["group"] == PRIVATE else r["group"], r["strategy"], r["files"],
                             r["written"],
                             f"{r['not_redacted']} ({', '.join(f'{k} {v}' for k, v in sorted(r['causes'].items()))})"
                             if r["not_redacted"] else "0",
                             r["values_not_redacted"] or 0, f"{r['silent']} ({r['verbatim']})", r["raw"], r["labels"],
                             r["code"], f"{r['wall']:.1f}", r["status"], r["recovered"] or "")
                            for r in sorted(rrows, key=lambda r: (r["group"], r["strategy"]))]))
            R.append("")
            # "no redactor for this file type" is the documented PDF/TIFF/GIF/BMP/WEBP refusal: counted
            # in the table above, not listed file by file.
            listed = [(r["group"], r["strategy"], rel, cause, detail[:120], n)
                      for r in sorted(rrows, key=lambda r: (r["group"], r["strategy"]))
                      for rel, cause, detail, n in r["unredacted"] if cause != "no redactor for this file type"]
            if listed:
                R.append(f"Files reported but not redacted ({label}, disclosed by the run; "
                         "'no redactor for this file type' omitted):\n")
                R.append(table(["format", "strategy", "file", "cause", "detail", "values"], listed))
                R.append("")
            if surv:
                R.append("**P0: reported values found again in a redacted copy the run did not disclose as unredacted:**\n")
                R.append(table(["strategy", "format", "file", "silent", "verbatim", "raw", "types"], [s[1:] for s in surv]))
                R.append("")
    report = "\n".join(R) + "\n"
    with open(os.path.join(a.out, "report.md"), "w") as f:
        f.write(report)
    log("")
    log(report)

    # ---------------- verdict ----------------
    lost = [r for r in real if r[0] == "lost"]
    worse = [g["name"] for g in ab.groups
             if base1[g["name"]]["status"] == "ok" and head[g["name"]]["status"] != "ok"]
    base_silent = {(s[2], s[3]) for s in red_base[1] if s[4]}
    new_silent = [s for s in red_head[1] if s[4] and (s[2], s[3]) not in base_silent]
    if not same and (lost or worse or new_silent):
        log(f"REGRESSION: lost {len(lost)}, formats newly failing {worse}, new silent survivors {len(new_silent)}")
        return 1
    log(f"done in {(time.monotonic() - t0) / 60:.1f} min; report: {os.path.join(a.out, 'report.md')}")
    return 0


sys.exit(main())
PY
status=${PIPESTATUS[0]}
exit "$status"
