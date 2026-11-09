#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# corpus-triage.sh — the FP-tuning ledgers of the real-file corpus (CORPUS_PLAN.md): list the
# findings an A/B left untriaged and record a verdict for them, so a later run shows only what is
# new, a finding marked FP stays marked, a lost FP counts as a win and a lost TP blocks.
#
#   <corpus>/triage/public.tsv    path, validator, type, line, text_sha256 -> verdict, note
#   <corpus>/triage/private.tsv   key_sha256 (of the whole finding key), type, format, level -> verdict
#
# Both are append-only; the latest row for a key wins. scripts/corpus-ab.sh writes what each A/B
# leaves pending: every new HIGH and every lost finding without a verdict. For the public set they
# are in <run>/public/triage-pending.tsv; for the private set they are rows of triage/private.tsv
# with an empty verdict, because a hashed key, its type, format and level are all that may be
# written about a private finding. This script never prints a private path or value: it has none.
#
# Usage:
#   scripts/corpus-triage.sh [--corpus DIR] list [--run DIR] [--all] [--unmasked]
#       untriaged public findings of the latest A/B run (or --run), then pending private keys;
#       --all includes those already in the ledger; --unmasked prints public values in full
#   scripts/corpus-triage.sh [--corpus DIR] mark TP|FP|unsure ID... [--note TEXT] [--run DIR]
#       record a verdict for public IDs (from `list`) or private key hashes (a 12+ character prefix)
#   scripts/corpus-triage.sh [--corpus DIR] mark-private TP|FP|unsure --type T [--format F]
#                            [--level L] [--note TEXT]
#       record a verdict for every PENDING private key of that type (and format, level)
#   scripts/corpus-triage.sh [--corpus DIR] stats
#       verdict counts in both ledgers
#
# The corpus root is --corpus DIR, else $FERRET_CORPUS_DIR, else ../ferret-corpus. Exit status: 0,
# 1 when an ID matched nothing, 2 on a usage error.
#
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$here/.." && pwd)

corpus="" pass=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,/^set -uo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 0 ;;
    --corpus) [ $# -ge 2 ] || { echo "corpus-triage: --corpus needs a directory" >&2; exit 2; }; corpus="$2"; shift 2 ;;
    --corpus=*) corpus="${1#--corpus=}"; shift ;;
    *) pass+=("$1"); shift ;;
  esac
done
[ -n "$corpus" ] || corpus="${FERRET_CORPUS_DIR:-}"
[ -n "$corpus" ] || corpus="$repo_root/../ferret-corpus"
if [ ! -d "$corpus" ]; then
  echo "corpus-triage: no corpus at $corpus; see scripts/corpus-fetch.sh" >&2
  exit 2
fi
corpus=$(cd "$corpus" && pwd)

exec python3 - "$corpus" ${pass[@]+"${pass[@]}"} <<'PY'
import argparse
import collections
import datetime
import gzip
import hashlib
import json
import os
import re
import sys

PUB_COLS = ["path", "validator", "type", "line", "text_sha256", "verdict", "note", "date", "run"]
PRIV_COLS = ["key_sha256", "type", "format", "level", "verdict", "note", "date", "run"]
PENDING_COLS = ["id", "kind", "level", "path", "validator", "type", "line", "text_sha256", "base", "head", "masked"]
VERDICTS = {"tp": "TP", "fp": "FP", "unsure": "unsure"}


def cell(v):
    return re.sub(r"[\t\r\n]+", " ", str(v))


def read(path, cols):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f):
            parts = line.rstrip("\n").split("\t")
            if n == 0 and parts[0] == cols[0]:
                continue
            if len(parts) == len(cols):
                rows.append(dict(zip(cols, parts)))
    return rows


def append(path, cols, rows):
    if not rows:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    new = not os.path.exists(path)
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write("\t".join(cols) + "\n")
        for r in rows:
            f.write("\t".join(cell(r.get(c, "")) for c in cols) + "\n")


def pub_key(r):
    return (r["path"], r["validator"], r["type"], r["line"], r["text_sha256"])


def latest(rows, keyf):
    out = {}
    for r in rows:
        out[keyf(r)] = r
    return out


def latest_run(corpus, explicit):
    if explicit:
        return os.path.abspath(explicit)
    runs = os.path.join(corpus, "runs")
    if not os.path.isdir(runs):
        return None
    cands = sorted((d for d in os.listdir(runs) if os.path.exists(os.path.join(runs, d, "public", "triage-pending.tsv"))),
                   reverse=True)
    return os.path.join(runs, cands[0]) if cands else None


def unmasked_values(run):
    """Public values by key from the run's own raw outputs (public data only)."""
    vals = {}
    for name in ("base1.json.gz", "head1.json.gz"):
        p = os.path.join(run, "public", "raw", name)
        if not os.path.exists(p):
            continue
        for r in json.loads(gzip.open(p).read()).get("results") or []:
            t = str(r.get("text", ""))
            key = (str(r.get("filename", "")), str(r.get("validator", "")), str(r.get("type", "")),
                   str(r.get("line_number") or 0), hashlib.sha256(t.encode("utf-8", "surrogatepass")).hexdigest())
            vals[key] = t
    return vals


def main():
    corpus = sys.argv[1]
    ap = argparse.ArgumentParser(prog="corpus-triage.sh")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list")
    p_list.add_argument("--run")
    p_list.add_argument("--all", action="store_true")
    p_list.add_argument("--unmasked", action="store_true")
    p_mark = sub.add_parser("mark")
    p_mark.add_argument("verdict")
    p_mark.add_argument("ids", nargs="+")
    p_mark.add_argument("--note", default="")
    p_mark.add_argument("--run")
    p_mp = sub.add_parser("mark-private")
    p_mp.add_argument("verdict")
    p_mp.add_argument("--type", required=True)
    p_mp.add_argument("--format")
    p_mp.add_argument("--level")
    p_mp.add_argument("--note", default="")
    sub.add_parser("stats")
    a = ap.parse_args(sys.argv[2:])

    tdir = os.path.join(corpus, "triage")
    pub_path, priv_path = os.path.join(tdir, "public.tsv"), os.path.join(tdir, "private.tsv")
    pub = latest(read(pub_path, PUB_COLS), pub_key)
    priv = latest(read(priv_path, PRIV_COLS), lambda r: r["key_sha256"])
    today = datetime.date.today().isoformat()

    if a.cmd == "stats":
        for name, rows in (("public", pub), ("private", priv)):
            c = collections.Counter((r["verdict"] or "pending") for r in rows.values())
            print(f"{name}: {len(rows)} key(s): " + ", ".join(f"{k} {n}" for k, n in sorted(c.items())))
        return 0

    if a.cmd in ("mark", "mark-private"):
        verdict = VERDICTS.get(a.verdict.lower())
        if not verdict:
            print("corpus-triage: the verdict is TP, FP or unsure", file=sys.stderr)
            return 2

    if a.cmd == "list":
        run = latest_run(corpus, a.run)
        shown = 0
        if run:
            pending = read(os.path.join(run, "public", "triage-pending.tsv"), PENDING_COLS)
            vals = unmasked_values(run) if a.unmasked else {}
            rows = [r for r in pending if a.all or pub_key(r) not in pub or not pub[pub_key(r)]["verdict"]]
            print(f"public: {len(rows)} untriaged of {len(pending)} pending in {os.path.relpath(run, corpus)}")
            for r in rows:
                v = vals.get(pub_key(r), r["masked"]) if a.unmasked else r["masked"]
                known = pub.get(pub_key(r), {}).get("verdict", "")
                print(f"  {r['id']}  {r['kind']:<4} {r['level']:<6} {r['type']:<22} {r['validator']:<14} "
                      f"{r['path']}:{r['line']}  {v}" + (f"  [{known}]" if known else ""))
                shown += 1
        else:
            print("public: no A/B run with a triage-pending list yet")
        pend = [r for r in priv.values() if not r["verdict"]]
        print(f"private: {len(pend)} pending key(s) (hash, type, format, level only)")
        by = collections.Counter((r["type"], r["format"], r["level"]) for r in pend)
        for (t, f, lv), n in sorted(by.items(), key=lambda kv: -kv[1]):
            print(f"  {n:>5}  {t:<22} {f:<8} {lv}")
        for r in sorted(pend, key=lambda r: (r["type"], r["format"]))[:200]:
            print(f"  {r['key_sha256'][:16]}  {r['type']:<22} {r['format']:<8} {r['level']}")
        return 0

    if a.cmd == "mark":
        run = latest_run(corpus, a.run)
        pending = read(os.path.join(run, "public", "triage-pending.tsv"), PENDING_COLS) if run else []
        add_pub, add_priv, missed = [], [], []
        for ident in a.ids:
            ident = ident.lower()
            hits = [r for r in pending if r["id"].startswith(ident)] if len(ident) >= 6 else []
            if len(hits) == 1:
                r = hits[0]
                add_pub.append(dict(path=r["path"], validator=r["validator"], type=r["type"], line=r["line"],
                                    text_sha256=r["text_sha256"], verdict=verdict, note=a.note, date=today,
                                    run=os.path.basename(run)))
                continue
            phits = [r for k, r in priv.items() if k.startswith(ident)] if len(ident) >= 12 else []
            if len(phits) == 1:
                r = phits[0]
                add_priv.append(dict(key_sha256=r["key_sha256"], type=r["type"], format=r["format"], level=r["level"],
                                     verdict=verdict, note=a.note, date=today, run=r.get("run", "")))
                continue
            missed.append(ident)
        append(pub_path, PUB_COLS, add_pub)
        append(priv_path, PRIV_COLS, add_priv)
        print(f"recorded {verdict}: {len(add_pub)} public, {len(add_priv)} private"
              + (f"; no single match for {', '.join(missed)}" if missed else ""))
        return 1 if missed else 0

    if a.cmd == "mark-private":
        rows = [r for r in priv.values() if not r["verdict"] and r["type"] == a.type
                and (not a.format or r["format"] == a.format) and (not a.level or r["level"] == a.level.upper())]
        append(priv_path, PRIV_COLS, [dict(r, verdict=verdict, note=a.note, date=today) for r in rows])
        print(f"recorded {verdict} for {len(rows)} pending private key(s)")
        return 0
    return 2


sys.exit(main())
PY
