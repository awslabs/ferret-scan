#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Collect ferret-scan download metrics from all public distribution channels.

Queries public APIs with NO change to the ferret-scan binary and NO egress from
the tool itself:

  * PyPI installs   -- pypistats.org (rolling windows, with/without mirrors,
                       and a per-Python-version breakdown)
  * Docker pulls    -- Amazon ECR Public gallery API (lifetime cumulative)
  * GitHub binaries -- GitHub Releases API, per-platform + total asset
                       download_count (lifetime cumulative)

Appends one row to docs/metrics/downloads.csv (creating it with a header if
absent). Cumulative counters (ECR, GitHub) also get a *_delta column computed
against the previous row, so week-over-week pulls are readable directly.

Runnable locally (python3 scripts/collect-download-metrics.py) or from CI. A
GITHUB_TOKEN in the environment is used for the GitHub API to avoid the low
unauthenticated rate limit; everything else is unauthenticated public data.

Per-channel network failures are recorded as empty cells rather than failing
the whole run, so a transient pypistats 429 never blocks the snapshot.

NOTE: installer breakdown (pip vs uv vs poetry) is intentionally absent --
pypistats has no installer endpoint; that split is only in the PyPI BigQuery
dataset, which needs GCP credentials and is out of scope here.
"""

import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

PYPI_PACKAGE = "ferret-scan"
ECR_ALIAS = "awslabs"
ECR_REPO = "ferret-scan"
GITHUB_REPO = "awslabs/ferret-scan"

# Declared support range (see python-package/setup.py classifiers). Anything
# outside this set -- newer 3.14+, or "null"/unknown -- folds into py_other so
# the CSV header stays stable as new Python versions appear.
PY_VERSIONS = ["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13"]

# GitHub release asset basename fragments -> column suffix. Matched as a
# substring of the asset name (e.g. "ferret-scan_1.10.0_linux_amd64").
GH_PLATFORMS = [
    ("linux_amd64", "gh_linux_amd64"),
    ("linux_arm64", "gh_linux_arm64"),
    ("darwin_amd64", "gh_darwin_amd64"),
    ("darwin_arm64", "gh_darwin_arm64"),
    ("windows_amd64", "gh_windows_amd64"),
    ("windows_arm64", "gh_windows_arm64"),
]

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(REPO_ROOT, "docs", "metrics", "downloads.csv")

COLUMNS = (
    ["date", "latest_release"]
    + ["pypi_last_day", "pypi_last_week", "pypi_last_month", "pypi_last_month_with_mirrors"]
    + [f"pypi_py{v.replace('.', '_')}_30d" for v in PY_VERSIONS]
    + ["pypi_py_other_30d"]
    + ["ecr_pulls_total", "ecr_pulls_delta"]
    + ["github_binary_downloads_total", "github_binary_downloads_delta"]
    + [col for _, col in GH_PLATFORMS]
)

USER_AGENT = "ferret-scan-metrics/1.0 (+https://github.com/awslabs/ferret-scan)"


def _get(url, headers=None, data=None, method="GET", retries=3, timeout=30):
    """HTTP request with simple backoff. Returns parsed JSON or raises."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = data.encode() if isinstance(data, str) else data
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code != 429 and e.code < 500:  # only retry 429 / 5xx
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
        if attempt < retries - 1:
            time.sleep(2 ** attempt)  # 1s, 2s
    raise last_err


def _sum_last_days(rows, days=30, predicate=None):
    """Sum `downloads` over the most recent `days` distinct dates in a
    pypistats daily series, optionally filtered by a category predicate."""
    dates = sorted({r["date"] for r in rows})[-days:]
    recent = set(dates)
    return sum(
        r["downloads"]
        for r in rows
        if r["date"] in recent and (predicate is None or predicate(r["category"]))
    )


def collect_pypi_windows():
    """Rolling last_day / last_week / last_month install counts (no mirrors)."""
    data = _get(f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/recent")["data"]
    return data.get("last_day"), data.get("last_week"), data.get("last_month")


def collect_pypi_with_mirrors_month():
    """Mirror-inclusive installs over the last 30 days (tracks CI/mirror noise)."""
    rows = _get(f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/overall?mirrors=true")["data"]
    return _sum_last_days(rows, 30, predicate=lambda c: c == "with_mirrors")


def collect_pypi_by_pyversion():
    """Last-30-day installs per declared Python minor version, plus an
    `other` catch-all for null/unknown and versions outside the support range."""
    rows = _get(f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/python_minor")["data"]
    known = set(PY_VERSIONS)
    out = {v: _sum_last_days(rows, 30, predicate=lambda c, ver=v: c == ver) for v in PY_VERSIONS}
    out["other"] = _sum_last_days(rows, 30, predicate=lambda c: c not in known)
    return out


def collect_ecr():
    """Lifetime cumulative pull count for the ECR Public repository (all tags)."""
    url = "https://api.us-east-1.gallery.ecr.aws/getRepositoryCatalogData"
    payload = json.dumps({"registryAliasName": ECR_ALIAS, "repositoryName": ECR_REPO})
    res = _get(url, headers={"Content-Type": "application/json"}, data=payload, method="POST")
    return res.get("insightData", {}).get("downloadCount")


def collect_github():
    """Per-platform + total + latest tag from the GitHub Releases API (lifetime)."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    per_platform = {col: 0 for _, col in GH_PLATFORMS}
    total = 0
    latest_tag = None
    page = 1
    while True:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=100&page={page}"
        releases = _get(url, headers=headers)
        if not releases:
            break
        for rel in releases:
            # First non-draft, non-prerelease tag seen (API returns newest first).
            if latest_tag is None and not rel.get("draft") and not rel.get("prerelease"):
                latest_tag = rel.get("tag_name")
            for asset in rel.get("assets", []):
                count = asset.get("download_count", 0)
                total += count
                name = asset.get("name", "")
                for frag, col in GH_PLATFORMS:
                    if frag in name:
                        per_platform[col] += count
                        break
        if len(releases) < 100:
            break
        page += 1
    return total, latest_tag, per_platform


def _previous_row():
    """Last data row of the existing CSV (for delta computation), or {}."""
    if not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0:
        return {}
    with open(CSV_PATH, newline="") as f:
        rows = list(csv.DictReader(f))
    return rows[-1] if rows else {}


def _delta(current, prev_row, key):
    """current - previous, or "" if either side is missing/non-numeric."""
    if current is None:
        return ""
    prev = (prev_row or {}).get(key, "")
    try:
        return current - int(prev)
    except (ValueError, TypeError):
        return ""


def safe(collector, name, default=None):
    try:
        return collector()
    except Exception as e:  # noqa: BLE001 - one bad channel must not sink the row
        print(f"WARN: {name} collection failed: {e}", file=sys.stderr)
        return default


def main():
    prev = _previous_row()

    day, week, month = safe(collect_pypi_windows, "pypi-windows", (None, None, None))
    time.sleep(1)  # be polite to pypistats between calls
    month_mirrors = safe(collect_pypi_with_mirrors_month, "pypi-mirrors")
    time.sleep(1)
    by_pyver = safe(collect_pypi_by_pyversion, "pypi-pyversion", {})

    ecr = safe(collect_ecr, "ecr")
    gh = safe(collect_github, "github", (None, None, {}))
    gh_total, latest_tag, gh_platforms = gh

    row = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "latest_release": latest_tag,
        "pypi_last_day": day,
        "pypi_last_week": week,
        "pypi_last_month": month,
        "pypi_last_month_with_mirrors": month_mirrors,
        "ecr_pulls_total": ecr,
        "ecr_pulls_delta": _delta(ecr, prev, "ecr_pulls_total"),
        "github_binary_downloads_total": gh_total,
        "github_binary_downloads_delta": _delta(gh_total, prev, "github_binary_downloads_total"),
    }
    for v in PY_VERSIONS:
        row[f"pypi_py{v.replace('.', '_')}_30d"] = by_pyver.get(v)
    row["pypi_py_other_30d"] = by_pyver.get("other")
    for _, col in GH_PLATFORMS:
        row[col] = gh_platforms.get(col) if gh_platforms else None

    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    write_header = not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0
    with open(CSV_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in COLUMNS})

    print(f"Appended {row['date']} to {os.path.relpath(CSV_PATH, REPO_ROOT)}")
    for k in COLUMNS:
        print(f"  {k}: {row.get(k)}")

    # Surface a hard failure only if every channel was unreachable.
    if day is None and ecr is None and gh_total is None:
        print("ERROR: all channels failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
