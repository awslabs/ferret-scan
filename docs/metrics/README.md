# Download Metrics

`downloads.csv` is a weekly snapshot of ferret-scan's public download/pull
counts across every distribution channel. It is produced **passively** — by
querying public APIs — with **no change to the ferret-scan binary and no
network egress from the tool itself**. The tool remains egress-free by design;
usage is measured from the outside.

## How it is collected

- **Automatically:** the [`Download Metrics`](../../.github/workflows/download-metrics.yml)
  workflow runs every Monday 06:00 UTC (and on manual dispatch) and commits a
  new row via `github-actions[bot]`.
- **Locally / on demand:**

  ```bash
  python3 scripts/collect-download-metrics.py
  ```

  (Set `GITHUB_TOKEN` to avoid the low unauthenticated GitHub rate limit.)

## Columns

| Column | Source | Meaning |
|---|---|---|
| `date` | — | UTC date the snapshot was taken |
| `latest_release` | GitHub Releases API | Newest non-prerelease tag at snapshot time (correlate spikes to releases) |
| `pypi_last_day` | pypistats.org | PyPI installs in the last day (mirrors excluded) |
| `pypi_last_week` | pypistats.org | PyPI installs in the last 7 days |
| `pypi_last_month` | pypistats.org | PyPI installs in the last 30 days |
| `pypi_last_month_with_mirrors` | pypistats.org | Last-30-day installs **including** mirrors (track CI/mirror noise ratio) |
| `pypi_py3_7_30d` … `pypi_py3_13_30d` | pypistats.org | Last-30-day installs per declared Python minor version |
| `pypi_py_other_30d` | pypistats.org | Last-30-day installs for unknown/`null` or out-of-range Python versions |
| `ecr_pulls_total` | ECR Public gallery API | **Lifetime cumulative** pulls of `public.ecr.aws/awslabs/ferret-scan` (all tags) |
| `ecr_pulls_delta` | computed | `ecr_pulls_total` minus the previous row's value (weekly pulls) |
| `github_binary_downloads_total` | GitHub Releases API | **Lifetime cumulative** sum of `download_count` across all release assets |
| `github_binary_downloads_delta` | computed | `github_binary_downloads_total` minus the previous row's value (weekly downloads) |
| `gh_linux_amd64` … `gh_windows_arm64` | GitHub Releases API | **Lifetime cumulative** per-platform asset downloads (shows which platforms matter) |

## Reading the numbers

- **PyPI columns are rolling windows** — read them directly.
- **ECR / GitHub totals are lifetime-cumulative.** Use the `*_delta` columns
  for the weekly rate (they are `total − previous row`; blank on the first row
  and whenever the prior value is missing). The per-platform `gh_*` columns are
  also cumulative — diff across rows for a weekly per-platform rate.
- The three channels measure **different funnel stages** and should not be
  summed. In particular the PyPI package is a thin shim that downloads the Go
  binary from GitHub on first run, so a `pip install` does not equal a GitHub
  binary download.
- All counters include CI re-installs / re-pulls and cannot dedupe users;
  treat them as ceilings, not unique-user counts.
- **Missing cells** mean a channel's API was unreachable that run (e.g. a
  pypistats `429`); the rest of the row is still valid.

## Not collected: installer breakdown

pip vs uv vs poetry is **not** included — pypistats has no installer endpoint,
and that split is only available in the PyPI BigQuery dataset, which requires
GCP credentials and is out of scope for this zero-secret job.

## What is intentionally **not** measured

Execution / active-user counts. There is no passive signal for "a scan ran";
only an in-binary phone-home could produce it. That was deliberately **not**
added — keeping the scanner egress-free is a security property worth more than
execution telemetry, especially for a tool pointed at sensitive data.
