### 🐛 Bug Fixes

- **web: `/export` exports the scan the server ran.** It used to rebuild findings from the JSON the
  browser posted back, which carries neither the explanation, nor the context keywords, nor typed
  metadata: in the parity test 18 of 28 exported bodies lost the explanation, 6 the context keywords
  and 2 the verbose validation block, and because every result travelled in one request under the
  1 MiB body cap, 782 findings answered HTTP 400. `/scan` now keeps its result server-side (per
  browser session, an hour at most, bounded in count and size) and returns a `scan_id`; `/export`
  takes `scan_ids` and formats exactly those results, in all seven formats byte-identical to
  `formatters.Export` of the same scan. 782 and 5,000 findings export. ⚠ An API client that posted
  `results` to `/export` now gets HTTP 400 naming `scan_ids`: keep the `ferret_scan_session` cookie
  `/scan` sets and send `{"format", "scan_ids", "show_match", "verbose"}`.
  ([#923](https://github.com/awslabs/ferret-scan/issues/923))
- **web: a narrowed `/scan` says so.** The response gains the `scan` block the CLI's json report
  carries (checks run and not run, confidence bands, config source), omitted for a full-scope scan
  as on the CLI. ([#904](https://github.com/awslabs/ferret-scan/issues/904))
- **coverage: a file every preprocessor failed on carries the cause `cannot parse`.** The worker
  pool stated no cause for the router's "all preprocessors failed" error, so `/scan` disclosed 12 of
  the 639 public corpus files with an empty cause while the CLI recovered `cannot parse` from the
  prose. ([#924](https://github.com/awslabs/ferret-scan/issues/924))
