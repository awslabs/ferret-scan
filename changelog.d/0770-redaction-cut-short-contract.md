### 🐛 Bug Fixes

- **redaction, pkg/scan, pkg/redact (cut-short coverage):** a redaction that could not examine all of
  its input now fails on every sink the way `--file` always has, and a fired validator budget keeps
  what it found instead of discarding it and re-running the file
  ([#770](https://github.com/awslabs/ferret-scan/issues/770)). Measured on v2.5.5: `--stdin
  --enable-redaction` exited 0 under `--fail-on-incomplete` on a cut-short scan (a 1ns budget, a log
  over the 5 MiB `CLOUD_RESOURCES` cap, `SSN=300ms` on 20,000 records), and in pre-commit mode `--stdin`
  printed 0 bytes of disclosure; `Engine.Redact` returned `err == nil` with the input unredacted for a
  pre-cancelled context, for 1, 100 and 200 ms deadlines (0 of 6,000 findings) and for a 5.8 MB
  `CLOUD_RESOURCES` request; `RedactFile` copied an unparseable `.pdf` byte-identical to the output
  path, and a log over the cap with 5,518 of 5,518 ARN lines in clear, at `err == nil`; `ScanText` and
  `ScanFile` ignored their context (30,000 of 30,000 findings under a pre-cancelled one). Now
  `--stdin` exits 3 under the flag on both of its paths and prints a one-line notice in pre-commit
  mode; `Engine.Redact` returns an error wrapping the new `redact.ErrIncomplete` and the cause, with
  the partial `Result` alongside (`Incomplete`, `IncompleteReason`, both also on `AuditRecord`);
  `RedactFile` and the new `RedactFileContext` return an error wrapping the new `scan.ErrIncomplete`
  with `RedactFileResult.Coverage` set (a pointer, so the struct stays comparable) and write no
  passthrough copy; `ScanText` and `ScanFile` return `(nil, ctx.Err())` for a context done at entry
  and the partial result with an error wrapping `ctx.Err()` when it fires mid-scan, and `ScanText`
  fills `NotExamined`; the web UI's `/scan` runs under the request's context. A fired budget is no
  longer retried as a transient fault (each re-ran every check on the file twice more: `SSN,EMAIL`
  with `SSN=1s` on records.txt cost 7.36–7.44 s CPU, now 3.22–3.29 s); the partial findings are kept
  (`SSN=1s`: 0 → 8,704–9,216 of 20,000 SSNs), scored and annotated exactly as a complete run scores
  them (each identical to its unbudgeted twin, metadata included); and a partial that arrives within
  100 ms of a caller's cancellation is collected (`Engine.Redact` on 2,000 records at a 100 ms
  deadline: 0 → 4,768 of 6,000 findings). Behaviour changes to know: library callers get an error
  where they got `(cleartext, nil)`; `examples/lambda-redact` answers `redaction incomplete` for a
  request over 5 MiB with `CLOUD_RESOURCES` enabled; budgeted runs report more findings and
  `--generate-suppressions` writes more rules; the `--stdin` warning's reason reads `coverage cut
  short: …`. Runs whose budget never fires are unchanged (golden corpus 0 files changed, `make score`
  identical).
