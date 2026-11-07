<!--
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Surface parity: the web UI and the container held to the CLI's contract

ferret-scan ships three ways to run it: the CLI, the web UI (`--web`) and the container image, which
offers both of those in another runtime. [TEST_PLAN.md](TEST_PLAN.md) holds every change to its
dimensions, but until [#907](https://github.com/awslabs/ferret-scan/issues/907) nothing asserted that
a file posted to `/scan`, or scanned inside the image, yields what the CLI yields. Four instruments
make that assertion mechanical. Three run in `go test ./...` on every pull request; the fourth needs a
container runtime and minutes, so it runs locally before a batch lands, and in CI after the image
smoke build when the Dockerfile changes.

| Instrument | File | Runs in | What it proves |
|---|---|---|---|
| A. web scan parity | `internal/web/surface_parity_test.go` | `go test ./...` | every golden-corpus input gives the same findings through `/scan` as through the corpus's own scan |
| B. export and menu parity | `internal/web/export_parity_test.go` | `go test ./...` | `/export` equals the CLI formatter for the same findings in every format; the export menu equals `formatters.List()` |
| C. capability inventory | `internal/web/surface_inventory_test.go` | `go test ./...` | every CLI flag, read from the built binary, has exactly one recorded web decision |
| D. four-surface gate | `scripts/surface-parity.sh`, `make surface-parity` | locally; `docker-multiarch.yml` | host CLI, host web, container CLI and container web agree on the same inputs; the container's redaction and runtime hold |

## A. Web scan parity

`TestWebScanMatchesCorpusScan` takes every case in `goldencorpus.Cases` and `goldencorpus.FileCases`
and scans the same bytes twice:

1. the way the corpus does: `core.ScanContent` with the virtual path `<golden:NAME>` for a `Case`,
   `core.ScanFile` on a written fixture with the case's preprocessor setting and budgets for a
   `FileCase`, both with the case's checks;
2. through `/scan`, against a `WebServer` built the way `ferret-scan --web --config <empty file>`
   builds one (strict-loaded config, routes behind the security middleware), served in-process by
   `httptest`. The file is posted as multipart `files` with `relative_path`, `checks` set to the case's
   checks, `confidence=all`, `verbose=false` and `recursive=false`, as `app.js` posts it.

The two finding sets are compared as sorted tuples of type, line, SHA-256 of the matched value and
confidence, plus band counts (high, medium, low, suppressed; `/scan` returns no `stats` object, so the
counts are derived from the findings on both sides with the formatter's own band function) and the
`Incomplete` flag. A difference fails naming the case, the type and both sides, and the value is
printed as a hash, never as text.

Measured on `main` at `5fecf59`: 97 cases, 94 identical, 3 differing only in `Incomplete`. Those three
(`file_docx_cut_short_without_metadata`, `file_docx_cut_short_with_metadata`,
`file_txt_cut_short_twin`) scan with a 1 ns PHONE budget, the corpus's stand-in for
`--validator-budget`, which `/scan` does not take. They are the three entries in `webSurfaceAllowed`.

### Adding a `webSurfaceAllowed` entry

The map is keyed by case name (every difference in the case) or `case/TYPE` (that type only;
`<incomplete>` and `<stats>` name the scan-level fields). The value is the mechanism, read in the code
and named by function, and an issue reference. "Differs today" is not a reason. Before adding one, ask
whether the difference is a bug in `/scan`: if the CLI reports a finding and the web does not, the
web is leaking, and the entry is the record of a known leak with the issue that will close it.
`TestWebSurfaceAllowlistIsLive` fails for an entry whose case no longer differs.

## B. Export and menu parity

`TestWebUI_ExportOptionsMatchFormatterRegistry` reads the `<option value>` list under
`<select id="exportFormat">` in the embedded template and requires it to equal `formatters.List()`,
naming the missing or extra format. Today both hold the seven formats.

`TestWebExportMatchesCLIFormatter` takes a fixed set of real findings (the golden fixtures
`file_txt_mixed_pii` and `file_docx_body_and_metadata`, scanned and then given what `runFullCLIScan`
gives every web finding: the upload name and an explanation), renders them as `/scan` delivers them to
the browser, posts that JSON to `/export` for every format under all four combinations of
`show_match` and `verbose`, and compares each body byte for byte with `formatters.Export` for the same
findings and handleExport's `FormatterOptions`. Stripped before comparing: gitlab-sast's
`scan.start_time` and `scan.end_time`, JUnit `time="…"` durations and the INTELLECTUAL_PROPERTY
`reconstruction_timestamp` value, plus JSON key order.

The comparison found that `/export` cannot reproduce three parts of a finding, because it rebuilds
each `detector.Match` from the JSON the browser posts back. They are recorded in `exportLosses`, each
stripped from the CLI side so every other difference still fails, and `TestWebExportLossesAreLive`
measures each one:

| Loss | Mechanism | Bodies it changes (of 28) |
|---|---|---|
| explanation | `/scan` sends the explanation as `JSONMatch.Explanation`; `handleExport` copies Text, LineNumber, Type, Confidence, Filename, Validator, Metadata and three context strings only | 18: json, yaml, sarif and gitlab-sast under every switch |
| context-keywords | `JSONMatch` carries `full_line`, `before_text` and `after_text` of `ContextInfo`; `PositiveKeywords`, `NegativeKeywords` and `ConfidenceImpact` are lost, and SARIF's verbose message renders the first as "Positive indicators" | 6 |
| metadata-types | metadata crosses as JSON, so `validation_checks` leaves as `map[string]bool` and returns as `map[string]any`; the text formatter's type assertion then skips its verbose "Validation results" block | 2 |

Fixing them belongs in `handleExport` (and possibly `JSONMatch`); when one is fixed, its liveness test
fails and the entry goes.

## C. Capability inventory

`TestCLIFlagsHaveAWebDecision` builds `./cmd` once per test binary and runs it with an undefined flag,
which makes Go's `flag` package print `flag.PrintDefaults`: every registered flag. `--help` is not
used, because it is hand-written prose (`internal/help`) and omits registered flags (`--bind`,
`--show-suppressed`, `-p`). The 41 flags are then partitioned across three tables in the test file:

- `webEquivalent`: the flag and how the web exposes it (15 today: `checks`, `confidence`, `verbose`,
  `recursive`, `format`, `show-match`, `suppression-file`, `config`, `exclude`, `explain`,
  `enable-preprocessors`, `show-suppressed`, `generate-suppressions`, `suppression-expires`,
  `version`);
- `webDeliberatelyAbsent`: the flag and the mechanism that makes it a CLI-only concern (18 today);
  most reasons are the troubleshooting lines `validateWebModeFlags` in `cmd/main.go` already prints
  when it refuses the flag with `--web`;
- `webUndecided`: the flag and the issue asking for a decision (8 today: `debug`, `disable-ip-types`,
  `limit`, `list-profiles`, `max-live-bytes`, `profile`, `respect-gitignore`, `validator-budget`).

The test fails for a flag in no table, a flag in two tables, an entry naming a flag the binary no
longer has, an empty reason, and an undecided value that is not an issue reference. A new CLI flag
therefore cannot land without someone writing down what the web does about it.

### Moving a flag between tables

Moving a flag out of `webUndecided` is a maintainer's decision. Make it in the pull request that
implements it (the web gains the capability: `webEquivalent`, naming the form field or endpoint) or
documents it (the web will not have it: `webDeliberatelyAbsent`, naming the mechanism, and ideally a
refusal in `validateWebModeFlags` so `--web --flag` says so instead of silently ignoring it, which is
what `--profile`, `--disable-ip-types`, `--respect-gitignore` and `--debug` do today).

## D. The four-surface gate

```bash
make surface-parity
make surface-parity CORPUS=/path/to/documents
scripts/surface-parity.sh --surfaces host --keep
scripts/surface-parity.sh --image ferret-scan:smoke --surfaces container
```

The script builds the host binary from the checkout (stamped with `VERSION` and `GIT_COMMIT`), builds
the image `ferret-scan:surface-parity` from the same checkout unless `--image` names one, writes the
golden-corpus inputs to a temporary directory with
`GOLDEN_DUMP_DIR=<dir> go test -count=1 -run '^TestDumpInputs$' ./internal/goldencorpus/`
(`make surface-parity-inputs SURFACE_PARITY_INPUTS=<dir>` does only that), and runs every input set
through the four surfaces:

| # | Surface | How |
|---|---|---|
| 1 | `cli` | the host binary, one `--file <set> --recursive` run |
| 2 | `web` | the host binary's `--web --bind 127.0.0.1 --port <free port>`; one `/scan` per file, then `/export` of the results in every format the server lists |
| 3 | `container-cli` | `docker create` the image with the same arguments against `/home/ferret/in`, `docker cp` the set in as a tar stream, `docker start -a`; no bind mount, no `-p`, so the result does not depend on the host's uid |
| 4 | `container-web` | `docker run -d -p 127.0.0.1:<free port>:8080 <image> --web --port 8080`; the same requests as surface 2 |

Every surface runs with `--config /dev/null --confidence all --limit 0 --format json --show-match`,
every check, preprocessors on (the default), and a suppression file that does not exist, so no user
configuration and no suppression rule reaches any of them.

| Flag or variable | Meaning |
|---|---|
| `--image REF` | use a prebuilt image; set `VERSION` and `GIT_COMMIT` to what it was built with |
| `--surfaces LIST` | `cli`, `web`, `container-cli`, `container-web`, or `host` (1, 2), `container` (3, 4), `all` (default) |
| `--include-private` | also scan `$CORPUS/private/`, printing aggregates only: counts by type and timings, never a file name, a path below `private/` or a matched value |
| `--keep` | keep the work directory with every raw and normalised output, and print its path |
| `--print-state` | print the checkout state a green run records (used by `pr-checklist.sh`) |
| `CORPUS=DIR` | also run every file under `DIR`; `DIR/private/` is skipped unless `--include-private` |
| `CONTAINER_CMD` | `docker` (default) or `finch` |
| `VERSION`, `GIT_COMMIT` | stamped into the host binary and the image; default `git describe --tags --always` and `git rev-parse --short HEAD` |

### What it asserts

- **1 == 3** and **2 == 4**, byte for byte after normalisation. Normalised, and nothing else: every
  path loses the set's root (the host directory, `/home/ferret/in`), so it is relative to the set;
  `stats.duration_seconds` is dropped; results are sorted by file, line, type, text and confidence
  (the CLI emits them in completion order within a band, which is not an output contract). `/scan`
  responses carry no clock or version field and are compared whole. `/export` bodies are compared
  after the export normalisation of instrument B; `/health` on `status`, `service`, `version` and
  `commit`; the security headers whole.
- **1 vs 2**, and 3 vs 4: the same finding sets, keyed by relative path, type, line, confidence and
  the value's SHA-256, plus the count of files not examined, except entries in
  `scripts/surface-parity/allowlist.tsv`. A finding inside an embedded attachment is named
  `<container> -> <member>` by the CLI and by the upload alone on `/scan` (`runFullCLIScan` sets
  every Filename to the upload name), so it is compared under its container's path, and the report
  prints how many were moved.
- **Redaction inside the container**: for every set, `--enable-redaction` under `simple` and
  `format_preserving` into `/tmp/out` and `/home/ferret/out`, plus one run into the image's `TMPDIR`.
  Every value surface 1 reported is looked for in its file's redacted copy, as written, XML-escaped
  and as UTF-16LE, inside every part of an OOXML container; values under 4 bytes are counted and
  skipped. A surviving value fails, and so does a file with findings that has neither a copy nor an
  entry in the run's own `unredacted` disclosure. A disclosed refusal is counted, not failed.
- **Runtime facts**: the container's `--version` equals the host binary's on version and commit
  (`built:`, `go:` and `platform:` are recorded, not compared: the host binary has no build date and
  may target another OS); the image's `USER` resolves to a non-zero uid in its `/etc/passwd`; a
  write into its `TMPDIR` succeeds; `/health` reports `VERSION` on both web surfaces; the CSP's
  `script-src` is `'self'` (TM-05) and `X-Frame-Options`, `X-Content-Type-Options` and
  `Referrer-Policy` are present (TM-03); `style-src` is recorded (TM-06 is open).
- **Network exposure**: after each start, `ss -ltn` (or `lsof` where `ss` is absent) on the port must
  show only `127.0.0.1:`, and `docker port` must map only to `127.0.0.1:`. The script refuses to run
  a publish whose host side is not `127.0.0.1`. Inside the container the server binds `0.0.0.0`
  (`FERRET_CONTAINER_MODE=true`); the loopback publish is the boundary.
- **Timing**: wall clock per surface, per-file p50 and max for the web surfaces (one request per
  file), and the container/host ratio. A ratio above 2.0 prints a WARNING; it does not fail.

It exits 1 on any unexplained difference, surviving value, failed fact or non-loopback listener, and
2 on a usage or setup error.

### What a real-file corpus showed

On 2026-11-07, `CORPUS=<644 public documents> scripts/surface-parity.sh --surfaces host` (the CLI
against the web UI, on the code at `5fecf59`): 643 of the 644 uploads gave the CLI's findings exactly
(13,915), and 90 of them sat inside embedded attachments. The 644th, a 7.5 MB CSV in which the CLI
reports 2,203 findings in 20 s, got an empty reply from `/scan` while the host was loaded: the server's
`WriteTimeout` is 30 s (`createSecureServer`), so a scan that outlasts it loses its response, and its
findings with it. The same file twice over (15 MB, under the 100 MB upload limit) reproduces it on an
idle server: the CLI reports 4,406 findings in 41.8 s, `/scan` answers nothing after 46 s. The
not-examined counts also differed, 52 on the CLI and 49 on the web, and the web gave no cause for 12
of its 49 where the CLI's summary counts 15 files it could not parse.

### Reading the output

The report prints the runtime facts, then per input set a table (files, findings by band, files not
examined, exit status, wall clock, per-file p50 and max), the comparisons, the export, redaction and
timing lines, then the allowlist in effect and the verdict. A difference between 1 and 3 or 2 and 4
prints the first differing lines of the two normalised documents; with `--keep` they are under
`raw/<set>/` in the work directory. A finding difference prints
`only-cli` or `only-web`, the relative path, the type, the line, the confidence and the value's hash.
For the private set only counts are printed.

### Adding an allowlist entry

`scripts/surface-parity/allowlist.tsv` takes `pair<TAB>pattern<TAB>reason`. The only pair is `cli-web`
(it covers 1 vs 2 and 3 vs 4; 1 == 3 and 2 == 4 cannot be allowlisted). The pattern is a Go regular
expression matched against `path<TAB>type<TAB>line<TAB>confidence`, with the tab written as the
escape `\t` (a literal tab ends the field). The reason names the mechanism and
an issue (`#NNN`); an entry without an issue reference is refused. The report prints every entry with
how many differences it absorbed. It is empty: on the golden inputs the CLI and the web agree.

### The pr-checklist line

A green run of all four surfaces writes `$(git rev-parse --git-dir)/surface-parity.ok` with the
checkout's content as a tree object (tracked and untracked files, ignored files excluded, computed
with a private index). `scripts/pr-checklist.sh` prints `14 surfaces (web+container)` as RAN when that
tree is the current checkout's, NEEDS-MANUAL when anything other than docs and tests changed, and N/A
only for a diff of docs and tests alone. Committing what was tested keeps the marker valid; any edit
invalidates it; a failed or partial run removes it.

## Proposed TEST_PLAN.md text

This section is the text proposed for `docs/testing/TEST_PLAN.md`, to paste after dimension 13 and
into the Applicability section; it is not part of the plan until it is pasted there.

```markdown
### 14. Surfaces: web UI and container (always)

The web UI and the container image run the same scanner as the CLI, and users meet them as
products of their own. `/scan` and `/export` consume every validator, formatter, suppression and
config change, so "when affected" no longer applies to the web: a change that never touches
`internal/web/` changes what the web reports. The container runs the same binary in another runtime
(`FROM scratch`, `USER ferret`, `TMPDIR=/home/ferret/tmp`, `FERRET_CONTAINER_MODE=true`, no shell,
no CA bundle); #776 shipped an image in which every redaction panicked while `--version` passed.

- `go test ./internal/web/` runs on every PR and holds the web to the corpus: every golden case
  through `/scan` (`TestWebScanMatchesCorpusScan`), `/export` against the CLI formatter for every
  format (`TestWebExportMatchesCLIFormatter`), the export menu against `formatters.List()`, and every
  CLI flag against a recorded web decision (`TestCLIFlagsHaveAWebDecision`). A new flag needs an
  entry in `webEquivalent`, `webDeliberatelyAbsent` or `webUndecided`; a new allowlist entry needs
  the mechanism and an issue.
- `make surface-parity` before a change lands whenever production code, the Dockerfile or a
  formatter changed: the same inputs through the host CLI, the host web UI on 127.0.0.1, the
  container CLI and the container web UI published on 127.0.0.1 only. Quote its per-surface table
  in the PR. Add `CORPUS=<dir>` when the change concerns a document type the golden corpus lacks.
- Never test the web or the container on anything but loopback: `--bind 127.0.0.1` on the host,
  `-p 127.0.0.1:<port>:8080` for the image, verified with `ss -ltn` and `docker port`.
- `scripts/pr-checklist.sh` prints this line as RAN only after a green four-surface run on the same
  checkout; it is never N/A for a production change.
```

Proposed Applicability table, with the column added (the rows are the plan's own):

```markdown
| Change kind | Always | Add | Surfaces (14) |
|---|---|---|---|
| Validator confidence / keyword logic | 1,2,3,5,6,9,10 | 4 if loops over line/match; 11 if ranking | always |
| Extraction / preprocessing | 1,2,4,5,9,11,12 | 3 only if corpus has that format; 13 if concurrent | always |
| Formatter / output schema | 1,2,3,7 | 8 if web-facing | always |
| Web / template / assets | 1,2,7,8 | — | always |
| Dockerfile / container scripts | 1 | — | always |
| Dead-code removal | 1,2,3,10 | (lands alone) | always |
| Pure docs | 1 | — | N/A |
```

## Follow-ups

- Paste the proposed text above into `docs/testing/TEST_PLAN.md` (owned by the docs stream this wave).
- The three `exportLosses` are web divergences to fix in `handleExport`.
- `/export` refuses a body over 1 MiB, and the UI posts every result in one request: measured, 391
  golden findings (572,492 bytes) export and 782 (1,144,919 bytes) are refused with HTTP 400.
- `/scan` loses the response of any scan longer than the server's 30 s `WriteTimeout` (above).
- `/scan` names a finding inside an embedded attachment by the upload alone, so the UI cannot say
  which attachment held it.
- The eight `webUndecided` flags need a decision each.
