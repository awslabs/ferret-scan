# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<a name="unreleased"></a>
## [Unreleased]

### 🔒 Security

- **web:** bind to loopback (`127.0.0.1`) by default. Closes [TM-01](THREAT_MODEL.md). Container runtimes (Docker/Podman) auto-detected via `/.dockerenv` or `FERRET_CONTAINER_MODE=true` env var keep binding to `0.0.0.0` so port-publishing semantics work; bare-metal users get loopback-only by default. New `--bind <addr>` flag for explicit override (with stderr warning when bound to a non-loopback interface).
- **web:** add Origin/Referer validation on POST/PUT/DELETE/PATCH for `/scan` and `/suppressions/*`. Closes [TM-02](THREAT_MODEL.md). Non-browser callers (curl, scripts) that send neither header are allowed — they aren't subject to CSRF.
- **web:** emit baseline security headers on every response — `Content-Security-Policy` (`default-src 'self'` with `'unsafe-inline'` for the existing template), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Closes [TM-03](THREAT_MODEL.md). Strict CSP (no `'unsafe-inline'`) deferred pending template refactor — tracked as TM-05.
- **web:** suppression endpoints now inherit the loopback trust boundary. Closes [TM-04](THREAT_MODEL.md).

### ✨ New Features

- **cloud-resources:** new Cloud Resources Validator detects cloud provider resource identifiers across six major cloud platforms. Supported providers: AWS (ARNs with 12-digit account IDs), Azure (Resource IDs with subscription UUIDs), GCP (resource names with project IDs), OCI (OCIDs), IBM Cloud (CRNs), and Alibaba Cloud (ARNs). Key features: provider-specific metadata extraction (account ID, resource type, region), confidence scoring with contextual analysis, configurable per-provider enable/disable, and custom pattern support via configuration. New validator ID: `CLOUD_RESOURCES`.
- **stdin:** read content to scan from standard input via `--stdin` or the POSIX-style alias `--file -`. Content is treated as plain text and findings are labelled `<stdin>` (configurable via `--stdin-name`). Useful for `git diff | ferret-scan --stdin`, scanning command output, and lambda/IPC callers that already have content in memory. Mutually exclusive with `--file <path>`, positional file args, and `--web`. Max input size: 100 MB.
- **stdin redaction (streaming gateway):** combine `--stdin` with `--enable-redaction` to act as a streaming redactor — redacted content streams to stdout while findings go to stderr (or `--output <file>` if specified). All three plaintext strategies (`simple`, `format_preserving`, `synthetic`) are supported. Suppressed matches pass through unmodified. When findings stream to stderr alongside redacted content on stdout, human-readable progress lines are suppressed so the findings document remains parseable (canonical shape: `... --enable-redaction --format json 2> findings.json > clean.txt`). When stdout is a terminal (interactive use, no redirect), findings are replaced by a one-line hint pointing at the pipe shape — this matches the `git diff` / `jq` convention of adapting output to the consumer.
- **api:** new `core.ScanContent(content, ContentScanConfig)` entry point for in-process callers — scans an in-memory buffer using the same validator pipeline as `ScanFile` but bypasses the path-driven file router.
- **api:** new `plaintext.PlainTextRedactor.RedactString(content, matches, strategy)` exposes pure in-memory redaction without requiring an output manager — the same code path that drives streaming stdin redaction is now available to lambda / gateway callers.
- **api:** new `redact.ValidCheckNames()` returns the sorted validator IDs accepted in `EngineOptions.Checks`. `NewEngine` silently drops names it doesn't recognize and only errors when the resulting set is empty, so a typo in a mixed list (e.g. `{"CREDIT_CARD", "emial"}`) otherwise fails *open* — the misspelled validator is quietly disabled and that data type passes unredacted. Callers wanting fail-closed behaviour can validate their `Checks` against this list and reject unknown names before constructing the engine. The `lambda-redact` example now does exactly this at `init()`.
- **explain:** new `--explain` flag annotates each finding with a plain-language rationale, a verdict (`likely_real` / `likely_test` / `uncertain`), and a drafted suppression reason. Fully offline and deterministic — it only re-phrases signals the detection engine already computes (validation checks, vendor, context impact, file location); no network calls, no new dependencies, nothing leaves the host. Off by default. Renders in text (verbose + pre-commit), JSON/YAML (first-class `explanation` field), SARIF (result message + structured property), and gitlab-sast (description); with `--generate-suppressions`, generated rules carry the drafted per-finding reason. A HIGH-confidence finding is never glossed as `likely_test`, so the verdict can't talk a reviewer out of a real finding. New `internal/explain` package (`Explainer`, `SignalSynthesizer`).

### 🐛 Bug Fixes

- **passport:** detect standard ICAO 9303 passport MRZ lines (e.g. `P<GBRSMITH<<JOHN<<…`). The detection regexes required a letter immediately after `P` (and the TD3 pattern required three), so a real `P<`-prefixed MRZ never matched and standalone MRZ lines were missed entirely. The fix validates the embedded 3-letter issuing-state code and treats a structurally-valid MRZ as self-evident context — guarded by a structural check so long uppercase tokens (API keys, hashes) that merely start with a country-code-shaped substring are not newly false-positived.

### 🔨 Internal

- **detector:** new `Match.SourceKind` field (zero-value `SourceKindFile`) classifies match origin. `SARIF` and `gitlab-sast` formatters skip path-normalization (`%SRCROOT%`, basename rewriting) for matches with `SourceKindVirtual`. JSON serialization is omit-when-empty so existing consumers see no change.
- **parallel:** extracted shared `parallel.RunValidators(ctx, validators, content, strategy)` helper from the worker pool. Worker pool now passes a retry-backed strategy; in-memory callers pass nil for direct invocation. Same dual-path / metadata-skip behaviour preserved.

<a name="v1.7.0"></a>
## [v1.7.0] - 2026-05-08

### 🚀 Features

- **web:** drag-and-drop folders onto the upload zone — the browser walks the folder client-side via `webkitGetAsEntry`, applies any configured `--exclude` patterns during the walk, and uploads each file with its relative path so findings display as `myrepo/src/foo.go`. Single-file drops and the native picker still work; PR #52 also unifies "Choose Files" / "Choose Folder" into matching styled buttons and uses `showDirectoryPicker` where available so excluded dirs (`.git`, `node_modules`, `__pycache__`) are skipped before the browser prompts.
- **web:** wire `--config`, `--suppression-file`, and `--exclude` through web mode so the server uses the same configuration as the CLI instead of always reading `~/.ferret-scan/suppressions.yaml`. New `/config-info` endpoint surfaces configured exclude patterns to the front-end.
- **suppressions:** append `# pragma: allowlist secret` to `hash:` lines in the suppression YAML so the file itself doesn't trigger secret-scanner false positives. Idempotent on re-save.
- **web:** suppression expiration bulk operations — Make Permanent / Renew 30 Days actions on selected rules, backed by `POST /suppressions/bulk-update-expiration`.

### ⚡ Performance

- **suppressions:** `IsSuppressed` is now O(1) via a hash index rebuilt on load and on every save. Per-call microbench (no-op match against a non-matching rule set):

    | rules  | before     | after    | speedup |
    |-------:|-----------:|---------:|--------:|
    | 100    |   870 ns   |  620 ns  |   1.4×  |
    | 1,000  | 2,984 ns   |  631 ns  |   4.7×  |
    | 10,000 | 23,236 ns  |  640 ns  |  36×    |
    | 50,000 | 113,155 ns |  619 ns  | 183×    |

- **web:** cache `SuppressionManager` on the `WebServer` with mtime-based reload — eliminates the per-request YAML re-parse that previously dominated `/scan` and `/suppressions` latency. With a 5,000-rule (45k-line) suppression file across 50 sequential requests:
  - `/scan`: 68.7 ms → 28.5 ms per request (**2.4×**)
  - `/suppressions`: 67.3 ms → 29.6 ms per request (**2.3×**)

- **validators:** hoist hot-path regex compilations to package level. Per-call microbench:

    | function                      | before     | after     | speedup | allocs   |
    |-------------------------------|-----------:|----------:|--------:|---------:|
    | `containsEnhancedPhoneNumber` | 8,293 ns   | 1,057 ns  |   7.8×  | 200 → 0  |
    | `extractEmail`                | 1,653 ns   |   378 ns  |   4.4×  |  37 → 0  |
    | `containsEnhancedGPSData`     |   432 ns   |   184 ns  |   2.4×  |   8 → 0  |
    | `isVersionNumber`             | 1,562 ns   |    86 ns  |  18×    |  62 → 1  |
    | `calculateCopyrightConfidence`| 1,376 ns   |   199 ns  |   6.9×  |  35 → 0  |

  Multi-line PEM regexes (SSH/cert/PGP) in the secrets validator and the year pattern in the intellectual-property validator are now compiled once at package init instead of recompiled per call.

- **parallel:** unbounded goroutine spawn in `ResourceMonitor.notifyCallbacks` replaced with synchronous invocation; callbacks that need async work spawn their own goroutine.

### 🐛 Bug Fixes

- **suppressions:** the web flow's hash mismatch — `getString` defaulted missing finding fields to `"Unknown"`, so `mockMatch.Context.AfterText` became the literal string `"Unknown"` when re-creating from a JSON body that omitted empty fields. Returns `""` now, so suppress-then-rescan in the web UI correctly suppresses the finding.
- **web:** suppressions inside `core.ScanFile` ran against the random temp filename, then matches were renamed to the upload's display name *after*. Suppressions now apply after the rename, so cross-mode rules (CLI rule applied to web scan and vice versa) match consistently.
- **parallel:** fix goroutine leak in `AdaptiveProcessor.adaptiveScalingLoop` — `Stop()` only stopped the ticker; the loop kept blocking on a channel that would never close. Now gated on a `done` chan closed via `sync.Once`. Also fixes a pre-existing data race in `Stop()` between the scaling loop's `adjustWorkerCount` (which swaps the worker pool) and the teardown's pool stop, via `sync.WaitGroup`.
- **suppressions:** parse errors on a malformed YAML file no longer silently produce an empty rule set — a stderr warning now names the file and the underlying error so users notice that their rules aren't being applied. Missing-file remains silent (the legitimate first-run case).
- **suppressions:** `RWMutex` around the new hash index makes `IsSuppressed` safe for concurrent use; previously the manager had no synchronization around shared state.
- **resilience:** `RetryWithBackoff` now treats `MaxInterval=0` as "no cap" instead of clamping every delay to zero, fixing a long-standing flake in `TestRetryWithBackoff_ContextCancellation`. Test rewritten to be deterministic.
- **preprocessors:** `readTextFile` now opens the file once instead of twice — closes the TOCTOU window between the size check and the read.

### 📦 Code Refactoring

- **web:** dedup 12 near-identical suppression HTTP handlers into a shared `suppressionEndpoint` wrapper plus typed `suppressionRequest` struct. `internal/web/server.go` shrank from 1,350 to 1,183 LOC (−167, −12%).
- **web:** delete unused `normalizePathForWeb` (strict subset of the live `sanitizeFilenameForDisplay`; zero callers since the initial commit).
- **parallel:** simplify `WorkerPool.Submit` — the `default` arm fell into an inner `select` identical to the outer one and had no behavioral effect.

### ✅ Tests

- new cross-platform GitHub Actions workflow `.github/workflows/go-test.yml` runs `go test -race -count=1 ./...` on `ubuntu-latest`, `macos-latest`, and `windows-latest`. Previously the repo had no Go unit-test workflow at all (only a secret-scanning workflow and a build-binary workflow). `tests/integration` is excluded from the test step (Windows-only files have separate pre-existing bugs); `vet` and `build` still cover them.
- restore `tests/helpers` package (was imported by `tests/integration/windows_*_test.go` but never committed).
- new tests: multi-line PEM detection covering 8 PEM types end-to-end, concurrent `IsSuppressed` under `-race`, `AdaptiveProcessor.Stop` goroutine-exit verification.
- track two validator test files (`internal/validators/email/validator_test.go`, `internal/validators/intellectualproperty/validator_test.go`, ~850 LOC combined) that the prior `*_test.go` ignore rule had been silently dropping from version control.
- `make test` targets repointed from the non-existent `./tests/unit/...` to `./internal/...`.

### 🛠 Build System

- bump GitHub Actions to versions running on Node 24 across all workflows: `actions/checkout@v6`, `actions/setup-go@v6`, `actions/cache@v5`, `actions/setup-python@v6`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, `actions/github-script@v9`. GitHub is removing Node 20 from runners on 2026-09-16.
- remove `*_test.go` and `tests/` patterns from `.gitignore` — they had been silently dropping every Go test file from version control; existing tests survived only via `git add -f`.

### Pull Requests

- Merge pull request [#52](https://github.com/awslabs/ferret-scan/pull/52) from awslabs/feature/web-enhancements
- Merge pull request [#51](https://github.com/awslabs/ferret-scan/pull/51) from awslabs/dev/web-server-caching
- Merge pull request [#50](https://github.com/awslabs/ferret-scan/pull/50) from awslabs/dev/perf-and-cleanup
- Merge pull request [#48](https://github.com/awslabs/ferret-scan/pull/48) from awslabs/dev/web-folder-scan-and-suppression-fixes

<a name="v1.5.2"></a>
## [v1.5.2] - 2026-02-18

### 🐛 Bug Fixes

- **pdf:** recover from PDF library panics on corrupted files — `zlib: invalid header`
  errors in `ledongthuc/pdf` now return a graceful error instead of crashing the scan.
  Two-layer fix: `ExtractText()` catches panics via defer/recover, and the file router
  goroutines also wrap preprocessor calls in a recover as a safety net.

<a name="v1.5.1"></a>
## [v1.5.1] - 2026-02-18

### 🐛 Bug Fixes

- **pre-commit:** fix hook failing with "Executable not found" after pre-built binaries
  were removed from the repository. Switched from `language:script` to `language:python`
  so pre-commit automatically installs ferret-scan from PyPI into an isolated virtualenv.
  Also bumped hook rev from v1.3.29 to v1.5.0 and added `pyproject.toml` stub.

<a name="v1.5.0"></a>
## [v1.5.0] - 2026-02-18

### 🐛 Bug Fixes

- **redaction:** fix synthetic strategy silently skipping SECRETS, PASSPORT, SOCIAL_MEDIA, and INTELLECTUAL_PROPERTY — added type-aware generators for all four types
- **redaction:** fix synthetic person name generation producing random character strings — now draws from embedded name databases (~5200 first names, ~2100 last names)
- **redaction:** fix PDF and Office redactors using their own duplicate replacement logic instead of the shared implementation

### 📦 Code Refactoring

- **redaction:** extract ~600 lines of duplicated replacement generation code into shared package `internal/redactors/replacement` — each redactor's `generateReplacement()` is now a one-liner
- reduce duplication across scanner, suppress count fix, exponential retry backoff, 47 new tests

### 🚀 Features

- **person-name:** expand name database coverage with 53 unambiguous names from South Asian, West African, Eastern European, Middle Eastern, Japanese, and Italian backgrounds

### 📚 Documentation

- add `docs/user-guides/README-Redaction.md` — comprehensive guide covering all three strategies, validator×strategy support table, document type support, synthetic token formats, and config reference

### 🛠 Build System

- remove pre-built platform binaries from repository and git history (repo size: ~200MB → 2.2MB)
- simplify `.gitignore` to ignore entire `bin/` directory
- remove platform dispatcher shell script — `make build` outputs directly to `bin/ferret-scan`
- fix git-chglog `repository_url` pointing to internal CodeCommit instead of GitHub

### Pull Requests

- Merge pull request [#38](https://github.com/awslabs/ferret-scan/issues/38) from awslabs/refactor/code-quality-improvements
- Merge pull request [#37](https://github.com/awslabs/ferret-scan/issues/37) from awslabs/dev/fabio-dev

<a name="v1.4.0"></a>
## [v1.4.0] - 2026-01-13

### 🚀 Features

- add `--exclude` flag for file and directory exclusion with glob pattern support

### Pull Requests

- Merge pull request [#36](https://github.com/awslabs/ferret-scan/issues/36) from awslabs/dev/fabio-dev
