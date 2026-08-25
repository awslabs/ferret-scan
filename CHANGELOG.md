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
- **api (pkg/scan):** `TextOptions`, `FileOptions` and `RedactFileOptions` gain `ConfigPath string` and `DisableConfigDiscovery bool`, so an embedded consumer can pin the config or opt out of ambient discovery entirely. Previously all three called `config.LoadConfigOrDefault("")` unconditionally with no config field on the options structs, so detection depended on the calling process's **working directory** with no way to pin it, no way to request built-in defaults, and no way to write a hermetic test. Verified with an identical `ScanText` call differing only in CWD: `findings=1` from one directory, `findings=0` from another holding a `.ferret-scan.yaml` with `disabled_types`. Same shape as the `redact.ValidCheckNames()`/`SOCIAL_MEDIA` case — a successful call, an empty finding list, input treated as clean — except the cause was ambient rather than in the caller's arguments, so the caller could neither detect nor prevent it. Both fields default to zero, so **existing callers are unaffected**: an empty `ConfigPath` keeps the historical discovery behaviour. `DisableConfigDiscovery` takes precedence when both are set, being the stricter request.

### 🐛 Bug Fixes

- **audio:** clamp a declared box/block length to the bytes the file actually holds before allocating. Every length in these containers is read out of the file, so it is producer-chosen, and the only previous guard on the `.m4a` `mvhd` size was a floor (`size < 24`) — a **52-byte** `.m4a` declaring `0xFFFFFFFF` allocated 4096MB, and an **8-byte** `.flac` whose first metadata block declared `0xFFFFFF` allocated 16MB. End to end, a directory of six such `.m4a` files plus one real recording (220KB of input) reached 4.03GB of peak RSS in 2.57s; now 0.03GB in 0.74s. Note for anyone reproducing this class: a SINGLE bomb shows almost nothing, because Go does not zero a span taken fresh from the OS, so 4GB is reserved and never written — the pages only become resident once the runtime reuses a dirty span and must zero it. Also fixes a correctness defect in the same code: the buffer was sized to the declaration and a short read tolerated, so an `mvhd` claiming more than the file holds parsed its zeroed tail as a real creation date and duration. Field access is now bounded by the bytes actually read. Verified on 600 real audio files (548 `.m4a`, 50 `.wav`, 2 `.mp3`): report output byte-identical, 17 findings, 0 empty outputs. Closes [#457](https://github.com/awslabs/ferret-scan/issues/457).

- **memory:** findings no longer pin the whole extracted buffer of the file they came from. Every string on a finding (`Text`, and the `FullLine`/`BeforeText`/`AfterText` context windows, plus content-derived metadata) was a Go substring of the file's entire extracted content, and a substring retains its parent's whole backing array — so one 16-byte finding kept that file's buffer alive until the process exited. `detector.DetachMatches`, called once at the scan convergence in `parallel.RunValidators`, replaces those strings with copies that share one allocation per line. Measured on 64 files of 2 MB with one EMAIL each (128 MB of input, 64 findings): peak RSS **248 MB → 109-146 MB**, which is the same band as scanning the identical bytes with **zero** findings (115-142 MB) — i.e. a scan that finds things now costs what a scan that finds nothing costs. Reported values are unchanged (byte-identical golden corpus, and suppression hashes are computed over values, so saved user rules keep matching). Two things this deliberately does not do: a document that is a single long line is left aliased, because there the copy would be as large as the buffer it frees; and it does not bound memory by finding COUNT, which is a separate retention term ([#337](https://github.com/awslabs/ferret-scan/issues/337) mechanism 2) in different files.

- **cli:** name a config file discovered in the working directory. `FindConfigFile` searches the current directory before the user config dir, so a `config.yaml` or `.ferret-scan.yaml` sitting beside the scanned content wins — and such a config can switch off whole detection categories via `validators.<name>.disabled_types`. Measured: the same binary, flags and input went from 1 finding to 0 because of a file dropped next to the content, with **nothing in the output naming it**. One stderr note (`Note: using project config .ferret-scan.yaml found in the working directory; it can disable detection types.`) now makes the substitution visible. Deliberately quiet for an explicit `--config <path>` (the user chose it) and for a config in the user config dir (a standing preference), because a line on every run trains people to ignore it. Not gated on `--quiet`: that suppresses progress output, whereas which config governed the run is a disclosure, and in CI it matters more. New `config.Config.SourcePath` records the provenance and carries `yaml:"-"` so a config file cannot claim an origin it does not have. This does **not** close the underlying trust-boundary question — whether a config discovered inside the scan target should require opt-in — which is a threat-model decision tracked in #293.
- **audio/video:** redact the XMP packet in MP4/M4A/MOV containers, not just the QuickTime/iTunes atoms. A metadata editor writes the same tag into two homes: measured on a real `.m4a` stripped with `exiftool -all=` and then given one tag, `Artist`, `Title` and `Author` each land in BOTH `moov/udta/meta/ilst` and an XMP packet, while `Comment` lands only in `udta`. The XMP copy was never mapped, so after the whole-file verify added in #451 those files were REFUSED outright — honest, but it made three of the four common tags unredactable. Now: refused -> written with zero residual, file size unchanged, `ffprobe` duration identical, and the packet still parses as XML. The packet is matched on the Adobe **user type** of its `uuid` box rather than on the box type, because `uuid` is the container format's extension point and also carries vendor and protection payloads a redactor must not rewrite; the 16-byte user type is deliberately left OUTSIDE the mapped span, so a same-length overwrite can never leave a `uuid` box that no longer identifies itself as XMP. Verified across 800 real ISO-BMFF files (726 `.m4a`, 50 `.mov`, 24 `.mp4`): 24 carry a top-level XMP `uuid` box, 14 carry `moov/udta/XMP_` which was already covered because `udta` is treated as one region, scan output byte-identical on all 800, and redaction output unchanged on every file that was already redactable. Mapping the packet also required closing a smaller leak standing behind it: a value in XML may be ENTITY-ENCODED (exiftool writes an apostrophe as `&#39;`), so the raw-byte write gate cannot see it. Before the packet was mapped, an unescaped copy of some OTHER value in it refused the whole file and incidentally protected the encoded one; overwriting that copy removed the refusal, and a `.m4a` tagged `Patrick O'Connor` was written at exit 0 with `Patrick O&#39;Connor` still in the packet — exiftool read the name back out of the "redacted" file. Both the audio and video write gates now also check for an entity-encoded survivor and refuse with that cause named. Refusing rather than masking, because masking an encoded occurrence needs an offset-mapping decoder; this is never worse than the behaviour it replaced, since such a file was refused before too. Enumerating escaped spellings would not work — XML allows `&apos;`, `&#39;`, `&#x27;`, `&#039;` and so on without limit — so the check DECODES instead, resolving exactly XML 1.0's five predefined entities plus numeric character references and leaving HTML-only names such as `&sect;` alone. Separately, the coordinate scrub reaches XML now that the packet is a region: it filled an ISO 6709 string with NUL, which XML 1.0 forbids outright, so a position inside an `exif:GPSLocation` element is masked with `*` instead — the position is still removed, and the packet still parses. Closes [#452](https://github.com/awslabs/ferret-scan/issues/452).
- **formatters (breaking, json/yaml shape):** `json` and `yaml` now always emit an object with a `stats` block, so the coverage disclosure is present on the report that reads as a clean bill of health. Both formatters returned early on an empty result list and emitted a bare `[]` / `results: []`, bypassing the only code path that attaches `stats` — and with it `files_not_examined`. The disclosure was therefore present exactly when there were findings and absent exactly when there were none. Measured on a directory of two unreadable files: `text` printed `NOT FULLY EXAMINED: 2 of 2 files` (728 bytes) while `json` printed `[]` (2 bytes) at exit 0. `stats.files_not_examined` exists so a machine consumer can tell an unexamined file from a clean one, and the sarif/gitlab-sast/junit work assumed json and yaml already disclosed. **Breaking:** a zero-finding scan changes from `[]` to `{"stats":{…},"results":[]}` in json and gains a `stats:` block in yaml, so a consumer that assumed a bare top-level array must be updated. This also *fixes* a shape bug in the same stroke — the top-level type used to flip between array (zero findings) and object (with findings), so a typed consumer that worked on a dirty scan failed on a clean one with `cannot unmarshal array into Go value of type struct`; it is now always an object. `--precommit` output is unchanged and still silent on a clean run. Five zero-finding golden files were regenerated (`[]` → `{"results": []}`); no other golden moved.
- **formatters (breaking, yaml keys):** `ScanStats` fields now carry `yaml` tags matching their `json` ones, so the yaml report spells them `total_files`, `files_processed` and `files_not_examined` instead of `totalfiles`, `filesprocessed` and `filesnotexamined`. `ScanStats` had only `json` tags, so `yaml.v3` fell back to the lower-cased Go field name: a consumer written against the documented JSON schema found nothing under `files_not_examined` while a differently-spelled key sat beside it reading zero — worse than the field being absent, because it looked present. The missing tag also dropped `omitempty`, so yaml emitted `files_not_examined: 0` where json omitted it; that is now consistent too.
- **images:** read PNG text chunks, and stop treating a missing EXIF block as an absence of metadata. A PNG keeps its descriptive text in `tEXt`/`zTXt`/`iTXt` chunks and normally has no EXIF at all, so a 210-byte PNG with an SSN in `tEXt`, a phone in `iTXt` and a card in a COMPRESSED `zTXt` reported **0 findings at exit 0** while exiftool read all three; it now reports SSN, PHONE and VISA. The compressed one is the case that shows why this needed a chunk reader rather than another byte scan — the value is not in the file's bytes at all. Separately and more widely, `ExtractExif` returned the moment `exif.Decode` failed, which made the four raw scans below it unreachable for ANY image without EXIF: a 426-byte JPEG carrying only an XMP packet reported 0 findings while the already-present `extractXMP`, called directly on the same bytes, returned the value. That code existed and simply never ran. A decode failure is now recorded rather than fatal, and the original error is still returned when nothing else found anything — so a genuinely empty or invalid file behaves exactly as before. Bounds, because a chunk length is a producer-chosen `uint32` and `zTXt` is deflated: the declared length is clamped to the bytes actually present, and recovered text is capped at 1MB per chunk and 4MB per image. Measured, a 509KB PNG can declare a `zTXt` that inflates to 512MB — 1029x, near zlib's ceiling. The JFIF comment scan is now confined to JPEG, which is a false-positive fix rather than a restriction: it matches the 2-byte marker `FF FE` and then TRUSTS the 2-byte length behind it, so a chance hit in compressed data yields a large payload rather than nothing. Measured on a 51,700-byte macOS icon it emitted 51KB of pixel data as a comment tag and the validators reported `TWITTER` at confidence **100** three times from handles present nowhere in the image. `extractIPTC` shares the 2-byte-marker shape and is deliberately NOT gated: gating it too was a first attempt that cost real recall — across a 4,000-file real-image sample it lost 41 TIFF findings, 40 being false positives worth losing and one being genuine (exiftool reports By-line `Jonathan Hess` on an Xcode `.tiff` that this tool reported at PERSON_NAME 92). Unlike the JFIF scan, IPTC validates what it matches — the record type must be one of four values and the payload printable — so marker length alone was the wrong discriminator; what the scan does after matching is. Verified on a 4,000-file random sample of 28,619 real images under `/System`, `/Library` and `/Applications`: findings 462 -> 1,375, and **HIGH-band findings went DOWN, 120 -> 92** — the gate removes 35 pre-existing false positives (2-character `@xx` handles and IPv6-looking fragments read out of TIFF pixel data) while adding 4 real ones. The 35 lost findings are all false positives and **no real value was lost**. The new HIGH findings are genuine and reachable by nothing before: a live `gehiere@apple.com` and `(c) 2010 Apple, Inc. Internal` in the 18,684-byte XMP packet of a PNG shipped inside Numbers.app. An earlier draft of this entry said findings were "all in the LOW band, none HIGH or MEDIUM"; that was an artefact of capping the corpus at 1,200 files, which excluded every file carrying a real XMP packet. Closes [#456](https://github.com/awslabs/ferret-scan/issues/456).
- **passport:** detect standard ICAO 9303 passport MRZ lines (e.g. `P<GBRSMITH<<JOHN<<…`). The detection regexes required a letter immediately after `P` (and the TD3 pattern required three), so a real `P<`-prefixed MRZ never matched and standalone MRZ lines were missed entirely. The fix validates the embedded 3-letter issuing-state code and treats a structurally-valid MRZ as self-evident context — guarded by a structural check so long uppercase tokens (API keys, hashes) that merely start with a country-code-shaped substring are not newly false-positived.
- **api (breaking, minor):** `redact.ValidCheckNames()` no longer advertises `SOCIAL_MEDIA` (18 → 17 names), and `redact.NewEngine(EngineOptions{Checks: []string{"SOCIAL_MEDIA"}})` now returns a `"no validators enabled"` error instead of a live engine. The SOCIAL_MEDIA validator ships no built-in patterns — its only pattern source is `validators.social_media.platform_patterns` in a config file, and `NewEngine` deliberately builds with a nil config — so it could never produce a finding on this in-memory path. A caller selecting it got a successful call, an empty finding list, and the input returned verbatim: a redaction library reporting success on cleartext, indistinguishable from clean input. `METADATA` already failed closed for the analogous reason (needs filesystem access); this makes the two consistent. Callers who need social-media detection should use `pkg/scan`, which loads project config. The CLI's `--checks SOCIAL_MEDIA` and config-file `checks:` values are unaffected — those come from `core.CheckNames()`. A new test drives a positive fixture through `Engine.Redact` for every advertised name and asserts both that a finding is produced and that the output changed, so the list cannot silently start lying again.

- **metadata:** a sensitivity marking carrying harmless decoration no longer scores HIGH. `Confidential - Draft`, `Confidential FY25`, `Confidential (Rev 3)` and — the dominant shape in practice — an organisation-prefixed label such as `Amazon Confidential` were reaching **100 HIGH**, indistinguishable from `Confidential - Project Nightjar acquisition`, which actually discloses something. Following #307, which demoted the *bare* marking, the remaining rule asked whether every token was a known marking, so any decoration read as content. It now removes the marking phrases and grades what remains by SHAPE — at most one ordinary word, a stem fused to a small number (`FY25`, `v2`), or a stem plus a small number (`Rev 3`) — so no vocabulary of decoration words is needed and an unrecognised shape keeps the full weight. Measured over 714 real Office/PDF documents: METADATA findings **HIGH 194 → 81, MEDIUM 1272 → 1385**, with **0 findings gained, 0 lost and 0 scores raised**; all 113 demoted rows are an org-prefixed or ALLCAP label, and none contains an email, a path or a digit run. Disclosures are untouched — a value naming a project, a person, an address or an account number still scores 100. A marking is demoted, never vetoed, and redaction is confidence-blind, so a demoted value is still masked in the redacted copy. Known limitation: a one-word remainder cannot be told from a status word, so `Confidential - Nightjar` is graded as decoration (zero occurrences in the 714 documents; still reported at MEDIUM, still redacted). ([#320](https://github.com/awslabs/ferret-scan/issues/320))
- **office:** inflate each embedded part once per scan instead of twice, bound the embedded part COUNT at 4,096 per container, and correct `embedded.BudgetBytes`' comment, which claimed to be a whole-traversal budget while the code grants a fresh per-container allowance. Every part used to be written to a temp file twice — once to decide metadata membership, once for scanning — so a 2-part `.docx` produced 4 temp files; the parts are still inflated for the admission verdict (it decides `EmbeddedMediaCount` and the `EmbeddedMedia_N_*` indices, which validators scan) but no longer written to disk. Measured: 40 parts x 5 MB 390ms -> 290ms, 2,000 tiny parts 2110ms -> 1390ms, output byte-identical on 381 real Office documents carrying 2,675 embedded parts. Separately, neither existing cap bounded the part COUNT — an empty part charges nothing against the 50 MB per-part cap or the 200 MB byte budget — so a 25 MB `.docx` declaring 200,000 empty parts cost 184s and 1.18 GB RSS; with the cap, 4.1s and 156 MB. 4,096 is ~11x the largest part count in 420 real Office documents (361), and report output is byte-identical across all 420. Parts past the cap are DISCLOSED on their own line with their own cause, naming the container's true total, never dropped silently. Closes [#379](https://github.com/awslabs/ferret-scan/issues/379).

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
