# Ferret-Scan v2: Architectural Analysis & Overhaul Proposal

> Status: **Proposal / Decision Document — partially IMPLEMENTED.**
> Audience: maintainers
> Scope: internal architecture only — **no change to core functions** (detection accuracy, output formats, redaction behavior, or the CLI / stdin / web / `pkg/redact` library contracts).
>
> **Reading guide:** the *Analysis* and *Confirmed Gaps* below are written in the present tense as of the
> original audit — several are now fixed. For the authoritative record of what has shipped vs. what remains,
> see the **[Status Ledger](#status-ledger-authoritative)** in Migration / Sequencing. Highest-value
> remaining work: **Phase 3** (ctx-polling in validator hot loops + shared `LineScan`), which is *not* the
> final phase — Move C and Move D follow.

## Executive Summary & Verdict

Ferret-scan is functionally healthy on the happy path — detection, the output formats
(text/json/csv/yaml/junit/gitlab-sast, plus sarif), redaction, and the CLI/stdin/web/`pkg/redact`
contracts all work. But its internal architecture has drifted into a set of structural liabilities
that no amount of local bug-fixing can resolve.

The single most consequential finding is that the `Validator` interface carries no `context.Context`
([internal/detector/detector.go:29-38](../../internal/detector/detector.go#L29-L38)) and the two
validator fan-out sites `wg.Wait()` unconditionally
([internal/parallel/validator_runner.go](../../internal/parallel/validator_runner.go) and
[internal/validators/dual_path_bridge.go:729-839](../../internal/validators/dual_path_bridge.go#L729-L839)),
so the only timeout in the system — a 5-minute per-job context
([internal/parallel/worker_pool.go:228](../../internal/parallel/worker_pool.go#L228)) — cannot interrupt an
in-flight validator. This turns the documented O(n²) DoS findings (IP ~313s, IP_PROP ~527s, SSN >600s in
`VALIDATOR_REVIEW.md`) into **unbounded hangs** rather than merely slow scans, and a validator panic on a
fan-out goroutine crashes the **entire process** because Go panics do not cross goroutine boundaries and
the only `recover()` lives on a different (worker) goroutine
([internal/parallel/worker_pool.go:147-157](../../internal/parallel/worker_pool.go#L147-L157)).

**Verdict: A scoped v2 overhaul is warranted — but as a *consolidation*, not a rewrite.** The right scope
is four unifying structural moves. Every move can be staged additively and behavior-preservingly, because
the codebase already demonstrates the exact migration pattern needed: `detector.SourceKind`
([detector.go:43-55](../../internal/detector/detector.go#L43-L55)) and `ScanConfig.LogWriter`
([core/scanner.go:46-60](../../internal/core/scanner.go#L46-L60)) were both added with zero-value/nil
defaults that preserved old behavior. The real prerequisite is a regression net to guard detection
behavior during the refactor — sequenced first.

### How this analysis was produced

8 parallel subsystem readers, each required to cite `file:line` evidence, followed by an **adversarial
verification pass** on every claimed gap (each verifier re-opened the cited code and tried to *refute*
the claim). Of 35 candidate gaps, **24 survived** (confirmed real *and* architectural) and **11 were
refuted or downgraded** (listed under [Non-Goals](#explicitly-out-of-scope--non-goals) so maintainers know
what was vetted and dismissed).

---

## Current Architecture in Brief

A scan enters through one of three real call sites — [cmd/main.go](../../cmd/main.go) (CLI),
[cmd/stdin.go](../../cmd/stdin.go) (stdin), or [pkg/redact/engine.go](../../pkg/redact/engine.go)
(library) — plus [internal/web/server.go](../../internal/web/server.go) (web). The CLI multi-file path
uses `parallel.NewParallelProcessor` ([core/scanner.go:145](../../internal/core/scanner.go#L145)), a fixed
worker pool capped at `min(NumCPU, 8)`
([internal/parallel/parallel_processor.go:36-39](../../internal/parallel/parallel_processor.go#L36-L39)).
Each worker routes a file through [internal/router/file_router.go](../../internal/router/file_router.go),
which fans out one goroutine per capable preprocessor and then **concatenates** all preprocessor outputs
into a single `strings.Builder` joined by human-readable `--- name ---` separators, discarding the
structured `PositionMappings` that `ProcessedContent` actually carries. The worker then calls
`parallel.RunValidators` ([worker_pool.go:215](../../internal/parallel/worker_pool.go#L215)) — handed a
**single-element** `[]detector.Validator` containing an `EnhancedManagerWrapper`
([core/scanner.go:122-123](../../internal/core/scanner.go#L122-L123)). That wrapper delegates through a
6-layer chain — `EnhancedManagerWrapper → EnhancedValidatorManager → ValidatorIntegrationHelper →
DualPathIntegration → EnhancedValidatorBridge → DocumentValidatorBridge` — before reaching a concrete
validator's `ValidateContent` regex. The bridge runs the *real* per-validator fan-out (one goroutine each,
its own `wg.Wait()`) and *swallows* per-validator errors. Matches are then suppressed/filtered and handed
to [internal/formatters/](../../internal/formatters) and, on the redact path, to
`internal/redactors/replacement.Generate`. `ScanContent`
([core/scanner.go](../../internal/core/scanner.go)) and the library bypass the worker pool and call
`RunValidators` directly.

---

## Confirmed Architectural Gaps

Grouped by theme; highest-severity and best-evidenced first. Unless noted, every fix is
**behavior-preserving on the happy path** and can be staged additively.

### Theme 1 — Execution contract: validators cannot be bounded, isolated, or interrogated

This is the spine of the report. Four findings converge on one root cause: **the `Validator` interface and
the fan-out plumbing have no execution-control surface** — no context, no isolation, no diagnostics.

| # | Gap | Severity | Strongest evidence |
|---|-----|----------|--------------------|
| 1.1 | **No timeout/cancellation can reach a running validator** (keystone). The only budget is a 5-min `context.WithTimeout`, never consulted during validator work because the interface methods take no ctx. A runaway validator runs to completion regardless. | **HIGH** | [detector.go:29-38](../../internal/detector/detector.go#L29-L38); [validator_runner.go:88-141](../../internal/parallel/validator_runner.go); [worker_pool.go:228](../../internal/parallel/worker_pool.go#L228); [resilience/retry.go:91](../../internal/resilience/retry.go#L91) |
| 1.2 | **Two redundant execution engines; the controllable one is bypassed.** All real validators are collapsed into one `EnhancedManagerWrapper`, so `RunValidators`' fan-out/error-isolation operate over a single opaque element; the genuine fan-out happens two layers down where the parallel package can't see it. | **HIGH** | [scanner.go:122-123](../../internal/core/scanner.go#L122-L123); [enhanced_wrapper.go:30-64](../../internal/validators/enhanced_wrapper.go); [dual_path_bridge.go:729-839](../../internal/validators/dual_path_bridge.go#L729-L839) |
| 1.3 | **A validator panic crashes the whole process.** The fan-out goroutines have only `defer wg.Done()` — no `recover()`. The worker-level `recover()` is on a different goroutine and cannot catch cross-goroutine panics. 10 of 13 validators have no `recover()` anywhere; one path feeds the public `pkg/redact` library. | **HIGH** | [dual_path_bridge.go:736-808](../../internal/validators/dual_path_bridge.go#L736-L808); [validator_runner.go:82-138](../../internal/parallel/validator_runner.go); [worker_pool.go:145-157](../../internal/parallel/worker_pool.go#L145-L157) |
| 1.4 | **Validator errors/timeouts/panics never surface to the user.** Errors are discarded unless `--debug`; the dual-path bridge returns nil error regardless of failures. A scan where 3/13 validators errored exits "clean" with a silently-incomplete result — a false sense of completeness for a DLP tool. | **HIGH** | [dual_path_bridge.go:821-839](../../internal/validators/dual_path_bridge.go#L821-L839); [worker_pool.go:216-221](../../internal/parallel/worker_pool.go#L216-L221); [scanner.go:64-70](../../internal/core/scanner.go#L64-L70) |

**Why architectural (1.1):** You cannot kill a goroutine in Go from outside. The only cooperative
cancellation is threading `ctx` into the work and polling `ctx.Err()` in the hot loop. Since
`ValidateContent`'s signature lacks `ctx` across ~13 validators plus the bridge call sites, honoring a
deadline is a cross-cutting interface change. Patching one `wg.Wait()` lets the *join* return early while
the spinning goroutine leaks — the resource pressure persists.

**Core-function impact: PRESERVED (additive).** Add a context-aware method (`ValidateContentCtx`) with the
existing `ValidateContent` as a `ctx.Background()` shim; validators opt in to polling incrementally;
un-migrated validators behave exactly as today. **Two honest caveats:** (a) returning *partial* matches on
timeout is a behavioral change *for the timed-out file* — so the budget must default generous and the
timeout must surface as an explicit incomplete/error signal, never a silent truncation (which for a DLP
tool would mask detections); (b) **both** fan-out sites must migrate together or the dual-path route stays
uncancellable.

### Theme 2 — Resource governance: unbounded, multiplicative, observation-only

| # | Gap | Severity | Strongest evidence |
|---|-----|----------|--------------------|
| 2.1 | **No global concurrency governor.** File-workers (≤8) × ~13 validator goroutines ≈ 100 CPU-bound goroutines on an 8-core box, with no shared semaphore. | MEDIUM | [parallel_processor.go:36-39](../../internal/parallel/parallel_processor.go#L36-L39); [validator_runner.go](../../internal/parallel/validator_runner.go); [redactors/manager.go:512-524](../../internal/redactors/manager.go#L512-L524) |
| 2.2 | **The adaptive governor is dead code.** `NewAdaptiveParallelProcessor`/`ResourceMonitor` are never instantiated by any real entry point; the memory-pressure signal is mathematically dead (`Alloc / max(Sys*2, 2GB)` can't reach 80%). | MEDIUM | [parallel_processor.go:47-50](../../internal/parallel/parallel_processor.go#L47-L50); [resource_monitor.go:189-247](../../internal/parallel/resource_monitor.go#L189-L247); [adaptive_processor.go:325-353](../../internal/parallel/adaptive_processor.go#L325-L353) |
| 2.3 | **Whole-file buffering + multiplicative content duplication; no live-bytes budget.** Content is never streamed; the 100MB gate is a size check, not a memory budget; the combine step makes a 2nd full copy; each validator materializes its own `strings.Split` line slices. N concurrent large files multiply independently. | HIGH | [file_router.go:27-28](../../internal/router/file_router.go#L27-L28),172-218; [scanner.go:289-297](../../internal/core/scanner.go#L289-L297) |
| 2.4 | **Decompression amplification.** The Office *text* extractor `io.ReadAll`s zip entries with no `LimitReader` — a sub-100MB `.docx` expands to multi-GB validator text. The *metadata* office extractor right next door already wraps reads in `io.LimitReader(rc, 10MB)`, proving the safety model is per-extractor and ad hoc. | HIGH | `text-extract-officetextlib/office-text-extractor.go` (unbounded `io.ReadAll`); `meta-extract-officelib/office-extractor.go:152` (10MB LimitReader) |

### Theme 3 — Validator contract & the bridge stack: layered indirection over a dead core

| # | Gap | Severity | Strongest evidence |
|---|-----|----------|--------------------|
| 3.1 | **The enhanced-manager layer is a dead pass-through; 6 hops to a regex.** `EnhancedValidatorManager`'s registry, cross-validator signals, and confidence calibrator are never reached — `ValidateContentWithDualPath` unconditionally delegates to the dual-path helper, which all call sites set. | MEDIUM | [enhanced_integration.go:271-283](../../internal/validators/enhanced_integration.go#L271-L283); [scanner.go:109-123](../../internal/core/scanner.go#L109-L123); [enhanced_wrapper.go:30-45](../../internal/validators/enhanced_wrapper.go#L30-L45) |
| 3.2 | **Dual `Validate(filePath)` / `ValidateContent` surface.** The interface mandates a file-reading `Validate` that production never calls on a concrete validator; 9 of 11 validators already gutted it to a no-op stub. Latent drift risk enforced by the exported interface. | MEDIUM | [detector.go:29-38](../../internal/detector/detector.go#L29-L38); [template/validator.go:58-60](../../internal/validators/template/validator.go#L58-L60); [dual_path_bridge.go:741](../../internal/validators/dual_path_bridge.go#L741) |
| 3.3 | **Adding one validator requires ~15 coordinated edits** with no single source of truth for display/SARIF/gitlab-sast/config metadata; 4 hardcoded check-name lists; the canonical how-to doc contradicts itself (prose says edit `cmd/main.go`, checklist says `factory.go`). | MEDIUM | [creating_validators.md:577-596](../development/creating_validators.md); [cmd/main.go:821](../../cmd/main.go#L821); [factory.go:75-93](../../internal/core/factory.go#L75-L93) |

### Theme 4 — DoS-complexity surface: one anti-pattern fixed ten ways, no input-shape guards

| # | Gap | Severity | Strongest evidence |
|---|-----|----------|--------------------|
| 4.1 | **Per-match whole-line rescan: one shared root-cause, fixed ad hoc per validator.** The O(n²) anti-pattern was remediated independently in ~10 validators with private machinery (`ssn.lineContext`, `ipaddress.analyzeContextLower`, `phone.lineKeywordCtx`, `vin.boundaryContext`, `personname.newLineContextCache`); `containsKeyword` is byte-for-byte duplicated across ssn/vin/ipaddress. No shared scanning primitive exists. | HIGH | [ssn/validator.go:190-233](../../internal/validators/ssn/validator.go#L190-L233); [ipaddress/validator.go:287-308](../../internal/validators/ipaddress/validator.go#L287-L308); [phone/validator.go:603-660](../../internal/validators/phone/validator.go#L603-L660); [vin/validator.go:498-539](../../internal/validators/vin/validator.go#L498-L539) |
| 4.2 | **No architecture-level input-shape/match budget.** Only passport (2000) and cloudresources (5000) cap matches at all, and they disagree on value *and* unit; email/IP/IPProp/socialmedia/vin/secrets/creditcard use `-1` (unbounded). | HIGH | [passport/validator.go:337-379](../../internal/validators/passport/validator.go#L337-L379); [cloudresources.go:33-36](../../internal/validators/cloudresources/cloudresources.go#L33-L36); [phone/validator.go:319](../../internal/validators/phone/validator.go#L319) |

*(4.3 — "validators cannot observe cancellation, so an O(n) catastrophe is an unrecoverable hang" — is the
same gap as 1.1 viewed through the DoS lens. It is the reason the complexity bugs are severe rather than
merely slow.)*

### Theme 5 — Provenance, routing, and preprocessing

| # | Gap | Severity | Strongest evidence |
|---|-----|----------|--------------------|
| 5.1 | **Provenance is a lossy round-trip through a concatenated string.** `ProcessedContent` carries a full `PositionMapping` model that is **never consumed** (`GetPositionMappingsForRange` has zero callers); for PDF/Office, `LineNumber` indexes the *extracted* text, not the source file. | HIGH | [file_router.go:180-218](../../internal/router/file_router.go#L180-L218); [content_router.go:840-880](../../internal/router/content_router.go#L840-L880); [preprocessors/preprocessor.go:34-113](../../internal/preprocessors/preprocessor.go#L34-L113) |
| 5.2 | **No ctx reaches the extractors; the timeout pattern leaks goroutines; the body-text extractor has no timeout at all.** `Preprocessor.Process(filePath)` carries no context; metadata extractors run the blocking call in a goroutine that is never cancelled (leaks on `ctx.Done`); the text preprocessor feeding the regex validators has no timeout. | HIGH | [preprocessor.go:116-131](../../internal/preprocessors/preprocessor.go#L116-L131); [file_router.go:143-169](../../internal/router/file_router.go#L143-L169) |
| 5.3 | **File-type routing is hardcoded extension switches, not data-driven** — 4 sources of truth that already drift (a `.heic` gates *in* then errors "no preprocessor can handle file"). | MEDIUM | [file_router.go:291-332](../../internal/router/file_router.go#L291-L332); [content_router.go:630-646](../../internal/router/content_router.go#L630-L646); [preprocessors/shared_utilities.go:91-124](../../internal/preprocessors/shared_utilities.go#L91-L124) |

### Theme 6 — Redaction, observability, and config

| # | Gap | Severity | Strongest evidence |
|---|-----|----------|--------------------|
| 6.1 | **Two parallel redaction engines.** The live path is `internal/redactors/replacement.Generate` (invalid synthetic SSNs — *safe*); the dead path is `internal/redactors/strategies` (valid SSNs — *less safe*, zero importers). A reader could adopt the wrong, less-safe code. | MEDIUM | [plaintext/redactor.go:362-365](../../internal/redactors/plaintext); [replacement/replacement.go:4-7](../../internal/redactors/replacement); [strategies/synthetic.go:235-261](../../internal/redactors/strategies) |
| 6.2 | **Observability is unstructured strings-to-`io.Writer`** with no metrics/traces/pluggable sink; concrete `*StandardObserver` threads through ~76 `SetObserver` signatures with no interface seam. Inadequate for Lambda/gateway/CI embedding. | MEDIUM | [observability/observer.go:56-67](../../internal/observability); [scanner.go:88-92](../../internal/core/scanner.go#L88-L92) |
| 6.3 | **`internal/monitoring` (~2.1K LOC) + most of `internal/performance` (~2.3K LOC) are dead code** — a phantom observability stack with zero importers on the scan path. | MEDIUM | [internal/monitoring/](../../internal/monitoring); [internal/performance/](../../internal/performance) |
| 6.4 | **Config: hand-coded 4-tier cascade, code+YAML default drift, untyped per-validator map, no schema validation.** Typos silently no-op (a DLP risk); a `containsField` hack re-parses the entire 51KB YAML per bool lookup. | MEDIUM | [cmd/main.go:155-249](../../cmd/main.go#L155-L249); [config.go:444-562](../../internal/config/config.go#L444-L562) |

---

## Proposed v2 Architecture

Four unifying structural moves close the gaps cohesively. Each names what changes **and what stays the
same** to preserve behavior.

### Move A — A context-aware, bounded, fault-isolated validator execution engine
*Closes 1.1, 1.2, 1.3, 1.4, 2.1, 2.3 (admission), 4.2, 4.3, 5.2.*

Introduce **one** validator-execution engine that owns: (1) a `ctx` threaded into the canonical validation
method; (2) a single dispatch chokepoint wrapping every validator call in `defer/recover()` (panic →
non-retryable per-validator error); (3) a process-scoped weighted concurrency limiter
(`golang.org/x/sync/semaphore`) every fan-out borrows from; (4) a per-validator time + match budget; and
(5) a per-validator diagnostics summary (ran/failed/timed-out/skipped) returned up to `ScanResult`.

- **What changes:** Add `ValidateContentCtx(ctx, content, path)` (legacy `ValidateContent` becomes a
  `ctx.Background()` shim). Collapse the two fan-out sites into one. `RunValidators` returns
  `(matches, diagnostics)`; `ScanResult` gains an optional `Diagnostics` field. Validators poll `ctx.Err()`
  at loop boundaries.
- **What stays the same:** Dual-path routing rules (metadata-only → metadata validator;
  `ValidateProcessedContent` precedence; `OriginalPath→Filename` fallback; document-path
  confidence/metadata annotations). Match-union semantics. On in-time inputs, byte-identical results. The
  diagnostics field defaults empty; non-zero exit on degraded coverage is opt-in. Output formats,
  redaction, and all four entry contracts untouched.

> **Phase 1 of this move is already prototyped on this branch — see
> [Phase 1 Prototype (landed)](#phase-1-prototype-landed) below.**

### Move B — Collapse the bridge/wrapper stack into one explicit `Detector` facade — **the chain collapse LANDED**

*Closes the structural half of 3.1 (chain collapse) and the metadata source-of-truth core of 3.3 (type-keyed registry); 3.2 (collapsing the dual `Validate`/`ValidateContent` interface surface) and the optional per-validator `Descriptor()` declaration remain future work.*

> **Gap 3.3 (type-metadata source-of-truth) — LANDED in part.** Per-`Match.Type` display metadata that was duplicated across the SARIF and gitlab-sast formatters now lives in one registry: [internal/core/typemeta.go](../../internal/core/typemeta.go) (`TypeDescriptor` + `TypeMeta(t)`), keyed by sub-type (e.g. `VISA`, `AWS_ACCESS_KEY`, `AUTHOR_INFO`). SARIF rule descriptions + sensitivity weights ([sarif/constants.go](../../internal/formatters/sarif/constants.go), [sarif/mapper.go](../../internal/formatters/sarif/mapper.go)) and the live gitlab-sast check-descriptions + remediation strings ([gitlab-sast/sanitizer.go](../../internal/formatters/gitlab-sast/sanitizer.go)) now read from it; their local maps were deleted. Each consumer gates on its own field's presence so the differing legacy key-sets (and per-site fallbacks) are preserved byte-for-byte — proven by the golden corpus passing with zero `UPDATE_GOLDEN`. Separately, the four hardcoded validator-**name** lists were unified onto the existing `core.CheckNames()` source of truth (three in `cmd/main.go`; the fourth in `internal/help/help.go` is documented-but-not-derived because `core` depends transitively on `help`, an import cycle), with byte-equality locked by `cmd/checks_test.go`. **Out of scope (deliberate):** adding descriptions/weights for the ~30 currently-uncovered sub-types (would change output, needs a golden update), the validator-NAME-keyed gitlab category/name maps and text/csv pre-commit switches (a separate NAME-tier follow-up), and the optional per-validator `Descriptor().SubTypes()` declaration.

Additionally, a related formatter bug was fixed alongside this work:

> **SARIF rule-accumulation bug (surfaced by the golden harness) — FIXED.** The SARIF formatter ([sarif/formatter.go](../../internal/formatters/sarif/formatter.go)) is now stateless: each `Format()` builds a fresh `RuleManager`, so a report's `tool.driver.rules` derives only from that call's matches (was: a process-singleton `RuleManager` accumulating rules across calls — benign for the CLI, a cross-invocation contamination bug for the web server). Regression-locked by `sarif/accumulation_test.go` (verified to fail against the old shared-manager behavior). gitlab-sast was checked and does not share the bug.

**Landed.** A single `Detector` type ([internal/validators/detector.go](../../internal/validators/detector.go))
now holds the `*EnhancedValidatorBridge` directly and is the only validator handed to `RunValidators`. It
replaced the five-type pass-through chain — `EnhancedManagerWrapper → EnhancedValidatorManager →
ValidatorIntegrationHelper → DualPathIntegration → EnhancedValidatorBridge` — collapsing the live ctx path
from **5 hops to 1** (`Detector.ValidateProcessedContentCtx → bridge.ProcessContentCtx`). Deleted:
`enhanced_wrapper.go` (`EnhancedManagerWrapper`), `enhanced_integration.go` (`EnhancedValidatorManager` +
`EnhancedValidatorConfig`/`DefaultEnhancedValidatorConfig`), and `ValidatorIntegrationHelper` +
`DualPathIntegration` from `dual_path_integration.go` (leaving only the load-bearing
`MetadataValidatorAdapter`). Also removed the dead `dual_path_worker.go` (`DualPathWorker`/`DualPathWorkerPool`
— constructed in the worker pool but never invoked) and its unused `WorkerPool.dualPathWorker` field. The
six-line construction ceremony at all four call sites (`core/scanner.go` ×2, `cmd/main.go`,
`pkg/redact/engine.go`) became two lines: `NewDetector(observer)` + `SetupValidators(...)` (+ `SetFileRouter`
where a router exists). The inert `EnableRealTimeMetrics` flag (set everywhere, read nowhere) is gone; debug
logging is still driven by the observer's `DebugObserver`, exactly as before.

- **What changed:** 5 hops → 1; four ~6-line construction sites → two lines each; ~4 types + 1 dead file
  removed.
- **What stayed the same (verified):** the live detection path is the *same* `EnhancedValidatorBridge`
  (content routing, document/metadata fan-outs, `applyCrossPathConfidenceAdjustments`) — untouched.
  Behavior-preservation proven by the golden corpus passing with **zero `UPDATE_GOLDEN`** regeneration,
  the execguard e2e (stall/panic/happy-path) green through the new facade, and full `go test ./...` +
  `-race` clean.
- **Deferred to a later increment:** 3.2 (collapsing the dual `Validate`/`ValidateContent` surface — still
  required by the exported `detector.Validator` interface) and 3.3 (a `Descriptor()` metadata
  source-of-truth so formatters/help/config stop hardcoding per-validator strings). Those change the
  exported interface and formatter inputs, so they need their own behavior-preserving design + golden
  extension.

### Move C — Shared scanning primitives + cross-cutting input-shape guards
*Closes 4.1, 4.2, 2.4, 5.1.*

Introduce one shared `detector.LineScan` primitive (lowercased line, byte offsets from a single
`FindAllStringIndex` pass, parameterized whole-word keyword lookup with junction handling proven once) that
validators are required to consume; delete the ~10 per-validator duplicates. Add a layered extraction +
match budget (per-zip-entry `io.LimitReader`, per-file uncompressed cap, aggregate router cap, uniform
per-validator match cap) surfaced as a first-class "truncated/over-budget" outcome. Carry an attributed
**segment stream** (text + sourceLabel + baseLineOffset) across the preprocessor→validator boundary so a
match's line maps to (source, original line).

- **What stays the same:** The primitive is *parameterized* to reproduce each validator's existing
  semantics byte-for-byte (word-byte predicate, junction window, raw/lower variants). Budgets default well
  above real corpora; chunking overlaps by ≥ max-token-length so no legitimate token is split.

### Move D — Dead-code excision + a stable public engine API + real telemetry seam
*Closes 2.2, 6.1, 6.2, 6.3, 6.4.*

Delete `internal/monitoring` and the unreachable parts of `internal/performance` (~4.4K LOC); delete
`redactors/strategies` (keep `replacement/` behind one `ReplacementGenerator` interface); delete the
unwired adaptive processor (or fold its concept into the Move-A budget reading real RSS/cgroup limits).
Introduce a minimal `Observer`/`Sink` interface with a default human/stderr adapter (current behavior) plus
optional slog/metrics adapters, passed once via `ScanConfig`. Adopt a single typed config schema as the
source of truth with warn-only unknown-key validation.

- **What stays the same:** The default observer adapter preserves byte-identical CLI output. `replacement/`
  is the kept redaction behavior. Config resolution reproduces current resolved values exactly; validation
  starts warn-not-fail.

---

## Migration / Sequencing

The ordering front-loads behavior-preserving, low-risk work and defers any observable change until a
regression net exists.

> **⚠️ Status note (kept current).** Execution has run *opportunistically as small PRs*, not strictly in the
> original Phase 0→4 numbering, so the phase labels below have drifted from what actually shipped. The
> **Status Ledger** immediately below is the authoritative record; the per-phase prose that follows is
> retained for the original design rationale. When the open PRs merge, the phase prose should be
> re-narrated to match the ledger.

### Status Ledger (authoritative)

Everything landed so far is **behavior-preserving on legitimate input** (golden corpus byte-identical, zero
`UPDATE_GOLDEN`); the only intended behavioral change is the opt-in bounded-partial + incomplete signal on
over-budget inputs, which requires Phase 3 (not yet done).

| Item | Gap(s) | Status | PR |
|---|---|---|---|
| Golden regression net (`internal/goldencorpus`) | Phase 0 | **merged** | #98 |
| Bounded/cancellable/panic-isolated execution (`execguard`, cancellable joins) | 1.1, 1.3 | **merged** | #98 |
| `ScanResult.Incomplete` on the in-memory (`ScanContent`) path | 1.4 (partial) | **merged** | #98 |
| Detector facade — collapse the 5-hop wrapper chain; delete advanced-features subsystem/`ValidatorBridge`/dead worker | 3.1 (structural), 1.2 | **merged** | #98, #100 |
| Type-metadata source-of-truth `core.TypeMeta` (SARIF + gitlab sub-type + name tier); check-name unification | 3.3 (core) | **merged** + **open** | #98, #103 |
| SARIF stateless-formatter fix (rule-accumulation) | (found by net) | **merged** | #98 |
| Decompression-amplification bound (Office text extractor) | 2.4 | **merged** | #99 |
| Remove dead adaptive processor + resource monitor | 2.2 | **merged** | #100 |
| Windows CI cross-platform fixes (CRLF/paths/timer) | (test infra) | **merged** | #98, #101 |
| Global concurrency governor (`execguard.Limiter`) | 2.1 | **open** | #102 |
| gitlab name-tier metadata → `core.TypeMeta` | 3.3 (remainder) | **open** | #103 |
| `ScanResult.Incomplete` on the file/worker-pool path | 1.4 (file path) | **open** | #104 |
| Performance baseline (docs) | — | **open** | #105 |

**Not yet started (the real remaining work, roughly two phases):**

| Item | Gap(s) | Notes |
|---|---|---|
| **ctx-polling inside validator hot loops + shared `LineScan` primitive + per-validator/extraction budgets** | 1.1 (tail), 4.1, 4.2 | **Phase 3** — the marquee remaining item; fixes the single-long-line O(n²) (see Performance Baseline: 256 KB line ~9.6s → target sub-second). First *observable* behavior change (bounded-partial on over-budget input). Highest value; needs its own review on merged base. |
| Structured provenance through preprocessing | 5.1 | Move C leftover (HIGH — lossy position round-trip) |
| Data-driven file-type routing (collapse 4 drifting extension maps) | 5.3 | Move C leftover |
| Structured `Observer`/telemetry seam | 6.2 | Move D |
| Typed config schema | 6.4 | Move D |
| Delete dead `internal/monitoring` + `internal/performance` (~4.4K LOC) | 6.3 | Move D — pure excision |
| Delete dead `redactors/strategies` (keep `replacement/`) | 6.1 | Move D — pure excision |
| Collapse dual `Validate`/`ValidateContent` interface surface | 3.2 | Exported-interface breaking change |
| CLI/web *consumption* of `ScanResult.Incomplete` (exit code / response) | 1.4 (surface) | Separate behavior-changing decision |
| NAME-tier: gitlab category `AddCategoryMapping` fully gone / text+csv pre-commit switches | 3.3 (tail) | Deliberately deferred; low value |

**Is Phase 3 the last phase?** No. After Phase 3 there is still Move C (provenance/routing) and Move D
(telemetry/config/dead-code excision), plus the smaller items above. Phase 3 is the highest-*value*
remaining chunk (it closes the founding "runaway validator" concern at the algorithmic level), but it is
roughly the program midpoint. A reasonable milestone is to declare the **security-and-correctness** goal met
after Phase 3 and treat Move C/D as lower-urgency cleanup.

---

### Original phase prose (design rationale; see ledger above for actual status)

**Phase 0 — Build the regression net (prerequisite; do this first). — LANDED.** The current test
architecture was too weak to refactor against safely: ~70 `_test.go` files for 252 Go files; no
golden/snapshot harness; [cmd/main.go](../../cmd/main.go) is ~95KB of largely untested orchestration. This
is now addressed by [internal/goldencorpus](../../internal/goldencorpus) (see its
[README](../../internal/goldencorpus/README.md)): a curated set of representative + adversarial inputs
scanned through **both** the in-memory path (`core.ScanContent`) **and the file path** (`core.ScanFile` —
worker pool + FileRouter + the metadata/dual-path branch, via text/source/JSON/CSV fixtures plus a
synthesized in-test `.wav` that exercises the audio-metadata preprocessor without committing a binary), and
rendered through every output format (text, json, csv, yaml, junit, gitlab-sast, sarif) plus the
`pkg/redact` path. Snapshots are byte-stable (123 committed fixtures) and regenerated via `UPDATE_GOLDEN=1`.
A `TestFileContentParity` test locks the invariant that file-mode and content-mode produce identical
findings for the same plain-text bytes. It also includes the per-validator "cost is independent of line
length" timing guard (`TestValidatorComplexityIsSubQuadratic`), which currently measures ~3–4× time for 4×
input (confirming linear scaling) and fails on quadratic regression — the guardrail for Move C. The harness
is **proven to catch regressions** (a deliberately perturbed snapshot and a tightened complexity ratio both
fail it) and is deterministic across 10 consecutive runs. This corpus is the gate every subsequent phase
must pass with zero `UPDATE_GOLDEN` regeneration.

> **New finding surfaced while building the net:** the SARIF formatter registered in
> `formatters.DefaultRegistry` is a process singleton whose `RuleManager` accumulates rules across every
> `Format()` call (`internal/formatters/sarif/formatter.go` — `ruleManager` is never reset), so its output
> depends on what was formatted earlier in the same process. Benign for the CLI (one format per process),
> but a real cross-invocation contamination bug for a long-lived embedder (e.g. the web server) that formats
> SARIF repeatedly. Candidate fix for the v2 work: reset-per-`Format()` or derive rules from the match set. *(Housekeeping: the stray multi-MB `*.test` binaries in the repo root are
build artifacts, not a suite — gitignore them.)*

**Phase 1 — Additive no-op interface evolution (behavior-identical).** Add `ValidateContentCtx(ctx, ...)`
with `ctx.Background()` shims; thread `ctx` through `RunValidators` and the bridge; add the
dispatch-chokepoint `recover()`; make the join honor `ctx`. **Done on this branch — see below.**

**Phase 2 — Consolidate execution (internal-only). — DEAD-CODE EXCISION LANDED.** The first slice of
this phase (gap 3.1) is done: `EnhancedValidatorManager` has been reduced from ~740 lines to ~150,
deleting the never-wired "advanced features" subsystem — `ValidateWithAdvancedFeatures` (zero callers) and
its cross-validator signal correlation, statistical confidence calibrator, language detector, analytics,
and recommendations layer — plus the dead per-validator registry (`RegisterValidator`/`enhancedValidators`)
and the entire `ValidatorBridge` type (`enhanced_bridge.go`, deleted). The registration loops at all four
construction sites (`core/scanner.go` ×2, `cmd/main.go`, `pkg/redact/engine.go`) were removed; validators
reach the live path solely via `SetupDualPathValidation`. The unreachable `validateContentLegacy` fallback
was replaced with an explicit error (a nil dual-path helper is now a loud failure, not a silent
zero-findings result). **Verified behavior-preserving**: `go build ./...` clean, full `go test ./...`
green, and the golden corpus passes with **zero `UPDATE_GOLDEN` regeneration** — the proof that detection,
confidence, formats, and redaction are byte-identical. Remaining Phase 2 work (collapsing the surviving
6-hop wrapper chain into a single `Detector` facade — Move B — and fusing the two fan-out engines, gap 1.2)
is deferred to a later increment.

**Phase 3 — Enforcement (first observable change, on pathological inputs only).** Turn on `ctx.Err()`
polling inside validators, the concurrency limiter, the per-validator budget, and extraction/match budgets
(Moves A, C). Behavior changes *only* on over-deadline/over-budget inputs (today: hang or crash; v2:
bounded partial + explicit incomplete signal).

**Phase 4 — Surface and consolidate.** Add `ScanResult.Diagnostics` + opt-in degraded-coverage exit (1.4);
the shared `LineScan` primitive (4.1); structured provenance (5.1); `Descriptor()` + data-driven routing
(3.3, 5.3); the `Observer` seam and typed config schema (6.2, 6.4).

---

## Performance Baseline (measured)

Empirical comparison of a **pre-v2 binary** (commit `75be0e6`, before PR #98) vs a **v2 binary**
(post #98–#104), built from the same toolchain and run on the same machine (macOS, `--checks all`,
output to `/dev/null`). This grounds the phase plan: it shows the landed orchestration work is
behavior-neutral-to-faster, and it isolates exactly what Phase 3 still has to fix.

| Workload | pre-v2 | v2 | Read |
|---|---|---|---|
| 3.9 MB normal text file | 4.85s | **3.20s** | v2 ~34% faster (collapsed bridge/cleaner path) |
| 200-file directory | 0.35s | 0.35s | identical — the concurrency governor (#102) adds no measurable overhead |
| 256 KB **single dense line** | 9.71s | 9.56s | **identical** — per-validator O(n²) cost is unchanged |
| 2 MB single dense line | did not finish (killed >90s) | did not finish (killed >90s) | both runaway |
| Peak RSS (3.9 MB file, v2) | — | ~65 MB | — |

**What this confirms about the design boundary (important):**

- The merged v2 work made a runaway validator **terminable and bounded at the ORCHESTRATION layer** —
  Phase 1's context-cancellable join, the configurable per-file `JobTimeout` (default 5 min), and #102's
  process-wide concurrency governor — so the *scan* can no longer hang forever and one pathological file
  cannot starve the worker pool. On normal inputs the consolidation is a net speedup.
- It did **not** touch the **per-validator O(n²) inner scanning cost** on a single very long line. The
  256 KB-single-line case is ~9.6s on *both* binaries, and 2 MB single-line runs away on both. This is the
  exact hot path **Phase 3** targets (ctx-polling in the validator loops + the Move-C shared `LineScan`
  primitive that removes the per-match full-line rescan). The complexity guard in `internal/goldencorpus`
  measures *linear* scaling on multi-line dense input; the single-very-long-line pathology is a distinct
  hot path still pending.

**Phase 3 success criteria, anchored to these numbers:** after Phase 3, the 256 KB single-line scan should
drop from ~9.6s toward sub-second (linear, not quadratic), and the 2 MB single-line scan should complete
within the per-file budget (today it must be killed). Detection output on normal inputs must remain
byte-identical (golden net), with the only behavioral change being bounded-partial + an explicit incomplete
signal on inputs that exceed the budget.

> Method caveat: macOS lacks `timeout`/`gtimeout`; "did not finish" runs were wall-clock-capped and killed
> manually. Numbers are best-of-small-N on one machine — directional, not a benchmark suite. A repeatable
> Go benchmark for the single-long-line path is worth adding alongside Phase 3.

---

## Phase 1 Prototype (landed)

This branch (`feat/v2-phase1-bounded-execution`) implements the behavior-preserving slice of Move A. It
directly closes the keystone availability gaps — **1.1** (a stalled validator no longer hangs the scan;
the leak is bounded to one goroutine) and **1.3** (a panic in any validator, document *or* metadata, is
recovered instead of crashing the process) — and makes a **partial** down payment on **1.4** (incomplete
coverage is surfaced via `ScanResult.Incomplete` on the `ScanContent` path; the worker-pool path remains
Phase 4). All without touching detection logic.

**What was added**
- New package [internal/execguard](../../internal/execguard/execguard.go): the single per-validator
  dispatch chokepoint.
  - `SafeRun(ctx, name, fn)` — runs `fn` under `recover()` (panic → **non-retryable**
    `resilience.NewPermanentError`, so the retry wrapper does not re-run a deterministically-panicking
    validator) and skips launching work once `ctx` is already cancelled/expired.
  - `ContextAwareValidator` — an **optional** extension interface (`ValidateContentCtx`). Validators that
    implement it receive `ctx` to poll; validators that don't are invoked through the legacy
    `ValidateContent` path, unchanged.

**What was wired**
- `ctx` is now threaded from `RunValidators` all the way down the live chain via additive `...Ctx` method
  variants (old signatures kept as `context.Background()` shims): `EnhancedManagerWrapper` →
  `EnhancedValidatorManager.ValidateContentWithDualPathCtx` →
  `ValidatorIntegrationHelper.ProcessContentWithDualPathCtx` → `DualPathIntegration.ProcessContentCtx` →
  `EnhancedValidatorBridge.ProcessContentCtx` → `processDualPath`/`processContentLegacy` →
  `DocumentValidatorBridge.ProcessDocumentContentCtx` / `MetadataValidatorBridge.ProcessMetadataContentCtx`.
- **Both** the document leaf fan-out and the **metadata** path now dispatch through `execguard`
  (`ValidateContent` / `SafeRun`) — so a panic in *any* validator, including the large metadata validator,
  is recovered into a non-retryable error instead of crashing the process. (This was tightened after
  review: the first cut covered only the document path.)
- `EnhancedManagerWrapper` implements `ContextAwareValidator`, so `RunValidators` prefers the ctx-aware
  path.
- Cancellation is honored at **both** the outer join and the inner document leaf join: `RunValidators` and
  `DocumentValidatorBridge.ProcessDocumentContentCtx` each `select` on `ctx.Done()` vs completion (instead
  of an unconditional `wg.Wait()`), and the metadata loop checks `ctx.Err()` per item. This **bounds the
  goroutine/content leak** from a runaway validator to the single still-running leaf goroutine, rather than
  pinning the whole nested stack (outer join + wrapper goroutine + dual-path goroutines + leaf) until the
  validator returns. `processDualPath` surfaces `ctx.Err()` with partial matches, and the caller does
  **not** fall back to a legacy re-run on cancellation (which would re-stall on the same validator).
  Buffered channels are intentionally **not** closed on the cancellation path so a late goroutine can still
  send without panicking.
- **Degraded-coverage signal is consumed, not just plumbed, on the `ScanContent` path**: `ScanResult` gains
  additive `Incomplete bool` / `IncompleteReason string` fields (default false / empty — no behavior
  change), and `ScanContent` sets them when the validator run ends in `context.DeadlineExceeded`/`Canceled`.
  This distinguishes "scanned clean" from "did not finish scanning" for the stdin/in-memory/library caller.

**What was explicitly NOT changed (Phase 1 boundaries)**
- The `detector.Validator` interface is untouched (no source-breaking change to the ~13 validators or
  external implementers).
- No validator yet polls `ctx` mid-run, so a *single already-running* validator goroutine still cannot be
  killed (Go has no goroutine kill) — but the **scan** is no longer held hostage to it, the leak is bounded
  to that one goroutine, and new validator work is skipped once the deadline passes. Making the hot loops
  interruptible is Phase 3.
- **File-level isolation vs. batch-completion delay (worker-pool path).** Files are processed concurrently
  across `min(NumCPU, 8)` workers and each file is panic-recovered (`safeProcessJob`), so a validator that
  *fails or panics* on one file does not affect the others (locked by `TestBatch_FailedFileDoesNotBlockOthers`).
  A validator that *stalls* on one file occupies one worker; the other workers keep going, but the batch's
  result collector waits for every file to report, so **overall batch completion is delayed until the stalled
  file hits its per-file timeout** (it can never hang forever). The per-file timeout is now configurable via
  `parallel.JobConfig.JobTimeout` (zero value = the historical 5-minute `DefaultJobTimeout`), so a long-lived
  embedder can tighten it. Locked by `TestBatch_StalledFileDoesNotBlockOthers` (a stalled file with a 300ms
  budget lets the good files finish in well under a second; verified to fail if the batch blocks). Reclaiming
  the stalled worker *immediately* (rather than at timeout) still requires Phase 3 ctx-polling.
- **The file/worker-pool path (`ScanFile`) does not yet surface `Incomplete` in `ScanResult`.** That path
  runs through the worker pool, whose per-file `Result.Error`/diagnostics are only retained under `--debug`
  and (pre-existing behavior) cause a file's matches to be dropped on error. Threading per-file diagnostics
  end-to-end is **Phase 4** (`ScanResult.Diagnostics`); the field is documented as ScanContent-only for now.
- Detection accuracy, output formats, redaction, and the CLI/stdin/web/`pkg/redact` contracts are
  unchanged (verified: full `go test ./...` green; `-race` clean on the touched packages; stall/cancel
  tests stable over `-count=10`; CLI/stdin smoke scans produce identical findings).

**Tests added**
- [internal/execguard/execguard_test.go](../../internal/execguard/execguard_test.go) — panic →
  non-retryable error; happy-path pass-through; already-cancelled skip; ctx-aware preference; expired
  deadline returns fast.
- [internal/parallel/validator_runner_cancel_test.go](../../internal/parallel/validator_runner_cancel_test.go)
  — a stalled validator no longer blocks `RunValidators` past the deadline; happy path unaffected.
- [internal/validators/execguard_e2e_test.go](../../internal/validators/execguard_e2e_test.go) —
  **keystone end-to-end through the real wrapper stack**: a stalled document validator returns shortly
  after the deadline with `DeadlineExceeded` (proving the inner-join escape, not just the outer primitive);
  a panicking document validator is recovered, not fatal; happy path produces matches unchanged.
- [internal/core/scanner_test.go](../../internal/core/scanner_test.go) — a completed `ScanContent` scan is
  not flagged `Incomplete` (happy-path default of the degraded-coverage signal).

---

## Future Capabilities (ideas preserved from deleted code)

These are **net-new feature ideas**, not part of the behavior-preserving consolidation. They are recorded
here so good ideas embedded in dead code are not lost when that code is excised. Each would be a deliberate,
opt-in behavioral *addition* (changing detection output), so each requires its own design, golden-corpus
extension, and review — they are explicitly **out of scope** for Moves A–D.

### FC-1 — Cross-validator co-occurrence confidence escalation

**Origin.** Surfaced from the dead `analyzeCrossValidatorSignals` removed in Phase 2 (gap 3.1). That code
was never wired in, but it encoded a genuinely useful idea the live pipeline does **not** currently
implement.

**The idea.** Escalate confidence when *multiple distinct PII types co-occur* in the same document,
especially in a corroborating domain context — e.g. a `CREDIT_CARD` **and** an `SSN` together in a document
the context analyzer classifies as `Financial` / `HR_Payroll` is far more likely to be real sensitive data
than either finding in isolation. The deleted prototype applied a correlation boost scaled by the number of
co-occurring validator types (≥3 types → larger boost; 2 types → smaller) and had a specific
financial-document rule.

**Why it's not already covered.** The live `EnhancedValidatorBridge.applyCrossPathConfidenceAdjustments`
only correlates the **document-body vs. metadata** paths of a single validator's output; it does **not**
correlate *across different validators* within the body. So validator-to-validator co-occurrence signal is a
real gap, not a duplicate.

**Why it's future, not now.** It changes confidence scores (hence detection output and every golden
snapshot), so it cannot ride along with a behavior-preserving move. It also needs care to avoid
false-positive inflation (e.g. a test-fixture file full of fake PII shouldn't all get boosted). A sound
design would: (a) run as an explicit post-validation pass over the unified match set; (b) gate boosts on the
context analyzer's domain/environment signals (suppress in `test`/`example` contexts); (c) cap the boost and
record it in match metadata for auditability; (d) ship behind a config flag, off by default, with new
golden-corpus cases added for the on state. Belongs naturally in the Move-A execution engine as an opt-in
stage once that engine exists.

---

## Explicitly Out of Scope / Non-Goals

**Core functions that MUST NOT change** (reaffirmed): detection accuracy and confidence scoring on
legitimate inputs; the set and exact output of all formats (text/json/csv/yaml/junit/gitlab-sast/sarif);
redaction behavior including the live `replacement/` engine's invalid-synthetic-SSN safety; and the CLI,
stdin, web, and `pkg/redact` library contracts. The one intentional, opt-in behavioral addition is "return
partial + explicit incomplete signal on timeout/over-budget" — gated so normal files never trip it.

**Refuted / downgraded claims** (considered and dismissed during adversarial verification, so maintainers
know what was vetted):

- *Retry strategy amplifies DoS; circuit breaker is dead code* — REFUTED as architectural. The circuit
  breaker is genuinely dead (zero callers) and retry is vestigially misapplied, but it is **not** a DoS
  multiplier (retry only re-runs on a *returned* retryable error; slow-but-successful runs return nil).
  Fix is a one-line `nil`-strategy patch + dead-code removal.
- *Default exit code is always 0; swallowed failures produce silent clean exits* — REFUTED as
  architectural. The silent-failure path is real, but the fix is a few-line local patch reusing the
  existing `precommit.GetExitCode` mapper.
- *Resilience error taxonomy is AWS-shaped and bypassed* — REFUTED. A scan-domain taxonomy *already exists*
  in `internal/preprocessors/error_handling.go`; remaining issue is local cleanup.
- *Runtime type-assertion dispatch silently drops validators* — REFUTED. `ValidateContent` is a mandatory
  interface method, so the compiler guarantees the fallback always matches; the "silent skip" is
  unreachable.
- *Custom IP regex inherits per-match rescan exposure* — REFUTED as architectural. The dominant O(n²) cost
  is already hoisted; the residual is a one-line match cap.
- *SecureString memory protection is vestigial* — REFUTED as architectural. Real doc/code contradiction
  (README advertises `Match.SecureText` storage that is never populated), but fixable with a local edit.
  Not a leak.
- *Disabled GenAI extractors remain as commented-out source* — REFUTED as architectural. ~63
  `GENAI_DISABLED` markers are dead weight, but removal is mechanical; the registry already is the seam.
- *LogWriter "no-leak chokepoint" claim is false in Debug mode* — REFUTED as architectural. A real
  `--debug` CLI redaction path JSON-logs raw `match_text` to stderr, but `pkg/redact`/stdin do not leak
  (nil observer). Fix is hashing/dropping 3 map keys — local.
- *RedactString vs RedactDocument diverge on position correlation* — REFUTED as architectural. The real
  concern (silently dropped matches passing unredacted) is a local fail-closed fix.
- *RedactionManager is bypassed by in-memory/web paths* — REFUTED as architectural. A shared substitution
  core already exists; remaining duplication is additive local cleanup.

---

## Evidence Index

| Gap | Strongest citations |
|---|---|
| 1.1 No ctx / unconditional `wg.Wait` (keystone) | `detector.go:29-38`; `validator_runner.go:88-141`; `worker_pool.go:228-231`; `resilience/retry.go:80-91` |
| 1.2 Two redundant engines | `scanner.go:122-123`; `enhanced_wrapper.go:30-64`; `validator_runner.go:74-78`; `dual_path_bridge.go:729-839` |
| 1.3 Validator panic crashes process | `dual_path_bridge.go:736-808`; `validator_runner.go:82-138`; `worker_pool.go:145-157` |
| 1.4 Errors silently swallowed | `dual_path_bridge.go:821-839`; `worker_pool.go:216-221`; `scanner.go:64-70,304-307`; `parallel_processor.go:106-119` |
| 2.1 Unbounded concurrency | `parallel_processor.go:36-39`; `validator_runner.go:74-141`; `redactors/manager.go:512-524` |
| 2.2 Adaptive governor dead | `parallel_processor.go:47-50`; `resource_monitor.go:189-247`; `adaptive_processor.go:325-353` |
| 2.3 Whole-file buffering | `file_router.go:27-28,172-218`; `scanner.go:289-297` |
| 2.4 Decompression amplification | `office-text-extractor.go` (unbounded `io.ReadAll`); `office-extractor.go:152` (10MB LimitReader) |
| 3.1 Dead manager indirection | `enhanced_integration.go:271-283`; `scanner.go:109-123`; `enhanced_wrapper.go:30-45` |
| 3.2 Dual `Validate`/`ValidateContent` | `detector.go:29-38`; `template/validator.go:58-60`; `dual_path_bridge.go:741` |
| 3.3 ~15-file validator onboarding | `creating_validators.md:577-596`; `cmd/main.go:821`; `factory.go:75-93`; `sarif/mapper.go:312-332` |
| 4.1 Per-match rescan, ad-hoc fixes | `ssn:190-233`; `ipaddress:287-308`; `phone:603-660`; `vin:498-539`; `personname:876-942` |
| 4.2 No input-shape/match budget | `passport:337-379`; `cloudresources:33-36`; `phone:319`; `ssn:251`; `ipaddress:332` |
| 5.1 Lossy provenance | `file_router.go:180-218`; `content_router.go:840-880`; `preprocessor.go:34-113` |
| 5.2 No extractor ctx; leak; no body-text timeout | `preprocessor.go:116-131`; `file_router.go:143-169` |
| 5.3 Hardcoded extension routing | `file_router.go:291-332`; `content_router.go:630-646`; `shared_utilities.go:91-124` |
| 6.1 Two redaction engines | `plaintext/redactor.go:362-365`; `replacement/replacement.go:4-7`; `strategies/synthetic.go:235-261` |
| 6.2 Unstructured observability | `observability/observer.go:56-67`; `scanner.go:88-92` |
| 6.3 Dead monitoring/performance | `internal/monitoring/` (zero importers); `internal/performance/` |
| 6.4 Config drift / untyped / no schema | `cmd/main.go:155-249`; `config.go:444-562`; `config.yaml` (51KB) |
