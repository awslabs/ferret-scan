# Golden Corpus — Behavior Regression Net (v2 Phase 0)

This package is the **behavior-locking regression net** for the v2 architectural
consolidation described in [docs/proposals/V2_ARCHITECTURE.md](../../docs/proposals/V2_ARCHITECTURE.md).
It exists so that the structural refactors in later phases (collapsing the bridge
stack, shared scanning primitives, a promoted public API) can be proven
**behavior-preserving** rather than merely asserted to be.

## What it locks

1. **In-memory scan → format output** ([golden_test.go](golden_test.go), `TestGoldenScanFormats`)
   — every `Case` is scanned through the real `core.ScanContent` path and
   rendered through every output format (text, json, csv, yaml, junit,
   gitlab-sast, sarif). Snapshotted under [testdata/golden/](testdata/golden).

2. **File scan → format output** ([golden_file_test.go](golden_file_test.go),
   `TestGoldenFileScanFormats`) — every `FileCase` is written to a real temp file
   and scanned through `core.ScanFile`, exercising the **worker pool**, the
   **FileRouter** (`CanProcessFile` / `CanContainMetadata` routing), and — for the
   synthesized `.wav` case — the **metadata / dual-path branch** that
   `core.ScanContent` skips entirely. This is the coverage Phase 2 (bridge-stack
   collapse) most needs.

3. **File-vs-content parity** (`TestFileContentParity`) — asserts that for
   plain-text/source inputs, `ScanFile` and `ScanContent` produce identical
   findings for identical bytes. The file-path machinery must not change *which*
   matches a document-body validator produces. (Metadata-bearing cases are
   excluded, since the file path legitimately adds the metadata branch.)

   A diff in (1) or (2) means detection, confidence scoring, or formatting
   changed.

4. **Redaction output** (`TestGoldenRedact`) — each case is redacted via the
   public `pkg/redact` engine under the two deterministic strategies (Simple,
   FormatPreserving) and the redacted text + findings are snapshotted. Synthetic
   strategy is excluded because it uses randomness and is not byte-stable.

5. **Algorithmic complexity** ([complexity_guard_test.go](complexity_guard_test.go),
   `TestValidatorComplexityIsSubQuadratic`) — guards against reintroducing the
   O(n²) per-line rescan pattern the audit found. It scales a dense single-line
   input 4× and asserts the work grows roughly linearly (not quadratically). This
   is the guardrail for Move C (shared scanning primitive).

   The growth measurement itself lives in `internal/perfguard`, shared with the
   SVG extraction guards. It is a ratio of minimum **CPU** readings with GC
   disabled, not a wall-clock median — that package's doc comment carries the
   measurements behind each choice, including the loaded run where a wall-clock
   median ranked a genuine O(n²) validator *below* a linear one. Because the
   estimator reads process-wide CPU time, no test in this package may call
   `t.Parallel`; `TestNothingInThisPackageRunsInParallel` enforces that.

## Determinism

The scan pipeline aggregates matches in goroutine-completion order, and several
output paths carry run-to-run variance. The harness neutralizes all of it so
snapshots are byte-stable:

- `CanonicalSort` imposes a total order on matches before formatting.
- A **fresh formatter instance per case** (not the global `formatters.DefaultRegistry`
  singleton), for case isolation. This originally worked around the SARIF
  formatter's `RuleManager` accumulating rules across `Format()` calls; that is
  fixed in product code now (see the resolved note below), but per-case instances
  stay so the snapshot cannot be polluted by per-instance state in any formatter.
- `NormalizePaths` replaces the per-run `t.TempDir()` path (stamped into
  `Match.Filename` and metadata `source_file`/`original_file`) with `<TMPDIR>`.
- `NormalizeOutput` replaces timestamps with `<TIMESTAMP>`, canonicalizes JSON
  object-key order, and normalizes the gitlab-sast `ferret-<hash>` vulnerability
  id (a SHA256 over `filename:line:type`, so path-coupled).

  It deliberately does **not** normalize array order any more. It used to sort the
  SARIF `tool.driver.rules` array and the gitlab-sast "Additional Information"
  bullets, which papered over Go map iteration order in the formatters themselves.
  Both now emit in sorted order at the source, so re-sorting here would only
  re-hide a regression — **this snapshot is the guard for those two emit paths.**
  Reverting the sort in `sarif/rules.go` alone fails the corpus.

These normalizations lock the *content* of the output, not incidental ordering.
A change to *what data appears* is still caught.

> **Resolved.** This section used to describe a latent bug surfaced while building
> this net: the SARIF formatter registered in `formatters.DefaultRegistry` is a
> process singleton whose `RuleManager` was never reset between `Format()` calls,
> so the rules array it emitted depended on everything formatted earlier in the
> same process — benign for the CLI (one format call per process) but real
> cross-invocation contamination for a long-lived embedder such as the web server.
>
> `sarif.Formatter.Format` now builds a fresh `RuleManager` and mapper per call, so
> the rules array derives only from that call's matches. Covered by
> `TestSARIF_NoRuleAccumulationAcrossCalls` and
> `TestSARIF_FormatIsIdempotentAcrossCalls` in
> `internal/formatters/sarif/accumulation_test.go`.
>
> The harness still uses a fresh formatter per case. That is no longer a
> workaround — it is case isolation, and it keeps the snapshot honest if a future
> formatter grows per-instance state.

## Workflow

```bash
# Run the net (compare against committed goldens):
go test ./internal/goldencorpus/...

# Skip the slower complexity guard:
go test -short ./internal/goldencorpus/...

# After an INTENTIONAL behavior change, regenerate and review the diff:
UPDATE_GOLDEN=1 go test ./internal/goldencorpus/...
git diff internal/goldencorpus/testdata/golden/   # inspect every change before committing
```

**Rule of thumb during the v2 consolidation:** a refactor that is meant to be
behavior-preserving must leave `go test ./internal/goldencorpus/...` green with
**zero** `UPDATE_GOLDEN` regeneration. If a golden file changes, stop and confirm
the change is intended before regenerating.

## Adding cases

Append to `Cases` in [corpus.go](corpus.go) (name, description, checks, input),
then run `UPDATE_GOLDEN=1 go test ./internal/goldencorpus/...` to materialize the
snapshots. Keep inputs small and focused; use realistic, non-denylisted secret
values for positives and known fakes only where a negative is expected.

> Note: the matched substrings appear verbatim in the redaction snapshots and in
> `--show-match` formatter output. This is acceptable for this local test corpus
> (synthetic/example data only — never real secrets). Do not add real credentials.
