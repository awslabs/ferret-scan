# Design Proposal: Ferret Explain — an offline triage layer with an opt-in local-LLM upgrade path

**Status:** Draft for maintainer review
**Author:** (proposed)
**Scope:** Adds finding explainability + suppression-reason drafting (Tier 1, ships on), with a quarantined, build-tagged local-LLM adjudicator (Tier 3, ships off).
**Decision requested:** Approve the framing and Phase 1 scope before any code lands.

---

## 0. Why this doc leads with history

Ferret Scan **already shipped GenAI and deliberately removed it.** Amazon Textract (OCR), Transcribe (audio→text), and Comprehend (ML PII detection) were integrated behind an `--enable-genai` flag with cost estimation, then disabled-by-commenting (not deleted) with a full [`docs/GENAI_RESTORATION_GUIDE.md`](../GENAI_RESTORATION_GUIDE.md). The stated reason, verbatim from [`internal/validators/comprehend/validator.go:6-8`](../../internal/validators/comprehend/validator.go#L6-L8):

> "The comprehend-analyzer-lib dependency and AWS SDK v2 required for this functionality have been removed from go.mod to **reduce binary size** and **eliminate cloud service dependencies**."

**The lesson is explicit and binding: anything that re-introduces an outbound trust boundary or AWS-SDK weight into the core gets removed.** This proposal is designed to be the *anti-pattern* of what was removed — the default build adds zero `go.mod` dependencies and makes zero network calls.

### The four hard constraints (verified in code) any AI feature must satisfy

| # | Constraint | Evidence |
|---|---|---|
| 1 | **Privacy** — PII must not leak to external services | `pkg/redact` no-payload-logging design; `LogWriter` defaults to `io.Discard` ([`pkg/redact/types.go`](../../pkg/redact/types.go)); THREAT_MODEL trust boundaries |
| 2 | **Size / offline** — ~5–10MB static binary | `CGO_ENABLED=0`, `scratch` final stage, `GOPROXY=direct` ([`Dockerfile`](../../Dockerfile)) |
| 3 | **No AWS SDK (or heavy deps) in core** | `go.mod` intentionally excludes it — the exact thing removed with GenAI |
| 4 | **Supply chain** | TM-10 digest pinning; reproducible builds |

---

## 1. The problem this solves

The documented top user pain is **false-positive triage** at the pre-commit gate, and **thin/static explainability** of findings. The scanner is regex- + heuristic-driven; when it flags a test fixture, an example key in docs, or a high-entropy non-secret, the user gets a finding with a generic per-type help paragraph and a boilerplate "add a suppression" instruction.

Crucially, **the engine already computes rich triage signals** — `validation_checks`, `vendor`, `format`, `context_impact`, positive/negative keyword hits, test-pattern booleans — and stashes them on `Match.Metadata`. Today those are rendered only in **verbose mode**. The cheapest high-value move is to **promote that data to the point of decision** (the pre-commit summary, the PR comment, the suppression file), in plain language.

---

## 2. Design overview — two tiers

### Tier 1 — `SignalSynthesizer` (default build, pure Go, ships ON via `--explain`)
Deterministic synthesis of signals the engine already produced into:
- a plain-language **rationale** ("matched a Visa pattern, passed the Luhn check, and sits next to the keyword 'card number'"),
- a **verdict gloss** on the *existing* confidence (not an independent signal — see §5),
- a drafted **suppression justification** to replace the boilerplate `reason`.

**This tier is not AI, and we will not call it AI.** It is triage/explainability. Saying otherwise would be dishonest and would erode trust in a security tool. Its value is real but narrow: promoting existing data + drafting suppression reasons.

### Tier 3 — `LLMAdjudicator` (build tag `//go:build explain_llm`, ships OFF)
The genuine AI: an adjudicator that calls an **operator-supplied, loopback-by-default** OpenAI-compatible endpoint (Ollama / llama.cpp / vLLM) over stdlib `net/http`, to resolve what regex cannot — a number's *role* from sentence semantics, non-Western names, free-text secrets (the capability Comprehend gave, but provider-flexible and local). **Compiled out of the shipped binary.** This is the disciplined version of what was removed: opt-in, build-tagged, local-first, advisory-only.

> There is no "Tier 2" in the shipped product; the numbering reflects that the LLM tier is the third increment in the delivery plan.

---

## 3. Integration seams (all verified against current code)

### 3.1 Annotation rides on existing metadata — no interface change
`Match` already carries a generic metadata map ([`internal/detector/detector.go:58-72`](../../internal/detector/detector.go#L58)):

```go
type Match struct {
    Text       string
    Confidence float64
    Type       string
    Metadata   map[string]any   // <-- explanation rides here
    Validator  string
    Context    ContextInfo
    // ...
}
```

The explainer attaches a typed `Explanation` under `m.Metadata["explanation"]`. **No change to the `Validator` interface** ([`detector.go:29-38`](../../internal/detector/detector.go#L29)).

### 3.2 Post-detection seams — where `[]Match` is complete
The advisory pass runs after detection assembles the full slice, at:
- [`internal/core/scanner.go:172`](../../internal/core/scanner.go#L172) (`ScanFile` → `ScanResult`)
- [`internal/core/scanner.go:322`](../../internal/core/scanner.go#L322) (`ScanContent` → `ScanResult`)
- [`pkg/redact/engine.go:194`](../../pkg/redact/engine.go#L194) (`Engine.Redact`)

### 3.3 Two invariants the explainer MUST respect (verified)
1. **Never mutate `Confidence`, and run after the suppression hash.** `generateFindingHash` hashes `match.Confidence` to two decimals ([`internal/suppressions/suppression.go:170-174`](../../internal/suppressions/suppression.go#L170)). Mutating confidence would invalidate the repo's ~151KB of existing suppressions and (for the LLM tier) make hashes non-deterministic. Explanations are **advisory annotations only**.
2. **Extend `Match.Clear()` to wipe the new fields.** `Clear()` currently scrubs `Text`/`SecureText`/`Context` but **not `Metadata`** ([`detector.go:92`](../../internal/detector/detector.go#L92)). If we add explanation text to `Metadata`, `Clear()` must scrub it too, or we open a new PII-retention surface. **This is a required Phase 1 change.**

---

## 4. Proposed interface

```go
// internal/explain/explain.go  (default build, pure-Go, no tags)
package explain

import "github.com/awslabs/ferret-scan/v2/internal/detector"

type Verdict string // "likely_real" | "likely_test" | "uncertain"

type Explanation struct {
    Rationale           string  // plain-language "why this matched"
    Verdict             Verdict // gloss on EXISTING confidence, not a new signal
    DraftSuppressReason string  // human-readable, for --generate-suppressions
}

type Explainer interface {
    Explain(m detector.Match) Explanation
}

// SignalSynthesizer is the default, dependency-free implementation:
// pure templating over m.Type, m.Confidence, and m.Metadata signals.
type SignalSynthesizer struct{ /* ... */ }
```

```go
// internal/explain/llm.go  (//go:build explain_llm — compiled out by default)
//go:build explain_llm

// LLMAdjudicator implements Explainer against an OpenAI-compatible endpoint
// over stdlib net/http. Loopback-only unless --explain-allow-remote.
type LLMAdjudicator struct{ Endpoint string /* ... */ }
```

---

## 5. Output & confidence integration

- **Three-tier confidence is untouched.** Thresholds stay HIGH ≥ 90 / MEDIUM 60–89 / LOW < 60 ([`internal/formatters/text/formatter.go:96-98`](../../internal/formatters/text/formatter.go#L96)). Explanation is additive narrative.
- **The Tier-1 verdict is partly circular** — it's derived from the same test-pattern booleans that fed confidence. So it is rendered **only as a gloss on the existing confidence**, never as an independent claim, and **HIGH findings always surface regardless of verdict.** A security tool that talks a human out of a real secret is the worst possible failure; the design forbids it.
- **Pre-commit:** replace the static block in `getPrecommitResolutionGuidance` ([`internal/formatters/text/formatter.go:778`](../../internal/formatters/text/formatter.go#L778)) with per-finding rationale + verdict gloss + drafted reason.
- **`--generate-suppressions`:** thread the drafted reason through `GenerateSuppressionRules(matches, reason, enabled)` ([`internal/suppressions/suppression.go:453`](../../internal/suppressions/suppression.go#L453)). This is the one real refactor — three call sites: [`cmd/main.go:1797`](../../cmd/main.go#L1797), [`cmd/stdin.go:188`](../../cmd/stdin.go#L188), and the manager itself.
- **SARIF / PR comments:** enrich the per-result help (SARIF `helpUri`/help text, [`internal/formatters/sarif/models.go:54`](../../internal/formatters/sarif/models.go#L54)) from the explanation, flowing into GitHub code-scanning annotations.
- **Web UI:** prefill the drafted reason in the "add as suppression" flow ([`internal/web/server.go`](../../internal/web/server.go)).

---

## 6. Privacy guardrails (enforced by structure, not by promise)

- **Keep explanation OFF the public `Finding`/`AuditRecord` structs by default.** The no-payload-logging guarantee is enforced by struct shape in `pkg/redact/types.go`. Expose explanation only via an explicit opt-in accessor (analogous to `FindingsWithMatchText`), or as count-only verdict tallies. Default: nothing on the wire/log.
- **`Match.Clear()` scrubs explanation fields** (see §3.3).
- **LLM-tier output sanitizer:** before storing any LLM `Rationale`, structurally strip any verbatim span equal to `m.Text` — do not trust the model to keep the secret out of its own explanation. Route all LLM observability through the existing `LogWriter` (default `io.Discard`).
- **LLM endpoint policy:** `--explain-endpoint` defaults to `http://127.0.0.1:11434`; a non-loopback endpoint is **refused unless `--explain-allow-remote`** is also passed, with a loud egress warning — remote inference is a hard trust-boundary crossing, treated like the old `--enable-genai`.

---

## 7. CLI surface (mirrors the `--enable-genai` precedent)

| Flag | Default | Effect |
|---|---|---|
| `--explain` | off | Enable the Tier-1 synthesizer |
| `--explain-backend=synth\|llm` | `synth` | `llm` errors unless built `-tags explain_llm` |
| `--explain-endpoint=<url>` | `http://127.0.0.1:11434` | LLM endpoint (Tier 3) |
| `--explain-allow-remote` | off | Required to use a non-loopback endpoint; prints an egress warning |

---

## 8. Phased delivery

**Phase 0 — Validate the premise (1–2 days; do first).**
Hand-write ~10 explanations from real findings on this repo's own 151KB suppression corpus. If they read as boilerplate, cut scope to just suppression-reason drafting. Cheap insurance against the "circular verdict" risk.

**Phase 1 — MVP: synthesizer + pre-commit (M, ~1 week).**
`internal/explain` + `SignalSynthesizer`; wire the three seams (metadata-only, no signature changes); replace the pre-commit block; **extend `Match.Clear()`**. Ships value under all four constraints, no AI, no new deps.

**Phase 2 — Suppression-reason drafting + SARIF/web (M, ~1 week).**
Thread per-finding reasons through `GenerateSuppressionRules` (the ~3-call-site refactor); SARIF help enrichment → PR comments; web UI prefill.

**Phase 3 — Optional LLM tier (L, separate track, off by default).**
`//go:build explain_llm` package; OpenAI-compatible client; strict JSON-schema output parsing; prompt-injection delimiting; output sanitizer; fail-closed-to-original-confidence. Adds the project's **first build tag** — establish a clean CI matrix lane for it. Ships disabled; advisory only; **never gates CI**. Requires a small labeled real-vs-fixture eval harness before it is recommended to anyone.

### Implementation status (as built)

- ✅ **Phase 1a** — `internal/explain` package (`Explainer`, `Explanation`, `SignalSynthesizer`, `Annotate`/`FromMatch`); `Match.Clear()` scrubs the annotation. Unit-tested.
- ✅ **Phase 1b** — `--explain` flag (off by default); annotation wired at the post-detection seam; text verbose + pre-commit output render the explanation.
- ✅ **Phase 2** — first-class explanation across **JSON/YAML** (typed field, lifted out of the raw metadata blob), **SARIF** (message + structured property), and **gitlab-sast** (sanitized description). `--generate-suppressions` now writes the per-finding **drafted reason** (falling back to the generic reason when unannotated). Cross-format + suppression-reason tests added.
  - Design note: rather than change the `GenerateSuppressionRules` signature, the drafted reason is read per-match via `explain.FromMatch` inside the generator — same effect, zero call-site churn. The CLI annotates the full match set *before* the suppression split so both the generator (operates on all matches) and the formatters (unsuppressed subset) see it.
  - **Web UI prefill (done):** the web `/scan` path annotates findings after the filename rewrite, so the JSON each finding carries includes `explanation.draft_suppress_reason`; the "Add Suppression" button passes it (via a `data-reason` attribute, attribute-escaped) to prefill the reason field, editable before saving.
  - Verified round-trip: a suppression rule generated from an annotated finding still suppresses that finding (and its un-annotated equivalent) on re-scan — the explanation never changes the suppression hash. Regression-tested.
- ⬜ **Phase 3** — not started.

---

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Tier 1 is "AI in name only" → credibility hit | Label it triage/explainability, not AI. Lead the changelog with the honest framing. |
| A `LIKELY_TEST` gloss lulls a human into dismissing a real secret | Verdict is a gloss on existing confidence, never independent; HIGH findings always surface; never auto-suppress; generated suppressions are `enabled=false` for human review. |
| Suppression-hash invalidation / non-determinism | Explainer runs after hashing and never mutates `Confidence`. |
| LLM rationale leaks payload bytes | Explanation off `Finding`/`AuditRecord`; `Clear()` wipes it; LLM tier span-strips `m.Text`; observability via `io.Discard`. |
| LLM tier re-opens an outbound trust boundary | Off by default, build-tagged out of the binary, loopback-only unless `--explain-allow-remote`, loud warning — the `--enable-genai` posture. |
| Phase 2 signature change ripples | Scoped to ~3 call sites; covered by existing suppression tests. |

---

## 10. Explicitly NOT doing

- **Not** bundling model weights; **not** adding a CGO inference runtime; **not** shipping ONNX/transformer NER — infeasible under `CGO_ENABLED=0` with no mature pure-Go runtime; would break the size constraint.
- **Not** adding any AWS SDK or heavy dependency to core `go.mod`.
- **Not** re-enabling Textract/Transcribe/Comprehend or any cloud API in the default build.
- **Not** letting any AI tier mutate confidence, gate CI, or auto-suppress.
- **Not** exposing explanation text on the payload-free public `Finding`/`AuditRecord` by default.
- **Not** making the LLM tier part of the released artifact — it is a separate opt-in build.

---

## 11. How this was produced

Multi-agent review: 5 parallel subsystem readers (architecture, AI history, detection/confidence engine, product surface, constraints) → 5 independent enhancement proposals from distinct angles → 15 adversarial judges (Go-feasibility / privacy-fit / user-impact lenses) → synthesis. Ranked outcomes (total /40): **Ferret Explain 30**, opt-in LLM adjudicator 29, free-text PII validator 27, ONNX NER re-scorer 23 (rejected on CGO/size). All load-bearing integration claims above were independently re-verified against current `main`.
