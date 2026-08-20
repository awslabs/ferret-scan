<!--
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
-->

# The score corpus — measuring detection *quality*

`make score` answers one question the rest of the test suite cannot: **did this
change make the tool better or worse?**

Everything else in `go test ./...` answers *"did anything change?"* — a different
and weaker question. The golden corpus says so itself
([`internal/goldencorpus/corpus.go`](../../internal/goldencorpus/corpus.go)):

> The purpose is **NOT** to assert that any particular detection is "correct" — it
> is to assert that detection, confidence scoring, output formats, and redaction do
> not **CHANGE**.

So a change that trades a real detection for a quieter report passes the golden net
(regenerate the snapshot and move on) and passes every unit test. `make score` is
what refuses it.

---

## Contents

- [Why one number is not enough](#why-one-number-is-not-enough)
- [The four layers](#the-four-layers)
- [The three detection numbers](#the-three-detection-numbers)
- [How ground truth works](#how-ground-truth-works)
- [Running it](#running-it)
- [Does this run in CI?](#does-this-run-in-ci)
- [The gate policy](#the-gate-policy)
- [Adding a case](#adding-a-case)
- [Adding a check](#adding-a-check)
- [Anti-vacuity: how we know the gate still bites](#anti-vacuity-how-we-know-the-gate-still-bites)
- [Known gaps, recorded on purpose](#known-gaps-recorded-on-purpose)
- [Traps found while building this](#traps-found-while-building-this)

---

## Why one number is not enough

A single precision/recall pair is **blind to the failure class this tool actually
ships**. Three regressions, each measured on `main`:

| mutation | full test suite | detection score | redacted artifact |
|---|---|---|---|
| a "fixed-width report noise" filter before the SSN regex | **rc=0, 65 pkgs ok** | 111 → 108 TP | **3 whole-value leaks** |
| revert [PR #250](https://github.com/awslabs/ferret-scan/pull/250) (Office redactor) | rc=1 | **bit-identical** | **1 container leak** |
| band-demote a bare 9-digit SSN | **rc=0, 65 pkgs ok** | `recall_all` unchanged | no leak, but pre-commit stops blocking |

Read row two carefully: **reverting a real cleartext-leak fix leaves the detection
score bit-for-bit identical.** The value was detected correctly and then dropped
during redaction. A precision/recall gate reports PASS on a shipped leak.

Rows one and three pass the *entire* existing suite today. That is the gap this
package fills.

---

## The four layers

A labelled value passes through four stages before a user is protected, and **each
can fail while the others look perfect**.

| layer | question | what breaks it alone |
|---|---|---|
| **validator** | was the value detected, with an acceptable type, at or above its band? | a veto, a scoring change, a regex narrowing |
| **redaction** | after redaction, are the value's bytes gone from the artifact? | overlap resolution, a container repack bug ([#250](https://github.com/awslabs/ferret-scan/pull/250)) |
| **suppression** | does a rule silence *exactly* the finding it names? | an over-broad hash → a leak with an audit trail saying it was approved |
| **executable** | does the real CLI report it, exit correctly, and write the file? | a streaming regression ([#193](https://github.com/awslabs/ferret-scan/pull/193)), an exit-code inversion ([#270](https://github.com/awslabs/ferret-scan/pull/270)) |

The executable layer exists because everything else calls the library in-process,
and **that is not the product**. A library that scores perfectly behind a CLI that
prints nothing protects nobody — and that exact regression shipped in #193: rc=1
with zero bytes on stdout *and* stderr.

---

## The three detection numbers

Within the validator layer, recall is reported **twice**, because the tool has two
independent consumers with different thresholds.

| metric | bands | the surface it describes |
|---|---|---|
| `recall_all` | **all**, including LOW | **redaction.** Redaction is confidence-blind: measured, a bare 9-digit SSN at confidence 50 still redacts to `*****5728`. A label that stops being detected *at all* is a cleartext leak, so this floor is hard. |
| `recall_hm` | ≥ MEDIUM | **the pre-commit exit code.** The only surface a band drop moves: the same finding at confidence 60 gives rc=0 under `FERRET_PRECOMMIT_EXIT_ON=high` and rc=1 under `=medium`. |
| `prec_hm` | ≥ MEDIUM | **the review surface.** Precision over findings a human actually sees. |

A band demotion leaves `recall_all` untouched and moves `recall_hm`. Reporting only
one of them would miss half the story.

---

## How ground truth works

**Labels come from bytes planted in the fixture, never from what the tool reports.**
If labels were harvested from tool output, the corpus would certify today's
behaviour as correct by construction — a tautology.

A `Label` is keyed by `(line, value, occurrence)`. There is deliberately **no byte
span**, because `detector.Match` has no offset field — only `LineNumber`.
Reconstructing a span means re-searching the line, which is ambiguous exactly when
it matters (a value twice on one line). `TestValueOccursOnce` asserts the invariant
that makes the line+value key sound, and fails loudly the day a case violates it.

`MinBand` records what the tool produces **today**. The label's *existence* is
ground truth; its band is a *measurement* and a ratchet floor.

Three properties keep the numbers honest:

- **No aspirational labels.** `TestEveryLabelIsSatisfiedToday` rejects any label the
  tool cannot currently satisfy. A permanent false FN would sit in the denominator
  forever and never move. Real gaps go in the quarantine (below).
- **No machine dependence.** `config.LoadConfig("")` — the *pure* default, not
  `LoadConfigOrDefault("")`, which discovers `~/.ferret-scan/config.yaml`. Measured:
  that discovery changed the enabled-validator count (2 vs 0) depending on the home
  directory. Suppressions are nil for the same reason.
- **No suppression leakage.** `TestHygiene` asserts `SuppressedCount == 0` on every
  case, so nothing is silently excluded from the score.

---

## Running it

```bash
make score                  # score all four layers, ratchet against the baseline
make score-update           # re-lock the baseline after an intentional change
make score-mutation-check   # prove the gate still catches real regressions
```

Sample output:

```
scorecorpus  141 cases, 177 gated labels, 16 check(s)

check      TP  FN(miss)  FN(band)  FP(H+M)  FP(low)  recall_all  recall_hm  prec_hm
CREDIT_CARD    3         0         0        0        0      1.0000     1.0000   1.0000
EMAIL          3         0         0        2        0      1.0000     1.0000   0.6000
IP_ADDRESS     2         0         0        0        0      1.0000     1.0000   1.0000
SSN          155         0         0       45        0      1.0000     0.9935   0.7739
...
TOTAL        177         0         0       47        0      1.0000     0.9944   0.7892

redaction sink (core.RedactFile, label-driven; 169 labels)
  strategy              whole_leak   residue4
  simple                         0          0
  format_preserving              0        817

suppression layer (a rule must silence exactly what it names)
  rules exercised 55   silenced 55   collateral 0   ineffective 0
```

Cost, measured: **~1.0s** for the in-process layers, ~5s including the executable
layer (which compiles the binary), ~16s under `-race`.

---

## Does this run in CI?

**Yes, automatically — with one caveat that needed fixing.**

CI runs `go test -race -count=1 $(go list ./... | grep -v /tests/integration)` on
**ubuntu, macos and windows**, so every test in this package runs on all three
platforms without any workflow change.

The caveat: the workflow is **path-filtered** to `**.go`, `go.mod`, `go.sum` and the
workflow file. `testdata/baseline.json` matches none of those — so a
**baseline-only commit would have received zero checks**, which is precisely the
commit shape that most needs them, since editing the baseline is how a quality
regression gets blessed. This PR adds `internal/scorecorpus/testdata/**` to both
path lists.

What is **not** in CI, deliberately:

| | why |
|---|---|
| `make score-mutation-check` | it edits tracked source files to inject regressions. A crash mid-run leaves the tree dirty. Run manually when changing the gate. |
| the `synthetic` redaction strategy | it substitutes generated values and is nondeterministic **by design** (measured 9/21/25 bytes of residue across runs). Gating it would flake. Printed, never gated. |
| real-document scoring | see [TEST_PLAN.md](TEST_PLAN.md) dimension 9. Real customer documents cannot be committed; that measurement stays manual. |

Cross-platform notes that were needed to make this safe:

- `os.DevNull`, not the literal `/dev/null` — the latter does not exist on Windows,
  and the CLI would fall back to discovering the developer's config.
- `.exe` suffix when building the test binary on Windows.
- All fixtures are Go string literals with non-ASCII bytes written as explicit
  `\uXXXX` escapes, so a re-encoding editor or a CRLF checkout cannot alter them.
  `TestSourceIsASCII` enforces this; `TestByteSensitiveFixturesSurvive` proves the
  escapes still decode to the bytes the BOM and em-dash cases exist to test.

---

## The gate policy

Deliberately **asymmetric**, because the two error directions are not equally
serious for a redaction tool.

| dimension | policy | reason |
|---|---|---|
| `tp` per check | **hard floor**, no allowance, no cross-check offset | a lost detection is a cleartext leak |
| `tp_high_medium` per check | **hard floor** | the only surface a band drop moves (pre-commit rc) |
| `fp_high_medium` per check | ceiling = baseline + `FPAllowance[check]` (default **0**) | FPs should go down; headroom is granted in code, visible in the diff |
| `whole_leak` per strategy | **hard 0-increase** | a surviving value is a leak, full stop |
| `residue4` per strategy | non-increase | tracks mask *depth*; see the NPI note below |
| suppression `collateral` / `ineffective` | **hard floor** | both directions are real failures |
| corpus size, quarantine size | **hard floor** | deleting a case cannot be a way to pass |
| **an improvement** | **reported, does NOT fail** | maintainer decision, 2026-08-05 |

On that last row: the alternative — failing with *"run `make score-update`"* — keeps
the floor rising automatically but taxes every PR that makes the tool better.
**Accepted tradeoff:** a win that is never locked in can be given back later without
the gate noticing. The `IMPROVED` lines exist to make that easy to spot.

Why `residue4` is gated rather than just `whole_leak`: the tempting argument
*"redaction covers the byte anyway"* is **measurably false**. `NPI: 1234567893`
redacts to `**********` under MEDICAL_ID but `******7893` under PHONE — the shipped
default. Mask depth is a real product property, and this is the only number tracking
it.

---

## Adding a case

1. Write the fixture and **verify the value against the real CLI first**:
   ```bash
   ferret-scan --file fixture.csv --config /dev/null --checks SSN --show-match --limit 0
   ```
2. Add a `Case` to `cases_<check>.go` with `Origin` (provenance) and `Rationale`
   (*why* this shape must behave this way, in user terms). Both are enforced —
   review is the only defence against a wrong label, and an unexplained label is
   unreviewable.
3. Set `MinBand` to what the tool produces today.
4. `make score-update`, then **read the diff** and explain it in the PR body.

A case that the tool cannot satisfy goes in the **quarantine** list instead:
counted, printed, never scored. The count is baselined, so moving something in or
out fails the gate until explained — the hatch cannot become a laundering channel.

---

## Adding a check

The machinery is **check-agnostic**. `registry.go` is the only coupling: everything
that scores reads `GatedCases()`, never a per-check variable.

```go
Register(checkCorpus{
    Check:       "PHONE",
    Gated:       PhoneCases,
    Quarantined: PhoneQuarantine,
    Containers:  PhoneContainerCases,
})
```

No edit to `score.go`, `sink.go` or `baseline.go` is needed.
`TestChecksAreReal` validates every name against `core.CheckNames()` — necessary
because **an unknown check name fails OPEN**: measured, `Checks: ["SSNN"]` returns
`err=nil` and zero matches, which would score precision 1.000 over an empty
numerator.

---

## Anti-vacuity: how we know the gate still bites

A quality gate has one dangerous failure mode: it keeps printing a number that no
longer means anything. `make score-mutation-check` breaks the product on purpose and
confirms the gate goes red. Every mutation must **compile** — a build failure proves
nothing.

| # | mutation | layer it moves | layer it does NOT move |
|---|---|---|---|
| control | none | — | gate is green |
| M1 | skip lines with 3+ consecutive spaces before the SSN regex | validator **and** redaction sink | — |
| M2 | revert PR #250 (`lineKey{number, text}` → `text: ""`) | **container sink only** | detection is bit-identical |

Plus 20 self-tests that guard the *harness*, including:

- `TestLabelsResolve` — every label exists in its own fixture
- `TestValueOccursOnce` — the invariant behind the no-span design
- `TestEveryLabelIsSatisfiedToday` — no aspirational labels
- `TestCorpusHasPositivesAndNegatives` — an all-negative corpus scores 1.000 at
  recall 0 and looks excellent while proving nothing
- `TestBandsMatchShared` — the gate's bands track `shared.GetConfidenceLevel` at
  59.9 / 60 / 89.9 / 90
- `TestContainerCaseWouldCatchTheLeak` — pins the span geometry that makes the
  container case meaningful (see below)
- `TestScorerScalesLinearly` — the gate itself is linear (measured **2.00× per
  doubling**, n=125…2000) with a vacuity floor asserting every label matched
- `TestScoreDeterminism` / `TestSinkDeterminism` — identical results across repeated
  runs. A gate that moves on its own gets ignored, then removed.

---

## Known gaps, recorded on purpose

Recorded rather than hidden, because an absent measurement reads as "covered".

| gap | detail |
|---|---|
| **2 unscored checks** (was 3) | `OTP` and `SOCIAL_MEDIA` have no case yet. **Both validators work**; an earlier draft of this doc wrongly called them "inert" after probing them with values that are out of scope *by design*. `OTP`'s scope is provisioning **secrets** (`otpauth://` URIs, base32 seeds, recovery codes), not transient 6-digit codes — a bare 6-digit number carries no structure, so matching it would be an FP factory. `SOCIAL_MEDIA` is config-gated by design and works with the shipped `examples/ferret.yaml` patterns, which are **valid RE2** (verified by compiling them); scoring it needs per-case config support. Listed in `UnscoredChecks` — a **corpus TODO, not a product bug**, enforced by `TestUnscoredChecksAreAccountedFor`. **`IP_ADDRESS` is now scored**: it correctly never reports RFC 5737 documentation ranges or well-known resolvers, and detects `13.52.11.22` fine — so the corpus gained both a positive case and a negative one pinning the reserved-range exclusion. |
| **45 SSN false positives** | SSN-shaped values under `tracking_number` / `order_id` / `zip_code` headers reach HIGH. A real defect, **baselined so a fix can be measured** rather than argued. A baseline is a floor to ratchet, never a statement of intent. |
| **PERSON_NAME hyphen recall** (**real validator bug**) | A name with a hyphen in BOTH parts is never matched in full, and the shortfall reaches the redacted file. Measured at the sink: `Anne-Marie Delacroix-Webb` → `Anne-********************`; `Mary-Jane Watson-Parker` → `****************-Parker`; `Jean-Claude Van Damme` → `Jean-****************`. The validator emits two overlapping partials (e.g. 91 and 66) and never the whole span. One hyphen is fine (`Anne-Marie Webb`, `Margaret Delacroix-Webb` both match in full), so the defect is specifically two hyphens. Quarantined in the corpus with the leak documented; needs a validator fix, not a corpus fix. |
| ~~24 contradictory SSN fixtures~~ | **RESOLVED 2026-08-05: labelled TP and now scored.** Honest headers for non-US national IDs (`sin`, `nino`, `personnummer`, `codice fiscale`) and generic government ones (`national_id`, `govt_id`, `tin`). Decided on evidence: the SSN validator's own `positiveKeywords` already contain `"national id"`, `"government id"`, `"federal id"`, `"tax id"` — it was **built** for these, so the behaviour is intent. Also, the options were not symmetric: labelling them FP would make *deleting real PII detections* score as an improvement. Measured: SSN precision 0.7115 (excluded) → **0.7739** (as TP); it would have been 0.5550 as FP. Cost, and the real substance of the decision: the recall floor rises 111 → **155**. |
| **4 cases flagged unredactable that are no longer** | `.tsv`, `.html` and `.sql` used to have no registered redactor. Since #359 the CLI redacts **any file whose bytes are text**, verified: each of those extensions now produces a redacted copy. The four corpus cases still carry `Redactable: false`, so the sink metric skips cases it could now check — coverage is **understated**, and a leak in those types would not be caught by the score. Tracked as the corpus residual of #315; flipping the flags moves the sink baseline, so it belongs to that change rather than to a doc edit. |
| **Hand-labelled** | A *wrong* label is invisible to every test here. Only review catches it. Hence mandatory `Origin` + `Rationale`. |

---

## Traps found while building this

Recorded because each one produced a *confidently wrong* number, and each will
recur.

**A `.csv` extension is worth +20 confidence.** On byte-identical content, changing
only the virtual path: `55 → 75` and `70 → 90` (MEDIUM → HIGH). The harness
originally used an extension-less `VirtualPath` and recorded two band drops that no
user would ever see. `scanConfig` now carries the real extension. This is the same
four-way "is it tabular?" disagreement tracked elsewhere in the backlog.

**My container case was vacuous.** The first `.docx` fixture used the author
`"Jane Smith"` and **passed under the reverted-#250 mutation** — meaning it would
have shipped a gate that certifies a cleartext leak. Span subsumption only fires
when the metadata span strictly *contains* the body span, so the author has to be
long enough. `TestContainerCaseWouldCatchTheLeak` now pins that arithmetic.

**A container hides its payload.** Grepping the raw `.docx` bytes for an SSN finds
nothing even when the SSN is present — the parts are DEFLATE-compressed. The only
honest check opens the ZIP and reads every part.

**`EnablePreprocessors` is required for containers.** Without it `ScanFile` returns
*"file type not supported for processing"* and never opens the archive — a silent
no-op that the well-formedness test caught.

**Residue must be measured against the original, not in isolation.** For the email
`alice.morgan@northwind-labs.com` in a CSV whose neighbouring column holds
`A Morgan`, a *perfectly redacted* document reported 5 bytes of residue: the
substring `organ`, from the name. Any substring of any value can occur innocently
elsewhere, so an isolated scan measures coincidence, not leakage.

**Use `core.RedactFile`, never `pkg/redact`.** The latter is in-memory
single-content and cannot reach container parts, where the most serious leaks live.
The #250 leak is invisible through it.

---

## Relationship to the other test layers

| | golden corpus | score corpus | TEST_PLAN §9 |
|---|---|---|---|
| asks | did output **change**? | is output **right**? | does it work on **real** documents? |
| pass means | bytes match the snapshot | labels found, nothing leaked | reviewed by a human |
| catches | unintended drift | quality regressions | everything synthetic data misses |
| misses | a wrong-but-stable detection | a formatting change | nothing, but cannot be automated |
| runs | CI, 3 OSes | CI, 3 OSes | manual |

They share **no code**: this package has its own canonical sort and its own OOXML
builder, and imports nothing from `internal/goldencorpus`, so a rename there cannot
produce a merge that is textually clean and does not compile.

When the two disagree — a wart-fixing PR looks like a golden regression *and* a
score improvement — **the score wins**: regenerate the golden files and say so in
the PR body.
