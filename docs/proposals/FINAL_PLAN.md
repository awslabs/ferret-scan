<!--
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Final plan: what to fix, in what order, and why

Status: 2026-08-01. Supersedes the ordering in `ARCHITECTURE_AND_PLAN.md`; that document remains
the architectural description and the evidence record.

This plan was written after an independent verification pass in which I re-tested the claims I had
been repeating. **Three of them were wrong or incomplete**, and correcting them changed the
ordering. Those corrections are in §5, because a plan built on unverified claims is worth less than
the claims it rests on.

---

## 1. What changed from my own verification

| Claim I had been carrying | What testing showed |
|---|---|
| "`--limit` is ignored by junit/csv/gitlab-sast/sarif" | **Wrong.** All four honour it. The real defect is worse: **four formats truncate SILENTLY at the DEFAULT limit of 200** — `sarif`, `csv`, `junit` emit 200 of 300 findings and never disclose the true total. `json`, `yaml`, `text`, `gitlab-sast` do disclose it. A CI gate consuming SARIF sees 200 of 300 by default. |
| "reported ≠ redacted at exit 0, all matches log `match_redaction_failed`" | **Incomplete and understated.** Reproduced with a worse shape: a `.docx` where **every part comes out byte-identical** — zero redaction applied — while 5 findings are reported at rc=0 and **nothing** logs `match_redaction_failed`. The output md5 differs only from zip re-compression, so a `cmp`/md5 check reports "differs" and misleads. |
| "the phone veto is a phone problem" | **Wrong — it is systemic.** The same prefix-a-character trick suppresses `VISA`, `DRIVERS_LICENSE` and `MEDICARE_MBI`, and the sink confirms all three sit in cleartext in the redacted output. This is 3+ validators, not one, which changes the fix from a one-file change to a pattern change. |

And one hypothesis I would have accepted that turned out **false**:

- "confidence is saturated at 100, so the bands carry little information." **Not true.** Over varied
  content: 11 findings, **10 distinct confidence values** spanning 33–100, only 2 at the ceiling.
  The scale is working. I have removed the recalibration item that assumed otherwise.

One reassuring measurement worth stating, because it is the counterweight to the veto findings:

- The negatives that the vetoes exist to suppress **are** suppressed correctly. A git SHA, a
  version string `1.2.3.4`, and an `ami-050451375729` resource id all produce **zero** findings.
  Any veto fix must preserve this. Removing the vetoes outright would be a bad trade.

---

## 2. The confirmed defect list, ranked

Ranked by (likelihood × impact). "Ordinary" means no attacker and no unusual document.

| # | Defect | Who it affects | Sink verified |
|---|---|---|---|
| **1** | **Office redactor silent no-op** — a `.docx` can come out with every part byte-identical, findings reported, rc=0, no error | **Ordinary.** Any `.docx` whose XML the redactor's matcher does not handle | Yes — SSN + PAN cleartext in "redacted" output |
| **2** | **Adjacency veto drops findings across ≥3 validators** — `xaccount4532015112830366`, `ref-D123-4567-8901`, `x1EG4-TE5-MK73` all undetected | Mostly **crafted**, but plausible by accident in machine-generated data (IDs concatenated without separators) | Yes — card, licence, MBI all cleartext |
| **3** | **Nested container body unscanned at depth 2** — `.docx` inside `.docx` | **Ordinary.** A document embedded in a document | Yes — SSN cleartext inside `word/media/inner.docx` |
| **4** | **Silent truncation at the default limit** in `sarif`, `csv`, `junit` | **Ordinary**, and worst in CI where SARIF is machine-consumed | N/A — omission, not a redaction failure |
| **5** | **9 of 11 confidence-policy keys unreachable** — `log_penalty`/`code_penalty` never fire; `tabular_boost` gives a CSV **+40** on an SSN | **Ordinary.** Over-reports on logs and source, over-trusts CSVs | N/A — precision, not a leak |
| **6** | Same-span double report (`NPI` 100 + `PHONE` 10 on identical bytes) | Ordinary, cosmetic | Verified **not** a leak: redaction emits one token; bands unaffected |

Defects 1–3 are the same failure class: **silent and lossy**. The tool cannot tell the operator that
it failed to protect something. That class is what this plan is organised around.

---

## 3. The plan

### Phase 0 — make silent loss impossible (do this first, it is cheap)

The reason defects 1–3 survived is not that they are subtle; it is that **nothing asserts the
sink**. One invariant, enforced once, converts all three from silent to loud:

> **Every reported finding must be either demonstrably absent from the redaction output, or
> reported as unredacted.** No third outcome.

`internal/parallel/parallel_processor.go` already has an `unredactedFiles` diagnostic for exactly
this, and it does **not** fire for defect 1 — so the plumbing exists and the check is missing.
Add it, wire it to `--fail-on-incomplete` (exit 3) as #238 did for unreadable files, and defect 1
becomes a loud error rather than a false success.

This is small, it is a correctness fix in its own right, and every subsequent fix inherits a real
gate. Doing it first means defects 1–3 cannot silently regress later.

### Phase 1 — the confirmed leaks

| Order | Item | Notes |
|---|---|---|
| 1 | **Office redactor no-op** (defect 1) | Root cause not yet established — the discriminator between a fixture that redacts and one that does not is something in the XML declaration. Investigate `internal/redactors/office/` re-location (it re-extracts its own text and does `strings.Index`). Phase 0's invariant makes this fail loudly even before the root cause is fixed. |
| 2 | **Adjacency veto → demote, never drop** (defect 2) | Now a **pattern change across ≥3 validators**, not one file. Reuse `ConfidenceCeilingKey`/`clampToCeiling` from #241: keep the veto's precision benefit, emit at LOW so the value is still reported and still redacted. **Must preserve** the negatives measured in §1 — git SHAs, version strings, `ami-` ids must stay at zero findings. |
| 3 | **Nested container body text** (defect 3) | Must land **with** a recursion depth cap (no depth guard exists anywhere) or the fix becomes a zip-bomb amplifier. Warn when the cap is hit, reusing #238's empty-extraction plumbing. |
| 4 | **Truncation disclosure** (defect 4) | Every format must state the true total when it truncates. Cheap, and it removes a silent failure from CI. |
| 5 | `docProps/custom.xml` property-value vector | Last open injection surface. |
| 6 | `TestGoldenRedact` cannot cover `FileCases` | The test gap that let defect 1 and defect 3 hide. Worth doing early — it is the golden-level expression of Phase 0's invariant. |
| 7 | Delete the 9 unreachable adjustment keys (defect 5, half) | Deleting dead policy is unambiguous. **Re-adding** it deliberately is a Phase 3 question. |
| 8 | Housekeeping | `.gitignore` for `.perfbase/`, stale branches, ship `fix/fake-value-hardcap`. |

Items 1–3 are independent PRs against `main`. Item 6 should land before or alongside them so they
get golden coverage as they go in.

### Phase 2 — the measurement capability

**Correction (2026-08-01).** An earlier draft of this plan proposed "add a complexity dimension
so the timing discipline becomes an automated gate". That gate **already exists**:
`internal/goldencorpus/complexity_guard_test.go` (plus `complexity_generators_test.go`) has 18
validator targets, non-vacuity `minMatches` floors, `wantMatchGrowth` assertions, a 4x-input
ratio ceiling and a `-race` multiplier, and it passes. The mechanism is built.

The real gap is **coverage past the validator boundary**: every target calls
`validator.ValidateContent` directly to isolate validator cost from orchestration, so
`grep -ci redact` on the guard returns **0**. Redaction, suppression, `ResolveOverlaps` and
router assembly have no targets — which is exactly why a superlinear redaction path
(~4x cost per input doubling, ~78s on ~1MB of dense matches against a 100MB `MaxFileSize`)
sat in `main` with everything green.

A redaction target is now in `complexity_guard_redaction_test.go`, with an honest caveat
recorded there: measured ratios before and after the constant-factor fix **overlap**
(12.6–13.7 vs 10.0–13.2), so a ratio ceiling can only catch a new order-of-magnitude
regression — it cannot prove linearity, and redaction remains superlinear. Making redaction
genuinely linear needs match byte offsets carried from detection, which is a larger change.

A labelled corpus and `make score` (precision/recall/F1 per validator, CI-gated), as
`ARCHITECTURE_AND_PLAN.md` §4 describes. Two additions that this verification pass justifies:

- **Structural cases, not just value cases.** Every expensive defect found today was structural —
  nested containers, unhandled XML shapes, adjacency. A corpus of `ssn-in-a-line` fixtures would
  have scored 100% while defects 1–3 all sat there.
- **The negatives from §1 as permanent cases.** Git SHAs, version strings, resource ids, GUIDs,
  digests. They are what the vetoes protect, so they are what a veto fix must not break.

### Phase 3 — the measured decisions

Unchanged, minus one item. Each of these is a coin flip today and should be decided by the harness:
`tabular_boost` (+40, currently unchosen), whether to re-add the doc-type/domain policy,
same-span arbitration policy, the co-occurrence reranker, and per-validator veto trigger sets.

**Dropped:** confidence recalibration. §1 shows the scale is not saturated, so the premise was false.

---

## 4. The single highest-value next action

**Phase 0: the sink invariant.**

Not the biggest defect — that is the Office redactor no-op — but the highest value, because it
turns the entire class from *silent* to *loud*. Defects 1, 2 and 3 were all found by manually
building a fixture and manually reading inside a zip. That does not scale and it clearly did not
catch these. One assertion in the pipeline catches all three, catches the next one nobody has
thought of, and makes every later fix verifiable rather than assumed.

Then Phase 1 item 1, because a tool that hands you an unredacted file while reporting success is
the worst thing this codebase can do.

---

## 5. Honest limits of this review

- **Defect 1 is not root-caused.** I established that it reproduces, that every part is
  byte-identical, and that the discriminator involves the XML declaration form. I did **not** prove
  the mechanism. Phase 0 is designed to be valuable regardless.
- **Defect 2's scope is a lower bound.** I proved 3 validators beyond phone. There are ~15
  veto-shaped functions; the rest are unaudited, so the pattern change may be larger.
- **My own error rate in this session was high.** Three carried claims were wrong (§1), plus
  earlier: a recorded phone repro that used a character which does not trigger the veto, and a
  golden fixture set that silently tested nothing because of a path guard. The lesson is the same
  one Phase 0 encodes — **do not trust a claim without a test that fails when it is false.**
- **Two subagent review workflows were still running** when this was written (12 cross-cutting
  dimensions, 9 components + 3 seams). This plan is deliberately based on what I verified myself.
  Their findings should be merged in as a revision, and any finding of theirs that contradicts
  something here should be re-tested rather than averaged.
- **Not assessed by me at all:** i18n/encoding offset survival through transcoding, `--web`
  security posture, `pkg/redact` compatibility surface, goroutine lifecycle under cancellation,
  and per-format schema validity. Those are with the subagent reviews.
