# The Confidence Contract

**Status:** Draft (survey-backed, adversarially verified). Written as the prerequisite for the
cross-validator co-occurrence reranker — it pins down what confidence *means* in this codebase
before anything is allowed to mutate it.

Every claim below carries a `file:line` citation gathered on the post-#169–#174 merged tree
(branch `test/merge-169-174`, 2026-07-26) by a 22-agent survey with an adversarial verification
pass. Line numbers drift; the anchors (function names, constants) are the durable reference.

---

## 1. The bands

One canonical definition, repeated (consistently) in ~10 places:

| Band | Score | Semantics | Canonical source |
|---|---|---|---|
| **HIGH** | ≥ 90 | "act on this" / very likely sensitive | `pkg/scan/confidence.go:9-13` |
| **MEDIUM** | 60–89 | "review" / possibly sensitive | same |
| **LOW** | < 60 | "likely noise / test data" | same |

Mirror sites: `pkg/redact/engine.go:339`, `internal/formatters/shared/structures.go:239`,
`text/formatter.go:748`, `junit/formatter.go:330`, `gitlab-sast/mapper.go:97` +
`sanitizer.go:184`, `internal/explain/synthesizer.go:31`, `cmd/main.go:1715,1813`,
`cmd/stdin.go:581`. All use the same 90/60 boundaries. (One doc drift: the
intellectualproperty README claims LOW is "40–59%" — cosmetic, no code effect.)

**gitlab-sast severity extension:** HIGH→Critical, MEDIUM→High, LOW→Medium
(`gitlab-sast/mapper.go:110-121`). It also has a *second, different* banding (80/50) for its
`confidence` field (`mapper.go:216-232`) — the only place in the codebase that doesn't use 90/60.

## 2. NONE is three different states

"A finding does not surface" has **three** distinct mechanisms with different recoverability.
Any rule like "the reranker must never resurrect a NONE" must say which one it means.

| State | Where it happens | Recoverable? | Reranker interaction |
|---|---|---|---|
| **N1 — never emitted** | Inside each validator (per-validator floors + hard drops, §3). No central floor exists anywhere in the bridge/parallel/facade layer (verified: `validator_runner.go`, `worker_pool.go`, `dual_path_bridge.go`, `detector.go` contain zero match-dropping confidence logic). | No. The candidate never becomes a `Match`. | Structurally immune: the reranker operates on emitted matches; N1 candidates don't exist at any seam. No rule needed — it's impossible by construction. |
| **N2 — suppressed** | `SuppressionManager.IsSuppressed`, hash-lookup only (`suppressions/suppression.go:238-284`). | Yes: `--show-suppressed`. | The reranker must run **after** suppression (§5) so suppressed findings never get reranked and hashes never shift. |
| **N3 — display-filtered** | Formatter layer only, per-formatter (`shared/structures.go:227` + private copies in text `:215` and junit `:153`). The match still exists, still counts for exit codes. | Yes: change `--confidence`. | A boost can legitimately move a finding across the filter (that is the feature). Note **gitlab-sast ignores the filter entirely** — every match is always mapped. |

**Key structural fact (verified):** there is **no global emission floor and no unconditional
global clamp**. The bridge clamps to [0,100] only when its (mostly-dead) adjustments actually
fire (`dual_path_bridge.go:797-800,1029-1032,530-531` — all conditional on domain/cross-path
state). Whatever a validator emits is what the pipeline carries.

## 3. Per-validator emission floors (the N1 table)

The floors below which a candidate is silently dropped, plus the score-independent hard drops.
"`<=0`" floors are the common degenerate gate — everything scoring above zero emits.

| Validator | Effective floor | Hard drops (score-independent) | Typical TP landing |
|---|---|---|---|
| PERSON_NAME | **≥ 50** — strongest real floor; both paths (`validator.go:197,269`) | capitalization/format gates, DB lookups | both-tokens-known 90–95 HIGH; one-token / non-Anglo names strand 65–89 MEDIUM |
| PASSPORT | **> 60 AND strong context required** (`validator.go:443-445`) | test patterns, per-country format fails | labeled ~100 HIGH; bare MRZ exactly 80 MEDIUM |
| SECRETS | entropy path **> 50**, keyword path **> 60** (`validator.go:1331-1335`, thresholds at `:312,:319`); **multiline (SSH/cert/PGP) and AWS-key paths have NO floor** | format gates per typed pattern | typed patterns 90–96 HIGH; M24 cap deliberately parks uncorroborated entropy at **51–55 LOW** |
| CLOUD_RESOURCES | **≥ 45** (`acceptThreshold`, `cloudresources.go:49,272`) | provider-format gates | ARNs/subscription IDs 90–100 HIGH; test-context −20 strands MEDIUM |
| BANK_ACCOUNT | SWIFT **< 40 w/o banking context**; ABA **< 50 w/o context** — *unreachable*, so a bare checksum-valid ABA is **never emitted**; other paths `<=0` (dead given caps) | **IBAN mod-97**, country/length, strong-negative-context line drop | labeled IBANs/SWIFT ≥ 90 HIGH |
| CREDIT_CARD | `<=0` only (`validator.go:348-350`); test patterns get a *forced minimum* 1.0 (`:342-344`) so they can't be zeroed away | **Luhn**, length/format, hard negative keywords | clean cards 95–100 HIGH; low-digit-diversity strands 85 |
| METADATA | **NO floor** — 0-confidence matches emit (clamp-then-append, e.g. `metadata_validator.go:748-755`) | none beyond field parsing | field boosts double-count → most TPs HIGH |
| INTELLECTUAL_PROPERTY | **NO floor** on the primary path — appended unconditionally (`validator.go:1009-1018`) | none | ©/™ notices 90–98 HIGH; word-only forms strand 70–85 MEDIUM |
| VIN | `<=0` — *unreachable*; suppressed noise emits at 15–70 instead of dropping | 17-char format (checksum is a boost, not a gate) | checksum-valid NA VIN 95–100 HIGH even keyword-free |
| PHYSICAL_ADDRESS | `<=0` — *unreachable*; min emitted 15 | line skips; street-FP heuristics (IP/version/file-ext/month-name collisions) | street+city/state/ZIP 75–85 MEDIUM; **HIGH requires an address keyword** |
| EMAIL | `<=0` (`validator.go:351-356`) | format validation | clean email exactly 100 HIGH; **machine addresses capped 85 MEDIUM** (`:344-346`) |
| PHONE | `<=0` (`validator.go:401-410`) | <7 digits etc. as −70 penalty (soft) | labeled 100 HIGH; the −20 no-keyword penalty is the classic MEDIUM strander |
| SSN | `<=0` (`validator.go:401-408`); survivors effectively start 85 | **invalid area/group/serial hard-dropped** before scoring | keyword-adjacent 100 HIGH; **decoys deliberately parked 55–80** by negative keywords |
| IP_ADDRESS | `<=0` (`validator.go:404`) | parse failure | keyword-adjacent 100 HIGH; **ambiguity cap parks context-free dotted-quads at exactly 75**, published as a `confidence_ceiling` so the document-level boost cannot cross it (#513). The ceiling is published whenever the value is **eligible** for the cap, not only once its score already exceeds it — gating both on the same `>= 90` test left every below-threshold ambiguous value with no bound at all, so the later adjustment had nothing to clamp (#545). A column header naming the value an address clears the cap, and header spellings are normalised so `sourceIPAddress` resolves as `source ip address` rather than one unbroken token (#548) |
| DATE_OF_BIRTH | `<=0` (`validator.go:216-218`) | structural date validation | labeled DOB exactly 90 — **cannot exceed 90**; weak keywords strand 70–85 |
| DRIVERS_LICENSE | `<=0` (keyword-gated scan) | requires a license keyword to scan at all | prefixed 95 HIGH; keyword-only 65–85 MEDIUM |
| MEDICAL_ID | `<=0` across all five sub-evaluators | **NPI Luhn-80840**, DEA checksum, MBI format | labeled DEA/NPI 90–100 HIGH; MRN base 15 rarely surfaces alone |
| OTP | `<=0` (shared emit closure `validator.go:223-226`) | base32/format gates | otpauth URIs ~100 HIGH; **16-char TOTP seeds strand MEDIUM** |
| SOCIAL_MEDIA | `<=0` (`validator.go:2752-2754`) | platform format validation | valid profile URLs/handles saturate 100 HIGH |

Notable asymmetries this table exposes:
- **Floors range from nonexistent (metadata, IP) to 60-plus-context (passport).** "Emitted at
  LOW" means different things per validator: for SSN/SECRETS it often means *deliberately
  demoted decoy*; for address/VIN it means *noise that an unreachable floor failed to drop*.
- **MEDIUM is not one population.** It contains: true positives stranded by a missing keyword
  (phone, address, DL), *structurally capped* true positives (DOB can never exceed 90; machine
  emails capped 85), and *deliberately parked* false positives (SSN decoys 55–80, secrets
  entropy noise 51–55, IP ambiguity cap exactly 75). A uniform boost treats all three the same;
  the contract's per-validator eligibility list (§6) exists because of this.

## 4. What a band crossing actually does (consumer table)

Behavior-changing consumers of MEDIUM→HIGH / LOW→MEDIUM crossings:

| Consumer | Crossing effect |
|---|---|
| **Pre-commit / stdin exit code** (`cmd/main.go:1808-1838`, `stdin.go:581-607`, `precommit/detector.go:173-188`) | MEDIUM→HIGH on the highest finding flips exit 0→1 under default `ExitOnFindings=high` — **the commit is blocked**. Gate reads matches *before* the display filter, so blocked-but-invisible is possible under `--confidence high`. |
| **`--confidence` display filter** (formatter layer, §2 N3) | LOW→MEDIUM becomes visible under the pre-commit profile `high,medium`. gitlab-sast ignores this filter. |
| **gitlab-sast severity** (`mapper.go:110-121`) | MEDIUM→HIGH escalates GitLab High→**Critical** — trips Critical-gated MR approval/scan policies. |
| **JUnit** (`junit/formatter.go:153-163,196-200`) | Under narrowed `--confidence`, a crossing flips a file's test case PASS→FAIL — CI goes red. |
| **Explain verdicts** (`synthesizer.go:94-136`) | LOW→MEDIUM flips `likely_test`→`likely_real`; ≥90 overrides test-file signals and rewrites the drafted suppression reason. |
| **Summary stats** (`cmd/main.go:1713-1735`) | bucket counts shift. |
| **Redaction — NOT band-gated anywhere** (`worker_pool.go:323`, `stdin.go:363-380`, `pkg/redact/engine.go:254-270`, `pkg/scan/apply.go:39`) | No change. All unsuppressed matches are redacted regardless of band. A rescore-only reranker cannot un-redact anything. Gateway-safe: band surfaces only as a reported tier string. |
| **SARIF** | `level` is always `"error"` (`sarif/mapper.go:83`) — band cosmetic; but see raw-score hazards. |

**Raw-score-sensitive consumers** (where +10 matters even *without* a band crossing):

1. **Suppression-rule hash** — the sharpest hazard. `generateFindingHash` folds
   `fmt.Sprintf("%.2f", match.Confidence)` into the SHA-256 (`suppression.go:207`), and
   `IsSuppressed` matches **purely by hash** (`:243-248`), no field fallback. Any post-hoc
   confidence change at 2-decimal precision **silently orphans every existing suppression rule**
   for that finding — previously suppressed findings resurface, and in pre-commit mode can newly
   block commits.
2. SARIF `rank` is linear in the raw score (`sarif/mapper.go:307-330`).
3. Sort order + `--limit` truncation order by raw score (`text/formatter.go:127-149`).
4. gitlab-sast's separate 80/50 confidence banding (`mapper.go:216-232`).
5. `pkg/scan.Finding.Confidence` exposes the raw float to external embedders (`scan.go:66`).
6. Web UI sorts by raw score (`app.js:257-260`).

## 5. Where the reranker may sit (verified insertion-point analysis)

Four candidate seams were analyzed; suppression-hash safety is the discriminator:

| Seam | Suppression hashes | Coverage | Verdict |
|---|---|---|---|
| **P1 — inside the bridge** (after `applyCrossPathConfidenceAdjustments`, `dual_path_bridge.go:482`) | **BROKEN** — hashes computed downstream on mutated scores; every existing rule on a boosted finding orphans | all paths at once (ScanFile, ScanContent, pkg/redact, web) | viable only with a separate-field design |
| **P2 — post-RunValidators, pre-suppression** | **BROKEN** — same | multi-site wiring | viable, same caveat |
| **P3 — post-suppression, pre-format/stats** (`core/scanner.go` between `:184-211`; `cmd/main.go` between `:1679` and the `:1713` stats) | **SAFE** — `IsSuppressed` already ran on original scores; existing rules keep matching. `--generate-suppressions` (`main.go:1701`) mints hashes on reranked values, which is self-consistent because the reranker is deterministic on the next run. | needs wiring at the orchestration sites (core.ScanFile, core.ScanContent, cmd/main.go batch path); pkg/redact can opt out (redaction is band-independent) | **RECOMMENDED** |
| **P4 — format-time** | safe | must be duplicated in 7 formatters + web + pkg/redact; gitlab-sast has no filter hook; **exit-code banding reads the pre-format match list, so pre-commit would block on un-reranked scores while displaying reranked ones — a direct contradiction** | **NON-VIABLE** |

**Decision: P3.** Mutate `Confidence` after suppression, before stats/exit-code/formatting, via
one shared core function called from the orchestration sites. Consequences accepted:
- Suppressed findings escape reranking entirely (correct: they are N2 by user decision).
- Inline redaction (worker pool) runs on pre-reranker scores — harmless today because redaction
  is band-independent at every layer; revisit if redaction ever gains a confidence threshold.
- Goldens change (expected — this is a behavior change; the goldens are the review artifact).
- The `original_confidence` and boost must be recorded in `Match.Metadata` (the hash ignores
  Metadata — verified `suppression.go:205-219` — so annotations are hash-safe).

## 6. The band-step principle (rules for any confidence mutation)

1. **Boost-only, bounded, clamped.** The reranker adds, never subtracts. Per-finding total
   cross-boost ≤ +15; result clamped to 100.
2. **At most one band crossing.** A boost may take MEDIUM→HIGH or LOW→MEDIUM, never LOW→HIGH
   (LOW at 59 + 15 = 74 stays MEDIUM arithmetically, but the rule is explicit: if a boost would
   cross two boundaries, cap it at the first).
3. **N1 is untouchable by construction; N2 by placement.** The reranker sees only
   post-suppression survivors (P3). No rule can resurrect a never-emitted or suppressed finding.
4. **Distinct-validator corroboration only.** Two findings from the same validator never
   corroborate each other (prevents self-amplification of one noisy validator).
5. **Eligibility is per-validator, not universal.** Validators whose MEDIUM/LOW band is
   *deliberately parked noise* must be excluded from receiving boosts (they may still *provide*
   corroboration): start with **SSN (decoys parked 55–80), SECRETS (M24 entropy cap 51–55),
   IP_ADDRESS (ambiguity cap exactly 75 — a +15 boost lands exactly at 90 HIGH: a cliff)**.
   The IP_ADDRESS cliff has since been closed the way item 6 below prescribes rather than by an
   eligibility list: the cap is published as a `confidence_ceiling` and the bridge clamps to it,
   so no downstream boost can cross 75 (#513). That went unnoticed for as long as it did because
   the boost is *document-level* — ten real `.odt` files carrying a byte-identical generator
   string split eight HIGH / two MEDIUM purely on their body text.
   This mirrors the never-enable list from the reranker benchmark (SSN/ADDRESS/SECRETS).
   PHYSICAL_ADDRESS is high-risk as a *receiver* (residential-suffix prose FPs at 50–58 live in
   exactly the resume/letter documents that carry real email/phone within 5 lines).
6. **Structurally capped validators need band-crossing review.** DOB cannot exceed 90 by its own
   scoring; machine emails are capped at 85 *on purpose*. A boost that overrides a deliberate
   cap (EMAIL machine-cap) is reverting an intentional precision fix — machine-capped emails
   should be boost-ineligible or capped below 90.
7. **Every mutation is annotated.** `Metadata["original_confidence"]` and
   `Metadata["cross_boost"]` on every changed match (hash-safe, audit-friendly, and lets the
   explain layer describe the boost).

## 7. Bugs and quirks found during the survey (side findings, not blockers)

- **No unconditional pipeline clamp:** a validator emitting >100 in a domain-less document would
  reach output unclamped (bridge clamps are conditional). All current validators clamp
  internally, so this is latent, not live.
- **Dead floors:** the `<=0` gates in address, VIN, bankaccount(non-SWIFT/ABA paths) are
  arithmetically unreachable — noise emits at LOW instead of dropping.
- **Bare checksum-valid ABA routing numbers are never emitted** (floor unreachable without a
  banking keyword) — recall gap worth knowing about.
- **address numbered-list FP branch is a no-op** (`validator.go:774-780` — both branches return
  false); `reZIPAlone` treats any adjacent 5-digit number as ZIP context.
- **secrets multiline + AWS-key paths bypass the validator's own floors.**
- **gitlab-sast ignores `--confidence` filtering entirely** and uses a second 80/50 banding for
  its confidence field.
- **text and junit carry private copies of the confidence filter** (drift risk with
  `shared.FilterMatchesByConfidence`).
- **`redactors/validation/recovery.go:353` gates on `Confidence >= 0.8`** — a 0–1 scale bug on a
  0–100 field; dead code (no callers).
- The explain-after-suppression comment at `scanner.go:186-188` is **accurate** (verified) — and
  is the precedent the P3 placement follows.

## 7b. Reproducibility is a precondition, not a detail (added 2026-07-27)

Two defects found after this survey change what §6 can assume. Both were found by validating an
unrelated keyword change against 1,156 real documents, not by reading code.

1. **Fixed (#178):** `ClassifyDomain` and `DetectStructure` in `internal/context/analyzer.go` each
   picked their winner by ranging a map with a strict `>`, so ties were resolved by Go's
   randomized iteration order. `DetectStructure` decides `DocumentType`, which grants
   `tabular_boost` of +20 in `calculateConfidenceAdjustments` — so a TSV↔Code coin flip moved
   **every finding in the document across a band**. Since §4 establishes that confidence is part
   of the suppression hash (`suppression.go:207`, `%.2f`), the flap could silently invalidate a
   user's suppression rules between two runs over unchanged input.

2. **Open (#179):** container formats (`.docx`/`.pptx`/`.xlsx`) still produce different line
   numbers, and occasionally different confidences, run to run. 33 of 60 sampled container-heavy
   files flap over 6 repeat runs; plain-text inputs were byte-identical over 15.

Consequences for the reranker:

- **Measure on plain-text inputs only until #179 is fixed.** A proximity-gated reranker keys on
  *relative position* of findings, so a preprocessor that shifts line numbers between runs makes
  the gate itself non-reproducible — the benchmark would measure the churn, not the reranker.
- **A/B comparisons need a same-binary noise floor.** On the first attempt here, 57 of 102
  "changed" files turned out to differ under the *unmodified* baseline. Without that control the
  raw diff read as a large precision shift that did not exist.
- **Any new argmax over a map needs an explicit tie-break.** The co-occurrence scorer will rank
  candidate boosts; ranking with a strict `>` over a map reintroduces exactly this bug.

## 7c. Reserved, documentation and test values: suppress vs demote (added 2026-08-31, #364)

Before this section the treatment of a reserved or documentation value varied per validator with
no stated reason: the voided SSN `078-05-1120` was dropped, NANP `555-01xx` and the RFC 6238 OTP
seed were capped at LOW 15, the Visa test card landed at 15 by arithmetic accident, and the AWS
documentation access key reported **84% MEDIUM**. Same class of value, four outcomes. The rule
below is what the shipped code already does, written down so a new validator has something to
follow.

**Three treatments, and the predicate that selects one.** Read them in order; the first that
applies wins.

| # | Treatment | Predicate | Precedent |
|---|---|---|---|
| **T1** | **Drop (N1 — never emitted)** | A numbering or registration authority has withheld **this exact value** from assignment, so it identifies nobody, now or later — *and* the value has no fixture footprint that needs redacting. | `ssn.isTestSSN` (`123-45-6789`, `078-05-1120`); `ipaddress` RFC 5737 TEST-NET ranges |
| **T2** | **Ceiling at 15, published as `Metadata["confidence_ceiling"]`** (see the note below — only the newest implementation publishes it) | The value is **published as a placeholder** by a standard, a registration authority or a vendor's own documentation, but nothing withholds it from being real — *or* T1's predicate holds while the value still needs to be redacted. | `phone.reservedFictionalCeiling` (NANP `555-01xx`); `otp.publishedSecretCeiling` (RFC 4226/6238 seeds); `creditcard` test cards; `secrets.awsDocPlaceholderCeiling` (`AKIAIOSFODNN7EXAMPLE`, `wJalr…CYEXAMPLEKEY`) |
| **T3** | **Leave reported at full confidence** | The value is a **vendor test-mode credential**. `sk_test_…` authenticates against Stripe's test environment: it can be abused and it discloses account structure. "test" in a vendor prefix is a product tier, not a fiction. | `secrets.isStripeAPIKey` — unchanged on purpose |

**Why 15 and not 85.** 15 is the top of LOW. At 85 the value still appears under
`--confidence medium,high`, which is the pre-commit filter this repo itself uses — i.e. it stays
exactly the finding the complaint was about. Four validators now agree on 15; a fifth number
would recreate the divergence.

**The four T2 precedents share the CEILING but not the PUBLICATION, and that is a real gap rather than a wording slip.** Measured: `phone.reservedFictionalCeiling`, `otp.publishedSecretCeiling` and the `creditcard` test-card handling each clamp locally — `if confidence > ceiling { confidence = ceiling }` — and none of the three packages contains any reference to `confidence_ceiling` or `ConfidenceCeilingKey` (`grep -rc` over `internal/validators/{phone,otp,creditcard}` returns zero for both names). Only `secrets.awsDocPlaceholderCeiling`, added by #364, publishes the bound it enforces. This matters because an unpublished ceiling does not survive a later re-score: a downstream consumer that raises confidence has no way to learn a bound was intended, so the clamp silently stops holding. Publishing is therefore the shape new T2 implementations should follow, and retrofitting the other three is worth its own change — not assumed here, and not claimed as already done.

**Why T2 is the default and T1 the exception.** Only reported findings reach the redactor
(§4, "Redaction — NOT band-gated anywhere"), so a drop removes the value from the redaction path
as well as from the report. Measured on the two AWS placeholders: `AKIAIOSFODNN7EXAMPLE` is a
live finding in **39** golden files and `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` in **16**,
because a reserved placeholder is the responsible value to commit to a public repo. Dropping them
would have left both in the cleartext of a "redacted" document. The ceiling moved only `conf=`
labels — **not one redacted byte changed** in any redaction golden. So: measure the fixture
footprint before choosing T1 over T2.

**A ceiling must be PUBLISHED, not just applied.** Confidence is raised in at least three places
after a validator scores a value, so a locally clamped variable does not hold:

1. `mergeBySpanKeepStrongest` (secrets) keeps the **max** confidence across detection paths —
   inside the validator. Measured: `wJalr…CYEXAMPLEKEY` was capped to 65 in `findAWSSecretKeys`
   and `ValidateContent` still returned 75.
2. The bridge's document-context adjustment and cross-path correlation boost (§5).

The generic mechanism is `Metadata["confidence_ceiling"]` (a **`float64`**; any other type is
ignored) plus `clampToCeiling` in `internal/validators/dual_path_bridge.go`. Note the bridge clamp
runs on the **bridge path only** — `pkg/redact` and any embedder calling `ValidateContent`
directly bypass it, so a validator that raises confidence internally must also clamp at its own
boundary (`secrets.clampToPublishedCeiling`).

**The predicate must not be attacker-reachable.** Anything that makes a finding quieter is an
evasion surface, and this repo has already recorded the shape once (TM-11: context-keyword padding
driving a checksum-valid secret to zero). A value-marker rule is only admissible where the
attacker cannot put the marker there. The AWS rule qualifies because both credential types have an
exact-length gate: appending `EXAMPLE` to a real 20-char `AKIA` key makes it 27, which
`isAWSAccessKey` rejects, and `reAWSSecretCandidate`'s trailing `($|[^A-Za-z0-9/+=])` means
`<real40>EXAMPLE` produces no 40-char capture at all. The same rule is deliberately **not**
applied to the generic `API_KEY_OR_SECRET` type, which has no length gate.

**Every such change ships with a same-shape control.** A fix that demotes real values alongside
placeholders is worse than the bug, because the finding still appears and the scan still looks
like it worked. Prove a randomly generated value of the identical shape keeps its exact
pre-change confidence.

### Deliberately out of scope: documentation-example IBANs

`#364` asks for "the ISO 13616 example IBAN" to be suppressed and names
`GB29NWBK60161331926819`. **There is no such value**, which is why this class gets no rule rather
than a half-rule. Measured 2026-08-31:

- ISO 13616 registers **formats**, not values. Neither the standard nor the Wikipedia articles
  that cite it attribute any IBAN to it; `GB82 WEST 1234 5698 7654 32` is Wikipedia's own
  fictitious worked example for the check-digit algorithm.
- The registration authority (ISO 13616-2) publishes one **sample per country**, and the current
  GB sample is `GB33BUKB20201555555555`. Neither `GB29NWBK60161331926819` nor
  `GB82WEST12345698765432` appears in that set at all — nor do `DE89370400440532013000`,
  `NL91ABNA0417164300` and the rest of this repo's own IBAN fixtures.
- That sample set changes between registry releases, so it is not a stable denylist either.

So T1 is unavailable (nothing withholds these values) and T2 has no citable predicate — only an
enumerated list of folklore values, which would demote three famous IBANs while leaving the other
six in `bankaccount`'s own suite at 100% HIGH: a fifth inconsistency, not a fix. `bankaccount`
also carries `intrinsicValueFloor` specifically so context cannot erase a mod-97-valid IBAN, so a
context-based rule is ruled out too.

For anyone revisiting this: the **cost** is low and was measured, so cost is not the objection.
Capping `GB29NWBK60161331926819` and `GB82WEST12345698765432` at 15 breaks exactly **one** test
(`TestBankAccountValidator_IBAN_IntrinsicValueFloor`, which asserts the second value scores high
with no negative context) and **zero** golden files — not the dozen a previous review estimated.
The objection is that no authority reserves an IBAN value, so any list is arbitrary. If the
registry sample set is ever vendored with its release number, T2 becomes available for it.

Also left alone, and not defects: `CREDIT_CARD` `4111…`/`4242…` at 15 and `EMAIL`
`test@example.com` at 8 / `jane@example.org` at 48 already sit in LOW, which T2 is satisfied by.
Non-NANP fictional phone ranges (Ofcom `07700 900xxx`, AU `0491 570 xxx`) are unimplemented T2
candidates; `phone.isReservedFictionalNumber` says so in a comment rather than implying the check
is exhaustive.

**One consequence that no longer applies — §4 hazard 1 is stale.** §4 warns that confidence is
folded into the suppression hash at `%.2f`, so any rescoring orphans a user's existing rules. That
was true when §4 was written and is not true now: `hashVersionCurrent` is
`hashVersionNoConfidence`, confidence is deliberately excluded from the identity, and
`generateFindingHash`'s lookup additionally tries the legacy confidence-bearing formulas
(`internal/suppressions/suppression.go:195-260,309`). **Verified end-to-end, not read off the
code:** rules generated by the pre-#364 binary against `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`
plus an SSN positive control still silence both findings under the post-#364 binary, across an
84 → 15 confidence move (2 suppressed before, 2 suppressed after). So a retreatment under this
section does **not** carry a suppression-file migration cost. Re-measure rather than assuming
either way — this is the check to run when re-banding anything.

## 8. What this unblocks

The cross-validator reranker plan (proximity-gated co-occurrence, ~5-line window, +8..+12) can
now be specified precisely: insertion at P3, band-step rules from §6, receiver-eligibility list
from §6.5/6.6, and the golden + 860-case benchmark gates as planned. The "boost never
manufactures a finding" invariant is discharged structurally (§2), not by runtime checks.
