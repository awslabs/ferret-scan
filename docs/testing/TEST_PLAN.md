<!--
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
-->

# ferret-scan test plan

ferret-scan is a PII/secret **detection and redaction** tool. A miss is not a cosmetic
defect: content that is not detected is not redacted, so it leaves the tool in
cleartext. Every change is therefore held to the checklist below before it ships.
The guiding rule is **prove it, don't assume it** — each claim in a PR ("no
regression", "faster", "redaction covers it") must be backed by a command whose
output is in the PR body.

This document is the standing definition of "tested enough to merge". It is a
checklist to reason against, not a gate that every trivial change must clear in
full — see [Applicability](#applicability-scaling-the-plan-to-the-change) — but the
default is to run more of it, not less.

---

## The dimensions

Each dimension names what it protects, the minimum bar, and how to run it.

### 1. Build, vet, format

- `go build ./...` — compiles.
- `go vet ./...` — clean.
- `gofmt -l ./cmd ./internal ./pkg` — empty output, with **no exceptions**. The
  previously documented `internal/config/config.go` exception is gone: that file was
  reformatted by an unrelated change and `main` is now gofmt-clean. CI enforces this
  on every PR (`Gofmt` step in `go-test.yml`), so an unformatted file is a build
  failure rather than a judgement call.
- Note `gofmt -l` prints offending files but still **exits 0**, so never trust its
  exit status — inspect the output.

### 2. Unit + full regression suite

- `go test ./...` — the whole module, **not** just the package you touched. A
  validator change can move a golden file or a formatter test three packages away.
- Capture the exit code explicitly (`go test ./... > log 2>&1; echo $?`); a piped
  `tail` hides the real status.
- New behavior gets a new test **that fails on the pre-change code** — a test that
  passes both before and after proves nothing. State in the PR which tests are
  non-vacuous (fail on the parent commit).

### 3. Golden corpus

- `go test ./internal/goldencorpus/` — the end-to-end contract across all output
  formats (9 per case, including `redact_simple.txt` and
  `redact_format_preserving.txt`).
- Regenerate intentionally with `UPDATE_GOLDEN=1 go test ./internal/goldencorpus/`,
  then **read every diff line** — a golden change is a behavior change and must be
  explained in the PR, never rubber-stamped.
- State golden impact even when it is "none" (e.g. the corpus has no `.xlsx` case, so
  spreadsheet-extraction work moves no goldens — say so).
- Run it **uncached** (`-count=1`) once before commit; the corpus test caches
  aggressively.

> **Golden answers "did it change?", not "is it right?"** For the second question
> use the score corpus below. A change that trades a real detection for a quieter
> report passes the golden net — regenerate the snapshot and move on — so golden
> alone cannot tell an improvement from a regression.

### 3b. Score corpus — detection QUALITY (`make score`)

Full documentation: **[SCORE_CORPUS.md](SCORE_CORPUS.md)**.

- `make score` — precision, recall and redaction-sink residue against a
  hand-labelled corpus, ratcheted against a committed baseline. Scores four
  independent layers: **validator, redaction, suppression, executable**.
- Quote the scorecard in the PR body, including when nothing moved.
- Regenerate deliberately with `make score-update` and **explain the delta**. An
  improvement is reported and does not fail the build, so banking a win is a
  conscious step.
- Recall is reported twice on purpose: `recall_all` (all bands) is the **redaction**
  surface, because redaction is confidence-blind; `recall_hm` (≥ MEDIUM) is the
  **pre-commit exit-code** surface. A band demotion moves only the second.
- Why the redaction layer is separate from detection: measured, reverting the
  Office-redactor fix leaves the detection score **bit-for-bit identical** while a
  labelled SSN survives inside `word/document.xml`. Detection-only scoring reports
  PASS on a cleartext leak.
- Changing the gate itself? Run `make score-mutation-check` — it injects real
  regressions and confirms the gate goes red. It is not in CI because it edits
  tracked files.

### 4. Timing / complexity (O(n²) and unacceptable slowdowns)

The scanner routinely runs over adversarial and machine-generated input where a line
can be megabytes and a file can be tens of thousands of near-identical rows. A hidden
`O(n²)` there is a denial-of-service, not a micro-optimization.

- **Scaling curve, not a single point.** Measure at N, 2N, 4N. Linear work roughly
  doubles per doubling; quadratic roughly quadruples. One data point cannot tell them
  apart.
- **Isolate the layer.** `--preprocess-only` measures extraction+preprocessing without
  validation; a focused `go test -bench` on the changed function measures it alone.
  Wall-clock of the whole CLI includes stages you did not touch — attribute the cost
  before blaming (or crediting) your change.
- **Compare against a same-parent baseline binary**, built by stashing your change, so
  the delta is your change and not machine noise. Never benchmark in `/tmp` on macOS —
  the reaper deletes the binary mid-run and yields fake 0.00s readings; build under
  the repo or home dir.
- **A guard that names a defect must be shown to detect it.** Install the regression the
  guard exists for and confirm it FAILS. Two guards in `line_span_complexity_test.go` named
  the line-id memo in their failure messages and neither could fire — one costs 17.6ms with
  the memo destroyed against a 4-second ceiling, and the other's fixture puts one match per
  line, so the memo condition never holds and the correct and regressed paths are identical
  ([#509](https://github.com/awslabs/ferret-scan/issues/509)). Record BOTH margins:
  threshold ÷ worst *correct* reading, and best *regressed* reading ÷ threshold. Aim for
  1.5x on each; a guard whose above-margin is 1.03x is one runner away from silence.
- **`-race` does not preserve a growth ratio.** It inflates the base term more than the big
  one, so the ratio COMPRESSES — measured 15.5x → 12.5x on a reproduced dob quadratic
  (base 1.39x, big 1.11x) and 7.3x → 5.6x independently on the detector's line-span guard.
  CI runs with `-race`, so a ratio threshold has to be chosen against `-race` readings, not
  local ones. Raising an absolute ceiling for `-race` while leaving the ratio alone is the
  mistake this repo made.
- **Sampling answers variance; it cannot answer bias.** Two sampling fixes (a 4x bigger
  fixture *and* best-of-3) still left a guard reading 9.7x on Windows against 5.24x locally,
  because the fixture grew bytes and match count together so only the big term fell out of
  cache. One instrument change — wall clock to **allocated bytes** — has not flaked since.
  Allocation substitutes for the clock **only when the defect copies bytes**: a per-match
  `strings.Replace` loop allocates 15.03x against a one-pass 3.87x, deterministic to 0.01x.
  A pure step-count regression, re-scanning a string the caller already owns, has no
  allocation signature at all — for those, use a fixture whose CORRECT population sits near
  1.0x by growing one axis while holding the other fixed, and verify the two populations do
  not overlap before trusting it.
- **Allocation is not neutral to `-race` either.** The detector's own bookkeeping is a large
  roughly CONSTANT addend — measured ~55MB on a base term of 3MB and ~61MB on a big term of
  12MB — so it swamps the small end and compresses an allocation ratio from 3.91x to 1.26x.
  That is the opposite direction from timing, where `-race` inflates the base more, and it is
  why the rule is *measure the instrument under `-race`*, not *prefer allocation*. Declare
  the thresholds in a `//go:build race` / `!race` pair (the repo has several) so the guard
  stays LIVE under `-race` instead of being skipped there — a guard that only runs locally is
  the thing being fixed, not the fix.
- **Profile, don't guess** (`-cpuprofile` + `go tool pprof -top`) when a number
  surprises you.
- A measured regression is a blocker unless it is the unavoidable cost of correct
  behavior (e.g. emitting findings that were previously dropped) — and then it is
  stated in the PR with the reason.
- **A size read out of the file is not a size.** Every allocation taken from a DECLARED
  length needs the declared value bounded by the bytes that are really there, checked
  against `Stat`. This repo has produced 8.62GB of RSS from a 4KB `.docx` and 631MB from
  sixteen 80-byte `.mp4` files, both by trusting a number an attacker supplied. Assert it
  by **allocation**, not by timing: a bomb often parses fast, so a wall-clock assertion
  passes on the broken build and flakes on slow CI.
  Write the bound as `declared > remaining`, never as `offset + declared > size` — a
  64-bit size near 2^63 makes the addition overflow to a negative number that every
  later check accepts.
- **Where metadata sits in a file is not a bound.** A container format that permits its
  metadata anywhere (ISO base media `moov`, which ffmpeg and cameras write LAST) must be
  tested in both layouts, and the two must produce identical output. A fixture generator
  that always writes the easy layout hides this completely — every MP4 fixture in this
  repo was implicitly faststart, which is why a 10MB positional cap went unnoticed.
  Build the large-but-cheap case with `Truncate` so the media payload is a hole: it is
  never read, so it need not exist.

### 5. Redaction — all types

Because redaction only rewrites what the validators emit, **every detection change is
also a redaction change**. Test it explicitly, do not infer it.

- `--enable-redaction --redaction-output-dir <dir>`, then assert **no raw sensitive
  value survives** in the output — for binary containers (`.xlsx`, `.docx`, `.pptx`)
  unzip the rewritten file and `grep` the parts, since the value lives inside the XML.
- Cover **both** redaction styles the golden corpus distinguishes: simple
  (`[TYPE-REDACTED]`) and format-preserving (masking that keeps length/shape, e.g.
  `************0366`).
- The decisive test for a recall fix is the **base-vs-fix leak diff**: show that the
  parent binary leaks the value through `--enable-redaction` and the changed binary
  does not. That is the whole point of a detection fix, stated as a security result.
- On macOS the output dir nests under `private/…` (the `/tmp` symlink); `find` for the
  rewritten file rather than assuming a flat path.

### 6. Suppression

- Confirm intended suppression still suppresses **and is counted**: `stats.suppressed`
  must reflect it. The TM-11 class of bug is precisely a finding that is *dropped
  before emission* so `stats.suppressed` stays 0 and nothing signals the value was
  hidden — that is a leak, not a suppression. A demoted-to-LOW finding is emitted
  (and therefore redacted); an erased one is not. Know which your change produces.
- Suppression-hash stability: the hash embeds `%.2f` confidence, so a confidence
  change silently invalidates saved suppressions — check when confidence math moves.
- Exercise the suppression *mutation* path only over loopback (TM-01); never test it
  against a `--bind 0.0.0.0` posture.

### 7. All output formats

- `--format` covers `text, json, csv, yaml, junit, gitlab-sast, sarif`. A schema or
  field change must be checked in **every** format, not just JSON — the golden corpus
  emits all of them per case, which is the cheapest way to cover this.
- `--show-match` is a formatter-layer concern and must never cause a validator to log
  the raw matched value (BSC4 / [[no-match-in-debug-logs]]).
- A zero-finding scan emits `[]`; `jq '.results'` on it errors — that is expected, not
  a bug. Guard analysis scripts with a type check.

### 8. Web UI (when affected)

- If the change touches `internal/web/`, its assets, or anything the embedded template
  renders: run the web tests, and verify CSP is not loosened (`script-src 'self'`, no
  new `'unsafe-inline'`) and no new security header is dropped (TM-03/05/06).
- The public redaction API (`pkg/redact`) is a separate external contract — a bump
  that external consumers pin to must keep `redact.ValidCheckNames()` and friends
  stable. Most `internal/formatter` and `internal/web` changes do not touch it; say so
  when true. If a change does alter that list, it needs an explicit `CHANGELOG`
  entry naming the added/removed names and the consumer impact.
- Adding a validator to `internal/core/factory.go` is enough to add it to
  `redact.ValidCheckNames()`, so it must also be able to detect on that package's
  in-memory, no-config path. `TestValidCheckNames_AllDetectAndRedact` enforces this
  by driving a positive fixture through `Engine.Redact` for every advertised name and
  asserting both that a finding is produced and that the output changed. A validator
  that genuinely cannot work there (needs the filesystem, or gets its patterns only
  from config) belongs in `checksUnsupportedInMemory` instead.

### 9. TP / FP and recall (real-world documents)

- Measure against real documents in `~/Downloads` (never invent synthetic-only
  evidence when real material exists), plus a purpose-built adversarial fixture for
  the specific mechanism.
- **Build ground truth independently** where possible (e.g. an XML-parser reference
  for spreadsheet cells) and score recall/precision against it, rather than trusting
  the tool to grade itself.
- Report the delta as **new / lost / confidence-changed by type**, and classify each
  new finding as TP or FP by hand. "0 lost" is the recall floor; unexplained "lost"
  is a blocker.
- **Anonymize** customer document names in anything destined for GitHub; refer to "a
  real-world .xlsx", never the filename.
- Do not trust an A/B corpus diff without a **same-binary noise floor first** — several
  code paths are nondeterministic run-to-run (see dimension 11), and a diff key of
  `(file, validator, type, line)` is not unique (one line holds several matches), so
  `join` on it manufactures fake symmetric "confidence changed" pairs. Include a value
  hash or per-line index in the key.

### 10. Dead / unreachable code

- A fix that makes an old branch unreachable (e.g. replacing `if x <= 0 { continue }`
  with a floor so `x` can never be `<= 0`) must **remove or rewrite** that branch, not
  leave it as misleading dead code.
- `go vet` and the deadcode tool over-report; `pkg/redact`, `internal/web`, and test
  helpers are protected surfaces — confirm a reported-dead symbol is truly unreferenced
  before deleting. Deletions ride their own PR, not a behavior change.

### 11. Determinism

Identical input must yield identical output across runs of the same binary. Randomized
Go **map iteration** is the recurring culprit — any argmax / first-wins / append-while-
ranging over a map is a latent nondeterminism bug.

- For any change near extraction, clustering, or ranking: run the same file **10×** and
  assert a stable finding count and stable line numbers.
- Add a repeat-N-runs determinism test in the style of
  `internal/router/determinism_test.go` when the change touches an ordering-sensitive
  path.
- Known live sites (do not attribute new flakes to your change until excluded):
  container-format line churn (#179, fixed in PR #181), analyzer map-argmax (fixed in
  #178), and **SOCIAL_MEDIA on plain `.html`** (14–21 rows across 10 runs of the same
  binary — open).

### 12. Cross-platform

- No wall-clock-granularity assertions (Windows timer resolution flakes); use a
  pre-cancelled context instead of a real sleep.
- Golden/fixture files pinned to LF, not CRLF; paths compared with `filepath.ToSlash`.
- Office-extractor fixtures: `meta-extract-officelib` has a path guard rejecting
  `/tmp`, `/var`, `/home`, so `t.TempDir()` silently drops a preprocessor there; build
  the zip **in memory** (`archive/zip` + `zip.NewReader`) and call the extractor
  directly, which also sidesteps the guard. `text-extract-officetextlib` has no such
  guard.

### 13. Race

- `go test -race -count=1` on every touched package, and on any package with shared
  mutable state (package-level caches, compiled-pattern maps) even if untouched, when
  the validator runs concurrently across files/chunks.

---

## Sequencing (stacked PRs)

Work lands as a conflict-free sequence, so:

- Check file overlap with every open PR (`gh pr view <n> --json files`) before
  starting; stack a PR on the one that already edits the same files rather than
  racing it.
- Keep each worktree on its own branch; verify `mergeable=MERGEABLE`,
  `mergeStateStatus=CLEAN`, and the file list is exactly what you intended (no stray
  scratch files) before opening.
- Do **not** babysit per-OS CI after push — local gates are the real check, CI is the
  backstop. Report the PR link and move on.

---

## Applicability (scaling the plan to the change)

| Change kind | Always | Add |
|---|---|---|
| Validator confidence / keyword logic | 1,2,3,5,6,9,10 | 4 if loops over line/match; 11 if ranking |
| Extraction / preprocessing | 1,2,4,5,9,11,12 | 3 only if corpus has that format; 13 if concurrent |
| Formatter / output schema | 1,2,3,7 | 8 if web-facing |
| Web / template / assets | 1,2,7,8 | — |
| Dead-code removal | 1,2,3,10 | (lands alone) |
| Pure docs | 1 | — |

When in doubt, run more. The cost of an extra `go test ./...` is seconds; the cost of a
shipped redaction bypass is a cleartext leak.

### Ask what SINK consumes what you changed

The table above is easy to recite and easy to misapply. Reciting a dimension is not
running it. The reliable question is not "which row am I in?" but **"what downstream sink
consumes the thing I just changed?"**:

| Changed | Sinks that must be exercised |
|---|---|
| Byte offsets / spans | redaction (writes at those offsets) **and** the suppression hash (embeds position) |
| Match order | redaction — replacement is a destructive sequential rewrite, so order decides the result |
| Confidence | suppression hash (embeds `%.2f`) **and** every band filter (`--confidence`, exit codes) |
| Match text | `--show-match`, the suppression `context_hash`, redaction token length |
| Detection (new/lost findings) | redaction output, `stats.suppressed` counts, all 7 formats |

**Before opening any PR, write the checklist out and mark every dimension either
`RAN <command> → <result>` or `N/A because <reason>`.** "Probably unaffected" is not a
reason. This exists because a perf change that only moved offset *computation* shipped
with no redaction or suppression run: scan output was byte-identical, which felt like
proof, but the offsets it rewrote are exactly what the redactor writes at and what the
suppression hash embeds.

Two traps specific to this repo:

- **Container formats.** Grepping a redacted `.xlsx`/`.docx` for cleartext PII searches
  *compressed* bytes and returns zero — indistinguishable from a clean pass. Read the part
  inside the zip (`xl/sharedStrings.xml`, `word/document.xml`) and also count redaction
  tokens, to prove the redactor rewrote content instead of copying the container through.
- **Suppression must be tested cross-binary.** Generate the suppression file with the
  **parent** binary and apply it with the **fixed** one. Same-binary round-tripping passes
  even when the hash inputs changed; the cross-binary run is what proves existing
  suppression files in the wild still match.

---

## Security reporting

A newly discovered vulnerability is reported to AWS/Amazon Security via the
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/)
**before** any public write-up — never as a public GitHub issue (`CONTRIBUTING.md`).
A remediation for an *already-documented* threat-model item (e.g. a `THREAT_MODEL.md`
row) is ordinary tracked work and ships as a normal PR.

---

## Run the checklist mechanically

Reciting these dimensions is not the same as running them, and a dimension that is simply absent
from a PR description is indistinguishable from one that was considered and dismissed. So enumerate
them:

```bash
make pr-checklist              # vs origin/main
scripts/pr-checklist.sh <ref>  # vs another base
```

It executes what it can and prints one line per dimension — `RAN`, `N/A because …`, or
`NEEDS-MANUAL`. The sink dimensions (redaction, suppression) and the timing curve print
NEEDS-MANUAL whenever production code changed, because those need a fixture that exercises *your*
change and no script can invent one. Paste the output in the PR; leaving a NEEDS-MANUAL item unrun
is how a cleartext leak ships.

## Green individually is not green together

Every dimension above tests one change against `main`. That is necessary and not sufficient: two
changes can each be correct against `main`, merge with no textual conflict, and still be wrong
together. GitHub will report "no conflicts" for both, because it only compares text.

This is not hypothetical. One PR added a golden case that snapshotted a duplicate MRZ finding;
another PR made the duplicate stop happening. Different files, clean merge, both green alone, red
together — and nothing in CI looked at the pair.

So before a batch lands, test the union:

```bash
make integration-branch                  # merge every open PR, run the gates on the result
make integration-branch PAIRWISE=1       # also build the conflict matrix (slower, N^2/2 merges)
make integration-branch NO_TEST=1        # merges only, when you just want the conflict report
```

It leaves the merged result on a local branch (`integration/all-open-prs`) so a red union is
something you can check out and look at, rather than a log line.

Two things worth knowing when it reports a problem:

- **A textual conflict is usually an anchor collision, not a disagreement.** Two PRs appending a
  case at the tail of the same list, or a subsection under the same heading, conflict without
  contradicting each other. Fix it by moving one to a distinct anchor — a new top-level heading, a
  different insertion point — not by picking a winner. Note that a blind "keep both" on adjacent Go
  struct literals glues them into one literal and fails to compile; the resolution needs the `},{`.
- **A semantic collision belongs to whichever change lands second.** If the union is red because a
  behavior fix moved a snapshot another PR recorded, merge the fix into the snapshot branch and
  regenerate there, with the case description updated to say what the row gates *now*. Regenerating
  a golden to make red go away, without establishing which change is right, converts a caught
  collision into a shipped one.
