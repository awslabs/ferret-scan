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
- **Profile, don't guess** (`-cpuprofile` + `go tool pprof -top`) when a number
  surprises you.
- A measured regression is a blocker unless it is the unavoidable cost of correct
  behavior (e.g. emitting findings that were previously dropped) — and then it is
  stated in the PR with the reason.

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
  when true.

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

---

## Security reporting

A newly discovered vulnerability is reported to AWS/Amazon Security via the
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/)
**before** any public write-up — never as a public GitHub issue (`CONTRIBUTING.md`).
A remediation for an *already-documented* threat-model item (e.g. a `THREAT_MODEL.md`
row) is ordinary tracked work and ships as a normal PR.
