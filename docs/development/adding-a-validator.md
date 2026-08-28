# Adding a New Validator — Runbook

> Checklist of every file and location that must be updated when adding a new
> validator to ferret-scan. Missing any of these causes CI failures or runtime
> gaps. Follow in order.

---

## 1. Create the validator package

```
internal/validators/<name>/
├── validator.go          # implements detector.Validator
├── validator_test.go     # positive, negative, context, edge-case tests
├── adversarial_test.go   # FP probes, cross-validator confusion, boundary tests
├── help.go              # func (v *Validator) GetCheckInfo() help.CheckInfo
└── README.md            # optional: design notes, pattern docs
```

**Required interface methods:**
- `NewValidator() *Validator`
- `ValidateContent(content, originalPath string) ([]detector.Match, error)`
- `ValidateContentCtx(ctx context.Context, content, originalPath string) ([]detector.Match, error)`
- `CalculateConfidence(match string) (float64, map[string]bool)`
- `AnalyzeContext(match string, context detector.ContextInfo) float64`
- `SetObserver(observer observability.Observer)`
- `GetCheckInfo() help.CheckInfo`

---

## 1a. Matching context keywords

Never hand-roll `strings.Contains` for a keyword. Use `internal/validators/kwmatch`,
which applies the whole-word rule the validators depend on — `strings.Contains` finds
`ssn` inside `assign` and `ein` inside `Einstein`.

| Call | Use for | Matches |
|---|---|---|
| `kwmatch.Contains(text, kw)` | **the default — and every suppressor** | `member id`, `member_id`, `member-id`, `member  id` |
| `kwmatch.ContainsLabel(text, kw)` | a POSITIVE keyword that labels the value beside it | the above **plus** `memberid`, `memberId` |
| `…Lower` variants of either | callers that already hold lowercased text, to skip the allocations | as above |
| `kwmatch.ContainsAny(text, kws)` | any of a list | as `Contains` |

Rules a multi-word keyword follows:

- **A space matches one or more separator bytes** (space, tab, `_`, `-`), so one keyword
  covers the spaced, snake_case, kebab-case and padded spellings.
- **`ContainsLabel` also allows ZERO separators**, adding the concatenated and camelCase
  spellings that JSON, REST payloads and ORM exports emit by default. Text is lowercased
  before matching, so `memberId` and `memberid` are the same string.
- **`.` and `/` are not separators** in either mode, by measurement: they cross sentence and
  URL boundaries, where the two words are unrelated (`see member.id in the docs`,
  `/member/id/lookup`).
- **The whole-word rule still applies at both ends** in either mode, so `member id` does not
  match inside `remembering`, `teammemberid` or `memberidentification`.

### The asymmetry is the important part

`ContainsLabel` is opt-in because **widening a suppressor's reach silences real values**, and a
silenced finding is never redacted. A positive keyword identifies the value it labels, so
widening it can only add findings; a suppressor withholds one.

That is not hypothetical. When the widened form was briefly the default, `medicalid`'s
suppressor `ip address` matched the ubiquitous key `ipAddress` — an unconditional veto — so

```json
{"member_id": "W1234567801", "ipAddress": "10.11.12.13"}
```

lost its finding entirely and was written back with the member ID in **cleartext** while the IP
was masked. `ssn`'s suppressor list carries the same threat: `part number`, `policy number`,
`order number`, `employee id`, `tax id` are all common camelCase keys.

So: **positive lists may use `ContainsLabel`; negative, suppressor and veto lists must use
`Contains`.** If one helper in your validator serves both lists, add a second one rather than
widening both — and if a helper *reports* which keywords matched, pass it the same matcher the
scorer used, or the context will disagree with the confidence.

Note that a dictionary screen does not substitute for this rule: `ipaddress` is not an English
word, so checking concatenations against `/usr/share/dict/words` passes it. The property that
matters is "is a token that occurs in real text", which no word list decides.

---

## 2. Register in the factory

**File:** `internal/core/factory.go`

Add one line to `validatorConstructors`:
```go
"<NAME>": func() detector.Validator { return <pkg>.NewValidator() },
```
Plus the import.

---

## 3. Update the schema validation allowlist

**File:** `internal/config/schema.go`

Add to `validCheckNames`:
```go
"<NAME>": true,
```

**Why:** `ValidateSchema()` rejects unknown check names in config files. Without
this, users who put `checks: <NAME>` in their `config.yaml` get a validation error.

---

## 4. Update the checks-test literal

**File:** `cmd/checks_test.go`

Update `checkNameLiteral` const with the new sorted comma-joined list. This test
locks the CLI's `--checks` help string.

---

## 5. Update documentation

| File | What to update |
|---|---|
| `README.md` | Validator count ("Nineteen") + table row |
| `config.yaml` | Line 12 comment listing all valid check names |
| `docs/architecture-diagram.md` | Validator count + mermaid list |
| `docs/validators-new.md` | Full technical description (if new) |

---

## 6. Verify all output formats

The new validator's findings must render correctly in all 7 output formats.
Run against a file containing the new type:

```bash
echo "<test input>" | ferret-scan --stdin --checks <NAME> --format json
echo "<test input>" | ferret-scan --stdin --checks <NAME> --format sarif
# ... repeat for csv, yaml, junit, gitlab-sast, text
```

All must show `[HIDDEN]` by default (secure) and produce valid structured output.

---

## 7. Verify explain integration

```bash
echo "<test input>" | ferret-scan --stdin --checks <NAME> --explain --verbose
```

Must show:
- Validation results (which structural checks passed/failed)
- Context analysis (which keywords boosted/suppressed)
- Rationale must NOT include the raw matched value

**Critical:** populate `match.Metadata["validation_checks"]` in your validator so
the explain system can synthesize a rationale.

This instruction was already here and four validators diverged from it anyway
([#363](https://github.com/awslabs/ferret-scan/issues/363)) — `physical_address`, `bank_account`,
`cloud_resources` and one dedicated path inside `secrets` set no checks, so `--explain` restated
the type and a confidence the reviewer had already seen: *"Flagged as an AWS ARN. (confidence 55%,
low)"*. It is now enforced by `TestEveryValidatorRecordsWhatItChecked` in
`internal/validators/explain_rationale_test.go`, which drives every validator from a fixture and
fails if one records nothing. **Add your validator to that table** rather than only reading this
paragraph.

Two conventions the synthesizer depends on:

- **Name a "this looks like test data" check with one of the spellings in `testCheckKeys`**
  (`internal/explain/synthesizer.go`) — `not_test`, `not_test_number`, `not_test_email`,
  `not_test_ip`, `not_test_data`, `not_example`, `not_published_test_secret`. A key in that list
  feeds the verdict *and* is kept out of the "it passed ..." prose. A new spelling outside it is
  silently ignored by the verdict and leaks into user-facing prose as a raw key name — which is
  the other half of #363.
- **Record only what the validator already decided.** The checks are display data: they are not
  inputs to confidence, and they are not inputs to the suppression hash (that reads type,
  confidence, line, filename, offsets and the hashed text). Computing something new here to
  report it would change scoring by the back door.

If your finding type is an acronym, add it to `typeDisplays` in the same file, with the article
spelled out — the default renders `SSN` as *"a ssn"*, because the article is otherwise chosen by
spelling rather than by how the letters are said.

---

## 8. Verify redaction

```bash
echo "<test input>" | ferret-scan --stdin --checks <NAME> --enable-redaction
```

The matched value must be masked. The default `generateReplacement` handles
unknown types with generic masking. For type-aware synthetic replacements, add a
case in `internal/redactors/replacement/replacement.go`.

---

## 9. Run the full test suite

```bash
go test ./... -count=1
```

**Not** just `./internal/validators/...` — the config schema test, checks-test
literal, and golden corpus also need to pass. CI runs on all three platforms
(Linux, macOS, Windows).

---

## 10. Adversarial analysis (recommended)

Write `adversarial_test.go` with:
- False-positive probes (things that look similar but shouldn't match)
- Cross-validator confusion (values another validator might also claim)
- Context strength tests (same value ± keywords → confidence must swing)
- Edge cases (empty, max-length, unicode, split across lines)

---

## Quick reference: files touched when adding a validator

| # | File | Change |
|---|---|---|
| 1 | `internal/validators/<name>/validator.go` | New |
| 2 | `internal/validators/<name>/validator_test.go` | New |
| 3 | `internal/validators/<name>/help.go` | New |
| 4 | `internal/core/factory.go` | +1 line (constructor) + import |
| 5 | `internal/config/schema.go` | +1 line (allowlist) |
| 6 | `cmd/checks_test.go` | Update `checkNameLiteral` |
| 7 | `config.yaml` | Update line-12 comment |
| 8 | `README.md` | Count + table row |
| 9 | `docs/architecture-diagram.md` | Count + list |
