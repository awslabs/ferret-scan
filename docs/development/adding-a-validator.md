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
