# Upstream Engine Asks

> These are feature requests for the ferret-scan engine (awslabs/ferret-scan).
> Per SPEC §8: these go upstream — never vendored into the mobile repo.
> Track progress here; file as GitHub issues when ready to assign.

---

## New Validators

### 1. BANK_ACCOUNT / IBAN / Routing Numbers
**Why:** Statements and tax docs are the most common sensitive files on phones; CREDIT_CARD alone misses ACH/IBAN.
**Scope:** US routing+account (ABA format), IBAN (international), SWIFT/BIC codes.
**Priority:** High — directly extends the mobile app's value on financial documents.

### 2. TWO_FACTOR_CODES / OTP Secrets
**Why:** Screenshots of QR setup pages and recovery-code lists are endemic on phones.
**Scope:** `otpauth://` URIs, TOTP/HOTP secret keys, recovery code blocks (e.g. "XXXX-XXXX-XXXX" patterns in groups of 8-10).
**Priority:** High — one of the most common sensitive items in a photo library.

### 3. DATE_OF_BIRTH
**Why:** Contacts, calendar entries, scanned IDs — DOB is core PII the current validator list lacks.
**Scope:** Common date formats in PII context (near keywords like "DOB", "born", "birthday", "date of birth"). Needs context-gating to avoid flagging every date.
**Priority:** Medium.

### 4. PHYSICAL_ADDRESS
**Why:** Contacts, documents, invoices — street-address detection.
**Scope:** US addresses first (street number + name + city/state/zip). Could extend to international later.
**Priority:** Medium — high value for document scanning use case.

### 5. DRIVERS_LICENSE (State Formats)
**Why:** Photographed licenses via OCR; complements the existing PASSPORT validator.
**Scope:** US state DL number formats (vary by state — CA is 1 letter + 7 digits, NY is 9 digits, etc.). Start with the top 10 states by population.
**Priority:** Medium — strong mobile use case (photos of IDs).

### 6. MEDICAL_ID / PHI Markers
**Why:** Insurance cards, medical letters in Files/photos.
**Scope:** MRN (Medical Record Number), insurance member IDs, NPI (National Provider Identifier), common PHI patterns.
**Priority:** Low-Medium — niche but high-sensitivity (HIPAA-adjacent).

---

## Format Support

### 7. .pkpass / .vcf / .ics Routing
**Why:** Wallet passes, shared contacts, calendar invites are common sensitive files on phones.
**Scope:** Accept these formats in `router.CanProcessFile`:
- `.pkpass` = zip containing JSON (`pass.json`) — extract and scan the JSON
- `.vcf` (vCard) = structured text with PII fields (phone, email, address, DOB)
- `.ics` (iCalendar) = structured text with location, attendees, notes
**Priority:** Medium — expands the mobile scanner's coverage for phone-native file types.

---

## API Surface

### 8. Public `pkg/scan` — expose the existing detection paths

**Why:** Detection should work whether or not you ever redact. Third-party apps
and the mobile repo currently can't call the engine's detection because it's
locked behind `internal/`. The capability already exists (`core.ScanContent` for
text, `core.ScanFile` for files) — it just needs a public surface.

**What already exists (internal, working, battle-tested):**
- `internal/core.ScanContent(content string, cfg ContentScanConfig) -> *ScanResult`
  — in-memory text scan. Used by `--stdin`. Runs all validators on a string.
- `internal/core.ScanFile(cfg ScanConfig) -> *ScanResult`
  — file-path scan. Handles PDF/DOCX/XLSX/images via preprocessors + worker pool.

**What to expose (new `pkg/scan`, zero new logic):**
```go
package scan // github.com/awslabs/ferret-scan/v2/pkg/scan

// ScanText detects sensitive data in an in-memory string.
// Delegates directly to internal/core.ScanContent — no duplication.
func ScanText(ctx context.Context, text string, opts TextOptions) (*Result, error)

// ScanFile detects sensitive data in a file (PDF, DOCX, images, text, etc.).
// Delegates directly to internal/core.ScanFile — no duplication.
func ScanFile(ctx context.Context, path string, opts FileOptions) (*Result, error)

// CheckNames returns the canonical validator IDs.
func CheckNames() []string
```

**Implementation:** each function is a thin forwarding call that maps the public
`Options` struct to the internal `Config` struct and calls the existing
`core.ScanContent` / `core.ScanFile`. No new detection logic. No duplication.
Zero latency added — it's a direct delegation. The internal functions remain the
single source of truth for the detection pipeline.

**Note on `pkg/redact` duplication:** `pkg/redact.Engine.Redact` currently
rebuilds the validator pipeline itself instead of delegating to
`core.ScanContent` (the code even comments: "ScanContent does this; we repeat it
here because we don't go through ScanContent"). A follow-up cleanup should make
`Redact` call `pkg/scan.ScanText` for detection then layer redaction on top —
eliminating that internal duplication. But that's independent of exposing the
public surface and can be done later without breaking the API.

**Priority:** High — unblocks third-party library consumers AND the mobile repo's
one-way dependency goal (see `UPSTREAM.md` in ferret-scan-mobile).

**Benefit:** once this lands, the mobile repo can switch from build-time engine
injection (`scripts/bind.sh`) to a plain `require github.com/awslabs/ferret-scan/v2`
+ import `pkg/scan`. The detection pipeline stays in one place (internal/core),
the public surface is just a forwarding layer, and `pkg/redact` can eventually
consume it too.

---

## Status

| # | Ask | Status | Notes |
|---|---|---|---|
| 1 | BANK_ACCOUNT / IBAN | Not started | |
| 2 | TWO_FACTOR_CODES | Not started | |
| 3 | DATE_OF_BIRTH | Not started | |
| 4 | PHYSICAL_ADDRESS | Not started | |
| 5 | DRIVERS_LICENSE | Not started | |
| 6 | MEDICAL_ID / PHI | Not started | |
| 7 | .pkpass / .vcf / .ics | Not started | |
| 8 | `pkg/scan` public API | **Done** | Implemented: ScanText, ScanFile, RedactText, RedactFile, CanProcessFile, CheckNames, ConfidenceOf, ParseStrategy. 27 tests. |

---

## Status

| # | Ask | Status | Notes |
|---|---|---|---|
| 1 | BANK_ACCOUNT / IBAN | Not started | |
| 2 | TWO_FACTOR_CODES | Not started | |
| 3 | DATE_OF_BIRTH | Not started | |
| 4 | PHYSICAL_ADDRESS | Not started | |
| 5 | DRIVERS_LICENSE | Not started | |
| 6 | MEDICAL_ID / PHI | Not started | |
| 7 | .pkpass / .vcf / .ics | Not started | |
| 8 | ScanText public API | Not started | Highest architectural impact |
