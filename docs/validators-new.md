# New Validators — Architecture & Context Design

> Technical reference for the 6 validators added in this release. Each follows
> the same architecture as the existing validators (SSN, CREDIT_CARD, etc.) but
> documents its specific detection logic, context system, and false-positive
> suppression strategy.

---

## Architecture (common to all)

Each validator implements `detector.Validator`:
- **`ValidateContentCtx(ctx, content, originalPath)`** — line-by-line scan with cooperative cancellation (`execguard.LineLoopCancelled`)
- **`CalculateConfidence(match)`** — structural validation (checksums, format rules) → base confidence
- **`AnalyzeContext(match, contextInfo)`** — keyword/domain scoring → confidence adjustment
- **`SetObserver(observer)`** — for observability/logging
- **`GetCheckInfo()`** — help text for `--list-checks`

All regexes are **pre-compiled as package-level vars** (never per-call).
All keyword matching uses **word-boundary-aware** `containsKeyword` (not `strings.Contains`).

---

## 1. BANK_ACCOUNT

### What it detects
| Type | Pattern | Validation |
|---|---|---|
| `ABA_ROUTING` | 9 digits, first 2 in 01-32 | ABA checksum: `(3(d1+d4+d7) + 7(d2+d5+d8) + (d3+d6+d9)) % 10 == 0` |
| `IBAN` | 2-letter country + 2 check digits + up to 30 alphanumeric | mod-97 checksum (ISO 7064) |
| `SWIFT_BIC` | 4 bank + 2 country + 2 location + optional 3 branch | ISO 9362 format, 8 or 11 chars |
| `US_BANK_ACCOUNT` | 8-17 digits in banking context | No structural validation (too diverse); relies entirely on keyword context |

### Context system
- **Positive keywords** (+10 to +25 each): `routing`, `aba`, `account number`, `bank account`, `checking`, `savings`, `wire`, `swift`, `bic`, `iban`, `transit`, `financial institution`, `deposit`, `ach`, `direct deposit`
- **Negative keywords** (-15 to -30): `phone`, `zip`, `postal`, `serial`, `model`, `version`, `test`, `example`, `ssn`, `social security`
- **Cross-validator guard**: Luhn-valid 13-19 digit numbers are excluded (they're credit cards, not bank accounts)

### Why this context design
Routing numbers are exactly 9 digits — the same length as SSNs. Without context, every 9-digit number is ambiguous. The ABA checksum eliminates ~90% of random numbers, and the keyword requirement ("routing", "bank", "ach") handles the remaining overlap with SSN/phone. The Luhn guard was added after adversarial testing found credit card numbers matching as bank accounts.

### Confidence curve
- IBAN (mod-97 valid): 100 base (structural proof)
- SWIFT/BIC (format match): 80 base
- ABA routing (checksum valid + keyword): 85
- ABA routing (checksum valid, no keyword): 50
- US bank account (digits + keyword): 65 base; without keyword: suppressed

---

## 2. OTP

### What it detects
| Type | Pattern | Validation |
|---|---|---|
| `OTPAUTH_URI` | `otpauth://totp/...` or `otpauth://hotp/...` | URI format; must contain `secret=` parameter |
| `OTP_SECRET` | 16-64 char base32 string in TOTP context | Must be near OTP keywords; rejects dictionary words, AKIA keys, sequential patterns |
| `RECOVERY_CODES` | 3+ groups of 4-10 alphanumeric blocks | Pattern: `XXXX-XXXX-XXXX` repeated; requires "recovery" or "backup" context |

### Context system
- **Positive keywords** (+15 to +30): `two-factor`, `2fa`, `mfa`, `authenticator`, `recovery code`, `backup code`, `totp`, `hotp`, `secret key`, `otpauth`, `google authenticator`, `authy`
- **Negative keywords** (-20 to -40): `license`, `activation`, `product key`, `serial`, `uuid`, `hash`, `jwt`, `session`, `version`
- **Entropy/pattern rejection**: words that are valid base32 but clearly not secrets (e.g. "ABCDEFGH", "TESTTEST", AWS `AKIA` prefix) are rejected

### Why this context design
Base32 is the key challenge: any uppercase string of A-Z2-7 is technically valid base32, which includes normal English words, AWS access key IDs, and random identifiers. Without aggressive rejection heuristics + mandatory keyword context, the FP rate is unacceptable. The `otpauth://` URI gets instant HIGH confidence (100) because its structure is unambiguous.

### Confidence curve
- `otpauth://` URI: 100 (unambiguous format)
- Base32 secret + OTP keyword: 80
- Base32 secret alone: suppressed (too ambiguous)
- Recovery codes + "recovery"/"backup" keyword: 75
- Recovery codes without keyword: 30 (could be license keys)

---

## 3. DATE_OF_BIRTH

### What it detects
| Type | Pattern | Validation |
|---|---|---|
| `DATE_OF_BIRTH` | MM/DD/YYYY, DD/MM/YYYY, YYYY-MM-DD, "Month DD, YYYY", "DD Month YYYY" | Date must be plausible (year 1900-2025); month/day in valid ranges |

### Context system — THE MOST CONSERVATIVE VALIDATOR
- **Positive keywords (tiered)**:
  - Strong (+50): `date of birth`, `dob`, `d.o.b`, `birthdate`, `birth date`
  - Medium (+30): `born`, `birthday`, `age`, `years old`
- **Negative keywords (priority suppression)**: `created`, `modified`, `expires`, `expiry`, `due`, `deadline`, `meeting`, `published`, `released`, `updated`, `version`, `build`, `compiled`
- **3-tier priority architecture** (post-adversarial fix):
  1. **Disqualifiers** (ceiling at 20): if file timestamps keywords dominate → hard cap
  2. **Strong positives** (floor at 70): explicit "DOB:" prefix overrides negatives
  3. **Weak context** (additive): birthday/age add incrementally

### Why this context design
Most dates are NOT dates of birth. File timestamps, calendar events, version strings, release dates — the ratio of non-DOB dates to real DOBs in typical documents is easily 100:1. The validator's entire value proposition is **extreme precision** over recall. A missed DOB is acceptable; a false positive on "file modified: 2024-01-15" is not.

The 3-tier priority system was added after adversarial testing found that a negative keyword ("modified") on the same line as an explicit "DOB: 01/15/1990" would kill the finding entirely — the short-circuit bug. The fix: explicit DOB labels always win over ambient negative context.

### Confidence curve
- "DOB: 03/15/1990" → 90+ (explicit label)
- "born January 15, 1990" → 70-80
- "01/15/1990" with no keywords → 15 (nearly suppressed)
- "modified: 01/15/1990" → 0 (explicitly suppressed)

---

## 4. PHYSICAL_ADDRESS

### What it detects
| Type | Pattern | Validation |
|---|---|---|
| `US_STREET_ADDRESS` | Number + Street Name + Type (St/Ave/Blvd/Dr/Ln/Ct/Rd/Way/Pkwy/Cir/…) | Must have a recognized street-type suffix |
| `PO_BOX` | "P.O. Box" / "PO Box" + number | Format match |

### Context system
- **Positive keywords** (+10 to +20): `address`, `street`, `mailing`, `shipping`, `billing`, `residence`, `home`, `office`, `deliver`, `apt`, `suite`, `unit`, `floor`
- **Negative keywords** (-15 to -25): `ip`, `version`, `line`, `page`, `step`, `item`, `chapter`, `section`, `figure`, `equation`
- **Structural requirement**: a street-type suffix (St, Ave, Blvd, etc.) is **mandatory** — "123 Main" alone never matches. This is the primary FP suppression mechanism.
- **City/state/ZIP boost**: if the line also contains a state abbreviation + ZIP pattern, confidence jumps +20

### Why this context design
Addresses are notoriously hard because "number + words" occurs everywhere (code line numbers, version strings, list items, mathematical expressions). The street-type suffix requirement is the single most effective discriminator — it eliminates >95% of false candidates before context analysis even runs. The downside: addresses without a standard suffix (e.g. "123 Broadway") may be missed. This is an acceptable recall gap for precision.

### Confidence curve
- "123 Main St, Springfield, IL 62701" + address keyword → 95
- "123 Main St" alone → 55 (matches but low — no city/state/zip)
- "123 Main" (no type suffix) → 0 (never matches)
- "line 456 in main.go" → 0 (never matches)

---

## 5. DRIVERS_LICENSE

### What it detects
| Type | Pattern | Validation |
|---|---|---|
| `DRIVERS_LICENSE` | State-specific formats for top 10 US states | CA: 1 letter + 7 digits; TX: 8 digits; FL: 1 letter + 12 digits; NY: 9 digits; PA: 8 digits; IL: 1 letter + 11 digits; OH: 2 letters + 6 digits; GA: 9 digits; NC: 1-12 digits; MI: 1 letter + 12 digits |

### Context system — THE MOST KEYWORD-DEPENDENT VALIDATOR
- **Positive keywords** (+30 to +50): `driver`, `license`, `licence`, `dl`, `dmv`, `motor vehicle`, `driving`, `permit`, `state id`, `identification card`, `operator`
- **Negative keywords** (-20 to -35): `ssn`, `social security`, `phone`, `account`, `serial`, `order`, `invoice`, `reference`, `tracking`, `confirmation`
- **Domain disambiguation** (post-adversarial fix): the word "license" alone is insufficient — it could be a software license, fishing license, gun license. The validator now requires **"driver" OR "dl" OR "dmv" OR "motor vehicle"** as a strong anchor, not just "license."
- **UUID/GUID exclusion**: patterns that match UUID format are rejected

### Why this context design
DL number formats are **maximally ambiguous** — they overlap with SSNs (9 digits), phone numbers (10 digits), and generic alphanumeric IDs. A California DL ("D1234567") looks like any letter+digit combination. Without strong keyword anchoring, this validator would fire on every 7-9 digit number in every document. The trade-off: real DL numbers without nearby "driver"/"DL"/"DMV" text will be missed — but that's acceptable because the FP rate of unanchored detection would make the tool unusable.

### Confidence curve
- "Driver's License: D1234567" → 95
- "DL: D1234567" → 90
- "License: D1234567" (bare "license") → 40 (could be software)
- "D1234567" with no context → 20 (too ambiguous)
- "Reference: D1234567" → 0 (negative keyword suppresses)

---

## 6. MEDICAL_ID

### What it detects
| Type | Pattern | Validation |
|---|---|---|
| `NPI` | 10 digits starting with 1 or 2 | **Luhn checksum** on "80840" + NPI (CMS standard) |
| `DEA_NUMBER` | 2 chars + 7 digits | **DEA checksum**: `(d1+d3+d5) + 2*(d2+d4+d6)` last digit = d7; first char in A/B/C/D/F/G/M |
| `MRN` | 6-10 digits | No structural validation — requires strong medical keywords (most restrictive) |
| `INSURANCE_MEMBER_ID` | 8-20 alphanumeric | No structural validation — requires insurance keywords |
| `MEDICARE_MBI` | 11 chars: C-A-N-A-N-A-N-A-N-A-N pattern | Format validation (position-specific char classes) |

### Context system
- **Positive keywords** (+10 to +25): `medical record`, `mrn`, `patient id`, `member id`, `insurance`, `npi`, `provider`, `medicare`, `medicaid`, `beneficiary`, `subscriber`, `policy number`, `group number`, `dea`, `prescriber`, `pharmacy`, `hospital`, `clinic`, `health plan`
- **Negative keywords** (-15 to -30): `phone`, `ssn`, `account`, `order`, `invoice`, `tracking`, `serial`, `model`, `version`, `ip address`, `zip`
- **Hard suppressions**:
  - `test`/`mock`/`demo` → hard cap at 25 regardless of positive keyword count
  - Phone-number context → suppress NPI (both are 10 digits)
  - Hex-prefix strings (0x...) → exclude from MRN matching
- **NPI-MRN dedup**: if a 10-digit number passes NPI Luhn, it's reported ONLY as NPI (not also as MRN)

### Why this context design
Medical IDs are high-sensitivity (HIPAA), so precision matters enormously — a false positive on "phone: 1234567890" flagged as an NPI would erode trust. The NPI Luhn check eliminates ~90% of random 10-digit numbers structurally, but phone numbers also sometimes pass Luhn (by chance). The phone-context suppression was the adversarial finding that caught this.

MRN detection is the most conservative: it's just 6-10 digits, which matches almost anything. Without "medical record", "mrn", "patient", or "hospital" on the same line, it's completely suppressed. The idea: if you're scanning a medical document, MRNs will have nearby medical vocabulary. If you're scanning code, they won't.

### Confidence curve
- NPI (Luhn valid + "provider" keyword): 90
- NPI (Luhn valid, no keyword): 60 (structural proof alone)
- DEA (checksum valid + "pharmacy"): 85
- DEA (checksum valid, no keyword): 55
- MRN (digits + "medical record"): 75
- MRN (digits alone): 15 (suppressed)
- Insurance ID + "member id": 70
- Medicare MBI (format valid + "medicare"): 80

---

## Common design principles across all 6

1. **Structural validation first, keywords second.** If a value fails format/checksum, it's rejected before context analysis runs. This is O(1) per match and eliminates the bulk of candidates cheaply.

2. **Conservative base confidence.** Without keywords, base confidence is always below 60 (MEDIUM threshold) — often below 30. Keywords are what push findings into actionable territory. This ensures that running the scanner on arbitrary text doesn't generate a wall of noise.

3. **Negative keywords are "ceiling" operators.** A positive keyword adds; a strong negative (like "test" or "phone") imposes a hard ceiling that stacking more positives cannot overcome. This prevents the "keyword arithmetic overflow" bug found in adversarial testing.

4. **Cross-validator awareness.** Bank accounts exclude Luhn-valid credit-card-length numbers. Medical IDs exclude phone-context 10-digit numbers. DL numbers exclude SSN-context 9-digit numbers. Each validator knows what the *other* validators are likely to catch and defers.

5. **Explain integration.** Every validator populates `Match.Metadata["validation_checks"]` with a map of which structural rules passed/failed. The explain system reads this to generate the human-readable rationale ("Flagged as a date of birth; it passed the plausible year check and the valid date check; nearby context raised confidence by 75%.").
