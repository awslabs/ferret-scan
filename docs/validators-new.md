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
| `IBAN` | 2-letter country + 2 check digits + BBAN, compact or in print grouping (fours separated by one space, two spaces or a hyphen; the last group shorter), read at the country's registered length; a value joined by `_` only when the identifier names it (`iban_DE89…`) | Country, length and BBAN structure (each position's digit/letter class) from the SWIFT IBAN Registry, 89 countries, generated into `iban_registry.go`; mod-97 checksum (ISO 7064) |
| `SWIFT_BIC` | 4 bank + 2 country + 2 location + optional 3 branch | ISO 9362 format, 8 or 11 chars |
| `US_BANK_ACCOUNT` | 8-17 digits in banking context | No structural validation (too diverse); relies entirely on keyword context |

### Context system
- **Positive keywords** (+15 each, total capped at +40): `routing`, `aba`, `account number`, `bank account`, `checking`, `savings`, `wire`, `swift`, `bic`, `iban`, `transit`, `financial institution`, `deposit`, `ach`, `direct deposit`, `bank`, `routing number`, `account no`, `acct`
- **Negative keywords** (-20 each, total floored at -50): `phone`, `zip`, `postal`, `serial`, `model`, `version`, `test`, `example`, `sample`, `ssn`, `social security`, `placeholder`, `fake`, `mock`, `demo`, `ip address`, `order`, `invoice`, `tracking`, `confirmation`
- **Cross-validator guard**: Luhn-valid 13-19 digit numbers are excluded (they're credit cards, not bank accounts)

### Why this context design
Routing numbers are exactly 9 digits — the same length as SSNs. Without context, every 9-digit number is ambiguous. The ABA checksum eliminates ~90% of random numbers, and the keyword requirement ("routing", "bank", "ach") handles the remaining overlap with SSN/phone. The Luhn guard was added after adversarial testing found credit card numbers matching as bank accounts.

### Confidence curve
- IBAN (registry structure and mod-97 valid): 85 + keyword impact, set to 15 when the line's negative context is strong; never dropped, because the checksum is value-intrinsic and context may demote it but not erase it
- SWIFT/BIC (format match): 50 + keyword impact, 75 + keyword impact with a banking keyword on the line; an all-letter code needs `swift`, `bic` or `iban` on the line
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
| Type | Pattern (`format`) | Validation |
|---|---|---|
| `DRIVERS_LICENSE` | US state shapes: 1 letter + 7 digits (`CA_1L7D`); 8 digits (`TX_PA_8D`); 1 letter + 12 digits (`FL_MI_1L12D`); 9 digits (`NY_GA_9D`); 1 letter + 11 digits (`IL_1L11D`); 2 letters + 6 digits (`OH_2L6D`); 1 letter + 14 digits (`NJ_1L14D`); 1 letter + 13 digits (`WI_1L13D`). Also written with dashes or spaces (`D123-4567-8901`). | Shape plus licence context: a label on the line, a label alone on the line above, the column header, or a state name with `id`/`number`. There is no checksum. |
| `DRIVERS_LICENSE` | Great Britain DVLA driver number (`GB_DVLA`): 16 characters, or 18 with the two-digit issue number written straight after it; contiguous, or in 5/6/5 groups separated by single spaces. Written `WOMBA901010ZZ9AA 01`, the issue number stays outside the span. | The DVLA layout: surname letters then 9-padding, birth month 01-12 or 51-62 (+50 for women), day 01-31, initials `[A-Z][A-Z9]` or `99`. No check algorithm is published, so the layout is the gate, on top of the licence context every shape needs. |
| `DRIVERS_LICENSE` | Ontario with hyphens, `A1234-12345-12345` (`CA_ON`); Quebec with hyphens, `A1234-123456-12` (`CA_QC`) — the printed layouts in [#861](https://github.com/awslabs/ferret-scan/issues/861) | Fixed groups, never one segment of a longer hyphenated token (`W1234-12345-12345-0001` is not reported). |

**`format` names the shape, not the issuing authority.** A number from elsewhere that has a US shape is reported under that shape's name: Ontario and Quebec numbers written without hyphens are `NJ_1L14D` and `FL_MI_1L12D`, and Northern Ireland's 8-digit numbers are `TX_PA_8D`. Read the state names in `format` as "a shape these states use", not as the jurisdiction that issued the number.

The North Carolina shape this table used to list ("1-12 digits") was never implemented: 7- and 12-digit values under a licence label give no finding.

**Not supported, by decision** ([#861](https://github.com/awslabs/ferret-scan/issues/861)). Measured there on 43,367 public OSS text files: a prototype of the shapes above plus India added no finding, and adding the other rows below added 216, every inspected one a false positive.

| left out | why |
|---|---|
| bare 7, 10 or 12 digits (BC, AU-WA, NL, AU 10-digit, FR, NC) | no structure or checksum; collides with epoch timestamps, uint32 max and account IDs |
| 1 letter + 8 digits (MA, VA) | the US passport shape |
| DE 11 alphanumerics, IT 2 letters + 7 digits + 1 letter, AU-SA 1 letter + 5 digits, CA-NS 5 letters + 9 digits, PL 5/2/4, ES 8 digits + letter | weak shapes; AU-SA's alone added 118 findings (Doxygen `l00005` anchors) |
| India (state code, RTO, year, serial) | no checksum, so precision would rest on the label alone; needs a cited primary layout source first |
| non-English labels (`Führerschein`, `permis`, `patente`, `licencia`, `carnet`, `CNH`, ...) | single words collide (patent, building permit, any card, software licence); needs a gate that pairs the word with its jurisdiction |
| WA `WDL` + 9 alphanumerics | not in this change; it had no corpus hit in #861's broad prototype, so it can be added as a shape later |

### Context system — THE MOST KEYWORD-DEPENDENT VALIDATOR
- **Positive keywords** (+45 for the first, +10 for each further one, at most +20 more): `driver`, `license`, `licence`, `dl`, `dmv`, `motor vehicle`, `driving`, `permit`, `state id`, `identification card`, `operator`, `dl number`, `license number`, `licence number`, and every licence label spelling (next bullet).
- **Licence label spellings are generated** (`internal/validators/driverslicense/vocabulary.go`): every {`driver`, `drivers`, `driver's`, `driving`} × {`license`, `licence`} × {"", ` number`, ` no`} combination, 24 spellings. The same parts feed the positive keywords, the label-position boost and the anywhere-on-the-line literals, so a spelling is in all three lists or in none ([#861](https://github.com/awslabs/ferret-scan/issues/861)). Before that, the three were written out by hand and had drifted: `drivingLicence:`, `DrivingLicenceNo:` and `driversLicence:` gave no finding, and `Driving licence:` and `Licence No.` scored 75 and 65, while their US twins scored 95.
- **Negative keywords** (-20 to -35): `ssn`, `social security`, `phone`, `account`, `serial`, `order`, `invoice`, `reference`, `tracking`, `confirmation`
- **Bare `license`/`licence`** opens the gate but never earns the label boost: `License: D1234567` scores 65 where a licence label scores 95, and a negative keyword (`software`, `fishing`, `business`, `key`, ...) lowers it further. A label that names some other licence and ends in `licence number` still earns the boost: `Premises licence number: 12341234` scores 95.
- **UUID/GUID**: the words `uuid` and `guid` suppress a finding wherever they sit on the line. A UUID-shaped VALUE is not recognised as one: `DL No: ab123456-0000-4000-8000-000000000001` reports `ab123456` as `OH_2L6D`.
- **Why the suffixed spellings exist**: `internal/validators/kwmatch` matches a keyword's concatenation only as a whole word, so `driversLicenseNumber` needs the three-word keyword, not just `drivers license`. These are not redundant with the shorter keywords, and the reason is worth knowing before editing the vocabulary.

`internal/validators/kwmatch` lets a keyword's spaces match **zero** separators, so a keyword also finds the concatenated and camelCase spellings of itself — but the concatenation must equal the **whole word**. `drivers license` yields `driverslicense` and did find `driversLicense`; append `Number` and the word becomes `driverslicensenumber`, which no two-word keyword can reach. Measured at HEAD, one label per line, with no state name present:

| label | findings |
|---|---|
| `driversLicenseNumber:` | **0** |
| `driverslicensenumber:` | **0** |
| `drivers_license_number:` | 1 @ 85 |
| `Drivers License Number:` | 1 @ 95 |
| `driver's license number:` | 1 @ 95 |
| `driversLicense:` | 1 @ 65 |

camelCase is the default key style of JSON, REST payloads and ORM exports, and the cross-line window (a label alone on the line above its value) had the identical gap. A licence that is not reported is never handed to the redactor: on a realistic JSON export carrying two licences, the scan found **0 findings and wrote no redacted file at all**, leaving both in cleartext ([#438](https://github.com/awslabs/ferret-scan/issues/438)).

That issue was filed against the **apostrophe** in `driver's license`, on the theory that it blocked the camelCase match. That premise is wrong, and it is worth recording because it is an easy trap: the apostrophe spellings already worked, the two failing spellings contain no apostrophe, and making the apostrophe optional in the matcher — measured — changed nothing at all, because the vocabulary still had no three-word keyword to concatenate. So the fix is vocabulary, and the shared matcher's apostrophe handling is deliberately untouched.

**Adding a positive keyword here is safe in one direction only.** It can add findings and never remove one, which is why this widening needed no suppressor review; the same edit to `negativeKeywords` would be a suppression change and is governed by the opposite rule. Measured on 901 real files from this host (401 licence-dense documents, 500 JSON/JS files): **0 findings gained, 0 lost** — the additions are specific enough not to fire on ordinary text — and the like-for-like scan cost of six more keywords is **1.02x**, inside the run-to-run noise of the measurement itself.

One consequence to be aware of: the concatenated spellings land at **65 (MEDIUM)** where the spaced spelling reaches 95, because `findKeywordsOnLine` — which counts keywords for **scoring** — uses the strict matcher, while `lineHasPositiveKeyword` — which opens the **gate** — uses the label-flexible one. So a camelCase label opens the gate but earns no context credit. Redaction still covers the finding (it acts on reported findings regardless of the display filter), but a report gated on `--confidence high` shows it as clean. That asymmetry is tracked separately; it cannot be fixed by widening `findKeywordsOnLine`, because that function is called with `negativeKeywords` too.

### Why this context design
DL number formats are **maximally ambiguous** — they overlap with SSNs (9 digits), phone numbers (10 digits), and generic alphanumeric IDs. A California DL ("D1234567") looks like any letter+digit combination. Without strong keyword anchoring, this validator would fire on every 7-9 digit number in every document. The trade-off: real DL numbers without nearby "driver"/"DL"/"DMV" text will be missed — but that's acceptable because the FP rate of unanchored detection would make the tool unusable.

### The label boost does not depend on the writing convention

A licence label standing in the **label position** — the text before the line's first `:`, `#` or `=` — earns the label boost (+75, taking a finding from the base of 20 to 95), and it earns the same boost however that label is spelled. It did not always: the boost was awarded by matching eleven exact substrings (`drivers license:`, `dl:`, `license number:`, …), every one of which carries a literal space and colon, so the same label written any other way fell through to the generic keyword arm at +45/+55. Measured, one label per line, the identical value:

| label | before | after |
|---|---|---|
| `drivers license:` | 95 HIGH | 95 HIGH |
| `Drivers License:` | 95 HIGH | 95 HIGH |
| `drivers_license:` | 75 MEDIUM | **95 HIGH** |
| `drivers-license:` | 75 MEDIUM | **95 HIGH** |
| `driversLicense:` | 65 MEDIUM | **95 HIGH** |
| `DriversLicense:` | 65 MEDIUM | **95 HIGH** |
| `dlNumber:` | 65 MEDIUM | **95 HIGH** |

camelCase and snake_case are the default key styles of JSON, REST payloads and ORM exports, so the two conventions that lost were the two a machine-generated export uses — and a consumer gated on HIGH saw the spaced form while missing the rest ([#553](https://github.com/awslabs/ferret-scan/issues/553)). Note that the **column-header** path was already convention-insensitive: the same label as a CSV header scored 100 for every spelling both before and after. It was the inline label that lagged behind it.

Two properties keep this from being a confidence giveaway, and both are asserted by tests:

- **The label must occupy the label position.** This is *narrower* than the substring list it supplements: `D1234567: issued under a drivers license` does not earn the boost, because there the licence words follow the separator and are therefore the value, not the label.
- **A label is short.** The label position is bounded at 64 bytes, so a sentence that happens to mention a licence and end in a colon cannot occupy it. Without that bound the separator requirement — which is the whole reason prose is excluded — would be defeated by any prose ending in a colon.

Bare `license` is deliberately **not** one of the labels that earns the boost: it could be a software, fishing, or gun licence. `Software license:` and `Fishing license:` are unchanged, as is `"license": "MIT"` in a package manifest.

### Confidence curve

Measured against the binary rather than transcribed — three of the five rows previously published here were wrong, and had been independent of any recent change:

- `Driver's License: D1234567` → 95 (any convention of the label; see above)
- `DL: D1234567` → 95 (was documented as 90)
- `License: D1234567` (bare "license") → 65 (was documented as 40)
- `Driving licence: D1234567` and `Licence No. D1234567` → 95, like `Driver's license:` and `License No.` (75 and 65 before #861)
- `Driving licence number: WOMBA901010ZZ9AA` → 95 `GB_DVLA`; the same label alone on the line above the value → 85, as for any label above
- `License key: W1234-12345-12345` → 45 `CA_ON` (`key` is a negative keyword)
- `D1234567` with no context → **not reported at all** (was documented as 20). The positive-keyword gate refuses a candidate with no DL vocabulary on the line, which is what the design note above describes; there is no low-confidence finding to see.
- `Reference: D1234567` → 0 (negative keyword suppresses)

---

## 6. MEDICAL_ID

### What it detects
| Type | Pattern | Validation |
|---|---|---|
| `NPI` | 10 digits starting with 1 or 2 | **Luhn checksum** on "80840" + NPI (CMS standard) |
| `DEA_NUMBER` | A registrant letter, a letter (last-name initial) or `9` (business address), 7 digits; either case | **DEA checksum**: `(d1+d3+d5) + 2*(d2+d4+d6)` last digit = d7; first char one of the 18 registrant letters `ABCDEFGHJKLMPRSTUX`. Only `A/B/C/D/F/G/M` + a letter is reported on the value alone; every other letter and the `9` form need DEA context |
| `MRN` | 6-10 digits | No structural validation — requires strong medical keywords (most restrictive) |
| `INSURANCE_MEMBER_ID` | 8-20 alphanumeric | No structural validation — requires insurance keywords |
| `MEDICARE_MBI` | 11 chars in the CMS C-A-AN-N-A-AN-N-A-A-N-N format, compact or card-printed 4-3-4 with dashes or spaces; either case | Format validation (position-specific char classes). An MBI carrying a lowercase letter needs a Medicare-specific label |

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

**"On the same line" is not literal for a delimited table.** In a CSV or TSV export the label lives in the header *row* and the value in a data row, which is the normal shape for this data — so "same line" alone reported nothing for an entire file family, while the identical layout naming an insurance member ID reported normally ([#436](https://github.com/awslabs/ferret-scan/issues/436)). A match is now also resolved to the header cell naming **its own column**, via `internal/tabular`.

Two properties of that arm are worth knowing, because they are what keep it from being a false-positive source:

- It is decided **per column, not per row**. A table holding one medical column does not make its neighbours medical: an `order number` / `invoice number` / `zip code` column beside a `medical record number` column is not reported.
- It only ever **adds** context. There is no "this header contradicts" rule, because suppressing a medical identifier on the strength of a column name would be suppression chosen by whoever wrote the file.

Column names are matched as real systems write them — `PATIENT` (Synthea), `PAT_MRN_ID` (Epic Clarity), `MRN` (Cerner), `patient_identifier`. Generic surrogate keys are deliberately **not** matched: the OMOP CDM's `person_id` is not treated as medical context, since a column of that name appears in countless non-clinical schemas and admitting it would make every one of them medical.

The provider, DEA and Medicare context that scores an `NPI`, a `DEA_NUMBER` and a `MEDICARE_MBI` follows the same per-column rule, and matches the camelCase key a JSON or ORM export writes (`providerNpi`, `npiNumber`, `deaNumber`, `medicareBeneficiaryIdentifier`, `mbiNumber`) as well as the snake_case one ([#858](https://github.com/awslabs/ferret-scan/issues/858)). All of it only adds: it cancels a no-context penalty, and admits the two gated forms below. The phone-context veto keeps the stricter separator-required match.

**Two forms are admitted only by context**, because each widens a pattern into shapes that ordinary non-medical values share ([#858](https://github.com/awslabs/ferret-scan/issues/858)):

- A DEA number whose first letter is one of the eleven newer registrant types (`E`, `H`, `J`, `K`, `L` for manufacturers, labs, importers, exporters and reverse distributors; `P`, `R`, `S`, `T`, `U` for narcotic treatment programs; `X` for the buprenorphine prescribing program), or whose second character is the business-address `9`, is reported only where DEA context covers it: on its line, on a field-label line above, or in its column header. Patent numbers (`EP1234563`) and passport numbers (a letter and 8 digits) have the same shape and pass the check digit one time in ten: measured on random decoys with no DEA context, removing the gate turned 79 of 800 patent numbers and 16 of 3,000 passport numbers into `DEA_NUMBER`. With it, none.
- An MBI written with a lowercase letter (CMS converts one to uppercase rather than rejecting it) is reported only beside a Medicare-specific label: `medicare`, `mbi`, `hicn`, `health insurance claim`, or a compound key such as `medicare_number` or `medicareBeneficiaryIdentifier`. The wider Medicare-adjacent words (`coverage`, `cms`, `enrollment`, `beneficiary`, `medicaid`, `part a/b/d`) still score an uppercase MBI but do not admit a lowercase one: over 200,000 random lowercase hex tokens, they admitted 146 as `MEDICARE_MBI` on `coverage report keys` lines and 153 on `cms asset keys` lines, where the narrow list admits 0. `Member Identification Number`, which insurance cards print too, scores an uppercase MBI but leaves a lowercase value an `INSURANCE_MEMBER_ID`.

The member-ID veto that hands a value to a more specific subtype asks that subtype's own admission decision, not its shape, so it fires only on a value the subtype actually reports: `Member ID: XR1234563` stays an `INSURANCE_MEMBER_ID`, while `Prescriber DEA and member id: XR1234563` is a `DEA_NUMBER`, as its legacy-letter sibling already was.

### What `--explain` says it checked

Every finding carries `Metadata["validation_checks"]`, and `--explain` turns it into the sentence a
reviewer reads. Which checks are recorded depends on the subtype, because the subtypes do not have
the same evidence available — an MBI has no check digit, so its format *is* the structural proof:

| Subtype | Structural check | Context check | Exclusions recorded |
|---|---|---|---|
| `NPI` | `npi_checksum` (always true — a failure is not emitted) | `provider_context` | `not_phone_context` |
| `DEA_NUMBER` | `dea_checksum` (always true) | `prescriber_context` | — |
| `MEDICARE_MBI` | `mbi_format` (always true) | `medicare_context` | — |
| `MRN` | `mrn_label` | `medical_context` | `not_an_npi`, `not_other_number_type` |
| `INSURANCE_MEMBER_ID` | `letters_and_digits` | `insurance_label` | `not_other_id_shape`, `not_a_more_specific_id` |

All five also record `not_test_data`, which is what drives the `likely_test` verdict rather than the
prose — the rationale reports that concept in its own words instead of naming the check.

Two rules govern what may appear here, and both are honesty rules rather than style:

- **Only decisions the validator already made.** A check reported `true` that was never actually
  tested is a false statement to whoever is reading the output to decide whether to redact. This is
  why `MEDICARE_MBI` records `mbi_format` and not `npi_checksum`: there is no check digit in an MBI
  to verify.
- **A check that cannot vary carries no information, so it must be labelled as such.** The three
  checksum-style entries are always `true` at the point of emission because a value that fails them
  is discarded earlier — they tell the reader *which* proof was applied. The context and exclusion
  entries genuinely vary per finding, and a test asserts they do; recording one as a constant would
  read identically in the output while meaning nothing.

Before this, medicalid was the one validator that recorded nothing, so its rationale named no check
at all — "Flagged as an NPI; nearby context raised confidence by 20%" — even though the CMS check
digit had in fact been verified ([#537](https://github.com/awslabs/ferret-scan/issues/537)). The
phone-context exclusion described two principles below was likewise invisible in the output.

### Confidence curve
Measured with the CLI, one value per file (`--checks MEDICAL_ID --confidence all`). The two column
rows are the validator's own score; a CSV file's findings also get the document-level adjustment,
+20 for these files.

- NPI (Luhn valid + "provider" keyword): 90
- NPI (Luhn valid, no keyword): 40 (structural proof alone)
- DEA (checksum valid + "pharmacy" or "prescriber"): 95
- DEA (checksum valid, no keyword): 55
- DEA with a newer registrant letter or a `9` + "DEA number:": 95; the same value with no DEA context: not reported
- MRN (digits + "medical record" on the line): 90
- MRN (digits in a column whose header says "mrn"/"medical record number"): 70
- MRN (digits in a column whose header is generically medical, e.g. "patient"): 45
- MRN (digits alone): 15 (suppressed)
- Insurance ID + "member id": 80
- Medicare MBI (format valid + "medicare"): 85; lowercase, the same 85
- Medicare MBI (format valid, no keyword): 40; lowercase: not reported

---

## Common design principles across all 6

1. **Structural validation first, keywords second.** If a value fails format/checksum, it's rejected before context analysis runs. This is O(1) per match and eliminates the bulk of candidates cheaply.

2. **Conservative base confidence.** Without keywords, base confidence is always below 60 (MEDIUM threshold) — often below 30. Keywords are what push findings into actionable territory. This ensures that running the scanner on arbitrary text doesn't generate a wall of noise.

3. **Negative keywords are "ceiling" operators.** A positive keyword adds; a strong negative (like "test" or "phone") imposes a hard ceiling that stacking more positives cannot overcome. This prevents the "keyword arithmetic overflow" bug found in adversarial testing.

4. **Cross-validator awareness.** Bank accounts exclude Luhn-valid credit-card-length numbers. Medical IDs exclude phone-context 10-digit numbers. DL numbers exclude SSN-context 9-digit numbers. Each validator knows what the *other* validators are likely to catch and defers.

5. **Explain integration.** Every validator populates `Match.Metadata["validation_checks"]` with a map of which structural rules passed/failed. The explain system reads this to generate the human-readable rationale ("Flagged as a date of birth; it passed the plausible year check and the valid date check; nearby context raised confidence by 75%.").
