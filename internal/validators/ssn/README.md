# SSN Validator

The SSN (Social Security Number) validator detects Social Security Numbers in various formats using pattern matching, validation rules, and contextual analysis. It also reports IRS Individual Taxpayer Identification Numbers under their own type, `ITIN` (see [ITIN](#itin)).

## Features

- **Multiple Format Support**: Detects SSNs in formats like `123-45-6789`, `123456789`, and `123 45 6789`
- **SSA Validation Rules**: Implements official Social Security Administration validation rules
- **Contextual Analysis**: Uses surrounding keywords to improve detection accuracy
- **Test Data Filtering**: Identifies and filters common test SSN patterns
- **Pattern Recognition**: Detects sequential and repeating number patterns that indicate test data

## Detection Capabilities

### Supported Formats

- `XXX-XX-XXXX` - Standard hyphenated format
- `XXXXXXXXX` - 9 consecutive digits
- `XXX XX XXXX` - Space-separated format

### Validation Rules

The validator implements official SSN validation rules:

1. **Area Number** (first 3 digits): Must be 001-665 or 667-899
   - `000` is invalid
   - `666` is invalid
   - `900-999` are never an SSN; a value there is checked as an [ITIN](#itin) instead
2. **Group Number** (middle 2 digits): Cannot be `00`
3. **Serial Number** (last 4 digits): Cannot be `0000`

### ITIN

An IRS Individual Taxpayer Identification Number is written like an SSN, but it begins with `9`
and its 4th and 5th digits are 50-65, 70-88, 90-92 or 94-99
([IRS Publication 4757](https://www.irs.gov/pub/irs-pdf/p4757.pdf)). Group 93 (the ATIN) is not
reported. A value is reported as type `ITIN`, under `--checks SSN`, when:

- its digits pass that rule, its serial is not `0000`, and it is neither in the SSA advertising
  block `987-65-4320`..`4329` nor the repdigit `999-99-9999`; and
- it is written `9XX-XX-XXXX` or `9XX XX XXXX`, or, as nine bare digits (or one half of a glued
  18-digit run in a Word document), its line or its column header says `ITIN` or
  `Individual Taxpayer Identification Number`.

The second condition is the form gate. A bare nine-digit run beginning with 9 is common in code and
data, and a Chilean mobile is `+56 9XXXXXXXX`, so the bare form needs the label.

An ITIN is scored on the SSN curve: its 9xx area counts as a valid area, and every other term,
keyword and penalty is the SSN's. `ITIN`, `Individual Taxpayer Identification Number` and `W-7` are
extra positive keywords for an ITIN only; they never move an SSN's confidence.

```
ITIN: 912-70-3456        -> ITIN, HIGH
SSN: 912-70-3456         -> ITIN, HIGH (an ITIN group under an SSN label is still an ITIN)
912-70-3456              -> ITIN, MEDIUM
ITIN: 912703456          -> ITIN, HIGH
912703456                -> not reported (bare, no ITIN label)
Contacto: +56 912703456  -> not reported by this validator (a phone number)
912-93-3456              -> not reported (group 93)
987-65-4325              -> not reported (SSA advertising block)
```

### Contextual Keywords

**Positive Keywords** (increase confidence):
- `ssn`, `social security`, `social security number`
- `tax id`, `taxpayer id`, `employee id`
- `benefits`, `medicare`, `medicaid`
- `payroll`, `hr`, `human resources`
- `w2`, `w-2`, `1099`, `tax return`

**Negative Keywords** (decrease confidence):
- `phone`, `telephone`, `fax`
- `zip`, `postal`, `area code`
- `test`, `example`, `sample`, `dummy`
- `credit card`, `account`, `routing`

## Confidence Scoring

The validator uses a multi-factor confidence scoring system:

| Factor | Impact | Description |
|--------|--------|-------------|
| Valid Format | Base 80% | Follows SSN validation rules |
| Valid Area Number | +10% | Area number in valid range |
| Contextual Keywords | +5% to +10% | SSN-related terms nearby |
| Test Number Pattern | -25% | Matches known test SSNs |
| Sequential Numbers | -15% | Contains sequential digits |
| Repeating Patterns | -15% | Contains repeating digits |
| Negative Keywords | -10% to -20% | Non-SSN terms nearby |

## Examples

### Valid Detections

```
Employee SSN: 123-45-6789
→ Detected: 123-45-6789 (Medium confidence)
→ Reason: Valid format + contextual keyword "SSN"

Social Security Number: 987654321
→ Detected: 987654321 (High confidence)
→ Reason: Valid format + strong contextual keywords

Tax ID 456-78-9012 for benefits
→ Detected: 456-78-9012 (High confidence)
→ Reason: Valid format + multiple positive keywords
```

### Filtered Out

```
Phone: 555-123-4567
→ Not detected
→ Reason: Invalid area number (555) + negative keyword "phone"

Test SSN: 000-12-3456
→ Not detected
→ Reason: Invalid area number (000)

Example: 123-45-6789
→ Low confidence detection
→ Reason: Valid format but negative keyword "example"

Profile: https://www.linkedin.com/in/michael-o-291135150
→ Not detected
→ Reason: a bare 9-digit run after `-` or `/` in the path of an http(s) URL is a resource ID
  (a profile-slug tail, a video ID), not an SSN
```

The URL rule is deliberately narrow, because a value that is not reported is not redacted. These
still report exactly as before: a line or column header that names the identifier (`SSN`, `tax id`,
`employee id`, ...; `social` and `hr` do not count), a query value (`?ssn=291135150`), a fragment, a
file name (`.../291135150.pdf`), a stored-file scheme (`s3://`, `file://`, `ftp://`), a field after
a quote, comma or semicolon (the next JSON or CSV field), the dashed form (`291-13-5150`) and a link
written without a scheme (`linkedin.com/in/...`).

## Common False Positives

The validator is designed to minimize false positives from:

- Phone numbers in similar formats
- ZIP codes with extensions
- Account numbers
- Serial numbers
- Other 9-digit identification numbers
- Numeric IDs in web URL paths (profile-slug tails, video and listing IDs)

## Usage Notes

1. **Context Matters**: The validator relies heavily on contextual keywords for accuracy
2. **Document Types**: Most effective on HR documents, tax forms, and employment records
3. **Data Sensitivity**: SSNs are highly sensitive - validate findings manually for critical applications
4. **Legal Compliance**: Ensure proper handling of detected SSNs per privacy regulations

## Implementation Details

The validator implements the `detector.Validator` interface with:

- `ValidateContent(content, originalPath string)` - Scans preprocessed content (the primary entry point)
- `ValidateContentCtx(ctx, content, originalPath string)` - Context-aware form that polls for cancellation (per-job deadline / `--validator-budget`)
- `CalculateConfidence(match string)` - Computes confidence scores
- `AnalyzeContext(match, context)` - Analyzes surrounding text

## Limitations

- Cannot verify if an SSN is actually assigned to a person
- May miss SSNs in unusual formats or with additional characters
- Requires contextual keywords for high confidence detection
- Cannot distinguish between valid SSNs and other 9-digit numbers without context
