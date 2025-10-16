# SSN Validator

The SSN (Social Security Number) validator detects Social Security Numbers in various formats using pattern matching, validation rules, and contextual analysis.

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
   - `900-999` are invalid
2. **Group Number** (middle 2 digits): Cannot be `00`
3. **Serial Number** (last 4 digits): Cannot be `0000`

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
```

## Common False Positives

The validator is designed to minimize false positives from:

- Phone numbers in similar formats
- ZIP codes with extensions
- Account numbers
- Serial numbers
- Other 9-digit identification numbers

## Usage Notes

1. **Context Matters**: The validator relies heavily on contextual keywords for accuracy
2. **Document Types**: Most effective on HR documents, tax forms, and employment records
3. **Data Sensitivity**: SSNs are highly sensitive - validate findings manually for critical applications
4. **Legal Compliance**: Ensure proper handling of detected SSNs per privacy regulations

## Implementation Details

The validator implements the `detector.Validator` interface with:

- `Validate(filePath string)` - Scans files directly
- `ValidateContent(content, originalPath string)` - Scans preprocessed content
- `CalculateConfidence(match string)` - Computes confidence scores
- `AnalyzeContext(match, context)` - Analyzes surrounding text

## Limitations

- Cannot verify if an SSN is actually assigned to a person
- May miss SSNs in unusual formats or with additional characters
- Requires contextual keywords for high confidence detection
- Cannot distinguish between valid SSNs and other 9-digit numbers without context
