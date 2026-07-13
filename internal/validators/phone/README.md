# Phone Validator

Detects phone numbers in scanned content across US/Canada, UK, European, and
international formats, with various separators (spaces, dashes, dots, parentheses).

## What it detects

- US/Canada domestic and international (`(555) 123-4567`, `+1 555 123 4567`)
- US/Canada toll-free (800, 833, 844, 855, 866, 877, 888)
- UK domestic and international (`0207 123 4567`, `+44 207 123 4567`)
- European and global mobile formats (`+33 1 42 34 56 78`, `+49 30 12345678`)
- Extensions (`ext`, `extension`, `x` + 1-6 digits)

## Validation pipeline

1. **Regex match** - Recognized domestic / international phone patterns
2. **Length check** - Must be 7-15 digits
3. **Test-number filter** - Rejects known test / placeholder numbers
4. **Sequential / repeating filter** - Rejects `1234567`-style and repeated-digit runs
5. **Timestamp filter** - Rejects values that look like timestamps
6. **Confidence scoring** - Base + country-format validation + context keyword analysis

## Confidence factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Valid Format | 18% | Matches a recognized phone pattern |
| Reasonable Length | 14% | Between 7 and 15 digits |
| Not Test Number | 18% | Does not match known test patterns |
| Valid Digits | 9% | Contains valid phone characters |
| Not Sequential | 14% | Not sequential digits |
| Not Repeating | 14% | No excessive repeating digits |
| Valid Country | 5% | Matches country format rules |
| Not Timestamp | 8% | Does not match timestamp patterns |

## Usage

```bash
ferret-scan --file contacts.csv --checks PHONE
ferret-scan --file customer-records.txt --checks PHONE --confidence high
ferret-scan --file support-logs.json --checks PHONE --verbose
```
