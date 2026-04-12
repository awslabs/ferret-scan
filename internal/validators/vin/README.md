# VIN Validator

Detects Vehicle Identification Numbers (VINs) in scanned content.

## What it detects

- 17-character alphanumeric VINs (ISO 3779 / SAE J853)
- Excludes characters I, O, Q per VIN standard
- Validates the check digit at position 9 using the weighted transliteration algorithm

## Validation pipeline

1. **Regex match** - 17 alphanumeric characters (A-H, J-N, P-R, S-Z, 0-9)
2. **Early rejection** - All-repeating characters, known test patterns
3. **Check digit validation** - Mod-11 weighted checksum (position 9)
4. **Encoded data filter** - Rejects matches embedded in hex dumps or longer tokens
5. **Confidence scoring** - Base confidence + WMI lookup + model year + context keywords

## Confidence factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Format | 65% base | Valid 17-char VIN format |
| Check digit | +20% | Position 9 check digit passes |
| Known WMI | +10% | Recognized manufacturer prefix |
| Model year | +5% | Valid year code at position 10 |
| Context | +/-50% max | Keyword analysis of surrounding text |

## Usage

```bash
ferret-scan --file vehicle-records.txt --checks VIN
ferret-scan --file fleet-data.csv --checks VIN --confidence high
```
