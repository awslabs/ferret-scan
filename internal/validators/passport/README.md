# Passport Validator

The Passport Validator detects passport numbers from various countries and formats in text.

## Supported Passport Types

- US passport
- UK passport
- Canadian passport
- EU passport (various countries)
- Machine Readable Zone (MRZ) formats

## Detection Features

- Country-specific format validation
- MRZ format detection and parsing
- Context analysis to improve confidence scoring
- Detection of passport numbers in various contexts (forms, scans, etc.)

## Confidence Scoring

The validator assigns confidence scores based on:

- Compliance with country-specific format rules
- Presence of valid check digits (where applicable)
- Surrounding context (e.g., keywords like "passport", "travel document")
- Presence of related information (name, date of birth, expiration date)

## Usage

```go
// Create a new passport validator
validator := passport.NewValidator()

// Validate already-extracted content (the scan pipeline reads/preprocesses the
// file once and passes the text in; the second arg is the original path, used
// only for reporting/context).
content, _ := os.ReadFile("path/to/file.txt")
matches, err := validator.ValidateContent(string(content), "path/to/file.txt")
if err != nil {
    log.Fatalf("Error validating content: %v", err)
}

// Process matches
for _, match := range matches {
    fmt.Printf("Found %s with confidence %.2f\n", match.Type, match.Confidence)
    if country, ok := match.Metadata["country"].(string); ok {
        fmt.Printf("Passport country: %s\n", country)
    }
}
```

## Implementation Details

The validator works by:

1. Scanning text for patterns that match passport number formats
2. Validating potential matches against country-specific rules
3. Parsing MRZ data when present
4. Analyzing surrounding context to refine confidence scores
5. Returning matches that meet the confidence threshold

### Country-Specific Formats

The `country` value in a finding's metadata is the name of the shape that
matched (`US`, `UK`, `Canada`, `EU`, `MRZ`, `MRZ_TD3`, `MRZ_TD3_L2`), not the
issuing state.

#### US Passport
- 1 letter followed by 8 digits (e.g., C12345678)

#### UK Passport
- 9 digits (e.g., 512345678); a value written with a country prefix such as
  GBR12345678 is not detected

#### Canadian Passport
- 2 letters followed by 6 digits (e.g., GK123456); this is the only Canadian
  shape detected

#### EU Passport
- 2 letters followed by 7 letters or digits (e.g., DE1234567)

#### MRZ Format
- ICAO 9303 TD3: line 1 (`P<` + 3-letter issuing state + name; `MRZ_TD3` is
  exactly 44 characters, `MRZ` 43 to 45) and line 2 (`MRZ_TD3_L2`: document
  number, dates and personal number, 44 characters, accepted only when all five
  check digits verify)
- Uppercase only, as ICAO 9303 defines the zone over `A-Z`, `0-9` and `<`

### Letter case

The US, Canadian and EU shapes are matched in either letter case
([#888](https://github.com/awslabs/ferret-scan/issues/888)). Letters are ASCII
`A-Z` and `a-z` only: a lookalike such as U+212A (Kelvin sign) or U+017F (long
s) is never a letter of a passport number.

- A value written in uppercase (`GK123456`) is scored exactly as before.
- A value containing a lowercase letter (`gk123456`, `Gk123456`) is scored on
  its uppercase form, so it gets the same confidence and bucket as its
  uppercase twin, but it is reported only when it is labelled:
  - a passport label ends at most 50 bytes before it, with nothing between the
    two but separators: `Passport Number: gk123456`, `passport_number:
    gk123456`, `passport no is gk123456`, `passport: gk123456`, `showed passport
    gk123456 at`, `Travel document number: gk123456`. A bare `passport` needs
    whitespace after it, so `.../passport:v20241012` is not a label; or
  - its column header names a passport (a CSV `passport_number` column); or
  - the line above is a field label naming a passport (`Passport Number` on
    its own line) and the value is the first word of its line.
- A labelled lowercase placeholder is not reported: a value whose leading
  letters are `redacted`, `password`, `pending`, `unknown`, `missing`,
  `sample`, `document`, `tbd`, `abc`, `xyz`, `none`, `null` or `test`, or form
  a word of four letters or more (`invalid01`). Uppercase placeholders
  (`REDACTED1`) are reported as before.
- Not covered: a lowercase value whose label comes after it (`gk123456
  (passport number)`), while `GK123456 (passport number)` is reported.

## Testing

Tests for the passport validator are the `*_test.go` files in this directory.
Run them with:

```bash
go test -v ./internal/validators/passport
```
