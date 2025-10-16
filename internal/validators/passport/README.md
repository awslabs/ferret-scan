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

// Validate a file
matches, err := validator.Validate("path/to/file.txt")
if err != nil {
    log.Fatalf("Error validating file: %v", err)
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

#### US Passport
- 9 digits (older passports: 6-9 alphanumeric characters)

#### UK Passport
- 9 digits preceded by country code (e.g., GBR12345678)

#### Canadian Passport
- 8 characters (2 letters followed by 6 digits)

#### EU Passport
- Varies by country, typically follows ICAO 9303 standard

#### MRZ Format
- Two or three lines of 44 characters each
- Contains passport number, name, nationality, date of birth, etc.

## Testing

Tests for the passport validator can be found in `passport_validator_test.go`. Run them with:

```bash
go test -v ./internal/validators/passport
```
