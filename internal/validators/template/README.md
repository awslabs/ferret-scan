# Template Validator

This is a template for creating new validators. Replace this content with information about your specific validator.

## Supported Types/Formats

- Format 1 (describe the format your validator detects)
- Format 2 (describe additional formats)
- Additional formats...

## Detection Capabilities

- Describe the key features of your validator
- Explain what patterns it can detect
- Mention any special handling for edge cases

## Confidence Scoring

Explain how confidence scores are calculated:

- **HIGH** (90-100%): Criteria for high confidence matches
- **MEDIUM** (60-89%): Criteria for medium confidence matches
- **LOW** (0-59%): Criteria for low confidence matches

## Implementation Details

Describe how your validator works:

1. Pattern matching approach
2. Validation algorithms used
3. Context analysis techniques
4. Any other technical details

## Usage Examples

```go
// Create a new validator
validator := yourpackage.NewValidator()

// Validate a file
matches, err := validator.Validate("path/to/file.txt")
if err != nil {
    log.Fatalf("Error validating file: %v", err)
}

// Process matches
for _, match := range matches {
    fmt.Printf("Found match: %s (Confidence: %.2f)\n", match.Text, match.Confidence)
}
```
