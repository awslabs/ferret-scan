# Credit Card Validator

The Credit Card Validator detects credit card numbers in text content using pattern matching, validation algorithms, and contextual analysis, with automatic identification of specific credit card types for better categorization.

## Supported Card Types

The validator automatically detects and categorizes the following credit card types in the TYPE column:

| Type | Pattern | Description |
|------|---------|-------------|
| **VISA** | 4xxx-xxxx-xxxx-xxxx | Cards starting with 4 |
| **MASTERCARD** | 5xxx-xxxx-xxxx-xxxx | Cards starting with 51-55 or 2221-2720 |
| **AMERICAN_EXPRESS** | 3xxx-xxxxxx-xxxxx | Cards starting with 34 or 37 |
| **DISCOVER** | 6xxx-xxxx-xxxx-xxxx | Cards starting with 6011, 65, or 644-649 |
| **DINERS_CLUB** | 3xxx-xxxxxx-xxxx | Cards starting with 30, 36, or 38 |
| **JCB** | 35xx-xxxx-xxxx-xxxx | Cards starting with 35 |
| **UNIONPAY** | 62xx-xxxx-xxxx-xxxx | Cards starting with 62 |
| **MAESTRO** | 5xxx-xxxx-xxxx-xxxx | Cards starting with 50 or 56-58 |
| **PRIVATE_LABEL_CARD** | 8xxx-xxxx-xxxx-xxxx | Cards starting with 8 (private label/regional) |
| **CREDIT_CARD** | Various | Generic type for unrecognized patterns |

## Detection Capabilities

- **Multiple Format Support**: Detects credit cards in various formats:
  - Dash-separated: `4532-0151-1283-0366`
  - Space-separated: `4532 0151 1283 0366`
  - No separators: `4532015112830366`
  - Mixed formats: `4532-0151 1283-0366`
- **XML/HTML Context**: Properly detects cards within XML/HTML tags: `<creditCard>4532-0151-1283-0366</creditCard>`
- **Quoted Strings**: Enhanced detection within quoted contexts: `"card": "4532-0151-1283-0366"`
- **All Card Lengths**: Supports 14-digit (Diners), 15-digit (Amex), and 16-digit cards
- **Luhn Validation**: Uses Luhn algorithm to reduce false positives
- **Card Type Detection**: Identifies card type based on IIN (Issuer Identification Number) ranges
- **Context Analysis**: Analyzes surrounding context to improve confidence scoring
- **Test Pattern Recognition**: Automatically identifies and flags test patterns with low confidence

## Confidence Scoring

The validator assigns confidence scores based on multiple factors:

- **HIGH** (90-100%): Valid card number passing Luhn check with correct length and IIN range for a known card type
- **MEDIUM** (60-89%): Valid number passing Luhn check but with uncertain card type or unusual context
- **LOW** (0-59%): Number with credit card-like pattern but failing validation checks or in contexts suggesting test data

## Implementation Details

The validator uses an optimized multi-step process:

1. **Enhanced Pattern Matching**: Uses comprehensive regex patterns to identify potential credit card numbers in multiple formats:
   - Dash-separated patterns: `\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}`
   - Space-only patterns: `\d{4}\s\d{4}\s\d{4}\s\d{4}`
   - No-separator patterns: `\d{16}`, `\d{15}`, `\d{14}`
   - XML/HTML boundary support: `(?:^|[\s\t,;|"'(){}[\]<>])`

2. **Luhn Algorithm Validation**: Filters out mathematically invalid numbers to reduce false positives

3. **Efficient BIN Range Checking**: Uses optimized range lookup instead of massive maps for card type identification

4. **Context Analysis**: Analyzes surrounding text with positive/negative keyword detection:
   - Positive keywords: "credit", "card", "payment", "visa", "mastercard"
   - Negative keywords: "account", "id", "serial", "tracking", "reference"

5. **Test Pattern Detection**: Identifies common test patterns and assigns very low confidence scores

6. **Performance Optimizations**:
   - Early filtering by length and format
   - Pre-compiled regex patterns
   - Efficient BIN range lookup (600x faster validator creation)

## Format Support Examples

The validator now supports credit cards in various contexts:

```text
<!-- XML/HTML Context -->
<creditCard>4532-0151-1283-0366</creditCard>
<input value="5425-2334-3010-9903">

<!-- JSON Context -->
{
  "visa": "4532015112830366",
  "mastercard": "5425 2334 3010 9903"
}

<!-- CSV Context -->
Name,Card,Expiry
John,"4532-0151-1283-0366",12/25

<!-- Tabular Data -->
Name            Card                    Expiry
John Smith      4532-0151-1283-0366     12/25
Jane Doe        5425 2334 3010 9903     06/26
```

## Usage Examples

```go
// Create a new credit card validator
validator := creditcard.NewValidator()

// Validate a file
matches, err := validator.Validate("path/to/file.txt")
if err != nil {
    log.Fatalf("Error validating file: %v", err)
}

// Process matches
for _, match := range matches {
    fmt.Printf("Found credit card: %s (Type: %s, Confidence: %.2f)\n",
        match.Text, match.Type, match.Confidence)

    // Access additional metadata
    if cardType, ok := match.Metadata["card_type"].(string); ok {
        fmt.Printf("  Card Type: %s\n", cardType)
    }
    if vendor, ok := match.Metadata["vendor"].(string); ok {
        fmt.Printf("  Vendor: %s\n", vendor)
    }
}
```

## Example Output

The validator detects credit cards in various formats and provides detailed type information:

```
LEVEL    VALIDATOR    TYPE                 CONF%    LINE       MATCH               FILE
---------------------------------------------------------------------------------------------
[HIGH  ] creditcard   VISA                  100.00% line     1 4532-0151-1283-0366 document.txt
[HIGH  ] creditcard   VISA                  100.00% line     2 4532 0151 1283 0366 document.txt
[HIGH  ] creditcard   VISA                  100.00% line     3 4532015112830366    document.txt
[HIGH  ] creditcard   MASTERCARD            100.00% line     4 5425-2334-3010-9903 document.txt
[HIGH  ] creditcard   AMERICAN_EXPRESS      100.00% line     5 3782-8224-6310-005  document.txt
[LOW   ] creditcard   VISA                   15.00% line     6 4000-0000-0000-0002 document.txt
```

**Key Features:**
- **Multiple Formats**: Same card detected in dash, space, and no-separator formats
- **Accurate Typing**: Precise card type identification (VISA, MASTERCARD, etc.)
- **Confidence Scoring**: High confidence for real cards, low for test patterns
- **Context Awareness**: Confidence adjusted based on surrounding text

This comprehensive detection makes it easier to identify and handle different credit card formats according to your specific security requirements.
