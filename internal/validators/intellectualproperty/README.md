# Intellectual Property Validator

This validator detects various types of intellectual property references in files, including patents, trademarks, copyrights, and trade secrets. It's designed to identify potential IP disclosures or references that might need review before sharing code or documents.

## Supported Types/Formats

### Patents
- US patent numbers (e.g., US9123456, US 9,123,456)
- European patent numbers (e.g., EP1234567, EP 1,234,567)
- Japanese patent numbers (e.g., JP6123456)
- Chinese patent numbers (e.g., CN101234567)
- International/PCT patent numbers (e.g., WO2019123456)

### Trademarks
- Trademark symbol (™) references (e.g., ProductName™)
- Registered trademark symbol (®) references (e.g., ProductName®)
- Text-based trademark references (e.g., ProductName(TM), ProductName(R))
- Explicit trademark statements (e.g., ProductName Trademark, ProductName Registered Trademark)

### Copyrights
- Copyright symbol (©) with year and owner (e.g., © 2023 Company Name)
- Text-based copyright notices (e.g., Copyright 2023 Company Name)
- Year ranges in copyright notices (e.g., © 2020-2023 Company Name)

### Trade Secrets
- Confidentiality markings (e.g., Confidential, Company Confidential)
- Trade secret declarations (e.g., Trade Secret, Proprietary)
- Restricted access markings (e.g., Internal Use Only, Restricted)

### Internal URLs
- Internal company domain patterns (e.g., *.internal.*, *.corp.*)
- Internal service URLs (configurable via ferret.yaml)
- Company-specific domains and subdomains

## Detection Capabilities

- **Pattern Recognition**: Uses regex patterns to identify common IP reference formats
- **Contextual Analysis**: Analyzes surrounding text to improve detection accuracy
- **Format Validation**: Applies format-specific validation rules for each IP type
- **False Positive Reduction**: Filters out common examples and test patterns

## Confidence Scoring

The validator assigns confidence scores based on multiple factors:

- **HIGH** (90-100%): Strong format match with supporting contextual keywords and proper symbols
- **MEDIUM** (60-89%): Good format match but limited contextual support or minor format issues
- **LOW** (40-59%): Potential match with significant format issues or contradictory context

Factors affecting confidence:
1. Format correctness (proper symbols, numbers, formatting)
2. Presence of supporting contextual keywords
3. Absence of negative keywords suggesting examples or tests
4. Specific validation rules for each IP type

## Implementation Details

### Pattern Matching
The validator uses specialized regex patterns for each IP type:
- Patent numbers with country codes and proper formatting
- Trademark symbols and text references
- Copyright notices with year and owner information
- Trade secret and confidentiality markings

### Contextual Analysis
The validator examines text surrounding potential matches for:
- Positive keywords that suggest IP context (e.g., "patent", "trademark", "proprietary")
- Negative keywords that suggest non-IP context (e.g., "example", "test", "public domain")

### Type-Specific Validation
Each IP type has specialized validation rules:
- Patents: Validates country codes and number formats
- Trademarks: Checks for proper symbols and references
- Copyrights: Validates year formats and owner information
- Trade Secrets: Analyzes strength of confidentiality markings

## Usage Examples

```go
// Initialize the validator
validator := intellectualproperty.NewValidator()

// Validate a file
matches, err := validator.Validate("path/to/file.txt")
if err != nil {
    log.Fatalf("Error validating file: %v", err)
}

// Process matches
for _, match := range matches {
    fmt.Printf("Found %s at line %d: %s (Confidence: %.2f%%)\n",
        match.Metadata["ip_type"], match.LineNumber, match.Text, match.Confidence)
}
```

## Configuration

**IMPORTANT: Custom internal URL patterns and intellectual property patterns can ONLY be configured through the ferret.yaml configuration file. There are no command-line options to specify these patterns.**

The validator can be configured through the ferret.yaml configuration file:

### Basic Profile Configuration

```yaml
profiles:
  ip-scan:
    format: text
    confidence_levels: all
    checks: INTELLECTUAL_PROPERTY
    verbose: true
    no_color: false
    recursive: true
    description: "Scan only for intellectual property references"
```

### Advanced Configuration with Custom Patterns

You can customize the validator's behavior by specifying internal URL patterns and custom intellectual property patterns:

```yaml
# Global validator configuration (applies to all profiles)
validators:
  intellectual_property:
    # Internal company URL patterns to detect
    internal_urls:
      - "http[s]?:\\/\\/s3\\.amazonaws\\.com"
      - "http[s]?:\\/\\/.*\\.internal\\..*"
      - "http[s]?:\\/\\/.*\\.corp\\..*"
      - "http[s]?:\\/\\/.*-internal\\..*"

    # Custom intellectual property patterns
    intellectual_property_patterns:
      patent: "\\b(US|EP|JP|CN|WO)[ -]?(\\d{1,3}[,.]?\\d{3}[,.]?\\d{3}|\\d{1,3}[,.]?\\d{3}[,.]?\\d{2}[A-Z]\\d?)\\b"
      trademark: "\\b(\\w+\\s*[™®]|\\w+\\s*\\(TM\\)|\\w+\\s*\\(R\\)|\\w+\\s+Trademark|\\w+\\s+Registered\\s+Trademark)\\b"
      copyright: "(©|\\(c\\)|\\(C\\)|Copyright|\\bCopyright\\b)\\s*\\d{4}[-,]?(\\d{4})?\\s+[A-Za-z0-9\\s\\.,]+"
      trade_secret: "\\b(Confidential|Trade\\s+Secret|Proprietary|Company\\s+Confidential|Internal\\s+Use\\s+Only|Restricted|Classified)\\b"

# Profile-specific validator configuration (overrides global settings)
profiles:
  company-specific:
    format: text
    confidence_levels: all
    checks: INTELLECTUAL_PROPERTY
    verbose: true
    recursive: true
    description: "Company-specific intellectual property scan"
    validators:
      intellectual_property:
        internal_urls:
          - "http[s]?:\\/\\/internal\\.example\\.com"
          - "http[s]?:\\/\\/wiki\\.example\\.com"
          - "http[s]?:\\/\\/.*\\.internal\\.example\\.com"
```
