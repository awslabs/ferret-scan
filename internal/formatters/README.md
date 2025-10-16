# Ferret-Scan Output Formatters

This directory contains output formatters for Ferret-Scan results. Each formatter is responsible for converting scan results into a specific output format.

## Architecture

The formatter system follows a plugin-like architecture where:

1. **formatter.go** - Contains the main `Formatter` interface and registry system
2. **Individual formatter directories** - Each output format has its own directory (e.g., `text/`, `json/`, `junit/`, `yaml/`)
3. **Shared components** - Common data structures and logic in the `shared/` directory
4. **Auto-registration** - Formatters register themselves with the global registry during initialization

## Formatter Interface

All formatters must implement the `Formatter` interface:

```go
type Formatter interface {
    // Format formats the matches according to the formatter's specific output format
    Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options FormatterOptions) (string, error)

    // Name returns the name of the formatter (e.g., "json", "text", "csv")
    Name() string

    // Description returns a brief description of what this formatter outputs
    Description() string

    // FileExtension returns the recommended file extension for this format (e.g., ".json", ".txt", ".csv")
    FileExtension() string
}
```

## FormatterOptions

The `FormatterOptions` struct provides configuration for all formatters:

```go
type FormatterOptions struct {
    ConfidenceLevel map[string]bool // Which confidence levels to display ("high", "medium", "low")
    Verbose         bool            // Whether to display detailed information
    NoColor         bool            // Whether to disable colored output (for text-based formats)
    ShowMatch       bool            // Whether to display the actual matched text
}
```

## Creating a New Formatter

To create a new formatter:

1. **Create a new directory** under `internal/formatters/` with your format name (e.g., `csv/`)

2. **Create a `formatter.go` file** in your directory that implements the `Formatter` interface:

```go
package csv

import (
    "ferret-scan/internal/detector"
    "ferret-scan/internal/formatters"
)

type Formatter struct{}

func NewFormatter() *Formatter {
    return &Formatter{}
}

func (f *Formatter) Name() string {
    return "csv"
}

func (f *Formatter) Description() string {
    return "Comma-separated values for spreadsheet import"
}

func (f *Formatter) FileExtension() string {
    return ".csv"
}

func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
    // Your formatting logic here
    return "", nil
}

// Register the formatter during package initialization
func init() {
    formatters.Register(NewFormatter())
}
```

3. **Import your formatter** in the main application to trigger registration:

```go
import _ "ferret-scan/internal/formatters/csv"
```

## Shared Components

For formatters that need to maintain compatibility (like JSON and YAML), use the shared package:

### Using Shared Data Structures

```go
import "ferret-scan/internal/formatters/shared"

// Use shared conversion logic
response := shared.ConvertMatchesToJSONFormat(matches, suppressedMatches, options)

// Use shared filtering
filteredMatches := shared.FilterMatchesByConfidence(matches, options)
```

### Shared Package Contents

- **`JSONResponse`** - Common response structure with dual JSON/YAML tags
- **`JSONMatch`** - Match structure compatible with both JSON and YAML
- **`FilterMatchesByConfidence()`** - Confidence-based filtering logic
- **`ConvertMatchesToJSONFormat()`** - Converts detector matches to JSON/YAML format
- **`GetConfidenceLevel()`** - Confidence level classification

### Maintaining Compatibility

When creating formatters that should be structurally identical:

1. **Use shared data structures** with appropriate tags:
   ```go
   type MyStruct struct {
       Field string `json:"field" yaml:"field" xml:"field"`
   }
   ```

2. **Use shared processing logic** to ensure identical filtering and conversion

3. **Only differ in marshaling**:
   ```go
   // JSON formatter
   return json.MarshalIndent(response, "", "  ")

   // YAML formatter
   return yaml.Marshal(response)
   ```

## Data Structures

### detector.Match
Contains information about a detected sensitive data match:
- `Text` - The matched text
- `LineNumber` - Line number where match was found
- `Type` - Type of sensitive data (e.g., "EMAIL", "SSN", "CREDIT_CARD")
- `Confidence` - Confidence score (0-100)
- `Filename` - Path to the file containing the match
- `Validator` - Name of the validator that found this match
- `Context` - Contextual information around the match
- `Metadata` - Additional metadata specific to the match type

### detector.SuppressedMatch
Contains information about matches that were suppressed by rules:
- `Match` - The original match that was suppressed
- `SuppressedBy` - Rule or reason for suppression
- `RuleReason` - Human-readable reason for suppression
- `ExpiresAt` - When the suppression expires (if applicable)
- `Expired` - Whether the suppression has expired

### detector.ContextInfo
Provides context around a match:
- `BeforeText` - Text before the match
- `AfterText` - Text after the match
- `FullLine` - Complete line containing the match
- `PositiveKeywords` - Keywords that increase confidence
- `NegativeKeywords` - Keywords that decrease confidence
- `ConfidenceImpact` - Impact on confidence score

## Best Practices

1. **Error Handling** - Always return meaningful errors from the `Format` method
2. **Performance** - Consider memory usage for large result sets
3. **Configurability** - Respect all `FormatterOptions` settings
4. **Security** - Be careful with sensitive data in output (respect `ShowMatch` option)
5. **Consistency** - Follow similar patterns to existing formatters
6. **Testing** - Include comprehensive tests for your formatter
7. **Compatibility** - Use shared components when formatters need to maintain structural compatibility
8. **Dependencies** - Only use dependencies with compatible licenses (MIT, BSD, Apache)

## Existing Formatters

- **text** - Human-readable text output with colors and tables
- **json** - Structured JSON output for programmatic consumption
- **csv** - Comma-separated values for spreadsheet import
- **yaml** - YAML format output, 100% compatible with JSON structure
- **junit** - JUnit XML format for CI/CD integration and test reporting
- **gitlab-sast** - GitLab Security Report format for GitLab Security Dashboard integration

## Integration

Formatters are automatically discovered and registered through the `init()` function pattern. The main application uses the registry to:

1. List available formatters
2. Get a specific formatter by name
3. Format results using the selected formatter

Example usage:
```go
// Get the appropriate formatter with error handling
formatter, exists := formatters.Get(format)
if !exists {
    availableFormats := formatters.List()
    fmt.Fprintf(os.Stderr, "Error: Unsupported output format '%s'\n", format)
    fmt.Fprintf(os.Stderr, "Supported formats: %s\n", strings.Join(availableFormats, ", "))
    os.Exit(1)
}

// Format the results
output, err := formatter.Format(matches, suppressedMatches, options)
if err != nil {
    fmt.Fprintf(os.Stderr, "Error formatting results: %v\n", err)
    os.Exit(1)
}
```

## Format-Specific Notes

### JUnit XML
- Designed for CI/CD integration
- Each scanned file becomes a test case
- Security findings become test failures
- Compatible with Jenkins, GitLab CI, GitHub Actions
- Use `--confidence high` in CI/CD to avoid false positive failures

### YAML
- 100% structurally compatible with JSON output
- Uses shared data structures to guarantee compatibility
- Suitable for configuration-driven workflows and GitOps
- Can be converted to/from JSON without data loss

### JSON
- Uses shared data structures for YAML compatibility
- Structured output for programmatic consumption
- Includes optional verbose context information

### Text
- Human-readable output with colors and tables
- Supports both summary and detailed verbose modes
- Respects `--no-color` flag for CI/CD environments

### GitLab SAST
- GitLab Security Report format (schema v15.0.4)
- Integrates with GitLab Security Dashboard and merge request widgets
- Maps Ferret confidence levels to GitLab severity (High→Critical, Medium→High, Low→Medium)
- Sanitizes sensitive data to prevent exposure in vulnerability descriptions
- Generates deterministic vulnerability IDs for consistent tracking
- Includes proper GitLab analyzer and scanner metadata
