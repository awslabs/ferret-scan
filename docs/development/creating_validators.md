# Creating Validators for Ferret Scan

[← Back to Documentation Index](../README.md)

> **Note for AI Assistants**: This document is designed to be included in prompts for AI systems to help create new validator modules for the Ferret Scan project. When asked to create a new validator, use this document as a reference for the required structure, interfaces, and best practices.

This guide explains how to create custom validators for the Ferret Scan tool. Validators are modules that detect specific types of sensitive data in files, such as credit card numbers, passport numbers, or any other type of sensitive information you want to detect.

## Table of Contents

- [Creating Validators for Ferret Scan](#creating-validators-for-ferret-scan)
  - [Table of Contents](#table-of-contents)
  - [Validator Structure](#validator-structure)
  - [Creating a New Validator](#creating-a-new-validator)
  - [Implementing the Validator Interface](#implementing-the-validator-interface)
    - [Basic Validator Structure](#basic-validator-structure)
    - [The Validate Method](#the-validate-method)
    - [The CalculateConfidence Method](#the-calculateconfidence-method)
  - [Adding Contextual Analysis](#adding-contextual-analysis)
  - [Creating Documentation](#creating-documentation)
    - [Help Documentation](#help-documentation)
    - [README Documentation](#readme-documentation)
  - [AI-Assisted Validator Creation](#ai-assisted-validator-creation)
  - [Best Practices](#best-practices)
  - [](#)

## Validator Structure

Each validator consists of at least three files:
- `validator.go`: Contains the main validation logic
- `help.go`: Contains help documentation for the validator
- `README.md`: Contains detailed documentation about the validator for developers

These files should be placed in a package under `internal/validators/`, for example:
```
internal/validators/
  ├── creditcard/
  │   ├── validator.go
  │   ├── help.go
  │   └── README.md
  ├── passport/
  │   ├── validator.go
  │   ├── help.go
  │   └── README.md
  └── yourvalidator/
      ├── validator.go
      ├── help.go
      └── README.md
```

## Creating a New Validator

To create a new validator, follow these steps:

1. Create a new directory under `internal/validators/` for your validator (e.g., `internal/validators/ssn/`)
2. Copy the template files (`validator.go`, `help.go`, and `README.md`) from `internal/validators/template/` to your new directory
3. Rename the validator struct (e.g., change `TemplateValidator` to `SSNValidator`) but keep the function name `NewValidator()`
4. Customize the validator logic for your specific use case
5. Update the README.md with detailed documentation about your validator
6. Register your validator in `cmd/main.go` (see the "Registering Your Validator" section below)
7. Add a link to your validator's README in the main README.md under the "Supported Data Types" section
8. Update any configuration files (like `examples/ferret.yaml`) to include your validator in the appropriate profiles
9. If your validator uses specific patterns that should be configurable, add them to the pattern configuration files (like `python_files/config.json`)

> **Important**: Each validator must be in its own package to avoid naming conflicts. The function name `NewValidator()` is used in every validator package, but this doesn't cause conflicts because they're in different packages.

## Implementing the Validator Interface

Your validator must implement the `detector.Validator` interface, which requires the following methods:

```go
type Validator interface {
    Validate(filePath string) ([]Match, error)
    CalculateConfidence(match string) (float64, map[string]bool)
}
```

### Basic Validator Structure

Here's a basic structure for your validator:

```go
package yourvalidator

import (
    "bufio"
    "os"
    "regexp"
    "strings"

    "ferret-scan/internal/detector"
)

type YourValidator struct {
    pattern string
    positiveKeywords []string
    negativeKeywords []string
}

func NewValidator() *YourValidator {
    return &YourValidator{
        pattern: `your-regex-pattern-here`,
        positiveKeywords: []string{"keyword1", "keyword2", "keyword3"},
        negativeKeywords: []string{"keyword4", "keyword5", "keyword6"},
    }
}

// Validate implements the detector.Validator interface
func (v *YourValidator) Validate(filePath string) ([]detector.Match, error) {
    // Implementation
}

// CalculateConfidence implements the detector.Validator interface
func (v *YourValidator) CalculateConfidence(match string) (float64, map[string]bool) {
    // Implementation
}
```

### The Validate Method

The `Validate` method scans a file for potential matches and returns a list of matches with confidence scores:

```go
func (v *YourValidator) Validate(filePath string) ([]detector.Match, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var matches []detector.Match
    scanner := bufio.NewScanner(file)
    lineNum := 0
    re := regexp.MustCompile(v.pattern)

    // Create a context extractor
    contextExtractor := detector.NewContextExtractor()

    for scanner.Scan() {
        lineNum++
        line := scanner.Text()
        foundMatches := re.FindAllString(line, -1)

        for _, match := range foundMatches {
            // Calculate base confidence
            confidence, checks := v.CalculateConfidence(match)

            // Extract context
            contextInfo, err := contextExtractor.ExtractContext(filePath, lineNum, match)
            if err == nil {
                // Analyze context and adjust confidence
                contextImpact := v.AnalyzeContext(match, contextInfo)
                confidence += contextImpact

                // Ensure confidence stays within bounds
                if confidence > 100 {
                    confidence = 100
                } else if confidence < 0 {
                    confidence = 0
                }

                // Store keywords found in context
                contextInfo.PositiveKeywords = v.findKeywords(contextInfo, v.positiveKeywords)
                contextInfo.NegativeKeywords = v.findKeywords(contextInfo, v.negativeKeywords)
                contextInfo.ConfidenceImpact = contextImpact
            }

            // Skip matches with 0% confidence - they are false positives
            if confidence <= 0 {
                continue
            }

            // Only include matches with reasonable confidence
            if confidence > 40 {
                matches = append(matches, detector.Match{
                    Text:       match,
                    LineNumber: lineNum,
                    Type:       "YOUR_CHECK_TYPE",
                    Confidence: confidence,
                    Context:    contextInfo,
                    Metadata: map[string]any{
                        "validation_checks": checks,
                        "context_impact":    contextInfo.ConfidenceImpact,
                        // Add any other metadata specific to your validator
                    },
                })
            }
        }
    }

    return matches, scanner.Err()
}
```

### The CalculateConfidence Method

The `CalculateConfidence` method evaluates a potential match and returns a confidence score and a map of validation checks:

```go
func (v *YourValidator) CalculateConfidence(match string) (float64, map[string]bool) {
    checks := map[string]bool{
        "check1": true,
        "check2": true,
        "check3": false,
        // Add more checks as needed
    }

    confidence := 100.0

    // Perform validation checks and adjust confidence
    // Example:
    if !v.checkSomething(match) {
        confidence -= 20
        checks["check1"] = false
    }

    // Ensure confidence is within bounds
    if confidence < 0 {
        confidence = 0
    }

    return confidence, checks
}
```

## Adding Contextual Analysis

Contextual analysis improves detection accuracy by considering the text surrounding a match. Here's how to implement it:

```go
func (v *YourValidator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
    // Combine all context text for analysis
    fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
    fullContext = strings.ToLower(fullContext)

    var confidenceImpact float64 = 0

    // Check for positive keywords (increase confidence)
    for _, keyword := range v.positiveKeywords {
        if strings.Contains(fullContext, strings.ToLower(keyword)) {
            // Give more weight to keywords that are closer to the match
            if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
                confidenceImpact += 7 // +7% for keywords in the same line
            } else {
                confidenceImpact += 3 // +3% for keywords in surrounding context
            }
        }
    }

    // Check for negative keywords (decrease confidence)
    for _, keyword := range v.negativeKeywords {
        if strings.Contains(fullContext, strings.ToLower(keyword)) {
            // Give more weight to keywords that are closer to the match
            if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
                confidenceImpact -= 15 // -15% for negative keywords in the same line
            } else {
                confidenceImpact -= 7 // -7% for negative keywords in surrounding context
            }
        }
    }

    // Cap the impact to reasonable bounds
    if confidenceImpact > 25 {
        confidenceImpact = 25 // Maximum +25% boost
    } else if confidenceImpact < -50 {
        confidenceImpact = -50 // Maximum -50% reduction
    }

    return confidenceImpact
}

func (v *YourValidator) findKeywords(context detector.ContextInfo, keywords []string) []string {
    fullContext := context.BeforeText + " " + context.FullLine + " " + context.AfterText
    fullContext = strings.ToLower(fullContext)

    var found []string
    for _, keyword := range keywords {
        if strings.Contains(fullContext, strings.ToLower(keyword)) {
            found = append(found, keyword)
        }
    }

    return found
}
```

## Creating Documentation

### Help Documentation

The help.go file provides runtime documentation for your validator that can be accessed through the CLI. It should implement the `help.HelpProvider` interface:

```go
package yourvalidator

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about this check
func (v *YourValidator) GetCheckInfo() help.CheckInfo {
    return help.CheckInfo{
        Name: "YOUR_CHECK_TYPE",
        ShortDescription: "Short one-line description of what this check detects",
        DetailedDescription: `Detailed multi-line description of what this check does.
Explain what kind of sensitive data it detects, how it works, and any other
relevant information that would help users understand the check.`,

        Patterns: []string{
            "Pattern description 1 (e.g., 9 digits with optional dashes)",
            "Pattern description 2 (e.g., alphanumeric string with specific prefix)",
            // Add more pattern descriptions as needed
        },

        SupportedFormats: []string{
            "Format 1 description",
            "Format 2 description",
            // Add more format descriptions as needed
        },

        ConfidenceFactors: []help.ConfidenceFactor{
            {Name: "Factor 1", Description: "Description of factor 1", Weight: 20},
            {Name: "Factor 2", Description: "Description of factor 2", Weight: 15},
            // Add more factors as needed (weights should add up to 100)
        },

        // Keywords that affect contextual analysis
        PositiveKeywords: v.positiveKeywords,
        NegativeKeywords: v.negativeKeywords,

        // Usage examples
        Examples: []string{
            "ferret-scan --file example1.txt --confidence high",
            "ferret-scan --file example2.txt --verbose | grep YOUR_CHECK_TYPE",
            // Add more examples as needed
        },
    }
}
```

### README Documentation

Each validator should have its own README.md file that provides detailed documentation for developers. This follows a modular documentation approach where each component has its own documentation that is linked from the main README.

Your validator's README.md should include:

```markdown
# Your Validator Name

Brief description of what your validator detects and its purpose.

## Supported Types/Formats

- Format 1 (e.g., 9-digit SSN with dashes)
- Format 2 (e.g., 9-digit SSN without separators)
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
// Example code showing how to use your validator
```
```

## Registering Your Validator

To register your validator with the Ferret Scan tool, you need to make three changes in `cmd/main.go`:

1. Import your validator package:
```go
import (
    // Other imports...
    "ferret-scan/internal/validators/yourvalidator"
)
```

2. Add your validator to the `allValidators` map:
```go
// Initialize all available validators
allValidators := map[string]detector.Validator{
    "CREDIT_CARD":    creditcard.NewValidator(),
    "PASSPORT":       passport.NewValidator(),
    "METADATA":       metadata.NewValidator(),
    "YOUR_CHECK_TYPE": yourvalidator.NewValidator(), // Add your validator here
    // Add more validators here
}
```

3. Add your validator to the `parseChecksToRun` function:
```go
func parseChecksToRun(checks string) map[string]bool {
    result := map[string]bool{
        "CREDIT_CARD":    false,
        "PASSPORT":       false,
        "METADATA":       false,
        "YOUR_CHECK_TYPE": false, // Add your validator here
    }
    // Rest of the function...
}
```

These changes ensure that:
- Your validator is available for use
- It appears in the `--help checks` list
- It can be selected with the `--checks` command line option
- It's included when the user specifies `--checks all`

## AI-Assisted Validator Creation

This documentation is designed to be used as a prompt for AI systems to help create new validators for the Ferret Scan project. When working with an AI assistant to create a new validator:

1. **Provide the specific type of sensitive data** you want to detect (e.g., SSN, API keys, database connection strings)

2. **Share relevant patterns and formats** for the data type, including:
   - Regular expressions that match the data
   - Format variations and edge cases
   - Common false positives to avoid

3. **Specify contextual keywords** that might indicate the presence of this data type:
   - Positive keywords that suggest this is the target data type
   - Negative keywords that suggest this is not the target data type

4. **Request validation logic** appropriate for the data type:
   - Format-specific validation rules
   - Checksum or algorithm validation if applicable
   - Entropy or randomness checks if relevant

5. **Ask for comprehensive documentation**:
   - Clear description of what the validator detects in the README.md file
   - Examples of the data formats it recognizes
   - Explanation of the confidence scoring system
   - Implementation details for developers
   - Runtime help documentation through the help.go file

Example prompt for an AI assistant:
```
Using the Ferret Scan validator creation guide, please create a new validator for detecting [DATA_TYPE].
The validator should detect patterns like [EXAMPLE_PATTERNS] and should consider contextual keywords like [KEYWORDS].
Please provide the validator.go, help.go, and README.md files following the project's structure and interfaces.
Also, provide the line to add to the main README.md to link to this validator's documentation.
```

## Windows Compatibility Testing

When creating validators, ensure they work correctly on Windows systems:

### Path Handling
```go
// Use filepath.Join() for cross-platform paths
configPath := filepath.Join(os.Getenv("APPDATA"), "ferret-scan", "config.yaml")

// Handle Windows environment variables
userProfile := os.Getenv("USERPROFILE")  // Windows equivalent of HOME
appData := os.Getenv("APPDATA")          // Windows application data directory
```

### File Operations
```go
// Use os.PathSeparator for platform-specific separators
separator := string(os.PathSeparator)  // '\' on Windows, '/' on Unix

// Handle Windows UNC paths
if strings.HasPrefix(filePath, `\\`) {
    // Handle UNC path: \\server\share\file
}

// Handle Windows drive letters
if len(filePath) >= 2 && filePath[1] == ':' {
    // Handle drive letter: C:\path\file
}
```

### Testing on Windows
```go
// +build windows

package yourvalidator

import (
    "testing"
    "runtime"
)

func TestWindowsSpecificBehavior(t *testing.T) {
    if runtime.GOOS != "windows" {
        t.Skip("Skipping Windows-specific test")
    }
    
    // Test Windows-specific functionality
    testCases := []struct {
        name     string
        filePath string
        expected bool
    }{
        {"Windows drive path", `C:\Users\test\document.txt`, true},
        {"UNC path", `\\server\share\document.txt`, true},
        {"Long path", `\\?\C:\very\long\path\document.txt`, true},
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Test your validator with Windows paths
        })
    }
}
```

### Configuration Considerations
```yaml
# Windows-specific configuration example
validators:
  yourvalidator:
    # Use Windows environment variables
    config_dir: "%APPDATA%\\ferret-scan"
    temp_dir: "%TEMP%\\ferret-scan"
    
    # Windows-specific patterns
    patterns:
      - "C:\\\\.*\\.sensitive"  # Windows drive paths
      - "\\\\\\\\.*\\\\.*"      # UNC paths
```

## Best Practices

1. **Use specific patterns**: Make your regex patterns as specific as possible to reduce false positives.

2. **Implement thorough validation**: Add multiple validation checks to accurately assess the confidence level.

3. **Leverage contextual analysis**: Use surrounding text to improve detection accuracy.

4. **Handle edge cases**: Consider common false positives and test patterns.

5. **Provide comprehensive documentation**:
   - Create a detailed README.md in your validator's directory
   - Implement the help.HelpProvider interface for CLI help
   - Keep documentation close to the code it describes
   - Link your validator's README from the main README.md

6. **Follow the modular documentation approach**:
   - Each validator has its own README.md with detailed information
   - The main README.md provides high-level information and links to individual validator READMEs
   - Documentation is kept in sync with code changes

7. **Test extensively**: Test your validator with various inputs, including edge cases and false positives.

8. **Optimize performance**: Ensure your validator is efficient, especially when scanning large files.
##
Validator Implementation Checklist

Use this checklist to ensure you've completed all necessary steps when creating a new validator:

- [ ] Create a new directory under `internal/validators/` with your validator name
- [ ] Implement the `validator.go` file with the `detector.Validator` interface
- [ ] Implement the `help.go` file with the `help.Provider` interface
- [ ] Create a comprehensive `README.md` file in your validator's directory
- [ ] Register your validator in `cmd/main.go`:
  - [ ] Import your validator package
  - [ ] Add it to the `allValidators` map
  - [ ] Add it to the `parseChecksToRun` function
- [ ] Add a link to your validator's README in the main README.md
- [ ] Update `examples/ferret.yaml` to include a profile for your validator
- [ ] Add any specific patterns to configuration files if needed
- [ ] Test your validator with various inputs
- [ ] Ensure your validator appears in the `--help checks` list

Following this checklist will ensure your validator is fully integrated into the Ferret Scan tool and available for users.
