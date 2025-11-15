# Person Name Validator

## Overview

The Person Name validator detects human names in documents using advanced pattern matching combined with embedded name database lookups. It identifies various name formats while minimizing false positives through contextual analysis and validation checks.

## Detection Capabilities

### Supported Name Patterns

The validator recognizes multiple name formats commonly used in Western naming conventions:

- **Basic Names**: `John Smith`, `Mary Johnson`
- **Names with Titles**: `Dr. Jane Doe`, `Prof. Robert Wilson`, `Ms. Sarah Davis`
- **Names with Suffixes**: `Robert Johnson Jr.`, `William Smith Sr.`, `John Davis III`
- **Names with Middle Initials**: `John M. Smith`, `Mary K. Johnson`
- **Multiple Names**: `Mary Jane Watson`, `John Michael Smith`
- **Hyphenated Names**: `Sarah Smith-Jones`, `Mary Anne Wilson-Davis`
- **Names with Apostrophes**: `Patrick O'Connor`, `Mary D'Angelo`

### Cultural Support

Currently optimized for Western name patterns with support for:
- English naming conventions
- Common academic and professional titles
- Generational suffixes (Jr., Sr., III, IV)
- Irish and French surname patterns (apostrophes)
- Compound and hyphenated surnames

## Detection Methodology

### Pattern Matching Engine

The validator uses a sophisticated pattern matching system with multiple regex patterns:

1. **Primary Patterns**: Basic first-last name combinations
2. **Enhanced Patterns**: Names with titles, suffixes, and middle components
3. **Cultural Patterns**: Hyphenated names and apostrophe variations
4. **Contextual Patterns**: Names in specific document contexts

### Embedded Name Database

The validator includes compressed, embedded databases for improved accuracy:

- **First Names**: ~5,200 common first names
- **Last Names**: ~2,100 common surnames

**Database Features:**
- Compile-time embedding (no external dependencies)
- Gzip compression (73% size reduction)
- O(1) hash map lookups for performance
- Lazy loading with thread safety
- **Database-First Optimization**: Early exit for non-matches (98% performance improvement)

### Confidence Scoring System

The validator uses a multi-factor confidence scoring system with **database-first optimization**:

#### Base Confidence Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Pattern Match | 15% | Must match valid name pattern |
| Known First Name | 25% | First name found in database |
| Known Last Name | 20% | Last name found in database |
| Proper Capitalization | 15% | Names properly capitalized |
| Reasonable Length | 10% | Names between 4-60 characters |

#### Key Improvements (2025)

- **Database-First Processing**: Names are checked against databases before pattern matching for 98% performance improvement
- **Enhanced Context Detection**: Technical contexts (API, function, method) receive automatic confidence penalties
- **Comma-Separated Name Support**: New patterns for "Last, First" format detection
- **Zero-Confidence Bug Fix**: Eliminated confidence leakage from non-matching patterns

#### Validation Checks

| Check | Penalty | Description |
|-------|---------|-------------|
| Test Data Detection | -35% | Matches test/placeholder patterns |
| Business Name Detection | -25% | Contains business indicators |
| Poor Capitalization | -15% | Improper case formatting |
| Suspicious Patterns | -10% | Contains numbers or suspicious text |
| Repeated Characters | -20% | Suspicious character repetition |

#### Contextual Analysis

**Positive Keywords** (+5-15% each):
- `name`, `employee`, `customer`, `contact`, `person`, `patient`
- `client`, `user`, `member`, `staff`, `author`, `owner`
- `student`, `teacher`, `doctor`, `nurse`, `manager`
- `resident`, `participant`, `attendee`, `speaker`

**Negative Keywords** (-10-20% each):
- `company`, `organization`, `business`, `product`, `service`
- `brand`, `system`, `application`, `software`, `corporation`
- `platform`, `solution`, `technology`, `framework`
- `vendor`, `supplier`, `manufacturer`, `publisher`

#### Enhanced Context Analysis

**Form Field Patterns** (+15%):
- "first name", "last name", "full name", "employee name"

**Email Signature Patterns** (+12%):
- "from:", "to:", "cc:", "sent by", "regards", "sincerely"

**Directory Patterns** (+10%):
- "directory", "roster", "list of", "staff list"

**Technical Context Penalties** (-15%):
- "api", "function", "method", "class", "variable"

## Configuration Options

### Basic Usage

The Person Name validator requires no configuration and works out-of-the-box:

```bash
ferret-scan --file document.txt --checks PERSON_NAME
```

### Advanced Usage

```bash
# High confidence only
ferret-scan --file employee-list.csv --checks PERSON_NAME --confidence high

# Verbose output with detection details
ferret-scan --file contacts.txt --checks PERSON_NAME --verbose

# Combined with other validators
ferret-scan --file directory.pdf --checks PERSON_NAME,EMAIL,PHONE --format json

# Recursive directory scanning
ferret-scan --file documents/ --recursive --checks PERSON_NAME
```

### Web UI Integration

The validator is available in the web interface:
1. Select "PERSON_NAME" from the validator dropdown
2. Upload files or enter text for analysis
3. View results with confidence scores and validation details

## Performance Characteristics

### Memory Usage
- **Total Memory**: <5MB (including embedded databases)
- **Database Storage**: ~2MB after decompression
- **Runtime Overhead**: Minimal (hash map lookups)

### Initialization Performance
- **Database Loading**: ~10ms (gzip decompression)
- **Hash Map Building**: ~20ms (15K names)
- **Pattern Compilation**: ~5ms (regex patterns)
- **Total Startup Time**: ~35ms additional

### Runtime Performance
- **Name Database Lookup**: ~50ns per lookup (O(1) hash map)
- **Database-First Early Exit**: ~100ns for non-matches (98% performance improvement)
- **Pattern Matching**: ~1-10μs per match (only for database matches)
- **Technical Term Filtering**: ~100ns per check (O(1) hash map)
- **Total Per-Match Processing**: ~2μs (optimized with early exit)
- **Throughput**: ~500,000 validations per second (12x improvement)

## Implementation Details

### Architecture

```
internal/validators/personname/
├── validator.go          # Main validator implementation
├── help.go              # Help provider implementation
├── README.md            # This documentation
├── data.go              # Embedded database handling
├── patterns.go          # Pattern definitions and matching
├── technical_terms.go   # Technical term filtering (optimized)
└── data/                # Source data files (build-time only)
    ├── first_names.txt  # Common first names
    └── last_names.txt   # Common surnames
```

### Interface Implementation

The validator implements both required interfaces:

```go
// Core validation interface
type Validator interface {
    Validate(filePath string) ([]Match, error)
    ValidateContent(content string, originalPath string) ([]Match, error)
    CalculateConfidence(match string) (float64, map[string]bool)
    AnalyzeContext(match string, context ContextInfo) float64
}

// Enhanced validation interface
type EnhancedValidator interface {
    ValidateWithContext(content string, filePath string, contextInsights ContextInsights) ([]Match, error)
    SetLanguage(lang string) error
    GetSupportedLanguages() []string
}

// Help provider interface
type HelpProvider interface {
    GetCheckInfo() CheckInfo
}
```

### Cross-Validator Integration

The validator works with other validators to improve accuracy:

- **Email Validator**: Names near email addresses get confidence boost
- **Phone Validator**: Names near phone numbers increase likelihood
- **Metadata Validator**: Author/creator fields provide strong signals
- **Enhanced Manager**: Participates in confidence calibration

### Error Handling

The validator implements graceful degradation:

- **Database Load Failure**: Falls back to pattern-only detection
- **Memory Constraints**: Optimized for minimal memory usage
- **Performance Issues**: Lazy loading prevents startup delays
- **Invalid Input**: Robust input validation and sanitization

## Usage Examples

### Employee Directory Processing

```bash
# Process employee directory with high confidence threshold
ferret-scan --file employee-directory.csv --checks PERSON_NAME --confidence high --verbose
```

**Expected Output:**
```
PERSON_NAME: John Smith (Confidence: 95%)
  - Line 1: John Smith, Software Engineer, john.smith@company.com
  - Known first name: John (+25%)
  - Known last name: Smith (+20%)
  - Context: employee (+8%)

PERSON_NAME: Dr. Sarah Johnson (Confidence: 98%)
  - Line 2: Dr. Sarah Johnson, Chief Medical Officer, sarah.johnson@company.com
  - Known first name: Sarah (+25%)
  - Known last name: Johnson (+20%)
  - Title present: Dr. (+5%)
  - Context: employee (+8%)
```

### Contact Form Analysis

```bash
# Analyze contact forms with JSON output
ferret-scan --file contact-forms.txt --checks PERSON_NAME --format json --output results.json
```

### Medical Records Processing

```bash
# Process medical records with multiple validators
ferret-scan --file medical-records.pdf --checks PERSON_NAME,EMAIL,PHONE --enable-preprocessors
```

### False Positive Analysis

```bash
# Debug mode to understand detection reasoning
ferret-scan --file product-catalog.txt --checks PERSON_NAME --debug --verbose
```

## Troubleshooting

### Common Issues

**High False Positives in Product Catalogs:**
- The validator applies business context penalties
- Use `--confidence high` to filter low-confidence matches
- Check for proper negative keyword detection in debug mode

**Missing Names in International Documents:**
- Current version optimized for Western name patterns
- Consider preprocessing to normalize name formats
- Future versions will include expanded cultural support

**Performance Issues with Large Files:**
- Validator uses lazy loading for optimal performance
- Memory usage remains constant regardless of file size
- Consider using `--preprocess-only` for text extraction testing

### Debug Information

Enable debug mode to see detailed detection reasoning:

```bash
ferret-scan --file document.txt --checks PERSON_NAME --debug --verbose
```

This provides:
- Pattern matching details
- Database lookup results
- Confidence calculation breakdown
- Context analysis results
- Validation check outcomes

## Future Enhancements

### Planned Features

1. **Expanded Cultural Support**: Additional name patterns for non-Western cultures
2. **Language-Specific Databases**: Name databases for different languages/regions
3. **Machine Learning Integration**: ML-based confidence calibration
4. **Custom Database Support**: User-provided name databases
5. **Advanced Context Analysis**: Document structure awareness

### Contributing

To contribute to the Person Name validator:

1. Follow the established validator architecture patterns
2. Maintain backward compatibility with existing interfaces
3. Include comprehensive tests for new features
4. Update documentation for any changes
5. Ensure performance characteristics remain within bounds

For questions or contributions, contact the development team or use the project's issue tracking system.
