# Ferret Configuration Guide

[← Back to Documentation Index](README.md)

This document provides detailed information about configuring Ferret Scan using the YAML configuration file.

**IMPORTANT: Custom internal URL patterns and intellectual property patterns can ONLY be configured through the ferret.yaml configuration file. There are no command-line options to specify these patterns.**

## Enhanced Validator Features (2025)

All validators now include advanced false positive prevention and enhanced accuracy features:

### Universal Enhancements
- **Zero Confidence Filtering**: Automatically excludes matches with 0% confidence scores
- **Context-Aware Analysis**: Improved keyword analysis and contextual validation
- **Test Data Detection**: Enhanced identification and filtering of placeholder/test patterns
- **Enhanced Validation**: Mathematical and structural validation for applicable data types

### Validator-Specific Enhancements
- **IP Address Validator**: RFC-compliant sensitivity filtering (excludes private, reserved, documentation ranges)
- **Credit Card Validator**: Mathematical validation with Luhn algorithm and test pattern filtering
- **Email Validator**: Advanced domain validation with context analysis
- **Phone Validator**: International format support with cross-validator false positive prevention
- **SSN Validator**: Domain-aware validation with HR/Tax/Healthcare context understanding
- **Passport Validator**: Multi-country format support with travel context analysis
- **Secrets Validator**: Enhanced entropy analysis with 40+ API key patterns
- **Intellectual Property Validator**: Patent, trademark, copyright detection with internal URL filtering
- **🆕 Enhanced Metadata Validator**: Preprocessor-aware validation with intelligent content routing and type-specific patterns

### Enhanced Metadata Processing Architecture (2025)

The metadata validator now includes a sophisticated dual-path routing system that separates metadata from document content:

- **Content Router**: Intelligently separates metadata from document body content
- **Preprocessor-Aware Validation**: Applies specific validation rules based on metadata source type
- **Enhanced Confidence Scoring**: Includes preprocessor-specific confidence boosts and context awareness
- **Dual Validation Paths**: Metadata goes exclusively to metadata validator, document content to other validators
- **Type-Specific Patterns**: Different validation patterns for image, document, audio, and video metadata

These enhancements require no configuration changes - they are automatically applied to improve accuracy and reduce false positives.

## Configuration File Structure

The configuration file has six main sections:
- `defaults`: Default settings applied when no profile is specified
- `preprocessors`: Configuration for text extraction <!-- GENAI_DISABLED: and GenAI services -->
- `validators`: Global validator-specific configurations
- `suppressions`: Suppression system configuration
<!-- GENAI_DISABLED: - `cost_control`: Cost management settings for GenAI services -->
<!-- GENAI_DISABLED: - `genai`: GenAI service configuration -->
- `profiles`: Named profiles for different scanning scenarios

## New Profile Features (2025)

Profiles now support all command-line options and include specialized configurations:

### Enhanced Profile Options
<!-- GENAI_DISABLED: - `enable_genai`: Enable GenAI services directly in profiles (no --enable-genai flag needed) -->
<!-- GENAI_DISABLED: - `estimate_only`: Show cost estimates without processing -->
<!-- GENAI_DISABLED: - `max_cost`: Set spending limits for GenAI services -->
- `show_match`: Display actual matched text in findings
- `quiet`: Suppress progress output for automation
- `show_suppressed`: Include suppressed findings in output
- `generate_suppressions`: Auto-generate suppression rules

### Output Format Support
Profiles now support all output formats:
- `text`: Human-readable text output (default)
- `json`: Structured JSON for APIs and programmatic processing
- `csv`: Spreadsheet-friendly format for analysis
- `yaml`: Detailed YAML output for debugging
- `junit`: JUnit XML for CI/CD test result integration

## Validator-Specific Configuration

Each validator can have its own configuration options that control its behavior. These can be set globally for all profiles or overridden for specific profiles.

### Intellectual Property Validator Configuration

The intellectual property validator can be configured with custom patterns for detecting internal URLs and intellectual property references.

#### Internal URL Pattern Configuration

**IMPORTANT**: Internal URL detection requires explicit configuration. The validator no longer includes hardcoded patterns and will only detect internal URLs that match your configured patterns.

**Behavior Change**: As of 2025, the intellectual property validator has been updated to remove all hardcoded internal URL patterns. This change improves flexibility and reduces false positives by requiring users to explicitly configure patterns relevant to their specific environment. If no internal URL patterns are configured, internal URL detection will be disabled, but other intellectual property detection (patents, trademarks, copyrights, trade secrets) will continue to function normally.

##### Purpose and Impact

Internal URL pattern configuration allows you to:
- Detect references to your organization's internal resources in documents
- Identify potential data leakage of internal system URLs
- Customize detection based on your specific infrastructure naming conventions
- Avoid false positives from generic URL patterns that don't apply to your environment

When internal URLs are detected, they are flagged as intellectual property references that may indicate sensitive internal information.

**Note**: If no internal URL patterns are configured, the validator will log an informational message indicating that internal URL detection is disabled. This ensures you're aware that this detection capability is not active and can configure patterns if needed.

##### Configuration Structure

You can specify custom patterns for detecting internal company URLs:

```yaml
validators:
  intellectual_property:
    internal_urls:
      - "http[s]?:\\/\\/.*\\.internal\\..*"
      - "http[s]?:\\/\\/.*\\.corp\\..*"
      - "http[s]?:\\/\\/.*-internal\\..*"
```

These patterns are regular expressions that will be used to detect internal URLs in scanned files. Each pattern should be a valid regex that matches your organization's internal URL structure.

##### Common Internal URL Patterns

###### AWS Cloud Infrastructure
```yaml
validators:
  intellectual_property:
    internal_urls:
      # AWS S3 buckets
      - "http[s]?:\\/\\/s3\\.amazonaws\\.com"
      - "http[s]?:\\/\\/.*\\.s3\\.amazonaws\\.com"
      - "http[s]?:\\/\\/s3-.*\\.amazonaws\\.com"

      # AWS CloudFront distributions
      - "http[s]?:\\/\\/.*\\.cloudfront\\.net"

      # AWS API Gateway
      - "http[s]?:\\/\\/.*\\.execute-api\\..*\\.amazonaws\\.com"

      # AWS Load Balancers
      - "http[s]?:\\/\\/.*\\.elb\\.amazonaws\\.com"
      - "http[s]?:\\/\\/.*\\.elb\\..*\\.amazonaws\\.com"
```

###### Azure Cloud Infrastructure
```yaml
validators:
  intellectual_property:
    internal_urls:
      # Azure Storage
      - "http[s]?:\\/\\/.*\\.blob\\.core\\.windows\\.net"
      - "http[s]?:\\/\\/.*\\.file\\.core\\.windows\\.net"

      # Azure Web Apps
      - "http[s]?:\\/\\/.*\\.azurewebsites\\.net"

      # Azure API Management
      - "http[s]?:\\/\\/.*\\.azure-api\\.net"

      # Azure CDN
      - "http[s]?:\\/\\/.*\\.azureedge\\.net"
```

###### Google Cloud Platform
```yaml
validators:
  intellectual_property:
    internal_urls:
      # Google Cloud Storage
      - "http[s]?:\\/\\/storage\\.googleapis\\.com"
      - "http[s]?:\\/\\/.*\\.storage\\.googleapis\\.com"

      # Google App Engine
      - "http[s]?:\\/\\/.*\\.appspot\\.com"

      # Google Cloud Run
      - "http[s]?:\\/\\/.*\\.run\\.app"

      # Google Cloud Functions
      - "http[s]?:\\/\\/.*\\.cloudfunctions\\.net"
```

###### Corporate Network Patterns
```yaml
validators:
  intellectual_property:
    internal_urls:
      # Common corporate domains
      - "http[s]?:\\/\\/.*\\.internal\\..*"
      - "http[s]?:\\/\\/.*\\.corp\\..*"
      - "http[s]?:\\/\\/.*\\.company\\..*"
      - "http[s]?:\\/\\/.*\\.local"

      # Internal naming conventions
      - "http[s]?:\\/\\/.*-internal\\..*"
      - "http[s]?:\\/\\/.*internal-.*"
      - "http[s]?:\\/\\/internal-.*"
      - "http[s]?:\\/\\/intranet\\..*"

      # Development and staging environments
      - "http[s]?:\\/\\/.*-dev\\..*"
      - "http[s]?:\\/\\/.*-staging\\..*"
      - "http[s]?:\\/\\/.*-test\\..*"
      - "http[s]?:\\/\\/dev-.*"
      - "http[s]?:\\/\\/staging-.*"
      - "http[s]?:\\/\\/test-.*"
```

###### Private IP Address Ranges
```yaml
validators:
  intellectual_property:
    internal_urls:
      # RFC 1918 private IP ranges
      - "http[s]?:\\/\\/10\\..*"
      - "http[s]?:\\/\\/172\\.(1[6-9]|2[0-9]|3[0-1])\\..*"
      - "http[s]?:\\/\\/192\\.168\\..*"

      # Localhost and loopback
      - "http[s]?:\\/\\/localhost"
      - "http[s]?:\\/\\/127\\..*"

      # Link-local addresses
      - "http[s]?:\\/\\/169\\.254\\..*"
```

##### Pattern Validation

The validator automatically validates all configured patterns at startup to ensure they are valid regular expressions:

- **Invalid patterns**: Logged as warnings with specific error details, but don't prevent startup
- **Valid patterns**: Compiled and used for internal URL detection
- **No valid patterns**: Internal URL detection is disabled with informational logging
- **Mixed valid/invalid**: Only valid patterns are used, invalid ones are skipped with warnings
- **Debug logging**: When enabled, shows the number of successfully loaded patterns

This validation approach ensures robust operation even with configuration errors, while providing clear feedback about any issues.

##### Configuration Examples by Organization Type

###### Technology Company
```yaml
validators:
  intellectual_property:
    internal_urls:
      - "http[s]?:\\/\\/.*\\.company\\.com"
      - "http[s]?:\\/\\/.*\\.company-internal\\.com"
      - "http[s]?:\\/\\/wiki\\.company\\.com"
      - "http[s]?:\\/\\/docs\\.company\\.com"
      - "http[s]?:\\/\\/api\\.company\\.com"
      - "http[s]?:\\/\\/.*-api\\.company\\.com"
```

###### Financial Services
```yaml
validators:
  intellectual_property:
    internal_urls:
      - "http[s]?:\\/\\/.*\\.bank\\.internal"
      - "http[s]?:\\/\\/.*\\.trading\\.internal"
      - "http[s]?:\\/\\/.*\\.risk\\.internal"
      - "http[s]?:\\/\\/compliance\\..*"
      - "http[s]?:\\/\\/audit\\..*"
```

###### Healthcare Organization
```yaml
validators:
  intellectual_property:
    internal_urls:
      - "http[s]?:\\/\\/.*\\.health\\.internal"
      - "http[s]?:\\/\\/.*\\.medical\\.internal"
      - "http[s]?:\\/\\/ehr\\..*"
      - "http[s]?:\\/\\/patient\\..*"
      - "http[s]?:\\/\\/.*-hipaa\\..*"
```

### Enhanced Metadata Validator Configuration

The metadata validator now supports preprocessor-aware validation with type-specific patterns and confidence scoring. The validator automatically applies different validation rules based on the source preprocessor type:

#### Supported Metadata Types

The enhanced metadata validator supports the following preprocessor types with specialized validation:

##### Image Metadata (EXIF, GPS, Device Info)
- **GPS Coordinates**: Latitude, longitude, altitude, GPS timestamps
- **Device Information**: Camera make/model, serial numbers, device IDs
- **Creator Information**: Artist, creator, copyright holder, software paths with usernames
- **Confidence Boosts**: GPS data (+60%), device info (+40%), creator info (+30%)

##### Document Metadata (PDF, Office Documents)
- **Author Information**: Author, creator, last modified by, manager, company
- **Content Metadata**: Comments, descriptions, keywords, subject
- **Rights Information**: Copyright, rights, copyright notice
- **Confidence Boosts**: Manager info (+40%), comments (+50%), author info (+30%)

##### Audio Metadata (MP3, FLAC, WAV, M4A)
- **Artist Information**: Artist, performer, composer, conductor, album artist
- **Contact Information**: Management, booking, social media handles
- **Location Information**: Recording venue, studio, recorded at
- **Rights Information**: Publisher, record label, copyright
- **Confidence Boosts**: Contact info (+50%), management (+40%), artist info (+30%)

##### Video Metadata (MP4, MOV, M4V)
- **Location Data**: GPS coordinates, XYZ coordinates, recording location
- **Device Information**: Camera make/model, recording device, device serial
- **Creator Information**: Recorded by, director, producer, cinematographer
- **Production Information**: Studio, production company
- **Confidence Boosts**: GPS data (+60%), location info (+50%), device info (+40%)

#### Content Routing and Dual-Path Validation

The enhanced architecture automatically routes content to appropriate validators:

```yaml
# No configuration required - automatic routing
# Metadata content → Enhanced Metadata Validator (preprocessor-aware)
# Document body content → All other validators (credit card, SSN, etc.)
```

#### Observability and Debugging

Enhanced debugging capabilities are available through the `--debug` flag:

- **Content Routing Decisions**: Shows how content is separated and routed
- **Preprocessor Type Detection**: Displays detected preprocessor types
- **Validation Rule Application**: Shows which rules are applied for each metadata type
- **Confidence Score Calculation**: Details confidence boosts and adjustments

#### Custom Intellectual Property Patterns

You can also customize the patterns used to detect different types of intellectual property:

```yaml
validators:
  intellectual_property:
    intellectual_property_patterns:
      patent: "\\b(US|EP|JP|CN|WO)[ -]?(\\d{1,3}[,.]?\\d{3}[,.]?\\d{3}|\\d{1,3}[,.]?\\d{3}[,.]?\\d{2}[A-Z]\\d?)\\b"
      trademark: "\\b(\\w+\\s*[™®]|\\w+\\s*\\(TM\\)|\\w+\\s*\\(R\\)|\\w+\\s+Trademark|\\w+\\s+Registered\\s+Trademark)\\b"
      copyright: "(©|\\(c\\)|\\(C\\)|Copyright|\\bCopyright\\b)\\s*\\d{4}[-,]?(\\d{4})?\\s+[A-Za-z0-9\\s\\.,]+"
      trade_secret: "\\b(Confidential|Trade\\s+Secret|Proprietary|Company\\s+Confidential|Internal\\s+Use\\s+Only|Restricted|Classified)\\b"
```

## Profile-Specific Validator Configuration

You can override the global validator configuration for specific profiles:

```yaml
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
          - "http[s]?:\\/\\/company-wiki\\.internal"
          - "http[s]?:\\/\\/docs\\.company\\.com"
          - "http[s]?:\\/\\/.*\\.company-internal\\.com"
```

This allows you to create profiles tailored to specific companies or projects with their own internal URL patterns and intellectual property definitions.

## Configuration Precedence

The configuration is applied in the following order:
1. Default built-in patterns
2. Global validator configuration from the `validators` section
3. Profile-specific validator configuration from the `profiles.<profile>.validators` section

This means that profile-specific configurations will override global configurations, which in turn override the default built-in patterns.

## Pre-Configured Profiles

Ferret Scan includes comprehensive pre-configured profiles for different use cases:

### Development and Testing Profiles

#### `quick` - Fast Security Check
- **Purpose**: Rapid scan focusing on critical data types
- **Features**: High confidence only, minimal processing, disabled preprocessors
- **Use Case**: Quick development checks, pre-commit hooks
- **Output**: Text format with minimal verbosity

#### `debug` - Troubleshooting and Analysis
- **Purpose**: Comprehensive debugging with detailed output
- **Features**: YAML output, show matches, show suppressed findings
- **Use Case**: Troubleshooting false positives, validator development
- **Output**: YAML format with full metadata

### CI/CD and Automation Profiles

#### `ci` - CI/CD Pipeline Integration
- **Purpose**: Automated testing with JUnit XML output
- **Features**: JUnit format, quiet mode, medium/high confidence
- **Use Case**: GitLab CI, Jenkins, automated testing pipelines
- **Output**: JUnit XML for test result integration

#### `silent` - Automated Systems
- **Purpose**: Minimal output for scripts and automation
- **Features**: JSON output, quiet mode, high confidence only
- **Use Case**: Automated scanning, monitoring systems
- **Output**: JSON format with minimal verbosity

### Security and Compliance Profiles

#### `security-audit` - Security Team Scanning
- **Purpose**: Security-focused analysis for audit purposes
- **Features**: Medium/high confidence, security-sensitive data types, no match display
- **Use Case**: Security audits, compliance scanning
- **Output**: JSON format without exposing sensitive data

#### `comprehensive` - Complete Analysis
- **Purpose**: Full-featured scanning with all capabilities
- **Features**: All confidence levels, show matches, suppression support
- **Use Case**: Thorough analysis, forensic investigation
- **Output**: YAML format with complete metadata

### Data Export and Analysis Profiles

#### `csv-export` - Spreadsheet Analysis
- **Purpose**: Export results for spreadsheet analysis
- **Features**: CSV format, quiet mode, all confidence levels
- **Use Case**: Data analysis, reporting, trend analysis
- **Output**: CSV format with headers

#### `json-api` - Programmatic Processing
- **Purpose**: Structured data for APIs and applications
- **Features**: JSON format, show matches, full metadata
- **Use Case**: API integration, custom processing
- **Output**: JSON format with complete data

<!-- GENAI_DISABLED: GenAI and Cost Management Profiles

#### `cost-estimate` - Cost Estimation
- **Purpose**: Show GenAI cost estimates without processing
- **Features**: Estimate-only mode, GenAI enabled
- **Use Case**: Budget planning, cost analysis
- **Output**: Cost breakdown without file processing

#### `cost-aware-genai` - Budget-Controlled GenAI
- **Purpose**: GenAI scanning with spending limits
- **Features**: $5 cost limit, JSON output, GenAI enabled
- **Use Case**: Controlled AI-powered analysis
- **Output**: JSON format with cost controls

#### `genai` - Full AI-Powered Analysis
- **Purpose**: Complete GenAI capabilities with higher budget
- **Features**: $10 cost limit, all GenAI services
- **Use Case**: Advanced document analysis, OCR processing
- **Output**: Text format with AI enhancements
-->

### Specialized Scanning Profiles

#### `credit-card` - Payment Card Focus
- **Purpose**: Dedicated credit card number detection
- **Features**: Credit card validator only, all confidence levels
- **Use Case**: PCI compliance, payment processing security
- **Output**: Text format with card-specific details

#### `passport` - Travel Document Focus
- **Purpose**: Passport number detection
- **Features**: Passport validator only, all confidence levels
- **Use Case**: Travel industry, identity verification
- **Output**: Text format with passport details

#### `intellectual-property` - IP Protection
- **Purpose**: Intellectual property detection
- **Features**: IP validator only, custom patterns
- **Use Case**: Corporate security, IP protection
- **Output**: Text format with IP-specific analysis

## Example Configuration

Here's a complete example configuration file with the new features:

```yaml
# Default settings applied when no profile is specified
defaults:
  format: text                # Output format: text, json, csv, yaml, junit, gitlab-sast
  confidence_levels: all      # Confidence levels to display: high, medium, low, or combinations
  checks: all                 # Specific checks to run: CREDIT_CARD, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS, METADATA, PASSPORT, PERSON_NAME, PHONE, SECRETS, SOCIAL_MEDIA, SSN<!-- GENAI_DISABLED: , COMPREHEND_PII -->, or combinations
  verbose: false              # Display detailed information for each finding
  debug: false                # Enable debug logging to show preprocessing and validation flow
  no_color: false             # Disable colored output
  recursive: false            # Recursively scan directories
  enable_preprocessors: true  # Enable text extraction from documents (PDF, Office files) (default: true)
  show_match: false           # Display the actual matched text in findings
  quiet: false                # Suppress progress output (useful for scripts and CI/CD)
  show_suppressed: false      # Include suppressed findings in output with suppression details
  generate_suppressions: false # Generate suppression rules for all findings
  <!-- GENAI_DISABLED: max_cost: 0                 # Maximum cost limit for GenAI services (0 = no limit) -->
  <!-- GENAI_DISABLED: estimate_only: false        # Show cost estimate and exit without processing -->

# Preprocessor configurations
preprocessors:
  # Text extraction from documents
  text_extraction:
    enabled: true             # Enable text extraction preprocessor
    types:                    # Types of text extraction to perform
      - pdf                   # Extract text from PDF documents
      - office                # Extract text from Office documents (DOCX, XLSX, PPTX, ODT, ODS, ODP)

  <!-- GENAI_DISABLED: Amazon Textract OCR (requires --enable-genai flag)
  # WARNING: Using Textract will send your files to AWS and incur costs
  textract:
    enabled: false            # Disabled by default, enabled with --enable-genai flag
    region: us-east-1         # AWS region for Textract service

  # Amazon Transcribe for audio file transcription (requires --enable-genai flag)
  # WARNING: Using Transcribe will send your files to AWS and incur costs
  transcribe:
    enabled: false            # Disabled by default, enabled with --enable-genai flag
    region: us-east-1         # AWS region for Transcribe service
    bucket: ""                # S3 bucket name for audio uploads (optional, creates temporary bucket if not specified)

  # Amazon Comprehend for PII detection (requires --enable-genai flag)
  # WARNING: Using Comprehend will send your text to AWS and incur costs
  comprehend:
    enabled: false            # Disabled by default, enabled with --enable-genai flag
    region: us-east-1         # AWS region for Comprehend service
  -->

# Validator-specific configurations
validators:
  # Intellectual property validator configuration
  intellectual_property:
    # Internal company URL patterns to detect
    internal_urls:
      - "http[s]?:\\/\\/s3\\.amazonaws\\.com"
      - "http[s]?:\\/\\/w\\.amazon"
      - "http[s]?:\\/\\/t\\.amazon"
      - "http[s]?:\\/\\/.*corp\\.amazon"
      - "http[s]?:\\/\\/.*\\.internal\\..*"
      - "http[s]?:\\/\\/.*\\.corp\\..*"
      - "http[s]?:\\/\\/.*-internal\\..*"
      - "http[s]?:\\/\\/.*internal-.*"

    # Custom intellectual property patterns
    intellectual_property_patterns:
      patent: "\\b(US|EP|JP|CN|WO)[ -]?(\\d{1,3}[,.]?\\d{3}[,.]?\\d{3}|\\d{1,3}[,.]?\\d{3}[,.]?\\d{2}[A-Z]\\d?)\\b"
      trademark: "\\b(\\w+\\s*[™®]|\\w+\\s*\\(TM\\)|\\w+\\s*\\(R\\)|\\w+\\s+Trademark|\\w+\\s+Registered\\s+Trademark)\\b"
      copyright: "(©|\\(c\\)|\\(C\\)|Copyright|\\bCopyright\\b)\\s*\\d{4}[-,]?(\\d{4})?\\s+[A-Za-z0-9\\s\\.,]+"
      trade_secret: "\\b(Confidential|Trade\\s+Secret|Proprietary|Company\\s+Confidential|Internal\\s+Use\\s+Only|Restricted|Classified)\\b"

# Suppression configuration
suppressions:
  file: ".ferret-scan-suppressions.yaml"  # Path to suppression configuration file
  generate_on_scan: false                 # Generate suppression rules for all findings during scan
  show_suppressed: false                  # Include suppressed findings in output

<!-- GENAI_DISABLED: Cost control settings for GenAI services
# NOTE: These settings only apply when --enable-genai flag is used
cost_control:
  max_cost: 0                            # Maximum cost limit for GenAI services (0 = no limit)
  estimate_only: false                   # Show cost estimate and exit without processing
  prompt_for_costs: true                 # Prompt user before incurring any GenAI costs

# GenAI service configuration
genai:
  services: "all"                        # Comma-separated list: textract, transcribe, comprehend, or 'all'
  region: "us-east-1"                    # Default AWS region for all GenAI services
-->

# Profiles for different scanning scenarios
profiles:
  # Quick scan profile - only high confidence matches, minimal output
  quick:
    format: text
    confidence_levels: high
    checks: CREDIT_CARD,SECRETS,SSN,EMAIL  # Focus on most critical data types
    verbose: false
    no_color: false
    recursive: false
    quiet: true
    show_match: false
    enable_preprocessors: false  # Skip document processing for speed
    description: "Quick scan focusing on critical data types with minimal processing"

  # CI/CD pipeline profile - JUnit XML output for integration with CI/CD systems
  ci:
    format: junit
    confidence_levels: high,medium
    checks: all
    verbose: true
    no_color: true
    recursive: true
    enable_preprocessors: true
    quiet: true
    show_suppressed: false
    generate_suppressions: false
    description: "CI/CD pipeline profile with JUnit XML output for test result integration"

  # Security audit profile - focused on security-sensitive data types
  security-audit:
    format: json
    confidence_levels: medium,high  # Exclude low confidence to reduce noise
    checks: SECRETS,CREDIT_CARD,SSN,PASSPORT,INTELLECTUAL_PROPERTY
    verbose: true
    no_color: true
    recursive: true
    enable_preprocessors: true
    show_match: false  # Don't show actual sensitive data in logs
    quiet: false
    description: "Security-focused scan for audit and compliance purposes"

  # Cost estimation profile - shows costs without processing
  cost-estimate:
    format: text
    confidence_levels: all
    checks: all
    verbose: false
    no_color: false
    recursive: true
    enable_preprocessors: true
    enable_genai: true
    estimate_only: true
    description: "Show GenAI cost estimates without processing files"

  # Comprehensive profile - all features enabled with suppression support
  comprehensive:
    format: yaml
    confidence_levels: all
    checks: all
    verbose: true
    no_color: false
    recursive: true
    enable_preprocessors: true
    show_match: true
    show_suppressed: true
    generate_suppressions: false
    description: "Comprehensive scan with all features and suppression support"
```
