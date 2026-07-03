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
- `profiles`: Named configuration profiles for different scanning scenarios
<!-- GENAI_DISABLED: - `cost_control`: Cost management settings for GenAI services -->
<!-- GENAI_DISABLED: - `genai`: GenAI service configuration -->

## File Exclusion Patterns

Ferret Scan supports excluding files and directories from scanning using glob patterns. Exclusion patterns can be configured in three ways:

### Command Line Flag
```bash
# Single exclusion
ferret-scan --file . --recursive --exclude ".git"

# Multiple exclusions (comma-separated)
ferret-scan --file . --recursive --exclude ".git,*.log,node_modules"
```

### Configuration File (Defaults)
```yaml
defaults:
  exclude_patterns:
    - ".git"          # Exclude .git directory
    - "*.log"         # Exclude all .log files
    - "node_modules"  # Exclude node_modules directory
    - "target"        # Exclude target directory
    - "*.tmp"         # Exclude temporary files
```

### Configuration File (Profiles)
```yaml
profiles:
  development:
    exclude_patterns:
      - ".git"
      - "node_modules"
      - "target"
      - "build"
      - "dist"
      - "*.log"
      - "*.tmp"
```

### Pattern Matching Rules

Exclusion patterns use **glob pattern matching** (not regular expressions), which means:

- **Dots are literal characters** - use `.git` not `\.git`
- **Asterisks are wildcards** - `*.log` matches all files ending with ".log"
- **Question marks match single characters** - `test?.txt` matches "test1.txt", "testa.txt", etc.
- **Square brackets match character ranges** - `[abc]*.txt` matches files starting with "a", "b", or "c"

**Important**: Since these are glob patterns, not regex patterns, special characters like `.`, `(`, `)`, `+`, etc. are treated as literal characters and do not need escaping.

Exclusion patterns support the following matching strategies:

1. **Filename Matching**: Patterns are matched against the base filename
   - `README.md` matches files named exactly "README.md"
   - `*.log` matches all files ending with ".log"

2. **Directory Matching**: Patterns are matched against directory names in the path
   - `.git` matches any directory named ".git"
   - `node_modules` matches any directory named "node_modules"

3. **Path Substring Matching**: Patterns are matched as substrings within the full path
   - `test` matches any path containing "test"

4. **Directory Exclusion with Trailing Slash**: Patterns ending with "/" are treated as directory exclusions
   - `build/` matches directories named "build"

### Pattern Precedence

When multiple exclusion sources are configured, they are applied in this order:
1. Configuration file defaults
2. Profile-specific patterns (override defaults)
3. Command line flags (override both defaults and profiles)

### Pattern Examples

```yaml
exclude_patterns:
  # Literal matching (no escaping needed)
  - ".git"              # Matches .git directory exactly
  - ".DS_Store"         # Matches .DS_Store files exactly
  - "config.json"       # Matches config.json files exactly

  # Glob wildcards
  - "*.log"             # Matches all .log files
  - "test_*"            # Matches files starting with "test_"
  - "*.tmp"             # Matches all .tmp files

  # Directory patterns
  - "node_modules"      # Matches node_modules directories
  - "target"            # Matches target directories
  - "build/"            # Matches build directories (trailing slash optional)

  # Character ranges
  - "[Tt]est*"          # Matches files starting with "Test" or "test"
  - "file[0-9].txt"     # Matches file0.txt, file1.txt, etc.
```

**Remember**: These are glob patterns, not regular expressions. Characters like `.`, `(`, `)`, `+`, `{`, `}` are treated literally and don't need escaping.

### Common Exclusion Patterns

```yaml
# Version control
exclude_patterns:
  - ".git"
  - ".svn"
  - ".hg"

# Build artifacts
exclude_patterns:
  - "target"        # Maven/Gradle
  - "build"         # Gradle/CMake
  - "dist"          # Distribution folders
  - "out"           # IntelliJ IDEA
  - "bin"           # Binary folders

# Dependencies
exclude_patterns:
  - "node_modules"  # Node.js
  - "vendor"        # PHP Composer, Go modules
  - ".venv"         # Python virtual environments
  - "venv"          # Python virtual environments

# Temporary files
exclude_patterns:
  - "*.tmp"
  - "*.temp"
  - "*.log"
  - "*.cache"
  - ".DS_Store"     # macOS
  - "Thumbs.db"     # Windows

# IDE files
exclude_patterns:
  - ".vscode"
  - ".idea"
  - "*.swp"         # Vim
  - "*.swo"         # Vim
  - "*~"            # Backup files
```

### Honoring `.gitignore` (opt-in)

Ferret Scan can optionally honor `.gitignore` files, `.git/info/exclude`, and your global git excludes file (`~/.config/git/ignore`). This is **off by default** and must be explicitly enabled.

Enable via config:

```yaml
defaults:
  respect_gitignore: true
```

Or per profile:

```yaml
profiles:
  development:
    respect_gitignore: true
```

Or on the command line:

```bash
ferret-scan --file . --recursive --respect-gitignore
```

**Behavior:**

- Walks up from the scan target collecting every `.gitignore` on the way to the filesystem root.
- Also loads `.git/info/exclude` from the nearest repo root and the global git excludes file if present.
- Full `.gitignore` syntax is supported, including `**`, negation (`!keep.log`), and directory-only patterns.
- The `.git` directory is always skipped when this is enabled.
- `--exclude` patterns still apply on top of `.gitignore` rules.

> **⚠️ Security consideration:** `.gitignore` is written for source control, not for security scanning. It commonly hides exactly the files Ferret most wants to see — `.env`, `*.pem`, `credentials/`, local config files. Enabling `respect_gitignore` may silently suppress high-value findings. Use it when scanning is meant to mirror your commit set (e.g., pre-commit hooks on tracked files); leave it off for deep audits.

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
- `respect_gitignore`: Honor `.gitignore` files when scanning (opt-in; see [File Exclusion Patterns](#file-exclusion-patterns))
- `generate_suppressions`: Auto-generate suppression rules
- `fail_on_incomplete`: Exit with code `3` when a scan's validator coverage was cut short (timeout, cancellation, or a per-validator budget). Off by default; equivalent to the `--fail-on-incomplete` flag, which overrides this setting. See the README [Exit Codes](../README.md#exit-codes).

### CLI-Only Options (Not Configurable in YAML)

- `--explain`: Annotates each finding with a plain-language rationale, a verdict (likely real / test / uncertain), and a drafted suppression reason. Fully offline; no data leaves the host. Web mode always runs explain automatically.
- `--validator-budget`: Per-validator time budget as `NAME=DURATION` pairs. `DURATION` accepts any Go duration unit (`ms`, `s`, `m`, `h`, or combinations — e.g. `SSN=500ms,IP_ADDRESS=2m`); `all=<duration>` bounds every validator, specific names override it. A validator exceeding its budget is stopped and the scan is reported incomplete. Off by default. CI/hardening control against pathological inputs; not valid with `--web` or `--preprocess-only`.
- `--max-live-bytes`: Cap total file content held in memory across concurrently scanned files, e.g. `256MB` or `1GB` (units `B`, `KB`, `MB`, `GB`; bare number = bytes). Each file reserves its on-disk size against the budget before it is read/extracted and releases it after the scan, bounding peak memory so a directory of large files cannot multiply memory independently (useful on memory-constrained hosts such as Lambda). Files are only sequenced — findings are unchanged — and a file larger than the whole budget still runs alone. Off by default; not valid with `--web`. Library callers set the same cap via `core.ScanConfig.MaxLiveBytes`.

### Output Format Support

Profiles support all output formats:
- `text`: Human-readable text output (default)
- `json`: Structured JSON for APIs and programmatic processing
- `csv`: Spreadsheet-friendly format for analysis
- `yaml`: Detailed YAML output for debugging
- `junit`: JUnit XML for CI/CD test result integration
- `gitlab-sast`: GitLab Security Dashboard compatible JSON
- `sarif`: SARIF for GitHub Advanced Security, Azure DevOps, and other SARIF-compatible tools

## Validator-Specific Configuration

Each validator can have its own configuration options that control its behavior. These can be set globally for all profiles or overridden for specific profiles.

### Intellectual Property Validator Configuration

The intellectual property validator can be configured with custom patterns for detecting internal URLs and intellectual property references.

#### Disabling Specific IP Sub-Types

You can selectively disable specific IP detection categories using the `disabled_types` config option or the `--disable-ip-types` CLI flag. This is useful when your codebase legitimately contains certain IP markers (e.g., copyright notices on all source files delivered by AWS Professional Services) that would generate excessive findings without disabling the entire INTELLECTUAL_PROPERTY check.

Valid values: `copyright`, `patent`, `trademark`, `trade_secret`, `internal_url`

##### CLI Flag

```bash
# Disable copyright detection from the command line
ferret-scan --file . --recursive --disable-ip-types copyright

# Disable multiple types
ferret-scan --file . --recursive --disable-ip-types copyright,trade_secret

# Works with pre-commit mode and CI pipelines
ferret-scan --pre-commit-mode --disable-ip-types copyright --file myfile.go
```

##### Configuration File

```yaml
validators:
  intellectual_property:
    disabled_types:
      - copyright          # Skip copyright notice detection
      # - patent           # Skip patent number detection
      # - trademark        # Skip trademark symbol detection
      # - trade_secret     # Skip trade secret/confidentiality marking detection
      # - internal_url     # Skip internal URL detection
```

This setting works globally (under `validators:`) and also within profile-specific overrides:

```yaml
profiles:
  proserve-delivery:
    checks: all
    recursive: true
    description: "Scan for ProServe code delivery (skip copyright notices)"
    validators:
      intellectual_property:
        disabled_types:
          - copyright
```

When a type is disabled, the validator will skip all pattern matching for that category. Debug logging (`--debug`) will show which types have been disabled. The `--disable-ip-types` CLI flag takes precedence over the config file setting.

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

##### Regex Values in YAML — Escaping Rules

YAML's escape behavior depends on quoting style, and this trips up everyone who writes a regex with `\b`, `\s`, `\d`, etc. Pick one of the safe forms below; any of them produces an identical Go regex.

| Form | Example | Notes |
|------|---------|-------|
| Unquoted | `trade_secret: \b(Trade\s+Secret)\b` | YAML treats backslashes literally. Simplest. |
| Single-quoted | `trade_secret: '\b(Trade\s+Secret)\b'` | Single quotes preserve content as-is. |
| Double-quoted with `\\` | `trade_secret: "\\b(Trade\\s+Secret)\\b"` | Double quotes process escapes; you must double every backslash. |

**Avoid** double-quoted scalars with single backslashes (`"\b(...)\b"`). YAML processes `\b` as a backspace byte (0x08) and `\s` raises `found unknown escape character`. ferret-scan now reports the parse error and exits, but if you've ever seen "my override doesn't seem to apply" silently, this is almost always the cause.

If you want to skip a built-in IP sub-type entirely instead of debugging YAML escaping, use `disabled_types` — it's a clean escape hatch:

```yaml
validators:
  intellectual_property:
    disabled_types:
      - trade_secret    # built-in pattern is never compiled or evaluated
```

The same escaping rules apply to every regex-valued config key (secrets patterns, internal URLs, future custom patterns).

### Cloud Resources Validator Configuration

The cloud resources validator detects cloud provider resource identifiers (ARNs, Resource IDs, OCIDs, CRNs) that may expose sensitive information such as account numbers, subscription IDs, and internal resource naming conventions.

#### Supported Cloud Providers

The validator supports six cloud providers, all enabled by default:

| Provider | Identifier Format | Example |
|----------|------------------|---------|
| AWS | Amazon Resource Names (ARNs) | `arn:aws:iam::123456789012:role/MyRole` |
| Azure | Resource IDs with subscription UUIDs | `/subscriptions/{uuid}/resourceGroups/{name}/...` |
| GCP | Resource names with project IDs | `projects/my-project/zones/us-central1-a/instances/vm` |
| OCI | Oracle Cloud Identifiers (OCIDs) | `ocid1.instance.oc1.us-phoenix-1.abcdef` |
| IBM Cloud | Cloud Resource Names (CRNs) | `crn:v1:bluemix:public:cos:us-south:a/abc123:...` |
| Alibaba Cloud | Alibaba Resource Names | `acs:ecs:cn-hangzhou:123456789:instance/i-abc` |

#### Complete Configuration Example

```yaml
validators:
  cloud_resources:
    # Enable/disable specific providers (all enabled by default)
    enabled_providers:
      aws: true
      azure: true
      gcp: true
      oci: true
      ibm: true
      alibaba: true

    # Custom regex patterns for additional resource detection (Go regex syntax)
    custom_patterns:
      - "arn:aws:custom-service:[a-zA-Z0-9-]*:[0-9]{12}:[a-zA-Z0-9:/_-]+"
      - "/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Custom\\.[^/]+/[^/]+/[^/]+"
```

#### Provider Enable/Disable Options

Use the `enabled_providers` map to selectively enable or disable detection for specific cloud platforms. When a provider is disabled, its patterns are skipped entirely during scanning.

To scan only for AWS and Azure resources:

```yaml
validators:
  cloud_resources:
    enabled_providers:
      aws: true
      azure: true
      gcp: false
      oci: false
      ibm: false
      alibaba: false
```

**Behavior notes:**
- If `enabled_providers` is not specified, all providers are enabled by default
- If an invalid provider name is configured, it is logged as a warning and ignored
- Disabled providers contribute zero overhead to scan time

#### Custom Pattern Configuration

You can extend the built-in detection by adding custom regex patterns. This is useful for detecting organization-specific cloud services or new resource formats not yet covered by the built-in patterns.

```yaml
validators:
  cloud_resources:
    custom_patterns:
      # Detect a custom AWS service ARN format
      - "arn:aws:myservice:[a-zA-Z0-9-]*:[0-9]{12}:[a-zA-Z0-9:/_-]+"

      # Detect a custom Azure resource provider
      - "/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/MyCompany\\.[^/]+/[^/]+/[^/]+"

      # Detect internal GCP project naming convention
      - "projects/myorg-[a-zA-Z0-9-]+/(?:zones|regions)/[a-zA-Z0-9-]+/[a-zA-Z0-9]+/[a-zA-Z0-9-]+"
```

**Custom pattern rules:**
- Patterns must be valid Go regular expressions
- Invalid patterns are logged as errors and skipped (scanning continues with valid patterns)
- Custom patterns are applied in addition to built-in patterns (not as replacements)
- Custom pattern matches receive the same confidence scoring as built-in pattern matches

#### Confidence Scoring

Each detection receives a confidence score (0–100) based on multiple factors:

| Factor | Effect | Description |
|--------|--------|-------------|
| Base Match | +85 | Pattern matches a known cloud resource format |
| Valid Account ID | +10 | Contains a properly formatted account/subscription ID |
| Config Context | +5 | Content appears to be from a configuration file |
| Short Match | -10 | Match shorter than 20 chars (potential false positive) |
| Long Match | -15 | Match longer than 500 chars (potential false positive) |
| Test Context | -20 | Surrounding content contains test/example keywords |

Keywords that reduce confidence: `example`, `test`, `demo`, `sample`, `fake`, `mock`, `dummy`, `placeholder`, `template`, `tutorial`, `documentation`

Custom patterns follow the same confidence scoring rules as built-in patterns.

#### Profile-Specific Cloud Resources Configuration

You can override cloud resources configuration per profile:

```yaml
profiles:
  aws-only:
    checks: CLOUD_RESOURCES
    recursive: true
    description: "Scan for AWS resource identifiers only"
    validators:
      cloud_resources:
        enabled_providers:
          aws: true
          azure: false
          gcp: false
          oci: false
          ibm: false
          alibaba: false
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

Ferret Scan ships with five streamlined profiles covering the most common workflows. Use them with `--profile <name>`.

### Interactive Use

#### `cli` - Default Terminal Output

- **Purpose**: Standard interactive scanning for developers
- **Features**: Text output, high+medium confidence, all checks, recursive, respects `.gitignore`
- **Use Case**: Day-to-day scanning from a terminal
- **Output**: Human-readable text

### Web Interface

#### `web` - Web UI Mode

- **Purpose**: Powers the `ferret-scan --web` interface
- **Features**: JSON output, all confidence levels, all checks, verbose, `show_match: true` (the web UI handles client-side redaction), respects `.gitignore`
- **Use Case**: Browser-based scanning and triage
- **Output**: JSON with full finding detail
- **Note**: Web mode always runs `--explain` automatically

### CI/CD and Automation

#### `ci` - CI/CD Pipeline Integration

- **Purpose**: Machine-readable output for pipelines
- **Features**: gitlab-sast format (change to `junit` or `sarif` as needed), high+medium confidence, all checks, quiet, no color, respects `.gitignore`
- **Use Case**: GitLab Security Dashboard, Jenkins, GitHub Advanced Security, Azure DevOps
- **Output**: gitlab-sast JSON (or junit/sarif depending on format override)

#### `precommit` - Git Pre-Commit Hook

- **Purpose**: Fast, focused scan of staged files before commit
- **Features**: Text output, high+medium confidence, focused checks (CREDIT_CARD, SECRETS, SSN, PASSPORT, EMAIL, PERSON_NAME), non-recursive (only staged files), quiet, no color, respects `.gitignore`
- **Use Case**: Git pre-commit hooks to prevent accidental PII commits
- **Output**: Text (exit code non-zero on findings)

### Data Protection

#### `redaction` - Scan and Redact

- **Purpose**: Detect and redact sensitive data, writing sanitized copies to an output directory
- **Features**: Text output, high+medium confidence, all checks, verbose, format-preserving redaction strategy enabled, respects `.gitignore`
- **Use Case**: Preparing documents for external sharing, data sanitization pipelines
- **Output**: Text summary of findings + redacted file copies in `./redacted/`

## Example Configuration

Here is a concise example configuration file showing the main sections and profiles. See [`examples/ferret.yaml`](../examples/ferret.yaml) for the full annotated version.

```yaml
# Default settings (applied when no --profile is specified)
defaults:
  format: text                    # Output format: text, json, csv, yaml, junit, gitlab-sast, sarif
  confidence_levels: high,medium  # high, medium, low, or "all"
  checks: all                     # CLOUD_RESOURCES, CREDIT_CARD, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS,
                                  # METADATA, PASSPORT, PERSON_NAME, PHONE, SECRETS, SOCIAL_MEDIA, SSN, VIN, or "all"
  verbose: false
  debug: false
  no_color: false
  recursive: true
  enable_preprocessors: true      # Text extraction from PDF/Office documents
  show_match: false               # Display matched text (redacted by default)
  quiet: false
  show_suppressed: false
  generate_suppressions: false
  fail_on_incomplete: false       # Exit code 3 if any file's coverage was cut short (timeout/budget)
  respect_gitignore: true         # Honor .gitignore, .git/info/exclude, global git excludes

  exclude_patterns:
    - .git
    - .svn
    - node_modules
    - vendor
    - dist
    - "*.log"
    - "*.tmp"
    - __pycache__
    - .DS_Store

# Preprocessor configurations
preprocessors:
  text_extraction:
    enabled: true
    types:
      - pdf
      - office

# Validator-specific configurations
validators:
  intellectual_property:
    internal_urls:
      - "http[s]?:\\/\\/s3\\.amazonaws\\.com"
      - "http[s]?:\\/\\/.*\\.s3\\.amazonaws\\.com"
      - "http[s]?:\\/\\/.*\\.s3-.*\\.amazonaws\\.com"
      - "http[s]?:\\/\\/.*\\.internal\\..*"
      - "http[s]?:\\/\\/.*\\.corp\\..*"
      - "http[s]?:\\/\\/.*-internal\\..*"
      - "http[s]?:\\/\\/.*internal-.*"

    intellectual_property_patterns:
      patent: "\\b(US|EP|JP|CN|WO)[ -]?(\\d{1,3}[,.]?\\d{3}[,.]?\\d{3}|\\d{1,3}[,.]?\\d{3}[,.]?\\d{2}[A-Z]\\d?)\\b"
      trademark: "\\b(\\w+\\s*[™®]|\\w+\\s*\\(TM\\)|\\w+\\s*\\(R\\)|\\w+\\s+Trademark|\\w+\\s+Registered\\s+Trademark)\\b"
      copyright: "(©|\\(c\\)|\\(C\\)|Copyright|\\bCopyright\\b)\\s*\\d{4}[-,]?(\\d{4})?\\s+[A-Za-z0-9\\s\\.,]+"
      trade_secret: "\\b(Trade\\s+Secret|Company\\s+Confidential|Internal\\s+Use\\s+Only|CONFIDENTIAL\\s*[-–—:]\\s*(DO\\s+NOT|NOT\\s+FOR)|RESTRICTED\\s*[-–—:]\\s*(DO\\s+NOT|NOT\\s+FOR)|PROPRIETARY\\s+AND\\s+CONFIDENTIAL)\\b"

# Suppression configuration
suppressions:
  file: .ferret-scan-suppressions.yaml
  generate_on_scan: false
  show_suppressed: false

# Redaction (activated with --enable-redaction or via a profile)
redaction:
  enabled: false
  output_dir: ./redacted
  strategy: format_preserving
  audit_log_file: ""
  memory_scrub: true
  audit_trail: true
  strategies:
    simple:
      replacement: "[REDACTED]"
    format_preserving:
      preserve_length: true
      preserve_format: true
    synthetic:
      secure: true

# Profiles — use with: ferret-scan --profile <name> --file <target>
profiles:
  cli:
    format: text
    confidence_levels: high,medium
    checks: all
    recursive: true
    respect_gitignore: true
    description: "Default CLI scan — human-readable text output"

  web:
    format: json
    confidence_levels: all
    checks: all
    verbose: true
    show_match: true
    no_color: true
    respect_gitignore: true
    description: "Web UI mode — JSON output; UI handles client-side redaction"

  ci:
    format: gitlab-sast
    confidence_levels: high,medium
    checks: all
    no_color: true
    recursive: true
    quiet: true
    show_match: false
    respect_gitignore: true
    description: "CI/CD pipeline — change format to junit or sarif as needed"

  precommit:
    format: text
    confidence_levels: high,medium
    checks: CREDIT_CARD,SECRETS,SSN,PASSPORT,EMAIL,PERSON_NAME
    no_color: true
    recursive: false
    quiet: true
    respect_gitignore: true
    description: "Pre-commit hook — fast scan of staged files"

  redaction:
    format: text
    confidence_levels: high,medium
    checks: all
    verbose: true
    recursive: true
    respect_gitignore: true
    redaction:
      enabled: true
      output_dir: ./redacted
      strategy: format_preserving
    description: "Scan and redact sensitive data with format-preserving replacement"
```

## Redaction Configuration

Redaction is enabled with `--enable-redaction` and configured under the `redaction` key.

```yaml
redaction:
  enabled: false                    # Overridden by --enable-redaction flag
  output_dir: "./redacted"          # Where redacted copies are written
  strategy: "format_preserving"     # simple | format_preserving | synthetic
  audit_log_file: ""                # Optional path for JSON compliance log
  memory_scrub: true                # Scrub sensitive data from memory after processing
  audit_trail: true                 # Write audit trail alongside redacted files

  strategies:
    simple:
      replacement: "[REDACTED]"     # Placeholder text for simple strategy

    format_preserving:
      preserve_length: true         # Keep original character count
      preserve_format: true         # Keep separators (dashes, dots, @, etc.)

    synthetic:
      secure: true                  # Use crypto/rand for generation
```

### Strategy Behaviour

| Strategy | What it produces | Best for |
|----------|-----------------|----------|
| `simple` | `[CREDIT-CARD-REDACTED]` | External sharing, maximum security |
| `format_preserving` | `4916****2832`, `j***@acme.com` | Downstream format validation |
| `synthetic` | `4111356762812018`, `Regan Dubois` | Test data generation, realistic output |

### Supported File Types

| Type | Redaction method |
|------|-----------------|
| `.txt` `.csv` `.json` `.yaml` `.md` `.log` | Direct string replacement |
| `.docx` `.xlsx` `.pptx` | XML element replacement inside ZIP |
| `.jpg` `.png` `.tiff` `.gif` `.bmp` `.webp` | EXIF metadata removal only |
| `.pdf` | ⚠️ Not yet implemented |

See the [Redaction Guide](user-guides/README-Redaction.md) for full details including per-validator behaviour and synthetic token formats.
