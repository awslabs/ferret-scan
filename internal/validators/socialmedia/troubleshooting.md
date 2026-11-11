# Social Media Validator Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Social Media Validator.

## Common Issues and Solutions

### 1. No Social Media Matches Found

**Symptoms:**
- Validator runs but finds no matches
- Expected social media URLs/handles are not detected

**Possible Causes and Solutions:**

#### A. No Configuration Provided

The validator ships no built-in patterns, so without a `social_media` section it detects nothing, and
it says nothing about that at startup. `--debug` shows it at scan time:
```bash
ferret-scan --file document.txt --checks SOCIAL_MEDIA --debug 2>&1 | grep 'No social media patterns'
# → socialmedia: No social media patterns configured for /full/path/document.txt - returning empty results
```

**Solution:** Add social media configuration to your `ferret.yaml`:
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        - "(?i)@[a-zA-Z0-9_]{1,15}\\b"
      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
```

#### B. Empty Platform Patterns

`platform_patterns: {}` configures nothing, exactly as a missing section does: no startup message, and
the same `No social media patterns configured for ...` line under `--debug`.

**Solution:** Ensure at least one platform has patterns configured:
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:  # At least one platform must have patterns
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

#### C. Invalid Regex Patterns

Each pattern that does not compile prints a warning on stderr when a `--file` scan runs the validator
(`--stdin` does not print it yet, [#903](https://github.com/awslabs/ferret-scan/issues/903)), naming its
platform and index, never the pattern, and is skipped:
```
Warning: config value validators.social_media.platform_patterns.linkedin[0]: not a valid RE2 regular expression: invalid named capture ("(?<!" is a PCRE negative lookbehind; RE2, Go's regex engine, has no lookaround) — skipped; no platform has a valid pattern, so social media detection is off
```

**Solution:** Write the pattern in RE2 syntax, which has no lookaround and no backreferences:
```yaml
# ❌ Wrong - a lookbehind, which RE2 does not compile
- "(?<!@)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"

# ✅ Correct
- "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

### 2. Too Many False Positives

**Symptoms:**
- Validator detects test data or examples as real social media
- Low confidence matches are flagged

**Solutions:**

#### A. Add Negative Keywords
```yaml
validators:
  social_media:
    negative_keywords:
      - "example"
      - "test"
      - "placeholder"
      - "demo"
      - "sample"
      - "fake"
      - "mock"
      - "template"
```

#### B. Use Higher Confidence Threshold
```bash
# Only show high confidence matches
ferret-scan --file document.txt --checks SOCIAL_MEDIA --confidence high
```

#### C. Improve Pattern Specificity
```yaml
# ❌ Too broad - matches any URL with "linkedin"
- ".*linkedin.*"

# ✅ More specific - matches actual LinkedIn profile URLs
- "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

### 3. Missing Expected Matches

**Symptoms:**
- Known social media URLs are not detected
- Patterns seem correct but matches are missed

**Debugging Steps:**

#### A. Enable Debug Mode
```bash
export FERRET_DEBUG=1
ferret-scan --file document.txt --checks SOCIAL_MEDIA --debug --verbose
```

#### B. Check Pattern Matching
Create a test file with known social media URLs:
```bash
echo "Connect with me: https://linkedin.com/in/johndoe" > test.txt
ferret-scan --file test.txt --checks SOCIAL_MEDIA --verbose
```

#### C. Verify Pattern Syntax
Test your regex patterns using online regex testers or:
```bash
# Use grep to test pattern matching
echo "https://linkedin.com/in/johndoe" | grep -E "(?i)https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9_-]+"
```

### 4. Configuration Not Loading

**Symptoms:**
- Configuration changes don't take effect
- Default patterns are used instead of custom ones

**Solutions:**

#### A. Verify Configuration File Path
```bash
# Specify config file explicitly
ferret-scan --config ferret.yaml --file document.txt --checks SOCIAL_MEDIA

# Check if config file exists and is readable
ls -la ferret.yaml
```

#### B. Validate YAML Syntax
```bash
# Use a YAML validator
python -c "import yaml; yaml.safe_load(open('ferret.yaml'))"

# Or use online YAML validators
```

#### C. Check Configuration Structure
Ensure proper nesting:
```yaml
validators:          # Top level
  social_media:      # Validator name
    platform_patterns:  # Required section
      linkedin:      # Platform name
        - "pattern"  # Pattern array
```

### 5. Performance Issues

**Symptoms:**
- Slow scanning with social media validator
- High memory usage

**Solutions:**

#### A. Optimize Regex Patterns
```yaml
# ❌ Inefficient - causes backtracking
- ".*@.*linkedin.*"

# ✅ Efficient - specific pattern
- "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

#### B. Limit Platform Scope
```yaml
# Only include platforms you actually need
validators:
  social_media:
    platform_patterns:
      linkedin:  # Only LinkedIn if that's all you need
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

#### C. Use Confidence Filtering
```bash
# Process fewer results by filtering confidence
ferret-scan --file document.txt --checks SOCIAL_MEDIA --confidence high,medium
```

### 6. Platform-Specific Issues

#### LinkedIn Issues
```yaml
# Common LinkedIn patterns that work well
linkedin:
  - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"      # Personal profiles
  - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+" # Company pages
  - "(?i)https?://(?:www\\.)?linkedin\\.com/pub/[a-zA-Z0-9_/-]+"    # Public profiles
```

#### Twitter/X Issues
```yaml
# Handle both Twitter and X domains
twitter:
  - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"  # Profile URLs
  - "(?i)@[a-zA-Z0-9_]{1,15}\\b"                              # Handle references
```

#### GitHub Issues
```yaml
# Match both user profiles and repositories
github:
  - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"  # User/repo
  - "(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io"                                  # GitHub Pages
```

## Diagnostic Commands

### Basic Diagnostics
```bash
# Test with known social media content
echo "Follow me: https://linkedin.com/in/johndoe" | ferret-scan --file - --checks SOCIAL_MEDIA --verbose

# Check configuration loading
ferret-scan --config ferret.yaml --file /dev/null --checks SOCIAL_MEDIA --debug

# Test specific platform
ferret-scan --file test.txt --checks SOCIAL_MEDIA --verbose --show-match
```

### Advanced Diagnostics
```bash
# Enable all debug output
export FERRET_DEBUG=1
ferret-scan --file document.txt --checks SOCIAL_MEDIA --debug --verbose --show-match

# Test with comprehensive sample data
ferret-scan --file tests/testdata/samples/social-media-comprehensive.txt --checks SOCIAL_MEDIA --verbose

# Profile-specific testing
ferret-scan --config ferret.yaml --profile social-media --file document.txt --debug
```

### Configuration Testing
```bash
# Test minimal configuration
cat > test-config.yaml << EOF
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
EOF

ferret-scan --config test-config.yaml --file document.txt --checks SOCIAL_MEDIA --verbose
```

## Debug Output Interpretation

`--debug` prints no configure-time line for this validator: a configuration problem is a
`Warning: config value ...` line on stderr whether or not `--debug` is set (section C above), and
patterns that compile print nothing.

### Configuration Issues
```
   → socialmedia: No social media patterns configured for /full/path/document.txt - returning empty results
```

### Pattern Matching Debug

Every matched value is printed as `[HIDDEN]` with its length. For `Connect with me: https://linkedin.com/in/johndoe`:
```
   → socialmedia: Context analysis for linkedin match [HIDDEN] (len=31): impact=23.0
   → socialmedia:   Positive keywords found: [connect with me connect link]
   → socialmedia: Found linkedin match [HIDDEN] (len=31) (confidence: 100.0%, type: profile_url, username len=7)
```

## Getting Help

### Enable Verbose Logging
```bash
# Maximum verbosity for troubleshooting
export FERRET_DEBUG=1
ferret-scan --file document.txt --checks SOCIAL_MEDIA --debug --verbose --show-match
```

### Create Minimal Test Case
```bash
# Create a simple test file
echo "Test social media: https://linkedin.com/in/test-user" > minimal-test.txt

# Test with minimal configuration
cat > minimal-config.yaml << EOF
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
EOF

# Run test
ferret-scan --config minimal-config.yaml --file minimal-test.txt --checks SOCIAL_MEDIA --verbose
```

### Check Version and Build
```bash
# Verify you have the latest version with social media support
ferret-scan --version

# Check available validators
ferret-scan --help | grep -A 10 "checks"
```

## Common Error Messages

### "Unknown check type 'SOCIAL_MEDIA'"
**Cause:** Using an older version of Ferret Scan that doesn't include the social media validator.
**Solution:** Update to the latest version or rebuild from source.

### "No social media patterns configured for ... - returning empty results" (`--debug`)
**Cause:** No social media configuration in ferret.yaml, or an empty `platform_patterns`.
**Solution:** Add social media configuration as shown in the examples above.

### "Warning: config value validators.social_media.platform_patterns..."
**Cause:** A pattern that RE2 does not compile, or a value of the wrong type; the warning names it.
**Solution:** Fix the value it names; RE2 has no lookaround and no backreferences.

### "No matches found"
**Cause:** Patterns don't match the content or confidence is too low.
**Solution:** Check pattern accuracy and use `--confidence all` to see low-confidence matches.

## Best Practices for Troubleshooting

1. **Start Simple:** Begin with minimal configuration and add complexity gradually
2. **Use Debug Mode:** Always enable debug output when troubleshooting
3. **Test Patterns:** Verify regex patterns work with known test data
4. **Check Logs:** Look for warning and error messages in the output
5. **Validate Configuration:** Ensure YAML syntax is correct
6. **Use Verbose Output:** Enable verbose mode to see detailed match information
7. **Test Incrementally:** Add one platform at a time to isolate issues

## Performance Optimization

### Pattern Optimization
```yaml
# ✅ Good - specific and efficient
- "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]{3,30}"

# ❌ Bad - causes excessive backtracking
- ".*linkedin.*in.*"
```

### Configuration Optimization
```yaml
# Only include platforms you need
validators:
  social_media:
    platform_patterns:
      linkedin:  # Only LinkedIn for corporate environments
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

### Runtime Optimization
```bash
# Use confidence filtering to reduce processing
ferret-scan --file document.txt --checks SOCIAL_MEDIA --confidence high

# Process specific file types only
ferret-scan --file "*.pdf" --checks SOCIAL_MEDIA
```
