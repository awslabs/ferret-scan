# Ferret Scan Suppression System

[← Back to Documentation Index](../README.md)

The suppression system allows you to suppress specific findings to reduce false positives and focus on actual security issues.

## How It Works

The suppression system uses **cryptographic hashing** to uniquely identify findings while protecting sensitive data:

- **Finding Hash**: Each finding gets a unique SHA-256 hash based on:
  - Data type (e.g., "SSN", "CREDIT_CARD")
  - Detection confidence
  - File context (line content)
  - File basename
  - Line number
  - Hashed match text (for privacy)
  - Hashed surrounding context (for privacy)

- **Privacy Protection**: Sensitive data is hashed before storage, so suppression files don't contain actual sensitive information.

## Expiry

**A generated rule does not expire.** It stays in force until you remove or disable it.

That is a change. Rules used to expire **one week** after generation, always, and there was no way to
ask for anything else. Because `IsSuppressed` skips an expired rule silently, a committed baseline
would simply stop working seven days later with nothing to indicate it. Measured on this repository's
own `.ferret-scan-suppressions.yaml`: all 245 rules — 92 of them `enabled: true` and hand-reviewed —
carried `expires_at: 2026-05-28` and had been inert for about four months, while the file's own header
said contributors and CI shared it as a baseline
([#696](https://github.com/awslabs/ferret-scan/issues/696)).

### Asking for an expiry

If you want suppressions to lapse so they get revisited, say so:

```bash
ferret-scan --file . --recursive --generate-suppressions --suppression-expires 30d
```

| what you write | means |
|---|---|
| `never` (or omitted, or `0`) | **no expiry** — the default |
| `30` | 30 days |
| `30d` / `4w` | 30 days / 4 weeks |
| `720h` / `90m` | any Go duration |
| `2026-12-31` | an absolute date — every rule from this run lapses on that day |

A bare number means **days**, not seconds — nobody sets a suppression to lapse in 30 seconds, and
reading it that way would silently expire every rule in the run.

Note that Go's own duration syntax has no `d` or `w`, so `720h` was originally the only way to say 30
days. Both are accepted now.

Set it once in config instead of on every invocation:

```yaml
suppressions:
  expires_in: 30d          # or never (the default), 4w, 720h, 2026-12-31

profiles:
  audit:
    suppression_expires_in: "2026-12-31"   # everything lapses before the next audit
```

Precedence is **`suppressions.expires_in` → profile `suppression_expires_in` → `--suppression-expires`**,
with the flag winning. An explicit `expires_at` you write into a rule by hand always wins over all of
them. An unparseable value is refused with the list of accepted forms rather than silently ignored.

`d` is 24 hours and `w` is 168 hours — wall-clock, not calendar, so a `30d` expiry set the day before a
DST change lands an hour off. That does not matter to a review interval measured in weeks, and calendar
arithmetic would mean carrying a timezone in a file shared across machines.

### An expired rule is now reported

Skipping an expired rule is no longer silent. When a rule *would* have suppressed a finding but has
lapsed, the run says so:

```
WARNING: 3 finding(s) are reported because their suppression rule has EXPIRED, oldest expired
2026-05-28. An expired rule is skipped, so a baseline can stop working without any other sign.
Remove the expires_at field, regenerate the rules, or run `ferret-scan-suppress --action cleanup`
to drop them.
```

The count is taken at the moment of matching, not by reading the file, because that is the number you
can act on — three findings in your report that your own rules were meant to suppress, rather than
"the file contains 245 expired rules", which does not tell you whether any of them mattered.

## Configuration Files

Ferret Scan resolves the suppression file path in this order:

1. Path specified with `--suppression-file` flag
2. `$FERRET_CONFIG_DIR/suppressions.yaml` if `FERRET_CONFIG_DIR` env var is set
3. Platform default:
   - **Unix**: `$XDG_CONFIG_HOME/ferret-scan/suppressions.yaml` (or `~/.ferret-scan/suppressions.yaml` if `XDG_CONFIG_HOME` is unset)
   - **Windows**: `%APPDATA%\ferret-scan\suppressions.yaml` (falls back to `%USERPROFILE%\.ferret-scan\suppressions.yaml`)

The `--suppression-file` flag is honored in **both** CLI and `--web` mode — the web server uses whichever path you pass it, not always the platform default.

### Web server caching

When running with `--web`, the suppression manager is cached in memory and reloaded only when the file's mtime changes. This makes per-request latency on `/scan` and `/suppressions` independent of rule-set size — measured 2.4× / 2.3× speedup on a 5,000-rule file. CLI-side or manual edits to the YAML are picked up on the next request because mtime is checked on every read.

### Hash-indexed lookup

`IsSuppressed` uses a hash index keyed on the rule hash, so suppression matching is O(1) regardless of how many rules exist. With 50,000 rules a per-call lookup runs in ~620 ns versus ~113 µs under the previous linear scan (183× faster).

## Suppression File Format

> **Note on `# pragma: allowlist secret`**: every `hash:` line is automatically annotated with this pragma when the file is written. The hash field is a SHA-256 of the finding identity (not the secret itself), but it has enough entropy to trip secret scanners — including ferret-scan running over its own suppressions file. The pragma silences those false positives. Re-saves are idempotent: existing pragma comments are preserved, never duplicated.

```yaml
version: "1.0"
rules:
  - id: "SUP-1703123456"
    hash: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456" # pragma: allowlist secret
    reason: "Test data - not actual sensitive information"
    enabled: true                     # Required: true to suppress, false to disable
    created_by: "security-team"
    created_at: 2023-12-21T10:30:00Z
    last_seen_at: 2023-12-21T15:45:00Z # Updated when finding encountered again
    expires_at: 2024-12-21T10:30:00Z  # Optional expiration
    reviewed_by: "john.doe"           # Optional review info
    reviewed_at: 2023-12-22T09:00:00Z # Optional review date
    metadata:
      finding_type: "SSN"
      filename: "test_data.txt"
      line_number: "42"
      confidence: "85.50"
      context_hash: "a1b2c3d4e5f67890"      # Hashed surrounding context (privacy-safe)
      match_text_hash: "1234567890abcdef"    # Hashed match text (privacy-safe)

  # Auto-generated disabled rule (can be enabled by changing enabled: true)
  - id: "SUP-1703123457"
    hash: "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567" # pragma: allowlist secret
    reason: "Auto-generated suppression rule (disabled by default)"
    enabled: false                    # Disabled - change to true to activate
    created_at: 2023-12-21T16:45:00Z
    last_seen_at: 2023-12-21T16:45:00Z # Same as created_at for new rules
    metadata:
      finding_type: "CREDIT_CARD"
      filename: "data-export.csv"
      line_number: "1205"
      confidence: "72.10"
      context_hash: "b2c3d4e5f6789012"      # Hashed surrounding context (privacy-safe)
      match_text_hash: "abcdef1234567890"    # Hashed match text (privacy-safe)
```

## Usage Examples

### Basic Scanning with Suppressions
```bash
# Scan with automatic suppression file detection
ferret-scan --file document.txt

# Scan with specific suppression file
ferret-scan --file document.txt --suppression-file custom-suppressions.yaml

# Generate suppression rules for all findings (disabled by default)
ferret-scan --file document.txt --generate-suppressions
```

### Managing Suppressions

**List all suppression rules:**
```bash
ferret-suppress --action list
```

**Remove a specific suppression:**
```bash
ferret-suppress --action remove --id SUP-1703123456
```

**Clean up expired suppressions:**
```bash
ferret-suppress --action cleanup
```

### Creating Suppressions

**Method 1: Auto-generate disabled rules**
```bash
# Generate suppression rules for all findings (disabled by default)
ferret-scan --file document.txt --generate-suppressions

# Run again to update last_seen_at timestamps for existing findings
ferret-scan --file document.txt --generate-suppressions

# Edit the generated .ferret-scan-suppressions.yaml file
# Change 'enabled: false' to 'enabled: true' for rules you want to activate
```

**Method 2: Manual creation**
To create a suppression manually, you need the finding hash. Run a scan first:

```bash
# Run scan to see findings
ferret-scan --file document.txt --format json

# The output will include suppression info for each finding:
{
  "text": "[HIDDEN]",
  "type": "SSN",
  "suppression_info": {
    "hash": "abc123...",
    "suppressed": false
  }
}
```

Then manually add the suppression rule to your `.ferret-scan-suppressions.yaml` file.

## Security Features

### Hash-Based Identification
- **Unique**: Each finding gets a unique hash based on multiple factors
- **Privacy-Safe**: Sensitive data is hashed, not stored in plain text
- **Context-Aware**: Includes file location and surrounding context
- **Tamper-Resistant**: Changes to the finding result in different hashes

### File Security
- **Restrictive Permissions**: Suppression files are created with 0600 permissions (owner-only)
- **Secure Storage**: No sensitive data stored in suppression files
- **Audit Trail**: Tracks who created/reviewed each suppression and when

### Expiration Support
- **Time-Limited**: Suppressions can have expiration dates
- **Automatic Cleanup**: Expired rules are automatically removed
- **Review Tracking**: Optional review dates and reviewers

## Best Practices

### 1. Use Auto-generation for Bulk Suppressions
```bash
# Generate all findings as disabled suppressions
ferret-scan --file . --recursive --generate-suppressions

# Review and selectively enable suppressions
vim .ferret-scan-suppressions.yaml
```

### 2. Use Descriptive Reasons
```yaml
reason: "Test data in development environment - SSN format but not real"
```

### 3. Set Expiration Dates
```yaml
expires_at: 2024-06-01T00:00:00Z  # Review in 6 months
```

### 4. Track Ownership
```yaml
created_by: "security-team@company.com"
reviewed_by: "john.doe@company.com"
```

### 5. Enable/Disable Rules as Needed
```yaml
# Temporarily disable a rule without deleting it
enabled: false

# Re-enable when needed
enabled: true
```

### 6. Regular Reviews
```bash
# Clean up expired rules monthly
ferret-suppress --action cleanup
```

### 7. Track Finding Activity
```bash
# Regular scans update last_seen_at automatically
ferret-scan --file . --recursive --generate-suppressions

# Review which findings are still active vs stale
grep "last_seen_at" .ferret-scan-suppressions.yaml
```

### 8. Version Control
- Store suppression files in version control
- Review changes in pull requests
- Document suppression decisions

## Integration Examples

### CI/CD Pipeline
```bash
#!/bin/bash
# Clean up expired suppressions
ferret-suppress --action cleanup

# Run scan with suppressions
ferret-scan --file . --recursive --format json --output scan-results.json

# Check if any new findings (exit code 1 if findings found)
if [ -s scan-results.json ] && [ "$(cat scan-results.json)" != "[]" ]; then
    echo "New sensitive data findings detected!"
    exit 1
fi
```

### Pre-commit Hook
```bash
#!/bin/bash
# Run scan on staged files
git diff --cached --name-only | xargs ferret-scan --file

# If findings detected, show suppression info
if [ $? -ne 0 ]; then
    echo "To suppress false positives, add rules to .ferret-scan-suppressions.yaml"
    echo "Use 'ferret-suppress --action list' to manage suppressions"
fi
```

## Troubleshooting

### Suppression Not Working
1. **Check Hash**: Ensure the hash in your suppression file matches exactly
2. **File Location**: Verify the suppression file is in the expected location
3. **YAML Syntax**: Validate your YAML syntax
4. **Permissions**: Ensure the suppression file is readable

### Getting Finding Hashes
```bash
# Run scan with debug output to see hashes
ferret-scan --file document.txt --debug 2>&1 | grep "hash"
```

### Suppression File Not Found
```bash
# Check current directory
ls -la .ferret-scan-suppressions.yaml

# Check home directory
ls -la ~/.ferret-scan-suppressions.yaml

# Use explicit path
ferret-scan --file document.txt --suppression-file /path/to/suppressions.yaml
```

## Advanced Features

### Metadata Filtering
Suppression rules include metadata for easier management:
- `finding_type`: Type of sensitive data detected
- `filename`: Original filename (basename only)
- `line_number`: Line where finding occurred
- `confidence`: Detection confidence score
- `context_hash`: SHA-256 hash of surrounding context (privacy-safe)
- `match_text_hash`: SHA-256 hash of matched text (privacy-safe)
- `last_seen_at`: Timestamp when finding was last encountered (updated automatically)

### Bulk Operations
```bash
# List suppressions for specific file type
ferret-suppress --action list | grep "finding_type: SSN"

# Clean up all suppressions older than 1 year
# (Manual process - edit the YAML file)
```

### Custom Suppression Files
```bash
# Development environment
ferret-scan --file . --suppression-file dev-suppressions.yaml

# Production environment
ferret-scan --file . --suppression-file prod-suppressions.yaml
```

This suppression system provides a secure, auditable way to manage false positives while maintaining the privacy of sensitive data.
