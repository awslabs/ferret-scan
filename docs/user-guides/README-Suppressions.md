# Ferret Scan Suppression System

[← Back to Documentation Index](../README.md)

The suppression system allows you to suppress specific findings to reduce false positives and focus on actual security issues.

## How It Works

The suppression system uses **cryptographic hashing** to uniquely identify findings while protecting sensitive data:

- **Finding Hash**: Each finding gets a unique SHA-256 hash (formula v5) based on:
  - Finding type (e.g., "SSN", "VISA")
  - The line content (surrounding whitespace removed; at most its first 8192 bytes)
  - File basename
  - Line number
  - A digest of the match text, its surrounding whitespace removed
  - A digest of the text just before and after the value on its line, with the whitespace at the
    outer edges removed

  Confidence is not part of it (a rule written before v2.3.0 hashed it, and still matches while the
  finding's confidence is unchanged). Converting a file between LF and CRLF, re-indenting it or adding
  a trailing space leaves a v5 rule matching; a line inserted above the finding or a renamed file does
  not. A rule whose finding only moved to another line matches again after `--generate-suppressions`,
  which re-anchors it to the line the finding is now on: the same value on the same line text in a
  file of the same name, and only when exactly one finding fits (see
  [Re-anchoring](../suppression-system.md#re-anchoring)). A renamed file or an edited line needs a new
  rule. `--generate-suppressions` also rewrites a rule it matched through an older formula to v5. A binary
  that predates formula v5 (v2.5.5 and earlier; v5 shipped in v2.6.0) does not read it, so upgrade every
  binary that reads a shared suppression file before regenerating it. A rule file written by v2.5.5 needs
  no change to keep working on a newer binary: its v2 rules still match every finding whose type, text and
  line are unchanged, and `--generate-suppressions`
  migrates the ones it matched to v5 (reported as `migrated N to the current hash formula`). The formulas
  are listed in
  [the suppression system architecture](../suppression-system.md#hash-generation-algorithm).

- **A suppression file is as sensitive as a report.** It does not contain the value verbatim, but its
  rule `hash` is *derived* from the value and from the line the value sits on, and a digest is only as
  private as the space of things it could be a digest of. Measured: given a 16-hex SHA-256 prefix of a
  US SSN, the whole 10^9 space falls in **367 seconds** single-threaded, a date of birth (10^4) is
  instant, and a search bounded to a known area and group number recovered a planted SSN in **5 ms**.
  So for any low-entropy value — an SSN, a phone number, a date of birth — treat the digest as
  equivalent to the value.

  That is why the file is written `0600`, and why **committing it to a repository is a disclosure
  decision** rather than a neutral one. It is a defensible decision — sharing suppressions is the whole
  point of the file — but make it deliberately.

  The identity `hash` cannot be salted: the file has to match the same finding on a teammate's machine,
  so any salt would have to travel in the file beside it. What *was* removable were two purely
  informational copies of the same digests, `context_hash` and `match_text_hash`, which every rule
  carried in its metadata and **nothing in the tool ever read**. Those are gone
  ([#673](https://github.com/awslabs/ferret-scan/issues/673)); existing rule files keep matching,
  because the identity hash is unchanged.

## When a rule stops matching

A scan says so when an enabled rule matched nothing. After a line is inserted above three suppressed
findings, the scan reports the three findings again (exit code unchanged) and prints one stderr line:

```
Note: 3 enabled suppression rule(s) for files scanned in this run matched no finding (the finding moved, changed, or was removed): SUP-00000001, SUP-00000002, SUP-00000003. Run --generate-suppressions to re-anchor the ones whose finding only moved.
```

The json and yaml reports carry the same count as `stats.suppression_rules_unmatched` (the key is absent
when it is zero). `--file` and `--stdin` behave the same; on the `--stdin --enable-redaction` gateway,
whose stderr is the findings document, the count is in that document and the note is not printed.

- Only rules for files the run scanned in full are counted: a rule for a file the run did not read is not
  named, and on a run narrowed by `--checks`, a rule of a type the run reported no finding of is not checked
  (the note says so).
- A note, not a warning: a rule that matched nothing hides nothing, so the exit code does not change.
- `--generate-suppressions` re-anchors a rule whose finding only moved and names neither the rules it
  re-anchored nor the ones it migrated to formula v5:

  ```
  Updated suppression rules: added 0 (disabled by default), refreshed 0, re-anchored 3, migrated 0 to the current hash formula
  Note: 3 rule(s) whose finding moved to another line now name that line (hash, metadata.line_number and last_seen_at rewritten; enabled, expiry and reason kept)
  ```

  A rule whose line was edited, or whose finding was removed, stays as it is and keeps being named:
  delete it, or write a new one.

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
Edit or remove the expires_at field, use the web UI's bulk expiration control, or delete the
expired rules and regenerate them.
```

An expired rule is never removed from the file for you, and re-running `--generate-suppressions` over
the same file does not renew it: it updates `last_seen_at` and keeps `expires_at`. To bring a lapsed
rule back, edit or delete its `expires_at`, or select it in the web UI's suppression list and use
**Make Permanent** or **Renew 30 Days**. To retire it, delete the rule; a later
`--generate-suppressions` run writes a fresh, disabled rule for the finding, to be reviewed again.

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

  # Auto-generated disabled rule (can be enabled by changing enabled: true)
  - id: "SUP-1703123457"
    hash: "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678" # pragma: allowlist secret
    reason: "Auto-generated suppression rule (disabled by default)"
    enabled: false                    # Disabled - change to true to activate
    created_at: 2023-12-21T16:45:00Z
    last_seen_at: 2023-12-21T16:45:00Z # Same as created_at for new rules
    metadata:
      finding_type: "CREDIT_CARD"
      filename: "data-export.csv"
      line_number: "1205"
      confidence: "72.10"
```

### Rule keys

A rule may carry only `id`, `hash`, `reason`, `enabled`, `created_by`, `created_at`, `last_seen_at`,
`expires_at`, `reviewed_by`, `reviewed_at` and `metadata`. A rule with any other key (a misspelled
`expires_at`, say) is **not applied**, and the run names it with its line on stderr, because applying it
with the key ignored would turn a lapsed rule into a permanent one
([#866](https://github.com/awslabs/ferret-scan/issues/866)). The same goes for a `metadata` key spelled
like a rule key: put free-form annotations under `metadata:` with other names (`ticket: SEC-1234` is
fine). A file whose `version` is not `"1.0"` applies none of its rules. A `hash` that is not 64
lower-case hexadecimal digits, and an `id` two rules share, are named too: the first can never match,
the second makes an id-based edit ambiguous.

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

A release ships one binary, `ferret-scan` (`.goreleaser.yml` builds `./cmd` only); there is no
separate suppression-management command. The rules are a YAML file, so you manage them in an editor or
in the web UI:

- **List the rules**: open the suppression file, or start `ferret-scan --web` and open its suppression
  list, which shows each rule's state, including expired rules and rules the loader does not apply.
- **Remove a rule**: delete its entry from the file, or use **Remove** (one rule) or **Delete Selected**
  in the web UI.
- **Expired rules**: nothing deletes them. Each run names the findings an expired rule would have
  suppressed (see [An expired rule is now reported](#an-expired-rule-is-now-reported)), and the web UI's
  **Make Permanent** and **Renew 30 Days** controls change the expiry of the selected rules.

### Creating Suppressions

**Method 1: Auto-generate disabled rules**
```bash
# Generate suppression rules for all findings (disabled by default)
ferret-scan --file document.txt --generate-suppressions

# Run again: it refreshes last_seen_at, re-anchors rules whose finding moved to another line,
# and prints what it did ("Updated suppression rules: added 0 (disabled by default), refreshed 3, ...")
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
- **No verbatim values**: digests and metadata, not the matched text. Note that a digest of a
  low-entropy value is recoverable by enumeration — see the note at the top of this page — so treat a
  suppression file as being as sensitive as a report.
- **Context-Aware**: Includes file location and surrounding context
- **Tamper-Resistant**: Changes to the finding result in different hashes

### File Security
- **Restrictive Permissions**: Suppression files are created with 0600 permissions (owner-only)
- **No verbatim values**: the file holds digests and metadata, not the matched text; see the note at
  the top of this page for why a digest of a low-entropy value still deserves care
- **Timestamps, not an audit trail**: the tool writes `created_at` and keeps `last_seen_at` current, and
  the web UI fills in `created_by`. `reviewed_by` and `reviewed_at` are yours to fill in: the tool keeps
  them when it saves the file but never sets or reads them. For a record of who changed a rule and why,
  keep the file in version control.

### Expiration Support
- **Time-Limited**: Suppressions can have expiration dates
- **No automatic cleanup**: an expired rule stays in the file and is skipped; each run names the
  findings it would have suppressed, and removing or renewing it is your decision
- **Review fields**: `reviewed_by` and `reviewed_at` are free fields for your own process

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
Give generated rules a lifetime (`--suppression-expires 90d`, or `suppressions.expires_in` in config)
so that they come up for review, and act on the `EXPIRED` warning when it appears: renew the rules that
still hold, and delete the rest.

### 7. Track Finding Activity
```bash
# A run that generates rules updates last_seen_at; a scan that does not generate leaves the file alone
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
# Run scan with suppressions
ferret-scan --file . --recursive --format json --output scan-results.json

# Fail the job if any finding was not suppressed. The report is a JSON object, never an empty
# list, and its stats block counts the findings left after suppression.
if [ "$(jq '.stats.total_findings' scan-results.json)" != "0" ]; then
    echo "New sensitive data findings detected!"
    exit 1
fi
```

### Pre-commit Hook
```bash
#!/bin/bash
# Run scan on staged files. --pre-commit-mode makes findings set the exit code; without it a
# scan exits 0 whatever it finds.
git diff --cached --name-only | xargs ferret-scan --pre-commit-mode --file

# If findings detected, show suppression info
if [ $? -ne 0 ]; then
    echo "To suppress false positives, add rules to .ferret-scan-suppressions.yaml"
    echo "Review and edit the rules in that file, or in the web UI (ferret-scan --web)"
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
- `last_seen_at`: Timestamp when finding was last encountered (updated by a run that generates rules: `--generate-suppressions`, or `generate_suppressions` / `suppressions.generate_on_scan` in the config)

### Bulk Operations
```bash
# Find the rules for one finding type: the line of each rule's metadata.finding_type
grep -n "finding_type: SSN" .ferret-scan-suppressions.yaml

# Clean up all suppressions older than 1 year
# (Manual process - edit the YAML file)
```

The web UI's suppression list acts on many rules at once: **Enable Selected**, **Disable Selected**,
**Make Permanent**, **Renew 30 Days** and **Delete Selected**.

### Custom Suppression Files
```bash
# Development environment
ferret-scan --file . --suppression-file dev-suppressions.yaml

# Production environment
ferret-scan --file . --suppression-file prod-suppressions.yaml
```

This suppression system provides a secure, auditable way to manage false positives while maintaining the privacy of sensitive data.

## Suppression and redaction

**Suppressing a finding excludes it from redaction as well as from the report. Unsuppress it to have
the value rewritten.**

That is worth stating plainly because the two halves used to disagree. A suppressed finding was left
out of the report and its span was rewritten anyway, so the report said nothing was found while the
output file had been modified:

```
report:   results: []                      suppressed: 2
artifact: Employee SSN: [SSN-REDACTED]     <- rewritten despite being suppressed
```

Worse, the `--file` and `--stdin` paths disagreed: `--stdin` filtered before redacting and `--file` did
not, so the same input with the same rules produced different output depending on which channel you
used. Both now honour the suppression.

### What this costs, and why it is disclosed

A suppressed value **stays in the redacted copy in cleartext**. That is the point — you told the tool
the finding was not a problem — but it means a rule that is wrong, or that has outlived its reason, is
invisible in the report while the value is still in a file you might forward. So a redaction run says
so:

```
Note: 2 suppressed finding(s) were left in the redacted output — suppressing a finding excludes it
from redaction as well as from the report. Unsuppress it to have the value rewritten, or use
--show-suppressed to see which findings these are.
```

Use `--show-suppressed` to list them. If a suppressed value should be redacted after all, remove or
disable its rule: there is no way to suppress a finding from the report while still redacting it, and
deliberately so — a report and an output file that disagree about the same document is the condition
this change removed.

