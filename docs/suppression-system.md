# Suppression System Architecture

[← Back to Documentation Index](README.md)

## Overview

The suppression system provides a robust mechanism for reducing false positives by allowing users to suppress specific findings based on cryptographic hashes. This system is designed to work seamlessly across both CLI and Web UI interfaces.

## Key Features

### Hash-Based Identification
- **Cryptographic Hashing**: Each finding is identified by a SHA-256 hash of its key attributes
- **Precise Matching**: Suppressions target exact findings, not broad patterns
- **Privacy Protection**: Sensitive data is hashed before storage in suppression rules

### Hash Generation Algorithm
New rules are written with formula **v5**:
```
Hash Components (v5):
- Finding Type (e.g., "EMAIL", "VISA")
- Full Line Content (trimmed; at most the first 8192 bytes)
- Filename (basename only for path independence)
- Line Number
- Context Hash: SHA-256 of the before-window with its leading whitespace removed followed by the
  after-window with its trailing whitespace removed, first 16 hex chars ("" when both are empty)
- Match Text Hash: SHA-256 of the matched text with its surrounding whitespace removed, first 16 hex chars

Final Hash = SHA-256(Type|FullLine|Filename|LineNumber|ContextHash|MatchHash)
```

The windows are the text just before and after the value on its line (50 bytes for most validators).
They stay in the identity because they tell two occurrences of one value on one line apart; only
their outer edges are trimmed, so whitespace inside a window or inside the value still counts.

A rule's hash is compared with every formula an earlier version wrote, so existing files keep working:

| formula | written by | what it digests differently |
|---|---|---|
| v5 | this version | (above) |
| v2 | v2.3.0 to v2.5.x | the windows and the value raw, edge whitespace and `\r` included |
| v1 | before v2.3.0 | v2 with the confidence (`%.2f`) as the second component (#247) |
| v2 / v1 without context | `secrets`, `PERSON_NAME` and `cloud_resources` rules written before v2.3.1, when those validators recorded no context | an empty line and empty windows |
| v2 / v1 with the other line ending | (never written) | the finding as it reads in an LF copy of a CRLF file, or the reverse |

What is and is not identity:

- **Line endings, indentation and trailing whitespace are not.** Converting a file between LF and CRLF,
  re-indenting it or adding a trailing space leaves a v5 rule matching. A v2 or v1 rule still matches
  across an LF/CRLF conversion, through the other-line-ending candidates, but stays sensitive to
  indentation and trailing whitespace until it is migrated. Measured on 39 of this repository's files
  (581 findings): rules a v2.5 binary generated on the LF copy suppressed 86 findings of the CRLF copy
  and 113 of a re-indented copy. Read by this version, the same rules suppress all 581 of the CRLF copy
  and 253 of the re-indented one; once migrated, or when written by this version, all 581 of each
  (#885).
- **The line number and the file's basename are.** A line inserted above a finding stops its rule
  matching at scan time; `--generate-suppressions` re-anchors the rule (see
  [Re-anchoring](#re-anchoring)). A renamed file stops it matching for good: a rule names a basename,
  and without one it could relocate anywhere.
- **Migration** happens only at an explicit write: `--generate-suppressions` rewrites a rule it matched
  through an older formula to v5 and changes nothing else in it (id, reason, `enabled`, dates and
  metadata stay). Scanning never rewrites a rule. A binary older than this one does not read v5, so a
  migrated rule whose finding has whitespace or a `\r` at a window edge stops matching there; for any
  other finding v5 and v2 are the same hash.

### Re-anchoring

Scan-time matching is exact, so a rule whose finding moved to another line matches nothing until the
file is regenerated. `--generate-suppressions` then moves it (#885): a rule that no finding of the run
identifies is re-anchored to the finding whose identity, recomputed at the line number the rule
recorded (`metadata.line_number`, and `metadata.confidence` for a v1 rule), equals the rule's `hash`.

- **Only the same finding moves.** Every other part of the identity comes from the finding: its type,
  its trimmed line, its file's basename, the text around it and the value. A rule can therefore move
  only to the same value on the same line text, in a file of the same name. A line that was edited as
  well as moved never relocates; its rule is reported as matching nothing.
- **Only one-to-one moves are made.** Findings are compared per basename and type, across every
  directory of the run. A rule that fits two findings (a repeated line, or same-named files with the
  finding at different lines) and a finding two rules fit are left alone and counted as ambiguous. Every
  finding of the run counts as a candidate, including those a rule already identifies, so a rule never
  moves onto one copy of a repeated line while the other copy keeps its own rule. Same-named files with
  the finding at the same line are one identity, as at scan time: the moved rule matches all of them.
- **Only `hash`, `metadata.line_number` and `last_seen_at` change**, the hash in the current formula.
  `id`, `reason`, `enabled`, `expires_at`, the dates and every other metadata key stay; disabled and
  expired rules move too, and keep their state. A rule the loader refused is neither moved nor counted.
  The save patches the file, so comments and unknown keys stay (see [Saving](#saving)).
- **Never at scan time, and never in the generating run.** A re-anchored rule takes effect when the file
  is next loaded. With `--stdin`, which generates before it reports, the generating run reports what
  `--file`'s does.
- **Bounded.** The search compares each finding of a basename and type with each distinct (line
  number, confidence) recorded by that group's unmatched rules, which is quadratic: a file of N findings
  with a line inserted at its top has N rules to move and N candidates for each. One regeneration makes
  at most **500,000 comparisons** (`suppressions.MaxReanchorComparisons`), about 0.6 s on a 2026 x86-64
  host: a group of 707 findings and 707 rules. Groups are searched cheapest first, and a group that does
  not fit in what is left is not searched at all, because a move is proven one-to-one only once every
  comparison of its group has been made. Its rules are left as they are and the run says so. A
  comparison costs the same however long the line is. For scale: re-anchoring this whole repository
  from rules generated at v2.4.0 took 38,260 comparisons (77 ms) and moved 1,443 rules.

Measured on the 39 files of `help.go`, `validator.go`, `metadata_validator.go` and `.gitlab-ci.yml`
present at both v2.4.0 and the v2.6.0 development head, with 473 rules generated at v2.4.0 and
enabled: a scan suppresses 238 of 612 findings and leaves 259 reported that only moved. One
regeneration re-anchors 253 rules, refuses 5 (three copies of one `.gitlab-ci.yml` line, and two lines
repeated in `metadata_validator.go`), and the rescan suppresses 492. 252 of the 253 moves are the
line mapping `git diff -U0` gives; the other is a block git shows as deleted and re-added, whose line
occurs once in each version. Before, the same regeneration grew the file from 473 to 846 rules and the
rescan still suppressed 238.

### What `--generate-suppressions` reports

It prints the counts of what it did, on both `--file` and `--stdin`, instead of a fixed line:

```
Updated suppression rules: added 0 (disabled by default), refreshed 0, re-anchored 5, migrated 0 to the current hash formula
Note: 5 rule(s) whose finding moved to another line now name that line (hash, metadata.line_number and last_seen_at rewritten; enabled, expiry and reason kept)
```

| count | means |
|---|---|
| added | new rules, for findings no rule identifies |
| refreshed | findings whose rule had `last_seen_at` updated (including the findings of migrated rules) |
| re-anchored | rules moved to the line their finding is now on |
| migrated | rules rewritten from an older hash formula to v5 |
| ambiguous | rules not moved because the move was not one-to-one |
| unmatched | rules for a file and type with findings in this run that fit none of them (an edited line, a removed finding, or no usable `line_number`) |
| not evaluated | rules the search did not reach because of its limit |

The last three are printed only when they are not zero, and those rules are unchanged. Rules for files
or types without findings in the run are not counted, because the run may not have scanned them. The
counts are also available to code as `SuppressionManager.LastGeneration()`.

### Rules that matched nothing

`IsSuppressed` records which rules matched a finding: a set per run, so the redaction filter and the
report asking about one finding count it once, and a rule matched behind another rule for the same
finding counts as matched. `SuppressionManager.UnmatchedRules(RunScope)` then lists the enabled,
applied, unexpired rules that matched nothing although the run could have matched them:

- the rule's `metadata.filename` is the basename of a file the run scanned completely
  (`RunScope.Files`; for `--stdin`, the `--stdin-name` label). A rule for a file the run did not read is
  not listed. A rule with no `metadata.filename` is counted as `Unattributed` instead;
- every check ran (`RunScope.AllChecks`), or the run reported a finding of the rule's type. In a
  narrowed run (`--checks`, a profile, a disabled type) the other rules are not listed and the report is
  marked `Partial`, so `--checks SSN` on an unchanged file lists none;
- a rule re-anchored by the same run counts as matched.

`suppressions.WriteUnmatchedRulesNote` prints the report as one stderr note naming the rules (the first
ten), for example `Note: 5 enabled suppression rule(s) for files scanned in this run matched no finding
(the finding moved, changed, or was removed): SUP-00000001, …. Run --generate-suppressions to re-anchor
the ones whose finding only moved.` It is a note: a rule that matched nothing hides nothing, so no exit
code changes. On the 39-file set above, 270 of the 473 enabled rules matched nothing, and the run said
only `Suppressed 238 findings`. The CLI does not print the note or a count yet; wiring both is tracked
in [#885](https://github.com/awslabs/ferret-scan/issues/885).

### Filename Consistency
- **Original Filename Preservation**: Web UI uploads maintain original filenames throughout processing
- **Path Independence**: Only basename is used in hash generation for portability
- **Suppression Matching**: Hash generation occurs after filename normalization

## Architecture Integration

### Processing Flow
```
Detection → Filename Normalization → Suppression Check → Confidence Filtering → Output
```

### Key Design Decisions

1. **Single-Point Filtering**: Confidence filtering occurs once in the scanner
2. **Pre-Suppression Normalization**: Filenames are normalized before suppression checks
3. **Consistent Thresholds**: Scanner and formatter use identical confidence definitions
4. **Hash Stability**: Hash algorithm ensures consistent identification across sessions

## Suppression Rule Structure

```yaml
version: "1.0"
rules:
  - id: SUP-00000001
    hash: d7cba2ce6b8361659c919a5dffc28886cb490a9e8f63aa04437207b701297282 # pragma: allowlist secret
    reason: "False positive - test data"
    enabled: true
    created_by: "web-ui"
    created_at: 2025-08-19T12:00:00Z
    expires_at: 2025-08-26T12:00:00Z
    metadata:
      finding_type: "EMAIL"
      filename: "test-file.txt"
      line_number: "5"
      confidence: "85.00"
      ticket: "SEC-1234"   # free-form: any key that is not a rule key
```

### Keys

The file has two top-level keys, `version` and `rules`. A rule has these eleven keys and no others:

| key | meaning |
|---|---|
| `id` | the rule's name, `SUP-` and eight digits; the web UI edits, disables and removes rules by it, so it must be unique |
| `hash` | the finding identity the rule matches: 64 lower-case hexadecimal digits, compared exactly |
| `reason` | why the finding is accepted |
| `enabled` | `true` to suppress; generated rules start `false` |
| `created_by`, `created_at` | who and when |
| `last_seen_at` | refreshed by `--generate-suppressions` each time the finding is seen again, and when it re-anchors the rule |
| `expires_at` | optional; after it the rule is skipped and the run warns that its findings are reported |
| `reviewed_by`, `reviewed_at` | optional review record |
| `metadata` | free-form string annotations, never interpreted |

### Rule Validation

A rule's keys constrain a suppressor, so the loader does not ignore one it does not know (#866). It
reads the file strictly and names every problem on stderr, with its line, whatever `--quiet` or
pre-commit mode say:

| in the file | effect |
|---|---|
| a rule key this version does not recognise (`expries_at`, `enabeld`, `pattern`, …) | the rule is **not applied** |
| a `metadata` key that reuses a rule key's name (`metadata.expires_at`) | the rule is **not applied** |
| `version` other than `"1.0"` (a missing version is accepted) | **no rule** is applied |
| a top-level key other than `version` and `rules` | named and ignored; with no `rules:` key the file loads 0 rules |
| a missing, non-hex or upper-case `hash` | named; the rule loads but can never match |
| an `id` two rules share | named; both rules apply |
| a YAML syntax error, YAML of the wrong shape (`rules: "…"`), or a file that cannot be read | **no rule** is applied, and the file is **never rewritten** (see [Saving](#saving)) |

A rule that is not applied stays in the file and in the web UI's list; its finding is reported until
the key is fixed. Refusing is deliberate: an ignored misspelling of `expires_at` used to turn a lapsed
rule into a permanent one, so a warning alone would have left the finding hidden. To keep a custom
note on a rule, put it under `metadata:` with a name that is not a rule key. The check is also
available as `suppressions.CheckSuppressionFile` for code that wants the verdict without loading.

### Saving

Every writer (`--generate-suppressions` and every web UI action) saves by patching the file it loaded:
a field is rewritten only when its value changed, new rules are appended, and a removed rule takes its
own lines with it. Comments, key order, unknown keys and untouched rules are kept byte for byte, so
regenerating a committed baseline changes only `last_seen_at` lines and appends the new rules. A file
that does not exist yet is written fresh.

A file that exists but does not parse (or cannot be read) is **never rewritten**. It loads as empty, so
its rules are not applied, and saving that empty state would replace the operator's rules. Every
writer refuses instead and the file stays byte-identical until it is fixed or moved aside:
`--generate-suppressions` reports `suppression file <path> could not be parsed (<yaml error>); fix it
or move it aside before regenerating; nothing was written`, and every web UI action that writes
answers 409 Conflict with the same text (#880). Moving the file aside counts as a missing file, so the
next save starts a new one.

## Web UI Integration

### Suppressed Findings Display
- **Structured Response**: Web UI returns both active and suppressed findings
- **Metadata Preservation**: Full finding details maintained in suppressed results
- **Count Accuracy**: Reliable suppressed finding counts from scanner library

### Response Format
```json
{
  "success": true,
  "results": [...],
  "suppressed": [
    {
      "finding": {
        "text": "user@example.com",
        "line_number": 5,
        "type": "EMAIL",
        "confidence": 85,
        "filename": "document.txt"
      },
      "suppressed_by": "SUP-00000001",
      "rule_reason": "False positive - test data",
      "expired": false
    }
  ],
  "suppressed_count": 1
}
```

## Performance Characteristics

### Efficiency Features

- **O(1) Lookup**: Hash-indexed lookup in `IsSuppressed`. The index is rebuilt from `config.Rules` on every load and on every save, so it stays consistent across mutations. Microbench (per-call cost on a non-matching match):

    | rules  | per-call cost |
    |-------:|--------------:|
    | 100    | 620 ns        |
    | 1,000  | 631 ns        |
    | 10,000 | 640 ns        |
    | 50,000 | 619 ns        |

  Previous linear scan grew with rule count (113 µs at 50,000 rules); the new index is constant-time. Replaced in v1.7.0.

- **Web-mode caching**: When running with `--web`, the `SuppressionManager` is held on the `WebServer` and reloaded only when the underlying file's mtime changes. This eliminates the per-request YAML parse cost. Measured 2.4× / 2.3× speedup on `/scan` and `/suppressions` against a 5,000-rule file.
- **Concurrent reads**: `RWMutex` around the hash index makes `IsSuppressed` safe for concurrent use. Mutating methods are still expected to be called serially (documented on the manager type).
- **Memory Efficient**: Hash-based storage minimizes memory footprint
- **Single Processing**: No duplicate filtering operations
- **Fast Hashing**: SHA-256 provides good performance for small inputs

### Scalability Considerations

- **Rule Limit**: With the hash index, lookup cost is constant up to and beyond 50,000 rules. Practical limits now come from YAML parse + write times, not lookup.
- **Hash Collisions**: Cryptographically unlikely with SHA-256
- **File Size**: Suppression file typically well under 1 MB for normal usage; file mtime is checked on every web request to invalidate the cache

## Security Features

### Data Protection
- **No verbatim values**: a rule stores digests and metadata, not the matched text itself.
- **But a digest of a low-entropy value is not private.** A rule's identity `hash` is derived from the
  value and from the line it sits on. Measured: the full 10^9 US SSN space falls to enumeration in 367
  seconds single-threaded, and a date of birth (10^4) is instant. Treat a suppression file as being as
  sensitive as a report, and treat committing one as a disclosure decision.
- **Secure Storage**: Suppression files stored with restricted permissions (0600)
- The identity hash cannot be salted, because the file must match the same finding on another machine
  and a salt would travel with it. The two informational digests rules used to carry in metadata
  (`context_hash`, `match_text_hash`) were read by nothing and have been removed (#673).

### Access Control
- **File Permissions**: Configuration directory restricted to user access only
- **Rule Validation**: a rule with a key the loader does not recognise, or a file of another version,
  is not applied and is named on stderr (see [Rule Validation](#rule-validation))
- **Expiration Enforcement**: an expired rule is skipped, and the run warns how many findings it left
  in the report

## Troubleshooting

### Common Issues

1. **Suppressions Not Working**
   - Verify original filename is preserved in web uploads
   - Check that suppression rules are enabled and not expired
   - Ensure hash generation uses consistent filename format

2. **Hash Mismatches**
   - Confirm filename normalization (basename only)
   - A line inserted or removed above the finding changes its line number, which is part of the identity;
     run `--generate-suppressions` to re-anchor the rule (see [Re-anchoring](#re-anchoring))
   - Line endings and whitespace at the line's edges are not, for rules written or migrated by this
     version (see [Hash Generation Algorithm](#hash-generation-algorithm))

3. **Performance Issues**
   - Clean up expired suppression rules periodically
   - Monitor suppression file size (should be <100KB)
   - Consider rule consolidation for large rule sets

## Future Enhancements

### Recently Shipped (v1.6.0)

- ✅ **Rule Indexing**: Hash-based indexing for O(1) lookup performance
- ✅ **Bulk Operations**: Efficient bulk enable/disable/delete and bulk expiration management
- ✅ **Web-mode caching**: `SuppressionManager` cached on `WebServer` with mtime-based reload
- ✅ **YAML pragma comments**: `# pragma: allowlist secret` auto-added to `hash:` lines so the file doesn't trip ferret-scan's own scanner

### Planned Improvements

- **Pattern Suppressions**: Support for regex-based suppression patterns
- **Rule Analytics**: Usage statistics and effectiveness metrics

### API Extensions
- **REST API**: Full CRUD operations for suppression rules
- **Import/Export**: Bulk rule management capabilities
- **Rule Sharing**: Team-based suppression rule sharing
- **Audit Logging**: Comprehensive suppression activity tracking

## Rule expiry

Generated rules **do not expire** by default; they last until removed or disabled. Expiry is opt-in via
`suppressions.expires_in` in config, a profile's `suppression_expires_in`, or `--suppression-expires`
(flag wins). An explicit `expires_at` written into a rule by hand always wins.

| what you write | means |
|---|---|
| `never` (or omitted, or `0`) | **no expiry** — the default |
| `30` | 30 days |
| `30d` / `4w` | 30 days / 4 weeks |
| `720h` / `90m` | any Go duration |
| `2026-12-31` | an absolute date — every rule from this run lapses on that day |


Rules previously expired one week after generation unconditionally, which made a committed baseline
inert a week later without any indication — `IsSuppressed` skips an expired rule silently. A run in
which an expired rule would otherwise have matched now warns, with the count and the oldest expiry
date (#696). The count is of findings: one finding is counted once however many times it is matched
(redaction and the report both ask), and not at all when another, live rule still suppresses it (#866).

