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
```
Hash Components:
- Finding Type (e.g., "EMAIL", "CREDIT_CARD")
- Confidence Level (formatted to 2 decimal places)
- Full Line Content (trimmed)
- Filename (basename only for path independence)
- Line Number
- Context Hash (SHA-256 of before/after text, first 16 chars)
- Match Text Hash (SHA-256 of sensitive text, first 16 chars)

Final Hash = SHA-256(Type|Confidence|FullLine|Filename|LineNumber|ContextHash|MatchHash)
```

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
    hash: d7cba2ce6b8361659c919a5dffc28886cb490a9e8f63aa04437207b701297282
    reason: "False positive - test data"
    enabled: true
    created_by: "web-ui"
    created_at: 2025-08-19T12:00:00Z
    expires_at: 2025-08-26T12:00:00Z
    metadata:
      finding_type: "EMAIL"
      filename: "test-file.txt"
      line_number: "5"
      confidence: "85"
      context_hash: "a1b2c3d4e5f6g7h8"
      match_text_hash: "h8g7f6e5d4c3b2a1"
```

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
- **Sensitive Data Hashing**: Actual sensitive content never stored in suppression rules
- **Context Privacy**: Before/after text hashed for privacy
- **Secure Storage**: Suppression files stored with restricted permissions (0600)

### Access Control
- **File Permissions**: Configuration directory restricted to user access only
- **Rule Validation**: Suppression rules validated before application
- **Expiration Enforcement**: Expired rules automatically ignored

## Troubleshooting

### Common Issues

1. **Suppressions Not Working**
   - Verify original filename is preserved in web uploads
   - Check that suppression rules are enabled and not expired
   - Ensure hash generation uses consistent filename format

2. **Hash Mismatches**
   - Confirm filename normalization (basename only)
   - Verify confidence level formatting (2 decimal places)
   - Check for whitespace differences in full line content

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
