# Redaction Guide

[← Back to Documentation Index](../README.md)

Ferret-scan can redact sensitive data in-place, writing clean copies of your files to an output directory while leaving originals untouched.

## Quick Start

```bash
# Redact with default strategy (format_preserving)
ferret-scan --enable-redaction --recursive /path/to/scan

# Choose a strategy
ferret-scan --enable-redaction --redaction-strategy synthetic /path/to/scan

# Save redacted files to a specific directory
ferret-scan --enable-redaction --redaction-output-dir ./clean-copy /path/to/scan

# Save a compliance audit log
ferret-scan --enable-redaction --redaction-audit-log ./audit.json /path/to/scan
```

## Strategies

Three strategies are available via `--redaction-strategy`:

### `simple` (highest security)

Replaces sensitive data with a bracketed placeholder. Nothing from the original value is preserved.

```
4916338506082832  →  [CREDIT-CARD-REDACTED]
372-84-1951       →  [SSN-REDACTED]
john@acme.com     →  [EMAIL-REDACTED]
AKIAIOSFODNN7...  →  [SECRET-REDACTED]
```

Use this when the document will be shared externally or when downstream systems don't need to parse the field.

### `format_preserving` (default)

Masks the sensitive portion while keeping separators, length, and structure intact. Useful when downstream systems validate format.

```
4916338506082832  →  4916********2832   (first 4 + last 4 visible)
372-84-1951       →  ***-**-1951        (last 4 digits visible)
john@acme.com     →  j***@acme.com      (first char + domain visible)
312-867-4201      →  312-***-4201       (area code + last 4 visible)
192.168.14.52     →  192.168.*.*        (first two octets visible)
```

### `synthetic`

Replaces sensitive data with realistic-looking but entirely fake values of the same type. Useful for test data generation or when documents need to remain parseable.

```
4916338506082832  →  4111356762812018   (valid Luhn, test prefix)
372-84-1951       →  000-61-4899        (invalid area code, same format)
john@acme.com     →  lgdeakpe@example.com
Michael Torres    →  Regan Dubois       (from real name database)
AKIAIOSFODNN7...  →  AKIAHXC4HGD897XZ  (same AKIA prefix)
ghp_16C7e42F...   →  ghp_ab3pMN5XQuRE  (same ghp_ prefix)
```

## Validator × Strategy Support

| Validator | `simple` | `format_preserving` | `synthetic` |
|-----------|:--------:|:-------------------:|:-----------:|
| CREDIT_CARD | ✅ | ✅ Luhn-valid mask | ✅ Valid Luhn number |
| SSN | ✅ | ✅ Last 4 visible | ✅ Invalid area code |
| EMAIL | ✅ | ✅ First char + domain | ✅ Random user@example.com |
| PHONE | ✅ | ✅ Area code + last 4 | ✅ Same format |
| PERSON_NAME | ✅ | ✅ Asterisk mask | ✅ Real name from database |
| IP_ADDRESS | ✅ | ✅ First two octets | ✅ Private range (192.168.x.x) |
| SECRETS | ✅ | ✅ Asterisk mask | ✅ Format-matching fake token |
| PASSPORT | ✅ | ✅ Asterisk mask | ✅ Same country format |
| SOCIAL_MEDIA | ✅ | ✅ Asterisk mask | ✅ Fake profile URL |
| INTELLECTUAL_PROPERTY | ✅ | ✅ Asterisk mask | ✅ Fake copyright/patent/trademark |

## Document Type Support

| File Type | Extensions | Redaction Method |
|-----------|-----------|-----------------|
| Plain text | `.txt` `.log` `.csv` `.json` `.yaml` `.md` `.xml` | Direct string replacement |
| Word | `.docx` | XML element replacement inside ZIP |
| Excel | `.xlsx` | Shared strings + cell values inside ZIP |
| PowerPoint | `.pptx` | Text elements inside ZIP |
| Images | `.jpg` `.png` `.tiff` `.gif` `.bmp` `.webp` | EXIF metadata removal only |
| PDF | `.pdf` | ⚠️ Not yet implemented — file is copied unchanged |

> **Note on images**: Only EXIF metadata (GPS, camera info, timestamps) is removed. Text embedded in image pixels is not redacted.
>
> **Note on PDFs**: PDF redaction is on the roadmap. Currently the tool detects findings in PDFs but the output file is an unchanged copy.

## Synthetic Strategy — Token Details

The `synthetic` strategy is type-aware for secrets:

| Secret Type | Synthetic Output |
|-------------|-----------------|
| AWS Access Key | `AKIA` + 16 random uppercase chars |
| GitHub Token | Preserves prefix (`ghp_`, `ghs_`, etc.) + 36 random chars |
| Google Cloud API Key | `AIza` + 35 random chars |
| Stripe Key | Preserves `sk_test_`/`pk_test_` prefix |
| GitLab Token | `glpat-` + 20 random chars |
| Slack Token | Preserves `xoxb-`/`xoxp-` prefix |
| JWT | Structurally valid fake (real header/payload, random signature) |
| Generic secret | Same-length random hex or alphanumeric |

Person names are drawn from the same database used for detection (~5,200 first names, ~2,100 last names), so synthetic names look realistic.

## Configuration File

Redaction can be configured in your `ferret.yaml`:

```yaml
redaction:
  enabled: false                    # Enable with --enable-redaction flag
  output_dir: "./redacted"          # Where to write redacted files
  strategy: "format_preserving"     # simple | format_preserving | synthetic
  audit_log_file: ""                # Path for JSON audit log (optional)
  memory_scrub: true                # Scrub sensitive data from memory after processing
  audit_trail: true                 # Generate audit trail

  strategies:
    simple:
      replacement: "[REDACTED]"     # Custom placeholder text

    format_preserving:
      preserve_length: true
      preserve_format: true

    synthetic:
      secure: true                  # Use cryptographically secure random generation
```

## Audit Log

When `--redaction-audit-log` is specified, a JSON file is written with details of every redaction performed — useful for compliance reporting.

```json
{
  "document_id": "sample.csv",
  "redactions": [
    {
      "data_type": "CREDIT_CARD",
      "strategy": "format_preserving",
      "line": 2,
      "confidence": 1.0
    }
  ]
}
```

## Examples

Redact a directory of CSV exports using synthetic data:

```bash
ferret-scan --enable-redaction \
  --redaction-strategy synthetic \
  --redaction-output-dir ./synthetic-data \
  --checks EMAIL,CREDIT_CARD,SSN,PERSON_NAME \
  --recursive ./exports/
```

Redact for compliance archiving (simple, with audit log):

```bash
ferret-scan --enable-redaction \
  --redaction-strategy simple \
  --redaction-output-dir ./archive \
  --redaction-audit-log ./audit-$(date +%Y%m%d).json \
  --recursive ./documents/
```

Use the built-in `redaction` profile:

```bash
ferret-scan --profile redaction --recursive ./documents/
```
