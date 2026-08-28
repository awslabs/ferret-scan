# Redaction Guide

[← Back to Documentation Index](../README.md)

Ferret-scan can redact sensitive data in two modes:

- **File mode**: writes clean copies of files to an output directory while leaving originals untouched.
- **Streaming mode** (`--stdin --enable-redaction`): pipes redacted content through stdout in real time. See the [Stdin Guide](README-Stdin.md) for the streaming gateway pattern (lambda, CI, shell pipelines).

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

# Streaming redaction via stdin (no temp file needed)
cat sensitive.log | ferret-scan --stdin --enable-redaction > clean.log
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
4916338506082832  →  ************2832   (last 4 visible; BIN masked)
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
| CREDIT_CARD | ✅ | ✅ Last 4 visible | ✅ Valid Luhn number |
| SSN | ✅ | ✅ Last 4 visible | ✅ Invalid area code |
| EMAIL | ✅ | ✅ First char + domain | ✅ Random user@example.com |
| PHONE | ✅ | ✅ Area code + last 4 | ✅ Same format |
| PERSON_NAME | ✅ | ✅ Asterisk mask | ✅ Real name from database |
| IP_ADDRESS | ✅ | ✅ First two octets | ✅ Private range (192.168.x.x) |
| SECRETS | ✅ | ✅ Asterisk mask | ✅ Format-matching fake token |
| PASSPORT | ✅ | ✅ Asterisk mask | ✅ Same country format |
| SOCIAL_MEDIA | ✅ | ✅ Asterisk mask | ✅ Fake profile URL |
| INTELLECTUAL_PROPERTY | ✅ | ✅ Asterisk mask | ✅ Fake copyright/patent/trademark |
| CLOUD_RESOURCES | ✅ | ✅ Generic mask | ✅ Length-matched random token (no provider-specific format) |

## Document Type Support

| File Type | Extensions | Redaction Method |
|-----------|-----------|-----------------|
| Plain text | **any file whose bytes are text** — `.txt` `.log` `.csv` `.json` `.yaml` `.md` `.xml` `.sql` `.html` `.tsv` `.env` `.tfvars` `.properties`, `Dockerfile`, `Makefile`, … | Direct string replacement |
| Word | `.docx` | XML element replacement inside ZIP |
| Excel | `.xlsx` | Shared strings + cell values inside ZIP |
| PowerPoint | `.pptx` | Text elements inside ZIP |
| Legacy Office | `.doc` `.xls` `.ppt` | Same-length in-place overwrite of stream bytes |
| Images | `.jpg` `.jpeg` `.png` | EXIF metadata removal only, by decode + re-encode; images over 64M pixels are refused |
| Other images | `.tiff` `.gif` `.bmp` `.webp` | ⚠️ Not redactable — **no output file is written** and the run says so |
| Audio | `.mp3` `.wav` `.m4a` `.flac` | Same-length in-place overwrite of tag metadata |
| Video | `.mp4` `.m4v` `.mov` `.3gp` `.3g2` | Same-length in-place overwrite of tag metadata; GPS payload zeroed |
| PDF | `.pdf` | ⚠️ Not redactable — **no output file is written** and the run says so |

> **Note on embedded parts**: an OOXML container may carry other documents, images, audio or
> legacy Office files under `word/media/` or `word/embeddings/`. Each is dispatched to the
> redactor for its own type and written back at the same entry name, and the container is
> **refused** — no output file — if any part that could hold a reported value cannot be shown
> free of it. Two shapes reach that refusal, and they are different:
>
> - the part **still contains** a reported value after its redactor ran, or no redactor claims
>   its type (an embedded `.pdf`, which is never redactable);
> - the part **could not be inspected at all**. A part named `.docx`/`.xlsx`/`.pptx` stores its
>   text compressed, so establishing that a value is absent requires opening the archive. When
>   the bytes are not a readable archive — a truncated or corrupt attachment — that cannot be
>   done, and "nothing found" would mean only "we could not look"
>   ([#517](https://github.com/awslabs/ferret-scan/issues/517)). Such a part is handed to a
>   redactor anyway rather than skipped, exactly as an embedded PDF is, and the container is
>   refused if the redactor cannot rewrite it.
>
> A part that IS readable and holds none of the reported values is deliberately left untouched
> and does not block the container: every redactor here is lossy — the image redactor decodes
> and re-encodes, dropping metadata — so running one over a part that was never implicated
> would degrade content for no reason.
>
> **Note on plain text**: selection follows the same content sniff the scanner uses, so
> whatever ferret-scan is willing to read as text it is willing to write back as text —
> extension or no extension. A `.env` holding a live credential is redacted exactly like
> a `.txt`.
>
> **Note on images**: Only EXIF metadata (GPS, camera info, timestamps) is removed. Text embedded
> in image pixels is not redacted. Only **JPEG and PNG** have an implementation: a `.tiff` `.gif`
> `.bmp` or `.webp` file with findings produces **no redacted copy**, and the run reports
> `redaction incomplete … the original values remain in cleartext`, naming the file. An earlier
> version of this table listed all six extensions as redacted, which was wrong in the dangerous
> direction — it implied a stripped copy where none is written.
>
> Stripping EXIF from a JPEG or PNG works by decoding the pixels and re-encoding them, so peak
> memory follows the image's **declared** width × height rather than its size on disk. Images over
> **64M pixels** (2^26 — above every camera sold, including a 61MP full-frame sensor) are therefore
> refused with the same disclosed warning, because a 4MB file can declare 400M pixels and a large
> enough declaration would otherwise exhaust memory. One consequence worth knowing: because the
> pixels are re-encoded, a redacted JPEG is **not** byte-identical to the original outside its
> metadata.
>
> **Note on PDFs**: PDF redaction is on the roadmap. Until then a PDF with findings
> produces **no redacted copy at all** — not an unchanged copy — and the run reports
> `redaction incomplete … the original values remain in cleartext`, naming the file. An
> earlier version of this table said the file was "copied unchanged", which was worse than
> wrong: it implied an output file exists at the sanitized path.
>
> **Note on the exit code for a refusal**: every refusal above is disclosed on the console,
> but none of them changes the exit code — a run that leaves values in cleartext still exits
> `0`. `--fail-on-incomplete` does **not** cover this: it reports incomplete *scan* coverage
> (a validator timeout or budget, or a file that could not be opened), and a refused
> redaction is a fully scanned file. An earlier version of this page said
> `--fail-on-incomplete` turned a PDF refusal into exit code 3; measured, it does not. Gate
> CI on the presence of the warning, or on the redacted file existing, until
> [#441](https://github.com/awslabs/ferret-scan/issues/441) gives these refusals an exit code
> of their own.
>
> **Note on audio and video**: only the tag metadata is redacted — a comment, artist,
> title, copyright, camera make and model, software, or GPS position. The audio or video
> stream itself is never read or modified, so nothing in the recording's *content* is
> redacted. Replacements are exactly as long as the value they replace, so no chunk,
> frame, atom size or sample offset has to be recomputed and the file stays playable.
> Two consequences follow. `synthetic` is **not** offered for these formats, because a
> generated value's length is unrelated to the original; `simple` and
> `format_preserving` are. And the redactor **refuses** rather than writing a partly
> handled file: if a reported value cannot be located in the tag bytes, no output is
> written and the run discloses it.
>
> **Note on XMP in MP4/M4A/MOV**: a metadata editor typically writes the same tag into **two**
> homes — the QuickTime/iTunes atoms under `moov/udta`, and an XMP packet. Both are redacted.
> Measured on a real `.m4a` stripped and then given a single tag: `Artist`, `Title` and `Author`
> each land in both homes, while `Comment` lands only in `udta`. Because the redactor refuses when
> any reported value remains, a file carrying one of the first three used to be refused outright
> ([#452](https://github.com/awslabs/ferret-scan/issues/452)) — the `udta` copy was overwritten and
> the XMP copy was not.
>
> The XMP packet is matched on the Adobe **user type** of its `uuid` box, not on the box type: `uuid`
> is the container format's extension point and also carries vendor and protection payloads, which a
> redactor must not rewrite. Across 800 real ISO-BMFF files, 24 carried a top-level XMP `uuid` box
> and 14 carried an `XMP_` atom under `moov/udta` instead; the latter is covered already, because
> `udta` is treated as one region.
>
> **Note on GPS in video**: a position is stored as binary fixed-point or as an ISO 6709
> string (`+36.3506-082.6985+447.403/`), and reports render it as decimal degrees — so the
> value never appears in the file as the text that was reported. Those payloads are
> therefore zeroed structurally rather than string-matched, which is also why a redacted
> clip reads as having no location rather than as having a masked one.
>
> **Note on legacy Office (`.doc` `.xls` `.ppt`)**: these are OLE compound files, not
> ZIPs. Redaction overwrites the matched bytes with a replacement of exactly the same
> byte length, so no stream changes size and every sector offset, chain and length
> prefix in the container stays valid — nothing has to be recomputed because nothing
> moves. Two consequences follow. The `synthetic` strategy is **not** offered for
> these formats, because a generated value's length is unrelated to the original;
> `simple` and `format_preserving` are. And detection of body text is approximate
> (see the Office metadata preprocessor README), so redaction of `.doc` body text is
> only as complete as detection was — document **properties** are exact.
>
> That includes **multi-valued** properties. A workbook keeps its sheet-name list, and a
> deck its slide titles, in a vector-valued property, and those were reported by nothing
> at all until #267: the property-set reader mis-reads a vector's type word, so the value
> arrived as the literal `0`. Measured on 19 real `.doc`/`.xls`/`.ppt` files, 14 of them
> carry such a property and 40 elements now decode — sheet names, slide titles, theme and
> font names. A value inside one is redactable like any other, because an element is stored
> behind its own length prefix and a same-length overwrite never touches it.

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
                                    # (alias: index_file)
```

The strategies themselves take no options: `simple` writes per-type markers like
`[SSN-REDACTED]`, `format_preserving` keeps the value's length and separators, and
`synthetic` generates a realistic replacement with `crypto/rand`.

## Audit Log

When `--redaction-audit-log` is specified, a JSON file is written with details of every redaction performed — useful for compliance reporting.

```json
{
  "document_id": "sample.csv",
  "original_file_hash": "29ee9f67da87f7c8284a0c2cda4c78f51184aaeda87e6023be9abf01819dcbf9",
  "redacted_file_hash": "7d3f1a0c5b9e2d84f61ac0e7b2358d94ee1c0f6ab84d2379ce50b8a1f3c47e02",
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

The two hashes let a reviewer confirm the log describes the artifact in front of them rather than
some other run. **They are never equal for a file the log reports as redacted** — a replacement
byte-identical to the bytes it replaces is not a redaction, so it is recorded under its own cause and
does not appear in `redactions`.

That distinction is not hypothetical. Re-scanning a redacted file is a normal way to verify a
redaction, and `format_preserving` masks a generic secret with a run of `*` of the same length — so a
value that was *already* a run of `*` used to be "redacted" into itself, producing an output identical
to its input, a `redactions` entry, and two equal hashes. The mask is no longer reported as a secret
in the first place (it cannot contain one), and the identity replacement is refused as a second,
independent guard.

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
