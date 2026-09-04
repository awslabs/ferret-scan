# Text Extraction Integration

[← Back to Documentation Index](../README.md)

This document describes the integration of text extractors as preprocessors in Ferret-scan.

## Overview

The text extraction preprocessors allow Ferret-scan to analyze the content of document files (PDF, Office documents) by extracting their text content before running PII/PHI validators.

## Architecture

### Components

1. **Preprocessor Interface** (`internal/preprocessors/preprocessor.go`)
   - Defines the `Preprocessor` interface for all preprocessors
   - Defines the shared `ProcessedContent` model

2. **File Router** (`internal/router/file_router.go`)
   - Registers and coordinates multiple preprocessors
   - Handles file type detection and routing

3. **Text Preprocessor** (`internal/preprocessors/text_preprocessor.go`)
   - Implements text extraction for PDF and Office documents
   - Uses existing text extraction libraries
   - Returns structured `ProcessedContent`

4. **Updated Validator Interface** (`internal/detector/detector.go`)
   - Added `ValidateContent()` method for processing extracted text
   - Maintains backward compatibility with existing `Validate()` method

### Supported File Types

- **PDF Documents**: `.pdf`
- **Microsoft Office**: `.docx`, `.xlsx`, `.pptx`, and the macro-enabled forms `.docm`, `.xlsm`, `.pptm`
- **OpenDocument**: `.odt`, `.ods`, `.odp` — and their templates `.ott`, `.ots`, `.otp`, which are the same packages with a template media type
- **SVG**: `.svg` — **prose only**, see below
- **Rich Text Format**: `.rtf` — **prose only**, see below

### SVG: prose only, never geometry

An `.svg` is XML text, so the byte-sniffing plaintext path used to claim it and hand the
whole document — path coordinates included — to every validator. Measured on a 64KB SVG
built from integer-coordinate glyph paths, the shape real icon and font SVGs carry:
**1,313 findings, 1,143 of them PHONE (122 HIGH), every one a path coordinate.** On a 7.2MB
SVG whose geometry sits in one huge `d=` attribute: **400,001 findings in 19.9 seconds.**

`.svg` is therefore routed to a dedicated extractor,
`internal/preprocessors/text-extractors/text-extract-svgtextlib`, which collects only:

| Collected | Never collected |
|---|---|
| `<text>`, `<tspan>`, `<textPath>`, `<tref>` character data | `d`, `points`, `transform`, `viewBox`, and every other geometry or presentation attribute |
| `<title>`, `<desc>` | `<path>`, `<polygon>`, `<polyline>`, `<line>`, `<rect>`, `<circle>`, `<ellipse>` content |
| `<metadata>` (RDF / Dublin Core) | `<style>` (CSS, including base64 `@font-face`) |
| Inkscape flowed text (`<flowRoot>`, `<flowPara>`, …) | `<script>` |
| The `<foreignObject>` subtree (embedded XHTML) | `href` / `xlink:href` **except** a `mailto:` or `tel:` target — see below |
| `aria-label`, `aria-description`, `aria-roledescription`, `aria-valuetext`, `alt`, `title`, `inkscape:label`, `sodipodi:docname` | `id`, `class`, and every other attribute |
| XML comments | |

The set of things that CAN be collected is an allowlist, so a construct nobody
anticipated is dropped rather than admitted. That is what makes the flood unreachable
rather than merely unlikely: no coordinate is handed to a validator, so no validator's
numeric patterns matter.

**The one value-conditional rule: `mailto:` and `tel:` link targets.** Every other admission above is
decided by NAME alone. These two are decided by the attribute's VALUE, because a link target is the
commonest place a real diagram carries a contact — an `<a xlink:href="mailto:...">` wrapping a
"Contact the owner" label puts the address in the attribute and only the label in the text node.
Measured on such a diagram, the address was reported at HIGH by the raw-XML scan this extractor
replaces, and not at all by prose extraction, so excluding every `href` traded 1,313 coordinate false
positives for a real miss.

Only those two schemes are admitted, and that is what keeps the flood out. Measured on 300 `<a>`
elements whose target is an ordinary numeric CDN asset URL: scanning those targets yields **256 PHONE
and 9 NPI** findings, every one false, and the rule admits **0** of them. `http:`, `https:`, `data:`,
fragments and relative paths stay excluded by construction — it is an allowlist of two schemes, not a
denylist of the rest. The scheme is matched case-insensitively (RFC 3986 §3.1), percent-encoding is
decoded with `PathUnescape` so a `tel:` number keeps its leading `+`, and a `mailto:` query
(`?subject=`) is cut.

Consequences worth knowing:

- **A prose-less drawing is clean, not unexamined.** An icon with no text reports zero
  findings and says nothing about it — 88 of 90 real `.svg` files measured carry no prose,
  so a coverage warning each would be noise. Truncation (size bound, nesting bound,
  malformed markup) *is* disclosed and makes `--fail-on-incomplete` exit 3.
- **Text converted to outlines is not read.** An Illustrator export can render words as
  `<path>` geometry with no character data anywhere. That is a known limitation, the same
  class as the pixels of a raster image.
- **A file named `.svg` that is not an SVG is still scanned as raw text.** The root
  element decides; a renamed `.txt` holding an SSN reports it exactly as before.
- **A value duplicated into an attribute nobody reads makes redaction REFUSE.** The residue check
  reads the whole written file, so a reported value that also sits in an unread attribute — an `id`,
  or an `https:` target — survives it and the output is discarded rather than shipped leaky.
  Measured: no artifact is written and the original stays in cleartext. This is **disclosed**, not
  silent: a `WARNING: redaction incomplete` names the file and the cause, and
  `--fail-on-incomplete` exits 3. Whether a refusal should also fail the default exit code is a
  cross-redactor contract question tracked in
  [#459](https://github.com/awslabs/ferret-scan/issues/459), not decided here.
- **Redaction rewrites the FILE, not the extracted prose.** See
  `internal/redactors/svg`: because SVG extraction is lossy by design, the content-based
  redaction path would have replaced the drawing with a list of its labels.
- **Embedded `.svg` parts are scanned and redacted too.** They were excluded
  (`embedded.SkipTextPipeline`) for the flood above; `.emf`, `.wmf` and `.wdp` remain
  excluded because they are binary metafiles with no text reader at all.

### RTF: reassemble what a producer split apart

An `.rtf` is ASCII markup, so the byte-sniffing plaintext path claimed it and handed the
whole document — control words included — to every validator. Unlike SVG, the failure was
not a flood of false positives but **silent misses**, which by the sink rule is worse: only
reported findings reach the redactor, so a value nobody reported stays cleartext in a file
the operator was told was clean.

Measured at `f91ad60` on files produced by macOS `textutil` (the engine behind TextEdit and
Pages), against the identical content as `.txt`:

| file | findings before | findings after |
|---|---|---|
| `textutil` RTF, **bold mid-value** | **0** | 3 |
| `textutil` RTF, no formatting at all | 3 | 4 |
| hand-written plain RTF | 1 | 2 |
| hex-escaped punctuation (`452\'2d11\'2d9384`) | **0** | 2 |
| the same content as `.txt` (control) | 4 | 4 |

The file was reported `files_processed: 1, files_skipped: 0` throughout, and
`--fail-on-incomplete` exited **0** — so nothing signalled that anything had been missed.

**The cause is that a producer splits a value across formatting runs.** Bolding four digits
makes the bytes reaching the validators

```
Employee SSN: 452-11-\f1\b 9384
```

and no SSN pattern can match across a control word. A completely unformatted `textutil`
file still loses a value, because the trailing `\` line-break escape alone is enough.

`.rtf` is therefore routed to a dedicated extractor,
`internal/preprocessors/text-extractors/text-extract-rtftextlib`:

| Collected | Never collected |
|---|---|
| Character data from document destinations | `\*\pict`, `\object`, `\objdata` — embedded images and OLE data, carried as megabytes of hex |
| `\'hh` hex escapes, decoded | `\fonttbl`, `\colortbl`, `\stylesheet`, `\listtable`, `\rsidtbl` — machine tables; font names produce PERSON_NAME hits |
| `\uN` Unicode escapes, decoded (the ANSI fallback byte is discarded, not doubled) | `\info`, `\generator` — document metadata, which has its own path |
| `\par`, `\line`, `\cell`, `\row`, `\tab` … as **separators** | any group opened with the specification's ignorable marker `{\*\…}` |

As with SVG the collected set is an **allowlist**: only character data from document
destinations is emitted, so a construct nobody anticipated is dropped rather than admitted.

**The two halves have to be got right in opposite directions.** A control word meaning "same
run, different formatting" (`\b`, `\f1`, `\i`) is *dropped*, which is what reassembles the
split value. A word meaning "new paragraph, cell or line" (`\par`, `\cell`, `\row`) emits a
*separator* — because deleting those instead would fuse two adjacent table cells into a
value that appears nowhere in the document. Both directions are pinned by test.

**Notes on the two hazards raised in #421.** Its "Hazard 1" (do not route RTF through the
printability sniff) is correct and is why the extractor keys on the `{\rtf` signature in the
bytes rather than on the extension. Its "Hazard 2" claimed the plaintext path already feeds
`\pict` hex to the validators and produces findings; measured, a 302KB RTF holding a 300KB
hex `\pict` yields exactly **1** finding — the planted SSN — and **0** false positives. The
hazard is real for *this* reader if it did not skip the destination, which is why it does,
and both the `{\*\shppict{\pict …}}` and bare `{\pict …}` wrappings are covered — they are
dropped by different code, and a test using only the first form passed even with `pict`
removed from the skip list.

**What is refused rather than truncated.** Input over 64MB is rejected with an error, and a
file named `.rtf` whose bytes are not RTF falls back to a raw-bytes scan rather than
returning empty text — an empty result would read as "scanned, nothing found", which is a
false all-clear.

**Redaction rewrites the FILE, not the extracted prose** — the same rule as SVG, and the failure
was measured the same way. RTF extraction is lossy by design, and the worker pool prefers a
redactor's `RedactContent` (the extracted text) over `RedactDocument` (the file). Routed to the
plaintext redactor, a 115-byte RTF's "redacted" output was two lines of prose with no `{\rtf`
header, no font table and no control words, and `textutil -convert txt` read **0 bytes** of text
back out of it where it read 54 from the same file redacted by the older path. So `.rtf` has its own
redactor, `internal/redactors/rtf`, which deliberately does **not** implement `RedactContent`.

**A value split across runs is detected but cannot yet be redacted, and that is disclosed rather
than hidden.** The reassembled value occurs nowhere literally in the file, so a byte substitution
finds nothing. A residue check at the sink — run against the DECODED rendering as well as the raw
bytes — catches this and refuses to write the file, naming only the finding TYPES and never the
values. Measured on the `textutil` bold fixture: 3 findings still reported,
`files_not_redacted: 1, values_not_redacted: 3`, a warning on stderr, and
`--fail-on-incomplete` exits **3**. Before this change the same file gave 0 findings and exit 0,
so this is strictly better — detected, disclosed, no destroyed file — but it is not a redaction.
Span-mapped redaction of split values is tracked as #593.

**Verified on real files.** All **60** `.rtf` files present on a macOS install (Apple software
licence agreements under `/System` and `/Library`, spanning Latin, Hebrew, Arabic, Japanese
and Chinese locales): **105 more `INTELLECTUAL_PROPERTY` findings and 26 more `PERSON_NAME`**,
all genuine licence text the old path was mangling, and **9 fewer `PERSON_NAME`** — every one
a false positive (`NEM MIN`, `EI LUO`) produced by the old path mis-decoding non-Latin
escapes. No real finding was lost.

## Configuration

### Command Line Options

- `--enable-preprocessors`: Enable/disable text extraction (default: true)

### Configuration File

```yaml
defaults:
  enable_preprocessors: true

preprocessors:
  text_extraction:
    enabled: true

profiles:
  thorough:
    enable_preprocessors: true
```

## Usage

### Basic Usage

```bash
# Scan with text extraction enabled (default)
ferret-scan --file document.pdf

# Disable text extraction
ferret-scan --file document.pdf --enable-preprocessors=false

# Use a profile with text extraction
ferret-scan --file documents/ --profile thorough --recursive
```

### Preprocessing Output

`--preprocess-only` (`-p`) prints each file's preprocessing status followed by the
extracted text:

```
=== FILE: document.docx ===
Processor: Text Extractor+office_metadata
Status: Success
Content: 19 words, 127 characters

Quarterly report text with several words in it for extraction.

--- office_metadata ---
DocumentType: Word Document
```

`Processor` is the `+`-joined list of preprocessors that actually ran, and each
non-body section is introduced by a `--- name ---` header. The `Content` line
gains a `, N pages` suffix when the extractor reports a page count.

`--verbose` does not print preprocessing information — it prints match details
and the scan summary.

## Integration Details

### Processing Flow

1. **File Detection**: Check if file extension requires preprocessing
2. **Preprocessing**: Extract text content using appropriate extractor
3. **Validation**: Pass extracted text to validators using `ValidateContent()`
4. **Failure**: If extraction fails there is no file-reading validation to fall
   back to; the failure is surfaced as an extraction error for that file

### Validator Updates

Validators operate exclusively on pre-extracted content:

- `ValidateContent(content, originalPath string)`: scans preprocessed content (the sole entry point)
- `ValidateContentCtx(ctx, content, originalPath string)`: context-aware form that polls for cancellation (per-job deadline / `--validator-budget`)

> The former file-reading `Validate(filePath string)` method was removed in v2
> (gap 3.2): every implementation was a no-op stub that never read the file, so
> production always went through `ValidateContent`. Extraction feeds
> `ValidateContent` directly.

### Performance Considerations

- Text extraction runs before validation, adding processing time
- Large documents may take longer to process
- Extracted text is processed in memory
- Parallel processing is maintained for multiple files

## Benefits

1. **Enhanced Detection**: Can find PII/PHI inside document content, not just filenames
2. **Comprehensive Coverage**: Supports multiple document formats
3. **Contextual Analysis**: Maintains context information for better confidence scoring
4. **Configurable**: Can be enabled/disabled per profile or globally

## Limitations

1. **File Size**: Large documents may consume significant memory
2. **Format Support**: Limited to supported document formats
3. **Processing Time**: Adds overhead for document parsing
4. **Text Quality**: Extracted text quality depends on document structure

## Future Enhancements

1. **Additional Formats**: Support for more document types
2. **OCR Integration**: Text extraction from images within documents
3. **Metadata Extraction**: Enhanced metadata analysis
4. **Streaming Processing**: Handle large documents more efficiently
5. **Custom Extractors**: Plugin system for custom text extractors

## Troubleshooting

### Common Issues

1. **Preprocessing Failures**: Check file permissions and format support
2. **Memory Issues**: Large documents may require more memory
3. **Performance**: Disable preprocessing for large file sets if needed

### Debug Information

Use `--preprocess-only` to see the preprocessing status and statistics for each
file. `--verbose` covers match details and the scan summary, not preprocessing.
