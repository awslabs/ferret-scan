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
