# Text Extractors

This directory contains text extraction libraries for various document formats.

## Available Extractors

- **text-extract-pdf**: Extracts text content from PDF documents
- **text-extract-office**: Extracts text content from Office documents
- **text-extract-svg**: Extracts the human-readable text from SVG drawings, and nothing else

## Usage

```bash
# Extract text from PDF documents
go run text-extract-pdf.go document.pdf

# Extract text from Office documents
go run text-extract-office.go document.docx
```

## Libraries

Each extractor uses its corresponding library:

- **text-extract-pdftextlib**: PDF text extraction library
- **text-extract-officetextlib**: Office document text extraction library
- **text-extract-svgtextlib**: SVG prose-node text extraction library
- **text-extract-rtftextlib**: RTF document-destination text extraction library

## Dependencies

- **github.com/ledongthuc/pdf**: For PDF text extraction

## Supported File Types

### PDF Documents
- PDF (.pdf) - various versions

### Office Documents
- Microsoft Word (.docx)
- Microsoft Excel (.xlsx)
- Microsoft PowerPoint (.pptx)
- OpenDocument Text (.odt)
- OpenDocument Spreadsheet (.ods)
- OpenDocument Presentation (.odp)

### Vector Graphics
- SVG (.svg) - **prose only**

An SVG's bulk is coordinate geometry, and handing it to the validators floods them:
measured 1,313 findings, 1,143 of them PHONE, on a 64KB drawing built from
integer-coordinate glyph paths, and 400,001 findings on a 7.2MB one. So
`text-extract-svgtextlib` collects only `<text>`, `<tspan>`, `<textPath>`, `<title>`,
`<desc>`, `<metadata>`, Inkscape flowed text, the `<foreignObject>` subtree, XML
comments, and the handful of attributes that hold prose by definition (`aria-label`,
`alt`, `title`, `inkscape:label`, ...). It never collects `d`, `points`, `transform`,
`viewBox`, `href`, `<style>` or `<script>`.

What CAN be collected is an allowlist, so the flood is unreachable rather than merely
unlikely -- no coordinate is handed to a validator, so no validator's numeric patterns
matter. A drawing with no prose extracts nothing and is reported as clean, not as
unexamined. Redaction goes through `internal/redactors/svg`, which rewrites the FILE:
this extraction is lossy by design, so writing the extracted text back would replace
the drawing with a list of its labels. See docs/development/text_extraction_integration.md.

### Rich Text Format
- RTF (.rtf) - **prose only**

An RTF is ASCII markup, so the plaintext path claimed it and handed the control words to
every validator. The failure is the opposite of SVG's: **silent misses, not a flood.** A
producer such as macOS `textutil` splits a value across formatting runs -- bolding four
digits yields `452-11-\f1\b 9384` -- and no validator pattern matches across a control
word. Measured, a bold `textutil` RTF reported 0 findings where its `.txt` twin reported 3,
at `files_processed: 1` and exit 0 under `--fail-on-incomplete`, so nothing signalled it.
Hex-escaped punctuation (`452\'2d11\'2d9384`) reported 0 as well.

So `text-extract-rtftextlib` emits only character data from document destinations, decoding
`\'hh` and `\uN` escapes, and treats `\par`/`\line`/`\cell`/`\row`/`\tab` as separators.
It never emits `\*\pict`, `\object`/`\objdata`, `\fonttbl`, `\colortbl`, `\stylesheet`,
`\listtable`, `\info`, `\generator`, or any `{\*\...}` ignorable group.

Redaction goes through `internal/redactors/rtf`, which rewrites the FILE: this extraction is
lossy by design, so writing the extracted text back would replace the document with its prose --
measured, `textutil` read 0 bytes of text out of such an output. A value the producer SPLIT across
runs is reported but cannot be removed by byte substitution, so redaction of that file is refused
loudly and disclosed (`values_not_redacted`, exit 3 under `--fail-on-incomplete`) rather than
shipped as a file that looks redacted. See #593.

The two halves pull in opposite directions and both are pinned by test: a word meaning
"same run, different formatting" is DROPPED (reassembling the split value), while one
meaning "new paragraph, cell or line" emits a SEPARATOR -- deleting those instead would
fuse two table cells into a value that appears nowhere in the document. Input over 64MB is
refused with an error, and a file named `.rtf` whose bytes are not RTF falls back to a
raw-bytes scan rather than returning empty text, which would read as a false all-clear.

## Features

- Preserves document structure (paragraphs, sheets, slides)
- Provides text statistics (word count, character count, etc.)
- Handles multiple document formats
- Clean text output with proper formatting
