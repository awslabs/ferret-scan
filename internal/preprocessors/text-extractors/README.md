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
measured 943 findings, 817 of them PHONE, on a 64KB drawing built from
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

## Features

- Preserves document structure (paragraphs, sheets, slides)
- Provides text statistics (word count, character count, etc.)
- Handles multiple document formats
- Clean text output with proper formatting
