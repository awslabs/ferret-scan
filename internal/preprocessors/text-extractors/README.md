# Text Extractors

This directory contains text extraction libraries for various document formats.

## Available Extractors

- **text-extract-pdf**: Extracts text content from PDF documents
- **text-extract-office**: Extracts text content from Office documents

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

## Features

- Preserves document structure (paragraphs, sheets, slides)
- Provides text statistics (word count, character count, etc.)
- Handles multiple document formats
- Clean text output with proper formatting
