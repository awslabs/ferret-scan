# PDF Text Extractor

This library extracts text content from PDF documents using the ledongthuc/pdf Go library.

## Features

- Extracts text from PDF documents
- Provides document statistics (page count, word count, etc.)
- Handles various PDF versions and formats
- Preserves basic text structure

## Dependencies

- [github.com/ledongthuc/pdf](https://github.com/ledongthuc/pdf) - A pure Go library for reading PDF files

## Usage

```go
import "Go-Metadata/pdftextlib"

// Extract text from a PDF document
content, err := pdftextlib.ExtractText("path/to/document.pdf")
if err != nil {
    // Handle error
}

// Access text content and metadata
fmt.Println("Page count:", content.PageCount)
fmt.Println("Word count:", content.WordCount)
fmt.Println("Text content:", content.Text)
```

## Content Fields

The extractor provides the following fields:

| Field | Description |
|-------|-------------|
| `Filename` | Name of the file |
| `Text` | Extracted text content |
| `PageCount` | Number of pages in the PDF |
| `WordCount` | Number of words in the text |
| `CharCount` | Number of characters in the text |
| `LineCount` | Number of lines in the text |

## Implementation Details

The extractor uses the ledongthuc/pdf library to:

1. Open and parse the PDF document
2. Extract text from each page
3. Clean and format the extracted text
4. Calculate document statistics

## Text Cleaning

The extractor performs the following text cleaning operations:

- Removes duplicate spaces
- Replaces tabs with spaces
- Trims whitespace
- Adds paragraph breaks at appropriate places

## Limitations

- Complex PDF layouts may not be perfectly preserved
- PDFs with scanned images require OCR (not supported by this extractor)
- Some PDF features (forms, annotations) are not processed
- Encrypted PDFs may not be fully supported
- Text extraction quality depends on how the PDF was created
