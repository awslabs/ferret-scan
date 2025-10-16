# PDF Metadata Extractor

This library extracts metadata from PDF documents using Go's standard libraries.

## Features

- Extracts common PDF metadata (title, author, subject, etc.)
- Provides document information (version, page count, etc.)
- Extracts creation and modification dates
- Retrieves document security settings
- No external dependencies - uses only Go standard libraries

## Usage

```go
import "Go-Metadata/pdflib"

// Extract metadata from a PDF document
metadata, err := pdflib.Extract("path/to/document.pdf")
if err != nil {
    // Handle error
}

// Access metadata fields
fmt.Println("Title:", metadata.Title)
fmt.Println("Author:", metadata.Author)
fmt.Println("Created:", metadata.CreationDate)
fmt.Println("Page count:", metadata.PageCount)
```

## Metadata Fields

The extractor provides the following metadata fields:

| Field | Description |
|-------|-------------|
| `Filename` | Name of the file |
| `FileSize` | Size of the file in bytes |
| `Version` | PDF version |
| `Title` | Document title |
| `Subject` | Document subject |
| `Author` | Document author |
| `Creator` | Application that created the document |
| `Producer` | Application that produced the PDF |
| `Keywords` | Document keywords |
| `CreationDate` | Document creation date |
| `ModDate` | Document last modification date |
| `PageCount` | Number of pages in the document |
| `PageSize` | Size of the pages (if consistent) |
| `Encrypted` | Whether the document is encrypted |
| `Permissions` | Document permissions (if encrypted) |
| `HasText` | Whether the document contains text |
| `HasImages` | Whether the document contains images |
| `HasForms` | Whether the document contains forms |
| `HasOutline` | Whether the document has an outline/bookmarks |
| `HasAnnotations` | Whether the document has annotations |

## Implementation Details

The extractor parses the PDF file structure to extract metadata from:

1. The document information dictionary
2. The document catalog
3. XMP metadata (if present)

It uses regular expressions and pattern matching to identify and extract metadata fields from the PDF structure.

## Limitations

- Only extracts metadata that is present in the document
- Some PDF features (digital signatures, attachments) may not be fully analyzed
- Encrypted PDFs with restrictions may have limited metadata extraction
- PDF structure variations may affect extraction accuracy
