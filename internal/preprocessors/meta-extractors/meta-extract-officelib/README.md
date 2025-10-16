# Office Document Metadata Extractor

This library extracts metadata from various office document formats using Go's standard libraries.

## Features

- Extracts metadata from Microsoft Office and OpenDocument formats
- Provides document properties (title, author, subject, etc.)
- Extracts creation and modification dates
- Retrieves document statistics (page count, word count, etc.)
- No external dependencies - uses only Go standard libraries

## Supported File Types

- Microsoft Word (.docx)
- Microsoft Excel (.xlsx)
- Microsoft PowerPoint (.pptx)
- OpenDocument Text (.odt)
- OpenDocument Spreadsheet (.ods)
- OpenDocument Presentation (.odp)

## Usage

```go
import "Go-Metadata/officelib"

// Extract metadata from an office document
metadata, err := officelib.Extract("path/to/document.docx")
if err != nil {
    // Handle error
}

// Access metadata fields
fmt.Println("Title:", metadata.Title)
fmt.Println("Author:", metadata.Author)
fmt.Println("Created:", metadata.Created)
fmt.Println("Page count:", metadata.PageCount)
```

## Metadata Fields

The extractor provides the following metadata fields:

| Field | Description |
|-------|-------------|
| `Filename` | Name of the file |
| `FileSize` | Size of the file in bytes |
| `Format` | Format of the document (Word Document, Excel Spreadsheet, etc.) |
| `Title` | Document title |
| `Subject` | Document subject |
| `Author` | Document author |
| `Keywords` | Document keywords |
| `Description` | Document description/comments |
| `LastModifiedBy` | User who last modified the document |
| `Created` | Document creation date |
| `Modified` | Document last modification date |
| `Application` | Application used to create the document |
| `AppVersion` | Version of the application |
| `PageCount` | Number of pages (for documents) or slides (for presentations) |
| `WordCount` | Number of words in the document |
| `CharCount` | Number of characters in the document |
| `LineCount` | Number of lines in the document |
| `ParaCount` | Number of paragraphs in the document |
| `SlideCount` | Number of slides (for presentations) |
| `NoteCount` | Number of notes (for presentations) |
| `HiddenSlideCount` | Number of hidden slides (for presentations) |
| `MultimediaClipCount` | Number of multimedia clips (for presentations) |

## Implementation Details

The extractor treats office documents as ZIP archives and extracts metadata from the XML files within:

- **DOCX/XLSX/PPTX**: Extracts metadata from `docProps/core.xml` and `docProps/app.xml`
- **ODT/ODS/ODP**: Extracts metadata from `meta.xml`

## Limitations

- Only extracts metadata that is present in the document
- Some application-specific metadata may not be recognized
- Metadata accuracy depends on the application that created the document
