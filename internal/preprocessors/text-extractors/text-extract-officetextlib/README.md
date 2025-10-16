# Office Document Text Extractor

This library extracts text content from various office document formats using Go's standard libraries.

## Features

- Extracts text from Microsoft Office and OpenDocument formats
- Preserves document structure (paragraphs, sheets, slides)
- Extracts metadata when available
- Provides document statistics (word count, character count, etc.)
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
import "Go-Metadata/officetextlib"

// Extract text from an office document
content, err := officetextlib.ExtractText("path/to/document.docx")
if err != nil {
    // Handle error
}

// Access text content and metadata
fmt.Println("Format:", content.Format)
fmt.Println("Word count:", content.WordCount)
fmt.Println("Text content:", content.Text)
```

## Content Fields

The extractor provides the following fields:

| Field | Description |
|-------|-------------|
| `Filename` | Name of the file |
| `Text` | Extracted text content |
| `Format` | Format of the document (Word Document, Excel Spreadsheet, etc.) |
| `PageCount` | Number of pages (for documents) or slides (for presentations) |
| `WordCount` | Number of words in the text |
| `CharCount` | Number of characters in the text |
| `LineCount` | Number of lines in the text |
| `Paragraphs` | Number of paragraphs in the text (for documents) |

## Implementation Details

The extractor treats office documents as ZIP archives and extracts text from the XML files within:

- **DOCX**: Extracts text from `word/document.xml`
- **XLSX**: Extracts text from worksheets and shared strings
- **PPTX**: Extracts text from slides
- **ODT/ODS/ODP**: Extracts text from `content.xml`

## Formatting

- **Word Documents**: Preserves paragraph breaks
- **Excel Spreadsheets**: Organizes text by worksheet with sheet names
- **PowerPoint Presentations**: Organizes text by slide with slide numbers

## Limitations

- Formatting (bold, italic, etc.) is not preserved
- Images and charts are not processed
- Complex document structures may not be perfectly represented
- Some document features (comments, headers/footers) may not be extracted
