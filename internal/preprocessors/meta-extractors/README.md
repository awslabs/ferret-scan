# Metadata Extractors

This directory contains metadata extractors for various file types.

## Extractors

- **meta-extract-exif**: Extracts EXIF metadata from image files
- **meta-extract-pdf**: Extracts metadata from PDF documents
- **meta-extract-office**: Extracts metadata from Office documents

## Usage

```bash
# Extract EXIF metadata from images
go run meta-extract-exif.go image.jpg

# Extract metadata from PDF documents
go run meta-extract-pdf.go document.pdf

# Extract metadata from Office documents
go run meta-extract-office.go document.docx
```

## Libraries

Each extractor uses its corresponding library:

- **meta-extract-exiflib**: EXIF metadata extraction library
- **meta-extract-pdflib**: PDF metadata extraction library
- **meta-extract-officelib**: Office document metadata extraction library

## Supported File Types

### Images (EXIF)
- JPEG (.jpg, .jpeg)
- TIFF (.tif, .tiff)

### PDF Documents
- PDF (.pdf) - various versions

### Office Documents
- Microsoft Word (.docx)
- Microsoft Excel (.xlsx)
- Microsoft PowerPoint (.pptx)
- OpenDocument Text (.odt)
- OpenDocument Spreadsheet (.ods)
- OpenDocument Presentation (.odp)
