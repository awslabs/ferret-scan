# Text Extractors

This directory contains text extraction libraries for various document formats, including AI-powered OCR capabilities.

## Available Extractors

### Standard Text Extractors
- **text-extract-pdf**: Extracts text content from PDF documents
- **text-extract-office**: Extracts text content from Office documents

### AI-Powered OCR Extractor (GenAI)
- **textract-extractor-lib**: Amazon Textract OCR for images and scanned documents

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
- **textract-extractor-lib**: Amazon Textract OCR library (GenAI mode)

## Dependencies

- **github.com/ledongthuc/pdf**: For PDF text extraction

## Supported File Types

### PDF Documents
- PDF (.pdf) - various versions
- PDF with Textract OCR (.pdf) - scanned and image-based PDFs (GenAI mode)

### Office Documents
- Microsoft Word (.docx)
- Microsoft Excel (.xlsx)
- Microsoft PowerPoint (.pptx)
- OpenDocument Text (.odt)
- OpenDocument Spreadsheet (.ods)
- OpenDocument Presentation (.odp)

### Images (Textract OCR - GenAI mode only)
- PNG (.png) - OCR text extraction
- JPEG (.jpg, .jpeg) - OCR text extraction
- TIFF (.tiff, .tif) - OCR text extraction

## Features

### Standard Text Extraction
- Preserves document structure (paragraphs, sheets, slides)
- Provides text statistics (word count, character count, etc.)
- Handles multiple document formats
- Clean text output with proper formatting

### GenAI Mode (Amazon Textract OCR)
- **High-accuracy OCR**: Professional-grade text extraction from images
- **Scanned Document Support**: Extract text from image-based PDFs
- **Confidence Scoring**: Provides confidence levels for extracted text
- **Cost Estimation**: Estimates AWS costs before processing
- **Multi-format Support**: PDF, PNG, JPEG, TIFF

### GenAI Requirements
- AWS account with valid credentials
- Internet connection to AWS services
- IAM permission: `textract:DetectDocumentText`
- Costs apply: ~$0.0015 per page/image

### GenAI Usage
```bash
# Enable GenAI mode for OCR
./ferret-scan --file scanned-document.pdf --enable-genai

# Specify AWS region
./ferret-scan --file image.png --enable-genai --textract-region us-west-2
```

⚠️ **Important**: GenAI mode sends files to AWS and incurs costs. Use `--enable-genai` flag to enable.
