# Text Extraction Integration

[← Back to Documentation Index](../README.md)

This document describes the integration of text extractors as preprocessors in Ferret-scan.

## Overview

The text extraction preprocessors allow Ferret-scan to analyze the content of document files (PDF, Office documents) by extracting their text content before running PII/PHI validators.

## Architecture

### Components

1. **Preprocessor Interface** (`internal/preprocessors/preprocessor.go`)
   - Defines the `Preprocessor` interface for all preprocessors
   - Provides `PreprocessorManager` for managing multiple preprocessors
   - Handles file type detection and routing

2. **Text Preprocessor** (`internal/preprocessors/text_preprocessor.go`)
   - Implements text extraction for PDF and Office documents
   - Uses existing text extraction libraries
   - Returns structured `ProcessedContent`

3. **Updated Validator Interface** (`internal/detector/detector.go`)
   - Added `ValidateContent()` method for processing extracted text
   - Maintains backward compatibility with existing `Validate()` method

### Supported File Types

- **PDF Documents**: `.pdf`
- **Microsoft Office**: `.docx`, `.xlsx`, `.pptx`
- **OpenDocument**: `.odt`, `.ods`, `.odp`

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
    types:
      - pdf
      - office

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

### Verbose Output

When using `--verbose`, the tool will show preprocessing information:

```
Preprocessed document.pdf: extracted 1250 words, 7890 characters
```

## Integration Details

### Processing Flow

1. **File Detection**: Check if file extension requires preprocessing
2. **Preprocessing**: Extract text content using appropriate extractor
3. **Validation**: Pass extracted text to validators using `ValidateContent()`
4. **Fallback**: If preprocessing fails, fall back to regular file validation

### Validator Updates

Validators now support two validation methods:

- `Validate(filePath string)`: Original method for direct file processing
- `ValidateContent(content, originalPath string)`: New method for preprocessed content

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

Use `--verbose` to see preprocessing status and statistics for each file.
