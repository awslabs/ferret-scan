# PDFMetadataPreprocessor

The PDFMetadataPreprocessor is a specialized preprocessor that extracts metadata from PDF documents. It's part of the refactored metadata preprocessing system that replaced the monolithic MetadataPreprocessor.

## Overview

This preprocessor focuses exclusively on PDF document metadata extraction, providing:
- Document properties and metadata extraction
- PDF version and structure information
- Comprehensive error handling for PDF-specific scenarios
- Support for encrypted and password-protected PDFs
- Resource management and timeout handling
- Observability and debug logging

## Supported File Types

The PDFMetadataPreprocessor supports:

- **PDF** (`.pdf`) - All PDF versions and variants

## ProcessorType

When processing files, this preprocessor sets the `ProcessorType` field to `"pdf_metadata"`. This identifier allows validators to determine which preprocessor was used and make appropriate processing decisions.

## Usage

### Basic Usage

The preprocessor is automatically registered with the router system and doesn't require direct instantiation in most cases:

```go
// The preprocessor is automatically available through the router
// PDF files are automatically routed to this preprocessor
```

### Direct Usage

For direct usage or testing:

```go
import "ferret-scan/internal/preprocessors"

// Create a new PDF metadata preprocessor
processor := preprocessors.NewPDFMetadataPreprocessor()

// Check if it can process a file
if processor.CanProcess("document.pdf") {
    // Process the file
    result, err := processor.Process("document.pdf")
    if err != nil {
        // Handle error
    }

    // Use the extracted metadata
    fmt.Printf("Extracted text: %s\n", result.Text)
    fmt.Printf("Processor type: %s\n", result.ProcessorType) // "pdf_metadata"
}
```

## Extracted Metadata

The preprocessor extracts comprehensive metadata from PDF documents:

### Document Properties
- Title, Author, Subject, Keywords
- Creator application and Producer
- Creation and modification dates
- Document version and PDF version

### Technical Information
- Page count and document structure
- Security settings and permissions
- Encryption status and password protection
- File size and optimization information

### Content Information
- Form fields and interactive elements
- Embedded fonts and resources
- Color space and image information
- Bookmarks and navigation structure

## Error Handling

The preprocessor implements comprehensive error handling for PDF-specific scenarios:

### Recoverable Errors
- **Encrypted PDFs**: Attempts to extract available metadata without decryption
- **Corrupted PDF structure**: Extracts partial metadata when possible
- **Version compatibility**: Handles older and newer PDF versions gracefully

### Non-Recoverable Errors
- **Severely corrupted files**: Fails with detailed error information
- **File size limits exceeded**: Respects configured resource limits
- **Unsupported PDF variants**: Returns appropriate error message

### Error Recovery Strategies
- **Retry**: Temporary file access issues, network problems
- **Graceful Degradation**: Extract available metadata when some data is corrupted
- **Skip**: Files that exceed size limits or are completely unreadable

## Resource Management

The preprocessor implements resource management for PDF processing:

### File Size Limits
- Standard PDF files: 100MB limit (configurable)
- Large document handling with streaming
- Automatic validation before processing

### Timeout Handling
- Processing timeout: 60 seconds (configurable for large documents)
- Context-based cancellation for long operations
- Graceful cleanup on timeout

### Memory Management
- Efficient memory usage for large PDFs
- Streaming processing for oversized documents
- Automatic cleanup after processing

## Observability

The preprocessor provides comprehensive observability features:

### Debug Logging
When debug logging is enabled, the preprocessor logs:
- PDF characteristics (version, page count, encryption status)
- Processing steps and timing information
- Error details and recovery attempts
- Resource usage statistics

### Performance Metrics
- Processing time per document
- Success/failure rates
- Document size distribution
- Error type frequency

### Structured Logging
All logs follow a consistent JSON structure:
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "component": "pdf_metadata_preprocessor",
  "operation": "metadata_extraction",
  "file_path": "/path/to/document.pdf",
  "file_size": 5242880,
  "page_count": 25,
  "processing_time_ms": 300,
  "success": true,
  "encrypted": false,
  "pdf_version": "1.7"
}
```

## Integration with Validators

The `ProcessorType` field set to `"pdf_metadata"` allows validators to:
- Identify PDF-specific metadata content
- Apply document-specific validation rules
- Make processing decisions based on the source preprocessor
- Implement specialized handling for PDF metadata

## Configuration

The preprocessor respects global configuration settings:

### Resource Limits
- File size limits (configurable via environment variables)
- Processing timeouts (configurable via environment variables)
- Memory usage limits

### Observability
- Debug logging level (controlled by `--debug` flag)
- Performance metrics collection
- Error reporting verbosity

## Dependencies

The preprocessor uses the following internal libraries:
- `meta-extract-pdflib`: PDF metadata extraction library
- `observability`: Debug logging and metrics collection
- `shared_utilities`: Common file validation and formatting functions

## Testing

The preprocessor has comprehensive test coverage including:
- Unit tests for PDF processing and metadata extraction
- Error handling scenario testing (encrypted PDFs, corrupted files)
- Resource limit enforcement testing
- Observability integration testing
- Performance and timeout testing

Test files are located at:
- `tests/unit/preprocessors/pdf_metadata_preprocessor_test.go`
- Integration tests in `tests/integration/specialized_preprocessors_*_test.go`

## Migration from MetadataPreprocessor

This preprocessor replaces the PDF processing functionality from the monolithic `MetadataPreprocessor`. The migration maintains full backward compatibility:

- Same `Preprocessor` interface implementation
- Identical `ProcessedContent` output format
- Same error handling behavior
- Preserved observability features

## Performance Characteristics

### Typical Processing Times
- Small PDFs (< 1MB): 50-200ms
- Medium PDFs (1-10MB): 200-800ms
- Large PDFs (10-100MB): 800-3000ms

### Memory Usage
- Minimal memory footprint for metadata extraction
- No full document loading required
- Efficient cleanup after processing

## Special Considerations

### Encrypted PDFs
- Limited metadata extraction without password
- Graceful handling of password-protected documents
- Clear error messages for access restrictions

### Large Documents
- Streaming processing for oversized files
- Progressive timeout handling
- Memory-efficient metadata extraction

## Limitations

- Cannot extract metadata from severely corrupted PDFs
- Password-protected PDFs have limited metadata availability
- Some proprietary PDF variants may not be fully supported
- Processing time increases significantly with document size and complexity
- Embedded multimedia content metadata may not be fully extracted
