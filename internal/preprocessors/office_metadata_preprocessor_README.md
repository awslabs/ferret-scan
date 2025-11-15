# OfficeMetadataPreprocessor

The OfficeMetadataPreprocessor is a specialized preprocessor that extracts metadata from Microsoft Office and OpenDocument format files. It's part of the refactored metadata preprocessing system that replaced the monolithic MetadataPreprocessor.

## Overview

This preprocessor focuses exclusively on Office document metadata extraction, providing:
- Document properties and metadata extraction
- Author, company, and revision history information
- Embedded media detection and reprocessing
- Comprehensive error handling for Office-specific scenarios
- Support for password-protected documents
- Resource management and timeout handling
- Observability and debug logging

## Supported File Types

The OfficeMetadataPreprocessor supports the following document formats:

### Microsoft Office Formats
- **Word Documents** (`.docx`) - Document properties, author info, revision history
- **Excel Spreadsheets** (`.xlsx`) - Workbook properties, author info, sheet metadata
- **PowerPoint Presentations** (`.pptx`) - Presentation properties, author info, slide metadata

### OpenDocument Formats
- **Text Documents** (`.odt`) - Document properties and metadata
- **Spreadsheets** (`.ods`) - Spreadsheet properties and metadata
- **Presentations** (`.odp`) - Presentation properties and metadata

## ProcessorType

When processing files, this preprocessor sets the `ProcessorType` field to `"office_metadata"`. This identifier allows validators to determine which preprocessor was used and make appropriate processing decisions.

## Usage

### Basic Usage

The preprocessor is automatically registered with the router system and doesn't require direct instantiation in most cases:

```go
// The preprocessor is automatically available through the router
// Office files are automatically routed to this preprocessor
```

### Direct Usage

For direct usage or testing:

```go
import "ferret-scan/internal/preprocessors"

// Create a new Office metadata preprocessor
processor := preprocessors.NewOfficeMetadataPreprocessor()

// Check if it can process a file
if processor.CanProcess("document.docx") {
    // Process the file
    result, err := processor.Process("document.docx")
    if err != nil {
        // Handle error
    }

    // Use the extracted metadata
    fmt.Printf("Extracted text: %s\n", result.Text)
    fmt.Printf("Processor type: %s\n", result.ProcessorType) // "office_metadata"
}
```

## Extracted Metadata

The preprocessor extracts comprehensive metadata from Office documents:

### Document Properties
- Title, Subject, Keywords, Description
- Author, Last Modified By, Company
- Creation and modification dates
- Document version and application info

### Content Information
- Word count, character count, page count
- Paragraph and section count
- Language and locale information
- Template and theme information

### Revision History
- Edit time and revision count
- Track changes information
- Comment and annotation metadata
- Version history details

### Security Information
- Password protection status
- Digital signature information
- Document permissions and restrictions
- Macro security settings

### Embedded Media
- Embedded images and media files
- Linked external resources
- Chart and diagram metadata
- Audio and video content detection

## Embedded Media Reprocessing

One of the key features of the OfficeMetadataPreprocessor is its ability to detect and reprocess embedded media:

### Automatic Detection
- Scans documents for embedded images, audio, and video
- Identifies linked external media resources
- Detects charts, diagrams, and other visual elements

### Router Integration
- Automatically routes detected media through appropriate preprocessors
- Combines metadata from document and embedded media
- Maintains processing context and relationships

### Supported Embedded Types
- Images (JPEG, PNG, GIF, etc.)
- Audio files (MP3, WAV, etc.)
- Video files (MP4, AVI, etc.)
- Charts and diagrams
- Embedded documents

## Error Handling

The preprocessor implements comprehensive error handling for Office-specific scenarios:

### Recoverable Errors
- **Password-protected documents**: Attempts to extract available metadata
- **Corrupted document structure**: Extracts partial metadata when possible
- **Missing embedded media**: Continues processing with available content

### Non-Recoverable Errors
- **Severely corrupted files**: Fails with detailed error information
- **File size limits exceeded**: Respects configured resource limits
- **Unsupported Office versions**: Returns appropriate error message

### Error Recovery Strategies
- **Retry**: Temporary file access issues, network problems
- **Graceful Degradation**: Extract available metadata when some data is corrupted
- **Skip**: Files that exceed size limits or are completely unreadable

## Resource Management

The preprocessor implements resource management for Office document processing:

### File Size Limits
- Standard Office files: 100MB limit (configurable)
- Large document handling with streaming
- Automatic validation before processing

### Timeout Handling
- Processing timeout: 45 seconds (configurable)
- Context-based cancellation for long operations
- Graceful cleanup on timeout

### Memory Management
- Efficient memory usage for large documents
- Streaming processing for oversized files
- Automatic cleanup after processing

## Observability

The preprocessor provides comprehensive observability features:

### Debug Logging
When debug logging is enabled, the preprocessor logs:
- Document characteristics (type, size, embedded media count)
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
  "component": "office_metadata_preprocessor",
  "operation": "metadata_extraction",
  "file_path": "/path/to/document.docx",
  "file_size": 3145728,
  "processing_time_ms": 250,
  "success": true,
  "document_type": "docx",
  "embedded_media_count": 3,
  "password_protected": false
}
```

## Integration with Validators

The `ProcessorType` field set to `"office_metadata"` allows validators to:
- Identify Office document-specific metadata content
- Apply document-specific validation rules
- Make processing decisions based on the source preprocessor
- Implement specialized handling for Office metadata

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
- `meta-extract-officelib`: Office document metadata extraction library
- `observability`: Debug logging and metrics collection
- `shared_utilities`: Common file validation and formatting functions
- Router integration for embedded media processing

## Testing

The preprocessor has comprehensive test coverage including:
- Unit tests for Office document processing and metadata extraction
- Error handling scenario testing (password-protected, corrupted files)
- Embedded media processing testing
- Resource limit enforcement testing
- Observability integration testing

Test files are located at:
- `tests/unit/preprocessors/office_metadata_preprocessor_test.go`
- Integration tests in `tests/integration/specialized_preprocessors_*_test.go`

## Migration from MetadataPreprocessor

This preprocessor replaces the Office document processing functionality from the monolithic `MetadataPreprocessor`. The migration maintains full backward compatibility:

- Same `Preprocessor` interface implementation
- Identical `ProcessedContent` output format
- Same error handling behavior
- Preserved observability features
- Maintained embedded media reprocessing functionality

## Performance Characteristics

### Typical Processing Times
- Small documents (< 1MB): 100-300ms
- Medium documents (1-10MB): 300-1000ms
- Large documents (10-100MB): 1000-4000ms

### Memory Usage
- Minimal memory footprint for metadata extraction
- Efficient handling of embedded media
- Automatic cleanup after processing

## Special Considerations

### Password-Protected Documents
- Limited metadata extraction without password
- Graceful handling of protected documents
- Clear error messages for access restrictions

### Embedded Media Processing
- Automatic detection and reprocessing of embedded content
- Maintains relationships between document and media metadata
- Efficient handling of multiple embedded items

### Large Documents
- Streaming processing for oversized files
- Progressive timeout handling
- Memory-efficient metadata extraction

## Limitations

- Cannot extract metadata from severely corrupted Office documents
- Password-protected documents have limited metadata availability
- Some legacy Office formats (DOC, XLS, PPT) are not supported
- Processing time increases with document complexity and embedded media count
- Very large documents with extensive embedded media may hit timeout limits
- Some proprietary Office features may not be fully supported
