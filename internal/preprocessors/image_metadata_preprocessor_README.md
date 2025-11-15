# ImageMetadataPreprocessor

The ImageMetadataPreprocessor is a specialized preprocessor that extracts EXIF and other metadata from image files. It's part of the refactored metadata preprocessing system that replaced the monolithic MetadataPreprocessor.

## Overview

This preprocessor focuses exclusively on image file metadata extraction, providing:
- EXIF data extraction from JPEG and TIFF files
- Basic metadata extraction from other image formats
- Comprehensive error handling for image-specific scenarios
- Resource management and timeout handling
- Observability and debug logging

## Supported File Types

The ImageMetadataPreprocessor supports the following image formats:

- **JPEG** (`.jpg`, `.jpeg`) - Full EXIF metadata extraction
- **TIFF** (`.tiff`, `.tif`) - Full EXIF metadata extraction
- **PNG** (`.png`) - Basic metadata extraction
- **GIF** (`.gif`) - Basic metadata extraction
- **BMP** (`.bmp`) - Basic metadata extraction
- **WebP** (`.webp`) - Basic metadata extraction

## ProcessorType

When processing files, this preprocessor sets the `ProcessorType` field to `"image_metadata"`. This identifier allows validators to determine which preprocessor was used and make appropriate processing decisions.

## Usage

### Basic Usage

The preprocessor is automatically registered with the router system and doesn't require direct instantiation in most cases:

```go
// The preprocessor is automatically available through the router
// Files with supported extensions are automatically routed to this preprocessor
```

### Direct Usage

For direct usage or testing:

```go
import "ferret-scan/internal/preprocessors"

// Create a new image metadata preprocessor
processor := preprocessors.NewImageMetadataPreprocessor()

// Check if it can process a file
if processor.CanProcess("image.jpg") {
    // Process the file
    result, err := processor.Process("image.jpg")
    if err != nil {
        // Handle error
    }

    // Use the extracted metadata
    fmt.Printf("Extracted text: %s\n", result.Text)
    fmt.Printf("Processor type: %s\n", result.ProcessorType) // "image_metadata"
}
```

## Extracted Metadata

The preprocessor extracts various types of metadata depending on the image format:

### EXIF Data (JPEG/TIFF)
- Camera make and model
- Date and time taken
- GPS coordinates (if available)
- Camera settings (ISO, aperture, shutter speed)
- Image dimensions and orientation
- Software used to create/edit the image

### Basic Metadata (All Formats)
- File size and dimensions
- Color depth and format information
- Creation and modification dates
- Basic technical specifications

## Error Handling

The preprocessor implements comprehensive error handling for image-specific scenarios:

### Recoverable Errors
- **Missing EXIF data**: Gracefully degrades to basic metadata extraction
- **Corrupted EXIF headers**: Attempts to extract partial data
- **File access issues**: Implements retry logic with exponential backoff

### Non-Recoverable Errors
- **Unsupported image formats**: Returns appropriate error message
- **Severely corrupted files**: Fails with detailed error information
- **File size limits exceeded**: Respects configured resource limits

### Error Recovery Strategies
- **Retry**: Temporary file access issues, network problems
- **Graceful Degradation**: Extract available metadata when some data is corrupted
- **Skip**: Files that exceed size limits or are completely unreadable

## Resource Management

The preprocessor implements resource management to handle various image processing scenarios:

### File Size Limits
- Standard image files: 100MB limit (configurable)
- Automatic validation before processing
- Clear error messages for oversized files

### Timeout Handling
- Processing timeout: 30 seconds (configurable)
- Context-based cancellation for long operations
- Graceful cleanup on timeout

### Memory Management
- Efficient memory usage for large images
- Automatic cleanup after processing
- Memory limit enforcement

## Observability

The preprocessor provides comprehensive observability features:

### Debug Logging
When debug logging is enabled, the preprocessor logs:
- File characteristics (size, format, EXIF availability)
- Processing steps and timing information
- Error details and recovery attempts
- Resource usage statistics

### Performance Metrics
- Processing time per file
- Success/failure rates
- File size distribution
- Error type frequency

### Structured Logging
All logs follow a consistent JSON structure:
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "component": "image_metadata_preprocessor",
  "operation": "exif_extraction",
  "file_path": "/path/to/image.jpg",
  "file_size": 2048000,
  "processing_time_ms": 150,
  "success": true,
  "exif_available": true
}
```

## Integration with Validators

The `ProcessorType` field set to `"image_metadata"` allows validators to:
- Identify image-specific metadata content
- Apply image-specific validation rules
- Make processing decisions based on the source preprocessor
- Implement specialized handling for image metadata

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
- `meta-extract-exiflib`: EXIF data extraction from JPEG/TIFF files
- `observability`: Debug logging and metrics collection
- `shared_utilities`: Common file validation and formatting functions

## Testing

The preprocessor has comprehensive test coverage including:
- Unit tests for file type detection and processing
- Error handling scenario testing
- Resource limit enforcement testing
- Observability integration testing
- Performance and timeout testing

Test files are located at:
- `tests/unit/preprocessors/image_metadata_preprocessor_test.go`
- Integration tests in `tests/integration/specialized_preprocessors_*_test.go`

## Migration from MetadataPreprocessor

This preprocessor replaces the image processing functionality from the monolithic `MetadataPreprocessor`. The migration maintains full backward compatibility:

- Same `Preprocessor` interface implementation
- Identical `ProcessedContent` output format
- Same error handling behavior
- Preserved observability features

## Performance Characteristics

### Typical Processing Times
- Small images (< 1MB): 10-50ms
- Medium images (1-10MB): 50-200ms
- Large images (10-100MB): 200-1000ms

### Memory Usage
- Minimal memory footprint for metadata extraction
- No full image loading required for EXIF data
- Efficient cleanup after processing

## Limitations

- EXIF extraction only available for JPEG and TIFF formats
- Some proprietary camera formats may not be fully supported
- GPS coordinates require specific EXIF tags to be present
- Processing time increases with file size and metadata complexity
