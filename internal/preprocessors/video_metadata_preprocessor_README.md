# VideoMetadataPreprocessor

The VideoMetadataPreprocessor is a specialized preprocessor that extracts metadata from video files. It's part of the refactored metadata preprocessing system that replaced the monolithic MetadataPreprocessor.

## Overview

This preprocessor focuses exclusively on video file metadata extraction, providing:
- Video container and stream metadata extraction
- Technical video information (resolution, codec, frame rate, duration)
- Comprehensive error handling for video-specific scenarios
- Resource management with video-specific limits
- Timeout handling for large video files
- Observability and debug logging

## Supported File Types

The VideoMetadataPreprocessor supports the following video formats:

- **MP4** (`.mp4`) - Container metadata, video/audio stream information
- **M4V** (`.m4v`) - iTunes video metadata, technical information
- **MOV** (`.mov`) - QuickTime metadata, technical specifications

## ProcessorType

When processing files, this preprocessor sets the `ProcessorType` field to `"video_metadata"`. This identifier allows validators to determine which preprocessor was used and make appropriate processing decisions.

## Usage

### Basic Usage

The preprocessor is automatically registered with the router system and doesn't require direct instantiation in most cases:

```go
// The preprocessor is automatically available through the router
// Video files are automatically routed to this preprocessor
```

### Direct Usage

For direct usage or testing:

```go
import "ferret-scan/internal/preprocessors"

// Create a new video metadata preprocessor
processor := preprocessors.NewVideoMetadataPreprocessor()

// Check if it can process a file
if processor.CanProcess("movie.mp4") {
    // Process the file
    result, err := processor.Process("movie.mp4")
    if err != nil {
        // Handle error
    }

    // Use the extracted metadata
    fmt.Printf("Extracted text: %s\n", result.Text)
    fmt.Printf("Processor type: %s\n", result.ProcessorType) // "video_metadata"
}
```

## Extracted Metadata

The preprocessor extracts comprehensive metadata from video files:

### Video Information
- Title, Description, Genre
- Director, Producer, Cast information
- Release date and copyright
- Language and subtitle information

### Technical Information
- Duration (length in seconds)
- Video resolution (width x height)
- Frame rate and aspect ratio
- Video codec and compression format

### Audio Information
- Audio codec and bitrate
- Sample rate and channels
- Audio language tracks
- Audio quality information

### Container Information
- File format and container type
- Creation and modification dates
- Encoding software and settings
- File size and quality metrics

### Format-Specific Metadata

#### MP4 Files
- MPEG-4 container metadata
- H.264/H.265 video stream information
- AAC/MP3 audio stream details
- Chapter and subtitle information

#### M4V Files
- iTunes-style video metadata
- DRM and protection information
- Artwork and thumbnail data
- Purchase and rental information

#### MOV Files
- QuickTime container metadata
- Apple-specific video information
- Professional video metadata
- Timecode and sync information

## Error Handling

The preprocessor implements comprehensive error handling for video-specific scenarios:

### Recoverable Errors
- **Missing metadata**: Extracts available technical information
- **Corrupted video headers**: Attempts to extract partial metadata
- **Unsupported codec information**: Falls back to container metadata

### Non-Recoverable Errors
- **Severely corrupted files**: Fails with detailed error information
- **File size limits exceeded**: Respects configured resource limits
- **Unsupported video formats**: Returns appropriate error message

### Error Recovery Strategies
- **Retry**: Temporary file access issues, network problems
- **Graceful Degradation**: Extract available metadata when some data is corrupted
- **Skip**: Files that exceed size limits or are completely unreadable

## Resource Management

The preprocessor implements video-specific resource management:

### File Size Limits
- Video files: 1GB limit (highest among all media types)
- Large file handling with streaming
- Automatic validation before processing

### Timeout Handling
- Processing timeout: 180 seconds (longest for large video files)
- Context-based cancellation for long operations
- Graceful cleanup on timeout

### Memory Management
- Efficient memory usage for large video files
- Streaming processing for oversized files
- Automatic cleanup after processing

## Observability

The preprocessor provides comprehensive observability features:

### Debug Logging
When debug logging is enabled, the preprocessor logs:
- Video characteristics (format, duration, resolution, codec information)
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
  "component": "video_metadata_preprocessor",
  "operation": "metadata_extraction",
  "file_path": "/path/to/movie.mp4",
  "file_size": 1073741824,
  "duration_seconds": 7200,
  "resolution": "1920x1080",
  "processing_time_ms": 2500,
  "success": true,
  "format": "mp4",
  "video_codec": "h264",
  "audio_codec": "aac"
}
```

## Integration with Validators

The `ProcessorType` field set to `"video_metadata"` allows validators to:
- Identify video-specific metadata content
- Apply video-specific validation rules
- Make processing decisions based on the source preprocessor
- Implement specialized handling for video metadata

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
- `meta-extract-videolib`: Video metadata extraction library
- `observability`: Debug logging and metrics collection
- `shared_utilities`: Common file validation and formatting functions

## Testing

The preprocessor has comprehensive test coverage including:
- Unit tests for video file processing and metadata extraction
- Error handling scenario testing (corrupted files, missing metadata)
- Resource limit enforcement testing
- Timeout handling for large files
- Observability integration testing

Test files are located at:
- `tests/unit/preprocessors/video_metadata_preprocessor_test.go`
- Integration tests in `tests/integration/specialized_preprocessors_*_test.go`

## Migration from MetadataPreprocessor

This preprocessor replaces the video processing functionality from the monolithic `MetadataPreprocessor`. The migration maintains full backward compatibility:

- Same `Preprocessor` interface implementation
- Identical `ProcessedContent` output format
- Same error handling behavior
- Preserved observability features

## Performance Characteristics

### Typical Processing Times
- Small video files (< 100MB): 200-800ms
- Medium video files (100MB-1GB): 800-3000ms
- Large video files (1GB+): 3000-10000ms

### Memory Usage
- Minimal memory footprint for metadata extraction
- No full video loading required
- Efficient cleanup after processing

## Special Considerations

### Large Video Files
- Highest file size limits among all media types
- Extended timeout handling for processing
- Streaming metadata extraction

### Multiple Streams
- Handles multiple video and audio streams
- Extracts metadata from all available streams
- Comprehensive codec and format information

### Professional Video Formats
- Support for professional video metadata
- Timecode and synchronization information
- Advanced technical specifications

## Limitations

- Cannot extract metadata from severely corrupted video files
- Some proprietary video formats may not be fully supported
- Embedded subtitles and complex metadata may not be fully extracted
- Processing time increases significantly with file size
- Very large files (>1GB) may hit timeout limits despite extended timeouts
- Some custom or non-standard metadata formats may not be recognized
- DRM-protected content may have limited metadata availability
