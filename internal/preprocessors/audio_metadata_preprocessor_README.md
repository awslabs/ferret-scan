# AudioMetadataPreprocessor

The AudioMetadataPreprocessor is a specialized preprocessor that extracts metadata from audio files. It's part of the refactored metadata preprocessing system that replaced the monolithic MetadataPreprocessor.

## Overview

This preprocessor focuses exclusively on audio file metadata extraction, providing:
- ID3 tags and audio metadata extraction
- Technical audio information (bitrate, sample rate, duration)
- Comprehensive error handling for audio-specific scenarios
- Resource management with audio-specific limits
- Timeout handling for large audio files
- Observability and debug logging

## Supported File Types

The AudioMetadataPreprocessor supports the following audio formats:

- **MP3** (`.mp3`) - ID3v1, ID3v2 tags, technical metadata
- **FLAC** (`.flac`) - Vorbis comments, technical metadata
- **WAV** (`.wav`) - Basic metadata, technical information
- **M4A** (`.m4a`) - iTunes metadata, technical information

## ProcessorType

When processing files, this preprocessor sets the `ProcessorType` field to `"audio_metadata"`. This identifier allows validators to determine which preprocessor was used and make appropriate processing decisions.

## Usage

### Basic Usage

The preprocessor is automatically registered with the router system and doesn't require direct instantiation in most cases:

```go
// The preprocessor is automatically available through the router
// Audio files are automatically routed to this preprocessor
```

### Direct Usage

For direct usage or testing:

```go
import "ferret-scan/internal/preprocessors"

// Create a new audio metadata preprocessor
processor := preprocessors.NewAudioMetadataPreprocessor()

// Check if it can process a file
if processor.CanProcess("song.mp3") {
    // Process the file
    result, err := processor.Process("song.mp3")
    if err != nil {
        // Handle error
    }
    
    // Use the extracted metadata
    fmt.Printf("Extracted text: %s\n", result.Text)
    fmt.Printf("Processor type: %s\n", result.ProcessorType) // "audio_metadata"
}
```

## Extracted Metadata

The preprocessor extracts comprehensive metadata from audio files:

### Music Information
- Title, Artist, Album, Genre
- Track number and total tracks
- Year/Date of release
- Album artist and composer

### Technical Information
- Duration (length in seconds)
- Bitrate and sample rate
- Audio codec and format
- File size and quality information

### Additional Metadata
- Comments and lyrics
- Copyright and publisher information
- Encoding software and settings
- Custom tags and extended metadata

### Format-Specific Metadata

#### MP3 Files
- ID3v1 and ID3v2 tag support
- Frame-specific information
- Encoding quality and VBR information

#### FLAC Files
- Vorbis comment extraction
- Lossless compression information
- Technical stream details

#### WAV Files
- Basic file information
- Embedded metadata chunks
- Technical audio specifications

#### M4A Files
- iTunes-style metadata
- AAC encoding information
- Chapter and artwork metadata

## Error Handling

The preprocessor implements comprehensive error handling for audio-specific scenarios:

### Recoverable Errors
- **Missing metadata tags**: Extracts available technical information
- **Corrupted audio headers**: Attempts to extract partial metadata
- **Unsupported tag versions**: Falls back to supported formats

### Non-Recoverable Errors
- **Severely corrupted files**: Fails with detailed error information
- **File size limits exceeded**: Respects configured resource limits
- **Unsupported audio formats**: Returns appropriate error message

### Error Recovery Strategies
- **Retry**: Temporary file access issues, network problems
- **Graceful Degradation**: Extract available metadata when some data is corrupted
- **Skip**: Files that exceed size limits or are completely unreadable

## Resource Management

The preprocessor implements audio-specific resource management:

### File Size Limits
- Audio files: 500MB limit (higher than other media types)
- Large file handling with streaming
- Automatic validation before processing

### Timeout Handling
- Processing timeout: 120 seconds (longer for large audio files)
- Context-based cancellation for long operations
- Graceful cleanup on timeout

### Memory Management
- Efficient memory usage for large audio files
- Streaming processing for oversized files
- Automatic cleanup after processing

## Observability

The preprocessor provides comprehensive observability features:

### Debug Logging
When debug logging is enabled, the preprocessor logs:
- Audio characteristics (format, duration, bitrate, metadata richness)
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
  "component": "audio_metadata_preprocessor",
  "operation": "metadata_extraction",
  "file_path": "/path/to/song.mp3",
  "file_size": 8388608,
  "duration_seconds": 240,
  "bitrate": 320,
  "processing_time_ms": 180,
  "success": true,
  "format": "mp3",
  "has_id3_tags": true
}
```

## Integration with Validators

The `ProcessorType` field set to `"audio_metadata"` allows validators to:
- Identify audio-specific metadata content
- Apply audio-specific validation rules
- Make processing decisions based on the source preprocessor
- Implement specialized handling for audio metadata

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
- `meta-extract-audiolib`: Audio metadata extraction library
- `observability`: Debug logging and metrics collection
- `shared_utilities`: Common file validation and formatting functions

## Testing

The preprocessor has comprehensive test coverage including:
- Unit tests for audio file processing and metadata extraction
- Error handling scenario testing (corrupted files, missing tags)
- Resource limit enforcement testing
- Timeout handling for large files
- Observability integration testing

Test files are located at:
- `tests/unit/preprocessors/audio_metadata_preprocessor_test.go`
- Integration tests in `tests/integration/specialized_preprocessors_*_test.go`

## Migration from MetadataPreprocessor

This preprocessor replaces the audio processing functionality from the monolithic `MetadataPreprocessor`. The migration maintains full backward compatibility:

- Same `Preprocessor` interface implementation
- Identical `ProcessedContent` output format
- Same error handling behavior
- Preserved observability features

## Performance Characteristics

### Typical Processing Times
- Small audio files (< 10MB): 50-200ms
- Medium audio files (10-100MB): 200-800ms
- Large audio files (100-500MB): 800-3000ms

### Memory Usage
- Minimal memory footprint for metadata extraction
- No full audio loading required
- Efficient cleanup after processing

## Special Considerations

### Large Audio Files
- Higher file size limits compared to other media types
- Extended timeout handling for processing
- Streaming metadata extraction

### Format Variations
- Different metadata standards across formats
- Graceful handling of format-specific features
- Comprehensive tag extraction across all supported formats

### Encoding Quality
- Metadata extraction independent of audio quality
- Support for both lossy and lossless formats
- Technical information extraction regardless of encoding

## Limitations

- Cannot extract metadata from severely corrupted audio files
- Some proprietary audio formats may not be fully supported
- Embedded artwork and large binary data are not extracted as text
- Processing time increases significantly with file size
- Very large files (>500MB) are rejected to prevent resource exhaustion
- Some custom or non-standard tag formats may not be recognized