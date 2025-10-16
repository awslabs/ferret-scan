# Video Metadata Extraction Library

This library provides native Go-based video metadata extraction capabilities for the Ferret Scan project.

## Supported Formats

- **MP4** - MPEG-4 container format with iTunes-style metadata
- **MOV** - QuickTime movie format with metadata atoms
- **M4V** - iTunes video format (MP4 variant)

## Features

- Native Go implementation using only standard library
- Extracts metadata from container atoms/boxes
- Handles GPS coordinates and location data
- Extracts device/camera information
- Parses creation dates and technical specifications
- Safe binary parsing with bounds checking

## Architecture

The library uses a container-based approach to parse video file structures:

1. **MP4Box** - Represents individual atoms/boxes in the container
2. **VideoMetadata** - Structured representation of extracted metadata
3. **Parser Functions** - Format-specific parsing logic

## Usage

```go
import "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-videolib"

// Extract metadata from MP4/MOV file
metadata, err := meta_extract_videolib.ExtractVideoMetadata(filePath)
if err != nil {
    return err
}

// Access extracted information
fmt.Printf("Title: %s\n", metadata.Title)
fmt.Printf("GPS: %f, %f\n", metadata.GPSLatitude, metadata.GPSLongitude)
```

## Implementation Details

### MP4 Container Structure

The library parses the following MP4 atoms for metadata:

- `moov.udta.meta.ilst` - iTunes-style metadata tags
- `moov.udta.©nam` - Title
- `moov.udta.©ART` - Artist/Author
- `moov.udta.©day` - Creation date
- `moov.udta.©xyz` - GPS coordinates
- `moov.mvhd` - Movie header (duration, creation time)

### Safety Features

- Bounds checking for all binary reads
- File size limits to prevent memory exhaustion
- Timeout handling for large files
- Graceful error handling for corrupted data

## License

This library uses only Go standard library components and is compatible with the project's licensing requirements.