# Audio Metadata Extraction Library

This package provides native Go implementations for extracting metadata from audio files without external dependencies.

## Supported Formats

- **MP3**: ID3v1 and ID3v2 tag parsing
- **FLAC**: Vorbis comments and metadata blocks
- **WAV**: INFO chunk metadata

## Features

- Native Go implementation using only standard library
- Support for common audio metadata fields
- Graceful error handling for corrupted files
- Memory-efficient parsing for large files

## Usage

```go
extractor := &MP3Extractor{}
metadata, err := extractor.ExtractMetadata("audio.mp3")
if err != nil {
    log.Printf("Failed to extract metadata: %v", err)
    return
}

fmt.Printf("Title: %s\n", metadata.Title)
fmt.Printf("Artist: %s\n", metadata.Artist)
```

## Implementation Details

The library focuses on extracting text-based metadata while skipping binary data like embedded artwork to maintain performance and security.
