# Ferret Scan Preprocessors

Preprocessors extract content from various file types before validation. This enables scanning of binary files like PDFs, Office documents, images, audio, and video files.

## Architecture

The preprocessor system uses a **specialized architecture** where each file type has its own dedicated preprocessor:

- **ImageMetadataPreprocessor**: Handles image files (.jpg, .jpeg, .tiff, .tif, .png, .gif, .bmp, .webp)
- **PDFMetadataPreprocessor**: Handles PDF documents (.pdf)
- **OfficeMetadataPreprocessor**: Handles Office documents (.docx, .xlsx, .pptx, .odt, .ods, .odp)
- **AudioMetadataPreprocessor**: Handles audio files (.mp3, .flac, .wav, .m4a)
- **VideoMetadataPreprocessor**: Handles video files (.mp4, .m4v, .mov)
- **TextPreprocessor**: Extracts document body text (.pdf, Office, ODF) and SVG prose (.svg)

## Features

- **Specialized Metadata Extraction**: Dedicated preprocessors for each file type
- **ProcessorType Identification**: Each preprocessor sets a unique ProcessorType for validator decision-making
- **Modular Design**: Each preprocessor can be enabled/disabled independently
- **Single Responsibility**: Each preprocessor focuses on one file type for better maintainability
- **Automatic Registration**: All preprocessors are automatically registered through the router system
- **Backward Compatibility**: Maintains identical behavior to the previous monolithic system

## Supported File Types

### Images
- **Extensions**: .jpg, .jpeg, .tiff, .tif, .png, .gif, .bmp, .webp
- **ProcessorType**: `image_metadata`
- **Extracts**: EXIF data, camera information, GPS coordinates, creation dates

### PDF Documents
- **Extensions**: .pdf
- **ProcessorType**: `pdf_metadata`
- **Extracts**: Document metadata, author information, creation/modification dates, embedded media

### Office Documents
- **Extensions**: .docx, .xlsx, .pptx, .odt, .ods, .odp
- **ProcessorType**: `office_metadata`
- **Extracts**: Document properties, author information, embedded media, revision history

### Vector Graphics
- **Extensions**: .svg
- **ProcessorType**: `Text Extractor`
- **Extracts**: `<text>`, `<tspan>`, `<textPath>`, `<title>`, `<desc>`, `<metadata>`,
  Inkscape flowed text, the `<foreignObject>` subtree, XML comments, and the prose-bearing
  attributes (`aria-label`, `alt`, `title`, `inkscape:label`, ...)
- **Never extracts**: `d`, `points`, `transform`, `viewBox`, `href`, `<style>`, `<script>`,
  or any other geometry, presentation or script content

An SVG is claimed by NAME here so the plaintext preprocessor cannot claim it on a byte
sniff. That matters because the router runs every claiming preprocessor and concatenates
the successes: handing the raw drawing to the validators measured 1,313 findings, 1,143 of
them PHONE, on a 64KB drawing of integer-coordinate glyph paths.

### Audio Files
- **Extensions**: .mp3, .flac, .wav, .m4a
- **ProcessorType**: `audio_metadata`
- **Extracts**: ID3 tags, artist information, album details, duration, bitrate

### Video Files
- **Extensions**: .mp4, .m4v, .mov
- **ProcessorType**: `video_metadata`
- **Extracts**: Video metadata, codec information, duration, resolution, creation dates

## Usage

Preprocessors are automatically used by the Ferret Scan system when processing files. No manual configuration is required.

### Command Line Usage

```bash
# Process a file with metadata extraction
ferret-scan --file document.pdf

# Process with preprocessing only (no validation)
ferret-scan --file image.jpg --preprocess-only

# Process with debug information
ferret-scan --file audio.mp3 --debug
```

### Programmatic Usage

```go
// Preprocessors are automatically registered
router := router.NewFileRouter(true)
router.RegisterDefaultPreprocessors(router)

// Process a file
result, err := router.ProcessFile("example.jpg")
if err != nil {
    log.Fatal(err)
}

// Check which preprocessor was used
fmt.Printf("Processed by: %s\n", result.ProcessorType)
```

### Extract text from PDF documents

```bash
go run pdftext.go /path/to/document.pdf
```

## Individual Preprocessor Documentation

Each specialized preprocessor has its own detailed documentation:

- [ImageMetadataPreprocessor README](image_metadata_preprocessor_README.md)
- [PDFMetadataPreprocessor README](pdf_metadata_preprocessor_README.md)
- [OfficeMetadataPreprocessor README](office_metadata_preprocessor_README.md)
- [AudioMetadataPreprocessor README](audio_metadata_preprocessor_README.md)
- [VideoMetadataPreprocessor README](video_metadata_preprocessor_README.md)

## Supported File Types

### Images (Metadata)

- JPEG (.jpg, .jpeg) - EXIF metadata
- TIFF (.tif, .tiff) - EXIF metadata
- PNG (.png) - Basic metadata
- GIF (.gif) - Basic metadata
- BMP (.bmp) - Basic metadata
- WEBP (.webp) - Basic metadata

### PDF Documents (Metadata + Text)

- PDF (.pdf) - Document metadata + text extraction

### Vector Graphics (Prose Text Only)

- SVG (.svg) - text/tspan/title/desc/metadata nodes and prose attributes; never geometry

### Office Documents (Metadata + Text)

- Microsoft Word (.docx) - Document properties + text content
- Microsoft Excel (.xlsx) - Document properties + text content
- Microsoft PowerPoint (.pptx) - Document properties + text content
- OpenDocument Text (.odt) - Document properties + text content
- OpenDocument Spreadsheet (.ods) - Document properties + text content
- OpenDocument Presentation (.odp) - Document properties + text content

## Preprocessor Architecture

The preprocessing system is organized into specialized, modular components following the single responsibility principle:

### Core Components
- **Router System**: Automatically routes files to appropriate specialized preprocessors
- **Preprocessor Interface**: Common interface implemented by all preprocessors
- **ProcessedContent**: Standardized output format with ProcessorType identification
- **Shared Utilities**: Common error handling, resource management, and observability

### Specialized Metadata Preprocessors
Each specialized preprocessor handles one file type:
- **ImageMetadataPreprocessor**: Image files (JPEG, PNG, TIFF, etc.)
- **PDFMetadataPreprocessor**: PDF documents
- **OfficeMetadataPreprocessor**: Office documents (DOCX, XLSX, PPTX, etc.)
- **AudioMetadataPreprocessor**: Audio files (MP3, FLAC, WAV, M4A)
- **VideoMetadataPreprocessor**: Video files (MP4, M4V, MOV)

### Metadata Extraction Libraries
- **meta-extract-exiflib**: EXIF metadata from images
- **meta-extract-pdflib**: Metadata from PDF documents
- **meta-extract-officelib**: Metadata from Office documents
- **meta-extract-audiolib**: Metadata from audio files
- **meta-extract-videolib**: Metadata from video files

### Text Extractors
- **text-extract-pdftextlib**: Text from PDF documents
- **text-extract-officetextlib**: Text from Office documents

### ProcessorType Identification
Each specialized preprocessor sets a unique ProcessorType value:
- `"image_metadata"` - ImageMetadataPreprocessor
- `"pdf_metadata"` - PDFMetadataPreprocessor
- `"office_metadata"` - OfficeMetadataPreprocessor
- `"audio_metadata"` - AudioMetadataPreprocessor
- `"video_metadata"` - VideoMetadataPreprocessor

This allows validators to identify which preprocessor was used and make appropriate processing decisions.

### Integration
Each preprocessor can be enabled/disabled independently and integrates seamlessly with the validation pipeline. The router system automatically selects the appropriate preprocessor based on file extension.

## ProcessorType Usage for Validator Selection

The ProcessorType field in ProcessedContent allows validators to make informed decisions based on the preprocessing method used:

### Validator Integration
```go
// Example validator logic using ProcessorType
func (v *MyValidator) Validate(content *ProcessedContent) ([]Match, error) {
    switch content.ProcessorType {
    case "image_metadata":
        // Apply image-specific validation rules
        return v.validateImageMetadata(content)
    case "pdf_metadata":
        // Apply PDF-specific validation rules
        return v.validatePDFMetadata(content)
    case "office_metadata":
        // Apply Office document-specific validation rules
        return v.validateOfficeMetadata(content)
    case "audio_metadata":
        // Apply audio-specific validation rules
        return v.validateAudioMetadata(content)
    case "video_metadata":
        // Apply video-specific validation rules
        return v.validateVideoMetadata(content)
    default:
        // Apply generic validation rules
        return v.validateGeneric(content)
    }
}
```

### Benefits for Validators
- **Specialized Rules**: Apply file-type-specific validation logic
- **Confidence Scoring**: Adjust confidence based on metadata source
- **Error Handling**: Handle file-type-specific validation errors
- **Performance**: Skip irrelevant validations for certain file types

## Dependencies

This project uses minimal external dependencies:

- Standard Go libraries for most functionality
- `github.com/ledongthuc/pdf` for PDF text extraction

## Limitations

- EXIF extraction only works with images that contain EXIF data
- PDF text extraction may not work with all PDF formats
- Office document extraction works best with newer formats (DOCX, XLSX, PPTX)
- Text formatting and layout are not preserved

## License

This project is licensed under the MIT License - see the LICENSE file for details.
