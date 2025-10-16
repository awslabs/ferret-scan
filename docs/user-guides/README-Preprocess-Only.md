# Preprocess-Only Mode User Guide

[← Back to Documentation Index](../README.md)

## Overview

The preprocess-only mode (`--preprocess-only` or `-p`) allows you to extract and view preprocessed text content from various file types without performing any sensitive data validation. This is useful for:

- **Content Inspection**: Understanding what text will be analyzed during validation
- **Debugging**: Troubleshooting preprocessing issues with specific file types
- **Text Extraction**: Using Ferret Scan as a text extraction tool for documents
- **Integration Testing**: Verifying that files can be properly processed before validation

## Supported File Types

### Text Files
- **Plain Text**: `.txt`, `.md`, `.json`, `.yaml`, `.yml`, `.xml`, `.csv`
- **Code Files**: `.py`, `.js`, `.go`, `.java`, `.cpp`, `.c`, `.h`, etc.
- **Configuration Files**: `.conf`, `.ini`, `.cfg`, `.env`

### Document Files
- **PDF Documents**: `.pdf` (text extraction, not OCR)
- **Microsoft Office**: `.docx`, `.xlsx`, `.pptx`
- **OpenDocument**: `.odt`, `.ods`, `.odp`

### Image Files (Metadata Only)
- **JPEG Images**: `.jpg`, `.jpeg` (EXIF metadata extraction)
- **Other Formats**: `.png`, `.gif`, `.bmp`, `.tiff`, `.webp` (metadata when available)

### Audio Files (GenAI Required)
- **Audio Formats**: `.mp3`, `.wav`, `.m4a` (requires `--enable-genai` for transcription)

## Basic Usage

### Extract Text from a Single File

```bash
# Long form
ferret-scan --file document.pdf --preprocess-only

# Short form
ferret-scan --file document.pdf -p
```

### Extract Text from Multiple Files

```bash
# Process all files in a directory
ferret-scan --file documents/ --preprocess-only

# Process specific file types
ferret-scan --file "*.pdf" --preprocess-only

# Recursive processing
ferret-scan --file documents/ --recursive --preprocess-only
```

**Note**: Preprocessors are enabled by default (`--enable-preprocessors=true`). If you've disabled them with `--enable-preprocessors=false`, preprocess-only mode will not work since it requires preprocessors to extract content from files.

## Output Format

The preprocess-only mode outputs structured information for each file:

```
=== FILE: document.pdf ===
Processor: PDF Text Extractor
Status: Success
Content: 1,234 words, 7,890 characters, 5 pages

[Extracted text content appears here]

=== FILE: image.jpg ===
Processor: Metadata Extractor
Status: Success
Content: 15 words, 89 characters

Camera: Canon EOS 5D Mark IV
DateTime: 2024:01:15 14:30:22
GPS Latitude: 37.7749
GPS Longitude: -122.4194
```

### Summary Output (Multiple Files)

When processing multiple files, a summary is displayed:

```
=== SUMMARY ===
Files processed: 12
Files with errors: 2
```

## Advanced Usage

### Verbose Mode

Add `--verbose` to see additional processing details:

```bash
ferret-scan --file document.pdf --preprocess-only --verbose
```

### Debug Mode

Add `--debug` to see detailed preprocessing flow:

```bash
ferret-scan --file document.pdf --preprocess-only --debug
```

### Configuration Files

Use configuration files to customize preprocessing behavior:

```bash
ferret-scan --file document.pdf --preprocess-only --config ferret.yaml
```

Example configuration:
```yaml
defaults:
  enable_preprocessors: true

preprocessors:
  text_extraction:
    enabled: true
    max_file_size: 10485760  # 10MB
```

### Profile-Based Processing

Use profiles for different preprocessing scenarios:

```bash
ferret-scan --file documents/ --preprocess-only --config ferret.yaml --profile text-extraction
```

## Error Handling

### Common Error Messages

#### No Files to Preprocess
```
No files to preprocess
```
**Cause**: No supported files found in the specified path
**Solution**: Check file paths and ensure files have supported extensions

#### All Available Preprocessors Failed
```
=== FILE: corrupted.pdf ===
Status: Error - All available preprocessors failed to process this file
```
**Cause**: File is corrupted, encrypted, or in an unsupported format
**Solution**: Verify file integrity and format

#### Unsupported File Type
```
=== FILE: unknown.xyz ===
Status: Error - No suitable preprocessor found for this file type
```
**Cause**: File extension is not supported by any preprocessor
**Solution**: Use supported file types or convert the file

#### Permission Denied
```
=== FILE: restricted.pdf ===
Status: Error - Permission denied reading file
```
**Cause**: Insufficient file system permissions
**Solution**: Check file permissions and access rights

#### Preprocessors Disabled
```
Error: --preprocess-only requires preprocessors to be enabled
Remove --enable-preprocessors=false or use --enable-preprocessors=true
```
**Cause**: Preprocessors have been explicitly disabled with `--enable-preprocessors=false`
**Solution**: Remove the `--enable-preprocessors=false` flag or change it to `--enable-preprocessors=true` (which is the default)

### Empty Content Handling

Files with no extractable content are handled gracefully:

```
=== FILE: empty.pdf ===
Processor: PDF Text Extractor
Status: Success

[No text content found - PDF may contain only images or be empty]
```

## Integration with Other Tools

### Shell Scripting

```bash
#!/bin/bash
# Extract text from all PDFs in a directory
for file in *.pdf; do
    echo "Processing: $file"
    ferret-scan --file "$file" --preprocess-only --quiet
    echo "---"
done
```

### Pipeline Processing

```bash
# Extract text and pipe to other tools
ferret-scan --file document.pdf --preprocess-only | grep -i "confidential"

# Save extracted text to file
ferret-scan --file document.pdf --preprocess-only > extracted_text.txt
```

## Limitations

### What Preprocess-Only Mode Does NOT Do

- **No Validation**: Does not detect sensitive data patterns
- **No Redaction**: Does not redact or modify files
- **No OCR**: Does not perform optical character recognition on images (unless GenAI is enabled)
- **No Audio Transcription**: Does not transcribe audio files (unless GenAI is enabled)

### File Size Limits

- Default maximum file size: 10MB per file
- Configurable via configuration files
- Large files may require increased memory allocation

### Memory Considerations

- Text content is loaded into memory during processing
- Large documents may require significant memory
- Memory is automatically cleaned after processing

## Incompatible Flags

The following flags cannot be used with `--preprocess-only`:

- `--enable-redaction`: Redaction requires validation results
- `--output`: Preprocess-only outputs directly to stdout
- `--show-match`: No matches are generated in preprocess-only mode
- `--generate-suppressions`: No validation results to suppress
- `--suppression-file`: No validation performed
- `--show-suppressed`: No validation results to suppress

## Troubleshooting

### Performance Issues

If preprocessing is slow:
1. Check file sizes and reduce if necessary
2. Use `--debug` to identify bottlenecks
3. Process files individually to isolate issues

### Memory Issues

If you encounter out-of-memory errors:
1. Process files individually instead of in batches
2. Increase available memory for the process
3. Check for very large files that may need special handling

### Encoding Issues

If text appears garbled:
1. Ensure files are in supported character encodings (UTF-8 preferred)
2. Check if files are corrupted or encrypted
3. Try processing with `--debug` to see detailed error messages

## Examples by File Type

### PDF Documents
```bash
# Extract text from PDF
ferret-scan --file report.pdf --preprocess-only

# Process multiple PDFs
ferret-scan --file "*.pdf" --preprocess-only
```

### Office Documents
```bash
# Extract text from Word document
ferret-scan --file document.docx --preprocess-only

# Process Excel spreadsheet
ferret-scan --file data.xlsx --preprocess-only
```

### Image Metadata
```bash
# Extract EXIF data from photos
ferret-scan --file photo.jpg --preprocess-only

# Process all images in directory
ferret-scan --file photos/ --recursive --preprocess-only --checks METADATA
```

### Configuration Files
```bash
# Extract content from JSON config
ferret-scan --file config.json --preprocess-only

# Process YAML files
ferret-scan --file "*.yaml" --preprocess-only
```

## Best Practices

1. **Test with Single Files First**: Before processing large batches, test with individual files
2. **Use Appropriate Flags**: Combine with `--verbose` or `--debug` for troubleshooting
3. **Check File Permissions**: Ensure read access to all files before processing
4. **Monitor Memory Usage**: For large files or batches, monitor system memory
5. **Validate File Integrity**: Ensure files are not corrupted before processing

## Related Documentation

- [Configuration Guide](../configuration.md) - Setting up preprocessing options
- [Architecture Overview](../architecture-diagram.md) - Understanding the preprocessing pipeline
- [Testing Guide](../testing/TESTING.md) - Testing preprocessing functionality
- [Main README](../../README.md) - General usage and examples