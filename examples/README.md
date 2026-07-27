# Ferret Scan Examples

This directory contains standalone examples demonstrating how to use individual components of Ferret Scan.

## Validators

**Note**: These examples use build tags to avoid conflicts with the main ferret-scan executable. Use the `-tags examples` flag when running:

```bash
cd examples/validators
go run -tags examples creditcard-example.go sample.txt
go run -tags examples passport-example.go sample.txt
go run -tags examples ssn-example.go sample.txt
go run -tags examples metadata-example.go document.pdf
go run -tags examples intellectualproperty-example.go sample.txt
```

## Text Extractors

```bash
cd examples/preprocessors/text-extractors
go run -tags examples office-text-example.go document.docx
go run -tags examples pdf-text-example.go document.pdf
```

## Preprocess-Only Mode Examples

The preprocess-only mode allows you to extract text content without performing validation:

```bash
# Extract text from a PDF document
ferret-scan --file document.pdf --preprocess-only

# Extract text using short form flag
ferret-scan --file document.docx -p

# Extract text from multiple files with verbose output
ferret-scan --file documents/ --recursive --preprocess-only --verbose

# Extract EXIF metadata from images (automatically processed for metadata)
ferret-scan --file photo.jpg --preprocess-only

# Note: Plain text files (.txt, .py, .js, etc.) are automatically skipped during metadata validation
# for improved performance, but can still be processed with --preprocess-only

# Extract text with configuration file
ferret-scan --file document.pdf --preprocess-only --config ferret.yaml

# Extract text with debug information
ferret-scan --file document.pdf --preprocess-only --debug
```

For detailed information about preprocess-only mode, see the [Preprocess-Only User Guide](../docs/user-guides/README-Preprocess-Only.md).

## Metadata Extractors

```bash
cd examples/preprocessors/meta-extractors
go run -tags examples exif-example.go image.jpg
go run -tags examples office-meta-example.go document.docx
go run -tags examples pdf-meta-example.go document.pdf
```
