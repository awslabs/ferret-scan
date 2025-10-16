# Ferret Scan Web UI

[← Back to Documentation Index](../README.md)

A simple web interface for the Ferret Scan sensitive data detection tool.

## Features

- **File Upload**: Upload single or multiple files directly through the web browser
- **Drag & Drop**: Drag files directly onto the upload area
- **Configurable Scans**: Choose confidence levels and specific detection types
- **Real-time Results**: View scan results immediately in a clean, organized format
- **Interactive Statistics**: Click stat cards to filter results by confidence level
- **Color-coded Results**: High, medium, and low confidence findings are visually distinguished
- **Sortable Tables**: Click column headers to sort results
- **Export Options**: Download results as CSV, JSON, YAML, JUnit, or Text
- **Suppression Management**: Create, edit, enable/disable, and bulk manage suppression rules
- **Detailed Metadata**: View additional information about detected sensitive data
- **Progress Tracking**: Real-time progress indicators during scanning
- **Help System**: Built-in documentation and feature explanations
<!-- GENAI_DISABLED: AI-Powered Features: OCR for images/PDFs, audio transcription, and AI PII detection -->

## Quick Start

1. **Build and Start the Web UI**:
   ```bash
   make build
   ./bin/ferret-scan --web --port 8080
   ```

2. **Open your browser** and navigate to:
   ```
   http://localhost:8080
   ```

3. **Upload a file** and configure your scan options, then click "Scan File"

## Manual Setup

If you prefer to run the components separately:

1. **Build the main Ferret binary**:
   ```bash
   make build
   ```

2. **Start the web server**:
   ```bash
   ./bin/ferret-scan --web --port 8080
   ```

## Configuration Options

### Confidence Levels
- **All Levels**: Show findings at all confidence levels
- **High Only**: Show only high-confidence findings (90-100%)
- **High & Medium**: Show high and medium confidence findings (60-100%)
- **Medium Only**: Show only medium-confidence findings (60-89%)
- **Low Only**: Show only low-confidence findings (0-59%)

### Check Types
- **All Checks**: Run all available validators
- **Credit Cards**: Detect credit card numbers with Luhn validation (15+ card brands)
- **Passport Numbers**: Multi-country formats (US, UK, Canada, EU, MRZ)
- **Social Security Numbers**: US SSN patterns with area validation
- **Email Addresses**: RFC-compliant validation with domain checks
- **Phone Numbers**: International and domestic formats
- **IP Addresses**: IPv4 and IPv6 address detection
- **Social Media**: Platform handles, profiles, and URLs
- **API Keys & Secrets**: API keys, tokens, credentials (40+ patterns)
- **Intellectual Property**: Patents, trademarks, copyrights, trade secrets
- **Metadata**: EXIF, GPS, document properties extraction
<!-- GENAI_DISABLED: AI PII Detection with Amazon Comprehend -->

## Supported File Types

The web UI supports the same file types as the CLI version:
- **Text files**: .txt, .log, .csv, .json, .xml, .yaml, .yml, .ini, .conf, .config, .cfg, .properties, .env
- **Documents**: PDF, Word (.docx), Excel (.xlsx), PowerPoint (.pptx), OpenDocument (.odt, .ods, .odp)
- **Images**: JPEG, PNG, GIF, BMP, TIFF, WebP (metadata extraction and OCR)
- **Audio**: MP3, WAV, M4A, FLAC, OGG <!-- GENAI_DISABLED: (transcription with AWS Transcribe) -->
- **Video**: MP4, MOV, AVI, MKV, WMV <!-- GENAI_DISABLED: (audio extraction and transcription) -->
- **Source Code**: Python, JavaScript, TypeScript, Java, C++, C, Go, Rust, and more

## Security Notes

- **Local Processing**: Files are processed locally on your machine - no data sent to external servers by default
- **Temporary Storage**: Files are temporarily stored during scanning and automatically deleted
- **Memory Scrubbing**: Secure memory handling for sensitive data
- **Upload Limits**: Maximum file upload size is 50MB
- **No Data Retention**: Scan results are displayed in browser only, not stored permanently
- **Audit Trail**: Comprehensive logging for compliance requirements
<!-- GENAI_DISABLED: When GenAI features are enabled, files may be sent to AWS services (Textract, Transcribe, Comprehend) -->

## Customization

To modify the web UI:

1. **Change the port**: Use the `--port` flag
   ```bash
   ./bin/ferret-scan --web --port 3000
   ```

2. **Modify the interface**: Edit `internal/web/server.go` to customize the web server or add new features

3. **Add new scan options**: Extend the form in the HTML template and update the scan handler

## Suppression Management

The web UI includes a comprehensive suppression management system:

### Features
- **View All Rules**: Browse all suppression rules with status indicators
- **Bulk Operations**: Select multiple rules for enable/disable/delete operations
- **Individual Actions**: Enable, disable, edit, or remove individual rules
- **Rule Creation**: Create new suppression rules from scan findings
- **Expiration Management**: Set expiration dates for temporary suppressions
- **Download/Upload**: Export and import suppression configurations
- **Undo Support**: Undo recent operations with one-click restore

### Usage
1. Click the **"Suppressions"** tab to access the management interface
2. Use checkboxes to select multiple rules for bulk operations
3. Click individual action buttons (enable/disable/edit/remove) for single rules
4. Create new rules by clicking "Suppress" on scan findings
5. Download your suppression configuration for backup or sharing

## Troubleshooting

**"ferret-scan binary not found" error**:
- Make sure you've built the project with `make build`
- The web UI is integrated into the main `./bin/ferret-scan` binary

**File upload fails**:
- Check that the file is under 50MB
- Ensure the file type is supported by Ferret Scan
- Try uploading files one at a time if multiple uploads fail

**Scan takes too long**:
- Large files or complex documents may take longer to process
- The web UI has reasonable timeouts for scan operations
- Consider using confidence filtering to speed up scans

**Documentation not loading**:
- Ensure the `docs/` directory is present alongside the web binary
- Check that all referenced documentation files exist

**Logo not displaying**:
- Verify `docs/images/ferret-scan-logo.png` exists
- Check file permissions on the docs directory
