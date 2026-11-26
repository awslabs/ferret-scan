# Ferret Scan Web UI

[← Back to Documentation Index](../README.md)

A simple web interface for the Ferret Scan sensitive data detection tool.

## Features

- **File Upload**: Upload single or multiple files directly through the web browser
- **Folder Upload**: Drag-and-drop a folder onto the upload zone, or click "Choose Folder" — the browser walks the directory client-side and uploads every file with its relative path. Configured `--exclude` patterns are applied during the walk so excluded directories (`.git`, `node_modules`, etc.) are never uploaded.
- **Drag & Drop**: Drag files or folders directly onto the upload area
- **CLI-Equivalent Flags**: `--web` honors `--config`, `--suppression-file`, `--exclude`, `--profile`, `--disable-ip-types`, `--validator-budget` and `--debug` so the server scans the way the CLI does (see [Scan flags with `--web`](#scan-flags-with---web))
- **Configurable Scans**: Choose confidence levels and specific detection types
- **Real-time Results**: View scan results immediately in a clean, organized format
- **Interactive Statistics**: Click stat cards to filter results by confidence level
- **Color-coded Results**: High, medium, and low confidence findings are visually distinguished
- **Sortable Tables**: Click column headers to sort results
- **Export Options**: Download results as CSV, JSON, YAML, JUnit, or Text
- **Suppression Management**: Create, edit, enable/disable, and bulk manage suppression rules — including bulk "Make Permanent" / "Renew 30 Days" expiration actions
- **Cached Suppression Manager**: Web server caches the parsed suppressions file in memory and reloads only when the file's mtime changes, so per-request latency does not depend on rule-set size
- **Detailed Metadata**: View additional information about detected sensitive data
- **Progress Tracking**: Real-time progress indicators during scanning
- **Help System**: Built-in documentation and feature explanations

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
- **Cloud Resources**: Cloud resource identifiers (AWS ARNs incl. GovCloud/China, Azure resource IDs, GCP resource names, OCI OCIDs, IBM CRNs, Alibaba ARNs)
- **Metadata**: EXIF, GPS, document properties extraction

## Supported File Types

The web UI supports the same file types as the CLI version:
- **Text files**: .txt, .log, .csv, .json, .xml, .yaml, .yml, .ini, .conf, .config, .cfg, .properties, .env
- **Documents**: PDF, Word (.docx, .docm), Excel (.xlsx, .xlsm), PowerPoint (.pptx, .pptm), OpenDocument (.odt, .ods, .odp) and its templates (.ott, .ots, .otp)
- **Images**: JPEG, PNG, GIF, BMP, TIFF, WebP (metadata extraction)
- **Audio**: MP3, WAV, M4A, FLAC, OGG (metadata extraction)
- **Video**: MP4, MOV, AVI, MKV, WMV (metadata extraction)
- **Source Code**: Python, JavaScript, TypeScript, Java, C++, C, Go, Rust, and more

## Security Notes

- **Local Processing**: Files are processed locally on your machine - no data is sent to external servers
- **Temporary Storage**: Files are temporarily stored during scanning and automatically deleted
- **Memory Scrubbing**: Secure memory handling for sensitive data
- **Upload Limits**: Maximum file upload size is 100 MB per file (decompression-bomb guard).
  A file over the limit is **refused and reported**, not truncated: the response carries
  `incomplete: true` with `file too large to scan` as the reason, so a partial scan is never
  presented as a complete one. Request bodies on the JSON endpoints (`/export`,
  `/suppressions/*`) are capped at 1 MB.

  This is **stricter than the CLI for video**, which admits `.mp4` `.m4v` `.mov` `.3gp` `.3g2`
  up to 500 MB. The difference is deliberate: the CLI reads a file the operator already has,
  and for a video that read is bounded and seeking, whereas an upload is *copied into a temp
  file* before anything reads it — so the larger allowance would let one request write 500 MB
  of temp disk, chosen by the filename it supplied. To scan a video between 100 MB and 500 MB,
  use the CLI: `ferret-scan --file clip.mov`.
- **Session Cookie**: `/scan` sets `ferret_scan_session` (`HttpOnly`, `SameSite=Strict`), which
  scopes stored results to your browser session so `/export` can format the scan the server ran.
  It is marked `Secure` when the request arrived over HTTPS (a TLS connection, or a reverse proxy
  that sends `X-Forwarded-Proto: https`) and left unmarked over plain HTTP, so the documented
  `http://localhost` path works in every browser; Safari refuses a `Secure` cookie there.
- **No Data Retention**: Scan results are displayed in browser only, not stored permanently
- **Audit Trail**: Comprehensive logging for compliance requirements

## Exporting a scan from a script

`/scan` returns a `scan_id` (32 hex characters) beside `results`, and keeps the scan's findings on the server
for one hour, under the `ferret_scan_session` cookie it set. `/export` formats those stored findings, so it takes
the id, not the findings:

```bash
curl -s -c jar --form "files=@report.txt" --form "confidence=all" http://127.0.0.1:8080/scan -o scan.json
ID=$(python3 -c "import json; print(json.load(open('scan.json'))['scan_id'])")
curl -s -b jar -H 'Content-Type: application/json' \
  -d "{\"format\":\"sarif\",\"scan_ids\":[\"$ID\"]}" http://127.0.0.1:8080/export -o report.sarif
```

- The body is `{"format": …, "scan_ids": […], "show_match": false, "verbose": false}`; `format` is any of the
  CLI's seven. Several ids are merged into one report when the scans ran with the same confidence and checks,
  and refused (400) when they did not.
- A body that still carries `results` and no `scan_ids` is refused with 400: the server no longer formats
  findings a client posts back, because that copy lost the explanation, the context keywords and the typed
  metadata, and a few hundred findings overran the 1 MiB request cap. An id sent without its session cookie, after
  it expired or after the store evicted it, answers 404: scan again.
- The report is the CLI's formatter over the findings the scan produced, so the finding rows match what the CLI
  prints for the same file. It also carries the CLI's `scan` scope block (present when the run was narrowed by
  `checks`, the confidence filter or disabled detection types) and the `stats` block the `/scan` run kept: files
  considered, processed, skipped and not examined, findings by band, suppressed count and the scan's duration.
  Exporting several ids adds their stats. The web counts a file with an empty text extraction as processed, where
  the CLI reports it as not examined.

## Customization

To modify the web UI:

1. **Change the port**: Use the `--port` flag
   ```bash
   ./bin/ferret-scan --web --port 3000
   ```

2. **Use a custom config / suppressions file**: Web mode honors the same flags as the CLI
   ```bash
   ./bin/ferret-scan --web --port 8080 \
     --config ./team-config.yaml \
     --suppression-file ./team-suppressions.yaml
   ```

3. **Configure folder-walk excludes**: `--exclude` patterns are surfaced to the front-end via `/config-info` and applied during folder drag-drop walks, so excluded directories never get uploaded
   ```bash
   ./bin/ferret-scan --web --port 8080 \
     --exclude '.git,node_modules,dist,target,__pycache__'
   ```

4. **Scan under a profile, without some IP sub-types, with a validator budget, or with debug logging**: see [Scan flags with `--web`](#scan-flags-with---web)

5. **Modify the interface**: Edit `internal/web/server.go` to customize the web server or add new features

6. **Add new scan options**: Extend the form in the HTML template and update the scan handler

## Scan flags with `--web`

Every CLI flag has a recorded web decision (`internal/web/surface_inventory_test.go`). The ones that
shape a scan:

| Flag | With `--web` |
|---|---|
| `--profile NAME` | Applied to every scan. The profile's `checks`, `confidence_levels`, `verbose`, `recursive` and `enable_preprocessors` sit between the config file and the form (a form field still wins), and its validator settings apply. An unknown name refuses to start: `refusing to start: Profile 'NAME' not found in config file`. |
| `--disable-ip-types t1,t2` | Applied to every scan, after the config and the profile, as on `--file`. |
| `--validator-budget NAME=DUR` | Applied to every scan. A validator that exceeds its budget makes that scan `incomplete`, as on `--file`. |
| `--debug` | Every scan runs with the debug observer, which writes to the **server's** stderr (the server log), never to the page or the `/scan` response. The log names the server-side temporary path of each upload and the validators' working notes; keep it as private as the scan itself. |
| `--respect-gitignore` | Refused at startup. An upload has no directory tree for `.gitignore` to apply to; use `--exclude` to skip paths in a dropped folder. |
| `--limit` | Refused at startup. The page shows every finding; `--limit` caps the CLI's printed report. |
| `--list-profiles` | Refused at startup. It prints the profiles and exits; use `--web --profile NAME` to scan under one. |
| `--check-config` | Refused at startup. It reports the CLI's configuration and exits; run `--check-config --config PATH` without `--web` to check the file you would start the server with. |
| `--max-live-bytes` | Refused at startup. Concurrent `/scan` requests are not admitted against a shared byte budget, so there is nothing for it to cap. |

A refusal exits with status 1 and a message naming the flag; the server does not start.

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

- Check that the file is under 100 MB. Over that, the file is refused and the response says so
  (`incomplete: true`, reason `file too large to scan`) — split the file and scan the parts.
  For a **video** between 100 MB and 500 MB, scan it with the CLI instead
  (`ferret-scan --file clip.mov`), which admits video containers up to 500 MB
- Ensure the file type is supported by Ferret Scan. A file the tool cannot scan does **not** fail
  the upload: it is skipped, and the other files in the same drop are still scanned and reported
- Try uploading files one at a time if multiple uploads fail
- For folder drops: very large directory trees can take a moment to enumerate client-side; the upload zone shows "Reading files…" while the walk is in progress

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
