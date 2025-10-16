# Debug Logging

[← Back to Documentation Index](../README.md)

The Ferret scanner includes comprehensive debug logging to help you understand the preprocessing and validation flow. This is especially useful for verifying that files are being preprocessed correctly before validators run.

## Enabling Debug Mode

### Command Line
Use the `--debug` flag to enable debug logging:

**Unix/Linux/macOS:**
```bash
# Enable debug logging
./ferret-scan --file /path/to/scan --debug

# Combine with other options
./ferret-scan --file /path/to/scan --debug --recursive --checks CREDIT_CARD,METADATA
```

**Windows:**
```cmd
REM Enable debug logging
ferret-scan --file "C:\path\to\scan" --debug

REM Combine with other options
ferret-scan --file "C:\path\to\scan" --debug --recursive --checks CREDIT_CARD,METADATA
```

**PowerShell:**
```powershell
# Enable debug logging
ferret-scan --file "C:\path\to\scan" --debug

# Save debug output to file
ferret-scan --file "C:\path\to\scan" --debug 2>&1 | Tee-Object -FilePath debug.log

# Enable debug with environment variable
$env:FERRET_DEBUG = "1"
ferret-scan --file "C:\path\to\scan"
```

### Configuration File
Add `debug: true` to your configuration file:

```yaml
defaults:
  debug: true
  verbose: true
  enable_preprocessors: true
```

### Profile-Based
Create or use a debug profile:

**Unix/Linux/macOS:**
```bash
# Use the built-in debug profile
./ferret-scan --file /path/to/scan --profile debug

# Or create a custom debug profile in your config
./ferret-scan --file /path/to/scan --profile my-debug-profile
```

**Windows:**
```cmd
REM Use the built-in debug profile
ferret-scan --file "C:\path\to\scan" --profile debug

REM Or create a custom debug profile in your config
ferret-scan --file "C:\path\to\scan" --profile my-debug-profile
```

### Environment Variables

**Unix/Linux/macOS:**
```bash
# Enable debug mode via environment variable
export FERRET_DEBUG=1
export FERRET_VERBOSE=1
./ferret-scan --file /path/to/scan
```

**Windows Command Prompt:**
```cmd
REM Enable debug mode via environment variable
set FERRET_DEBUG=1
set FERRET_VERBOSE=1
ferret-scan --file "C:\path\to\scan"
```

**Windows PowerShell:**
```powershell
# Enable debug mode via environment variable
$env:FERRET_DEBUG = "1"
$env:FERRET_VERBOSE = "1"
ferret-scan --file "C:\path\to\scan"

# Make permanent for current user
[Environment]::SetEnvironmentVariable("FERRET_DEBUG", "1", "User")
[Environment]::SetEnvironmentVariable("FERRET_VERBOSE", "1", "User")
```

## What Debug Logging Shows

When debug mode is enabled, you'll see detailed information about:

### 1. Configuration Summary
```
[DEBUG] Configuration summary:
[DEBUG]   - Preprocessors enabled: true
[DEBUG]   - Text extraction enabled: true
[DEBUG]   - Validators to run: all
[DEBUG]   - Recursive scan: true
[DEBUG]   - Confidence levels: all
```

### 2. Preprocessor Registration
```
[DEBUG] Text extraction preprocessor registered for extensions: [.pdf .docx .xlsx .pptx .odt .ods .odp]
```

### 3. File Processing Flow
For each file being processed:

```
[DEBUG] Processing file: /path/to/document.pdf
[DEBUG]   - Should preprocess: true
[DEBUG]   - Starting preprocessing...
[DEBUG]   - Preprocessing successful:
[DEBUG]     * Processor type: text
[DEBUG]     * Content format: pdf
[DEBUG]     * Text length: 1234 characters
[DEBUG]     * Word count: 200
[DEBUG]     * Line count: 45
[DEBUG]     * Page count: 3
[DEBUG]     * Content preview:
[DEBUG]       Document Title: Annual Report 2023
[DEBUG]       Author: Finance Department
[DEBUG]       Created: 2023-12-01
[DEBUG]       ... (content continues)
```

For image files with metadata:

```
[DEBUG] Processing file: /path/to/photo.jpg
[DEBUG]   - Should preprocess: true
[DEBUG]   - Starting preprocessing...
[DEBUG]   - Preprocessing successful:
[DEBUG]     * Processor type: metadata
[DEBUG]     * Content format: image_metadata
[DEBUG]     * Text length: 856 characters
[DEBUG]     * Word count: 45
[DEBUG]     * Line count: 23
[DEBUG]     * Content preview:
[DEBUG]       GPSLatitudeDecimal: 35.228128
[DEBUG]       GPSLongitudeDecimal: -80.842858
[DEBUG]       GPSAltitude: 233.27 meters Above Sea Level
[DEBUG]       Camera Make: Canon
[DEBUG]       DateTime: 2023:07:15 14:30:22
[DEBUG]       ... (and more metadata fields)
```

For Office documents with metadata:

```
[DEBUG] Processing file: /path/to/document.docx
[DEBUG]   - Should preprocess: true
[DEBUG]   - Starting preprocessing...
[DEBUG]   - Preprocessing successful:
[DEBUG]     * Processor type: metadata
[DEBUG]     * Content format: office_metadata
[DEBUG]     * Text length: 445 characters
[DEBUG]     * Word count: 52
[DEBUG]     * Line count: 18
[DEBUG]     * Content preview:
[DEBUG]       Author: John Smith
[DEBUG]       LastModifiedBy: jane.doe@company.com
[DEBUG]       Company: Acme Corporation
[DEBUG]       CreationDate: 2023:12:01 09:30:15-05:00
[DEBUG]       Application: Microsoft Office Word
[DEBUG]       ... (and more metadata fields)
```

For PDF documents with metadata:

```
[DEBUG] Processing file: /path/to/document.pdf
[DEBUG]   - Should preprocess: true
[DEBUG]   - Starting preprocessing...
[DEBUG]   - Preprocessing successful:
[DEBUG]     * Processor type: metadata
[DEBUG]     * Content format: pdf_metadata
[DEBUG]     * Text length: 312 characters
[DEBUG]     * Word count: 38
[DEBUG]     * Line count: 12
[DEBUG]     * Content preview:
[DEBUG]       Author: Dr. Sarah Johnson
[DEBUG]       Creator: Adobe Acrobat Pro
[DEBUG]       Producer: Adobe PDF Library 15.0
[DEBUG]       CreationDate: 2023:11:15 14:22:33-08:00
[DEBUG]       Title: Confidential Research Report
[DEBUG]       ... (and more metadata fields)
```

### 4. Validator Execution
```
[DEBUG]   - Running 4 validators...
[DEBUG]     * Validator 1 (*creditcard.Validator): starting
[DEBUG] Credit Card Validator: Luhn test failed
[DEBUG]   - File: /path/to/document.pdf, Line: 15
[DEBUG]   - Original: 4532-1234-5678-9999
[DEBUG]   - Cleaned: 4532123456789999
[DEBUG]   - Length: 16 digits
[DEBUG]   - Detected vendor: Visa
[DEBUG]   - Reason: Failed Luhn algorithm check
[DEBUG]     * Validator 1 (*creditcard.Validator): completed using preprocessed content, found 0 matches
[DEBUG]       → Confirmed: Validator scanned 1234 chars of text-extracted content
[DEBUG]     * Validator 2 (*passport.Validator): starting
[DEBUG]     * Validator 2 (*passport.Validator): completed using preprocessed content, found 1 matches
[DEBUG]       → Confirmed: Validator scanned 1234 chars of text-extracted content
[DEBUG]     * Validator 3 (*metadata.Validator): starting
[DEBUG]     * Validator 3 (*metadata.Validator): completed using preprocessed content, found 2 matches
[DEBUG]       → Confirmed: Validator scanned 856 chars of metadata-extracted content
[DEBUG]     * Validator 4 (*intellectualproperty.Validator): starting
[DEBUG]     * Validator 4 (*intellectualproperty.Validator): completed using original file (fallback), found 0 matches
```

### 5. Results Summary
```
[DEBUG]   - File processing complete: 3 total matches found
[DEBUG] ----------------------------------------
[DEBUG] Progress: 10/50 files processed (0 skipped)
```

## Understanding the Output

### Preprocessing Status
- **Should preprocess: true/false** - Indicates whether the file type supports preprocessing
- **Preprocessing successful** - Shows the preprocessor extracted content successfully
- **Text length** - Number of characters extracted from the document
- **Word/Line/Page counts** - Statistics about the extracted content

### Validator Methods
- **preprocessed content** - Validator used the extracted content from preprocessing (text, metadata, etc.)
- **original file** - Validator read the file directly (either no preprocessing available or validator doesn't support preprocessed content)
- **original file (fallback)** - Preprocessing was available but validator doesn't support it, so it fell back to reading the original file

### Confirmation Messages
When a validator uses preprocessed content, you'll see a confirmation message like:
- `→ Confirmed: Validator scanned 1234 chars of text-extracted content` - For PDF/Office documents
- `→ Confirmed: Validator scanned 856 chars of metadata-extracted content` - For image files with EXIF/metadata

This confirms that the validator is actually scanning the preprocessed content, not the original binary file.

### Match Counts
The debug output shows how many matches each validator found, helping you understand which validators are finding issues and whether preprocessing is affecting the results.

## Troubleshooting

### No Preprocessing Happening
If you see `Should preprocess: false` for files you expect to be preprocessed:
1. Check that `enable_preprocessors: true` in your config
2. Verify the file extension is supported:
   - **Documents (Text Extraction)**: PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP
   - **Documents (Metadata Extraction)**: PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP
   - **Images (Metadata Extraction)**: JPG, JPEG, TIFF, TIF, PNG, GIF, BMP, WEBP
3. For document text extraction: Ensure the text extraction preprocessor is enabled in your config
4. For metadata extraction: The metadata preprocessor is automatically enabled when preprocessors are enabled

### Preprocessing Failures
If you see "Preprocessing failed":
1. Check file permissions
2. Verify the file isn't corrupted
3. Ensure required libraries are installed for the file type

### Validators Not Using Preprocessed Content
If validators show "original file (fallback)":
- This is normal for validators that don't support preprocessed content yet
- The validator will still work by reading the original file directly

### Binary Data in Output
If you see binary data being printed when scanning images or other binary files:
- The debug output now includes content preview filtering to avoid binary data
- Only readable metadata fields are shown in the preview
- If you still see binary data, it may indicate the preprocessor isn't working correctly

### Credit Card Luhn Test Failures
When debug mode is enabled, you'll see detailed information about potential credit card numbers that fail the Luhn algorithm test:
- Shows the original and cleaned number format
- Displays the detected card vendor (Visa, MasterCard, etc.)
- Indicates the specific reason for rejection (Luhn algorithm failure)
- This helps understand why suspicious number patterns aren't being flagged as credit cards

## Performance Impact

Debug logging adds minimal overhead but does write more information to stderr. For production scans of large file sets, consider using verbose mode instead of debug mode, or redirect stderr to a file:

```bash
# Redirect debug output to a file
./ferret-scan --file /path/to/scan --debug 2> debug.log

# Or suppress debug output in production
./ferret-scan --file /path/to/scan --debug 2>/dev/null
```
## Windows-Specific Debugging

### Windows Path Debugging

When debugging on Windows, pay special attention to path-related issues:

```cmd
REM Debug Windows path handling
ferret-scan --file "C:\Users\username\Documents" --debug --recursive

REM Debug UNC path handling
ferret-scan --file "\\server\share\documents" --debug --recursive

REM Debug long path handling (>260 characters)
ferret-scan --file "\\?\C:\very\long\path\to\file.txt" --debug
```

**Common Windows Path Issues in Debug Output:**
```
[DEBUG] File path normalization:
[DEBUG]   - Original: C:\Users\username\Documents\file.txt
[DEBUG]   - Normalized: C:\Users\username\Documents\file.txt
[DEBUG]   - Is absolute: true
[DEBUG]   - Drive letter: C:

[DEBUG] UNC path handling:
[DEBUG]   - Original: \\server\share\file.txt
[DEBUG]   - Is UNC path: true
[DEBUG]   - Server: server
[DEBUG]   - Share: share

[DEBUG] Long path support:
[DEBUG]   - Path length: 275 characters
[DEBUG]   - Exceeds Windows limit: true
[DEBUG]   - Using UNC prefix: \\?\C:\very\long\path...
```

### Windows Environment Variable Debugging

Debug Windows-specific environment variable resolution:

```powershell
# Debug configuration directory resolution
$env:FERRET_DEBUG = "1"
ferret-scan --list-profiles --debug

# Expected debug output:
# [DEBUG] Configuration directory resolution:
# [DEBUG]   - FERRET_CONFIG_DIR: (not set)
# [DEBUG]   - APPDATA: C:\Users\username\AppData\Roaming
# [DEBUG]   - USERPROFILE: C:\Users\username
# [DEBUG]   - Final config dir: C:\Users\username\AppData\Roaming\ferret-scan
```

### Windows File Attribute Debugging

Debug Windows file attributes and permissions:

```cmd
REM Debug file attribute handling
ferret-scan --file "C:\path\to\readonly-file.txt" --debug

REM Expected debug output for Windows attributes:
REM [DEBUG] File attributes:
REM [DEBUG]   - Read-only: true
REM [DEBUG]   - Hidden: false
REM [DEBUG]   - System: false
REM [DEBUG]   - Archive: true
```

### Windows Performance Debugging

Monitor Windows-specific performance issues:

```powershell
# Debug with performance monitoring
$env:FERRET_DEBUG = "1"
$env:FERRET_PERF = "1"

# Start performance monitoring in background
Start-Job -ScriptBlock {
    while ($true) {
        $process = Get-Process -Name "ferret-scan" -ErrorAction SilentlyContinue
        if ($process) {
            $memory = [math]::Round($process.WorkingSet / 1MB, 2)
            Write-Host "$(Get-Date -Format 'HH:mm:ss') Memory: ${memory}MB"
        }
        Start-Sleep -Seconds 2
    }
}

# Run scan with debug
ferret-scan --file "C:\large-dataset" --recursive --debug

# Stop monitoring
Get-Job | Stop-Job
Get-Job | Remove-Job
```

### Windows Antivirus Debugging

Debug antivirus interference issues:

```powershell
# Check if Windows Defender is interfering
$env:FERRET_DEBUG = "1"
ferret-scan --file "C:\test-file.txt" --debug

# Look for these debug messages:
# [DEBUG] File access error: Access denied
# [DEBUG] Antivirus scan detected: Windows Defender
# [DEBUG] Retrying file access after delay...
```

### Windows Registry Debugging

Debug Windows registry access (if applicable):

```cmd
REM Debug registry-based configuration
set FERRET_DEBUG=1
ferret-scan --debug --version

REM Expected debug output:
REM [DEBUG] Registry configuration check:
REM [DEBUG]   - HKCU\Software\FerretScan: (not found)
REM [DEBUG]   - HKLM\Software\FerretScan: (not found)
REM [DEBUG]   - Using file-based configuration
```

### Windows Service Debugging

Debug when running as Windows service:

```powershell
# Debug service mode
$env:FERRET_DEBUG = "1"
$env:FERRET_SERVICE_MODE = "1"

# Check service-specific debug output:
# [DEBUG] Service mode detected
# [DEBUG] Service account: NT AUTHORITY\SYSTEM
# [DEBUG] Working directory: C:\Windows\System32
# [DEBUG] Config directory: C:\ProgramData\ferret-scan
```

### Windows Event Log Integration

Enable Windows Event Log debugging:

```powershell
# Enable Windows Event Log debugging
$env:FERRET_DEBUG = "1"
$env:FERRET_EVENTLOG = "1"

ferret-scan --file "C:\test" --debug

# Check Windows Event Logs
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "ferret-scan"} | Select-Object -First 10
```

### Debugging Output Redirection on Windows

**Command Prompt:**
```cmd
REM Redirect debug output to file
ferret-scan --file "C:\path" --debug > output.log 2>&1

REM Separate stdout and stderr
ferret-scan --file "C:\path" --debug > output.log 2> debug.log

REM View debug output in real-time
ferret-scan --file "C:\path" --debug 2>&1 | more
```

**PowerShell:**
```powershell
# Redirect and display debug output
ferret-scan --file "C:\path" --debug 2>&1 | Tee-Object -FilePath debug.log

# Capture debug output in variable
$debugOutput = ferret-scan --file "C:\path" --debug 2>&1

# Filter debug messages
ferret-scan --file "C:\path" --debug 2>&1 | Where-Object { $_ -match "\[DEBUG\]" }

# Save debug output with timestamp
ferret-scan --file "C:\path" --debug 2>&1 | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $_" } | Out-File debug-$(Get-Date -Format 'yyyyMMdd-HHmmss').log
```

### Windows Troubleshooting Tips

1. **Path Length Issues:**
   - Look for debug messages about path length limits
   - Check for UNC prefix usage in debug output

2. **Permission Problems:**
   - Debug output will show "Access denied" errors
   - Check file attribute debug information

3. **Antivirus Interference:**
   - Look for retry attempts in debug output
   - Check for delayed file access patterns

4. **Configuration Loading:**
   - Verify Windows environment variable expansion
   - Check APPDATA vs USERPROFILE usage

5. **Performance Issues:**
   - Monitor memory usage during debug runs
   - Look for Windows Defender exclusion recommendations

For more Windows-specific troubleshooting, see:
- [Windows Troubleshooting Guide](../troubleshooting/WINDOWS_TROUBLESHOOTING.md)
- [Windows Development Guide](WINDOWS_DEVELOPMENT.md)
- [Windows Installation Guide](../WINDOWS_INSTALLATION.md)