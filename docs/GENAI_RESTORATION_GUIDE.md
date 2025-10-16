# GenAI Features Restoration Guide

This document provides comprehensive instructions for restoring GenAI features that were disabled across all 20 tasks.

## Overview

The GenAI disabling implementation was designed with restoration in mind. All GenAI code was preserved but commented out with `GENAI_DISABLED` markers, making restoration straightforward and reliable.

## Quick Restoration

### Automated Restoration Script

The fastest way to restore GenAI features is using the automated script:

```bash
# Make the script executable
chmod +x scripts/restore-genai-features.sh

# Run the restoration script
bash scripts/restore-genai-features.sh
```

This script will:
- ✅ Automatically find and uncomment all `GENAI_DISABLED` code
- ✅ Create backup files before making changes
- ✅ Provide detailed progress reporting
- ✅ Verify restoration success

## Manual Restoration Process

If you prefer manual restoration or need to restore specific components:

### 1. CLI Interface Restoration

**File**: `cmd/main.go`

```bash
# Remove GENAI_DISABLED comment markers
sed -i 's|// GENAI_DISABLED: ||g' cmd/main.go
```

**Restores**:
- `--enable-genai` flag
- `--genai-services` flag
- `--textract-region` flag
- `--transcribe-bucket` flag
- `--max-cost` flag
- `--estimate-only` flag
- GenAI configuration processing

### 2. Web Interface Restoration

**Files**: `cmd/web/main.go`, `cmd/web/template.html`

```bash
# Restore web backend
sed -i 's|// GENAI_DISABLED: ||g' cmd/web/main.go

# Restore web UI elements
sed -i 's|<!-- GENAI_DISABLED: \(.*\) -->|\1|g' cmd/web/template.html
```*
*Restores**:
- GenAI checkbox and form controls
- GenAI service selection dropdowns
- GenAI warning messages and cost estimation UI
- GenAI JavaScript functionality
- GenAI backend processing

### 3. Configuration System Restoration

**File**: `internal/config/config.go`

```bash
sed -i 's|// GENAI_DISABLED: ||g' internal/config/config.go
```

**Restores**:
- GenAI configuration options
- AWS service configuration
- Cost management settings

### 4. Router Components Restoration

**Files**: `internal/router/file_router.go`, `internal/router/context.go`, `internal/router/integration.go`

```bash
sed -i 's|// GENAI_DISABLED: ||g' internal/router/file_router.go
sed -i 's|// GENAI_DISABLED: ||g' internal/router/context.go
sed -i 's|// GENAI_DISABLED: ||g' internal/router/integration.go
```

**Restores**:
- Textract OCR preprocessor
- Transcribe audio preprocessor
- GenAI service routing logic
- AWS integration handling

### 5. Scanner Components Restoration

**File**: `internal/scanner/scanner.go`

```bash
sed -i 's|// GENAI_DISABLED: ||g' internal/scanner/scanner.go
```

**Restores**:
- COMPREHEND_PII validator
- GenAI validator integration

### 6. Help System Restoration

**File**: `internal/help/help.go`

```bash
sed -i 's|// GENAI_DISABLED: ||g' internal/help/help.go
```

**Restores**:
- GenAI flag documentation
- GenAI usage examples
- GenAI help text

### 7. Documentation and Examples Restoration

**Files**: `README.md`, `examples/ferret.yaml`, `examples/genai_example.sh`

```bash
sed -i 's|# GENAI_DISABLED: ||g' README.md
sed -i 's|# GENAI_DISABLED: ||g' examples/ferret.yaml
sed -i 's|# GENAI_DISABLED: ||g' examples/genai_example.sh
```

**Restores**:
- GenAI documentation sections
- GenAI configuration examples
- GenAI usage examples## Verificat
ion After Restoration

### 1. Build and Test

```bash
# Build the application
go build -o ferret-scan cmd/main.go

# Verify GenAI flags are available
./ferret-scan --help | grep -i genai
```

**Expected Output**:
```
--enable-genai                Enable GenAI services (Textract, Transcribe, Comprehend)
--genai-services strings      Comma-separated list of GenAI services to use
--textract-region string      AWS region for Textract service
--transcribe-bucket string    S3 bucket name for Transcribe audio uploads
--max-cost float             Maximum cost limit for GenAI services
--estimate-only              Show cost estimate and exit without processing
```

### 2. Test GenAI Functionality

```bash
# Test GenAI flag acceptance
./ferret-scan --enable-genai --help

# Test COMPREHEND_PII validator
./ferret-scan --checks COMPREHEND_PII --help
```

### 3. Test Web UI

```bash
# Start web server
./ferret-scan --web --port 8080

# Open browser to http://localhost:8080
# Verify GenAI checkboxes and options are visible
```

### 4. Verify Configuration

```bash
# Test GenAI configuration loading
./ferret-scan --config examples/ferret.yaml --enable-genai --estimate-only
```

## File Restoration Checklist

Use this checklist to ensure complete restoration:

### Core Components
- [ ] `cmd/main.go` - CLI flags and functionality
- [ ] `cmd/web/main.go` - Web backend GenAI processing
- [ ] `cmd/web/template.html` - Web UI GenAI elements

### Internal Components
- [ ] `internal/config/config.go` - GenAI configuration
- [ ] `internal/router/file_router.go` - GenAI preprocessors
- [ ] `internal/router/context.go` - GenAI context handling
- [ ] `internal/router/integration.go` - GenAI integration
- [ ] `internal/scanner/scanner.go` - GenAI validators
- [ ] `internal/help/help.go` - GenAI help system
- [ ] `internal/parallel/worker_pool.go` - GenAI parallel processing

### Documentation and Examples
- [ ] `README.md` - GenAI documentation
- [ ] `examples/ferret.yaml` - GenAI configuration examples
- [ ] `examples/genai_example.sh` - GenAI usage examples