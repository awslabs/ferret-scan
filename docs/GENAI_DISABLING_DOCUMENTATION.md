# GenAI Features Disabling Documentation

## Overview

This document provides comprehensive information about the temporary disabling of GenAI (Generative AI) features in Ferret Scan. The GenAI features include Amazon Textract OCR, Amazon Transcribe, and Amazon Comprehend PII detection services.

The disabling approach uses strategic commenting to hide GenAI functionality from users while preserving the complete codebase for easy restoration in future releases.

## Commenting Strategy

### Comment Markers Used

All GenAI-related code has been commented out using consistent markers to enable easy identification and restoration:

- **Go Code Single Line**: `// GENAI_DISABLED: <description>`
- **Go Code Block Start**: `/* GENAI_DISABLED_START: <description>`
- **Go Code Block End**: `GENAI_DISABLED_END */`
- **HTML Comments**: `<!-- GENAI_DISABLED: <description> -->`
- **YAML/Shell Comments**: `# GENAI_DISABLED: <description>`
- **Markdown Comments**: `<!-- GENAI_DISABLED: <description> -->`

### Commenting Principles

1. **Preservation**: No GenAI code is deleted, only commented out
2. **Consistency**: All disabled code uses the same marker format
3. **Descriptive**: Each marker includes a brief description of what was disabled
4. **Reversible**: All changes can be easily undone by uncommenting marked sections
5. **Complete**: All user-facing GenAI functionality is hidden

## Files Modified with GenAI Comment Markers

### Core Application Files

#### 1. `cmd/main.go`
**Purpose**: Main CLI application entry point
**Modifications**:
- GenAI command line flags (--enable-genai, --genai-services, --textract-region, --transcribe-bucket, --max-cost, --estimate-only)
- GenAI flag processing and validation logic
- AWS credential validation calls for GenAI services
- GenAI service parsing functions
- GenAI cost estimation and warning logic
- COMPREHEND_PII validator registration

**Search Pattern**: `GENAI_DISABLED` in `cmd/main.go`

#### 2. `internal/help/help.go`
**Purpose**: Help system and usage documentation
**Modifications**:
- GenAI flag descriptions in help output
- GenAI usage examples and warnings
- Cost control examples and documentation
- GenAI-related warning messages

**Search Pattern**: `GENAI_DISABLED` in `internal/help/help.go`

#### 3. `cmd/web/template.html`
**Purpose**: Web UI interface template
**Modifications**:
- GenAI checkbox and form controls
- GenAI warning messages and cost estimation UI
- GenAI service selection dropdowns
- AWS region selection for GenAI
- GenAI-related JavaScript functions (toggleGenAI, getSelectedGenAIServices)
- GenAI cost calculation functions

**Search Pattern**: `GENAI_DISABLED` in `cmd/web/template.html`

#### 4. `cmd/web/main.go`
**Purpose**: Web UI backend processing
**Modifications**:
- GenAI parameter extraction from web forms
- GenAI parameter passing to processUploadedFile()
- GenAI parameter passing to runFerretScan()
- GenAI flag construction in command building

**Search Pattern**: `GENAI_DISABLED` in `cmd/web/main.go`

#### 5. `internal/config/config.go`
**Purpose**: Configuration parsing and management
**Modifications**:
- Textract configuration struct fields
- Textract default value assignments
- GenAI-related configuration validation
- GenAI configuration parsing logic

**Search Pattern**: `GENAI_DISABLED` in `internal/config/config.go`

#### 6. `internal/router/file_router.go`
**Purpose**: File routing and processing logic
**Modifications**:
- GenAI service checks and validation
- GenAI context creation parameters
- GenAI-related processing context fields
- Audio file GenAI requirement messages

**Search Pattern**: `GENAI_DISABLED` in `internal/router/file_router.go`

### Documentation Files

#### 7. `README.md`
**Purpose**: Main project documentation
**Modifications**:
- GenAI features removed from main feature list
- GenAI command line options documentation
- GenAI usage examples and warnings
- GenAI prerequisites and setup sections

**Search Pattern**: `GENAI_DISABLED` in `README.md`

#### 8. `examples/ferret.yaml`
**Purpose**: Configuration file examples
**Modifications**:
- Textract configuration section
- GenAI profile examples
- GenAI-related comments and descriptions
- transcribe-bucket and other GenAI settings

**Search Pattern**: `GENAI_DISABLED` in `examples/ferret.yaml`

#### 9. `examples/genai_example.sh`
**Purpose**: GenAI usage example script
**Modifications**:
- Entire script content commented out
- GenAI usage examples throughout the script
- AWS service descriptions and warnings
- File structure preserved but all functional content disabled

**Search Pattern**: `GENAI_DISABLED` in `examples/genai_example.sh`

## Preserved GenAI Implementation Code

The following files contain GenAI implementation code that remains **UNCHANGED** and ready for restoration:

### Preprocessors
- `internal/preprocessors/textract_preprocessor.go` - Amazon Textract integration
- `internal/preprocessors/transcribe_preprocessor.go` - Amazon Transcribe integration
- `internal/preprocessors/text-extractors/textract-extractor-lib/` - Textract library
- `internal/preprocessors/audio-extractors/transcribe-extractor-lib/` - Transcribe library

### Validators
- `internal/validators/comprehend/` - Complete Comprehend PII validator implementation
- `internal/validators/comprehend/comprehend-analyzer-lib/` - Comprehend analysis library

### Cost Estimation
- `internal/cost/estimator.go` - AWS cost estimation functionality

### Examples
- `examples/preprocessors/textract-example.go` - Textract usage example
- `examples/preprocessors/transcribe-example.go` - Transcribe usage example
- `examples/validators/comprehend-example.go` - Comprehend validator example

## Search Patterns for Finding Disabled Code

### Global Search Commands

To find all disabled GenAI code across the entire codebase:

```bash
# Find all GENAI_DISABLED markers
grep -r "GENAI_DISABLED" .

# Find all GENAI_DISABLED markers with line numbers
grep -rn "GENAI_DISABLED" .

# Find all GENAI_DISABLED markers in specific file types
grep -r "GENAI_DISABLED" --include="*.go" .
grep -r "GENAI_DISABLED" --include="*.html" .
grep -r "GENAI_DISABLED" --include="*.yaml" .
grep -r "GENAI_DISABLED" --include="*.sh" .
grep -r "GENAI_DISABLED" --include="*.md" .
```

### File-Specific Search Patterns

```bash
# Search in Go files
grep -n "GENAI_DISABLED" cmd/main.go
grep -n "GENAI_DISABLED" internal/help/help.go
grep -n "GENAI_DISABLED" cmd/web/main.go
grep -n "GENAI_DISABLED" internal/config/config.go
grep -n "GENAI_DISABLED" internal/router/file_router.go

# Search in web files
grep -n "GENAI_DISABLED" cmd/web/template.html

# Search in documentation
grep -n "GENAI_DISABLED" README.md
grep -n "GENAI_DISABLED" examples/ferret.yaml
grep -n "GENAI_DISABLED" examples/genai_example.sh
```

### Advanced Search Patterns

```bash
# Find commented out GenAI flags
grep -r "// GENAI_DISABLED.*flag" .

# Find commented out GenAI functions
grep -r "// GENAI_DISABLED.*func" .

# Find commented out GenAI struct fields
grep -r "// GENAI_DISABLED.*struct" .

# Find commented out GenAI HTML elements
grep -r "<!-- GENAI_DISABLED.*-->" .
```

## Restoration Process for Future Developers

### Step-by-Step Restoration Guide

#### Phase 1: Identify All Disabled Code
1. Run global search to find all GENAI_DISABLED markers:
   ```bash
   grep -rn "GENAI_DISABLED" . > genai_disabled_locations.txt
   ```

2. Review the generated list to understand the scope of changes

#### Phase 2: Uncomment Go Code
1. **CLI Flags and Processing** (`cmd/main.go`):
   - Uncomment GenAI flag definitions
   - Uncomment GenAI flag processing logic
   - Uncomment AWS credential validation
   - Uncomment COMPREHEND_PII validator registration

2. **Help System** (`internal/help/help.go`):
   - Uncomment GenAI flag descriptions
   - Uncomment GenAI usage examples
   - Uncomment GenAI warning messages

3. **Configuration** (`internal/config/config.go`):
   - Uncomment Textract struct fields
   - Uncomment GenAI configuration parsing

4. **Web Backend** (`cmd/web/main.go`):
   - Uncomment GenAI parameter processing
   - Uncomment GenAI parameter passing

5. **Router** (`internal/router/file_router.go`):
   - Uncomment GenAI service checks
   - Uncomment GenAI context parameters

#### Phase 3: Uncomment Web UI
1. **HTML Template** (`cmd/web/template.html`):
   - Uncomment GenAI form elements
   - Uncomment GenAI JavaScript functions
   - Uncomment GenAI warning messages

#### Phase 4: Uncomment Documentation
1. **README** (`README.md`):
   - Uncomment GenAI feature descriptions
   - Uncomment GenAI usage examples

2. **Configuration Examples** (`examples/ferret.yaml`):
   - Uncomment GenAI configuration sections

3. **Example Scripts** (`examples/genai_example.sh`):
   - Uncomment entire script content

#### Phase 5: Testing and Validation
1. **Compile and Test**:
   ```bash
   go build ./cmd
   ./ferret-scan --help  # Verify GenAI flags appear
   ```

2. **Test GenAI Functionality**:
   ```bash
   # Test GenAI flags are recognized
   ./ferret-scan --enable-genai --help

   # Test COMPREHEND_PII validator
   ./ferret-scan --checks COMPREHEND_PII --help
   ```

3. **Test Web UI**:
   - Start web server and verify GenAI elements are visible
   - Test GenAI form submission

4. **Validate Documentation**:
   - Verify README shows GenAI features
   - Check example configurations include GenAI settings

### Automated Restoration Script

Create a script to automate the restoration process:

```bash
#!/bin/bash
# restore_genai.sh - Automated GenAI restoration script

echo "Starting GenAI feature restoration..."

# Find all GENAI_DISABLED markers
echo "Finding all disabled GenAI code..."
grep -rn "GENAI_DISABLED" . > genai_locations.txt

# Process each file type
echo "Processing Go files..."
find . -name "*.go" -exec sed -i 's|// GENAI_DISABLED: ||g' {} \;
find . -name "*.go" -exec sed -i 's|/\* GENAI_DISABLED_START:.*||g' {} \;
find . -name "*.go" -exec sed -i 's|.*GENAI_DISABLED_END \*/||g' {} \;

echo "Processing HTML files..."
find . -name "*.html" -exec sed -i 's|<!-- GENAI_DISABLED: \(.*\) -->|\1|g' {} \;

echo "Processing YAML files..."
find . -name "*.yaml" -exec sed -i 's|# GENAI_DISABLED: ||g' {} \;

echo "Processing shell scripts..."
find . -name "*.sh" -exec sed -i 's|# GENAI_DISABLED: ||g' {} \;

echo "Processing markdown files..."
find . -name "*.md" -exec sed -i 's|<!-- GENAI_DISABLED: \(.*\) -->|\1|g' {} \;

echo "GenAI restoration complete. Please test functionality."
```

## Validation Checklist

### Pre-Restoration Validation
- [ ] All GenAI flags return "unknown flag" errors
- [ ] COMPREHEND_PII returns "unknown check" error
- [ ] Web UI shows no GenAI elements
- [ ] Help output contains no GenAI references
- [ ] Documentation contains no GenAI mentions
- [ ] All non-GenAI functionality works normally

### Post-Restoration Validation
- [ ] All GenAI flags are recognized and functional
- [ ] COMPREHEND_PII validator is available and works
- [ ] Web UI shows GenAI elements and they function
- [ ] Help output includes GenAI flag documentation
- [ ] Documentation includes GenAI feature descriptions
- [ ] GenAI examples work correctly
- [ ] AWS integration functions properly
- [ ] Cost estimation works
- [ ] All non-GenAI functionality still works

## Maintenance Considerations

### During GenAI Disabled Period
1. **Code Updates**: When adding new features, avoid GenAI dependencies
2. **Documentation**: Keep GenAI implementation docs updated for restoration
3. **Dependencies**: Monitor AWS SDK updates that might affect GenAI features
4. **Testing**: Ensure new code doesn't break GenAI restoration capability

### Planning for Restoration
1. **AWS Credentials**: Ensure test AWS credentials are available
2. **Test Data**: Prepare test files for GenAI validation
3. **Documentation**: Update GenAI docs if AWS services change
4. **Dependencies**: Verify AWS SDK compatibility before restoration

## Troubleshooting

### Common Issues During Restoration

#### Issue: GenAI flags not recognized after uncommenting
**Solution**:
- Verify all flag definitions in `cmd/main.go` are uncommented
- Check flag processing logic is also uncommented
- Rebuild the application

#### Issue: COMPREHEND_PII validator not available
**Solution**:
- Verify validator registration in `cmd/main.go` is uncommented
- Check validator is added to available checks list
- Ensure parseChecksToRun() includes COMPREHEND_PII

#### Issue: Web UI GenAI elements not visible
**Solution**:
- Check HTML template has GenAI elements uncommented
- Verify JavaScript functions are uncommented
- Clear browser cache and reload

#### Issue: Configuration parsing errors
**Solution**:
- Verify Textract struct fields are uncommented in `internal/config/config.go`
- Check configuration validation logic is restored
- Test with example configuration file

### Getting Help

If you encounter issues during restoration:
1. Review this documentation thoroughly
2. Check the original requirements and design documents
3. Compare with preserved GenAI implementation files
4. Test individual components before full integration
5. Consult AWS documentation for service-specific issues

## Conclusion

This documentation provides a complete guide for understanding, maintaining, and restoring GenAI features in Ferret Scan. The commenting approach ensures that GenAI functionality can be easily restored when needed while keeping it completely hidden from users in the current release.

The systematic approach with consistent markers, comprehensive documentation, and clear restoration procedures ensures that future developers can confidently work with the GenAI disabling system.
