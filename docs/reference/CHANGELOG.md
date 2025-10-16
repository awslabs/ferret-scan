# Ferret Scan Changelog

[← Back to Documentation Index](../README.md)

## v0.14.1 - Security Release (September 16, 2025)

### 🔒 SECURITY FIXES
- **CRITICAL**: Fixed path traversal vulnerabilities across codebase
- **Added `filepath.Clean()` sanitization** to all file operations to prevent directory traversal attacks
- **Fixed fragile error detection** - replaced language-dependent string matching with robust `os.IsPermission()` checks
- **Secured 8 critical components**:
  - Config file loading (`internal/config/config.go`)
  - Web server file operations (`internal/web/server.go`)
  - File routing and processing (`internal/router/file_router.go`)
  - Platform file attributes (`internal/platform/attributes.go`)
  - Text preprocessors (`internal/preprocessors/plaintext_preprocessor.go`)
  - Cost estimation (`internal/cost/estimator.go`)
  - Suppression management (`internal/suppressions/suppression.go`)
  - Validator operations (`internal/validators/comprehend/validator.go`)

### 🛡️ Security Impact
- **Prevents unauthorized file access** through malicious path manipulation
- **Cross-platform protection** - works on Windows, Linux, and macOS
- **Backward compatible** - no breaking changes
- **Immediate deployment recommended**

### ✅ Quality Assurance
- All regression tests pass
- Build and functionality verified
- Code quality checks pass (`make fmt`, `make vet`)

---

## Enhanced Validator System (2025)

### Universal False Positive Prevention
- **Zero Confidence Filtering**: All validators now automatically exclude matches with 0% confidence scores
- **Enhanced Context Analysis**: Improved keyword analysis and contextual validation across all validators
- **Test Data Detection**: Enhanced identification and filtering of placeholder/test patterns
- **Mathematical Validation**: Structural validation for applicable data types (credit cards, etc.)

### Validator-Specific Enhancements

#### Credit Card Validator - Enhanced Format Support (December 2025)
- **Multiple Separator Formats**: Added support for space-only separators (`4532 0151 1283 0366`) and no separators (`4532015112830366`)
- **XML/HTML Context Support**: Enhanced boundary detection for XML/HTML tags (`<creditCard>4532-0151-1283-0366</creditCard>`)
- **Improved Quoted String Handling**: Better detection within JSON, CSV, and other quoted contexts
- **All Card Lengths**: Full support for 14-digit (Diners), 15-digit (Amex), and 16-digit cards in all formats
- **Performance Optimization**: 600x faster validator creation with optimized BIN range lookup
- **Backward Compatibility**: All existing formats continue to work perfectly
- **Comprehensive Testing**: 100% detection rate across 17 different format scenarios

#### IP Address Validator - Sensitivity Filtering
- **RFC Compliance**: Excludes non-identifying addresses (private, reserved, test ranges)
- **Private IP Filtering**: 10.x.x.x, 192.168.x.x, 172.16-31.x.x ranges excluded
- **Reserved Address Detection**: Filters loopback, link-local, multicast, broadcast addresses
- **Documentation Ranges**: Excludes RFC 5737 test ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
- **IPv6 Support**: Filters non-sensitive IPv6 addresses (link-local, unique local, documentation)
- **DNS Server Filtering**: Excludes common public DNS servers (Google, Cloudflare, etc.)

#### Enhanced Validation Algorithms
- **Credit Card Validator**: Mathematical validation with Luhn algorithm and test pattern filtering
- **Email Validator**: Advanced domain validation with context analysis
- **Phone Validator**: International format support with cross-validator false positive prevention
- **SSN Validator**: Domain-aware validation with HR/Tax/Healthcare context understanding
- **Passport Validator**: Multi-country format support with travel context analysis
- **Secrets Validator**: Enhanced entropy analysis with 40+ API key patterns
- **Intellectual Property Validator**: Patent, trademark, copyright detection with internal URL filtering
- **Metadata Validator**: EXIF and document metadata analysis with validation

### Implementation Changes
- **Template Validator**: Updated with zero confidence filtering best practices
- **Consistent Architecture**: All validators follow same false positive prevention pattern
- **No Configuration Required**: Enhancements automatically applied to improve accuracy
- **Developer Guide Updated**: Creating validators documentation includes new filtering requirements

### Impact
- **Reduced False Positives**: Significant improvement in detection accuracy
- **Enhanced Sensitivity**: IP addresses now focus only on potentially identifying data
- **Better User Experience**: Cleaner results with fewer irrelevant matches
- **Enterprise Ready**: Production-grade accuracy for compliance and security scanning

## [BREAKING] Cache System Removal

### Security Enhancement - Cache Elimination
- **REMOVED**: Complete cache system (`internal/cache/`) to eliminate sensitive data storage
- **SECURITY**: No more sensitive data (credit cards, SSNs, API keys) stored on disk
- **BREAKING**: Removed `--cache-dir` and `--clear-cache` CLI flags
- **IMPACT**: Processing will be slower for repeat scans but more secure
- **FILES REMOVED**:
  - `internal/cache/cache.go`
  - `docs/development/cache_system.md`
  - `internal/paths/paths.go` GetCacheDir() function

### Code Changes
- **Router**: Removed cache logic from file processing pipeline
- **Parallel Processing**: Removed cache parameter from worker pools
- **Main**: Removed cache initialization and CLI flag handling
- **Documentation**: Updated all references to remove cache mentions
- **Docker**: Simplified volume mapping (no cache directory needed)

### Migration Notes
- **No Action Required**: Cache removal is automatic
- **Performance**: Expect 30-50% slower processing for repeat scans
- **Security**: Significantly improved - no sensitive data persists on disk
- **CLI**: Remove any `--cache-dir` or `--clear-cache` flags from scripts

## Major Updates and Enhancements

### Web UI Enhancements

#### CloudScape Design System Integration
- **Professional UI**: Implemented AWS CloudScape design system for enterprise-grade interface
- **Responsive Layout**: Mobile and desktop optimized with proper breakpoints
- **Color Scheme**: AWS Console-style theming with consistent visual hierarchy

#### Advanced Pagination System
- **Smart Pagination**: Only shows controls when needed (50+ results)
- **Page Size Options**: 50, 100, or all results per page
- **Clickable Page Numbers**: Navigate directly to specific pages (shows 5 pages at a time)
- **Navigation Controls**: Previous/Next buttons with proper state management
- **Result Information**: Shows "Showing X-Y of Z results" with current page info

#### Enhanced Results Display
- **Multi-level Default Sorting**: Results sorted by confidence (desc), filename (asc), line number (asc)
- **Interactive Statistics**: Clickable stat cards to filter by confidence level
- **Sortable Columns**: Click any table header to sort results
- **Visual Progress Bar**: Replaced text progress with animated progress bar
- **Original Filenames**: Display actual filenames instead of temporary file paths

<!-- GENAI_DISABLED: GenAI Cost Management
- **Selective Service Usage**: Individual checkboxes for Textract, Transcribe, Comprehend
- **Accurate Cost Calculation**: Only calculates costs for selected services
- **Real-time Cost Estimates**: Updates based on file types and selected services
- **Cost Transparency**: Clear pricing information for each service
-->

#### User Experience Improvements
- **Expandable Sections**: Collapsible configuration sections for clean interface
- **Interactive Help Modal**: Comprehensive help system with usage examples
- **CLI Command Display**: Shows equivalent command-line usage in real-time
- **Export Functionality**: CSV and JSON export with current display settings
- **Error Handling**: Individual file errors don't stop batch processing

### CLI Enhancements

<!-- GENAI_DISABLED: GenAI Service Selection
- **--genai-services Flag**: Selective AWS service usage (textract, transcribe, comprehend, all)
- **Cost Control**: Ability to exclude expensive services like Comprehend
- **Service Validation**: Proper validation of service combinations
-->

#### Suppression System
- **--generate-suppressions Flag**: Auto-generate suppression rules for findings
- **Privacy Protection**: SHA-256 hashing of sensitive data in suppression files
- **Rule Management**: Enable/disable suppression rules with timestamps
- **Audit Trail**: Track creation and last seen dates for suppression rules

#### Agent System Framework
- **Modular Architecture**: Extensible agent system for advanced analysis
- **Local Agents**: Risk assessment, context analysis, remediation suggestions
- **Agent Control Flags**: --enable-agents and --agents for selective usage
<!-- GENAI_DISABLED: - **Future AI Integration**: Framework ready for AI-powered agents -->

### Core System Improvements

#### Memory Security
- **Memory Scrubbing**: Secure handling of sensitive data in memory
- **Automatic Cleanup**: Sensitive data cleared after processing
- **Multiple Overwrites**: Enhanced security through multiple memory passes

#### Performance Optimizations
- **Efficient Pagination**: Memory-efficient handling of large result sets
- **Progress Tracking**: Real-time progress updates for long-running scans
- **Error Isolation**: Individual file failures don't affect batch operations

#### Configuration System
- **YAML Configuration**: Comprehensive configuration file support
- **Profile Management**: Named profiles for different scanning scenarios
- **Validator Configuration**: Per-validator settings and customization

### Validator Enhancements

#### Interface Compliance
- **Standardized Interface**: All validators implement GetName(), GetDescription(), GetSupportedTypes()
- **Comprehensive Documentation**: Individual README files for each validator
- **Help System Integration**: Detailed help for each validator type

#### New Detection Capabilities
- **Intellectual Property**: Patents, trademarks, copyrights, trade secrets
- **Social Security Numbers**: US SSN detection with format validation
- **Enhanced Metadata**: GPS coordinates, timestamps, device fingerprints
<!-- GENAI_DISABLED: - **AI-Powered PII**: Amazon Comprehend integration for advanced detection -->

### Documentation Updates

#### README Enhancements
- **Web UI Documentation**: Comprehensive web interface guide
<!-- GENAI_DISABLED: - **GenAI Integration**: Detailed AWS service setup and usage -->
- **Pagination Features**: Documentation of new navigation capabilities
- **Cost Management**: Clear guidance on controlling AWS costs

#### Help System
- **Interactive Help**: Modal help system in web interface
- **CLI Help**: Comprehensive command-line help with examples
- **Validator Help**: Detailed help for each detection type

### Technical Infrastructure

#### Build System
- **Makefile Improvements**: Enhanced build targets and development tools
- **Docker Support**: Containerized deployment with proper template inclusion
- **Development Scripts**: Setup scripts for development environment

#### Code Quality
- **Test Cleanup**: Removed test files and obsolete test code
- **Code Organization**: Improved package structure and interfaces
- **Error Handling**: Enhanced error messages and user feedback

## Removed Features

### Cleanup Actions
- **Test Files**: Removed `test_agents.txt` and `test_suppressions.txt`
- **Obsolete Code**: Cleaned up unused test code and examples
- **Temporary Features**: Removed experimental suppression UI features

## Breaking Changes

### Interface Changes
- **Validator Interface**: All validators must implement new interface methods
- **Configuration Format**: Enhanced YAML configuration structure
- **API Changes**: Web API updated for new pagination and filtering

### Default Behavior
- **Default Sorting**: Results now sorted by confidence, filename, line number
- **Pagination**: Large result sets automatically paginated
<!-- GENAI_DISABLED: - **GenAI Services**: More granular control over AWS service usage -->

## Migration Guide

### For Developers
1. **Update Validators**: Implement new interface methods (GetName, GetDescription, GetSupportedTypes)
2. **Configuration Files**: Update YAML configuration to new format
3. **Build Process**: Use updated Makefile targets

### For Users
1. **Web Interface**: New pagination and filtering controls
<!-- GENAI_DISABLED: 2. **CLI Options**: New --genai-services flag for cost control -->
3. **Suppression Files**: Enhanced suppression system with new features

## Future Roadmap

### Planned Features
<!-- GENAI_DISABLED: - **AI Agent Integration**: Advanced AI-powered analysis agents -->
- **Enhanced Reporting**: More detailed reporting and analytics
- **Additional Validators**: More sensitive data detection types
- **Performance Improvements**: Further optimization for large datasets

### Under Consideration
- **Real-time Scanning**: Live file monitoring capabilities
- **Integration APIs**: REST API for third-party integrations
- **Cloud Deployment**: Native cloud deployment options
<!-- GENAI_DISABLED: - **Advanced Analytics**: Machine learning for pattern detection -->
