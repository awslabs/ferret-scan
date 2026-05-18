# Ferret Scan Documentation

[← Back to Main README](../README.md)

Welcome to the comprehensive documentation for Ferret Scan - a sensitive data detection tool that scans files for potential sensitive information such as credit card numbers, passport numbers, secrets, and more.

## 📚 Documentation Index

### 🚀 Getting Started
- [Main README](../README.md) - Project overview and quick start
- [Installation Guide](INSTALL.md) - Quick installation guide for releases
- [Complete Installation Guide](INSTALLATION.md) - Comprehensive installation options
- [Configuration Guide](configuration.md) - YAML configuration and profiles
- [Architecture Overview](architecture-diagram.md) - System architecture and flow diagrams
- [Application Flow](ferret-application-flow.md) - Processing diagrams and workflows

### 👥 User Guides
- [Docker Guide](user-guides/README-Docker.md) - Container deployment and usage
- [Web UI Guide](user-guides/README-WebUI.md) - Web interface documentation
- [🆕 Enhanced Metadata Guide](user-guides/README-Enhanced-Metadata.md) - Comprehensive guide to enhanced metadata validation
- [Preprocess-Only Mode](user-guides/README-Preprocess-Only.md) - Text extraction without validation
- [🆕 Stdin / Streaming Gateway](user-guides/README-Stdin.md) - Pipe content via stdin and use as a streaming redaction gateway (lambda / CI integration)
- [Suppression System](user-guides/README-Suppressions.md) - Managing false positives
- [Redaction Guide](user-guides/README-Redaction.md) - Redacting sensitive data with simple, format-preserving, and synthetic strategies
- [Suppression Architecture](suppression-system.md) - Technical suppression system details

### 🧪 Testing & Quality Assurance

- [GitLab CI Testing Tracker](testing/GITLAB_CI_TESTING_TRACKER.md) - Status of the GitLab CI test suite
- [Cross-platform Go Test Workflow](../.github/workflows/go-test.yml) - GitHub Actions matrix that runs `go test -race -count=1 ./...` on `ubuntu-latest`, `macos-latest`, and `windows-latest`. The `tests/integration/` package is excluded from the test step (Windows-only files have separate pre-existing bugs); `vet` and `build` still cover them. Run locally with `make test` (which targets `./internal/...`).

### 🚀 Deployment & CI/CD
- [GitLab Integration](GITLAB_INTEGRATION.md) - GitLab Ultimate integration guide
- [GitLab CI/CD Setup](deployment/GITLAB_CI_SETUP.md) - Pipeline configuration and usage
- [🆕 GitLab Security Scanner Setup](deployment/GITLAB_SECURITY_SCANNER_SETUP.md) - Complete GitLab SAST integration guide

### 🛠 Development
- [Creating Validators](development/creating_validators.md) - Developer guide for new validators
- [Debug Logging](development/debug_logging.md) - Troubleshooting and debugging
- [Text Extraction Integration](development/text_extraction_integration.md) - Document processing
- [🆕 Content Router Architecture](development/content-router-architecture.md) - Enhanced content routing and dual-path validation
- [🆕 Preprocessor-Aware Validation](development/preprocessor-aware-validation.md) - Validation rules and confidence scoring
- [🆕 Enhanced Processing Sequence](development/enhanced-processing-sequence.md) - Updated processing flow with content routing
- [🆕 Content Routing Troubleshooting](development/content-routing-troubleshooting.md) - Troubleshooting guide for enhanced architecture
- [🆕 Context Analysis Integration](development/context-analysis-integration.md) - Context engine integration and data flow
- [🆕 Enhanced Metadata Validation](development/enhanced-metadata-validation.md) - Preprocessor-aware metadata validation guide
- [🆕 FileRouter Metadata Capabilities](development/file-router-metadata-capabilities.md) - File type detection and metadata capability methods
<!-- GENAI_DISABLED: - [GenAI Integration](development/genai_integration.md) - AI-powered features overview -->
<!-- GENAI_DISABLED: - [GenAI Implementation](development/genai_implementation_summary.md) - Textract OCR implementation -->
<!-- GENAI_DISABLED: - [Comprehend Implementation](development/comprehend_implementation_summary.md) - AI PII detection -->

### 📖 Reference
- [Quotas and Limits](reference/quotas-and-limits.md) - File size limits and system constraints
- [Changelog](reference/CHANGELOG.md) - Version history and updates
- [Implementation Status](reference/IMPLEMENTATION_STATUS.md) - Current feature status
- [Suppression System Improvements](reference/SUPPRESSION_SYSTEM_IMPROVEMENTS.md) - Recent suppression fixes

### 🔧 Troubleshooting
- [🆕 GitLab Integration Troubleshooting](troubleshooting/GITLAB_INTEGRATION_TROUBLESHOOTING.md) - Common GitLab integration issues and solutions

## 🔍 Quick Navigation

### By Use Case
- **New Users**: Start with [Main README](../README.md) → [Configuration Guide](configuration.md)
- **Developers**: [Creating Validators](development/creating_validators.md) → run `make test` and check the [cross-platform Go Test Workflow](../.github/workflows/go-test.yml)
- **DevOps/CI**: [GitLab Integration](GITLAB_INTEGRATION.md) → [GitLab Security Scanner Setup](deployment/GITLAB_SECURITY_SCANNER_SETUP.md)
- **Web Interface**: [Web UI Guide](user-guides/README-WebUI.md) → [Docker Guide](user-guides/README-Docker.md)
- **Testing**: [GitLab CI Testing Tracker](testing/GITLAB_CI_TESTING_TRACKER.md) — `make test` runs the full Go suite locally; CI runs `go test -race ./...` on Linux/macOS/Windows

### By Topic
- **🔧 Configuration**: [Configuration Guide](configuration.md)
- **🐳 Docker**: [Docker Guide](user-guides/README-Docker.md)
- **🌐 Web UI**: [Web UI Guide](user-guides/README-WebUI.md)
- **🆕 Enhanced Metadata**: [Enhanced Metadata Guide](user-guides/README-Enhanced-Metadata.md)
- **🆕 Stdin / Gateway**: [Stdin Guide](user-guides/README-Stdin.md)
- **🔒 Redaction**: [Redaction Guide](user-guides/README-Redaction.md)
<!-- GENAI_DISABLED: - **🤖 AI Features**: [GenAI Integration](development/genai_integration.md) -->
- **🧪 Testing**: [GitLab CI Testing Tracker](testing/GITLAB_CI_TESTING_TRACKER.md)
- **🚀 Deployment**: [GitLab Security Scanner Setup](deployment/GITLAB_SECURITY_SCANNER_SETUP.md)
- **🔧 Troubleshooting**: [GitLab Integration Troubleshooting](troubleshooting/GITLAB_INTEGRATION_TROUBLESHOOTING.md)

## 📋 Document Status

Documents in this index are kept in sync with the codebase as features land. The CHANGELOG at the root of the repo is the source of truth for what shipped in each release; the per-topic guides above describe how each feature works in the current version.

## 🤝 Contributing to Documentation

When adding new documentation:

1. **Place in appropriate folder**: `user-guides/`, `development/`, `testing/`, `deployment/`, or `reference/`
2. **Add navigation links**: Include `[← Back to Documentation Index](../README.md)` at the top
3. **Update this index**: Add your document to the appropriate section above
4. **Follow naming conventions**: Use descriptive, kebab-case filenames
5. **Include relative links**: Link to related documents using relative paths

## 📞 Support

- **Issues**: Report bugs and feature requests in the project issue tracker
- **Questions**: Use the project discussions or internal channels
- **Documentation**: Improvements and corrections are welcome via merge requests

---

*This documentation is maintained alongside the Ferret Scan codebase.*
