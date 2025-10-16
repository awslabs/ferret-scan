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
- [Suppression System](user-guides/README-Suppressions.md) - Managing false positives
- [Suppression Architecture](suppression-system.md) - Technical suppression system details

### 🧪 Testing & Quality Assurance
- [Testing Guide](testing/TESTING.md) - Comprehensive testing documentation
- [Testing Strategy](testing/testing-strategy.md) - Overall testing approach and architecture
- [Implementation Summary](testing/TESTING_IMPLEMENTATION_SUMMARY.md) - What was implemented
- [Success Summary](testing/TESTING_SUCCESS_SUMMARY.md) - Final results and achievements

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
- [Battle Card](battle-card.md) - Competitive analysis and positioning
- [Quotas and Limits](reference/quotas-and-limits.md) - File size limits and system constraints
- [Changelog](reference/CHANGELOG.md) - Version history and updates
- [Implementation Status](reference/IMPLEMENTATION_STATUS.md) - Current feature status
- [Suppression System Improvements](reference/SUPPRESSION_SYSTEM_IMPROVEMENTS.md) - Recent suppression fixes

### 🔧 Troubleshooting
- [🆕 GitLab Integration Troubleshooting](troubleshooting/GITLAB_INTEGRATION_TROUBLESHOOTING.md) - Common GitLab integration issues and solutions

## 🔍 Quick Navigation

### By Use Case
- **New Users**: Start with [Main README](../README.md) → [Configuration Guide](configuration.md)
- **Developers**: [Creating Validators](development/creating_validators.md) → [Testing Guide](testing/TESTING.md)
- **DevOps/CI**: [GitLab Integration](GITLAB_INTEGRATION.md) → [GitLab Security Scanner Setup](deployment/GITLAB_SECURITY_SCANNER_SETUP.md)
- **Web Interface**: [Web UI Guide](user-guides/README-WebUI.md) → [Docker Guide](user-guides/README-Docker.md)
- **Testing**: [Testing Guide](testing/TESTING.md) → [Testing Strategy](testing/testing-strategy.md)

### By Topic
- **🔧 Configuration**: [Configuration Guide](configuration.md)
- **🐳 Docker**: [Docker Guide](user-guides/README-Docker.md)
- **🌐 Web UI**: [Web UI Guide](user-guides/README-WebUI.md)
- **🆕 Enhanced Metadata**: [Enhanced Metadata Guide](user-guides/README-Enhanced-Metadata.md)
<!-- GENAI_DISABLED: - **🤖 AI Features**: [GenAI Integration](development/genai_integration.md) -->
- **🧪 Testing**: [Testing Guide](testing/TESTING.md)
- **🚀 Deployment**: [GitLab Security Scanner Setup](deployment/GITLAB_SECURITY_SCANNER_SETUP.md)
- **🔧 Troubleshooting**: [GitLab Integration Troubleshooting](troubleshooting/GITLAB_INTEGRATION_TROUBLESHOOTING.md)

## 📋 Document Status

| Category | Documents | Status |
|----------|-----------|---------|
| User Guides | 4 | ✅ Complete |
| Development | 12 | ✅ Complete |
| Testing | 4 | ✅ Complete |
| Deployment | 3 | ✅ Complete |
| Reference | 5 | ✅ Complete |
| Troubleshooting | 1 | ✅ Complete |
| **Total** | **29** | **✅ Complete** |

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

*This documentation is maintained alongside the Ferret Scan codebase. Last updated: $(date)*
