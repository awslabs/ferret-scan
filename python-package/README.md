# Ferret Scan Python Package

A Python wrapper for [Ferret Scan](https://github.com/awslabs/ferret-scan), a sensitive data detection tool. This package provides easy installation and seamless pre-commit hook integration.

## Installation

```bash
pip install ferret-scan
```

## Usage

### Command Line

After installation, use `ferret-scan` exactly like the native binary:

```bash
# Basic scan
ferret-scan --file document.txt

# JSON output
ferret-scan --file document.txt --format json

# Quiet mode for scripts
ferret-scan --file document.txt --quiet

# Pre-commit mode with optimizations
ferret-scan --pre-commit-mode --confidence high,medium --checks all
```

### Pre-commit Hook

Ferret Scan provides multiple pre-commit hook configurations for different security requirements. Add to your `.pre-commit-config.yaml`:

#### Default Configuration (Recommended)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan
```

#### Strict Security (Blocks on high confidence findings)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan-strict
```

#### Advisory Mode (Shows findings but never blocks)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan-advisory
```

#### Secrets Only (Focus on API keys and tokens)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan-secrets
```

#### Financial Data (Credit cards and financial info)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan-financial
```

#### PII Detection (SSN, passport, email)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan-pii
```

#### Metadata Check (Document metadata scanning)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan-metadata
```

#### CI/CD Optimized (Structured output for pipelines)
```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan-ci
```

#### Custom Configuration
You can also customize any hook with additional arguments:

```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v1.0.0
    hooks:
      - id: ferret-scan
        args: ['--confidence', 'high', '--checks', 'CREDIT_CARD,SECRETS', '--verbose']
```

#### Local Installation
For local installations, use the `ferret-scan` command directly:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan - Sensitive Data Detection
        entry: ferret-scan
        language: system
        files: '\.(txt|py|js|ts|go|java|json|yaml|yml|md|csv|log|conf|config|ini|env)$'
        args: ['--pre-commit-mode', '--confidence', 'high,medium']
```

## How It Works

This Python package:

1. **Automatic Binary Download**: Downloads the appropriate ferret-scan binary for your platform (Linux/macOS/Windows, x86_64/ARM64)
2. **Transparent Execution**: Passes all arguments directly to the native binary
3. **Cross-Platform**: Works on all platforms supported by ferret-scan
4. **Pre-commit Ready**: Integrates seamlessly with pre-commit hooks with automatic optimizations

## Supported Platforms

- **Linux**: x86_64, ARM64
- **macOS**: x86_64 (Intel), ARM64 (Apple Silicon)
- **Windows**: x86_64, ARM64

## Features

All features of the native ferret-scan binary are available:

- **Sensitive Data Detection**: Credit cards, passports, SSNs, API keys, etc.
- **Multiple Formats**: Text, JSON, CSV, YAML, JUnit, GitLab SAST output
- **Document Processing**: PDF, Office documents, images
- **Pre-commit Optimizations**: Automatic quiet mode, no colors, appropriate exit codes
- **Suppression Rules**: Manage false positives
- **Configuration**: YAML config files and profiles
- **Redaction**: Remove sensitive data from documents

## Command Line Options

The Python package supports all command-line options of the native binary:

- `--file`: Input file, directory, or glob pattern
- `--format`: Output format (text, json, csv, yaml, junit, gitlab-sast)
- `--confidence`: Confidence levels (high, medium, low, combinations)
- `--checks`: Specific checks to run (CREDIT_CARD, SECRETS, SSN, etc.)
- `--pre-commit-mode`: Enable pre-commit optimizations
- `--verbose`: Detailed information for findings
- `--quiet`: Suppress progress output
- `--no-color`: Disable colored output
- `--recursive`: Recursively scan directories
- `--enable-preprocessors`: Enable document text extraction
- `--config`: Configuration file path
- `--profile`: Configuration profile name

## Requirements

- Python 3.7+
- Internet connection (for initial binary download)

## License

Apache License 2.0 - see the [LICENSE](https://github.com/awslabs/ferret-scan/blob/main/LICENSE) file for details.

## Contributing

See the main [Ferret Scan repository](https://github.com/awslabs/ferret-scan) for contribution guidelines.