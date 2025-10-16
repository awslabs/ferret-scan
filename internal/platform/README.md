# Platform Abstraction Layer

This package provides a platform abstraction layer for Ferret Scan, enabling cross-platform compatibility between Windows and Unix-like systems (Linux, macOS).

## Overview

The platform package abstracts platform-specific operations such as:
- Configuration directory resolution
- Path handling and normalization
- Executable extensions
- Installation directories
- Platform capabilities (symlinks, case sensitivity)

## Usage

### Basic Platform Detection

```go
import "ferret-scan/internal/platform"

// Get the current platform implementation
platform := platform.GetPlatform()

// Check if running on Windows
if platform.IsWindows() {
    // Windows-specific code
}

// Check if running on Unix-like system
if platform.IsUnix() {
    // Unix-specific code
}
```

### Configuration Directories

```go
// Get platform-appropriate config directory
configDir := platform.GetConfigDir()
// Windows: %APPDATA%\ferret-scan or %USERPROFILE%\.ferret-scan
// Unix: ~/.ferret-scan or $XDG_CONFIG_HOME/ferret-scan

// Get temporary directory
tempDir := platform.GetTempDir()
// Windows: %TEMP% or %TMP%
// Unix: $TMPDIR or /tmp
```

### Path Operations

```go
// Normalize paths for the current platform
path := platform.NormalizePath("test/path/file.txt")
// Windows: test\path\file.txt
// Unix: test/path/file.txt

// Check if path is absolute
isAbs := platform.IsAbsolutePath("/home/user/file.txt")
// Windows: false (not a Windows absolute path)
// Unix: true

// Get platform-specific path separator
sep := platform.GetPathSeparator()
// Windows: "\"
// Unix: "/"
```

### Installation Directories

```go
// Get system-wide installation directory
systemDir := platform.GetSystemInstallDir()
// Windows: C:\Program Files\ferret-scan
// Unix: /usr/local/bin

// Get user-specific installation directory
userDir := platform.GetUserInstallDir()
// Windows: %LOCALAPPDATA%\Programs\ferret-scan
// Unix: ~/.local/bin
```

### Platform Configuration

```go
// Get complete platform configuration
config := platform.GetConfig()

fmt.Printf("OS: %s\n", config.OS)
fmt.Printf("Architecture: %s\n", config.Architecture)
fmt.Printf("Config Directory: %s\n", config.ConfigDirectory)
fmt.Printf("Supports Symlinks: %v\n", config.SupportsSymlinks)
fmt.Printf("Case Sensitive Paths: %v\n", config.CaseSensitivePaths)
```

## Platform Implementations

### Windows Platform

- **Config Directory**: Uses `%APPDATA%\ferret-scan` or falls back to `%USERPROFILE%\.ferret-scan`
- **Temp Directory**: Uses `%TEMP%` or `%TMP%`
- **Executable Extension**: `.exe`
- **Path Separator**: `\`
- **Case Sensitivity**: False (Windows is case-insensitive by default)
- **Symlinks**: True (supported in Windows 10+ with appropriate permissions)
- **UNC Paths**: Supported (\\server\share format)

### Unix Platform

- **Config Directory**: Uses `~/.ferret-scan` or `$XDG_CONFIG_HOME/ferret-scan`
- **Temp Directory**: Uses `$TMPDIR` or `/tmp`
- **Executable Extension**: None (empty string)
- **Path Separator**: `/`
- **Case Sensitivity**: True (Unix filesystems are case-sensitive)
- **Symlinks**: True (full symlink support)

## Environment Variables

The platform layer respects the following environment variables:

### Cross-Platform
- `FERRET_CONFIG_DIR`: Override for configuration directory

### Windows-Specific
- `APPDATA`: Application data directory
- `USERPROFILE`: User profile directory
- `LOCALAPPDATA`: Local application data directory
- `PROGRAMFILES`: Program Files directory
- `TEMP`, `TMP`: Temporary directories

### Unix-Specific
- `XDG_CONFIG_HOME`: XDG configuration directory
- `TMPDIR`, `TMP`: Temporary directories
- `HOME`: User home directory

## Testing

The package includes comprehensive tests for both Windows and Unix platforms:

```bash
# Run all platform tests
go test ./internal/platform -v

# Run with coverage
go test ./internal/platform -cover

# Run Windows-specific tests (on Windows)
go test ./internal/platform -v -tags windows

# Run Unix-specific tests (on Unix)
go test ./internal/platform -v -tags !windows
```

## Integration

To integrate the platform abstraction layer into existing code:

1. Replace hardcoded path operations with platform-aware methods
2. Use `platform.GetConfigDir()` instead of hardcoded config paths
3. Use `platform.NormalizePath()` for all path operations
4. Check platform capabilities before using platform-specific features

Example migration:

```go
// Before
configDir := filepath.Join(os.Getenv("HOME"), ".ferret-scan")

// After
platform := platform.GetPlatform()
configDir := platform.GetConfigDir()
```

This ensures your code works correctly across all supported platforms.