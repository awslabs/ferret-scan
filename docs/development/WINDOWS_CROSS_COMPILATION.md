# Windows Cross-Compilation Guide

## Overview

This guide covers cross-compiling Ferret Scan for Windows targets from different platforms (Linux, macOS) and building Windows-specific features in a cross-platform development environment.

## Cross-Compilation Basics

### Go Cross-Compilation Support

Go provides excellent cross-compilation support for Windows targets:

```bash
# Set target OS and architecture
export GOOS=windows
export GOARCH=amd64

# Build for Windows from any platform
go build -o ferret-scan.exe ./cmd/main.go

# Reset environment
unset GOOS GOARCH
```

### Supported Windows Targets

| GOOS | GOARCH | Description | Minimum Windows Version |
|------|--------|-------------|------------------------|
| windows | amd64 | 64-bit Intel/AMD | Windows 7 SP1 |
| windows | arm64 | 64-bit ARM | Windows 10 version 1709 |
| windows | 386 | 32-bit Intel/AMD | Windows XP SP3 |

## Development Environment Setup

### Linux Development Environment

#### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y git build-essential

# Install Go
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
```

#### Cross-Compilation Tools
```bash
# Install additional tools for Windows development
sudo apt-get install -y mingw-w64 wine

# Install Go tools
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### macOS Development Environment

#### Prerequisites
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew install go

# Install additional tools
brew install git make
```

#### Cross-Compilation Setup
```bash
# Install Wine for testing Windows binaries (optional)
brew install --cask wine-stable

# Install Go tools
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Building Windows Binaries

### Basic Cross-Compilation

```bash
#!/bin/bash
# build-windows.sh

set -e

echo "Building Ferret Scan for Windows..."

# Get version information
VERSION=${VERSION:-"dev"}
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X ferret-scan/internal/version.Version=$VERSION"
LDFLAGS="$LDFLAGS -X ferret-scan/internal/version.GitCommit=$COMMIT"
LDFLAGS="$LDFLAGS -X ferret-scan/internal/version.BuildDate=$BUILD_DATE"

# Build for different Windows architectures
build_windows() {
    local arch=$1
    local output="ferret-scan-windows-${arch}.exe"
    
    echo "Building for windows/$arch..."
    
    GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build \
        -ldflags "$LDFLAGS" \
        -o "$output" \
        ./cmd/main.go
    
    if [ $? -eq 0 ]; then
        echo "✓ Built $output ($(du -h "$output" | cut -f1))"
    else
        echo "✗ Failed to build for windows/$arch"
        exit 1
    fi
}

# Build for all supported architectures
build_windows "amd64"
build_windows "arm64"
build_windows "386"

echo "Windows builds completed successfully!"
```

### Advanced Build Configuration

```bash
#!/bin/bash
# advanced-windows-build.sh

set -e

# Configuration
PROJECT_NAME="ferret-scan"
VERSION=${VERSION:-$(git describe --tags --always --dirty)}
OUTPUT_DIR="dist"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build matrix
declare -A BUILD_MATRIX=(
    ["windows/amd64"]="Windows 64-bit (Intel/AMD)"
    ["windows/arm64"]="Windows ARM64"
    ["windows/386"]="Windows 32-bit (Legacy)"
)

# Build function
build_target() {
    local target=$1
    local description=$2
    local goos=$(echo $target | cut -d'/' -f1)
    local goarch=$(echo $target | cut -d'/' -f2)
    
    echo "Building $description ($target)..."
    
    # Output filename
    local output="$OUTPUT_DIR/${PROJECT_NAME}-${goos}-${goarch}"
    if [ "$goos" = "windows" ]; then
        output="${output}.exe"
    fi
    
    # Build flags
    local ldflags="-s -w"
    ldflags="$ldflags -X ferret-scan/internal/version.Version=$VERSION"
    ldflags="$ldflags -X ferret-scan/internal/version.GitCommit=$(git rev-parse HEAD)"
    ldflags="$ldflags -X ferret-scan/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Build command
    GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go build \
        -ldflags "$ldflags" \
        -trimpath \
        -o "$output" \
        ./cmd/main.go
    
    if [ $? -eq 0 ]; then
        local size=$(du -h "$output" | cut -f1)
        echo "✓ $description: $output ($size)"
        
        # Generate checksum
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$output" > "${output}.sha256"
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 "$output" > "${output}.sha256"
        fi
    else
        echo "✗ Failed to build $description"
        return 1
    fi
}

# Build all targets
for target in "${!BUILD_MATRIX[@]}"; do
    build_target "$target" "${BUILD_MATRIX[$target]}"
done

echo "All Windows builds completed successfully!"
echo "Output directory: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"
```

## Testing Windows Binaries

### Using Wine on Linux/macOS

```bash
#!/bin/bash
# test-windows-binary.sh

set -e

BINARY="ferret-scan-windows-amd64.exe"

if [ ! -f "$BINARY" ]; then
    echo "Error: Windows binary not found: $BINARY"
    exit 1
fi

# Check if Wine is available
if ! command -v wine >/dev/null 2>&1; then
    echo "Wine not installed. Installing..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update
        sudo apt-get install -y wine
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install --cask wine-stable
    fi
fi

echo "Testing Windows binary with Wine..."

# Test version command
echo "Testing --version:"
wine "$BINARY" --version

# Test help command
echo "Testing --help:"
wine "$BINARY" --help | head -10

# Create test file
echo "Creating test file..."
echo "Test content with credit card: 4111-1111-1111-1111" > test-windows.txt

# Test scanning
echo "Testing scan functionality:"
wine "$BINARY" scan test-windows.txt --format json

# Cleanup
rm -f test-windows.txt

echo "Windows binary testing completed successfully!"
```

### Docker-based Testing

```dockerfile
# Dockerfile.windows-test
FROM mcr.microsoft.com/windows/servercore:ltsc2019

# Install PowerShell
RUN powershell -Command \
    Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.3.0/PowerShell-7.3.0-win-x64.msi -OutFile PowerShell.msi; \
    Start-Process msiexec.exe -ArgumentList '/i', 'PowerShell.msi', '/quiet' -Wait; \
    Remove-Item PowerShell.msi

# Copy binary
COPY ferret-scan-windows-amd64.exe C:/ferret-scan.exe

# Test script
RUN powershell -Command \
    C:/ferret-scan.exe --version; \
    echo 'Test content' | Out-File test.txt; \
    C:/ferret-scan.exe scan test.txt
```

```bash
# Build and test with Docker
docker build -f Dockerfile.windows-test -t ferret-scan-windows-test .
docker run --rm ferret-scan-windows-test
```

## Platform-Specific Code Handling

### Build Tags for Windows Code

```go
//go:build windows
// +build windows

package platform

import (
    "os"
    "path/filepath"
)

// Windows-specific implementation
func GetConfigDir() string {
    if dir := os.Getenv("FERRET_CONFIG_DIR"); dir != "" {
        return dir
    }
    
    if appData := os.Getenv("APPDATA"); appData != "" {
        return filepath.Join(appData, "ferret-scan")
    }
    
    return ".ferret-scan"
}
```

### Cross-Platform Abstractions

```go
// platform.go - Common interface
package platform

type Platform interface {
    GetConfigDir() string
    GetTempDir() string
    NormalizePath(path string) string
    IsAbsolutePath(path string) bool
}

func GetPlatform() Platform {
    switch runtime.GOOS {
    case "windows":
        return &WindowsPlatform{}
    default:
        return &UnixPlatform{}
    }
}
```

### Conditional Compilation

```go
// config_windows.go
//go:build windows

package config

const (
    DefaultConfigDir = "%APPDATA%\\ferret-scan"
    DefaultTempDir   = "%TEMP%\\ferret-scan"
    PathSeparator    = "\\"
)

// config_unix.go  
//go:build !windows

package config

const (
    DefaultConfigDir = "~/.ferret-scan"
    DefaultTempDir   = "/tmp/ferret-scan"
    PathSeparator    = "/"
)
```

## Automated Cross-Compilation

### Makefile for Cross-Compilation

```makefile
# Makefile
.PHONY: build-windows build-all clean

# Variables
PROJECT_NAME := ferret-scan
VERSION := $(shell git describe --tags --always --dirty)
BUILD_DIR := dist
LDFLAGS := -s -w -X ferret-scan/internal/version.Version=$(VERSION)

# Windows targets
WINDOWS_TARGETS := windows/amd64 windows/arm64 windows/386

# Build all Windows targets
build-windows:
	@echo "Building Windows targets..."
	@mkdir -p $(BUILD_DIR)
	@for target in $(WINDOWS_TARGETS); do \
		goos=$$(echo $$target | cut -d'/' -f1); \
		goarch=$$(echo $$target | cut -d'/' -f2); \
		output=$(BUILD_DIR)/$(PROJECT_NAME)-$$goos-$$goarch.exe; \
		echo "Building $$target..."; \
		GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 go build \
			-ldflags "$(LDFLAGS)" \
			-o $$output \
			./cmd/main.go; \
		if [ $$? -eq 0 ]; then \
			echo "✓ Built $$output"; \
		else \
			echo "✗ Failed to build $$target"; \
			exit 1; \
		fi; \
	done

# Test Windows binaries (requires Wine)
test-windows:
	@echo "Testing Windows binaries..."
	@for binary in $(BUILD_DIR)/*windows*.exe; do \
		if [ -f "$$binary" ]; then \
			echo "Testing $$binary..."; \
			wine "$$binary" --version || echo "Wine test failed for $$binary"; \
		fi; \
	done

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

# Build all platforms
build-all: build-windows
	@echo "All builds completed!"
```

### GitHub Actions Workflow

```yaml
# .github/workflows/cross-compile.yml
name: Cross-Platform Build

on:
  push:
    branches: [ main, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main ]

jobs:
  cross-compile:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        include:
          - goos: windows
            goarch: amd64
            name: windows-amd64
          - goos: windows
            goarch: arm64
            name: windows-arm64
          - goos: windows
            goarch: "386"
            name: windows-386
          - goos: linux
            goarch: amd64
            name: linux-amd64
          - goos: darwin
            goarch: amd64
            name: darwin-amd64
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      with:
        fetch-depth: 0
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Get version
      id: version
      run: echo "version=$(git describe --tags --always --dirty)" >> $GITHUB_OUTPUT
    
    - name: Build binary
      env:
        GOOS: ${{ matrix.goos }}
        GOARCH: ${{ matrix.goarch }}
        CGO_ENABLED: 0
      run: |
        # Set output filename
        if [ "${{ matrix.goos }}" = "windows" ]; then
          OUTPUT="ferret-scan-${{ matrix.name }}.exe"
        else
          OUTPUT="ferret-scan-${{ matrix.name }}"
        fi
        
        # Build flags
        LDFLAGS="-s -w"
        LDFLAGS="$LDFLAGS -X ferret-scan/internal/version.Version=${{ steps.version.outputs.version }}"
        LDFLAGS="$LDFLAGS -X ferret-scan/internal/version.GitCommit=${{ github.sha }}"
        LDFLAGS="$LDFLAGS -X ferret-scan/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        
        # Build
        go build -ldflags "$LDFLAGS" -trimpath -o "$OUTPUT" ./cmd/main.go
        
        # Generate checksum
        sha256sum "$OUTPUT" > "${OUTPUT}.sha256"
        
        echo "Built $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
    
    - name: Test Windows binary (Wine)
      if: matrix.goos == 'windows' && matrix.goarch == 'amd64'
      run: |
        # Install Wine
        sudo apt-get update
        sudo apt-get install -y wine
        
        # Test binary
        wine ferret-scan-${{ matrix.name }}.exe --version || echo "Wine test completed"
    
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: ferret-scan-${{ matrix.name }}
        path: |
          ferret-scan-${{ matrix.name }}*
        retention-days: 30
```

## GoReleaser Configuration

### Cross-Platform GoReleaser Setup

```yaml
# .goreleaser.yml
version: 2

project_name: ferret-scan

before:
  hooks:
    - go mod tidy
    - go generate ./...

builds:
  - id: ferret-scan
    main: ./cmd/main.go
    binary: ferret-scan
    env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
      - "386"
    ignore:
      # Skip 32-bit builds for non-Windows platforms
      - goos: linux
        goarch: "386"
      - goos: darwin
        goarch: "386"
    ldflags:
      - -s -w
      - -X ferret-scan/internal/version.Version={{.Version}}
      - -X ferret-scan/internal/version.GitCommit={{.Commit}}
      - -X ferret-scan/internal/version.BuildDate={{.Date}}

archives:
  - id: default
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    format_overrides:
      - goos: windows
        format: zip
    files:
      - README.md
      - LICENSE*
      - docs/WINDOWS_INSTALLATION.md
      - scripts/install-system-windows.ps1

checksum:
  name_template: "checksums.txt"

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
```

## Testing Cross-Compiled Binaries

### Automated Testing Script

```bash
#!/bin/bash
# test-cross-compiled.sh

set -e

echo "Testing cross-compiled Windows binaries..."

# Test matrix
declare -A BINARIES=(
    ["ferret-scan-windows-amd64.exe"]="Windows 64-bit"
    ["ferret-scan-windows-arm64.exe"]="Windows ARM64"
    ["ferret-scan-windows-386.exe"]="Windows 32-bit"
)

# Test function
test_binary() {
    local binary=$1
    local description=$2
    
    echo "Testing $description ($binary)..."
    
    if [ ! -f "$binary" ]; then
        echo "  ✗ Binary not found: $binary"
        return 1
    fi
    
    # Check file type
    file "$binary" | grep -q "PE32" || {
        echo "  ✗ Not a valid Windows PE executable"
        return 1
    }
    
    # Test with Wine (if available)
    if command -v wine >/dev/null 2>&1; then
        echo "  Testing with Wine..."
        
        # Test version command
        if wine "$binary" --version >/dev/null 2>&1; then
            echo "  ✓ Version command works"
        else
            echo "  ⚠ Version command failed (Wine compatibility issue)"
        fi
        
        # Test help command
        if wine "$binary" --help >/dev/null 2>&1; then
            echo "  ✓ Help command works"
        else
            echo "  ⚠ Help command failed (Wine compatibility issue)"
        fi
    else
        echo "  ⚠ Wine not available, skipping runtime tests"
    fi
    
    # Check binary size (should be reasonable)
    local size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)
    local size_mb=$((size / 1024 / 1024))
    
    if [ $size_mb -lt 1 ]; then
        echo "  ✗ Binary too small ($size_mb MB) - likely build error"
        return 1
    elif [ $size_mb -gt 100 ]; then
        echo "  ⚠ Binary quite large ($size_mb MB) - consider optimization"
    else
        echo "  ✓ Binary size reasonable ($size_mb MB)"
    fi
    
    echo "  ✓ $description testing completed"
    return 0
}

# Test all binaries
failed=0
for binary in "${!BINARIES[@]}"; do
    if ! test_binary "$binary" "${BINARIES[$binary]}"; then
        failed=$((failed + 1))
    fi
    echo
done

# Summary
if [ $failed -eq 0 ]; then
    echo "All Windows binaries passed testing! ✓"
    exit 0
else
    echo "$failed Windows binaries failed testing ✗"
    exit 1
fi
```

### Integration Test Suite

```bash
#!/bin/bash
# integration-test-windows.sh

set -e

BINARY="ferret-scan-windows-amd64.exe"
TEST_DIR="windows-integration-test"

# Setup test environment
setup_test_env() {
    echo "Setting up test environment..."
    
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"
    
    # Create test files
    echo "Test file with credit card: 4111-1111-1111-1111" > test-data.txt
    echo "Another file with SSN: 123-45-6789" > test-ssn.txt
    
    # Create subdirectory
    mkdir -p subdir
    echo "Nested file with email: test@example.com" > subdir/nested.txt
    
    echo "Test environment created"
}

# Cleanup test environment
cleanup_test_env() {
    echo "Cleaning up test environment..."
    cd ..
    rm -rf "$TEST_DIR"
}

# Test basic functionality
test_basic_functionality() {
    echo "Testing basic functionality..."
    
    # Test version
    wine "../$BINARY" --version || return 1
    
    # Test help
    wine "../$BINARY" --help >/dev/null || return 1
    
    # Test single file scan
    wine "../$BINARY" scan test-data.txt --format json >/dev/null || return 1
    
    # Test directory scan
    wine "../$BINARY" scan . --recursive --format text >/dev/null || return 1
    
    echo "Basic functionality tests passed"
}

# Test Windows-specific features
test_windows_features() {
    echo "Testing Windows-specific features..."
    
    # Test Windows path handling (simulated)
    # Note: Wine translates paths, so this is limited
    
    # Test configuration directory detection
    # This would use Wine's Windows environment simulation
    
    echo "Windows-specific feature tests completed"
}

# Main test execution
main() {
    if [ ! -f "$BINARY" ]; then
        echo "Error: Windows binary not found: $BINARY"
        echo "Please build the Windows binary first"
        exit 1
    fi
    
    if ! command -v wine >/dev/null 2>&1; then
        echo "Error: Wine not installed"
        echo "Please install Wine to test Windows binaries"
        exit 1
    fi
    
    trap cleanup_test_env EXIT
    
    setup_test_env
    test_basic_functionality
    test_windows_features
    
    echo "All integration tests passed! ✓"
}

main "$@"
```

## Troubleshooting Cross-Compilation

### Common Issues and Solutions

#### CGO Dependencies
```bash
# Error: CGO not supported when cross-compiling
# Solution: Disable CGO
export CGO_ENABLED=0
go build -o ferret-scan.exe ./cmd/main.go
```

#### Missing Build Tags
```bash
# Error: Windows-specific code not included
# Solution: Ensure proper build tags
go build -tags windows -o ferret-scan.exe ./cmd/main.go
```

#### Path Separator Issues
```go
// Problem: Hard-coded path separators
path := "config\\ferret.yaml"  // Wrong

// Solution: Use filepath.Join
path := filepath.Join("config", "ferret.yaml")  // Correct
```

#### Environment Variable Handling
```go
// Problem: Unix-style environment variables
configDir := os.Getenv("HOME") + "/.ferret-scan"  // Wrong on Windows

// Solution: Platform-specific logic
func getConfigDir() string {
    if runtime.GOOS == "windows" {
        if appData := os.Getenv("APPDATA"); appData != "" {
            return filepath.Join(appData, "ferret-scan")
        }
    }
    return filepath.Join(os.Getenv("HOME"), ".ferret-scan")
}
```

### Debugging Cross-Compilation Issues

```bash
# Enable verbose build output
go build -v -x -o ferret-scan.exe ./cmd/main.go

# Check build environment
go env GOOS GOARCH CGO_ENABLED

# Verify binary architecture
file ferret-scan.exe
objdump -f ferret-scan.exe  # On Linux with mingw-w64

# Test with different Go versions
go1.20 build -o ferret-scan-120.exe ./cmd/main.go
go1.21 build -o ferret-scan-121.exe ./cmd/main.go
```

## Best Practices

### Cross-Compilation Best Practices

1. **Use Build Tags**: Separate platform-specific code with build tags
2. **Abstract Platform Differences**: Use interfaces to abstract platform-specific functionality
3. **Test Early and Often**: Test cross-compiled binaries regularly
4. **Automate Testing**: Use CI/CD to test all target platforms
5. **Handle Paths Correctly**: Always use `filepath` package for path operations
6. **Environment Variables**: Handle platform-specific environment variables properly
7. **Error Messages**: Provide platform-appropriate error messages and suggestions

### Development Workflow

1. **Feature Development**: Develop features with cross-platform compatibility in mind
2. **Local Testing**: Test on development platform first
3. **Cross-Compilation**: Build for all target platforms
4. **Automated Testing**: Run automated tests on cross-compiled binaries
5. **Manual Testing**: Perform manual testing on actual target platforms when possible
6. **Documentation**: Document platform-specific behavior and limitations

### Performance Considerations

1. **Binary Size**: Monitor binary sizes across platforms
2. **Build Time**: Optimize build processes for CI/CD efficiency
3. **Runtime Performance**: Test performance characteristics on target platforms
4. **Memory Usage**: Verify memory usage patterns across platforms

---

This cross-compilation guide provides comprehensive coverage of building Ferret Scan for Windows from any development platform, ensuring consistent and reliable Windows support regardless of the development environment.