# Windows Development Guide

## Overview

This guide covers developing Ferret Scan on Windows systems, including setting up the development environment, building, testing, and debugging Windows-specific features.

## Development Environment Setup

### Prerequisites

#### Required Software
- **Go 1.21+**: Download from [golang.org](https://golang.org/dl/)
- **Git for Windows**: Download from [git-scm.com](https://git-scm.com/download/win)
- **PowerShell 7+**: Download from [GitHub](https://github.com/PowerShell/PowerShell/releases)
- **Windows Terminal**: Install from Microsoft Store (recommended)

#### Recommended Tools
- **Visual Studio Code**: With Go extension
- **GoLand**: JetBrains IDE for Go development
- **Windows Subsystem for Linux (WSL2)**: For cross-platform testing
- **Docker Desktop**: For containerized development

#### Optional Tools
- **Make for Windows**: For using Makefiles
- **Chocolatey**: Package manager for Windows
- **Scoop**: Command-line installer for Windows

### Installation Steps

#### Install Go
```powershell
# Download and install Go from golang.org
# Or use Chocolatey
choco install golang

# Or use Scoop
scoop install go

# Verify installation
go version
```

#### Install Git
```powershell
# Download from git-scm.com
# Or use Chocolatey
choco install git

# Configure Git
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

#### Install Development Tools
```powershell
# Install Visual Studio Code
choco install vscode

# Install Go extension for VS Code
code --install-extension golang.go

# Install PowerShell 7
choco install powershell-core

# Install Windows Terminal
# Available from Microsoft Store or GitHub releases
```

### Environment Configuration

#### Set Environment Variables
```powershell
# Set GOPATH (if not using Go modules)
[Environment]::SetEnvironmentVariable("GOPATH", "C:\Go", "User")

# Add Go bin to PATH
$GoPath = [Environment]::GetEnvironmentVariable("GOPATH", "User")
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
[Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$GoPath\bin", "User")

# Set development-specific variables
[Environment]::SetEnvironmentVariable("FERRET_DEV_MODE", "1", "User")
[Environment]::SetEnvironmentVariable("FERRET_DEBUG", "1", "User")
```

#### Configure Git for Windows
```powershell
# Configure line endings for cross-platform development
git config --global core.autocrlf true
git config --global core.safecrlf warn

# Configure long path support
git config --global core.longpaths true

# Configure default editor
git config --global core.editor "code --wait"
```

## Project Setup

### Clone Repository
```powershell
# Clone the repository
git clone https://github.com/your-org/ferret-scan.git
cd ferret-scan

# Initialize Go modules
go mod download
go mod tidy
```

### Development Dependencies
```powershell
# Install development tools
go install golang.org/x/tools/cmd/goimports@latest
go install golang.org/x/lint/golint@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install honnef.co/go/tools/cmd/staticcheck@latest

# Install testing tools
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go install github.com/onsi/gomega@latest

# Install build tools
go install github.com/goreleaser/goreleaser@latest
```

### IDE Configuration

#### Visual Studio Code
Create `.vscode/settings.json`:
```json
{
    "go.toolsManagement.checkForUpdates": "local",
    "go.useLanguageServer": true,
    "go.formatTool": "goimports",
    "go.lintTool": "golangci-lint",
    "go.vetOnSave": "package",
    "go.buildOnSave": "package",
    "go.testOnSave": true,
    "go.coverOnSave": true,
    "go.testFlags": ["-v", "-race"],
    "go.buildFlags": ["-v"],
    "go.testTimeout": "30s",
    "files.eol": "\n",
    "files.insertFinalNewline": true,
    "files.trimTrailingWhitespace": true
}
```

Create `.vscode/launch.json`:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Ferret Scan",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}/cmd/main.go",
            "args": ["scan", ".", "--debug"],
            "env": {
                "FERRET_DEBUG": "1",
                "FERRET_TEST_MODE": "1"
            },
            "console": "integratedTerminal"
        },
        {
            "name": "Launch Web UI",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}/cmd/main.go",
            "args": ["web", "--port", "8080"],
            "env": {
                "FERRET_DEBUG": "1"
            },
            "console": "integratedTerminal"
        },
        {
            "name": "Attach to Process",
            "type": "go",
            "request": "attach",
            "mode": "local",
            "processId": 0
        }
    ]
}
```

## Building on Windows

### Local Development Build
```powershell
# Build for current platform
go build -o ferret-scan.exe ./cmd/main.go

# Build with debug information
go build -gcflags="all=-N -l" -o ferret-scan-debug.exe ./cmd/main.go

# Build with version information
$Version = "v1.0.0-dev"
$Commit = git rev-parse HEAD
$BuildDate = Get-Date -Format "2006-01-02T15:04:05Z"

go build -ldflags "-X ferret-scan/internal/version.Version=$Version -X ferret-scan/internal/version.GitCommit=$Commit -X ferret-scan/internal/version.BuildDate=$BuildDate" -o ferret-scan.exe ./cmd/main.go
```

### Cross-Platform Building
```powershell
# Build for different Windows architectures
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o ferret-scan-windows-amd64.exe ./cmd/main.go

$env:GOARCH = "arm64"
go build -o ferret-scan-windows-arm64.exe ./cmd/main.go

$env:GOARCH = "386"
go build -o ferret-scan-windows-386.exe ./cmd/main.go

# Build for other platforms from Windows
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o ferret-scan-linux-amd64 ./cmd/main.go

$env:GOOS = "darwin"
$env:GOARCH = "amd64"
go build -o ferret-scan-darwin-amd64 ./cmd/main.go

# Reset environment
Remove-Item Env:\GOOS
Remove-Item Env:\GOARCH
```

### Using Make on Windows
```powershell
# Install Make for Windows
choco install make

# Or use the project's PowerShell equivalents
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\lint.ps1
```

### PowerShell Build Scripts

Create `scripts/build.ps1`:
```powershell
#!/usr/bin/env pwsh
param(
    [string]$Version = "dev",
    [string]$Output = "ferret-scan.exe",
    [switch]$Debug,
    [switch]$Race
)

Write-Host "Building Ferret Scan for Windows..." -ForegroundColor Green

# Get build information
$GitCommit = git rev-parse HEAD
$BuildDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

# Build flags
$BuildFlags = @()
$LdFlags = @(
    "-X ferret-scan/internal/version.Version=$Version",
    "-X ferret-scan/internal/version.GitCommit=$GitCommit",
    "-X ferret-scan/internal/version.BuildDate=$BuildDate"
)

if (-not $Debug) {
    $LdFlags += "-s", "-w"  # Strip debug info for release builds
}

if ($Race) {
    $BuildFlags += "-race"
}

# Build command
$BuildArgs = @("build") + $BuildFlags + @("-ldflags", ($LdFlags -join " "), "-o", $Output, "./cmd/main.go")

Write-Host "Running: go $($BuildArgs -join ' ')" -ForegroundColor Cyan
& go @BuildArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful: $Output" -ForegroundColor Green
    
    # Display file info
    $FileInfo = Get-Item $Output
    Write-Host "Size: $([math]::Round($FileInfo.Length / 1MB, 2)) MB" -ForegroundColor Cyan
} else {
    Write-Host "Build failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
```

## Testing on Windows

### Running Tests
```powershell
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with race detection
go test -race ./...

# Run specific test packages
go test -v ./internal/platform/...
go test -v ./internal/paths/...

# Run Windows-specific tests
go test -v -tags windows ./tests/integration/...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Windows-Specific Testing
```powershell
# Set Windows test environment
$env:FERRET_TEST_MODE = "1"
$env:GOOS = "windows"

# Run Windows integration tests
go test -v -tags windows ./tests/integration/windows_*.go

# Test Windows path handling
go test -v ./internal/paths/ -run TestWindows

# Test Windows platform features
go test -v ./internal/platform/ -run TestWindows

# Clean up test environment
Remove-Item Env:\FERRET_TEST_MODE
Remove-Item Env:\GOOS
```

### Test Data Management
```powershell
# Create test data directory
New-Item -ItemType Directory -Path "testdata" -Force

# Generate test files with Windows paths
@"
Test file with Windows path: C:\Users\test\file.txt
UNC path: \\server\share\file.txt
Credit card: 4111-1111-1111-1111
"@ | Out-File "testdata\windows_test.txt" -Encoding UTF8

# Create test configuration
@"
defaults:
  format: "json"
  checks: "all"
platform:
  windows:
    use_appdata: true
"@ | Out-File "testdata\windows_config.yaml" -Encoding UTF8
```

## Debugging

### Debug Configuration
```powershell
# Enable debug mode
$env:FERRET_DEBUG = "1"
$env:FERRET_LOG_LEVEL = "debug"

# Run with debug output
.\ferret-scan.exe scan . --debug --verbose

# Debug specific components
$env:FERRET_DEBUG_PLATFORM = "1"
$env:FERRET_DEBUG_PATHS = "1"
```

### Using Delve Debugger
```powershell
# Install Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug the application
dlv debug ./cmd/main.go -- scan . --debug

# Debug tests
dlv test ./internal/platform/ -- -test.run TestWindows

# Attach to running process
$ProcessId = (Get-Process ferret-scan).Id
dlv attach $ProcessId
```

### Visual Studio Code Debugging
Use the launch configurations in `.vscode/launch.json` to debug:

1. **Set Breakpoints**: Click in the gutter next to line numbers
2. **Start Debugging**: Press F5 or use Debug menu
3. **Step Through Code**: Use F10 (step over), F11 (step into)
4. **Inspect Variables**: Hover over variables or use Debug Console

### Logging and Diagnostics
```powershell
# Enable comprehensive logging
$env:FERRET_DEBUG = "1"
$env:FERRET_LOG_FILE = "debug.log"

# Run with logging
.\ferret-scan.exe scan . --debug 2>&1 | Tee-Object debug-output.txt

# Analyze logs
Select-String -Path "debug-output.txt" -Pattern "ERROR|WARN"
```

## Windows-Specific Development

### Platform Abstraction Layer
```go
// internal/platform/windows.go
package platform

import (
    "os"
    "path/filepath"
    "strings"
)

// WindowsPlatform implements Platform interface for Windows
type WindowsPlatform struct{}

func (w *WindowsPlatform) GetConfigDir() string {
    // Windows-specific configuration directory logic
    if dir := os.Getenv("FERRET_CONFIG_DIR"); dir != "" {
        return dir
    }
    
    if appData := os.Getenv("APPDATA"); appData != "" {
        return filepath.Join(appData, "ferret-scan")
    }
    
    if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
        return filepath.Join(userProfile, ".ferret-scan")
    }
    
    return ".ferret-scan"
}

func (w *WindowsPlatform) NormalizePath(path string) string {
    // Convert forward slashes to backslashes
    normalized := filepath.Clean(path)
    
    // Handle UNC paths
    if strings.HasPrefix(path, "\\\\") && !strings.HasPrefix(normalized, "\\\\") {
        normalized = "\\\\" + strings.TrimPrefix(normalized, "\\")
    }
    
    return normalized
}
```

### Windows Path Handling
```go
// internal/paths/windows.go
package paths

import (
    "path/filepath"
    "strings"
)

// IsUNCPath checks if a path is a Windows UNC path
func IsUNCPath(path string) bool {
    return len(path) >= 2 && path[0] == '\\' && path[1] == '\\'
}

// HasDriveLetter checks if a Windows path has a drive letter
func HasDriveLetter(path string) bool {
    return len(path) >= 2 && path[1] == ':'
}

// ToLongPathFormat converts a Windows path to long path format if needed
func ToLongPathFormat(path string) string {
    if len(path) <= 260 {
        return path
    }
    
    if strings.HasPrefix(path, "\\\\?\\") {
        return path
    }
    
    absPath, err := filepath.Abs(path)
    if err != nil {
        return path
    }
    
    return "\\\\?\\" + absPath
}
```

### Windows Error Handling
```go
// internal/platform/windows_errors.go
package platform

import (
    "errors"
    "fmt"
    "syscall"
)

// WindowsError represents a Windows-specific error
type WindowsError struct {
    Op         string
    Path       string
    Err        error
    Suggestion string
}

func (e *WindowsError) Error() string {
    msg := fmt.Sprintf("windows error in %s", e.Op)
    if e.Path != "" {
        msg += fmt.Sprintf(" for path %s", e.Path)
    }
    msg += fmt.Sprintf(": %v", e.Err)
    if e.Suggestion != "" {
        msg += fmt.Sprintf(" (suggestion: %s)", e.Suggestion)
    }
    return msg
}

// IsPermissionError checks if an error is a Windows permission error
func IsPermissionError(err error) bool {
    if err == nil {
        return false
    }
    
    // Check for Windows-specific permission errors
    if errno, ok := err.(syscall.Errno); ok {
        return errno == syscall.ERROR_ACCESS_DENIED ||
               errno == syscall.ERROR_SHARING_VIOLATION
    }
    
    return false
}

// IsLongPathError checks if an error is related to Windows long path limits
func IsLongPathError(err error) bool {
    if err == nil {
        return false
    }
    
    errStr := err.Error()
    return strings.Contains(errStr, "path too long") ||
           strings.Contains(errStr, "name too long") ||
           strings.Contains(errStr, "260")
}
```

## Testing Windows Features

### Unit Tests for Windows Platform
```go
// internal/platform/windows_test.go
//go:build windows
// +build windows

package platform

import (
    "os"
    "path/filepath"
    "testing"
)

func TestWindowsPlatform_GetConfigDir(t *testing.T) {
    platform := &WindowsPlatform{}
    
    // Save original environment
    originalAppData := os.Getenv("APPDATA")
    originalUserProfile := os.Getenv("USERPROFILE")
    
    defer func() {
        os.Setenv("APPDATA", originalAppData)
        os.Setenv("USERPROFILE", originalUserProfile)
    }()
    
    t.Run("uses APPDATA when available", func(t *testing.T) {
        testAppData := "C:\\Users\\test\\AppData\\Roaming"
        os.Setenv("APPDATA", testAppData)
        
        expected := filepath.Join(testAppData, "ferret-scan")
        actual := platform.GetConfigDir()
        
        if actual != expected {
            t.Errorf("Expected %s, got %s", expected, actual)
        }
    })
    
    t.Run("falls back to USERPROFILE", func(t *testing.T) {
        os.Setenv("APPDATA", "")
        testUserProfile := "C:\\Users\\test"
        os.Setenv("USERPROFILE", testUserProfile)
        
        expected := filepath.Join(testUserProfile, ".ferret-scan")
        actual := platform.GetConfigDir()
        
        if actual != expected {
            t.Errorf("Expected %s, got %s", expected, actual)
        }
    })
}

func TestWindowsPlatform_NormalizePath(t *testing.T) {
    platform := &WindowsPlatform{}
    
    tests := []struct {
        input    string
        expected string
    }{
        {"C:/Users/test", "C:\\Users\\test"},
        {"\\\\server\\share", "\\\\server\\share"},
        {"C:\\Users\\test\\..\\other", "C:\\Users\\other"},
    }
    
    for _, test := range tests {
        t.Run(test.input, func(t *testing.T) {
            actual := platform.NormalizePath(test.input)
            if actual != test.expected {
                t.Errorf("Expected %s, got %s", test.expected, actual)
            }
        })
    }
}
```

### Integration Tests
```go
// tests/integration/windows_integration_test.go
//go:build windows
// +build windows

package integration

import (
    "os"
    "path/filepath"
    "testing"
    
    "ferret-scan/internal/platform"
)

func TestWindowsIntegration(t *testing.T) {
    if !platform.IsWindows() {
        t.Skip("Skipping Windows-specific tests on non-Windows platform")
    }
    
    t.Run("Windows path handling", func(t *testing.T) {
        // Test Windows-specific path scenarios
        testPaths := []string{
            "C:\\Users\\test\\file.txt",
            "\\\\server\\share\\file.txt",
            "D:\\Data\\documents\\report.pdf",
        }
        
        for _, testPath := range testPaths {
            // Test path operations
            normalized := platform.NormalizePath(testPath)
            if normalized == "" {
                t.Errorf("Path normalization failed for: %s", testPath)
            }
        }
    })
}
```

## Performance Optimization

### Profiling on Windows
```powershell
# Build with profiling enabled
go build -o ferret-scan-profile.exe ./cmd/main.go

# Run with CPU profiling
.\ferret-scan-profile.exe scan . --cpuprofile=cpu.prof

# Run with memory profiling
.\ferret-scan-profile.exe scan . --memprofile=mem.prof

# Analyze profiles
go tool pprof cpu.prof
go tool pprof mem.prof

# Generate profile reports
go tool pprof -http=:8080 cpu.prof
```

### Benchmarking
```powershell
# Run benchmarks
go test -bench=. ./internal/platform/
go test -bench=BenchmarkWindows ./internal/paths/

# Run benchmarks with memory allocation info
go test -bench=. -benchmem ./internal/platform/

# Compare benchmarks
go test -bench=. -count=5 ./internal/platform/ > old.txt
# Make changes
go test -bench=. -count=5 ./internal/platform/ > new.txt
benchcmp old.txt new.txt
```

## Continuous Integration

### GitHub Actions for Windows
```yaml
# .github/workflows/windows.yml
name: Windows CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test-windows:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Cache Go modules
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
        restore-keys: |
          ${{ runner.os }}-go-
    
    - name: Install dependencies
      run: go mod download
    
    - name: Run tests
      run: go test -v -race ./...
    
    - name: Run Windows-specific tests
      run: go test -v -tags windows ./tests/integration/
    
    - name: Build Windows binary
      run: go build -o ferret-scan.exe ./cmd/main.go
    
    - name: Test Windows binary
      run: |
        .\ferret-scan.exe --version
        echo "Test content" | Out-File test.txt
        .\ferret-scan.exe scan test.txt
```

### Local CI Simulation
```powershell
# Simulate CI environment locally
function Invoke-LocalCI {
    Write-Host "Running local CI simulation..." -ForegroundColor Green
    
    # Clean environment
    go clean -cache
    go clean -testcache
    
    # Download dependencies
    go mod download
    go mod tidy
    
    # Run linting
    golangci-lint run
    
    # Run tests
    go test -v -race ./...
    
    # Run Windows-specific tests
    go test -v -tags windows ./tests/integration/
    
    # Build binary
    go build -o ferret-scan.exe ./cmd/main.go
    
    # Test binary
    .\ferret-scan.exe --version
    
    Write-Host "Local CI simulation completed" -ForegroundColor Green
}

Invoke-LocalCI
```

## Deployment and Distribution

### Creating Windows Installer
```powershell
# Using WiX Toolset to create MSI installer
# Install WiX Toolset first

# Create installer configuration
$WixConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Ferret Scan" Language="1033" Version="1.0.0" 
           Manufacturer="Your Company" UpgradeCode="PUT-GUID-HERE">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />
    
    <MajorUpgrade DowngradeErrorMessage="A newer version is already installed." />
    <MediaTemplate EmbedCab="yes" />
    
    <Feature Id="ProductFeature" Title="Ferret Scan" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
  </Product>
  
  <Fragment>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="Ferret Scan" />
      </Directory>
    </Directory>
  </Fragment>
  
  <Fragment>
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="MainExecutable">
        <File Source="ferret-scan.exe" />
      </Component>
    </ComponentGroup>
  </Fragment>
</Wix>
"@

$WixConfig | Out-File "installer.wxs" -Encoding UTF8

# Build installer
candle installer.wxs
light installer.wixobj -o ferret-scan-installer.msi
```

### PowerShell Module Distribution
```powershell
# Create PowerShell module structure
New-Item -ItemType Directory -Path "FerretScan" -Force
New-Item -ItemType Directory -Path "FerretScan\bin" -Force

# Copy binary
Copy-Item "ferret-scan.exe" -Destination "FerretScan\bin\"

# Create module manifest
$ModuleManifest = @{
    Path = "FerretScan\FerretScan.psd1"
    RootModule = "FerretScan.psm1"
    ModuleVersion = "1.0.0"
    Author = "Your Name"
    Description = "PowerShell module for Ferret Scan"
    PowerShellVersion = "5.1"
    FunctionsToExport = @("Invoke-FerretScan", "Start-FerretWeb")
}

New-ModuleManifest @ModuleManifest

# Create module script
$ModuleScript = @"
# Import binary path
`$BinaryPath = Join-Path `$PSScriptRoot "bin\ferret-scan.exe"

function Invoke-FerretScan {
    param(
        [Parameter(Mandatory=`$true)]
        [string]`$Path,
        [string]`$Format = "text"
    )
    
    & `$BinaryPath scan `$Path --format `$Format
}

function Start-FerretWeb {
    param([int]`$Port = 8080)
    
    & `$BinaryPath web --port `$Port
}

Export-ModuleMember -Function Invoke-FerretScan, Start-FerretWeb
"@

$ModuleScript | Out-File "FerretScan\FerretScan.psm1" -Encoding UTF8
```

## Troubleshooting Development Issues

### Common Build Issues
```powershell
# Go module issues
go clean -modcache
go mod download
go mod tidy

# Build cache issues
go clean -cache
go clean -testcache

# CGO issues (if using CGO)
$env:CGO_ENABLED = "0"
go build ./cmd/main.go

# Path issues
$env:GOPATH = "C:\Go"
$env:PATH += ";C:\Go\bin"
```

### Debugging Build Problems
```powershell
# Verbose build output
go build -v -x ./cmd/main.go

# Check Go environment
go env

# Verify module dependencies
go mod verify
go mod graph
```

### Performance Issues
```powershell
# Check for memory leaks
go test -memprofile=mem.prof ./...
go tool pprof mem.prof

# Check for race conditions
go test -race ./...

# Profile CPU usage
go test -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof
```

## Best Practices

### Code Organization
1. **Platform-specific code**: Use build tags (`//go:build windows`)
2. **Interface abstraction**: Abstract platform differences behind interfaces
3. **Error handling**: Provide Windows-specific error messages and suggestions
4. **Path handling**: Always use `filepath` package for path operations
5. **Testing**: Write comprehensive tests for Windows-specific functionality

### Development Workflow
1. **Feature branches**: Use feature branches for Windows-specific development
2. **Cross-platform testing**: Test on multiple Windows versions
3. **Code reviews**: Include Windows developers in code reviews
4. **Documentation**: Document Windows-specific behavior and limitations

### Security Considerations
1. **File permissions**: Handle Windows ACLs appropriately
2. **Execution policy**: Consider PowerShell execution policies
3. **Antivirus**: Account for antivirus software interference
4. **UAC**: Handle User Account Control requirements

---

This development guide provides comprehensive coverage of developing Ferret Scan on Windows, from environment setup through deployment and troubleshooting.