// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build windows
// +build windows

package integration

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ferret-scan/internal/platform"
	"ferret-scan/tests/helpers"
)

// TestWindowsReleaseDistributionValidation tests Windows binary distribution and installation
func TestWindowsReleaseDistributionValidation(t *testing.T) {
	if !platform.IsWindows() {
		t.Skip("Skipping Windows-specific tests on non-Windows platform")
	}

	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	t.Run("WindowsArchitectureBinaryValidation", func(t *testing.T) {
		// Test building for all supported Windows architectures
		architectures := []struct {
			arch        string
			description string
			canExecute  bool
		}{
			{"amd64", "Windows 64-bit (Intel/AMD)", runtime.GOARCH == "amd64"},
			{"arm64", "Windows ARM64", runtime.GOARCH == "arm64"},
			{"386", "Windows 32-bit (Intel)", runtime.GOARCH == "386"},
		}

		tempDir := t.TempDir()

		for _, arch := range architectures {
			t.Run(fmt.Sprintf("Architecture_%s", arch.arch), func(t *testing.T) {
				binaryName := fmt.Sprintf("ferret-scan-%s.exe", arch.arch)
				binaryPath := filepath.Join(tempDir, binaryName)

				// Build binary for specific architecture
				buildCmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/main.go")
				buildCmd.Env = append(os.Environ(),
					"GOOS=windows",
					fmt.Sprintf("GOARCH=%s", arch.arch),
					"CGO_ENABLED=0",
				)

				buildOutput, err := buildCmd.CombinedOutput()
				if err != nil {
					t.Fatalf("Failed to build Windows %s binary: %v\nOutput: %s", arch.arch, err, string(buildOutput))
				}

				// Verify binary exists and has correct extension
				if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
					t.Fatalf("Binary not created for %s: %s", arch.arch, binaryPath)
				}

				if !strings.HasSuffix(binaryPath, ".exe") {
					t.Errorf("Windows binary should have .exe extension: %s", binaryPath)
				}

				// Test binary execution (only for current architecture)
				if arch.canExecute {
					versionCmd := exec.Command(binaryPath, "--version")
					versionOutput, err := versionCmd.CombinedOutput()
					if err != nil {
						t.Fatalf("Failed to execute %s binary: %v\nOutput: %s", arch.arch, err, string(versionOutput))
					}

					versionStr := string(versionOutput)
					if !strings.Contains(versionStr, "ferret-scan") {
						t.Errorf("Version output should contain 'ferret-scan': %s", versionStr)
					}

					t.Logf("Successfully built and tested %s binary: %s", arch.description, binaryPath)
				} else {
					t.Logf("Successfully built %s binary (cross-compiled): %s", arch.description, binaryPath)
				}

				// Verify binary size is reasonable (should be > 1MB for a Go binary)
				fileInfo, err := os.Stat(binaryPath)
				if err != nil {
					t.Errorf("Failed to get binary file info: %v", err)
				} else {
					size := fileInfo.Size()
					if size < 1024*1024 { // Less than 1MB
						t.Errorf("Binary size seems too small: %d bytes", size)
					}
					t.Logf("Binary size: %.2f MB", float64(size)/(1024*1024))
				}
			})
		}
	})

	t.Run("WindowsInstallationPackageCreation", func(t *testing.T) {
		// Test creating comprehensive Windows installation package
		tempDir := t.TempDir()
		packageDir := filepath.Join(tempDir, "ferret-scan-windows-release")

		// Create package directory structure
		dirs := []string{
			packageDir,
			filepath.Join(packageDir, "bin"),
			filepath.Join(packageDir, "config"),
			filepath.Join(packageDir, "docs"),
			filepath.Join(packageDir, "examples"),
		}

		for _, dir := range dirs {
			err := os.MkdirAll(dir, 0755)
			if err != nil {
				t.Fatalf("Failed to create package directory %s: %v", dir, err)
			}
		}

		// Build main binary
		binaryPath := filepath.Join(packageDir, "bin", "ferret-scan.exe")
		buildCmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/main.go")
		buildCmd.Env = append(os.Environ(),
			"GOOS=windows",
			"GOARCH=amd64",
			"CGO_ENABLED=0",
		)

		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build main binary: %v\nOutput: %s", err, string(buildOutput))
		}

		// Build suppress utility
		suppressBinaryPath := filepath.Join(packageDir, "bin", "ferret-suppress.exe")
		suppressBuildCmd := exec.Command("go", "build", "-o", suppressBinaryPath, "../../cmd/suppress/main.go")
		suppressBuildCmd.Env = append(os.Environ(),
			"GOOS=windows",
			"GOARCH=amd64",
			"CGO_ENABLED=0",
		)

		suppressBuildOutput, err := suppressBuildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build suppress binary: %v\nOutput: %s", err, string(suppressBuildOutput))
		}

		// Create installation script
		installScript := filepath.Join(packageDir, "install.ps1")
		installScriptContent := `# Ferret Scan Windows Installation Script
param(
    [string]$InstallPath = "$env:ProgramFiles\ferret-scan",
    [switch]$UserInstall = $false,
    [switch]$AddToPath = $true,
    [switch]$CreateShortcuts = $false
)

Write-Host "Installing Ferret Scan for Windows..." -ForegroundColor Green

# Determine installation path
if ($UserInstall) {
    $InstallPath = "$env:LOCALAPPDATA\Programs\ferret-scan"
    Write-Host "Installing for current user: $InstallPath" -ForegroundColor Cyan
} else {
    Write-Host "Installing system-wide: $InstallPath" -ForegroundColor Cyan
    # Check if running as administrator for system-wide install
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Warning: System-wide installation requires administrator privileges" -ForegroundColor Yellow
    }
}

# Create installation directory
try {
    New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
    Write-Host "Created installation directory: $InstallPath" -ForegroundColor Green
} catch {
    Write-Host "Failed to create installation directory: $_" -ForegroundColor Red
    exit 1
}

# Copy binaries
try {
    Copy-Item "bin\ferret-scan.exe" -Destination "$InstallPath\ferret-scan.exe" -Force
    Copy-Item "bin\ferret-suppress.exe" -Destination "$InstallPath\ferret-suppress.exe" -Force
    Write-Host "Copied binaries to installation directory" -ForegroundColor Green
} catch {
    Write-Host "Failed to copy binaries: $_" -ForegroundColor Red
    exit 1
}

# Copy configuration files
try {
    $configDir = "$InstallPath\config"
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    Copy-Item "config\*" -Destination $configDir -Recurse -Force
    Write-Host "Copied configuration files" -ForegroundColor Green
} catch {
    Write-Host "Failed to copy configuration files: $_" -ForegroundColor Red
}

# Copy documentation
try {
    $docsDir = "$InstallPath\docs"
    New-Item -ItemType Directory -Force -Path $docsDir | Out-Null
    Copy-Item "docs\*" -Destination $docsDir -Recurse -Force
    Write-Host "Copied documentation" -ForegroundColor Green
} catch {
    Write-Host "Failed to copy documentation: $_" -ForegroundColor Red
}

# Add to PATH
if ($AddToPath) {
    try {
        $pathType = if ($UserInstall) { "User" } else { "Machine" }
        $currentPath = [Environment]::GetEnvironmentVariable("PATH", $pathType)
        
        if ($currentPath -notlike "*$InstallPath*") {
            $newPath = "$currentPath;$InstallPath"
            [Environment]::SetEnvironmentVariable("PATH", $newPath, $pathType)
            Write-Host "Added $InstallPath to $pathType PATH" -ForegroundColor Green
        } else {
            Write-Host "$InstallPath already in PATH" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Failed to update PATH: $_" -ForegroundColor Red
    }
}

# Create shortcuts
if ($CreateShortcuts) {
    try {
        $WshShell = New-Object -comObject WScript.Shell
        
        # Desktop shortcut
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcut = $WshShell.CreateShortcut("$desktopPath\Ferret Scan.lnk")
        $shortcut.TargetPath = "$InstallPath\ferret-scan.exe"
        $shortcut.WorkingDirectory = $InstallPath
        $shortcut.Description = "Ferret Scan Security Scanner"
        $shortcut.Save()
        
        Write-Host "Created desktop shortcut" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create shortcuts: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Ferret Scan installed successfully!" -ForegroundColor Green
Write-Host "Installation directory: $InstallPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  ferret-scan --help" -ForegroundColor White
Write-Host "  ferret-scan scan <directory>" -ForegroundColor White
Write-Host ""
if ($AddToPath) {
    Write-Host "Please restart your command prompt to use the 'ferret-scan' command" -ForegroundColor Yellow
}
`

		err = os.WriteFile(installScript, []byte(installScriptContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create installation script: %v", err)
		}

		// Create uninstall script
		uninstallScript := filepath.Join(packageDir, "uninstall.ps1")
		uninstallScriptContent := `# Ferret Scan Windows Uninstallation Script
param(
    [string]$InstallPath = "$env:ProgramFiles\ferret-scan",
    [switch]$UserInstall = $false
)

Write-Host "Uninstalling Ferret Scan for Windows..." -ForegroundColor Yellow

# Determine installation path
if ($UserInstall) {
    $InstallPath = "$env:LOCALAPPDATA\Programs\ferret-scan"
}

Write-Host "Uninstalling from: $InstallPath" -ForegroundColor Cyan

# Remove from PATH
try {
    $pathType = if ($UserInstall) { "User" } else { "Machine" }
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", $pathType)
    
    if ($currentPath -like "*$InstallPath*") {
        $newPath = $currentPath -replace [regex]::Escape(";$InstallPath"), ""
        $newPath = $newPath -replace [regex]::Escape("$InstallPath;"), ""
        $newPath = $newPath -replace [regex]::Escape("$InstallPath"), ""
        [Environment]::SetEnvironmentVariable("PATH", $newPath, $pathType)
        Write-Host "Removed $InstallPath from $pathType PATH" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to update PATH: $_" -ForegroundColor Red
}

# Remove shortcuts
try {
    $desktopShortcut = [Environment]::GetFolderPath("Desktop") + "\Ferret Scan.lnk"
    if (Test-Path $desktopShortcut) {
        Remove-Item $desktopShortcut -Force
        Write-Host "Removed desktop shortcut" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to remove shortcuts: $_" -ForegroundColor Red
}

# Remove installation directory
try {
    if (Test-Path $InstallPath) {
        Remove-Item -Recurse -Force $InstallPath
        Write-Host "Removed installation directory: $InstallPath" -ForegroundColor Green
    } else {
        Write-Host "Installation directory not found: $InstallPath" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Failed to remove installation directory: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Ferret Scan uninstalled successfully!" -ForegroundColor Green
`

		err = os.WriteFile(uninstallScript, []byte(uninstallScriptContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create uninstallation script: %v", err)
		}

		// Create sample configuration files
		configFiles := map[string]string{
			"config/ferret.yaml": `# Ferret Scan Configuration for Windows
defaults:
  format: "text"
  checks: "all"
  confidence_levels: "high,medium"
  verbose: false
  recursive: true
  enable_preprocessors: true

platform:
  windows:
    use_appdata: true
    long_path_support: false
    temp_dir: "%TEMP%\\ferret-scan"

profiles:
  quick:
    checks: "CREDIT_CARD,SSN,SECRETS"
    confidence_levels: "high"
    description: "Quick scan for common sensitive data"
  
  comprehensive:
    checks: "all"
    confidence_levels: "all"
    recursive: true
    enable_preprocessors: true
    description: "Comprehensive scan with all validators"
`,
			"config/suppressions.yaml": `# Ferret Scan Suppressions
# Add suppression rules here to ignore false positives

# Example: Ignore test credit card numbers
# - pattern: "4111-1111-1111-1111"
#   reason: "Test credit card number"
#   file: "tests/*"

# Example: Ignore development secrets
# - pattern: "dev_secret_key_.*"
#   reason: "Development environment secret"
#   file: "dev/*"
`,
		}

		for filename, content := range configFiles {
			filePath := filepath.Join(packageDir, filename)
			err := os.MkdirAll(filepath.Dir(filePath), 0755)
			if err != nil {
				t.Fatalf("Failed to create config directory: %v", err)
			}
			err = os.WriteFile(filePath, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create config file %s: %v", filename, err)
			}
		}

		// Create documentation files
		docFiles := map[string]string{
			"docs/README.txt": `Ferret Scan for Windows
======================

Ferret Scan is a security scanner that detects sensitive data in files and directories.

Installation:
1. Run install.ps1 in PowerShell as Administrator for system-wide installation
2. Or run with -UserInstall flag for user-only installation

Usage:
- Open Command Prompt or PowerShell
- Run: ferret-scan --help
- Scan a directory: ferret-scan scan C:\path\to\scan
- Use web interface: ferret-scan web

Configuration:
- Configuration files are located in the config\ directory
- Copy ferret.yaml to your user config directory for customization
- User config directory: %APPDATA%\ferret-scan\

Uninstallation:
- Run uninstall.ps1 in PowerShell

For more information, visit: https://github.com/your-org/ferret-scan
`,
			"docs/WINDOWS_USAGE.txt": `Windows-Specific Usage Guide
============================

File Paths:
- Use Windows path separators: C:\path\to\file
- UNC paths are supported: \\server\share\file
- Relative paths work: .\current\directory

Configuration:
- Default config location: %APPDATA%\ferret-scan\config.yaml
- System config location: %PROGRAMDATA%\ferret-scan\config.yaml
- Override with: set FERRET_CONFIG_DIR=C:\custom\path

Environment Variables:
- FERRET_CONFIG_DIR: Override config directory
- TEMP: Temporary file location
- APPDATA: User application data directory

PowerShell Integration:
- ferret-scan scan . | Out-File results.txt
- Get-ChildItem -Recurse | ferret-scan scan --stdin

Batch Script Integration:
- @echo off
- ferret-scan scan %1
- if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

Common Issues:
- Long path errors: Enable long path support in Windows 10/11
- Permission errors: Run as Administrator or check file permissions
- Path not found: Ensure ferret-scan is in your PATH environment variable
`,
		}

		for filename, content := range docFiles {
			filePath := filepath.Join(packageDir, filename)
			err := os.WriteFile(filePath, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create doc file %s: %v", filename, err)
			}
		}

		// Create example files
		exampleFiles := map[string]string{
			"examples/scan_directory.bat": `@echo off
REM Example batch script to scan a directory
echo Scanning directory: %1
ferret-scan scan "%1" --format json --output results.json
if %ERRORLEVEL% equ 0 (
    echo Scan completed successfully
) else (
    echo Scan failed with error code %ERRORLEVEL%
)
`,
			"examples/scan_with_config.ps1": `# Example PowerShell script to scan with custom configuration
param(
    [Parameter(Mandatory=$true)]
    [string]$Directory,
    [string]$ConfigFile = "config\ferret.yaml"
)

Write-Host "Scanning directory: $Directory" -ForegroundColor Green
Write-Host "Using configuration: $ConfigFile" -ForegroundColor Cyan

& ferret-scan scan $Directory --config $ConfigFile --format text

if ($LASTEXITCODE -eq 0) {
    Write-Host "Scan completed successfully" -ForegroundColor Green
} else {
    Write-Host "Scan failed with error code $LASTEXITCODE" -ForegroundColor Red
}
`,
		}

		for filename, content := range exampleFiles {
			filePath := filepath.Join(packageDir, filename)
			err := os.WriteFile(filePath, []byte(content), 0644)
			if err != nil {
				t.Fatalf("Failed to create example file %s: %v", filename, err)
			}
		}

		// Verify package contents
		expectedFiles := []string{
			"bin/ferret-scan.exe",
			"bin/ferret-suppress.exe",
			"install.ps1",
			"uninstall.ps1",
			"config/ferret.yaml",
			"config/suppressions.yaml",
			"docs/README.txt",
			"docs/WINDOWS_USAGE.txt",
			"examples/scan_directory.bat",
			"examples/scan_with_config.ps1",
		}

		for _, expectedFile := range expectedFiles {
			filePath := filepath.Join(packageDir, expectedFile)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected package file missing: %s", expectedFile)
			}
		}

		t.Logf("Windows installation package created successfully: %s", packageDir)

		// Test installation script syntax (basic check)
		if strings.Contains(string(installScriptContent), "param(") &&
			strings.Contains(string(installScriptContent), "Write-Host") {
			t.Logf("Installation script appears to have valid PowerShell syntax")
		} else {
			t.Error("Installation script may have syntax issues")
		}
	})

	t.Run("WindowsZipDistributionValidation", func(t *testing.T) {
		// Test creating and validating ZIP distribution
		tempDir := t.TempDir()
		zipPath := filepath.Join(tempDir, "ferret-scan-windows-amd64.zip")

		// Create ZIP file
		zipFile, err := os.Create(zipPath)
		if err != nil {
			t.Fatalf("Failed to create ZIP file: %v", err)
		}
		defer zipFile.Close()

		zipWriter := zip.NewWriter(zipFile)
		defer zipWriter.Close()

		// Build binary for ZIP
		binaryDir := filepath.Join(tempDir, "binary")
		err = os.MkdirAll(binaryDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create binary directory: %v", err)
		}

		binaryPath := filepath.Join(binaryDir, "ferret-scan.exe")
		buildCmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/main.go")
		buildCmd.Env = append(os.Environ(),
			"GOOS=windows",
			"GOARCH=amd64",
			"CGO_ENABLED=0",
		)

		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build binary for ZIP: %v\nOutput: %s", err, string(buildOutput))
		}

		// Add binary to ZIP
		binaryData, err := os.ReadFile(binaryPath)
		if err != nil {
			t.Fatalf("Failed to read binary for ZIP: %v", err)
		}

		binaryWriter, err := zipWriter.Create("ferret-scan.exe")
		if err != nil {
			t.Fatalf("Failed to create binary entry in ZIP: %v", err)
		}

		_, err = binaryWriter.Write(binaryData)
		if err != nil {
			t.Fatalf("Failed to write binary to ZIP: %v", err)
		}

		// Add README to ZIP
		readmeWriter, err := zipWriter.Create("README.txt")
		if err != nil {
			t.Fatalf("Failed to create README entry in ZIP: %v", err)
		}

		readmeContent := `Ferret Scan Windows Distribution

Extract this ZIP file to a directory of your choice.
Add the directory to your PATH environment variable to use ferret-scan from anywhere.

Usage: 
  ferret-scan --help
  ferret-scan scan C:\path\to\scan

For more information, visit: https://github.com/your-org/ferret-scan
`

		_, err = readmeWriter.Write([]byte(readmeContent))
		if err != nil {
			t.Fatalf("Failed to write README to ZIP: %v", err)
		}

		// Add LICENSE to ZIP
		licenseWriter, err := zipWriter.Create("LICENSE.txt")
		if err != nil {
			t.Fatalf("Failed to create LICENSE entry in ZIP: %v", err)
		}

		licenseContent := `MIT License

Copyright (c) 2024 Ferret Scan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

		_, err = licenseWriter.Write([]byte(licenseContent))
		if err != nil {
			t.Fatalf("Failed to write LICENSE to ZIP: %v", err)
		}

		// Add CHANGELOG to ZIP
		changelogWriter, err := zipWriter.Create("CHANGELOG.txt")
		if err != nil {
			t.Fatalf("Failed to create CHANGELOG entry in ZIP: %v", err)
		}

		changelogContent := `Ferret Scan Changelog

## Windows Compatibility Release

### Added
- Full Windows compatibility support
- Windows-specific installation scripts
- PowerShell integration examples
- Windows path handling (UNC paths, drive letters)
- Windows configuration directory support (APPDATA)
- Windows error handling and user experience improvements

### Fixed
- Path separator handling on Windows
- Configuration file loading on Windows
- Web server startup on Windows
- Pre-commit hook integration with Windows Git

### Changed
- Updated build system to support Windows targets
- Enhanced documentation for Windows users
- Improved cross-platform configuration compatibility
`

		_, err = changelogWriter.Write([]byte(changelogContent))
		if err != nil {
			t.Fatalf("Failed to write CHANGELOG to ZIP: %v", err)
		}

		// Close ZIP writer
		err = zipWriter.Close()
		if err != nil {
			t.Fatalf("Failed to close ZIP writer: %v", err)
		}

		err = zipFile.Close()
		if err != nil {
			t.Fatalf("Failed to close ZIP file: %v", err)
		}

		// Verify ZIP file was created and has reasonable size
		zipInfo, err := os.Stat(zipPath)
		if err != nil {
			t.Fatalf("ZIP file was not created: %v", err)
		}

		zipSize := zipInfo.Size()
		if zipSize < 1024*1024 { // Less than 1MB
			t.Errorf("ZIP file seems too small: %d bytes", zipSize)
		}
		t.Logf("ZIP file size: %.2f MB", float64(zipSize)/(1024*1024))

		// Test extracting ZIP file
		extractDir := filepath.Join(tempDir, "extracted")
		err = extractZipFile(zipPath, extractDir)
		if err != nil {
			t.Fatalf("Failed to extract ZIP file: %v", err)
		}

		// Verify extracted contents
		expectedExtractedFiles := []string{
			"ferret-scan.exe",
			"README.txt",
			"LICENSE.txt",
			"CHANGELOG.txt",
		}

		for _, expectedFile := range expectedExtractedFiles {
			extractedPath := filepath.Join(extractDir, expectedFile)
			if _, err := os.Stat(extractedPath); os.IsNotExist(err) {
				t.Errorf("Extracted file not found: %s", expectedFile)
			}
		}

		// Test extracted binary
		extractedBinary := filepath.Join(extractDir, "ferret-scan.exe")
		versionCmd := exec.Command(extractedBinary, "--version")
		versionOutput, err := versionCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to execute extracted binary: %v\nOutput: %s", err, string(versionOutput))
		}

		versionStr := string(versionOutput)
		if !strings.Contains(versionStr, "ferret-scan") {
			t.Errorf("Extracted binary version output should contain 'ferret-scan': %s", versionStr)
		}

		t.Logf("Windows ZIP distribution created and validated successfully: %s", zipPath)
	})
}

// Helper function to extract ZIP files
func extractZipFile(src, dest string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer reader.Close()

	err = os.MkdirAll(dest, 0755)
	if err != nil {
		return err
	}

	for _, file := range reader.File {
		path := filepath.Join(dest, file.Name)

		if file.FileInfo().IsDir() {
			err = os.MkdirAll(path, file.FileInfo().Mode())
			if err != nil {
				return err
			}
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		_, err = io.Copy(targetFile, fileReader)
		if err != nil {
			return err
		}
	}

	return nil
}
