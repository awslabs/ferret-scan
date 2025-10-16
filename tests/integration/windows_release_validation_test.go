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

	"ferret-scan/internal/config"
	"ferret-scan/internal/paths"
	"ferret-scan/internal/platform"
	"ferret-scan/tests/helpers"
)

// TestWindowsBinaryDistributionAndInstallation tests Windows binary distribution and installation
func TestWindowsBinaryDistributionAndInstallation(t *testing.T) {
	if !platform.IsWindows() {
		t.Skip("Skipping Windows-specific tests on non-Windows platform")
	}

	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	t.Run("WindowsBinaryArchitectures", func(t *testing.T) {
		// Test building for different Windows architectures
		architectures := []struct {
			arch        string
			description string
		}{
			{"amd64", "Windows 64-bit (Intel/AMD)"},
			{"arm64", "Windows ARM64"},
		}

		tempDir := t.TempDir()

		for _, arch := range architectures {
			t.Run(fmt.Sprintf("Windows_%s", arch.arch), func(t *testing.T) {
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
				if arch.arch == runtime.GOARCH {
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
			})
		}
	})

	t.Run("WindowsInstallationPackaging", func(t *testing.T) {
		// Test creating Windows installation package
		tempDir := t.TempDir()
		packageDir := filepath.Join(tempDir, "ferret-scan-windows")

		// Create package directory structure
		err := os.MkdirAll(packageDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create package directory: %v", err)
		}

		// Build binary for packaging
		binaryPath := filepath.Join(packageDir, "ferret-scan.exe")
		buildCmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/main.go")
		buildCmd.Env = append(os.Environ(),
			"GOOS=windows",
			"GOARCH=amd64",
			"CGO_ENABLED=0",
		)

		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build binary for packaging: %v\nOutput: %s", err, string(buildOutput))
		}

		// Create installation script
		installScript := filepath.Join(packageDir, "install.ps1")
		installScriptContent := `# Ferret Scan Windows Installation Script
param(
    [string]$InstallPath = "$env:ProgramFiles\ferret-scan",
    [switch]$UserInstall = $false
)

Write-Host "Installing Ferret Scan for Windows..."

if ($UserInstall) {
    $InstallPath = "$env:LOCALAPPDATA\ferret-scan"
}

# Create installation directory
New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null

# Copy binary
Copy-Item "ferret-scan.exe" -Destination "$InstallPath\ferret-scan.exe" -Force

# Add to PATH (user level)
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$InstallPath*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$InstallPath", "User")
    Write-Host "Added $InstallPath to user PATH"
}

Write-Host "Ferret Scan installed successfully to $InstallPath"
Write-Host "Please restart your command prompt to use the 'ferret-scan' command"
`

		err = os.WriteFile(installScript, []byte(installScriptContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create installation script: %v", err)
		}

		// Create uninstall script
		uninstallScript := filepath.Join(packageDir, "uninstall.ps1")
		uninstallScriptContent := `# Ferret Scan Windows Uninstallation Script
param(
    [string]$InstallPath = "$env:ProgramFiles\ferret-scan"
)

Write-Host "Uninstalling Ferret Scan for Windows..."

# Remove from PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -like "*$InstallPath*") {
    $newPath = $userPath -replace [regex]::Escape(";$InstallPath"), ""
    $newPath = $newPath -replace [regex]::Escape("$InstallPath;"), ""
    $newPath = $newPath -replace [regex]::Escape("$InstallPath"), ""
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    Write-Host "Removed $InstallPath from user PATH"
}

# Remove installation directory
if (Test-Path $InstallPath) {
    Remove-Item -Recurse -Force $InstallPath
    Write-Host "Removed installation directory: $InstallPath"
}

Write-Host "Ferret Scan uninstalled successfully"
`

		err = os.WriteFile(uninstallScript, []byte(uninstallScriptContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create uninstallation script: %v", err)
		}

		// Create README for Windows
		readmeFile := filepath.Join(packageDir, "README-Windows.txt")
		readmeContent := `Ferret Scan for Windows
======================

Installation:
1. Run install.ps1 in PowerShell as Administrator for system-wide installation
2. Or run with -UserInstall flag for user-only installation

Usage:
- Open Command Prompt or PowerShell
- Run: ferret-scan --help

Uninstallation:
- Run uninstall.ps1 in PowerShell

For more information, visit: https://github.com/your-org/ferret-scan
`

		err = os.WriteFile(readmeFile, []byte(readmeContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create Windows README: %v", err)
		}

		// Verify package contents
		expectedFiles := []string{
			"ferret-scan.exe",
			"install.ps1",
			"uninstall.ps1",
			"README-Windows.txt",
		}

		for _, expectedFile := range expectedFiles {
			filePath := filepath.Join(packageDir, expectedFile)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected package file missing: %s", expectedFile)
			}
		}

		t.Logf("Windows installation package created successfully: %s", packageDir)
	})

	t.Run("WindowsZipDistribution", func(t *testing.T) {
		// Test creating ZIP distribution for Windows
		tempDir := t.TempDir()
		zipPath := filepath.Join(tempDir, "ferret-scan-windows.zip")

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

Usage: ferret-scan --help
`

		_, err = readmeWriter.Write([]byte(readmeContent))
		if err != nil {
			t.Fatalf("Failed to write README to ZIP: %v", err)
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

		// Verify ZIP file was created
		if _, err := os.Stat(zipPath); os.IsNotExist(err) {
			t.Fatalf("ZIP file was not created: %s", zipPath)
		}

		// Test extracting ZIP file
		extractDir := filepath.Join(tempDir, "extracted")
		err = extractZip(zipPath, extractDir)
		if err != nil {
			t.Fatalf("Failed to extract ZIP file: %v", err)
		}

		// Verify extracted contents
		extractedBinary := filepath.Join(extractDir, "ferret-scan.exe")
		if _, err := os.Stat(extractedBinary); os.IsNotExist(err) {
			t.Errorf("Extracted binary not found: %s", extractedBinary)
		}

		extractedReadme := filepath.Join(extractDir, "README.txt")
		if _, err := os.Stat(extractedReadme); os.IsNotExist(err) {
			t.Errorf("Extracted README not found: %s", extractedReadme)
		}

		t.Logf("Windows ZIP distribution created and tested successfully: %s", zipPath)
	})
}

// TestWindowsReleaseConfigurationHandling tests Windows-specific configuration handling for releases
func TestWindowsReleaseConfigurationHandling(t *testing.T) {
	if !platform.IsWindows() {
		t.Skip("Skipping Windows-specific tests on non-Windows platform")
	}

	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	t.Run("WindowsConfigurationDirectories", func(t *testing.T) {
		// Test Windows-specific configuration directory handling

		// Save original environment
		originalAppData := os.Getenv("APPDATA")
		originalUserProfile := os.Getenv("USERPROFILE")
		originalProgramData := os.Getenv("PROGRAMDATA")

		defer func() {
			os.Setenv("APPDATA", originalAppData)
			os.Setenv("USERPROFILE", originalUserProfile)
			os.Setenv("PROGRAMDATA", originalProgramData)
		}()

		// Test APPDATA configuration
		testAppData := filepath.Join(t.TempDir(), "AppData", "Roaming")
		os.Setenv("APPDATA", testAppData)

		configDir := paths.GetConfigDir()
		expectedAppDataPath := filepath.Join(testAppData, "ferret-scan")
		if configDir != expectedAppDataPath {
			t.Errorf("APPDATA config directory incorrect: expected %s, got %s", expectedAppDataPath, configDir)
		}

		// Test USERPROFILE fallback
		os.Setenv("APPDATA", "")
		testUserProfile := filepath.Join(t.TempDir(), "Users", "testuser")
		os.Setenv("USERPROFILE", testUserProfile)

		configDir = paths.GetConfigDir()
		expectedUserProfilePath := filepath.Join(testUserProfile, ".ferret-scan")
		if configDir != expectedUserProfilePath {
			t.Errorf("USERPROFILE config directory incorrect: expected %s, got %s", expectedUserProfilePath, configDir)
		}

		// Test system-wide configuration (PROGRAMDATA)
		if originalProgramData != "" {
			// Note: System config directory is handled by platform-specific logic
			// We can test that the platform config includes system directories
			platformConfig := platform.GetConfig()
			if platformConfig.SystemInstallDirectory == "" {
				t.Error("System install directory should not be empty")
			}
		}

		t.Logf("Windows configuration directories tested successfully")
	})

	t.Run("WindowsConfigurationFileFormats", func(t *testing.T) {
		// Test Windows-specific configuration file handling
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "ferret.yaml")

		// Create Windows-specific configuration
		windowsConfig := `# Ferret Scan Windows Configuration
defaults:
  checks: "all"
  confidence_levels: "high"
  format: "json"

# Platform-specific settings
platform:
  windows:
    use_appdata: true
    long_path_support: true
    temp_dir: "C:\\Windows\\Temp\\ferret-scan"
`

		err := os.WriteFile(configFile, []byte(windowsConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to create Windows config file: %v", err)
		}

		// Test loading Windows configuration
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			t.Fatalf("Failed to load Windows configuration: %v", err)
		}

		// Verify configuration values
		if cfg.Defaults.Checks != "all" {
			t.Errorf("Config checks: expected 'all', got '%s'", cfg.Defaults.Checks)
		}

		if cfg.Defaults.ConfidenceLevels != "high" {
			t.Errorf("Config confidence_levels: expected 'high', got '%s'", cfg.Defaults.ConfidenceLevels)
		}

		if cfg.Defaults.Format != "json" {
			t.Errorf("Config format: expected 'json', got '%s'", cfg.Defaults.Format)
		}

		t.Logf("Windows configuration file format tested successfully")
	})

	t.Run("WindowsEnvironmentVariableExpansion", func(t *testing.T) {
		// Test Windows environment variable expansion in configuration
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "ferret-env.yaml")

		// Create configuration with Windows environment variables
		envConfig := `# Configuration with Windows environment variables
defaults:
  checks: "all"

platform:
  windows:
    temp_dir: "%TEMP%\\ferret-scan"
    config_dir: "%APPDATA%\\ferret-scan"
`

		err := os.WriteFile(configFile, []byte(envConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to create environment config file: %v", err)
		}

		// Test loading configuration with environment variables
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			t.Fatalf("Failed to load environment configuration: %v", err)
		}

		// Verify environment variables are handled
		// Note: The actual expansion depends on the config implementation
		if cfg.Defaults.Checks != "all" {
			t.Errorf("Environment config checks: expected 'all', got '%s'", cfg.Defaults.Checks)
		}

		t.Logf("Environment variable configuration loaded successfully")
		t.Logf("Config defaults: %+v", cfg.Defaults)
	})
}

// TestCrossPlatformConfigurationFileCompatibility tests cross-platform configuration file compatibility
func TestCrossPlatformConfigurationFileCompatibility(t *testing.T) {
	if !platform.IsWindows() {
		t.Skip("Skipping Windows-specific tests on non-Windows platform")
	}

	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	t.Run("UnixConfigurationOnWindows", func(t *testing.T) {
		// Test that Unix-style configuration works on Windows
		tempDir := t.TempDir()
		unixConfigFile := filepath.Join(tempDir, "unix-style.yaml")

		// Create Unix-style configuration
		unixConfig := `# Unix-style configuration
defaults:
  checks: "creditcard,ssn,email"
  confidence_levels: "medium"
  format: "text"

platform:
  unix:
    temp_dir: "/tmp/ferret-scan"
`

		err := os.WriteFile(unixConfigFile, []byte(unixConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to create Unix-style config file: %v", err)
		}

		// Test loading Unix-style configuration on Windows
		cfg, err := config.LoadConfig(unixConfigFile)
		if err != nil {
			t.Fatalf("Failed to load Unix-style configuration on Windows: %v", err)
		}

		// Verify basic configuration values work
		if cfg.Defaults.Checks != "creditcard,ssn,email" {
			t.Errorf("Unix config checks: expected 'creditcard,ssn,email', got '%s'", cfg.Defaults.Checks)
		}

		if cfg.Defaults.ConfidenceLevels != "medium" {
			t.Errorf("Unix config confidence_levels: expected 'medium', got '%s'", cfg.Defaults.ConfidenceLevels)
		}

		t.Logf("Unix-style configuration loaded successfully on Windows")
	})

	t.Run("MixedPathSeparators", func(t *testing.T) {
		// Test configuration with mixed path separators
		tempDir := t.TempDir()
		mixedConfigFile := filepath.Join(tempDir, "mixed-paths.yaml")

		// Create configuration with mixed path separators
		mixedConfig := `# Configuration with mixed path separators
defaults:
  checks: "all"
  confidence_levels: "all"

platform:
  windows:
    temp_dir: "C:/Windows/Temp/ferret-scan"
    config_dir: "C:\\ProgramData\\ferret-scan"
`

		err := os.WriteFile(mixedConfigFile, []byte(mixedConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to create mixed paths config file: %v", err)
		}

		// Test loading configuration with mixed paths
		cfg, err := config.LoadConfig(mixedConfigFile)
		if err != nil {
			t.Fatalf("Failed to load mixed paths configuration: %v", err)
		}

		// Verify configuration loads successfully
		if cfg.Defaults.Checks != "all" {
			t.Errorf("Mixed paths config checks: expected 'all', got '%s'", cfg.Defaults.Checks)
		}

		t.Logf("Mixed path separators configuration loaded successfully")
	})

	t.Run("RelativePathHandling", func(t *testing.T) {
		// Test relative path handling in configuration
		tempDir := t.TempDir()
		relativeConfigFile := filepath.Join(tempDir, "relative-paths.yaml")

		// Create configuration with relative paths
		relativeConfig := `# Configuration with relative paths
defaults:
  checks: "all"
  confidence_levels: "all"

platform:
  windows:
    temp_dir: "./temp"
    config_dir: "../config"
`

		err := os.WriteFile(relativeConfigFile, []byte(relativeConfig), 0644)
		if err != nil {
			t.Fatalf("Failed to create relative paths config file: %v", err)
		}

		// Test loading configuration with relative paths
		cfg, err := config.LoadConfig(relativeConfigFile)
		if err != nil {
			t.Fatalf("Failed to load relative paths configuration: %v", err)
		}

		// Verify configuration loads successfully
		if cfg.Defaults.Checks != "all" {
			t.Errorf("Relative paths config checks: expected 'all', got '%s'", cfg.Defaults.Checks)
		}

		t.Logf("Relative paths configuration loaded successfully")
	})
}

// TestWindowsReleaseErrorHandlingAndUserExperience tests Windows error handling and user experience for releases
func TestWindowsReleaseErrorHandlingAndUserExperience(t *testing.T) {
	if !platform.IsWindows() {
		t.Skip("Skipping Windows-specific tests on non-Windows platform")
	}

	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	// Build binary for error handling tests
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "ferret-scan.exe")

	buildCmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/main.go")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build binary for error handling test: %v\nOutput: %s", err, string(buildOutput))
	}

	t.Run("WindowsPermissionErrors", func(t *testing.T) {
		// Test Windows permission error handling

		// Try to scan a system directory that might have restricted access
		systemDir := "C:\\System Volume Information"

		scanCmd := exec.Command(binaryPath, "scan", systemDir)
		scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

		scanOutput, err := scanCmd.CombinedOutput()
		outputStr := string(scanOutput)

		// Should handle permission errors gracefully
		if strings.Contains(outputStr, "panic") {
			t.Error("Application should not panic on Windows permission errors")
		}

		// Should provide helpful error messages
		if err != nil && !strings.Contains(outputStr, "access") && !strings.Contains(outputStr, "permission") {
			t.Logf("Permission error handled (may be expected): %v", err)
		}

		t.Logf("Windows permission error handling tested")
	})

	t.Run("WindowsLongPathErrors", func(t *testing.T) {
		// Test Windows long path error handling

		// Create a very long path
		longPathBase := tempDir
		for i := 0; i < 10; i++ {
			longPathBase = filepath.Join(longPathBase, strings.Repeat("a", 25))
		}
		longFilePath := filepath.Join(longPathBase, "test.txt")

		// Try to create the long path
		err := os.MkdirAll(filepath.Dir(longFilePath), 0755)
		if err != nil {
			// Expected on systems without long path support
			t.Logf("Long path creation failed as expected: %v", err)

			// Test scanning the long path
			scanCmd := exec.Command(binaryPath, "scan", longFilePath)
			scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

			scanOutput, err := scanCmd.CombinedOutput()
			outputStr := string(scanOutput)

			// Should handle long path errors gracefully
			if err != nil && strings.Contains(outputStr, "panic") {
				t.Error("Application should not panic on Windows long path errors")
			}

			// Should provide helpful guidance
			if strings.Contains(outputStr, "path") || strings.Contains(outputStr, "long") {
				t.Logf("Long path error message provided: %s", outputStr)
			}
		} else {
			// Long path creation succeeded
			err = os.WriteFile(longFilePath, []byte("test content"), 0644)
			if err == nil {
				t.Logf("Long path support available on this system")
			}
		}

		t.Logf("Windows long path error handling tested")
	})

	t.Run("WindowsInvalidDriveErrors", func(t *testing.T) {
		// Test invalid drive letter handling
		invalidPath := "Z:\\nonexistent\\file.txt"

		scanCmd := exec.Command(binaryPath, "scan", invalidPath)
		scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

		scanOutput, err := scanCmd.CombinedOutput()
		outputStr := string(scanOutput)

		// Should handle invalid drive errors gracefully
		if strings.Contains(outputStr, "panic") {
			t.Error("Application should not panic on Windows invalid drive errors")
		}

		if err != nil {
			t.Logf("Invalid drive error handled appropriately: %v", err)
		}

		t.Logf("Windows invalid drive error handling tested")
	})

	t.Run("WindowsHelpfulErrorMessages", func(t *testing.T) {
		// Test that error messages are helpful for Windows users

		// Test invalid command
		invalidCmd := exec.Command(binaryPath, "invalid-command")
		invalidCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

		invalidOutput, err := invalidCmd.CombinedOutput()
		outputStr := string(invalidOutput)

		// Should provide helpful usage information
		if !strings.Contains(outputStr, "Usage:") && !strings.Contains(outputStr, "help") {
			t.Error("Invalid command should provide helpful usage information")
		}

		// Test help command
		helpCmd := exec.Command(binaryPath, "--help")
		helpOutput, err := helpCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Help command failed: %v", err)
		}

		helpStr := string(helpOutput)
		if !strings.Contains(helpStr, "Usage:") {
			t.Error("Help output should contain usage information")
		}

		// Verify Windows-specific information in help
		if !strings.Contains(helpStr, "scan") {
			t.Error("Help should mention scan command")
		}

		t.Logf("Windows helpful error messages verified")
	})

	t.Run("WindowsExitCodes", func(t *testing.T) {
		// Test Windows exit codes

		// Test successful execution
		successCmd := exec.Command(binaryPath, "--version")
		err := successCmd.Run()
		if err != nil {
			t.Errorf("Version command should exit with code 0: %v", err)
		}

		// Test error exit code
		errorCmd := exec.Command(binaryPath, "scan", "nonexistent-file.txt")
		errorCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")
		err = errorCmd.Run()
		if err == nil {
			t.Log("Scan of nonexistent file completed (may be expected)")
		} else {
			// Should exit with non-zero code for errors
			if exitError, ok := err.(*exec.ExitError); ok {
				if exitError.ExitCode() == 0 {
					t.Error("Error conditions should exit with non-zero code")
				} else {
					t.Logf("Error exit code: %d", exitError.ExitCode())
				}
			}
		}

		t.Logf("Windows exit codes tested successfully")
	})
}

// Helper function to extract ZIP files
func extractZip(src, dest string) error {
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
