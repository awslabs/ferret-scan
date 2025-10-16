// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"os"
	"path/filepath"
	"strings"
)

// WindowsPlatform implements Platform interface for Windows systems
type WindowsPlatform struct{}

// GetConfigDir returns the Windows-appropriate configuration directory
func (w *WindowsPlatform) GetConfigDir() string {
	// Check for explicit override first
	if dir := os.Getenv("FERRET_CONFIG_DIR"); dir != "" {
		return dir
	}

	// Try APPDATA first (recommended for Windows applications)
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "ferret-scan")
	}

	// Fallback to user profile directory
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		return filepath.Join(userProfile, ".ferret-scan")
	}

	// Last resort fallback
	return ".ferret-scan"
}

// GetTempDir returns the Windows temporary directory
func (w *WindowsPlatform) GetTempDir() string {
	if temp := os.Getenv("TEMP"); temp != "" {
		return temp
	}
	if tmp := os.Getenv("TMP"); tmp != "" {
		return tmp
	}
	return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
}

// GetExecutableExtension returns the Windows executable extension
func (w *WindowsPlatform) GetExecutableExtension() string {
	return ".exe"
}

// IsAbsolutePath checks if a path is absolute on Windows
func (w *WindowsPlatform) IsAbsolutePath(path string) bool {
	return filepath.IsAbs(path)
}

// NormalizePath normalizes a path for Windows
func (w *WindowsPlatform) NormalizePath(path string) string {
	// Convert forward slashes to backslashes
	normalized := filepath.Clean(path)

	// Handle UNC paths (\\server\share)
	if strings.HasPrefix(path, "\\\\") && !strings.HasPrefix(normalized, "\\\\") {
		normalized = "\\\\" + strings.TrimPrefix(normalized, "\\")
	}

	return normalized
}

// GetSystemInstallDir returns the system-wide installation directory
func (w *WindowsPlatform) GetSystemInstallDir() string {
	if programFiles := os.Getenv("PROGRAMFILES"); programFiles != "" {
		return filepath.Join(programFiles, "ferret-scan")
	}
	return filepath.Join("C:", "Program Files", "ferret-scan")
}

// GetUserInstallDir returns the user-specific installation directory
func (w *WindowsPlatform) GetUserInstallDir() string {
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		return filepath.Join(localAppData, "Programs", "ferret-scan")
	}
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		return filepath.Join(userProfile, "AppData", "Local", "Programs", "ferret-scan")
	}
	return filepath.Join(".", "ferret-scan")
}

// GetPathSeparator returns the Windows path separator
func (w *WindowsPlatform) GetPathSeparator() string {
	return "\\"
}

// SupportsCaseSensitivePaths returns false for Windows (case-insensitive by default)
func (w *WindowsPlatform) SupportsCaseSensitivePaths() bool {
	return false
}

// SupportsSymlinks returns true for Windows (supported in Windows 10+ with developer mode)
func (w *WindowsPlatform) SupportsSymlinks() bool {
	// Windows 10+ supports symlinks, but may require developer mode or admin privileges
	// We'll return true but handle errors gracefully in actual symlink operations
	return true
}
