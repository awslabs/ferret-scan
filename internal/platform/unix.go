// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"os"
	"path/filepath"
)

// UnixPlatform implements Platform interface for Unix-like systems (Linux, macOS, etc.)
type UnixPlatform struct{}

// GetConfigDir returns the Unix-appropriate configuration directory
func (u *UnixPlatform) GetConfigDir() string {
	// Check for explicit override first
	if dir := os.Getenv("FERRET_CONFIG_DIR"); dir != "" {
		return dir
	}

	// Check XDG Base Directory specification
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "ferret-scan")
	}

	// Default to home directory
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ferret-scan")
}

// GetTempDir returns the Unix temporary directory
func (u *UnixPlatform) GetTempDir() string {
	if tmpDir := os.Getenv("TMPDIR"); tmpDir != "" {
		return tmpDir
	}
	if tmp := os.Getenv("TMP"); tmp != "" {
		return tmp
	}
	return "/tmp"
}

// GetExecutableExtension returns empty string for Unix (no extension needed)
func (u *UnixPlatform) GetExecutableExtension() string {
	return ""
}

// IsAbsolutePath checks if a path is absolute on Unix
func (u *UnixPlatform) IsAbsolutePath(path string) bool {
	return filepath.IsAbs(path)
}

// NormalizePath normalizes a path for Unix
func (u *UnixPlatform) NormalizePath(path string) string {
	return filepath.Clean(path)
}

// GetSystemInstallDir returns the system-wide installation directory
func (u *UnixPlatform) GetSystemInstallDir() string {
	return "/usr/local/bin"
}

// GetUserInstallDir returns the user-specific installation directory
func (u *UnixPlatform) GetUserInstallDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin")
}

// GetPathSeparator returns the Unix path separator
func (u *UnixPlatform) GetPathSeparator() string {
	return "/"
}

// SupportsCaseSensitivePaths returns true for Unix (case-sensitive)
func (u *UnixPlatform) SupportsCaseSensitivePaths() bool {
	return true
}

// SupportsSymlinks returns true for Unix (full symlink support)
func (u *UnixPlatform) SupportsSymlinks() bool {
	return true
}
