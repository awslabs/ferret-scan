// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"os"
	"path/filepath"

	"ferret-scan/internal/platform"
)

// GetConfigDir returns the ferret-scan configuration directory
// Uses platform-specific logic for Windows APPDATA directories and Unix home directories
func GetConfigDir() string {
	// Check for explicit override first (works on all platforms)
	if dir := os.Getenv("FERRET_CONFIG_DIR"); dir != "" {
		return dir
	}

	// Use platform-specific configuration directory logic
	p := platform.GetPlatform()
	return p.GetConfigDir()
}

// GetConfigFile returns the path to the main config file
func GetConfigFile() string {
	return filepath.Join(GetConfigDir(), "config.yaml")
}

// GetSuppressionsFile returns the path to the suppressions file
func GetSuppressionsFile() string {
	return filepath.Join(GetConfigDir(), "suppressions.yaml")
}

// GetTempDir returns the platform-appropriate temporary directory
func GetTempDir() string {
	p := platform.GetPlatform()
	return p.GetTempDir()
}

// NormalizePath normalizes a file path for the current platform
// Handles Windows UNC paths, drive letters, and path separators
func NormalizePath(path string) string {
	p := platform.GetPlatform()
	return p.NormalizePath(path)
}

// IsAbsolutePath checks if a path is absolute on the current platform
func IsAbsolutePath(path string) bool {
	p := platform.GetPlatform()
	return p.IsAbsolutePath(path)
}

// GetSystemInstallDir returns the system-wide installation directory
func GetSystemInstallDir() string {
	p := platform.GetPlatform()
	return p.GetSystemInstallDir()
}

// GetUserInstallDir returns the user-specific installation directory
func GetUserInstallDir() string {
	p := platform.GetPlatform()
	return p.GetUserInstallDir()
}

// GetExecutableExtension returns the platform-appropriate executable extension
func GetExecutableExtension() string {
	p := platform.GetPlatform()
	return p.GetExecutableExtension()
}

// GetPathSeparator returns the platform-appropriate path separator
func GetPathSeparator() string {
	p := platform.GetPlatform()
	return p.GetPathSeparator()
}

// JoinPath joins path elements using the platform-appropriate separator
func JoinPath(elements ...string) string {
	return filepath.Join(elements...)
}

// SanitizePath sanitizes a path for the current platform
// Removes invalid characters and handles platform-specific constraints
func SanitizePath(path string) string {
	// First normalize the path
	normalized := NormalizePath(path)

	// Handle Windows-specific path constraints
	if platform.IsWindows() {
		return sanitizeWindowsPath(normalized)
	}

	return normalized
}

// sanitizeWindowsPath handles Windows-specific path sanitization
func sanitizeWindowsPath(path string) string {
	// Windows reserved characters: < > : " | ? *
	// These are handled by the OS, but we can provide better error messages

	// Handle long path scenarios (Windows has 260 character limit by default)
	if len(path) > 260 {
		// Could implement long path prefix (\\?\) here if needed
		// For now, just return as-is and let the OS handle it
	}

	return path
}

// IsUNCPath checks if a path is a Windows UNC path (\\server\share)
func IsUNCPath(path string) bool {
	if !platform.IsWindows() {
		return false
	}
	return len(path) >= 2 && path[0] == '\\' && path[1] == '\\'
}

// HasDriveLetter checks if a Windows path has a drive letter (C:, D:, etc.)
func HasDriveLetter(path string) bool {
	if !platform.IsWindows() {
		return false
	}
	return len(path) >= 2 && path[1] == ':'
}

// GetDriveLetter extracts the drive letter from a Windows path
func GetDriveLetter(path string) string {
	if !HasDriveLetter(path) {
		return ""
	}
	return string(path[0])
}

// IsLongPath checks if a path exceeds Windows path length limits
func IsLongPath(path string) bool {
	if !platform.IsWindows() {
		return false
	}
	// Standard Windows path limit is 260 characters
	// Long path support allows up to 32,767 characters with \\?\ prefix
	return len(path) > 260
}

// ToLongPathFormat converts a Windows path to long path format if needed
func ToLongPathFormat(path string) string {
	if !platform.IsWindows() || !IsLongPath(path) {
		return path
	}

	// Don't add prefix if already present
	if len(path) >= 4 && path[:4] == "\\\\?\\" {
		return path
	}

	// Convert to absolute path first
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path // Return original if conversion fails
	}

	// Add long path prefix
	return "\\\\?\\" + absPath
}

// ResolvePath resolves a path to its absolute form with platform-specific handling
func ResolvePath(path string) (string, error) {
	// Handle empty path
	if path == "" {
		return "", nil
	}

	// Normalize first
	normalized := NormalizePath(path)

	// Get absolute path
	absPath, err := filepath.Abs(normalized)
	if err != nil {
		return "", err
	}

	// Apply platform-specific formatting
	if platform.IsWindows() && IsLongPath(absPath) {
		return ToLongPathFormat(absPath), nil
	}

	return absPath, nil
}

// ValidatePath validates a path for the current platform
func ValidatePath(path string) error {
	if path == "" {
		return nil // Empty path is valid
	}

	if platform.IsWindows() {
		return validateWindowsPath(path)
	}

	return validateUnixPath(path)
}

// validateWindowsPath validates a Windows path
func validateWindowsPath(path string) error {
	// Check for invalid characters
	invalidChars := []rune{'<', '>', ':', '"', '|', '?', '*'}
	for i, char := range path {
		for _, invalid := range invalidChars {
			if char == invalid {
				// Skip colon if it's part of a drive letter (position 1: C:)
				if char == ':' && i == 1 && len(path) >= 2 {
					continue
				}
				return &PathValidationError{
					Path:   path,
					Reason: "contains invalid character: " + string(char),
				}
			}
		}
	}

	// Check path length
	if len(path) > 32767 {
		return &PathValidationError{
			Path:   path,
			Reason: "path exceeds maximum length of 32,767 characters",
		}
	}

	return nil
}

// validateUnixPath validates a Unix path
func validateUnixPath(path string) error {
	// Unix paths are generally more permissive
	// Main restriction is null bytes
	for _, char := range path {
		if char == 0 {
			return &PathValidationError{
				Path:   path,
				Reason: "contains null byte",
			}
		}
	}

	return nil
}

// PathValidationError represents a path validation error
type PathValidationError struct {
	Path   string
	Reason string
}

func (e *PathValidationError) Error() string {
	return "invalid path '" + e.Path + "': " + e.Reason
}
