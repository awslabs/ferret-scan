// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/awslabs/ferret-scan/v2/internal/platform"
)

// tempDirOverride is the platform-specific temp directory from the config file's
// `platform:` block, if one was set.
//
// It is package state rather than a parameter because internal/config imports
// this package, so this package cannot import internal/config to read the value
// directly. The loader pushes it in with SetTempDirOverride once the config is
// parsed. This mirrors the FERRET_CONFIG_DIR environment override below: a
// process-wide setting, read from everywhere.
//
// The mutex is load-bearing, not defensive. Config loading is not confined to
// startup: the web server falls back to a per-request LoadConfigOrDefault, and
// pkg/scan calls it on every exported entry point, so a caller scanning from
// several goroutines writes this while other goroutines read it.
var (
	tempDirMu       sync.RWMutex
	tempDirOverride string
)

// SetTempDirOverride records the config file's platform-specific temp directory.
// An empty value clears the override. Called by the config loader; the config's
// `platform:` block was previously validated and then ignored.
func SetTempDirOverride(dir string) {
	tempDirMu.Lock()
	defer tempDirMu.Unlock()
	tempDirOverride = dir
}

// tempDirOverrideValue reads the override under the lock.
func tempDirOverrideValue() string {
	tempDirMu.RLock()
	defer tempDirMu.RUnlock()
	return tempDirOverride
}

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

// GetTempDir returns the temporary directory, preferring the config file's
// platform-specific override when one is set.
func GetTempDir() string {
	if dir := tempDirOverrideValue(); dir != "" {
		return dir
	}
	p := platform.GetPlatform()
	return p.GetTempDir()
}

// NormalizePath normalizes a file path for the current platform
// Handles Windows UNC paths, drive letters, and path separators
func NormalizePath(path string) string {
	p := platform.GetPlatform()
	return p.NormalizePath(path)
}

// JoinPath joins path elements using the platform-appropriate separator
func JoinPath(elements ...string) string {
	return filepath.Join(elements...)
}

// HasDriveLetter checks if a Windows path has a drive letter (C:, D:, etc.)
func HasDriveLetter(path string) bool {
	if !platform.IsWindows() {
		return false
	}
	return len(path) >= 2 && path[1] == ':'
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
	// A NUL byte is invalid in a path on every platform: Win32 treats it as the
	// string terminator, and Go's own syscall layer rejects it outright, so a
	// path containing one can never open the file the caller named. The Unix
	// validator already rejected it; this one silently accepted it, so a config
	// with an embedded NUL passed validation on Windows and failed later at the
	// syscall with a far less obvious error.
	for _, char := range path {
		if char == 0 {
			return &PathValidationError{
				Path:   path,
				Reason: "contains null byte",
			}
		}
	}

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
