// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SimpleFileAttributes represents basic file attributes that can be detected cross-platform
type SimpleFileAttributes struct {
	ReadOnly bool
	Hidden   bool
	Exists   bool
	Size     int64
}

// GetSimpleFileAttributes gets basic file attributes that work on all platforms
func GetSimpleFileAttributes(filePath string) (*SimpleFileAttributes, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &SimpleFileAttributes{
				Exists: false,
			}, nil
		}
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	attrs := &SimpleFileAttributes{
		Exists: true,
		Size:   info.Size(),
	}

	// Check if file is read-only by trying to open for write
	if file, err := os.OpenFile(cleanPath, os.O_WRONLY, 0); err != nil {
		if os.IsPermission(err) {
			attrs.ReadOnly = true
		}
	} else {
		file.Close()
	}

	// Check if file is hidden (basic check)
	attrs.Hidden = strings.HasPrefix(info.Name(), ".")

	return attrs, nil
}

// CheckFileAccessibility checks if a file can be accessed and provides helpful error messages
func CheckFileAccessibility(filePath string) error {
	cleanPath := filepath.Clean(filePath)
	attrs, err := GetSimpleFileAttributes(cleanPath)
	if err != nil {
		return WrapFileError(err, cleanPath, "checking file attributes")
	}

	if !attrs.Exists {
		return fmt.Errorf("file does not exist: %s", cleanPath)
	}

	var issues []string
	if attrs.ReadOnly {
		issues = append(issues, "file is read-only")
	}
	if attrs.Hidden {
		issues = append(issues, "file is hidden")
	}
	if attrs.Size == 0 {
		issues = append(issues, "file is empty")
	}

	if len(issues) > 0 {
		suggestion := ""
		if IsWindows() {
			suggestion = "\nSuggestions for Windows:\n"
			if attrs.ReadOnly {
				suggestion += "  • Use 'attrib -r \"" + cleanPath + "\"' to remove read-only attribute\n"
				suggestion += "  • Run as Administrator if needed\n"
			}
			if attrs.Hidden {
				suggestion += "  • Use 'attrib -h \"" + cleanPath + "\"' to remove hidden attribute\n"
				suggestion += "  • Enable 'Show hidden files' in File Explorer\n"
			}
		} else {
			suggestion = "\nSuggestions for Unix:\n"
			if attrs.ReadOnly {
				suggestion += "  • Use 'chmod +w \"" + cleanPath + "\"' to add write permission\n"
			}
			if attrs.Hidden {
				suggestion += "  • Hidden files start with '.' on Unix systems\n"
			}
		}

		return fmt.Errorf("file access issues for '%s': %v%s", cleanPath, issues, suggestion)
	}

	// Try to actually open the file
	file, err := os.Open(cleanPath)
	if err != nil {
		return WrapFileError(err, cleanPath, "opening file for reading")
	}
	file.Close()

	return nil
}

// IsFileReadOnly checks if a file is read-only using cross-platform methods
func IsFileReadOnly(filePath string) (bool, error) {
	cleanPath := filepath.Clean(filePath)
	attrs, err := GetSimpleFileAttributes(cleanPath)
	if err != nil {
		return false, err
	}

	if !attrs.Exists {
		return false, fmt.Errorf("file does not exist: %s", cleanPath)
	}

	return attrs.ReadOnly, nil
}

// IsFileHidden checks if a file is hidden using cross-platform methods
func IsFileHidden(filePath string) (bool, error) {
	cleanPath := filepath.Clean(filePath)
	attrs, err := GetSimpleFileAttributes(cleanPath)
	if err != nil {
		return false, err
	}

	if !attrs.Exists {
		return false, fmt.Errorf("file does not exist: %s", cleanPath)
	}

	return attrs.Hidden, nil
}

// SetFileReadOnly attempts to set or remove read-only attribute
func SetFileReadOnly(filePath string, readOnly bool) error {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return WrapFileError(err, cleanPath, "getting file info")
	}

	mode := info.Mode()
	if readOnly {
		// Remove write permissions
		mode &= ^os.FileMode(0222)
	} else {
		// Add write permission for owner
		mode |= 0200
	}

	err = os.Chmod(cleanPath, mode)
	if err != nil {
		return WrapFileError(err, cleanPath, "setting file permissions")
	}

	return nil
}
