// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/observability"
)

// OutputStructureManager manages the creation of mirrored folder structures for redacted documents
type OutputStructureManager struct {
	// baseOutputDir is the base directory where redacted files will be stored
	baseOutputDir string

	// observer handles observability and metrics
	observer *observability.StandardObserver

	// preservePermissions indicates whether to preserve original file permissions
	preservePermissions bool

	// preserveTimestamps indicates whether to preserve original file timestamps
	preserveTimestamps bool
}

// FileInfo contains information about a file for copying
type FileInfo struct {
	Path        string
	Mode        os.FileMode
	ModTime     time.Time
	Size        int64
	IsDirectory bool
}

// NewOutputStructureManager creates a new OutputStructureManager
func NewOutputStructureManager(baseOutputDir string, observer *observability.StandardObserver) (*OutputStructureManager, error) {
	if baseOutputDir == "" {
		return nil, fmt.Errorf("base output directory cannot be empty")
	}

	// Clean and validate the path
	cleanPath := filepath.Clean(baseOutputDir)
	if !filepath.IsAbs(cleanPath) && !strings.HasPrefix(cleanPath, "./") && !strings.HasPrefix(cleanPath, "../") {
		cleanPath = "./" + cleanPath
	}

	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	return &OutputStructureManager{
		baseOutputDir:       cleanPath,
		observer:            observer,
		preservePermissions: true,
		preserveTimestamps:  true,
	}, nil
}

// CreateMirroredPath generates the output path for a redacted file, mirroring the original structure
func (osm *OutputStructureManager) CreateMirroredPath(originalPath string) (string, error) {
	finishTiming := osm.observer.StartTiming("output_manager", "create_mirrored_path", originalPath)
	defer finishTiming(true, map[string]interface{}{
		"base_output_dir": osm.baseOutputDir,
	})

	if originalPath == "" {
		return "", fmt.Errorf("original path cannot be empty")
	}

	// Clean the original path
	cleanOriginalPath := filepath.Clean(originalPath)

	// Convert to absolute path if it's relative
	var absOriginalPath string
	if filepath.IsAbs(cleanOriginalPath) {
		absOriginalPath = cleanOriginalPath
	} else {
		// For relative paths, we want to preserve the relative structure
		absOriginalPath = cleanOriginalPath
	}

	// Remove any leading path separators or drive letters for cross-platform compatibility
	relativePath := osm.makeRelativePath(absOriginalPath)

	// Combine with base output directory
	mirroredPath := filepath.Join(osm.baseOutputDir, relativePath)

	// Ensure the path is clean and doesn't escape the base directory
	cleanMirroredPath := filepath.Clean(mirroredPath)
	if !strings.HasPrefix(cleanMirroredPath, filepath.Clean(osm.baseOutputDir)) {
		return "", fmt.Errorf("mirrored path would escape base output directory: %s", cleanMirroredPath)
	}

	return cleanMirroredPath, nil
}

// makeRelativePath converts an absolute or relative path to a relative path suitable for mirroring
func (osm *OutputStructureManager) makeRelativePath(path string) string {
	// Handle current directory references first
	if path == "." || path == "" {
		return "current"
	}

	// Remove leading "./" from relative paths
	path = strings.TrimPrefix(path, "./")

	// Remove volume name on Windows (e.g., "C:")
	if len(path) >= 2 && path[1] == ':' {
		path = path[2:]
	}

	// Convert backslashes to forward slashes for consistency
	path = strings.ReplaceAll(path, "\\", "/")

	// Remove leading path separators
	path = strings.TrimLeft(path, "/")
	path = strings.TrimLeft(path, string(filepath.Separator))

	// Handle empty path after processing
	if path == "" {
		return "current"
	}

	// Replace any remaining problematic characters
	path = strings.ReplaceAll(path, "..", "parent")

	return path
}

// EnsureDirectoryExists creates the directory structure for the given path if it doesn't exist
func (osm *OutputStructureManager) EnsureDirectoryExists(path string) error {
	finishTiming := osm.observer.StartTiming("output_manager", "ensure_directory_exists", path)
	defer finishTiming(true, map[string]interface{}{
		"path": path,
	})

	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Get the directory part of the path
	dir := filepath.Dir(path)

	// Check if directory already exists
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", dir)
		}
		return nil // Directory already exists
	}

	// Create the directory with secure permissions (owner only)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	return nil
}

// CopyFileStructure copies a file from source to destination, preserving attributes
func (osm *OutputStructureManager) CopyFileStructure(sourcePath, destPath string) error {
	finishTiming := osm.observer.StartTiming("output_manager", "copy_file_structure", sourcePath)
	defer finishTiming(true, map[string]interface{}{
		"source_path": sourcePath,
		"dest_path":   destPath,
	})

	if sourcePath == "" || destPath == "" {
		return fmt.Errorf("source and destination paths cannot be empty")
	}

	// Get source file info
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", sourcePath, err)
	}

	// Ensure destination directory exists
	if err := osm.EnsureDirectoryExists(destPath); err != nil {
		return fmt.Errorf("failed to ensure destination directory: %w", err)
	}

	// Copy the file
	if err := osm.copyFile(sourcePath, destPath, sourceInfo); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Preserve attributes if configured
	if err := osm.preserveFileAttributes(destPath, sourceInfo); err != nil {
		// Log warning but don't fail the operation
		osm.observer.StartTiming("output_manager", "preserve_attributes_warning", destPath)(false, map[string]interface{}{
			"warning": err.Error(),
		})
	}

	return nil
}

// copyFile performs the actual file copy operation
func (osm *OutputStructureManager) copyFile(sourcePath, destPath string, sourceInfo os.FileInfo) error {
	// Open source file
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// Copy file contents
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	// Ensure all data is written to disk
	err = destFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	return nil
}

// preserveFileAttributes preserves file permissions and timestamps
func (osm *OutputStructureManager) preserveFileAttributes(destPath string, sourceInfo os.FileInfo) error {
	// Preserve permissions
	if osm.preservePermissions {
		err := os.Chmod(destPath, sourceInfo.Mode())
		if err != nil {
			return fmt.Errorf("failed to preserve permissions: %w", err)
		}
	}

	// Preserve timestamps
	if osm.preserveTimestamps {
		err := os.Chtimes(destPath, sourceInfo.ModTime(), sourceInfo.ModTime())
		if err != nil {
			return fmt.Errorf("failed to preserve timestamps: %w", err)
		}
	}

	return nil
}

// ValidatePath validates that a path is safe and within allowed boundaries
func (osm *OutputStructureManager) ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path contains invalid traversal sequences: %s", path)
	}

	// Check for absolute paths that might escape intended boundaries
	if filepath.IsAbs(cleanPath) {
		// For absolute paths, ensure they don't reference system directories
		systemDirs := []string{"/etc", "/sys", "/proc", "/dev", "C:\\Windows", "C:\\System32"}
		for _, sysDir := range systemDirs {
			if strings.HasPrefix(strings.ToLower(cleanPath), strings.ToLower(sysDir)) {
				return fmt.Errorf("path references system directory: %s", path)
			}
		}
	}

	return nil
}

// SanitizePath sanitizes a path by removing or replacing problematic characters
func (osm *OutputStructureManager) SanitizePath(path string) string {
	// Replace problematic characters
	sanitized := path

	// Replace path traversal sequences
	sanitized = strings.ReplaceAll(sanitized, "..", "parent")

	// Replace other problematic characters
	problematicChars := map[string]string{
		"<":  "lt",
		">":  "gt",
		":":  "colon",
		"\"": "quote",
		"|":  "pipe",
		"?":  "question",
		"*":  "star",
	}

	for char, replacement := range problematicChars {
		sanitized = strings.ReplaceAll(sanitized, char, replacement)
	}

	return sanitized
}

// GetFileInfo retrieves information about a file
func (osm *OutputStructureManager) GetFileInfo(path string) (*FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info for %s: %w", path, err)
	}

	return &FileInfo{
		Path:        path,
		Mode:        info.Mode(),
		ModTime:     info.ModTime(),
		Size:        info.Size(),
		IsDirectory: info.IsDir(),
	}, nil
}

// CreateDirectoryStructure creates a complete directory structure
func (osm *OutputStructureManager) CreateDirectoryStructure(paths []string) error {
	finishTiming := osm.observer.StartTiming("output_manager", "create_directory_structure", "")
	defer finishTiming(true, map[string]interface{}{
		"path_count": len(paths),
	})

	for _, path := range paths {
		if err := osm.EnsureDirectoryExists(path); err != nil {
			return fmt.Errorf("failed to create directory structure for %s: %w", path, err)
		}
	}

	return nil
}

// CleanupEmptyDirectories removes empty directories in the output structure
func (osm *OutputStructureManager) CleanupEmptyDirectories() error {
	finishTiming := osm.observer.StartTiming("output_manager", "cleanup_empty_directories", osm.baseOutputDir)
	defer finishTiming(true, nil)

	return filepath.Walk(osm.baseOutputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && path != osm.baseOutputDir {
			// Check if directory is empty
			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}

			if len(entries) == 0 {
				// Remove empty directory
				err := os.Remove(path)
				if err != nil {
					// Log warning but continue
					osm.observer.StartTiming("output_manager", "cleanup_warning", path)(false, map[string]interface{}{
						"warning": err.Error(),
					})
				}
			}
		}

		return nil
	})
}

// GetBaseOutputDir returns the base output directory
func (osm *OutputStructureManager) GetBaseOutputDir() string {
	return osm.baseOutputDir
}

// SetPreservePermissions sets whether to preserve file permissions
func (osm *OutputStructureManager) SetPreservePermissions(preserve bool) {
	osm.preservePermissions = preserve
}

// SetPreserveTimestamps sets whether to preserve file timestamps
func (osm *OutputStructureManager) SetPreserveTimestamps(preserve bool) {
	osm.preserveTimestamps = preserve
}

// GetComponentName returns the component name for observability
func (osm *OutputStructureManager) GetComponentName() string {
	return "output_structure_manager"
}
