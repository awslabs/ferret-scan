// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// Windows error constants
const (
	ERROR_ACCESS_DENIED        = syscall.Errno(5)
	ERROR_PRIVILEGE_NOT_HELD   = syscall.Errno(1314)
	ERROR_SHARING_VIOLATION    = syscall.Errno(32)
	ERROR_LOCK_VIOLATION       = syscall.Errno(33)
	ERROR_FILENAME_EXCED_RANGE = syscall.Errno(206)
	ERROR_BUFFER_OVERFLOW      = syscall.Errno(111)
	ERROR_WRITE_PROTECT        = syscall.Errno(19)
	ERROR_FILE_NOT_FOUND       = syscall.Errno(2)
	ERROR_PATH_NOT_FOUND       = syscall.Errno(3)
)

// WindowsError represents a Windows-specific error with enhanced messaging
type WindowsError struct {
	OriginalError error
	Path          string
	Operation     string
	Suggestion    string
}

func (we *WindowsError) Error() string {
	if we.Suggestion != "" {
		return fmt.Sprintf("%s: %s. %s", we.Operation, we.OriginalError.Error(), we.Suggestion)
	}
	return fmt.Sprintf("%s: %s", we.Operation, we.OriginalError.Error())
}

func (we *WindowsError) Unwrap() error {
	return we.OriginalError
}

// ErrorHandler provides platform-specific error handling
type ErrorHandler interface {
	HandleFileError(err error, filePath string, operation string) error
	HandlePermissionError(err error, filePath string) error
	HandleLongPathError(err error, filePath string) error
	IsPermissionError(err error) bool
	IsLongPathError(err error) bool
	IsReadOnlyError(err error) bool
	IsHiddenFileError(err error) bool
}

// GetErrorHandler returns the appropriate error handler for the current platform
func GetErrorHandler() ErrorHandler {
	if IsWindows() {
		return &WindowsErrorHandler{}
	}
	return &UnixErrorHandler{}
}

// WindowsErrorHandler handles Windows-specific errors
type WindowsErrorHandler struct{}

// HandleFileError provides Windows-specific file error handling
func (w *WindowsErrorHandler) HandleFileError(err error, filePath string, operation string) error {
	if err == nil {
		return nil
	}

	// Check for specific Windows error types
	if w.IsPermissionError(err) {
		return w.HandlePermissionError(err, filePath)
	}

	if w.IsLongPathError(err) {
		return w.HandleLongPathError(err, filePath)
	}

	if w.IsReadOnlyError(err) {
		return &WindowsError{
			OriginalError: err,
			Path:          filePath,
			Operation:     operation,
			Suggestion:    "The file is read-only. Use 'attrib -r \"" + filePath + "\"' to remove read-only attribute, or run as Administrator.",
		}
	}

	if w.IsHiddenFileError(err) {
		return &WindowsError{
			OriginalError: err,
			Path:          filePath,
			Operation:     operation,
			Suggestion:    "The file may be hidden. Use 'attrib -h \"" + filePath + "\"' to remove hidden attribute, or enable 'Show hidden files' in File Explorer.",
		}
	}

	// Handle other Windows-specific errors
	if strings.Contains(err.Error(), "being used by another process") {
		return &WindowsError{
			OriginalError: err,
			Path:          filePath,
			Operation:     operation,
			Suggestion:    "The file is being used by another process. Close any applications that might be using this file and try again.",
		}
	}

	if strings.Contains(err.Error(), "network path was not found") {
		return &WindowsError{
			OriginalError: err,
			Path:          filePath,
			Operation:     operation,
			Suggestion:    "Network path not found. Verify the network connection and that the remote server is accessible.",
		}
	}

	if strings.Contains(err.Error(), "invalid character") && strings.Contains(filePath, ":") {
		return &WindowsError{
			OriginalError: err,
			Path:          filePath,
			Operation:     operation,
			Suggestion:    "Invalid characters in filename. Windows doesn't allow characters like: < > : \" | ? * in filenames.",
		}
	}

	// Return enhanced error with path context
	return &WindowsError{
		OriginalError: err,
		Path:          filePath,
		Operation:     operation,
	}
}

// HandlePermissionError provides specific handling for Windows permission errors
func (w *WindowsErrorHandler) HandlePermissionError(err error, filePath string) error {
	suggestion := "Access denied. Try one of the following:\n" +
		"  • Run the command as Administrator (right-click Command Prompt → 'Run as administrator')\n" +
		"  • Check file permissions and ensure you have read/write access\n" +
		"  • Verify the file is not in use by another application\n" +
		"  • If the file is on a network drive, check network permissions"

	return &WindowsError{
		OriginalError: err,
		Path:          filePath,
		Operation:     "file access",
		Suggestion:    suggestion,
	}
}

// HandleLongPathError provides specific handling for Windows long path errors
func (w *WindowsErrorHandler) HandleLongPathError(err error, filePath string) error {
	pathLength := len(filePath)
	suggestion := fmt.Sprintf("File path is too long (%d characters). Windows has a default 260-character limit.\n", pathLength) +
		"Solutions:\n" +
		"  • Enable long path support: Run 'gpedit.msc' → Computer Configuration → Administrative Templates → System → Filesystem → Enable Win32 long paths\n" +
		"  • Use a shorter path or move files closer to the root directory\n" +
		"  • Use UNC path format: \\\\?\\C:\\your\\long\\path\n" +
		"  • Map a network drive to shorten the path"

	return &WindowsError{
		OriginalError: err,
		Path:          filePath,
		Operation:     "file path access",
		Suggestion:    suggestion,
	}
}

// IsPermissionError checks if the error is a Windows permission error
func (w *WindowsErrorHandler) IsPermissionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for syscall errors
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD,
			ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION:
			return true
		}
	}

	// Check for os.PathError with permission issues
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.As(pathErr.Err, &errno) {
			switch errno {
			case ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD:
				return true
			}
		}
	}

	// Check error message patterns
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "access denied") ||
		strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "access is denied") ||
		strings.Contains(errMsg, "privilege not held")
}

// IsLongPathError checks if the error is related to Windows long path limitations
func (w *WindowsErrorHandler) IsLongPathError(err error) bool {
	if err == nil {
		return false
	}

	// Check for syscall errors
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case ERROR_FILENAME_EXCED_RANGE, ERROR_BUFFER_OVERFLOW:
			return true
		}
	}

	// Check error message patterns
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "filename or extension is too long") ||
		strings.Contains(errMsg, "path too long") ||
		strings.Contains(errMsg, "name is too long") ||
		strings.Contains(errMsg, "buffer overflow")
}

// IsReadOnlyError checks if the error is related to read-only file attributes
func (w *WindowsErrorHandler) IsReadOnlyError(err error) bool {
	if err == nil {
		return false
	}

	// Check for syscall errors
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case ERROR_WRITE_PROTECT, ERROR_ACCESS_DENIED:
			return true
		}
	}

	// Check error message patterns
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "read-only") ||
		strings.Contains(errMsg, "write protected") ||
		strings.Contains(errMsg, "cannot modify read-only")
}

// IsHiddenFileError checks if the error is related to hidden file attributes
func (w *WindowsErrorHandler) IsHiddenFileError(err error) bool {
	if err == nil {
		return false
	}

	// Check for syscall errors related to hidden files
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND:
			// These could indicate hidden files, but we need additional context
			return false // We'll handle this in the calling code with file attribute checks
		}
	}

	// Check error message patterns
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "hidden") ||
		strings.Contains(errMsg, "system file")
}

// UnixErrorHandler provides basic error handling for Unix systems
type UnixErrorHandler struct{}

// HandleFileError provides basic file error handling for Unix systems
func (u *UnixErrorHandler) HandleFileError(err error, filePath string, operation string) error {
	if err == nil {
		return nil
	}

	if u.IsPermissionError(err) {
		return u.HandlePermissionError(err, filePath)
	}

	return err
}

// HandlePermissionError provides basic permission error handling for Unix systems
func (u *UnixErrorHandler) HandlePermissionError(err error, filePath string) error {
	return fmt.Errorf("permission denied accessing '%s': %w. Try using 'sudo' or check file permissions with 'ls -la'", filePath, err)
}

// HandleLongPathError is not applicable for Unix systems (no path length limits like Windows)
func (u *UnixErrorHandler) HandleLongPathError(err error, filePath string) error {
	return err
}

// IsPermissionError checks for Unix permission errors
func (u *UnixErrorHandler) IsPermissionError(err error) bool {
	if err == nil {
		return false
	}
	return os.IsPermission(err) || strings.Contains(err.Error(), "permission denied")
}

// IsLongPathError is not applicable for Unix systems
func (u *UnixErrorHandler) IsLongPathError(err error) bool {
	return false
}

// IsReadOnlyError checks for Unix read-only errors
func (u *UnixErrorHandler) IsReadOnlyError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "read-only")
}

// IsHiddenFileError is not applicable for Unix systems (no hidden attribute like Windows)
func (u *UnixErrorHandler) IsHiddenFileError(err error) bool {
	return false
}

// WrapFileError wraps a file operation error with platform-specific handling
func WrapFileError(err error, filePath string, operation string) error {
	if err == nil {
		return nil
	}

	handler := GetErrorHandler()
	return handler.HandleFileError(err, filePath, operation)
}

// IsWindowsSpecificError checks if an error is Windows-specific
func IsWindowsSpecificError(err error) bool {
	if !IsWindows() {
		return false
	}

	var winErr *WindowsError
	return errors.As(err, &winErr)
}
