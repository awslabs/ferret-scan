// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"
	"os"
)

// ExampleWindowsErrorHandling demonstrates how to use the Windows error handling
func ExampleWindowsErrorHandling() {
	// Example 1: Handle a file operation error
	filePath := "C:\\test\\nonexistent.txt"

	// Simulate a file operation that fails
	_, err := os.Open(filePath)
	if err != nil {
		// Wrap the error with Windows-specific handling
		wrappedErr := WrapFileError(err, filePath, "opening file")
		fmt.Printf("Enhanced error message: %s\n", wrappedErr.Error())
	}

	// Example 2: Check if an error is Windows-specific
	if IsWindows() {
		handler := GetErrorHandler()

		// Test permission error detection
		if handler.IsPermissionError(err) {
			fmt.Println("This is a permission error")
		}

		// Test long path error detection
		longPath := "C:\\" + "very_long_directory_name\\"
		for i := 0; i < 10; i++ {
			longPath += "another_very_long_directory_name\\"
		}
		longPath += "file.txt"

		_, longPathErr := os.Open(longPath)
		if longPathErr != nil && handler.IsLongPathError(longPathErr) {
			fmt.Println("This is a long path error")
		}
	}
}

// ExampleErrorTypes demonstrates different types of Windows errors
func ExampleErrorTypes() {
	_ = GetErrorHandler() // Get handler for demonstration

	// Example error messages that would be enhanced on Windows
	examples := []struct {
		operation string
		path      string
		errorMsg  string
	}{
		{
			operation: "file access",
			path:      "C:\\Windows\\System32\\config\\SAM",
			errorMsg:  "Access is denied",
		},
		{
			operation: "file creation",
			path:      "C:\\very\\long\\path\\that\\exceeds\\windows\\limit\\file.txt",
			errorMsg:  "The filename or extension is too long",
		},
		{
			operation: "file modification",
			path:      "C:\\readonly\\file.txt",
			errorMsg:  "Access is denied",
		},
	}

	for _, example := range examples {
		fmt.Printf("\nExample: %s\n", example.operation)
		fmt.Printf("Path: %s\n", example.path)
		fmt.Printf("Original error: %s\n", example.errorMsg)

		// This would provide enhanced error messages on Windows
		if IsWindows() {
			fmt.Println("Enhanced Windows error handling would provide:")
			fmt.Println("- Specific suggestions for resolution")
			fmt.Println("- Context-aware error messages")
			fmt.Println("- Platform-appropriate guidance")
		}
	}
}
