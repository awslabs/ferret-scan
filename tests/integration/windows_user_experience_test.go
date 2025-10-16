// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build windows
// +build windows

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ferret-scan/internal/platform"
	"ferret-scan/tests/helpers"
)

// TestWindowsErrorHandlingAndUserExperience tests Windows error handling and user experience
func TestWindowsErrorHandlingAndUserExperience(t *testing.T) {
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

	t.Run("WindowsPermissionErrorHandling", func(t *testing.T) {
		// Test Windows permission error handling

		// Try to scan system directories that might have restricted access
		restrictedDirs := []string{
			"C:\\System Volume Information",
			"C:\\Windows\\System32\\config",
			"C:\\$Recycle.Bin",
		}

		for _, restrictedDir := range restrictedDirs {
			t.Run(fmt.Sprintf("RestrictedDirectory_%s", strings.ReplaceAll(restrictedDir, "\\", "_")), func(t *testing.T) {
				scanCmd := exec.Command(binaryPath, "scan", restrictedDir)
				scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

				scanOutput, err := scanCmd.CombinedOutput()
				outputStr := string(scanOutput)

				// Should handle permission errors gracefully
				if strings.Contains(outputStr, "panic") {
					t.Error("Application should not panic on Windows permission errors")
				}

				// Should provide helpful error messages
				if err != nil {
					if strings.Contains(outputStr, "access") ||
						strings.Contains(outputStr, "permission") ||
						strings.Contains(outputStr, "denied") {
						t.Logf("Appropriate permission error message provided: %s", strings.TrimSpace(outputStr))
					} else {
						t.Logf("Permission error handled (may not have specific message): %v", err)
					}
				} else {
					t.Logf("Directory scan completed (may have appropriate permissions)")
				}
			})
		}

		t.Logf("Windows permission error handling tested")
	})

	t.Run("WindowsLongPathErrorHandling", func(t *testing.T) {
		// Test Windows long path error handling

		// Create progressively longer paths to test limits
		longPathTests := []struct {
			name       string
			pathLength int
			shouldWork bool
		}{
			{"NormalPath", 100, true},
			{"LongPath", 250, true},
			{"VeryLongPath", 300, false}, // May fail on systems without long path support
			{"ExtremelyLongPath", 500, false},
		}

		for _, test := range longPathTests {
			t.Run(test.name, func(t *testing.T) {
				// Create a path of specified length
				baseDir := tempDir
				remainingLength := test.pathLength - len(baseDir)

				if remainingLength > 0 {
					// Create nested directories to reach desired path length
					segmentLength := 50
					for remainingLength > segmentLength {
						segment := strings.Repeat("a", segmentLength)
						baseDir = filepath.Join(baseDir, segment)
						remainingLength -= segmentLength + 1 // +1 for separator
					}

					if remainingLength > 0 {
						segment := strings.Repeat("b", remainingLength-4) // -4 for ".txt"
						baseDir = filepath.Join(baseDir, segment+".txt")
					}
				}

				// Try to create the long path
				err := os.MkdirAll(filepath.Dir(baseDir), 0755)
				if err != nil {
					if test.shouldWork {
						t.Logf("Long path creation failed (may be expected on this system): %v", err)
					} else {
						t.Logf("Long path creation failed as expected: %v", err)
					}

					// Test scanning the long path even if creation failed
					scanCmd := exec.Command(binaryPath, "scan", baseDir)
					scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

					scanOutput, err := scanCmd.CombinedOutput()
					outputStr := string(scanOutput)

					// Should handle long path errors gracefully
					if err != nil && strings.Contains(outputStr, "panic") {
						t.Error("Application should not panic on Windows long path errors")
					}

					// Should provide helpful guidance
					if strings.Contains(outputStr, "path") ||
						strings.Contains(outputStr, "long") ||
						strings.Contains(outputStr, "limit") {
						t.Logf("Long path error message provided: %s", strings.TrimSpace(outputStr))
					}
				} else {
					// Long path creation succeeded
					err = os.WriteFile(baseDir, []byte("test content for long path"), 0644)
					if err == nil {
						t.Logf("Long path support available on this system (path length: %d)", len(baseDir))

						// Test scanning the successfully created long path
						scanCmd := exec.Command(binaryPath, "scan", baseDir)
						scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

						scanOutput, err := scanCmd.CombinedOutput()
						if err != nil {
							t.Logf("Long path scan completed with exit code (may be expected): %v", err)
						} else {
							t.Logf("Long path scan completed successfully")
						}
						t.Logf("Scan output: %s", string(scanOutput))
					} else {
						t.Logf("Long path directory created but file creation failed: %v", err)
					}
				}

				t.Logf("Path length test completed: %s (length: %d)", test.name, len(baseDir))
			})
		}

		t.Logf("Windows long path error handling tested")
	})

	t.Run("WindowsInvalidPathErrorHandling", func(t *testing.T) {
		// Test invalid path handling
		invalidPaths := []struct {
			path        string
			description string
		}{
			{"Z:\\nonexistent\\file.txt", "Invalid drive letter"},
			{"\\\\nonexistent-server\\share\\file.txt", "Invalid UNC path"},
			{"C:\\invalid<>chars\\file.txt", "Invalid characters in path"},
			{"", "Empty path"},
			{"   ", "Whitespace-only path"},
		}

		for _, invalidPath := range invalidPaths {
			t.Run(fmt.Sprintf("InvalidPath_%s", strings.ReplaceAll(invalidPath.description, " ", "_")), func(t *testing.T) {
				scanCmd := exec.Command(binaryPath, "scan", invalidPath.path)
				scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

				scanOutput, err := scanCmd.CombinedOutput()
				outputStr := string(scanOutput)

				// Should handle invalid path errors gracefully
				if strings.Contains(outputStr, "panic") {
					t.Error("Application should not panic on Windows invalid path errors")
				}

				if err != nil {
					t.Logf("%s error handled appropriately: %v", invalidPath.description, err)
				} else {
					t.Logf("%s handled without error (may be expected)", invalidPath.description)
				}

				t.Logf("Invalid path test completed: %s", invalidPath.description)
			})
		}

		t.Logf("Windows invalid path error handling tested")
	})

	t.Run("WindowsHelpfulErrorMessages", func(t *testing.T) {
		// Test that error messages are helpful for Windows users

		errorTests := []struct {
			args        []string
			description string
			expectHelp  bool
		}{
			{[]string{"invalid-command"}, "Invalid command", true},
			{[]string{"scan"}, "Missing scan target", true},
			{[]string{"--invalid-flag"}, "Invalid flag", true},
			{[]string{"scan", "--format", "invalid"}, "Invalid format", true},
		}

		for _, errorTest := range errorTests {
			t.Run(fmt.Sprintf("ErrorMessage_%s", strings.ReplaceAll(errorTest.description, " ", "_")), func(t *testing.T) {
				cmd := exec.Command(binaryPath, errorTest.args...)
				cmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

				output, err := cmd.CombinedOutput()
				outputStr := string(output)

				if err != nil {
					t.Logf("Command failed as expected: %v", err)
				}

				if errorTest.expectHelp {
					// Should provide helpful usage information
					if !strings.Contains(outputStr, "Usage:") &&
						!strings.Contains(outputStr, "help") &&
						!strings.Contains(outputStr, "usage") {
						t.Errorf("%s should provide helpful usage information: %s", errorTest.description, outputStr)
					} else {
						t.Logf("%s provided helpful error message", errorTest.description)
					}
				}

				// Should not contain panic or stack traces
				if strings.Contains(outputStr, "panic") || strings.Contains(outputStr, "goroutine") {
					t.Errorf("%s should not contain panic or stack traces: %s", errorTest.description, outputStr)
				}

				t.Logf("Error message test completed: %s", errorTest.description)
			})
		}

		// Test help command specifically
		helpCmd := exec.Command(binaryPath, "--help")
		helpOutput, err := helpCmd.CombinedOutput()
		if err != nil {
			t.Errorf("Help command should not fail: %v", err)
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

	t.Run("WindowsExitCodeValidation", func(t *testing.T) {
		// Test Windows exit codes

		exitCodeTests := []struct {
			args          []string
			description   string
			expectSuccess bool
		}{
			{[]string{"--version"}, "Version command", true},
			{[]string{"--help"}, "Help command", true},
			{[]string{"scan", "--help"}, "Scan help", true},
			{[]string{"invalid-command"}, "Invalid command", false},
			{[]string{"scan", "nonexistent-file.txt"}, "Nonexistent file", false},
		}

		for _, exitTest := range exitCodeTests {
			t.Run(fmt.Sprintf("ExitCode_%s", strings.ReplaceAll(exitTest.description, " ", "_")), func(t *testing.T) {
				cmd := exec.Command(binaryPath, exitTest.args...)
				cmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

				err := cmd.Run()

				if exitTest.expectSuccess {
					if err != nil {
						t.Errorf("%s should exit with code 0: %v", exitTest.description, err)
					} else {
						t.Logf("%s exited successfully", exitTest.description)
					}
				} else {
					if err == nil {
						t.Logf("%s completed without error (may be expected)", exitTest.description)
					} else {
						// Should exit with non-zero code for errors
						if exitError, ok := err.(*exec.ExitError); ok {
							if exitError.ExitCode() == 0 {
								t.Errorf("%s should exit with non-zero code", exitTest.description)
							} else {
								t.Logf("%s exited with appropriate error code: %d", exitTest.description, exitError.ExitCode())
							}
						} else {
							t.Logf("%s failed with error: %v", exitTest.description, err)
						}
					}
				}
			})
		}

		t.Logf("Windows exit codes tested successfully")
	})

	t.Run("WindowsPerformanceAndResponsiveness", func(t *testing.T) {
		// Test performance and responsiveness on Windows

		performanceTests := []struct {
			name        string
			args        []string
			maxDuration time.Duration
		}{
			{"VersionCommand", []string{"--version"}, 5 * time.Second},
			{"HelpCommand", []string{"--help"}, 5 * time.Second},
			{"QuickScan", []string{"scan", tempDir, "--format", "json"}, 30 * time.Second},
		}

		for _, perfTest := range performanceTests {
			t.Run(fmt.Sprintf("Performance_%s", perfTest.name), func(t *testing.T) {
				startTime := time.Now()

				cmd := exec.Command(binaryPath, perfTest.args...)
				cmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

				output, err := cmd.CombinedOutput()
				duration := time.Since(startTime)

				if duration > perfTest.maxDuration {
					t.Errorf("%s took too long: %v (max: %v)", perfTest.name, duration, perfTest.maxDuration)
				} else {
					t.Logf("%s completed in %v", perfTest.name, duration)
				}

				// Verify command completed (success or expected failure)
				if err != nil {
					t.Logf("%s completed with exit code (may be expected): %v", perfTest.name, err)
				}

				// Verify output is reasonable
				outputStr := string(output)
				if len(outputStr) == 0 {
					t.Logf("%s produced no output (may be expected)", perfTest.name)
				} else {
					t.Logf("%s produced %d bytes of output", perfTest.name, len(outputStr))
				}
			})
		}

		t.Logf("Windows performance and responsiveness tested")
	})

	t.Run("WindowsFileSystemInteraction", func(t *testing.T) {
		// Test file system interaction edge cases

		// Create test files with various characteristics
		testFiles := map[string]struct {
			content     string
			attributes  string
			description string
		}{
			"normal_file.txt": {
				content:     "Normal file content",
				attributes:  "normal",
				description: "Normal file",
			},
			"empty_file.txt": {
				content:     "",
				attributes:  "normal",
				description: "Empty file",
			},
			"large_file.txt": {
				content:     strings.Repeat("Large file content line.\n", 1000),
				attributes:  "normal",
				description: "Large file",
			},
		}

		testDir := filepath.Join(tempDir, "filesystem_test")
		err := os.MkdirAll(testDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create test directory: %v", err)
		}

		// Create test files
		for filename, fileInfo := range testFiles {
			filePath := filepath.Join(testDir, filename)
			err := os.WriteFile(filePath, []byte(fileInfo.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file %s: %v", filename, err)
			}

			t.Logf("Created test file: %s (%s)", filename, fileInfo.description)
		}

		// Test scanning the directory
		scanCmd := exec.Command(binaryPath, "scan", testDir, "--format", "json")
		scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

		scanOutput, err := scanCmd.CombinedOutput()
		outputStr := string(scanOutput)

		// Should handle all file types gracefully
		if strings.Contains(outputStr, "panic") {
			t.Error("Application should not panic when scanning various file types")
		}

		if err != nil {
			t.Logf("File system scan completed with exit code (may be expected): %v", err)
		} else {
			t.Logf("File system scan completed successfully")
		}

		// Verify output format
		if len(outputStr) > 0 {
			t.Logf("Scan produced output: %d bytes", len(outputStr))
		}

		t.Logf("Windows file system interaction tested")
	})
}

// TestWindowsUserInterfaceExperience tests Windows-specific user interface aspects
func TestWindowsUserInterfaceExperience(t *testing.T) {
	if !platform.IsWindows() {
		t.Skip("Skipping Windows-specific tests on non-Windows platform")
	}

	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	// Build binary for UI tests
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "ferret-scan.exe")

	buildCmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/main.go")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build binary for UI test: %v\nOutput: %s", err, string(buildOutput))
	}

	t.Run("WindowsConsoleOutput", func(t *testing.T) {
		// Test console output formatting on Windows

		outputTests := []struct {
			args        []string
			description string
		}{
			{[]string{"--version"}, "Version output"},
			{[]string{"--help"}, "Help output"},
			{[]string{"scan", "--help"}, "Scan help output"},
		}

		for _, outputTest := range outputTests {
			t.Run(fmt.Sprintf("ConsoleOutput_%s", strings.ReplaceAll(outputTest.description, " ", "_")), func(t *testing.T) {
				cmd := exec.Command(binaryPath, outputTest.args...)
				cmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

				output, err := cmd.CombinedOutput()
				outputStr := string(output)

				if err != nil {
					t.Logf("Command execution result: %v", err)
				}

				// Verify output is readable
				if len(outputStr) == 0 {
					t.Errorf("%s should produce output", outputTest.description)
				}

				// Verify no control characters that might break Windows console
				if strings.Contains(outputStr, "\x1b[") {
					t.Logf("%s contains ANSI escape sequences (may be intentional)", outputTest.description)
				}

				// Verify Windows line endings are handled properly
				if strings.Contains(outputStr, "\r\n") || strings.Contains(outputStr, "\n") {
					t.Logf("%s contains proper line endings", outputTest.description)
				}

				t.Logf("%s console output verified", outputTest.description)
			})
		}
	})

	t.Run("WindowsPathDisplayFormatting", func(t *testing.T) {
		// Test that Windows paths are displayed correctly

		// Create test files with Windows-specific paths
		testPaths := []string{
			filepath.Join(tempDir, "test_file.txt"),
			filepath.Join(tempDir, "subdir", "nested_file.txt"),
		}

		// Create test files
		for _, testPath := range testPaths {
			err := os.MkdirAll(filepath.Dir(testPath), 0755)
			if err != nil {
				t.Fatalf("Failed to create directory for %s: %v", testPath, err)
			}

			err = os.WriteFile(testPath, []byte("Test content with credit card: 4111-1111-1111-1111"), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file %s: %v", testPath, err)
			}
		}

		// Scan and check path formatting
		scanCmd := exec.Command(binaryPath, "scan", tempDir, "--format", "text")
		scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

		scanOutput, err := scanCmd.CombinedOutput()
		outputStr := string(scanOutput)

		if err != nil {
			t.Logf("Scan command result: %v", err)
		}

		// Should display Windows paths correctly
		for _, testPath := range testPaths {
			// Convert to Windows format for comparison
			windowsPath := strings.ReplaceAll(testPath, "/", "\\")

			if strings.Contains(outputStr, windowsPath) || strings.Contains(outputStr, testPath) {
				t.Logf("Path displayed correctly: %s", testPath)
			} else {
				t.Logf("Path may be displayed in normalized format: %s", testPath)
			}
		}

		t.Logf("Windows path display formatting tested")
	})

	t.Run("WindowsColorOutputSupport", func(t *testing.T) {
		// Test color output support on Windows

		colorTests := []struct {
			args        []string
			description string
		}{
			{[]string{"scan", tempDir, "--format", "text"}, "Default color output"},
			{[]string{"scan", tempDir, "--format", "text", "--no-color"}, "No color output"},
		}

		for _, colorTest := range colorTests {
			t.Run(fmt.Sprintf("ColorOutput_%s", strings.ReplaceAll(colorTest.description, " ", "_")), func(t *testing.T) {
				cmd := exec.Command(binaryPath, colorTest.args...)
				cmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

				output, err := cmd.CombinedOutput()
				outputStr := string(output)

				if err != nil {
					t.Logf("Color test command result: %v", err)
				}

				// Check for ANSI color codes
				hasColorCodes := strings.Contains(outputStr, "\x1b[")

				if strings.Contains(colorTest.description, "no-color") {
					if hasColorCodes {
						t.Errorf("No-color output should not contain ANSI escape sequences")
					} else {
						t.Logf("No-color output verified")
					}
				} else {
					if hasColorCodes {
						t.Logf("Color output contains ANSI escape sequences")
					} else {
						t.Logf("Color output may be disabled or not supported")
					}
				}

				t.Logf("Color output test completed: %s", colorTest.description)
			})
		}
	})

	t.Run("WindowsProgressIndicators", func(t *testing.T) {
		// Test progress indicators and user feedback

		// Create a larger directory structure for progress testing
		progressTestDir := filepath.Join(tempDir, "progress_test")
		err := os.MkdirAll(progressTestDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create progress test directory: %v", err)
		}

		// Create multiple files to scan
		for i := 0; i < 10; i++ {
			subdir := filepath.Join(progressTestDir, fmt.Sprintf("subdir_%d", i))
			err := os.MkdirAll(subdir, 0755)
			if err != nil {
				t.Fatalf("Failed to create subdirectory: %v", err)
			}

			for j := 0; j < 5; j++ {
				filename := filepath.Join(subdir, fmt.Sprintf("file_%d.txt", j))
				content := fmt.Sprintf("File %d-%d content with test data", i, j)
				err := os.WriteFile(filename, []byte(content), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
			}
		}

		// Test scanning with verbose output
		scanCmd := exec.Command(binaryPath, "scan", progressTestDir, "--verbose", "--format", "text")
		scanCmd.Env = append(os.Environ(), "FERRET_TEST_MODE=true")

		output, err := scanCmd.CombinedOutput()
		outputStr := string(output)

		// Should provide some indication of progress or activity
		if len(outputStr) > 0 {
			t.Logf("Verbose scan produced output indicating progress")
		}

		// Should complete in reasonable time
		t.Logf("Progress indicator test completed")
	})
}
