// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"bufio"
	"os"
	"strings"
)

// ExtractContext extracts contextual information from a file for a specific match
func (ce *ContextExtractor) ExtractContext(filePath string, lineNumber int, matchText string) (ContextInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return ContextInfo{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Initialize context info
	contextInfo := ContextInfo{}

	// Read lines from the file
	currentLine := 0
	var beforeLines []string
	var afterLines []string
	var fullLine string

	// Read through the file to get context lines
	for scanner.Scan() {
		currentLine++

		// Store lines before the match
		if currentLine >= lineNumber-ce.ContextLines && currentLine < lineNumber {
			beforeLines = append(beforeLines, scanner.Text())
		}

		// Store the line with the match
		if currentLine == lineNumber {
			fullLine = scanner.Text()
		}

		// Store lines after the match
		if currentLine > lineNumber && currentLine <= lineNumber+ce.ContextLines {
			afterLines = append(afterLines, scanner.Text())
		}

		// Stop reading if we've gone far enough
		if currentLine > lineNumber+ce.ContextLines {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return ContextInfo{}, err
	}

	// Set the full line containing the match
	contextInfo.FullLine = fullLine

	// Extract text before and after the match within the line
	if fullLine != "" {
		matchIndex := strings.Index(fullLine, matchText)
		if matchIndex != -1 {
			// Get text before the match
			startIndex := max(0, matchIndex-ce.ContextChars)
			contextInfo.BeforeText = fullLine[startIndex:matchIndex]

			// Get text after the match
			endIndex := min(len(fullLine), matchIndex+len(matchText)+ce.ContextChars)
			contextInfo.AfterText = fullLine[matchIndex+len(matchText) : endIndex]
		}
	}

	// Add surrounding lines to context
	if len(beforeLines) > 0 {
		contextInfo.BeforeText = strings.Join(beforeLines, "\n") + "\n" + contextInfo.BeforeText
	}

	if len(afterLines) > 0 {
		contextInfo.AfterText = contextInfo.AfterText + "\n" + strings.Join(afterLines, "\n")
	}

	return contextInfo, nil
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
