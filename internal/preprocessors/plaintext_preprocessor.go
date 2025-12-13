// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"ferret-scan/internal/observability"
)

// PlainTextPreprocessor handles plain text files by passing their content through
// This ensures text files are processed through the same pipeline as other file types
type PlainTextPreprocessor struct {
	observer        *observability.StandardObserver
	enableRedaction bool
}

// NewPlainTextPreprocessor creates a new plain text preprocessor
func NewPlainTextPreprocessor() *PlainTextPreprocessor {
	return NewPlainTextPreprocessorWithConfig(true) // Default to enabled for backward compatibility
}

// NewPlainTextPreprocessorWithConfig creates a new plain text preprocessor with redaction configuration
func NewPlainTextPreprocessorWithConfig(enableRedaction bool) *PlainTextPreprocessor {
	return &PlainTextPreprocessor{
		enableRedaction: enableRedaction,
	}
}

// SetObserver sets the observability component
func (ptp *PlainTextPreprocessor) SetObserver(observer *observability.StandardObserver) {
	ptp.observer = observer
}

// GetName returns the name of this preprocessor
func (ptp *PlainTextPreprocessor) GetName() string {
	return "Plain Text Preprocessor"
}

// GetSupportedExtensions returns the file extensions this preprocessor supports
func (ptp *PlainTextPreprocessor) GetSupportedExtensions() []string {
	return []string{
		// Plain text files
		".txt", ".text", ".log", ".md", ".markdown", ".rst",
		// Configuration files
		".yaml", ".yml", ".json", ".xml", ".toml", ".ini", ".conf", ".config", ".cfg",
		// Source code files
		".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".go", ".rs", ".rb", ".php",
		".html", ".htm", ".css", ".scss", ".sass", ".less",
		".sql", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
		// Data files
		".csv", ".tsv", ".jsonl", ".ndjson",
		// Other text formats
		".env", ".gitignore", ".dockerfile", ".makefile",
	}
}

// CanProcess checks if this preprocessor can handle the given file
func (ptp *PlainTextPreprocessor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check supported extensions
	supportedExts := ptp.GetSupportedExtensions()
	for _, supportedExt := range supportedExts {
		if ext == supportedExt {
			return true
		}
	}

	// Also check files without extensions that might be text
	if ext == "" {
		// Check if it's a known text file without extension
		basename := strings.ToLower(filepath.Base(filePath))
		textFiles := []string{
			"readme", "license", "changelog", "makefile", "dockerfile",
			"jenkinsfile", "vagrantfile", "gemfile", "rakefile",
		}
		for _, textFile := range textFiles {
			if basename == textFile {
				return true
			}
		}

		// For files without extension, do a quick content check
		return ptp.isTextFile(filePath)
	}

	return false
}

// Process extracts text content from the file
func (ptp *PlainTextPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if ptp.observer != nil {
		finishTiming = ptp.observer.StartTiming("plaintext_preprocessor", "process_file", filePath)
		if ptp.observer.DebugObserver != nil {
			finishStep = ptp.observer.DebugObserver.StartStep("plaintext_preprocessor", "process_file", filePath)
		}
	}

	// Read the file content
	content, err := ptp.readTextFile(filePath)
	if err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		if finishStep != nil {
			finishStep(false, fmt.Sprintf("Failed to read text file: %v", err))
		}
		return &ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			ProcessorType: "plaintext",
			Success:       false,
			Error:         err,
		}, err
	}

	// Count basic statistics
	wordCount := ptp.countWords(content)
	lineCount := strings.Count(content, "\n") + 1
	charCount := len(content)
	paragraphs := ptp.countParagraphs(content)

	result := &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          content,
		Format:        "Plain Text",
		WordCount:     wordCount,
		CharCount:     charCount,
		LineCount:     lineCount,
		Paragraphs:    paragraphs,
		ProcessorType: "plaintext",
		Success:       true,
		Metadata:      make(map[string]interface{}),
	}

	// Only enable position tracking if redaction is enabled
	if ptp.enableRedaction {
		result.EnablePositionTracking()
		result.SetPositionConfidence(1.0) // Perfect confidence for plain text

		// Create optimized position mappings for plain text (1:1 mapping)
		ptp.createOptimizedPositionMappings(result, content)

		// Add position tracking metadata
		result.AddPositionMetadata("mapping_method", "direct")
		result.AddPositionMetadata("confidence_reason", "plain_text_1to1_mapping")
	}

	// Add file extension info to metadata
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != "" {
		result.Metadata["file_extension"] = ext
		result.Metadata["file_type"] = ptp.getFileTypeDescription(ext)
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"word_count": wordCount,
			"char_count": charCount,
			"line_count": lineCount,
		})
	}
	if finishStep != nil {
		finishStep(true, fmt.Sprintf("Processed plain text file: %d words, %d lines", wordCount, lineCount))
	}

	return result, nil
}

// readTextFile reads the content of a text file with proper encoding handling
func (ptp *PlainTextPreprocessor) readTextFile(filePath string) (string, error) {
	cleanPath := filepath.Clean(filePath)
	file, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Check file size (limit to 100MB for text files)
	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %w", err)
	}

	const maxSize = 100 * 1024 * 1024 // 100MB
	if fileInfo.Size() > maxSize {
		return "", fmt.Errorf("file too large: %d bytes (max: %d bytes)", fileInfo.Size(), maxSize)
	}

	// Read the entire file content to preserve original formatting
	// This approach preserves the exact original content including newline behavior
	fileContent, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	content := string(fileContent)

	// Validate UTF-8 encoding
	if !utf8.ValidString(content) {
		// Try to clean up invalid UTF-8
		content = strings.ToValidUTF8(content, "")
	}

	// Count lines for validation (prevent excessive memory usage)
	lineCount := strings.Count(content, "\n") + 1
	if lineCount > 1000000 { // 1M lines max
		return "", fmt.Errorf("file has too many lines: %d (max: 1000000)", lineCount)
	}

	return content, nil
}

// isTextFile performs a quick check to determine if a file contains text
func (ptp *PlainTextPreprocessor) isTextFile(filePath string) bool {
	cleanPath := filepath.Clean(filePath)
	file, err := os.Open(cleanPath)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read first 512 bytes to check for binary content
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && n == 0 {
		return false
	}

	buffer = buffer[:n]

	// Check for null bytes (common in binary files)
	for _, b := range buffer {
		if b == 0 {
			return false
		}
	}

	// Count printable characters
	printableCount := 0
	for _, b := range buffer {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printableCount++
		}
	}

	// Consider it text if more than 95% of characters are printable
	printableRatio := float64(printableCount) / float64(len(buffer))
	return printableRatio > 0.95
}

// countWords counts the number of words in the text
func (ptp *PlainTextPreprocessor) countWords(text string) int {
	words := strings.Fields(text)
	return len(words)
}

// countParagraphs counts the number of paragraphs in the text
func (ptp *PlainTextPreprocessor) countParagraphs(text string) int {
	// Split by double newlines to identify paragraphs
	paragraphs := strings.Split(text, "\n\n")
	count := 0
	for _, para := range paragraphs {
		if strings.TrimSpace(para) != "" {
			count++
		}
	}
	if count == 0 && strings.TrimSpace(text) != "" {
		count = 1 // At least one paragraph if there's content
	}
	return count
}

// createPositionMappings creates 1:1 position mappings for plain text content (legacy method)
func (ptp *PlainTextPreprocessor) createPositionMappings(result *ProcessedContent, content string) {
	ptp.createOptimizedPositionMappings(result, content)
}

// createOptimizedPositionMappings creates optimized position mappings for plain text content
func (ptp *PlainTextPreprocessor) createOptimizedPositionMappings(result *ProcessedContent, content string) {
	lines := splitLines(content)

	// Pre-calculate line offsets once to avoid O(n²) complexity
	lineOffsets := ptp.preCalculateLineOffsets(lines)

	mappingCount := 0
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and very short lines (unlikely to contain sensitive data)
		if len(trimmed) < 3 {
			continue
		}

		// Skip lines that are clearly non-sensitive (comments, headers, etc.)
		if ptp.isLikelyNonSensitive(trimmed) {
			continue
		}

		// Create a mapping using pre-calculated offset (O(1) operation)
		extractedPos := TextPosition{
			Line:           lineNum + 1, // 1-based line numbering
			StartChar:      0,
			EndChar:        len(line),
			AbsoluteOffset: lineOffsets[lineNum], // Use pre-calculated offset
		}

		originalPos := DocumentPosition{
			Page:       1, // Plain text is single "page"
			CharOffset: lineOffsets[lineNum],
			LineNumber: lineNum + 1,
		}

		mapping := PositionMapping{
			ExtractedPosition: extractedPos,
			OriginalPosition:  originalPos,
			ConfidenceScore:   1.0, // Perfect confidence for plain text
			Context:           ptp.getLineContext(lines, lineNum),
			Method:            "direct_mapping_optimized",
		}

		result.AddPositionMapping(mapping)
		mappingCount++
	}

	if ptp.observer != nil && ptp.observer.DebugObserver != nil {
		ptp.observer.DebugObserver.LogDetail("plaintext_preprocessor",
			fmt.Sprintf("Created %d optimized position mappings for %d lines (%.1f%% reduction)",
				mappingCount, len(lines),
				100.0*(1.0-float64(mappingCount)/float64(len(lines)))))
	}
}

// preCalculateLineOffsets calculates absolute offsets for all lines once
func (ptp *PlainTextPreprocessor) preCalculateLineOffsets(lines []string) []int {
	lineOffsets := make([]int, len(lines))
	offset := 0

	for i, line := range lines {
		lineOffsets[i] = offset
		offset += len(line) + 1 // +1 for newline character
	}

	return lineOffsets
}

// isLikelyNonSensitive identifies lines unlikely to contain sensitive data
func (ptp *PlainTextPreprocessor) isLikelyNonSensitive(line string) bool {
	// Skip HTML/XML tags, comments, headers, etc.
	if strings.HasPrefix(line, "<!--") ||
		strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "<") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "---") ||
		strings.HasPrefix(line, "===") {
		return true
	}

	// Skip lines that are mostly punctuation or whitespace
	alphanumCount := 0
	for _, r := range line {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			alphanumCount++
		}
	}

	// If less than 30% alphanumeric, likely not sensitive data
	return float64(alphanumCount)/float64(len(line)) < 0.3
}

// getLineContext returns context around a line for position verification
func (ptp *PlainTextPreprocessor) getLineContext(lines []string, lineIndex int) string {
	contextLines := 2 // Lines before and after
	start := lineIndex - contextLines
	end := lineIndex + contextLines + 1

	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}

	contextLinesSlice := lines[start:end]
	return strings.Join(contextLinesSlice, "\n")
}

// getFileTypeDescription returns a human-readable description of the file type
func (ptp *PlainTextPreprocessor) getFileTypeDescription(ext string) string {
	descriptions := map[string]string{
		".txt":        "Plain Text",
		".text":       "Plain Text",
		".log":        "Log File",
		".md":         "Markdown",
		".markdown":   "Markdown",
		".rst":        "reStructuredText",
		".yaml":       "YAML Configuration",
		".yml":        "YAML Configuration",
		".json":       "JSON Data",
		".xml":        "XML Document",
		".toml":       "TOML Configuration",
		".ini":        "INI Configuration",
		".conf":       "Configuration File",
		".config":     "Configuration File",
		".cfg":        "Configuration File",
		".py":         "Python Source Code",
		".js":         "JavaScript Source Code",
		".ts":         "TypeScript Source Code",
		".java":       "Java Source Code",
		".c":          "C Source Code",
		".cpp":        "C++ Source Code",
		".h":          "C Header File",
		".hpp":        "C++ Header File",
		".cs":         "C# Source Code",
		".go":         "Go Source Code",
		".rs":         "Rust Source Code",
		".rb":         "Ruby Source Code",
		".php":        "PHP Source Code",
		".html":       "HTML Document",
		".htm":        "HTML Document",
		".css":        "CSS Stylesheet",
		".scss":       "SCSS Stylesheet",
		".sass":       "Sass Stylesheet",
		".less":       "Less Stylesheet",
		".sql":        "SQL Script",
		".sh":         "Shell Script",
		".bash":       "Bash Script",
		".zsh":        "Zsh Script",
		".ps1":        "PowerShell Script",
		".bat":        "Batch File",
		".cmd":        "Command File",
		".csv":        "CSV Data",
		".tsv":        "TSV Data",
		".jsonl":      "JSON Lines",
		".ndjson":     "Newline Delimited JSON",
		".env":        "Environment Variables",
		".gitignore":  "Git Ignore File",
		".dockerfile": "Dockerfile",
		".makefile":   "Makefile",
	}

	if desc, exists := descriptions[ext]; exists {
		return desc
	}
	return "Text File"
}
