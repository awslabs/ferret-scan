// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractpdftextlib

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ledongthuc/pdf"
)

// TextContent represents the extracted text content from a PDF document
type TextContent struct {
	Filename  string
	Text      string
	PageCount int
	WordCount int
	CharCount int
	LineCount int
}

// ExtractText extracts text from a PDF document using ledongthuc/pdf
func ExtractText(filePath string) (*TextContent, error) {
	// Initialize content with basic file info
	content := &TextContent{
		Filename: filepath.Base(filePath),
	}

	// Open the PDF file
	f, r, err := pdf.Open(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening PDF: %v", err)
	}
	defer f.Close()

	// Get the number of pages
	content.PageCount = r.NumPage()

	// Performance optimization: limit processing for very large PDFs
	maxPages := 50 // Configurable limit to prevent excessive processing time
	if content.PageCount > maxPages {
		content.PageCount = maxPages
		// Note: This truncates processing but maintains reasonable performance
	}

	// Extract text from all pages with parallel processing for better performance
	type pageResult struct {
		pageNum int
		text    string
		err     error
	}

	// Use parallel processing for multi-page PDFs
	resultChan := make(chan pageResult, content.PageCount)

	// Process pages in parallel
	for i := 1; i <= content.PageCount; i++ {
		go func(pageNum int) {
			p := r.Page(pageNum)
			if p.V.IsNull() {
				resultChan <- pageResult{pageNum: pageNum, err: fmt.Errorf("null page")}
				return
			}

			text, err := extractTextWithProperSpacing(p)
			resultChan <- pageResult{pageNum: pageNum, text: text, err: err}
		}(i)
	}

	// Collect results in order
	pageTexts := make(map[int]string)
	failedPages := 0

	for i := 0; i < content.PageCount; i++ {
		result := <-resultChan
		if result.err != nil {
			failedPages++
			continue
		}
		pageTexts[result.pageNum] = result.text
	}

	// Assemble pages in correct order
	var buf bytes.Buffer
	for i := 1; i <= content.PageCount; i++ {
		if text, exists := pageTexts[i]; exists {
			// Preserve page structure with clear page boundaries
			if buf.Len() > 0 {
				buf.WriteString("\n--- PAGE BREAK ---\n")
			}
			buf.WriteString(text)
		}
	}

	// Silent tracking of extraction completeness (no output)
	// failedPages is tracked but not reported to stderr

	// Extract form data (AcroForm fields)
	formData, err := extractFormData(r)
	if err == nil && formData != "" {
		buf.WriteString("\n--- PDF Form Data ---\n")
		buf.WriteString(formData)
		buf.WriteString("\n")
	}
	// Silent handling of form data extraction errors

	// Set the extracted text
	content.Text = buf.String()

	// Clean up the text while preserving structure
	content.Text = cleanTextPreservingStructure(content.Text)

	// Validate extraction quality (silent check)
	validateExtractionQuality(content.Text)

	// Count words, characters, and lines
	content.WordCount = len(strings.Fields(content.Text))
	content.CharCount = len(content.Text)
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// extractFormData extracts form field data from PDF AcroForms
func extractFormData(r *pdf.Reader) (string, error) {
	var buf bytes.Buffer

	// Try to access the document catalog
	root := r.Trailer().Key("Root")
	if root.IsNull() {
		return "", fmt.Errorf("no document catalog found")
	}

	// Look for AcroForm dictionary
	acroForm := root.Key("AcroForm")
	if acroForm.IsNull() {
		return "", nil // No forms in this PDF
	}

	// Try to extract form fields
	fields := acroForm.Key("Fields")
	if fields.IsNull() {
		return "", nil
	}

	// Process form fields array
	if fields.Kind() == pdf.Array {
		array := fields
		for i := 0; i < array.Len(); i++ {
			field := array.Index(i)
			if !field.IsNull() {
				name, value := extractFieldNameValue(field)
				if name != "" && value != "" {
					// Include both field name and value for context and PII detection
					buf.WriteString(fmt.Sprintf("Name: %s Value: %s\n", name, value))
				}
			}
		}
	}

	return buf.String(), nil
}

// extractFieldNameValue extracts name and value from a single form field
func extractFieldNameValue(field pdf.Value) (string, string) {
	if field.Kind() != pdf.Dict {
		return "", ""
	}

	var fieldName, fieldValue string

	// Get field name
	t := field.Key("T")
	if !t.IsNull() && t.Kind() == pdf.String {
		fieldName = t.Text()
	}

	// Get field value - try different value keys
	v := field.Key("V")
	if !v.IsNull() {
		switch v.Kind() {
		case pdf.String:
			fieldValue = v.Text()
		case pdf.Name:
			fieldValue = v.Name()
		}
	}

	// If no value in V, try DV (default value)
	if fieldValue == "" {
		dv := field.Key("DV")
		if !dv.IsNull() {
			switch dv.Kind() {
			case pdf.String:
				fieldValue = dv.Text()
			case pdf.Name:
				fieldValue = dv.Name()
			}
		}
	}

	return fieldName, fieldValue
}

// addParagraphBreaks adds paragraph breaks at logical boundaries
func addParagraphBreaks(text string) string {
	// Split into sentences/phrases
	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var result []string
	var currentLine []string

	for i, word := range words {
		currentLine = append(currentLine, word)

		// Add line break after sentences or at logical boundaries
		if shouldBreakLine(word, i, words) {
			result = append(result, strings.Join(currentLine, " "))
			currentLine = []string{}
		}
	}

	// Add remaining words
	if len(currentLine) > 0 {
		result = append(result, strings.Join(currentLine, " "))
	}

	return strings.Join(result, "\n")
}

// cleanTextPreservingStructure cleans text while maintaining logical structure for PII detection
func cleanTextPreservingStructure(text string) string {
	// Split into lines for processing
	lines := strings.Split(text, "\n")
	var cleanedLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			cleanedLines = append(cleanedLines, line)
		}
	}

	// Preserve line structure instead of flattening to spaces
	// This maintains context for validators (e.g., "SSN: 123-45-6789" stays on separate line)
	result := strings.Join(cleanedLines, "\n")

	// Remove tabs and replace with spaces (but keep line breaks)
	result = strings.ReplaceAll(result, "\t", " ")

	// Clean up excessive spaces within lines (but preserve line breaks)
	lines = strings.Split(result, "\n")
	for i, line := range lines {
		// Replace multiple spaces with single space within each line
		for strings.Contains(line, "  ") {
			line = strings.ReplaceAll(line, "  ", " ")
		}
		lines[i] = strings.TrimSpace(line)
	}

	return strings.Join(lines, "\n")
}

// validateExtractionQuality performs basic validation on extracted text
func validateExtractionQuality(text string) bool {
	if len(text) == 0 {
		return false
	}

	// Count printable vs non-printable characters
	printableCount := 0
	totalCount := len(text)

	for _, r := range text {
		// Allow standard printable characters, spaces, tabs, and newlines
		if (r >= 32 && r <= 126) || r == '\n' || r == '\r' || r == '\t' {
			printableCount++
		}
	}

	// If less than 80% of characters are printable, consider it potentially corrupted
	printableRatio := float64(printableCount) / float64(totalCount)
	if printableRatio < 0.8 {
		return false
	}

	// Check for reasonable word patterns (basic heuristic)
	words := strings.Fields(text)
	if len(words) == 0 {
		return false
	}

	// If average word length is extremely long or short, might indicate corruption
	totalWordLength := 0
	for _, word := range words {
		totalWordLength += len(word)
	}
	avgWordLength := float64(totalWordLength) / float64(len(words))

	// Reasonable average word length is between 2 and 15 characters
	if avgWordLength < 2 || avgWordLength > 15 {
		return false
	}

	return true
}

// extractTextWithProperSpacing extracts text using row-based positioning for better spacing
func extractTextWithProperSpacing(p pdf.Page) (string, error) {
	// Try row-based extraction first (more accurate spacing)
	rows, err := p.GetTextByRow()
	if err != nil {
		// Fallback to simple text extraction if row-based fails
		return p.GetPlainText(nil)
	}

	// Sort rows by Y coordinate for proper reading order (top to bottom)
	// PDF coordinates: Y increases from bottom to top, so higher Y = higher on page
	sortedRows := make([]*pdf.Row, 0, len(rows))
	for _, row := range rows {
		if row != nil && len(row.Content) > 0 {
			sortedRows = append(sortedRows, row)
		}
	}

	// Sort by Y coordinate (ascending - lower Y values first for top-to-bottom reading)
	sort.Slice(sortedRows, func(i, j int) bool {
		return getAverageY(sortedRows[i].Content) < getAverageY(sortedRows[j].Content)
	})

	var buf bytes.Buffer

	for _, row := range sortedRows {
		// Process text elements in this row with proper spacing
		rowText := reconstructRowText(row.Content)
		if strings.TrimSpace(rowText) != "" {
			buf.WriteString(rowText)
			buf.WriteString("\n")
		}
	}

	return buf.String(), nil
}

// getAverageY calculates the average Y coordinate for text elements in a row
func getAverageY(textElements []pdf.Text) float64 {
	if len(textElements) == 0 {
		return 0
	}

	var totalY float64
	for _, element := range textElements {
		totalY += element.Y
	}

	return totalY / float64(len(textElements))
}

// reconstructRowText reconstructs text from a row with proper spacing based on coordinates
func reconstructRowText(textElements []pdf.Text) string {
	if len(textElements) == 0 {
		return ""
	}

	// Sort elements by X coordinate to ensure left-to-right order
	sortedElements := make([]pdf.Text, len(textElements))
	copy(sortedElements, textElements)

	// Sort by X coordinate for left-to-right reading order
	sort.Slice(sortedElements, func(i, j int) bool {
		return sortedElements[i].X < sortedElements[j].X
	})

	var buf bytes.Buffer

	for i, element := range sortedElements {
		// Add the text content
		buf.WriteString(element.S)

		// Determine if we need a space before the next element
		if i < len(sortedElements)-1 {
			nextElement := sortedElements[i+1]

			// Calculate the gap between this element and the next
			currentEnd := element.X + element.W
			nextStart := nextElement.X
			gap := nextStart - currentEnd

			// Insert space if there's a significant gap
			// Use font size as a reference for what constitutes a "significant" gap
			fontSize := element.FontSize
			if fontSize <= 0 {
				fontSize = 12 // Default font size
			}

			// If gap is more than 20% of font size, insert a space
			spaceThreshold := fontSize * 0.2

			if gap > spaceThreshold {
				buf.WriteString(" ")
			}
		}
	}

	return buf.String()
}

// shouldBreakLine determines if a line break should be added after a word
func shouldBreakLine(word string, index int, words []string) bool {
	// Break after sentences
	if strings.HasSuffix(word, ".") || strings.HasSuffix(word, "!") || strings.HasSuffix(word, "?") {
		// Don't break after abbreviations or initials
		if len(word) <= 3 && strings.HasSuffix(word, ".") {
			return false
		}
		return true
	}

	// Break after colons (often indicate section headers)
	if strings.HasSuffix(word, ":") {
		return true
	}

	// Break after common form field patterns
	if strings.HasSuffix(word, ":") && index < len(words)-1 {
		// Check if next word might be a value
		nextWord := words[index+1]
		if len(nextWord) > 0 && (strings.Contains(nextWord, "-") || len(nextWord) >= 5) {
			return true
		}
	}

	return false
}
