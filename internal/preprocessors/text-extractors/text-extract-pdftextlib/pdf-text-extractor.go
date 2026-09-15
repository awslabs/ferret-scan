// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractpdftextlib

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ledongthuc/pdf"
)

// TextContent represents the extracted text content from a PDF document
type TextContent struct {
	Filename string
	Text     string

	// PageCount is the document's REAL page count, always, even when only some of those pages were
	// read. It used to be overwritten with the page cap, which made it a lie in output the operator
	// reads: pdf_metadata_preprocessor formats PageCount as a reported field, so a 200-page document
	// was described as having 50 pages.
	PageCount int

	// PagesScanned is how many pages were actually visited. Equal to PageCount for a document under
	// the cap; below it when maxScannedPages fired.
	//
	// A separate field rather than a bool, because the disclosure has to be able to say WHICH numbers
	// it is talking about — "50 of 200" is actionable and "truncated" is not.
	PagesScanned int

	// PagesFailed is how many of the PagesScanned pages yielded no text because their
	// extraction returned an error or panicked.
	//
	// A separate field from PagesScanned for the reason PagesScanned is separate from
	// PageCount: the disclosure has to name WHICH numbers it is talking about. A page the
	// budget never reached and a page that was reached and failed are different facts with
	// different remedies — raise the budget, versus investigate or repair the file.
	//
	// This count previously existed as a local `failedPages` and was DISCARDED, under a
	// comment reading "Silent tracking of extraction completeness (no output)". Measured on
	// 60 real PDFs, whole-file extraction failed for 7 of them, so per-page failure is not
	// a hypothetical shape.
	PagesFailed int

	WordCount int
	CharCount int
	LineCount int
}

// Truncated reports that the page cap stopped extraction before the end of the document, so any
// value on a later page was never seen — and under this project's sink rule, never redacted either.
func (c *TextContent) Truncated() bool { return c.PagesScanned < c.PageCount }

// maxScannedPages bounds how many pages one PDF costs.
//
// The number is unchanged at 50. What changed is that it no longer destroys the page count and no
// longer applies in silence: measured before this, a 60-page PDF with an SSN on page 1 and six more
// on pages 55-60 reported exactly ONE finding, at exit 0, with files_skipped: 0, no
// files_not_examined, and an empty stderr. Six cleartext SSNs, unreported and unredacted, with
// nothing anywhere saying the scan had stopped.
//
// It is deliberately still a constant and still 50: raising it is a cost decision that wants a
// measurement behind it (see #626), and disclosure is correct at any value. The old comment called it
// "configurable", which it never was -- no config key, no flag, no override.
const maxScannedPages = 50

// ExtractText extracts text from a PDF document using ledongthuc/pdf
func ExtractText(filePath string) (content *TextContent, err error) {
	// Initialize content with basic file info
	content = &TextContent{
		Filename: filepath.Base(filePath),
	}

	// Recover from panics in the PDF library (e.g. corrupted zlib streams)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("PDF library panic on %s: %v", filepath.Base(filePath), r)
		}
	}()

	// Open the PDF file
	f, r, err := pdf.Open(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening PDF: %v", err)
	}
	defer f.Close()

	// The document's real page count, kept whether or not all of it is read.
	content.PageCount = r.NumPage()

	// Bound the work, WITHOUT overwriting the count above. Every loop below iterates PagesScanned.
	content.PagesScanned = content.PageCount
	if content.PagesScanned > maxScannedPages {
		content.PagesScanned = maxScannedPages
	}

	// Extract text from all pages with parallel processing for better performance
	type pageResult struct {
		pageNum int
		text    string
		err     error
	}

	// Use parallel processing for multi-page PDFs
	resultChan := make(chan pageResult, content.PagesScanned)

	// Process pages in parallel
	for i := 1; i <= content.PagesScanned; i++ {
		go func(pageNum int) {
			// A panic here would kill the PROCESS, not the page.
			//
			// The recover() in ExtractText's own defer cannot see this: a Go panic does
			// not cross a goroutine boundary. That recover exists because this library
			// panics on malformed input — nobody adds one speculatively — so the parent
			// is protected and the children it spawns were not.
			//
			// Latent rather than observed: 323 real PDFs and 24 deliberately damaged ones
			// (truncated at 50% and 90%, %%EOF removed, a 512-byte run zeroed) produced
			// zero crashes, so this is defence in depth rather than a live defect. It is
			// still worth closing, because the failure mode is the worst available — the
			// process dies mid-run, every file after this one goes unscanned, and there is
			// no report at all, which is strictly worse than a disclosed refusal.
			defer func() {
				if r := recover(); r != nil {
					resultChan <- pageResult{pageNum: pageNum,
						err: fmt.Errorf("pdf page %d panicked: %v", pageNum, r)}
				}
			}()

			p := r.Page(pageNum)
			if p.V.IsNull() {
				resultChan <- pageResult{pageNum: pageNum, err: fmt.Errorf("null page")}
				return
			}

			text, err := extractPageText(p)
			resultChan <- pageResult{pageNum: pageNum, text: text, err: err}
		}(i)
	}

	// Collect results in order
	pageTexts := make(map[int]string)
	failedPages := 0

	for i := 0; i < content.PagesScanned; i++ {
		result := <-resultChan
		if result.err != nil {
			failedPages++
			continue
		}
		pageTexts[result.pageNum] = result.text
	}

	// Assemble pages in correct order
	var buf bytes.Buffer
	for i := 1; i <= content.PagesScanned; i++ {
		if text, exists := pageTexts[i]; exists {
			// Preserve page structure with clear page boundaries
			if buf.Len() > 0 {
				buf.WriteString("\n--- PAGE BREAK ---\n")
			}
			buf.WriteString(text)
		}
	}

	// Extraction completeness is now REPORTED, not tracked silently. The caller turns a
	// non-zero PagesFailed into a coverage disclosure; see text_preprocessor.go.
	content.PagesFailed = failedPages

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

// extractPageText extracts a page's text in reading order.
//
// # Why this no longer reconstructs rows
//
// It used to call GetTextByRow, re-sort the rows by average Y, and rebuild each row from its text
// elements with gap-based spacing — about 90 lines whose stated purpose was "better spacing". Measured
// against `pdftotext -layout` on 40 real PDFs, that reconstruction was worse than the library's own
// plain text on every axis it was supposed to improve:
//
//	                              row reconstruction   GetPlainText
//	reading order correct                12 of 40         32 of 40
//	reading order INVERTED               15 of 40          3 of 40
//	expected token absent entirely       13 of 40          5 of 40
//	word recall vs pdftotext                88.1%            94.2%
//	adjacent words glued together           6.41%            5.49%
//	findings across the corpus                231              254
//
// So it inverted reading order on 15 of 40 documents, dropped text outright on 13, and glued MORE
// words than the code it was preferred over. GetPlainText was already the fallback for when
// GetTextByRow errored; it is now simply the path.
//
// # Why reading order is not cosmetic here
//
// Several detections are cross-line: a label above its value (the passport and medicalid validators
// both rely on it), the before/after window that drives keyword proximity and therefore confidence,
// and table header to data row association. On an inverted page every one of those reads the document
// backwards, so a label follows its value instead of preceding it. That is a recall loss, and an
// invisible one — the findings that survive look normal. The corpus measurement above bears it out:
// +23 findings from ordering and completeness alone.
//
// # Why not simply flip the comparator
//
// Because the sort was not uniformly backwards. Sorting descending, or not sorting at all, both moved
// the corpus from 15 inverted to 5 — fixing the 15 and breaking 5 that had been correct. The Y values
// reaching that comparator are not consistently oriented: a producer may emit a flipped CTM, so
// ascending Y is reading order for some pages and reverse order for others. Any single comparator is
// therefore wrong for one population, which is why the fix is to stop deciding order from Y at all and
// take the content-stream order the library already produces.
func extractPageText(p pdf.Page) (string, error) {
	return p.GetPlainText(nil)
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
