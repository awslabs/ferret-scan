// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// TextContent represents the extracted text content from a document
type TextContent struct {
	Filename   string
	Text       string
	Format     string
	PageCount  int
	WordCount  int
	CharCount  int
	LineCount  int
	Paragraphs int
}

// ExtractText extracts text from an Office document
func ExtractText(filePath string) (*TextContent, error) {
	// Check if file exists
	_, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file error: %v", err)
	}

	// Initialize content with basic file info
	content := &TextContent{
		Filename: filepath.Base(filePath),
	}

	// Determine file type based on extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".docx":
		content.Format = "Word Document"
		return extractDocxText(filePath, content)
	case ".xlsx":
		content.Format = "Excel Spreadsheet"
		return extractXlsxText(filePath, content)
	case ".pptx":
		content.Format = "PowerPoint Presentation"
		return extractPptxText(filePath, content)
	case ".odt":
		content.Format = "OpenDocument Text"
		return extractOdtText(filePath, content)
	case ".ods":
		content.Format = "OpenDocument Spreadsheet"
		return extractOdsText(filePath, content)
	case ".odp":
		content.Format = "OpenDocument Presentation"
		return extractOdpText(filePath, content)
	default:
		return nil, fmt.Errorf("unsupported file format: %s", ext)
	}
}

// extractDocxText extracts text from a Word document
func extractDocxText(filePath string, content *TextContent) (*TextContent, error) {
	// Open the docx file (it's a zip archive)
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening file: %v", err)
	}
	defer reader.Close()

	// Find document content files
	var documentFile *zip.File
	var headerFiles []*zip.File
	var footerFiles []*zip.File
	var corePropsFile *zip.File
	for _, file := range reader.File {
		if file.Name == "word/document.xml" {
			documentFile = file
		} else if strings.HasPrefix(file.Name, "word/header") && strings.HasSuffix(file.Name, ".xml") {
			headerFiles = append(headerFiles, file)
		} else if strings.HasPrefix(file.Name, "word/footer") && strings.HasSuffix(file.Name, ".xml") {
			footerFiles = append(footerFiles, file)
		} else if file.Name == "docProps/core.xml" {
			corePropsFile = file
		}
	}

	if documentFile == nil {
		return content, fmt.Errorf("document.xml not found in the archive")
	}

	// Extract raw XML content
	rc, err := documentFile.Open()
	if err != nil {
		return content, err
	}
	docContent, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return content, err
	}

	// First, remove all XML tags that aren't text content
	cleanedXML := string(docContent)

	// Handle table cells and tabs - preserve tabular structure
	// Convert table cell boundaries to tabs
	cleanedXML = regexp.MustCompile(`</w:tc>\s*<w:tc[^>]*>`).ReplaceAllString(cleanedXML, "\t")
	cleanedXML = regexp.MustCompile(`<w:tc[^>]*>|</w:tc>`).ReplaceAllString(cleanedXML, "")

	// Handle table rows - convert to line breaks
	cleanedXML = regexp.MustCompile(`</w:tr>\s*<w:tr[^>]*>`).ReplaceAllString(cleanedXML, "\n")
	cleanedXML = regexp.MustCompile(`<w:tr[^>]*>|</w:tr>`).ReplaceAllString(cleanedXML, "")

	// Handle paragraphs - preserve line breaks
	cleanedXML = regexp.MustCompile(`<w:p[^>]*>|</w:p>`).ReplaceAllString(cleanedXML, "\n")

	// Extract form field content
	formFieldRe := regexp.MustCompile(`<w:fldSimple[^>]*w:instr="[^"]*"[^>]*>(.*?)</w:fldSimple>`)
	formMatches := formFieldRe.FindAllStringSubmatch(cleanedXML, -1)
	for _, match := range formMatches {
		if len(match) > 1 {
			cleanedXML = strings.Replace(cleanedXML, match[0], "[FORM:"+match[1]+"]", 1)
		}
	}

	// Extract form text input values
	textInputRe := regexp.MustCompile(`<w:instrText[^>]*>(.*?)</w:instrText>`)
	textMatches := textInputRe.FindAllStringSubmatch(cleanedXML, -1)
	for _, match := range textMatches {
		if len(match) > 1 {
			cleanedXML = strings.Replace(cleanedXML, match[0], "[FORM_INSTR:"+match[1]+"]", 1)
		}
	}

	// Handle tab characters explicitly
	cleanedXML = regexp.MustCompile(`<w:tab[^>]*/?>`).ReplaceAllString(cleanedXML, "\t")

	// Remove all remaining XML tags
	cleanedXML = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(cleanedXML, "")

	// Clean up XML entities
	cleanedXML = strings.Replace(cleanedXML, "&lt;", "<", -1)
	cleanedXML = strings.Replace(cleanedXML, "&gt;", ">", -1)
	cleanedXML = strings.Replace(cleanedXML, "&amp;", "&", -1)
	cleanedXML = strings.Replace(cleanedXML, "&quot;", "\"", -1)
	cleanedXML = strings.Replace(cleanedXML, "&apos;", "'", -1)

	// Clean up whitespace while preserving tabs and structure
	// Convert non-breaking spaces to regular spaces
	cleanedXML = strings.Replace(cleanedXML, "\u00a0", " ", -1)

	// Collapse multiple spaces but preserve tabs
	cleanedXML = regexp.MustCompile(`[ ]+`).ReplaceAllString(cleanedXML, " ")

	// Clean up excessive line breaks but preserve paragraph structure
	cleanedXML = regexp.MustCompile(`\n\s*\n\s*\n+`).ReplaceAllString(cleanedXML, "\n\n")
	cleanedXML = regexp.MustCompile(`\n[ ]+`).ReplaceAllString(cleanedXML, "\n")
	cleanedXML = regexp.MustCompile(`[ ]+\n`).ReplaceAllString(cleanedXML, "\n")

	cleanedXML = strings.TrimSpace(cleanedXML)

	// Combine main document with headers and footers
	var allText strings.Builder

	// Add headers first
	for _, headerFile := range headerFiles {
		headerText, err := extractWordXMLText(headerFile)
		if err == nil && headerText != "" {
			allText.WriteString("--- HEADER ---\n")
			allText.WriteString(headerText)
			allText.WriteString("\n\n")
		}
	}

	// Add main document
	allText.WriteString(cleanedXML)

	// Add footers last
	for _, footerFile := range footerFiles {
		footerText, err := extractWordXMLText(footerFile)
		if err == nil && footerText != "" {
			allText.WriteString("\n\n--- FOOTER ---\n")
			allText.WriteString(footerText)
		}
	}

	content.Text = allText.String()

	// Extract metadata from core.xml if available
	if corePropsFile != nil {
		extractCoreProps(corePropsFile, content)
	}

	// Count words, characters, and paragraphs
	content.WordCount = countWords(content.Text)
	content.CharCount = len(content.Text)
	content.Paragraphs = strings.Count(content.Text, "\n\n") + 1
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// extractXlsxText extracts text from an Excel spreadsheet
func extractXlsxText(filePath string, content *TextContent) (*TextContent, error) {
	// Open the xlsx file (it's a zip archive)
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening file: %v", err)
	}
	defer reader.Close()

	// Find shared strings and worksheets
	var sharedStringsFile *zip.File
	var worksheets []*zip.File
	var corePropsFile *zip.File

	for _, file := range reader.File {
		if file.Name == "xl/sharedStrings.xml" {
			sharedStringsFile = file
		} else if strings.HasPrefix(file.Name, "xl/worksheets/sheet") && strings.HasSuffix(file.Name, ".xml") {
			worksheets = append(worksheets, file)
		} else if file.Name == "docProps/core.xml" {
			corePropsFile = file
		}
	}

	// Extract shared strings
	sharedStrings := extractSharedStringsSimple(sharedStringsFile)

	// Process worksheets
	var allText strings.Builder

	// Sort worksheets by name
	sortWorksheets(worksheets)

	for _, worksheet := range worksheets {
		// Get sheet name
		sheetName := strings.TrimPrefix(worksheet.Name, "xl/worksheets/")
		sheetName = strings.TrimSuffix(sheetName, ".xml")

		allText.WriteString("--- " + sheetName + " ---\n")

		// Extract text from worksheet
		sheetText := extractWorksheetText(worksheet, sharedStrings)
		allText.WriteString(sheetText)
		allText.WriteString("\n\n")
	}

	content.Text = allText.String()

	// Extract metadata from core.xml if available
	if corePropsFile != nil {
		extractCoreProps(corePropsFile, content)
	}

	// Count words and characters
	content.WordCount = countWords(content.Text)
	content.CharCount = len(content.Text)
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// extractPptxText extracts text from a PowerPoint presentation
func extractPptxText(filePath string, content *TextContent) (*TextContent, error) {
	// Open the pptx file (it's a zip archive)
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening file: %v", err)
	}
	defer reader.Close()

	// Find all presentation content files
	var slides []*zip.File
	var notes []*zip.File
	var masters []*zip.File
	var corePropsFile *zip.File

	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "ppt/slides/slide") && strings.HasSuffix(file.Name, ".xml") {
			slides = append(slides, file)
		} else if strings.HasPrefix(file.Name, "ppt/notesSlides/notesSlide") && strings.HasSuffix(file.Name, ".xml") {
			notes = append(notes, file)
		} else if strings.HasPrefix(file.Name, "ppt/slideMasters/") && strings.HasSuffix(file.Name, ".xml") {
			masters = append(masters, file)
		} else if file.Name == "docProps/core.xml" {
			corePropsFile = file
		}
	}

	// Process slides, notes, and masters
	var allText strings.Builder

	// Process slides
	for i, slide := range slides {
		slideNum := i + 1
		allText.WriteString(fmt.Sprintf("--- Slide %d ---\n", slideNum))

		slideText, err := extractTextFromXML(slide, "//a:t")
		if err == nil {
			allText.WriteString(slideText)
		}

		// Add corresponding notes if available
		if i < len(notes) {
			notesText, err := extractTextFromXML(notes[i], "//a:t")
			if err == nil && notesText != "" {
				allText.WriteString("\n[SPEAKER NOTES]\n")
				allText.WriteString(notesText)
			}
		}
		allText.WriteString("\n\n")
	}

	// Process master slides
	for i, master := range masters {
		allText.WriteString(fmt.Sprintf("--- Master %d ---\n", i+1))
		masterText, err := extractTextFromXML(master, "//a:t")
		if err == nil {
			allText.WriteString(masterText)
		}
		allText.WriteString("\n\n")
	}

	content.Text = allText.String()
	content.PageCount = len(slides)

	// Extract metadata from core.xml if available
	if corePropsFile != nil {
		extractCoreProps(corePropsFile, content)
	}

	// Count words and characters
	content.WordCount = countWords(content.Text)
	content.CharCount = len(content.Text)
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// extractOdtText extracts text from an OpenDocument Text file
func extractOdtText(filePath string, content *TextContent) (*TextContent, error) {
	// Open the odt file (it's a zip archive)
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening file: %v", err)
	}
	defer reader.Close()

	// Find content and style files
	var contentFile *zip.File
	var stylesFile *zip.File
	var metaFile *zip.File
	for _, file := range reader.File {
		if file.Name == "content.xml" {
			contentFile = file
		} else if file.Name == "styles.xml" {
			stylesFile = file
		} else if file.Name == "meta.xml" {
			metaFile = file
		}
	}

	if contentFile == nil {
		return content, fmt.Errorf("content.xml not found in the archive")
	}

	// Extract text from content.xml
	docText, err := extractTextFromXML(contentFile, "//text:p")
	if err != nil {
		return content, err
	}

	// Combine content with styles (headers/footers)
	var allText strings.Builder
	allText.WriteString(docText)

	// Extract headers/footers from styles.xml
	if stylesFile != nil {
		stylesText, err := extractTextFromXML(stylesFile, "//text:p")
		if err == nil && stylesText != "" {
			allText.WriteString("\n\n--- STYLES/HEADERS/FOOTERS ---\n")
			allText.WriteString(stylesText)
		}
	}

	content.Text = allText.String()

	// Extract metadata from meta.xml if available
	if metaFile != nil {
		extractOdfMeta(metaFile, content)
	}

	// Count words, characters, and paragraphs
	content.WordCount = countWords(content.Text)
	content.CharCount = len(content.Text)
	content.Paragraphs = strings.Count(content.Text, "\n\n") + 1
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// extractOdsText extracts text from an OpenDocument Spreadsheet
func extractOdsText(filePath string, content *TextContent) (*TextContent, error) {
	// Open the ods file (it's a zip archive)
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening file: %v", err)
	}
	defer reader.Close()

	// Find the content.xml file which contains the spreadsheet data
	var contentFile *zip.File
	var metaFile *zip.File
	for _, file := range reader.File {
		if file.Name == "content.xml" {
			contentFile = file
		} else if file.Name == "meta.xml" {
			metaFile = file
		}
	}

	if contentFile == nil {
		return content, fmt.Errorf("content.xml not found in the archive")
	}

	// Extract text from content.xml
	// For ODS, we need to extract cell values
	docText, err := extractTextFromXML(contentFile, "//table:table-cell")
	if err != nil {
		return content, err
	}
	content.Text = docText

	// Extract metadata from meta.xml if available
	if metaFile != nil {
		extractOdfMeta(metaFile, content)
	}

	// Count words and characters
	content.WordCount = countWords(content.Text)
	content.CharCount = len(content.Text)
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// extractOdpText extracts text from an OpenDocument Presentation
func extractOdpText(filePath string, content *TextContent) (*TextContent, error) {
	// Open the odp file (it's a zip archive)
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening file: %v", err)
	}
	defer reader.Close()

	// Find content and style files
	var contentFile *zip.File
	var stylesFile *zip.File
	var metaFile *zip.File
	for _, file := range reader.File {
		if file.Name == "content.xml" {
			contentFile = file
		} else if file.Name == "styles.xml" {
			stylesFile = file
		} else if file.Name == "meta.xml" {
			metaFile = file
		}
	}

	if contentFile == nil {
		return content, fmt.Errorf("content.xml not found in the archive")
	}

	// Extract text from content.xml
	docText, err := extractTextFromXML(contentFile, "//text:p")
	if err != nil {
		return content, err
	}

	// Combine content with styles (master slides)
	var allText strings.Builder
	allText.WriteString(docText)

	// Extract master slides from styles.xml
	if stylesFile != nil {
		stylesText, err := extractTextFromXML(stylesFile, "//text:p")
		if err == nil && stylesText != "" {
			allText.WriteString("\n\n--- MASTER SLIDES ---\n")
			allText.WriteString(stylesText)
		}
	}

	content.Text = allText.String()

	// Extract metadata from meta.xml if available
	if metaFile != nil {
		extractOdfMeta(metaFile, content)
	}

	// Count words and characters
	content.WordCount = countWords(content.Text)
	content.CharCount = len(content.Text)
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// extractTextFromXML extracts text from an XML file using a simple pattern matching approach
func extractTextFromXML(file *zip.File, pattern string) (string, error) {
	// Open the XML file
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	// Read the content
	content, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}

	// For simplicity, we'll use regex to extract text
	// This is not a full XML parser but works for basic text extraction
	var result strings.Builder

	// Simplified approach: extract text between tags
	// This works for most Office XML formats where text is in <w:t>, <a:t>, or <text:p> tags
	var re *regexp.Regexp

	if pattern == "//w:t" {
		re = regexp.MustCompile(`<w:t[^>]*>(.*?)</w:t>`)
	} else if pattern == "//a:t" {
		re = regexp.MustCompile(`<a:t[^>]*>(.*?)</a:t>`)
	} else if pattern == "//text:p" {
		re = regexp.MustCompile(`<text:p[^>]*>(.*?)</text:p>`)
	} else if pattern == "//table:table-cell" {
		re = regexp.MustCompile(`<table:table-cell[^>]*>.*?<text:p[^>]*>(.*?)</text:p>.*?</table:table-cell>`)
	} else {
		re = regexp.MustCompile(`<[^>]*>(.*?)</[^>]*>`)
	}

	// Also extract form fields for OpenDocument
	var formRe *regexp.Regexp
	if pattern == "//text:p" {
		formRe = regexp.MustCompile(`<form:text[^>]*form:current-value="([^"]*)"|<form:listbox[^>]*>.*?<form:option[^>]*form:current-selected="true"[^>]*form:value="([^"]*)"|<form:checkbox[^>]*form:current-state="([^"]*)"`)
	}

	matches := re.FindAllSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			// Clean up XML entities
			text := string(match[1])
			text = strings.Replace(text, "&lt;", "<", -1)
			text = strings.Replace(text, "&gt;", ">", -1)
			text = strings.Replace(text, "&amp;", "&", -1)
			text = strings.Replace(text, "&quot;", "\"", -1)
			text = strings.Replace(text, "&apos;", "'", -1)

			// Remove any XML tags that might be inside the text
			text = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(text, "")

			result.WriteString(text)
			result.WriteString(" ")
		}
	}

	// Extract form field values for OpenDocument
	if formRe != nil {
		formMatches := formRe.FindAllSubmatch(content, -1)
		for _, match := range formMatches {
			for i := 1; i < len(match); i++ {
				if match[i] != nil {
					formValue := string(match[i])
					if formValue != "" {
						result.WriteString("[FORM:" + formValue + "] ")
					}
				}
			}
		}
	}

	// Clean up the text
	text := result.String()

	// Remove multiple spaces
	for strings.Contains(text, "  ") {
		text = strings.Replace(text, "  ", " ", -1)
	}

	// Add paragraph breaks
	if pattern == "//w:t" || pattern == "//text:p" {
		text = regexp.MustCompile(`\s*\n\s*`).ReplaceAllString(text, "\n")
	}

	return text, nil
}

// extractSharedStringsSimple extracts shared strings from an Excel file
func extractSharedStringsSimple(file *zip.File) []string {
	if file == nil {
		return nil
	}

	// Open the shared strings file
	rc, err := file.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()

	// Read the content
	content, err := io.ReadAll(rc)
	if err != nil {
		return nil
	}

	// Extract strings using regex
	var result []string

	// Match <si> elements
	siRe := regexp.MustCompile(`<si>(.*?)</si>`)
	siMatches := siRe.FindAllSubmatch(content, -1)

	for _, siMatch := range siMatches {
		if len(siMatch) < 2 {
			continue
		}

		// Extract text from <t> elements
		tRe := regexp.MustCompile(`<t[^>]*>(.*?)</t>`)
		tMatches := tRe.FindAllSubmatch(siMatch[1], -1)

		var combinedText strings.Builder
		for _, tMatch := range tMatches {
			if len(tMatch) >= 2 {
				text := string(tMatch[1])
				// Clean up XML entities
				text = strings.Replace(text, "&lt;", "<", -1)
				text = strings.Replace(text, "&gt;", ">", -1)
				text = strings.Replace(text, "&amp;", "&", -1)
				text = strings.Replace(text, "&quot;", "\"", -1)
				text = strings.Replace(text, "&apos;", "'", -1)

				combinedText.WriteString(text)
			}
		}

		result = append(result, combinedText.String())
	}

	return result
}

// extractWorksheetText extracts text from a worksheet
func extractWorksheetText(file *zip.File, sharedStrings []string) string {
	if file == nil {
		return ""
	}

	// Open the worksheet file
	rc, err := file.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()

	// Read the content
	content, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}

	// Extract rows
	var result strings.Builder

	// Find rows
	rowRe := regexp.MustCompile(`<row[^>]*>(.*?)</row>`)
	rowMatches := rowRe.FindAllSubmatch(content, -1)

	for _, rowMatch := range rowMatches {
		if len(rowMatch) < 2 {
			continue
		}

		var rowText strings.Builder
		rowContent := rowMatch[1]

		// Find cells and form controls
		cellRe := regexp.MustCompile(`<c[^>]*>.*?(?:<v>(.*?)</v>|<is>.*?<t>(.*?)</t>.*?</is>|<t>(.*?)</t>).*?</c>`)
		cellMatches := cellRe.FindAllSubmatch(rowContent, -1)

		// Also look for form controls in Excel
		formControlRe := regexp.MustCompile(`<formControlPr[^>]*defaultValue="([^"]*)"|<dataValidation[^>]*formula1="([^"]*)"`)
		formMatches := formControlRe.FindAllSubmatch(rowContent, -1)

		for _, cellMatch := range cellMatches {
			if len(cellMatch) < 4 {
				continue
			}

			// Get cell content
			var cellText string

			// Check if it's a shared string
			cellStr := string(cellMatch[0])
			isSharedString := strings.Contains(cellStr, `t="s"`)

			// Extract value from <v> tag
			if cellMatch[1] != nil {
				value := string(cellMatch[1])

				if isSharedString && len(sharedStrings) > 0 {
					// Convert to shared string
					index, err := strconv.Atoi(value)
					if err == nil && index >= 0 && index < len(sharedStrings) {
						cellText = sharedStrings[index]
					}
				} else {
					cellText = value
				}
			} else if cellMatch[2] != nil {
				// Inline string
				cellText = string(cellMatch[2])
			} else if cellMatch[3] != nil {
				// Direct text
				cellText = string(cellMatch[3])
			}

			if cellText != "" {
				rowText.WriteString(cellText)
				rowText.WriteString("\t")
			}
		}

		// Add form control values
		for _, formMatch := range formMatches {
			for i := 1; i < len(formMatch); i++ {
				if formMatch[i] != nil {
					formValue := string(formMatch[i])
					if formValue != "" {
						rowText.WriteString("[FORM:" + formValue + "]\t")
					}
				}
			}
		}

		// Add row to result
		if rowText.Len() > 0 {
			result.WriteString(rowText.String())
			result.WriteString("\n")
		}
	}

	return result.String()
}

// sortWorksheets sorts worksheets by sheet number
func sortWorksheets(worksheets []*zip.File) {
	// Extract sheet number from filename
	getSheetNumber := func(filename string) int {
		re := regexp.MustCompile(`sheet(\d+)\.xml`)
		matches := re.FindStringSubmatch(filename)
		if len(matches) >= 2 {
			num, err := strconv.Atoi(matches[1])
			if err == nil {
				return num
			}
		}
		return 9999 // Default high number for non-standard sheet names
	}

	// Sort worksheets by sheet number
	for i := 0; i < len(worksheets); i++ {
		for j := i + 1; j < len(worksheets); j++ {
			if getSheetNumber(worksheets[i].Name) > getSheetNumber(worksheets[j].Name) {
				worksheets[i], worksheets[j] = worksheets[j], worksheets[i]
			}
		}
	}
}

// extractCoreProps extracts metadata from the core.xml file
func extractCoreProps(file *zip.File, content *TextContent) {
	// Open the core properties file
	rc, err := file.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	// Read the content
	xmlContent, err := io.ReadAll(rc)
	if err != nil {
		return
	}

	// Extract page count
	pageCountRe := regexp.MustCompile(`<Pages>(\d+)</Pages>`)
	pageCountMatch := pageCountRe.FindSubmatch(xmlContent)
	if len(pageCountMatch) > 1 {
		content.PageCount, _ = strconv.Atoi(string(pageCountMatch[1]))
	}

	// Extract word count
	wordCountRe := regexp.MustCompile(`<Words>(\d+)</Words>`)
	wordCountMatch := wordCountRe.FindSubmatch(xmlContent)
	if len(wordCountMatch) > 1 {
		wordCount, _ := strconv.Atoi(string(wordCountMatch[1]))
		if wordCount > 0 {
			content.WordCount = wordCount
		}
	}

	// Extract character count
	charCountRe := regexp.MustCompile(`<Characters>(\d+)</Characters>`)
	charCountMatch := charCountRe.FindSubmatch(xmlContent)
	if len(charCountMatch) > 1 {
		charCount, _ := strconv.Atoi(string(charCountMatch[1]))
		if charCount > 0 {
			content.CharCount = charCount
		}
	}
}

// extractOdfMeta extracts metadata from the meta.xml file in OpenDocument formats
func extractOdfMeta(file *zip.File, content *TextContent) {
	// Open the meta file
	rc, err := file.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	// Read the content
	xmlContent, err := io.ReadAll(rc)
	if err != nil {
		return
	}

	// Extract page count
	pageCountRe := regexp.MustCompile(`<meta:page-count>(\d+)</meta:page-count>`)
	pageCountMatch := pageCountRe.FindSubmatch(xmlContent)
	if len(pageCountMatch) > 1 {
		content.PageCount, _ = strconv.Atoi(string(pageCountMatch[1]))
	}

	// Extract word count
	wordCountRe := regexp.MustCompile(`<meta:word-count>(\d+)</meta:word-count>`)
	wordCountMatch := wordCountRe.FindSubmatch(xmlContent)
	if len(wordCountMatch) > 1 {
		wordCount, _ := strconv.Atoi(string(wordCountMatch[1]))
		if wordCount > 0 {
			content.WordCount = wordCount
		}
	}

	// Extract character count
	charCountRe := regexp.MustCompile(`<meta:character-count>(\d+)</meta:character-count>`)
	charCountMatch := charCountRe.FindSubmatch(xmlContent)
	if len(charCountMatch) > 1 {
		charCount, _ := strconv.Atoi(string(charCountMatch[1]))
		if charCount > 0 {
			content.CharCount = charCount
		}
	}
}

// extractWordXMLText extracts text from Word XML files (headers/footers)
func extractWordXMLText(file *zip.File) (string, error) {
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	docContent, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}

	// Apply same cleaning as main document
	cleanedXML := string(docContent)
	cleanedXML = regexp.MustCompile(`<w:p[^>]*>|</w:p>`).ReplaceAllString(cleanedXML, "\n")

	// Extract form fields from headers/footers
	formFieldRe := regexp.MustCompile(`<w:fldSimple[^>]*w:instr="[^"]*"[^>]*>(.*?)</w:fldSimple>`)
	formMatches := formFieldRe.FindAllStringSubmatch(cleanedXML, -1)
	for _, match := range formMatches {
		if len(match) > 1 {
			cleanedXML = strings.Replace(cleanedXML, match[0], "[FORM:"+match[1]+"]", 1)
		}
	}

	cleanedXML = regexp.MustCompile(`<w:tab[^>]*/?>`).ReplaceAllString(cleanedXML, "\t")
	cleanedXML = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(cleanedXML, "")

	// Clean up XML entities
	cleanedXML = strings.Replace(cleanedXML, "&lt;", "<", -1)
	cleanedXML = strings.Replace(cleanedXML, "&gt;", ">", -1)
	cleanedXML = strings.Replace(cleanedXML, "&amp;", "&", -1)
	cleanedXML = strings.Replace(cleanedXML, "&quot;", "\"", -1)
	cleanedXML = strings.Replace(cleanedXML, "&apos;", "'", -1)

	// Clean up whitespace
	cleanedXML = regexp.MustCompile(`[ ]+`).ReplaceAllString(cleanedXML, " ")
	cleanedXML = regexp.MustCompile(`\n\s*\n\s*\n+`).ReplaceAllString(cleanedXML, "\n\n")
	cleanedXML = strings.TrimSpace(cleanedXML)

	return cleanedXML, nil
}

// countWords counts the number of words in a text
func countWords(text string) int {
	// Split by whitespace and count non-empty words
	words := strings.Fields(text)
	return len(words)
}
