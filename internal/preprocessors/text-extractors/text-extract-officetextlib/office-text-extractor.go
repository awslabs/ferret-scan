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
	"sort"
	"strconv"
	"strings"
)

// Decompression-amplification bounds. Office files are zip archives; a small
// archive can expand to gigabytes of XML ("zip bomb" shape), which would then be
// concatenated and fed whole into every regex validator. We cap BOTH the size of
// any single decompressed zip entry and the total decompressed text accumulated
// from one document. These mirror the bounds the metadata office extractor
// already enforces (meta-extract-officelib MaxXMLSize); the text extractor was
// the unprotected sibling (v2 gap 2.4).
//
// The caps are generous — far above any realistic document — so legitimate files
// are unaffected; only hostile decompression amplification is bounded. When a
// bound is hit, extraction returns the text gathered so far (best-effort) rather
// than erroring, consistent with the extractor's existing partial-content
// behavior.
const (
	// MaxZipEntryBytes bounds a single decompressed entry (e.g. document.xml,
	// one sheet's sharedStrings.xml).
	MaxZipEntryBytes = 50 * 1024 * 1024 // 50MB
	// MaxTotalTextBytes bounds the CUMULATIVE extracted text across all entries
	// in one document. The per-entry cap alone doesn't stop a document with many
	// entries (e.g. thousands of slides/sheets, each under 50MB) from summing to
	// tens of GB and then being fed whole to every validator (security finding
	// LOW-1). Consistent with this extractor's truncate-don't-error philosophy,
	// accumulation loops stop appending once the running total exceeds this.
	MaxTotalTextBytes = 200 * 1024 * 1024 // 200MB
)

// readZipEntryLimited reads a decompressed zip entry, capped at MaxZipEntryBytes,
// regardless of the entry's claimed/actual uncompressed size. It is a
// drop-in replacement for readZipEntryLimited(rc) (same (content, err) signature) used at
// every zip-entry read in this file. Capping each entry closes the
// decompression-amplification ("zip bomb") vector at the source: a small archive
// can no longer expand to gigabytes of validator text. A capped read returns
// valid (if truncated) content, which is still safe to scan; truncation is not
// an error.
func readZipEntryLimited(rc io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(rc, MaxZipEntryBytes))
}

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

	// BodyParts counts the archive members this extractor identified as document
	// body (the main document, the worksheets, the slides). Zero means the
	// container held nothing recognizable as body content at all — as opposed to a
	// body that was read and turned out to be empty.
	BodyParts int

	// ExtractionWarning is a short, payload-free note set when a container that
	// CAN carry a document body yielded no body text. Nothing used to distinguish
	// that from a genuinely empty document: extraction reported Success with
	// textLen 0, the router stamped Success, and --fail-on-incomplete returned 0,
	// so a file whose body was skipped was indistinguishable from an empty one and
	// the run looked clean. Callers surface this and count it as a coverage gap.
	ExtractionWarning string
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
		content, err = extractDocxText(filePath, content)
	case ".xlsx":
		content.Format = "Excel Spreadsheet"
		content, err = extractXlsxText(filePath, content)
	case ".pptx":
		content.Format = "PowerPoint Presentation"
		content, err = extractPptxText(filePath, content)
	case ".odt":
		content.Format = "OpenDocument Text"
		content, err = extractOdtText(filePath, content)
	case ".ods":
		content.Format = "OpenDocument Spreadsheet"
		content, err = extractOdsText(filePath, content)
	case ".odp":
		content.Format = "OpenDocument Presentation"
		content, err = extractOdpText(filePath, content)
	default:
		return nil, fmt.Errorf("unsupported file format: %s", ext)
	}

	noteEmptyExtraction(content, ext)
	return content, err
}

// noteEmptyExtraction records an ExtractionWarning when a container whose format
// carries a document body produced no body text.
//
// This is the visibility half of the part-selection fix. Selecting the body by
// name means a name we do not recognize yields zero text, and zero text used to be
// reported exactly like an empty document — Success=true, textLen=0, exit 0. So
// the failure mode the part-name fix addresses was, by construction, silent: the
// operator had no signal that a 40-page document contributed nothing to the scan.
// The warning fires on the OUTCOME (no body text) rather than on any specific
// cause, so it also covers whatever part-naming trick we have not thought of.
func noteEmptyExtraction(content *TextContent, ext string) {
	if content == nil || content.ExtractionWarning != "" {
		return
	}
	if strings.TrimSpace(content.Text) != "" {
		return
	}
	if content.BodyParts > 0 {
		content.ExtractionWarning = fmt.Sprintf(
			"no text extracted from %s: %d body part(s) were read but held no text",
			ext, content.BodyParts)
		return
	}
	content.ExtractionWarning = fmt.Sprintf(
		"no text extracted from %s: no document body part was found in the archive, "+
			"so document content was NOT scanned", ext)
}

// extractDocxText extracts text from a Word document
func extractDocxText(filePath string, content *TextContent) (*TextContent, error) {
	// Open the docx file (it's a zip archive)
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return content, fmt.Errorf("error opening file: %v", err)
	}
	defer reader.Close()

	// Find document content files. Part names are producer-controlled, so the main
	// document is located through the package relationships and by conventional
	// name case-insensitively, then unioned — see ooxml_parts.go for why one
	// capital letter used to drop the entire body.
	pkg := newOOXMLPackage(reader.File)
	documentFiles := unionParts(
		pkg.relatedParts("", "officeDocument"),
		[]*zip.File{pkg.lookup("word/document.xml"), pkg.lookup("word/main.xml")},
	)
	headerFiles := pkg.matching("word/header", ".xml")
	footerFiles := pkg.matching("word/footer", ".xml")
	corePropsFile := pkg.lookup("docProps/core.xml")

	if len(documentFiles) == 0 {
		return content, fmt.Errorf("document.xml not found in the archive")
	}
	content.BodyParts = len(documentFiles)

	// Extract raw XML content. Where a package names more than one main-document
	// part (relationships pointing somewhere other than the conventional name, or
	// two entries differing only in case) every one is extracted: dropping the
	// ones we did not expect is exactly how content escaped scanning before.
	var rawDoc strings.Builder
	for _, documentFile := range documentFiles {
		if rawDoc.Len() > MaxTotalTextBytes {
			break
		}
		rc, err := documentFile.Open()
		if err != nil {
			continue
		}
		part, err := readZipEntryLimited(rc)
		rc.Close()
		if err != nil {
			continue
		}
		rawDoc.Write(part)
	}

	// First, remove all XML tags that aren't text content
	cleanedXML := rawDoc.String()

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
	// One pass, not one full-document scan per match. Rewriting inside a
	// FindAllStringSubmatch loop makes extraction O(matches x document): each
	// strings.Replace re-scans everything from the start. Measured on a .docx of
	// N form fields, cost grew ~2.5-3.3x per input doubling (linear is 2x) and a
	// 43KB file took 2.85s. ReplaceAllString is byte-identical here -- verified
	// against the loop on duplicate fields, empty values, and values containing
	// "$1"/"${x}", which are NOT re-expanded because template expansion applies
	// to the replacement string, not to the inserted capture.
	cleanedXML = formFieldRe.ReplaceAllString(cleanedXML, "[FORM:$1]")

	// Extract form text input values
	textInputRe := regexp.MustCompile(`<w:instrText[^>]*>(.*?)</w:instrText>`)
	// One pass -- see the note on the form-field replacement above.
	cleanedXML = textInputRe.ReplaceAllString(cleanedXML, "[FORM_INSTR:$1]")

	// Handle tab characters explicitly
	cleanedXML = regexp.MustCompile(`<w:tab[^>]*/?>`).ReplaceAllString(cleanedXML, "\t")

	// Remove all remaining XML tags
	cleanedXML = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(cleanedXML, "")

	cleanedXML = decodeXMLEntities(cleanedXML)

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
		// Stop once cumulative extracted text hits the cap (LOW-1).
		if allText.Len() > MaxTotalTextBytes {
			break
		}
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
		// Stop once cumulative extracted text hits the cap (LOW-1).
		if allText.Len() > MaxTotalTextBytes {
			break
		}
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

	// Find shared strings and worksheets. Resolved through the workbook's
	// relationships and by conventional name case-insensitively, then unioned —
	// see ooxml_parts.go. A capitalized "xl/Worksheets/" or "xl/SharedStrings.xml"
	// used to make the whole sheet, or every shared string in it, invisible.
	pkg := newOOXMLPackage(reader.File)
	workbookParts := unionParts(
		pkg.relatedParts("", "officeDocument"),
		[]*zip.File{pkg.lookup("xl/workbook.xml")},
	)

	var relSheets, relShared []*zip.File
	for _, wb := range workbookParts {
		relSheets = append(relSheets, pkg.relatedParts(wb.Name, "worksheet")...)
		relShared = append(relShared, pkg.relatedParts(wb.Name, "sharedStrings")...)
	}

	worksheets := unionParts(relSheets, pkg.matching("xl/worksheets/", ".xml"))
	sharedStringsFiles := unionParts(relShared, []*zip.File{pkg.lookup("xl/sharedStrings.xml")})
	corePropsFile := pkg.lookup("docProps/core.xml")

	// Shared strings are referenced by POSITION, so only one table can be
	// authoritative; the relationship-resolved one leads and a conventional-name
	// hit is the fallback. Concatenating two tables would shift every index.
	var sharedStringsFile *zip.File
	if len(sharedStringsFiles) > 0 {
		sharedStringsFile = sharedStringsFiles[0]
	}

	content.BodyParts = len(worksheets)

	// Extract shared strings
	sharedStrings := extractSharedStringsSimple(sharedStringsFile)

	// Process worksheets
	var allText strings.Builder

	// Sort worksheets by name
	sortWorksheets(worksheets)

	for _, worksheet := range worksheets {
		// Stop once cumulative extracted text hits the cap (LOW-1): many small
		// entries can still sum to a memory-exhausting total.
		if allText.Len() > MaxTotalTextBytes {
			break
		}
		// Get sheet name (case-insensitive trim: a capitalized "xl/Worksheets/"
		// otherwise left the directory in the emitted section label).
		sheetName := trimPartLabel(worksheet.Name, "xl/worksheets/")

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

	// Find all presentation content files. Slides come from the presentation's
	// relationships unioned with the conventional name matched case-insensitively
	// (see ooxml_parts.go); pkg also resolves each slide's notes through its own
	// relationships part, rather than guessing by position.
	pkg := newOOXMLPackage(reader.File)
	presentationParts := unionParts(
		pkg.relatedParts("", "officeDocument"),
		[]*zip.File{pkg.lookup("ppt/presentation.xml")},
	)

	var relSlides, relMasters []*zip.File
	for _, pres := range presentationParts {
		relSlides = append(relSlides, pkg.relatedParts(pres.Name, "slide")...)
		relMasters = append(relMasters, pkg.relatedParts(pres.Name, "slideMaster")...)
	}

	slides := unionParts(relSlides, pkg.matching("ppt/slides/slide", ".xml"))
	masters := unionParts(relMasters, pkg.matching("ppt/slideMasters/", ".xml"))
	corePropsFile := pkg.lookup("docProps/core.xml")

	content.BodyParts = len(slides) + len(masters)

	// Order slides and masters by their numeric index. zip.OpenReader returns
	// entries in the archive's central-directory order, which the producer
	// controls and is NOT guaranteed to be slideN order — a re-saved or
	// tool-generated deck can interleave them, which would both mislabel
	// "--- Slide N ---" and emit content out of reading order.
	sortByNumericSuffix(slides)
	sortByNumericSuffix(masters)

	// Process slides, notes, and masters
	var allText strings.Builder

	// Process slides
	for i, slide := range slides {
		// Stop once cumulative extracted text hits the cap (LOW-1).
		if allText.Len() > MaxTotalTextBytes {
			break
		}
		slideNum := i + 1
		allText.WriteString(fmt.Sprintf("--- Slide %d ---\n", slideNum))

		slideText, err := extractTextFromXML(slide, "//a:t")
		if err == nil {
			allText.WriteString(slideText)
		}

		// Attach the notes that actually belong to THIS slide, resolved through
		// the slide's .rels. The previous code paired notes[i] with slides[i] by
		// position, but notesSlideN is not aligned with slideN — decks routinely
		// have notes on only some slides and in a different order — so a slide
		// got another slide's speaker notes (or none), mislabeling where that
		// text, and any PII in it, came from.
		if notesFile := pptxNotesForSlide(slide, pkg); notesFile != nil {
			notesText, err := extractTextFromXML(notesFile, "//a:t")
			if err == nil && notesText != "" {
				allText.WriteString("\n[SPEAKER NOTES]\n")
				allText.WriteString(notesText)
			}
		}
		allText.WriteString("\n\n")
	}

	// Process master slides
	for i, master := range masters {
		// Stop once cumulative extracted text hits the cap (LOW-1).
		if allText.Len() > MaxTotalTextBytes {
			break
		}
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

	// Find content and style files. ODF has no relationship parts, but the entry
	// names are still producer-controlled, so match them case-insensitively for the
	// same reason the OOXML paths do (ooxml_parts.go).
	pkg := newOOXMLPackage(reader.File)
	contentFile := pkg.lookup("content.xml")
	stylesFile := pkg.lookup("styles.xml")
	metaFile := pkg.lookup("meta.xml")

	if contentFile == nil {
		return content, fmt.Errorf("content.xml not found in the archive")
	}
	content.BodyParts = 1

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

	// Find the content.xml file which contains the spreadsheet data, matched
	// case-insensitively like the other container paths (ooxml_parts.go).
	pkg := newOOXMLPackage(reader.File)
	contentFile := pkg.lookup("content.xml")
	metaFile := pkg.lookup("meta.xml")

	if contentFile == nil {
		return content, fmt.Errorf("content.xml not found in the archive")
	}
	content.BodyParts = 1

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

	// Find content and style files, matched case-insensitively like the other
	// container paths (ooxml_parts.go).
	pkg := newOOXMLPackage(reader.File)
	contentFile := pkg.lookup("content.xml")
	stylesFile := pkg.lookup("styles.xml")
	metaFile := pkg.lookup("meta.xml")

	if contentFile == nil {
		return content, fmt.Errorf("content.xml not found in the archive")
	}
	content.BodyParts = 1

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
	content, err := readZipEntryLimited(rc)
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
			text := decodeXMLEntities(string(match[1]))

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
	content, err := readZipEntryLimited(rc)
	if err != nil {
		return nil
	}

	// Extract strings using regex
	var result []string

	// Match <si> elements. The (?s) flag is mandatory, not cosmetic: a cell whose
	// text contains a line break (very common for multi-line answer lists) has
	// literal newlines inside its <si>, and without (?s) the `.` stops at them so
	// the element does not match at all. Because the shared-string table is
	// referenced *positionally* by <v> indices, a skipped entry does not merely
	// lose one string — it shifts every subsequent index, so unrelated cells
	// silently resolve to the wrong text. Measured on a real 15 KB spreadsheet:
	// 12 of 123 entries were skipped, first divergence at index 89.
	siMatches := sharedStringSiRe.FindAllSubmatch(content, -1)

	for _, siMatch := range siMatches {
		if len(siMatch) < 2 {
			continue
		}

		// Extract text from <t> elements. Same (?s) requirement, same reason.
		tMatches := sharedStringTRe.FindAllSubmatch(siMatch[1], -1)

		var combinedText strings.Builder
		for _, tMatch := range tMatches {
			if len(tMatch) >= 2 {
				combinedText.WriteString(decodeXMLEntities(string(tMatch[1])))
			}
		}

		result = append(result, combinedText.String())
	}

	return result
}

// Shared-string and worksheet patterns are compiled once at package level rather
// than inside the per-element loops they are used in; the previous code rebuilt
// them for every <si> and every <row>.
var (
	sharedStringSiRe = regexp.MustCompile(`(?s)<si>(.*?)</si>`)
	sharedStringTRe  = regexp.MustCompile(`(?s)<t[^>]*>(.*?)</t>`)

	worksheetRowRe = regexp.MustCompile(`(?s)<row[^>]*>(.*?)</row>`)

	// Cells are matched in two stages because Go's RE2 has no lookahead and a
	// self-closing `<c r="B2"/>` must not be treated as an opening tag. The
	// attribute group deliberately requires the last character before `>` to not
	// be `/`, which is the RE2-compatible way to say "not self-closing".
	worksheetCellRe = regexp.MustCompile(`(?s)<c((?:[^>]*[^/>])?)>(.*?)</c>`)

	// Value extraction inside a single cell body.
	cellValueRe  = regexp.MustCompile(`(?s)<v>(.*?)</v>`)
	cellInlineRe = regexp.MustCompile(`(?s)<is>.*?<t[^>]*>(.*?)</t>.*?</is>`)
	cellTextRe   = regexp.MustCompile(`(?s)<t[^>]*>(.*?)</t>`)

	worksheetFormControlRe = regexp.MustCompile(`<formControlPr[^>]*defaultValue="([^"]*)"|<dataValidation[^>]*formula1="([^"]*)"`)

	sharedStringTypeRe = regexp.MustCompile(`\bt="s"`)

	// Named entities and numeric character references, matched in one alternation
	// so decodeXMLEntities can resolve each in a single non-overlapping pass.
	entityRe = regexp.MustCompile(`&(?:lt|gt|quot|apos|amp|#x[0-9a-fA-F]+|#[0-9]+);`)
)

// decodeXMLEntities expands the XML entities that appear in OOXML text runs.
//
// Every entity is decoded in a SINGLE pass, because any two-pass scheme
// re-reads its own output and invents markup that was never in the document.
// Both orderings are wrong in the same way:
//
//	`&amp;lt;`  is the encoded *literal* "&lt;" — expanding &amp; first, then
//	            &lt;, yields "<".
//	`&#38;lt;`  is the same literal written with a numeric reference —
//	            expanding numeric refs first, then &lt;, also yields "<".
//
// A single left-to-right pass that consumes each reference exactly once and
// never revisits the text it just wrote gets both cases right.
func decodeXMLEntities(s string) string {
	if !strings.ContainsRune(s, '&') {
		return s
	}

	return entityRe.ReplaceAllStringFunc(s, func(m string) string {
		switch m {
		case "&lt;":
			return "<"
		case "&gt;":
			return ">"
		case "&quot;":
			return "\""
		case "&apos;":
			return "'"
		case "&amp;":
			return "&"
		}

		// Numeric character reference: &#NNN; or &#xHHH;. Excel emits these for
		// characters outside the sheet's encoding.
		body := m[2 : len(m)-1]
		base, digits := 10, body
		if body[0] == 'x' || body[0] == 'X' {
			base, digits = 16, body[1:]
		}
		cp, err := strconv.ParseInt(digits, base, 32)
		// Leave anything unparseable or outside the valid Unicode scalar range
		// as written rather than emitting U+FFFD, so the raw form still reaches
		// the validators instead of becoming an unsearchable placeholder.
		if err != nil || cp <= 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) {
			return m
		}
		return string(rune(cp))
	})
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
	content, err := readZipEntryLimited(rc)
	if err != nil {
		return ""
	}

	// Extract rows
	var result strings.Builder

	// Find rows
	rowMatches := worksheetRowRe.FindAllSubmatch(content, -1)

	for _, rowMatch := range rowMatches {
		if len(rowMatch) < 2 {
			continue
		}

		var rowText strings.Builder
		rowContent := rowMatch[1]

		// Find cells. This is a two-stage match: locate each non-self-closing
		// <c>…</c> first, then pull the value out of its body. The previous
		// single-pattern approach had two defects on real spreadsheets:
		//
		//  1. `<c[^>]*>` also matched a self-closing `<c r="B2"/>` (an empty,
		//     styled cell — 16 of 52 cells in one real sheet). Having consumed
		//     it as an opening tag, `.*?</c>` then ran on to the *next* cell's
		//     closing tag and reported that neighbour's value under the empty
		//     cell, dropping cells in the process.
		//  2. The inline-string and direct-text branches used a bare `<t>`,
		//     which does not match the attributed `<t xml:space="preserve">`
		//     Excel writes whenever a value has leading or trailing spaces.
		cellMatches := worksheetCellRe.FindAllSubmatch(rowContent, -1)

		// Also look for form controls in Excel
		formMatches := worksheetFormControlRe.FindAllSubmatch(rowContent, -1)

		for _, cellMatch := range cellMatches {
			if len(cellMatch) < 3 {
				continue
			}

			attrs, body := cellMatch[1], cellMatch[2]

			// Check if it's a shared string. Matched on a word boundary so a
			// different attribute ending in `t="s"` cannot be mistaken for the
			// cell type.
			isSharedString := sharedStringTypeRe.Match(attrs)

			var cellText string
			switch {
			case cellValueRe.Match(body):
				value := string(cellValueRe.FindSubmatch(body)[1])
				if isSharedString && len(sharedStrings) > 0 {
					// Shared strings are referenced positionally.
					index, err := strconv.Atoi(strings.TrimSpace(value))
					if err == nil && index >= 0 && index < len(sharedStrings) {
						cellText = sharedStrings[index]
					}
				} else {
					cellText = decodeXMLEntities(value)
				}
			case cellInlineRe.Match(body):
				cellText = decodeXMLEntities(string(cellInlineRe.FindSubmatch(body)[1]))
			case cellTextRe.Match(body):
				cellText = decodeXMLEntities(string(cellTextRe.FindSubmatch(body)[1]))
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

// numericSuffixRe pulls the trailing integer out of an OOXML part name such as
// "ppt/slides/slide12.xml" (→ 12) so parts can be ordered by index rather than
// by the archive's central-directory order.
var numericSuffixRe = regexp.MustCompile(`(\d+)\.xml$`)

// partNumber returns the trailing numeric index of a part name, or a large
// sentinel for non-standard names so they sort to the end deterministically.
func partNumber(name string) int {
	if m := numericSuffixRe.FindStringSubmatch(name); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 1 << 30
}

// sortByNumericSuffix orders zip parts by their trailing numeric index (slide2
// before slide10), then by name as a stable tiebreak.
func sortByNumericSuffix(files []*zip.File) {
	sort.SliceStable(files, func(i, j int) bool {
		ni, nj := partNumber(files[i].Name), partNumber(files[j].Name)
		if ni != nj {
			return ni < nj
		}
		return files[i].Name < files[j].Name
	})
}

// pptxNotesForSlide resolves the notesSlide part that belongs to the given slide
// through the slide's own relationships, which is the authoritative link. Returns
// nil if the slide has no notes or its rels part is missing/unreadable. This
// replaces the previous positional pairing of notes[i] with slides[i], which
// mis-attached notes because notesSlideN is not aligned with slideN.
//
// Relationship lookup now goes through ooxmlPackage, so the slide's .rels part is
// found regardless of the case the producer used and the target is resolved by the
// shared relative-target rules rather than by trimming "../" by hand.
func pptxNotesForSlide(slide *zip.File, pkg *ooxmlPackage) *zip.File {
	notes := pkg.relatedParts(slide.Name, "notesSlide")
	if len(notes) == 0 {
		return nil
	}
	return notes[0]
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
	xmlContent, err := readZipEntryLimited(rc)
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
	xmlContent, err := readZipEntryLimited(rc)
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

	docContent, err := readZipEntryLimited(rc)
	if err != nil {
		return "", err
	}

	// Apply same cleaning as main document
	cleanedXML := string(docContent)
	cleanedXML = regexp.MustCompile(`<w:p[^>]*>|</w:p>`).ReplaceAllString(cleanedXML, "\n")

	// Extract form fields from headers/footers
	formFieldRe := regexp.MustCompile(`<w:fldSimple[^>]*w:instr="[^"]*"[^>]*>(.*?)</w:fldSimple>`)
	// One pass, not one full-document scan per match. Rewriting inside a
	// FindAllStringSubmatch loop makes extraction O(matches x document): each
	// strings.Replace re-scans everything from the start. Measured on a .docx of
	// N form fields, cost grew ~2.5-3.3x per input doubling (linear is 2x) and a
	// 43KB file took 2.85s. ReplaceAllString is byte-identical here -- verified
	// against the loop on duplicate fields, empty values, and values containing
	// "$1"/"${x}", which are NOT re-expanded because template expansion applies
	// to the replacement string, not to the inserted capture.
	cleanedXML = formFieldRe.ReplaceAllString(cleanedXML, "[FORM:$1]")

	cleanedXML = regexp.MustCompile(`<w:tab[^>]*/?>`).ReplaceAllString(cleanedXML, "\t")
	cleanedXML = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(cleanedXML, "")

	cleanedXML = decodeXMLEntities(cleanedXML)

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
