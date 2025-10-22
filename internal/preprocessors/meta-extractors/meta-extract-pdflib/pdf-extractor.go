// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractpdflib

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Metadata represents PDF document metadata
type Metadata struct {
	Filename    string
	FileSize    int64
	ModTime     time.Time
	MimeType    string
	Title       string
	Author      string
	Creator     string
	Producer    string
	CreatedDate time.Time
	ModDate     time.Time
	Subject     string
	Keywords    string
	PageCount   int
	Version     string
	Encrypted   bool
	Properties  map[string]string
}

// ExtractMetadata extracts metadata from a PDF document with improved error handling and memory efficiency
func ExtractMetadata(filePath string) (*Metadata, error) {
	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("file error: %v", err)
	}

	// Initialize metadata with basic file info
	metadata := &Metadata{
		Filename:   filepath.Base(filePath),
		FileSize:   fileInfo.Size(),
		ModTime:    fileInfo.ModTime(),
		MimeType:   "application/pdf",
		Properties: make(map[string]string),
	}

	// Check file size and warn about potential memory issues
	const maxSafeFileSize = 100 * 1024 * 1024 // 100MB
	if fileInfo.Size() > maxSafeFileSize {
		fmt.Fprintf(os.Stderr, "Warning: Large PDF file (%d MB), metadata extraction may use significant memory\n", fileInfo.Size()/(1024*1024))
	}

	// Read the PDF file - for very large files, consider streaming in future
	data, err := os.ReadFile(filePath)
	if err != nil {
		return metadata, fmt.Errorf("error reading file: %v", err)
	}

	// Extract PDF version
	metadata.Version = extractPDFVersion(data)
	if os.Getenv("FERRET_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[DEBUG] PDF Metadata: Extracted version: %s\n", metadata.Version)
	}

	// Extract metadata from the PDF
	extractInfoDictionary(data, metadata)
	if os.Getenv("FERRET_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[DEBUG] PDF Metadata: After info dictionary - Creator: '%s', Producer: '%s'\n", metadata.Creator, metadata.Producer)
	}

	// Try direct extraction for specific fields if they're still empty
	if metadata.Creator == "" {
		metadata.Creator = extractDirectField(data, "Creator")
		// Try alternative field names
		if metadata.Creator == "" {
			metadata.Creator = extractDirectField(data, "CreatorTool")
		}
	}

	if metadata.Producer == "" {
		metadata.Producer = extractDirectField(data, "Producer")
		// Try alternative field names
		if metadata.Producer == "" {
			metadata.Producer = extractDirectField(data, "PDF Producer")
		}
	}

	// Check for malformed or encrypted metadata
	if containsNonPrintableChars(metadata.Creator) {
		metadata.Creator = "[Encrypted or malformed data]"
	}

	if containsNonPrintableChars(metadata.Producer) {
		metadata.Producer = "[Encrypted or malformed data]"
	}

	// Try XMP metadata as a last resort
	if metadata.Creator == "" || metadata.Producer == "" {
		extractXMPMetadata(data, metadata)
	}

	// Extract page count
	metadata.PageCount = countPages(data)

	// Check if PDF is encrypted
	metadata.Encrypted = isEncrypted(data)

	return metadata, nil
}

// extractPDFVersion extracts the PDF version from the header
func extractPDFVersion(data []byte) string {
	// PDF header format: %PDF-1.x
	headerPattern := regexp.MustCompile(`%PDF-(\d+\.\d+)`)

	// Check only the first 1KB or the entire file if smaller
	size := len(data)
	if size > 1024 {
		size = 1024
	}

	matches := headerPattern.FindSubmatch(data[:size])

	if len(matches) >= 2 {
		return string(matches[1])
	}

	return "Unknown"
}

// extractInfoDictionary extracts metadata from the PDF Info dictionary
func extractInfoDictionary(data []byte, metadata *Metadata) {
	// First approach: Look for the Info dictionary reference
	infoPattern := regexp.MustCompile(`/Info\s+(\d+)\s+\d+\s+R`)
	infoMatches := infoPattern.FindSubmatch(data)

	var infoDictionary string

	if len(infoMatches) >= 2 {
		// Find the object with the Info dictionary
		objNum := string(infoMatches[1])
		objPattern := regexp.MustCompile(objNum + `\s+\d+\s+obj\s+<<(.*?)>>`)
		objMatches := objPattern.FindSubmatch(data)

		if len(objMatches) >= 2 {
			infoDictionary = string(objMatches[1])
		}
	}

	// Second approach: Look for metadata directly in the trailer
	if infoDictionary == "" {
		trailerPattern := regexp.MustCompile(`trailer\s*<<(.*?)>>`)
		trailerMatches := trailerPattern.FindSubmatch(data)

		if len(trailerMatches) >= 2 {
			trailerDict := string(trailerMatches[1])

			// Look for Info reference in trailer
			infoRefPattern := regexp.MustCompile(`/Info\s+(\d+)\s+\d+\s+R`)
			infoRefMatches := infoRefPattern.FindStringSubmatch(trailerDict)

			if len(infoRefMatches) >= 2 {
				// Find the object with the Info dictionary
				objNum := infoRefMatches[1]
				objPattern := regexp.MustCompile(objNum + `\s+\d+\s+obj\s+<<(.*?)>>`)
				objMatches := objPattern.FindSubmatch(data)

				if len(objMatches) >= 2 {
					infoDictionary = string(objMatches[1])
				}
			}
		}
	}

	// Third approach: Look for metadata directly
	if infoDictionary == "" {
		// Try to find a metadata dictionary directly
		metaPattern := regexp.MustCompile(`<<\s*/Creator[^>]*>>|<<\s*/Producer[^>]*>>`)
		metaMatches := metaPattern.FindSubmatch(data)

		if len(metaMatches) >= 1 {
			infoDictionary = string(metaMatches[0])
			// Remove the << and >> delimiters
			infoDictionary = strings.TrimPrefix(infoDictionary, "<<")
			infoDictionary = strings.TrimSuffix(infoDictionary, ">>")
		}
	}

	// Extract common metadata fields
	metadata.Title = extractStringField(infoDictionary, "Title")
	metadata.Author = extractStringField(infoDictionary, "Author")
	metadata.Subject = extractStringField(infoDictionary, "Subject")
	metadata.Keywords = extractStringField(infoDictionary, "Keywords")
	metadata.Creator = extractStringField(infoDictionary, "Creator")
	metadata.Producer = extractStringField(infoDictionary, "Producer")

	// Extract dates
	creationDate := extractStringField(infoDictionary, "CreationDate")
	if creationDate != "" {
		if date, err := parsePDFDate(creationDate); err == nil {
			metadata.CreatedDate = date
		}
		metadata.Properties["CreationDate"] = creationDate
	}

	modDate := extractStringField(infoDictionary, "ModDate")
	if modDate != "" {
		if date, err := parsePDFDate(modDate); err == nil {
			metadata.ModDate = date
		}
		metadata.Properties["ModificationDate"] = modDate
	}

	// Extract other fields that might be present
	otherFields := []string{"Trapped", "GTS_PDFXVersion", "GTS_PDFXConformance"}
	for _, field := range otherFields {
		value := extractStringField(infoDictionary, field)
		if value != "" {
			metadata.Properties[field] = value
		}
	}
}

// extractStringField extracts a string field from the Info dictionary
func extractStringField(dictionary, fieldName string) string {
	// Pattern for string fields: /FieldName (Value) or /FieldName (Val\)ue)
	pattern := regexp.MustCompile(`/` + fieldName + `\s*\(((?:\\.|[^\\()])*)\)`)
	matches := pattern.FindStringSubmatch(dictionary)

	if len(matches) >= 2 {
		// Unescape PDF string
		value := matches[1]
		value = strings.ReplaceAll(value, "\\)", ")")
		value = strings.ReplaceAll(value, "\\(", "(")
		value = strings.ReplaceAll(value, "\\\\", "\\")
		return value
	}

	// Try hex string format: /FieldName <HEXDATA>
	hexPattern := regexp.MustCompile(`/` + fieldName + `\s*<([0-9A-Fa-f]+)>`)
	hexMatches := hexPattern.FindStringSubmatch(dictionary)

	if len(hexMatches) >= 2 {
		// Convert hex to string (simplified)
		hexStr := hexMatches[1]
		var result strings.Builder

		for i := 0; i < len(hexStr); i += 2 {
			if i+1 < len(hexStr) {
				byteVal, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
				if err == nil {
					result.WriteByte(byte(byteVal))
				}
			}
		}

		return result.String()
	}

	// Try alternative format: /FieldName /Value
	altPattern := regexp.MustCompile(`/` + fieldName + `\s*/([^/\s<>()\[\]]+)`)
	altMatches := altPattern.FindStringSubmatch(dictionary)

	if len(altMatches) >= 2 {
		return altMatches[1]
	}

	// Try yet another format with quotes: /FieldName "Value"
	quotePattern := regexp.MustCompile(`/` + fieldName + `\s*"([^"]*)"`)
	quoteMatches := quotePattern.FindStringSubmatch(dictionary)

	if len(quoteMatches) >= 2 {
		return quoteMatches[1]
	}

	return ""
}

// countPages counts the number of pages in the PDF
func countPages(data []byte) int {
	// Look for /Type /Page entries
	pagePattern := regexp.MustCompile(`/Type\s*/Page[^s]`)
	matches := pagePattern.FindAllSubmatch(data, -1)

	if len(matches) > 0 {
		return len(matches)
	}

	// Alternative method: look for /Count in the Pages object
	countPattern := regexp.MustCompile(`/Count\s+(\d+)`)
	countMatches := countPattern.FindSubmatch(data)

	if len(countMatches) >= 2 {
		count, err := strconv.Atoi(string(countMatches[1]))
		if err == nil {
			return count
		}
	}

	return 0
}

// isEncrypted checks if the PDF is encrypted
func isEncrypted(data []byte) bool {
	// Look for /Encrypt dictionary
	encryptPattern := regexp.MustCompile(`/Encrypt\s+\d+\s+\d+\s+R`)
	return encryptPattern.Match(data)
}

// parsePDFDate parses a PDF date string
func parsePDFDate(dateStr string) (time.Time, error) {
	// PDF date format: D:YYYYMMDDHHmmSSOHH'mm'
	// where O is the offset direction (+ or -)

	// Remove the D: prefix if present
	dateStr = strings.TrimPrefix(dateStr, "D:")

	// Basic validation
	if len(dateStr) < 4 {
		return time.Time{}, fmt.Errorf("invalid date format")
	}

	// Extract components with defaults
	year := extractInt(dateStr, 0, 4, 0)
	month := extractInt(dateStr, 4, 2, 1)
	day := extractInt(dateStr, 6, 2, 1)
	hour := extractInt(dateStr, 8, 2, 0)
	minute := extractInt(dateStr, 10, 2, 0)
	second := extractInt(dateStr, 12, 2, 0)

	// Create the time
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)

	// Handle timezone if present
	if len(dateStr) >= 15 && (dateStr[14] == '+' || dateStr[14] == '-') {
		tzHour := extractInt(dateStr, 15, 2, 0)
		tzMinute := extractInt(dateStr, 18, 2, 0)

		// Create timezone offset
		tzOffset := tzHour*3600 + tzMinute*60
		if dateStr[14] == '-' {
			tzOffset = -tzOffset
		}

		// Apply timezone
		t = t.In(time.FixedZone("", tzOffset))
	}

	return t, nil
}

// extractXMPMetadata extracts metadata from XMP data in the PDF
func extractXMPMetadata(data []byte, metadata *Metadata) {
	// Look for XMP metadata
	xmpPattern := regexp.MustCompile(`<x:xmpmeta[^>]*>(.*?)</x:xmpmeta>`)
	xmpMatches := xmpPattern.FindSubmatch(data)

	if len(xmpMatches) < 2 {
		// Try alternative XMP pattern
		xmpPattern = regexp.MustCompile(`<xmp:CreatorTool>(.*?)</xmp:CreatorTool>`)
		xmpMatches = xmpPattern.FindSubmatch(data)
		if len(xmpMatches) >= 2 && metadata.Creator == "" {
			metadata.Creator = string(xmpMatches[1])
		}

		xmpPattern = regexp.MustCompile(`<pdf:Producer>(.*?)</pdf:Producer>`)
		xmpMatches = xmpPattern.FindSubmatch(data)
		if len(xmpMatches) >= 2 && metadata.Producer == "" {
			metadata.Producer = string(xmpMatches[1])
		}
		return
	}

	xmpData := string(xmpMatches[1])

	// Extract creator
	if metadata.Creator == "" {
		creatorPattern := regexp.MustCompile(`<xmp:CreatorTool>(.*?)</xmp:CreatorTool>`)
		creatorMatches := creatorPattern.FindStringSubmatch(xmpData)
		if len(creatorMatches) >= 2 {
			metadata.Creator = creatorMatches[1]
		}
	}

	// Extract producer
	if metadata.Producer == "" {
		producerPattern := regexp.MustCompile(`<pdf:Producer>(.*?)</pdf:Producer>`)
		producerMatches := producerPattern.FindStringSubmatch(xmpData)
		if len(producerMatches) >= 2 {
			metadata.Producer = producerMatches[1]
		}
	}
}

// containsNonPrintableChars checks if a string contains non-printable characters
func containsNonPrintableChars(s string) bool {
	if s == "" {
		return false
	}

	// Count non-printable characters
	nonPrintable := 0
	for _, r := range s {
		if r < 32 || r > 126 {
			nonPrintable++
		}
	}

	// If more than 20% of characters are non-printable, consider it malformed
	return float64(nonPrintable)/float64(len(s)) > 0.2
}

// extractInt extracts an integer from a string with bounds checking
func extractInt(s string, start, length, defaultVal int) int {
	if start+length <= len(s) {
		val, err := strconv.Atoi(s[start : start+length])
		if err == nil {
			return val
		}
	}
	return defaultVal
}

// extractDirectField searches for a field directly in the PDF content
func extractDirectField(data []byte, fieldName string) string {
	// Special case for TCPDF files
	if fieldName == "Producer" {
		// Try different TCPDF patterns
		tcpdfPatterns := []string{
			`TCPDF\s+([\d\.]+)\s+\(http://www\.tcpdf\.org\)`,
			`TCPDF\s*([\d\.]+)`,
			`Producer.*?TCPDF`,
			`tcpdf`,
		}

		for _, pattern := range tcpdfPatterns {
			tcpdfRegex := regexp.MustCompile(pattern)
			tcpdfMatches := tcpdfRegex.FindSubmatch(data)
			if len(tcpdfMatches) >= 2 {
				return "TCPDF " + string(tcpdfMatches[1]) + " (http://www.tcpdf.org)"
			} else if len(tcpdfMatches) >= 1 {
				return "TCPDF (http://www.tcpdf.org)"
			}
		}
	}

	// Try various patterns that might contain the field
	patterns := []string{
		// Standard PDF patterns
		`/` + fieldName + `\s*\(([^)]+)\)`,
		`/` + fieldName + `\s*\(([^)]*)\)`,
		`/` + fieldName + `\s*<([0-9A-Fa-f]+)>`,
		`/` + fieldName + `\s*/([^/\s<>()\[\]]+)`,
		`/` + fieldName + `\s*"([^"]*)"`,
		// Google Docs specific pattern - matches `/Producer (Skia/PDF m138 Google Docs Renderer)>>`
		`/` + fieldName + `\s*\(([^)]+)\)>>`,
		// Alternative patterns
		`\(` + fieldName + `\)\s*\(([^)]*)\)`,
		`\(` + fieldName + `\)\s*<([0-9A-Fa-f]+)>`,
		`\(` + fieldName + `\)\s*/([^/\s<>()\[\]]+)`,
		`\(` + fieldName + `\)\s*"([^"]*)"`,
		`<` + fieldName + `>\s*\(([^)]*)\)`,
		`<` + fieldName + `>\s*<([0-9A-Fa-f]+)>`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindSubmatch(data)

		if os.Getenv("FERRET_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "[DEBUG] PDF Metadata: Trying pattern '%s' for field '%s'\n", pattern, fieldName)
		}

		if len(matches) >= 2 {
			value := string(matches[1])

			if os.Getenv("FERRET_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "[DEBUG] PDF Metadata: Pattern matched! Found value: '%s'\n", value)
			}

			// If it's a hex string, decode it
			if strings.HasPrefix(pattern, `/`+fieldName+`\s*<`) {
				var result strings.Builder
				hexStr := value

				for i := 0; i < len(hexStr); i += 2 {
					if i+1 < len(hexStr) {
						byteVal, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
						if err == nil {
							result.WriteByte(byte(byteVal))
						}
					}
				}

				value = result.String()
			}

			return value
		}
	}

	if os.Getenv("FERRET_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[DEBUG] PDF Metadata: No patterns matched for field '%s'\n", fieldName)
	}

	return ""
}
