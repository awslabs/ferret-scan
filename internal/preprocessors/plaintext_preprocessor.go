// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// PlainTextPreprocessor handles plain text files by passing their content through
// This ensures text files are processed through the same pipeline as other file types
type PlainTextPreprocessor struct {
	observer        observability.Observer
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
func (ptp *PlainTextPreprocessor) SetObserver(observer observability.Observer) {
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

	// A container extension whose BYTES are text: claim it as text.
	//
	// Routing picks preprocessors by extension, so a file named .docx went to the
	// Office extractor alone. When the bytes are not a ZIP that extractor fails,
	// no other preprocessor had claimed the file, and the scan reported zero
	// findings. Since only reported findings are redacted, everything in such a
	// file was left in cleartext. Measured on identical bytes holding an SSN:
	// 1 finding as .txt, 0 as .doc / .docx / .xlsx.
	//
	// It needs no attacker. An export pipeline that writes CSV or HTML and labels
	// it .doc, a hand-renamed file, or a truncated download all land here. As a
	// pre-commit bypass it is cheaper still: rename the file.
	//
	// This is deliberately a CLAIM, not a fallback. The router already runs every
	// preprocessor that claims a file and combines the successes, so on a real
	// container the Office extractor still wins and this contributes nothing (a
	// real .docx is a ZIP, so isTextFile rejects it on the binary sniff). Adding a
	// claim therefore recovers the mislabelled case without a second code path,
	// and without changing anything for well-formed documents.
	if containerExtensions[ext] {
		return ptp.isTextFile(filePath)
	}

	// An extension no preprocessor claims by name: decide on the BYTES.
	//
	// This is the same argument as the container case above, in its weakest form.
	// A .swift or .kt file is not mislabelled and needs no attacker — it is simply
	// a text format nobody enumerated. The allowlist above holds ~45 extensions and
	// will always lag the set of text formats that exist: .swift, .kt, .kts, .tf,
	// .tfvars, .properties, .jsx, .tsx, .dart, .m, .mm, .proto, .vue and .gradle
	// were all absent, so a Terraform variables file or a Java .properties — two of
	// the likeliest places on disk to find a credential — scanned as zero findings.
	//
	// Worse, the router's own gate already decides this by sniffing:
	// CanProcessFile answers `true, "Text file"` for a .swift file, and then
	// processFileInternal finds no capable preprocessor and fails the file. The
	// scan reports "No matches found" and exit 0 over a file it never read. That
	// gate-versus-preprocessor drift is the bug this closes; deciding here on the
	// same signal the gate uses is what keeps the two in agreement.
	//
	// Deliberately NOT claimed: extensions belonging to the image, video and audio
	// metadata extractors. Those route to a preprocessor that handles them, so they
	// are not the failing case, and claiming them would change behavior for every
	// media file rather than recovering an unscanned one.
	if !claimedByAnotherPreprocessor(ext) {
		return ptp.isTextFile(filePath)
	}

	return false
}

// mediaExtValidator answers which extensions the media metadata extractors handle.
// It is the same validator the router's routing gate delegates to, so this
// preprocessor and the gate cannot drift about who owns an extension.
var mediaExtValidator = NewFileExtensionValidator()

// claimedByAnotherPreprocessor reports whether ext routes to a preprocessor other
// than this one on name alone.
//
// Office and PDF are excluded from the check because containerExtensions has
// already handled them above with a sniff: they are claimed by another
// preprocessor AND claimable here when the bytes turn out to be text. What
// remains are the media types, which this preprocessor should not claim.
//
// .svg is the one entry here whose bytes ARE text, and it is the reason IsVectorFile
// exists. Sniffing decided it, so this preprocessor claimed it and handed the whole
// drawing -- path coordinates and base64 rasters included -- to every validator:
// measured at 9046dae, 1,313 findings on a 75KB SVG of integer-coordinate glyph paths,
// 817 of them PHONE. The router runs EVERY claiming preprocessor and concatenates the
// successes, so adding an SVG-aware extractor without withdrawing this claim would
// have scanned both texts and changed nothing. Unlike the image and audio cases, the
// withdrawal here has no fallback: a file named .svg that is NOT an SVG is recovered
// by the SVG branch itself, which scans the raw bytes when the root element is not
// <svg> (see TextPreprocessor.processSVG). Verified with a plain text file holding an
// SSN renamed to .svg: 2 findings before and after.
func claimedByAnotherPreprocessor(ext string) bool {
	// The Is*File predicates run filepath.Ext internally, which returns "" for a
	// bare ".heic", so give them a filename to inspect.
	probe := "f" + ext
	return mediaExtValidator.IsImageFile(probe) ||
		mediaExtValidator.IsVideoFile(probe) ||
		mediaExtValidator.IsAudioFile(probe) ||
		mediaExtValidator.IsVectorFile(probe)
}

// containerExtensions are the extensions whose files are normally binary
// containers, and which therefore route away from this preprocessor on name alone.
// Each is admitted only after isTextFile inspects the actual bytes.
//
// PDF is included for the same reason as the rest: a text file named .pdf is
// exactly as unscannable as one named .docx, and the sniff is what decides.
// pdfMagic is the header every PDF is required to begin with (PDF 1.7 §7.5.2). It is the
// discriminator LooksLikeText uses, because a PDF's header is ASCII and a printability sniff
// therefore cannot tell one from a text file.
var pdfMagic = []byte("%PDF-")

var containerExtensions = map[string]bool{
	".docx": true, ".xlsx": true, ".pptx": true,
	".docm": true, ".xlsm": true, ".pptm": true,
	".doc": true, ".xls": true, ".ppt": true,
	".odt": true, ".ods": true, ".odp": true,
	".ott": true, ".ots": true, ".otp": true,
	".pdf": true,
}

// Process extracts text content from the file
func (ptp *PlainTextPreprocessor) Process(filePath string) (*ProcessedContent, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if ptp.observer != nil {
		finishTiming = ptp.observer.StartTiming("plaintext_preprocessor", "process_file", filePath)
		if ptp.observer.Debug() != nil {
			finishStep = ptp.observer.Debug().StartStep("plaintext_preprocessor", "process_file", filePath)
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

// readTextFile reads the content of a text file with proper encoding handling.
// The file is opened once and read through the same handle (previously the
// function opened it twice — once via os.Open for stat, once via os.ReadFile
// for the content — which doubled the syscall count and introduced a TOCTOU
// window where the file could change between the size check and the read).
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

	// Read through the same handle and cap at maxSize as a defense-in-depth
	// guard against the file growing between Stat and ReadAll.
	fileContent, err := io.ReadAll(io.LimitReader(file, maxSize))
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Decode transcodable encodings (UTF-16 LE/BE with or without BOM,
	// BOM'd UTF-8) to UTF-8 before scanning; validators only speak UTF-8.
	// Windows tooling (PowerShell 5 Out-File, .reg exports) writes UTF-16LE,
	// which previously reached the validators as null-riddled bytes no
	// pattern could match even when the sniff let the file through.
	var content string
	if decoded, ok := DecodeToUTF8(fileContent, DetectTextEncoding(fileContent)); ok {
		content = decoded
	} else {
		content = string(fileContent)
	}

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

	// Null-byte and ratio gating live inside LooksLikeText: the null check
	// must come AFTER encoding detection, because UTF-16 text has a null in
	// every other byte by construction — the old order made every UTF-16
	// file (PowerShell Out-File, .reg exports) binary by definition.
	return LooksLikeText(buffer)
}

// LooksLikeText reports whether buf (a null-free prefix of the file) is text.
// Exported because the FileRouter maintains a second sniff site (isTextFile in
// internal/router) that must apply identical semantics — the two copies of the
// old byte-ratio heuristic drifted into the same UTF-8 bug independently.
//
// UTF-8 first: every byte of a multi-byte UTF-8 sequence is >= 0x80, so the
// old ASCII-printable ratio counted EVERY non-ASCII character against the
// file. A short line with a ™ (3 bytes) or an em-dash, a name with accents,
// or any non-Latin-script document fell below the 95% bar and the file was
// silently skipped as "binary" — a recall hole across ALL validators in file
// mode (stdin mode never sniffs, which is how the gap hid). Genuinely binary
// data essentially never forms long runs of valid UTF-8, so utf8.Valid is
// both the safer and the stricter signal; the ASCII-ratio heuristic remains
// only as the fallback for legacy single-byte encodings (Latin-1 etc.),
// which are not valid UTF-8 but are still text someone may want scanned.
func LooksLikeText(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}

	// A format whose header is ASCII BY SPECIFICATION cannot be judged by a printability
	// sniff, so it is judged by its magic bytes instead.
	//
	// PDF is the only such container in this tree. Every PDF opens "%PDF-1.x", and one written
	// by a browser or by Office follows that with a large ASCII metadata dictionary (/Title,
	// /Creator, /Producer), so the first 512 bytes carry no NUL and are ~100% printable — and
	// the tests below therefore returned TRUE for a file that is mostly compressed streams.
	//
	// Measured on one real 957KB PDF: the plaintext preprocessor claimed it and handed 533,976
	// characters of RAW PDF SOURCE to every validator, 33% of it non-printable. That produced
	// 200 TWITTER findings at HIGH 100 on stream bytes, 41 PHONE findings on xref table offsets
	// ("0000956276" is a byte offset, not a number anyone can call), and INTELLECTUAL_PROPERTY
	// on stray 0xA9/0xAE bytes. Across 10 real PDFs the finding count tracked the non-printable
	// share of the extracted text almost exactly, and the three whose extraction was clean
	// produced ZERO (#419).
	//
	// The other container extensions are safe and always were, though for two different
	// reasons. ZIP fails on its magic alone, because PK\x03\x04 carries NUL bytes. OLE's magic
	// does NOT — \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 has no NUL and every byte >= 0xA0
	// counts as printable in the fallback below — so .doc/.xls/.ppt are rejected by the
	// NUL-filled header REGION that follows their magic rather than by a signature. Verified
	// against real files of all six types; see TestLooksLikeText_WhyOnlyPDFNeedsAMagicCheck,
	// which pins the distinction so a future NUL-free container variant is not assumed safe.
	//
	// This does NOT withdraw #271. A text file merely NAMED .pdf does not carry the magic, so
	// it still sniffs as text and is still scanned and redacted — that mislabelled case is what
	// #271 exists for, and it keeps working. Nor does it stop PDFs being scanned: the router
	// accepts them as "Binary document" (isBinaryDocument -> IsPDFFile) before this sniff is
	// ever consulted, and the PDF text and metadata extractors have their own parsers.
	if bytes.HasPrefix(buf, pdfMagic) {
		return false
	}

	// Transcodable encodings first: UTF-16 (BOM'd or heuristically detected)
	// contains a null byte per ASCII character, so it can never survive a
	// pre-decode null-byte gate or the ratio tests below — decode the sniff
	// window and judge the decoded text instead. PowerShell 5 Out-File,
	// .reg exports, and plenty of Windows logs are UTF-16LE.
	if decoded, ok := utf8OrDecoded(buf); ok {
		return looksLikeDecodedText(decoded)
	}

	// Not a recognized transcodable encoding: any null byte means binary
	// (the classic gate, now applied only after UTF-16 has had its chance).
	for _, b := range buf {
		if b == 0 {
			return false
		}
	}

	// The 512-byte read may split a multi-byte sequence at the end; trim up
	// to utf8.UTFMax-1 trailing continuation/start bytes of an incomplete
	// rune so a truncated final character doesn't fail validation.
	trimmed := buf
	for i := 0; i < utf8.UTFMax-1 && len(trimmed) > 0; i++ {
		if r, _ := utf8.DecodeLastRune(trimmed); r != utf8.RuneError {
			break
		}
		trimmed = trimmed[:len(trimmed)-1]
	}
	if len(trimmed) > 0 && utf8.Valid(trimmed) {
		return looksLikeDecodedText(string(trimmed))
	}

	// Not valid UTF-8: fall back to a legacy single-byte-encoding judgment.
	//
	// Floor (identical to the historical rule): ASCII printables, tab/CR/LF,
	// and ALL bytes >= 0xA0 count as printable against a 95% bar. Bytes at
	// 0xA0+ are where every ISO-8859-x / Windows-125x codepage puts its
	// letters — Cyrillic cp1251, Greek cp1253, Hebrew cp1255, Arabic cp1256
	// prose is majority high-byte, and an "ASCII majority" requirement here
	// silently skipped all of it (proven by adversarial verification:
	// Russian cp1251 with an embedded email went from 2 findings to a
	// silent skip). Never require ASCII dominance of legacy text.
	//
	// Extension (the cp1252 fix): Windows-1252 also places typographic
	// characters — curly quotes, en/em dashes, ellipsis, ™ — in 0x80-0x9F.
	// Those count as printable ONLY when the document is ASCII-majority,
	// which is what a smart-quoted Word/Outlook export actually looks like.
	// Gating the 0x80-0x9F allowance (rather than granting it wholesale)
	// keeps structureless high-byte binary rejected: random bytes spanning
	// 0x80-0xFF are not ASCII-majority, so their 0x80-0x9F content stays
	// unprintable and drags them under the bar, exactly as before.
	asciiCount, high160Count, typo1252Count := 0, 0, 0
	for _, b := range buf {
		switch {
		case (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13:
			asciiCount++
		case b >= 160:
			high160Count++
		case b >= 128:
			typo1252Count++
		}
	}
	n := float64(len(buf))
	printable := asciiCount + high160Count
	if float64(asciiCount)/n > 0.5 {
		printable += typo1252Count
	}
	return float64(printable)/n > 0.95
}

// looksLikeDecodedText judges already-decoded (valid UTF-8) text: accept
// unless dominated by control characters — binary formats that happen to be
// UTF-8-clean (some font/archive headers) survive the null-byte gates.
func looksLikeDecodedText(s string) bool {
	control, total := 0, 0
	for _, r := range s {
		total++
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			control++
		}
	}
	return total > 0 && float64(control)/float64(total) < 0.05
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

	if ptp.observer != nil && ptp.observer.Debug() != nil {
		ptp.observer.Debug().LogDetail("plaintext_preprocessor",
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
