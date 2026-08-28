// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/position"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// OfficeRedactor implements redaction for Microsoft Office documents using unified ZIP/XML approach
type OfficeRedactor struct {
	// observer handles observability and metrics
	observer observability.Observer

	// outputManager handles file system operations
	outputManager *redactors.OutputStructureManager

	// positionCorrelator handles position correlation between extracted and original text
	positionCorrelator position.PositionCorrelator

	// enablePositionCorrelation controls whether to use position correlation
	enablePositionCorrelation bool

	// confidenceThreshold is the minimum confidence required for position-based redaction
	confidenceThreshold float64

	// fallbackToSimple controls whether to fall back to simple text replacement on correlation failure
	fallbackToSimple bool

	// embeddedRedactor redacts files found INSIDE this document — an embedded
	// .docx, a legacy .doc, an image whose EXIF holds a finding.
	//
	// An interface, injected, rather than the concrete RedactionManager: the
	// manager knows every redactor and a single format redactor must not. nil is a
	// supported state and means "do not descend", which keeps this type usable
	// standalone in tests and from callers that never registered a manager. When it
	// is nil and an embedded part holds a reported value, that is DISCLOSED rather
	// than passed over — see redactEmbeddedParts.
	embeddedRedactor redactors.EmbeddedRedactor
}

// OfficeDocumentType represents the type of Office document
type OfficeDocumentType int

const (
	// DocumentTypeUnknown represents an unknown document type
	DocumentTypeUnknown OfficeDocumentType = iota
	// DocumentTypeDOCX represents a Word document
	DocumentTypeDOCX
	// DocumentTypeXLSX represents an Excel spreadsheet
	DocumentTypeXLSX
	// DocumentTypePPTX represents a PowerPoint presentation
	DocumentTypePPTX
	// DocumentTypeODF represents an OpenDocument package — .odt/.ods/.odp and their
	// .ott/.ots/.otp template forms.
	//
	// ONE type for all six, unlike the OOXML side which needs three, because ODF puts
	// body text in `content.xml` and metadata in `meta.xml` whatever the document is:
	// a spreadsheet cell is `<table:table-cell><text:p>` and a slide's text is
	// `<draw:frame><text:p>`, so the same part names and the same element vocabulary
	// cover text, spreadsheet and presentation. OOXML by contrast renames both the
	// parts (word/ vs xl/ vs ppt/) and the text element (w:t vs t/v vs a:t).
	DocumentTypeODF
)

// Decompression-bomb bounds for extractOfficeContent. An Office file is a ZIP,
// and the only upstream gate is on-disk (compressed) size — a small archive can
// declare gigabytes of uncompressed content. These caps bound what a single
// document can expand to in memory. They mirror the 50MB/entry cap already used
// by the text and metadata extractors; the redactor was the one reader still
// doing an unbounded io.ReadAll (security finding HIGH-4).
const (
	// maxOfficeEntryBytes bounds a single decompressed zip entry.
	maxOfficeEntryBytes = 50 * 1024 * 1024 // 50MB
	// maxOfficeTotalBytes bounds the cumulative decompressed size across all
	// entries in one document.
	//
	// Aliased to embedded.BudgetBytes rather than repeating the number: the read
	// side charges the same 200MB against the same archive, and two independent
	// literals would let the write side quietly diverge from the read side. Both
	// are per-container — see BudgetBytes for what that does and does not bound.
	maxOfficeTotalBytes = embedded.BudgetBytes
)

// String returns the string representation of the document type
func (dt OfficeDocumentType) String() string {
	switch dt {
	case DocumentTypeDOCX:
		return "docx"
	case DocumentTypeXLSX:
		return "xlsx"
	case DocumentTypePPTX:
		return "pptx"
	case DocumentTypeODF:
		return "odf"
	default:
		return "unknown"
	}
}

// NewOfficeRedactor creates a new OfficeRedactor
func NewOfficeRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *OfficeRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	return &OfficeRedactor{
		observer:                  observer,
		outputManager:             outputManager,
		positionCorrelator:        position.NewDefaultPositionCorrelator(),
		enablePositionCorrelation: true,
		confidenceThreshold:       0.8,
		fallbackToSimple:          true,
	}
}

// SetEmbeddedRedactor injects the component used to redact files embedded inside
// this document. Called once at construction by internal/core, after every redactor
// is registered, because the value is the manager that owns them all.
func (or *OfficeRedactor) SetEmbeddedRedactor(er redactors.EmbeddedRedactor) {
	or.embeddedRedactor = er
}

// GetName returns the name of the redactor
func (or *OfficeRedactor) GetName() string {
	return "office_redactor"
}

// GetSupportedTypes returns the file types this redactor can handle
func (or *OfficeRedactor) GetSupportedTypes() []string {
	// The macro-enabled forms are included because redactors/manager.go already routes
	// them here, and this list disagreeing with that routing is how a caller was told a
	// type was unsupported by the very redactor it had been handed to (#497).
	return []string{
		"docx", ".docx", "xlsx", ".xlsx", "pptx", ".pptx",
		"docm", ".docm", "xlsm", ".xlsm", "pptm", ".pptm",
		// OpenDocument, including the template forms. Every ODF finding used to be
		// reported and then left in cleartext — "no redactor registered for file type:
		// .odt" — which is a disclosed leak, not a silent one, but a leak (#514). The
		// scanner reads all six (#515, #528), so all six are claimed here.
		"odt", ".odt", "ods", ".ods", "odp", ".odp",
		"ott", ".ott", "ots", ".ots", "otp", ".otp",
	}
}

// GetSupportedStrategies returns the redaction strategies this redactor supports
func (or *OfficeRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// RedactDocument creates a redacted copy of the Office document at outputPath
func (or *OfficeRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if or.observer != nil {
		finishTiming = or.observer.StartTiming("office_redactor", "redact_document", originalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	startTime := time.Now()

	// Detect document type
	docType, err := or.detectDocumentType(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect document type: %w", err)
	}

	// Extract ZIP contents and text
	zipContents, extractedText, textPositions, children, err := or.extractOfficeContent(originalPath, docType)
	if err != nil {
		return nil, fmt.Errorf("failed to extract office content: %w", err)
	}

	// Normalize the match set ONCE, here, before every consumer of Match.Text.
	//
	// Both of these rewrite matches whose Text does not occur in the document:
	// ExpandClusterMatches replaces a SOCIAL_MEDIA_CLUSTER with the real spans it
	// collapsed, and RestoreBoundedMatchText restores a display-truncated consolidated
	// text to its full line.
	//
	// They used to live inside redactOfficeContent, which took `matches` as a PARAMETER —
	// so reassigning it there normalized only that function's local slice. This function
	// then handed the ORIGINAL, un-normalized slice to redactEmbeddedParts below, and that
	// is a second consumer of Match.Text: it builds the residue value set the embedded
	// dispatch gate and the post-redaction verification both use.
	//
	// The consequence was a leak, measured on a .docx holding two clustered handles in its
	// body AND in an embedded inner.docx:
	//
	//	2 HIGH findings reported, rc=0, one file written
	//	body:  handles removed
	//	inner: BOTH handles still present verbatim
	//
	// embeddedValueSet was built from the cluster's rendered summary — a string in no
	// part's bytes — so partHoldsValue proved "absence" for every part, the part holding
	// the real handles was never dispatched, and the fail-closed unredacted-part refusal
	// that exists to prevent exactly this never fired because its residue check was
	// looking for the same absent string. A non-clustered SSN in the same fixture is
	// correctly removed from the embedded copy, which is what isolates the cause.
	//
	// Normalizing before both consumers is the fix. redactOfficeContent has exactly one
	// caller (immediately below), so nothing else depended on it doing this itself.
	matches = redactors.ExpandClusterMatches(matches)
	matches = redactors.RestoreBoundedMatchText(matches)

	// Perform redaction
	redactionMap, modifiedContents, err := or.redactOfficeContent(zipContents, extractedText, textPositions, matches, strategy, docType)
	if err != nil {
		return nil, fmt.Errorf("failed to redact office content: %w", err)
	}

	// Redact files embedded INSIDE this document, each by the redactor that owns
	// its format, and store the results back at their own entry names.
	embeddedMap, unredacted := or.redactEmbeddedParts(originalPath, modifiedContents, children, matches, strategy)
	redactionMap = append(redactionMap, embeddedMap...)

	// Refuse to write a document that still holds a reported value.
	//
	// FAIL CLOSED, deliberately, and this is the crux of the fix. The alternative --
	// write the file and warn -- puts a document containing an SSN into a directory
	// named "redacted", which is the artefact a user forwards. The same policy
	// already applies one level up: when the image or PDF redactor cannot handle a
	// standalone file, no output is written and the run reports
	// "redaction incomplete ... the original values remain in cleartext". Writing
	// here while refusing there would make the tool's guarantee depend on whether
	// the value happened to be nested.
	//
	// The blast radius is bounded by design: redactEmbeddedParts only reports a part
	// when a reported value is actually still present in it (or when the format is
	// one whose bytes cannot be inspected, where absence cannot be established). An
	// embedded image that merely fails to decode, holding nothing, does not stop the
	// container from being written.
	if len(unredacted) > 0 {
		// "could not be shown free of reported values" rather than "still contain reported
		// values". Both cases end here and only one of them is the latter: a part that could
		// not be INSPECTED holds no value we know of, precisely because we could not look —
		// see embedded.ContentInspectable. Claiming it contains a reported value would be a
		// true refusal under a false heading, and the per-part reason beside it already says
		// which case each one is.
		return nil, fmt.Errorf(
			"refusing to write %s: %d embedded part(s) could not be shown free of reported values: %s",
			filepath.Base(outputPath), len(unredacted), embeddedFailureSummary(unredacted))
	}

	// Refuse to write a document whose OWN parts still hold a reported value.
	//
	// The embedded refusal above covers children only. The parent document was never
	// checked at all, which is what let the entity-escaping defect attest success:
	// applyPendingRedactions could no-op for a value and RedactDocument still returned
	// Success with failed_redactions:0, because nothing ever asked whether the value
	// was gone. A missed rewrite is now a refusal rather than a false attestation, on
	// the same fail-closed policy and for the same reason — the artefact a user
	// forwards must not be a document containing an SSN in a directory named
	// "redacted".
	if residue := parentPartResidue(modifiedContents, matches); len(residue) > 0 {
		// TYPES, never the values. This message reaches stderr and every machine format
		// with no --show-match, so listing the residual values would publish the exact
		// data the refusal exists to protect — the same rule that keeps a matched value
		// out of a validator's debug log, and out of #367's failed-extraction line.
		// The count and the types are what an operator acts on.
		return nil, fmt.Errorf(
			"refusing to write %s: %d reported value(s) still present in the document's own parts (types: %s)",
			filepath.Base(outputPath), len(residue), strings.Join(residueTypes(residue), ", "))
	}

	// Repackage ZIP with modified contents
	err = or.repackageOfficeDocument(modifiedContents, outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to repackage office document: %w", err)
	}

	// Calculate overall confidence
	confidence := or.calculateOverallConfidence(redactionMap)

	processingTime := time.Since(startTime)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     redactionMap,
		ProcessingTime:   processingTime,
		Confidence:       confidence,
		Error:            nil,
	}, nil
}

// detectDocumentType detects the type of Office document by examining the ZIP contents
func (or *OfficeRedactor) detectDocumentType(filePath string) (OfficeDocumentType, error) {
	// First, try to detect by file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".docx", ".docm":
		return DocumentTypeDOCX, nil
	case ".xlsx", ".xlsm":
		return DocumentTypeXLSX, nil
	case ".pptx", ".pptm":
		return DocumentTypePPTX, nil
	case ".odt", ".ods", ".odp", ".ott", ".ots", ".otp":
		// All six share one type — see DocumentTypeODF. The template forms are here
		// because the scanner reads them (#528) and every value it reports from one is
		// in the same two parts as a non-template package.
		return DocumentTypeODF, nil
	}

	// If extension is not conclusive, examine ZIP contents
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return DocumentTypeUnknown, fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer reader.Close()

	// ODF declares its type in a `mimetype` entry rather than in [Content_Types].xml, so
	// it is checked in the same pass. ODF 1.2 §3.3 requires that entry to be first and
	// STORED, which is what makes a byte sniff of an ODF package work at all.
	for _, file := range reader.File {
		if file.Name != "mimetype" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, 256))
		_ = rc.Close()
		if err != nil {
			continue
		}
		if strings.HasPrefix(string(content), "application/vnd.oasis.opendocument.") {
			return DocumentTypeODF, nil
		}
	}

	// Look for content types file
	for _, file := range reader.File {
		if file.Name == "[Content_Types].xml" {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				continue
			}

			contentStr := string(content)
			if strings.Contains(contentStr, "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main") {
				return DocumentTypeDOCX, nil
			}
			if strings.Contains(contentStr, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main") {
				return DocumentTypeXLSX, nil
			}
			if strings.Contains(contentStr, "application/vnd.openxmlformats-officedocument.presentationml.presentation.main") {
				return DocumentTypePPTX, nil
			}
		}
	}

	return DocumentTypeUnknown, fmt.Errorf("unable to determine document type")
}

// OfficeZipContents represents the contents of an Office document ZIP file
type OfficeZipContents struct {
	Files map[string][]byte // filename -> content

	// Order is the entry order of the ORIGINAL package, captured while reading
	// it. Repackaging replays this order instead of ranging Files, which is a
	// Go map and therefore randomized: without it the redacted .docx/.xlsx/.pptx
	// was written with its parts in a different sequence on every run, so the
	// same input produced a different output file each time — no byte
	// reproducibility for anything that hashes or diffs the artifact. It also
	// meant [Content_Types].xml frequently landed after the content parts, and
	// OPC requires it to be the first entry in the package.
	Order []string
}

// addFile records a package entry, preserving first-seen order.
func (c *OfficeZipContents) addFile(name string, content []byte) {
	if _, exists := c.Files[name]; !exists {
		c.Order = append(c.Order, name)
	}
	c.Files[name] = content
}

// orderedNames returns the entry names in the original package order, with any
// entry that is present in Files but absent from Order appended in sorted order.
// The fallback keeps output deterministic even if a future code path adds a part
// without going through addFile.
func (c *OfficeZipContents) orderedNames() []string {
	names := make([]string, 0, len(c.Files))
	seen := make(map[string]bool, len(c.Files))
	for _, name := range c.Order {
		if _, exists := c.Files[name]; exists && !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	if len(names) == len(c.Files) {
		return names
	}

	extra := make([]string, 0, len(c.Files)-len(names))
	for name := range c.Files {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	return append(names, extra...)
}

// OfficeTextPosition represents text position information in an Office document
type OfficeTextPosition struct {
	FileName       string            // XML file containing the text
	XMLPath        string            // XPath-like location in XML
	DocumentOffset int               // Character offset within the entire document
	Text           string            // The actual text
	ElementInfo    OfficeElementInfo // XML element information
}

// OfficeElementInfo contains XML element information for Office text
type OfficeElementInfo struct {
	ElementName string            // XML element name (e.g., "w:t", "t", "a:t")
	Attributes  map[string]string // Element attributes
	ParentPath  string            // Path to parent element
}

// extractOfficeContent extracts ZIP contents and text from an Office document
func (or *OfficeRedactor) extractOfficeContent(filePath string, docType OfficeDocumentType) (*OfficeZipContents, string, []OfficeTextPosition, []embeddedChild, error) {
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, "", nil, nil, fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer reader.Close()

	zipContents := &OfficeZipContents{
		Files: make(map[string][]byte, len(reader.File)),
		Order: make([]string, 0, len(reader.File)),
	}

	var extractedText strings.Builder
	var textPositions []OfficeTextPosition
	var totalDecompressed int64
	// children are embedded files to be redacted in their own right, in source
	// order so the redacted output is reproducible.
	var children []embeddedChild

	// Extract all files from ZIP
	for _, file := range reader.File {
		// Reject before decompressing when the entry declares a size over the
		// per-entry cap. This is the cheap first line of defense against a
		// decompression bomb (a tiny compressed entry claiming multi-GB output).
		if file.UncompressedSize64 > maxOfficeEntryBytes {
			return nil, "", nil, nil, fmt.Errorf("office entry %q declares %d bytes, exceeding the %d cap (possible decompression bomb)",
				file.Name, file.UncompressedSize64, maxOfficeEntryBytes)
		}

		rc, err := file.Open()
		if err != nil {
			or.logEvent("file_extraction_failed", false, map[string]interface{}{
				"file_name": file.Name,
				"error":     err.Error(),
			})
			continue
		}

		// Read at most one byte past the cap so a lying declared size (or a
		// stored/zip64 entry) is still caught by the actual decompressed length.
		content, err := io.ReadAll(io.LimitReader(rc, maxOfficeEntryBytes+1))
		rc.Close()
		if err != nil {
			or.logEvent("file_read_failed", false, map[string]interface{}{
				"file_name": file.Name,
				"error":     err.Error(),
			})
			continue
		}
		// The redactor repackages exactly what it reads, so a truncated entry
		// would silently corrupt the redacted output — fail closed instead.
		if int64(len(content)) > maxOfficeEntryBytes {
			return nil, "", nil, nil, fmt.Errorf("office entry %q exceeds the %d per-entry decompression cap (possible bomb)",
				file.Name, maxOfficeEntryBytes)
		}
		totalDecompressed += int64(len(content))
		if totalDecompressed > maxOfficeTotalBytes {
			return nil, "", nil, nil, fmt.Errorf("office document exceeds the %d cumulative decompression cap (possible bomb)",
				maxOfficeTotalBytes)
		}

		// Record the entry with its position in the source package, so the
		// repackaged document is written in the same order.
		zipContents.addFile(file.Name, content)

		// Record an embedded file for separate redaction, rather than trying to
		// treat it as text of this document.
		//
		// Its text is deliberately NOT folded into extractedText. An earlier attempt
		// did exactly that and then rewrote the value inside the nested package with
		// a byte substitution. That works for an embedded .docx and cannot work for
		// an embedded JPEG, because removing an SSN from EXIF is not a string replace
		// in a zip member -- measured, the .docx case was fixed and the image case
		// still shipped the SSN in cleartext. Handing the whole part to the redactor
		// that owns its format covers both, plus legacy OLE and PDF, with one loop.
		if embedded.IsPartPath(file.Name) && !embedded.SkipTextPipeline(file.Name) {
			children = append(children, embeddedChild{name: file.Name, content: content})
			continue
		}

		// Extract text from relevant XML files
		if or.isTextContainingFile(file.Name, docType) {
			fileText, filePositions, err := or.extractTextFromXML(file.Name, content, docType, extractedText.Len())
			if err != nil {
				or.logEvent("text_extraction_failed", false, map[string]interface{}{
					"file_name": file.Name,
					"error":     err.Error(),
				})
				continue
			}

			extractedText.WriteString(fileText)
			textPositions = append(textPositions, filePositions...)
		}
	}

	return zipContents, extractedText.String(), textPositions, children, nil
}

// isTextContainingFile determines if a ZIP file contains text content based on document type.
//
// Matching is case-INSENSITIVE because a zip entry name is producer-controlled data and
// nothing makes the conventional spelling normative. This mirrors the extractor's part
// selection, and it has to: the extractor finds the text, the redactor rewrites it, and
// if only one of them recognizes a part then the tool reports a finding it cannot
// redact. Measured before this change, on a .docx whose body part was named
// word/Document.xml: the SSN and card were detected (4 findings) yet both survived
// --enable-redaction in cleartext inside the rewritten file, because this predicate's
// strings.Contains(fileName, "document") is case-sensitive and never matched. A
// reported-but-unredacted value is the same leak as an undetected one, dressed as a
// success.
// isDocPropsPart reports whether name is an OOXML document-properties part.
// name must already be lower-cased.
//
// docProps/core.xml holds the Dublin Core properties (creator, title, subject,
// keywords, lastModifiedBy); docProps/app.xml holds the extended ones (Company,
// Manager, Application, Template); docProps/custom.xml holds author-defined
// properties. All three are author-controlled free text and all three are
// scanned, so all three must be redactable.
func isDocPropsPart(name string) bool {
	return strings.HasPrefix(name, "docprops/") && strings.HasSuffix(name, ".xml")
}

func (or *OfficeRedactor) isTextContainingFile(fileName string, docType OfficeDocumentType) bool {
	name := strings.ToLower(fileName)
	if !strings.HasSuffix(name, ".xml") {
		return false
	}

	// Document properties, for every Office format. These carry author names,
	// titles, keywords, company, manager and the template path — values the
	// scanner reports as AUTHOR_INFO, COMPANY_INFO, TEMPLATE_INFO and friends.
	//
	// They were unreachable before: each case below requires a body-part prefix
	// ("word/", "xl/worksheets/", "ppt/slides/"), so docProps/* returned false and
	// the redactor never rewrote it. The effect was that metadata findings were
	// REPORTED and never REMOVED — the tool named a value, wrote a "redacted"
	// copy, and left that value in cleartext inside docProps/core.xml. Measured
	// across the golden container corpus: 10 reported findings survived, every one
	// of them in docProps/core.xml, while every body part redacted correctly.
	//
	// This is checked before the per-format switch because the part name is
	// identical in DOCX, XLSX and PPTX.
	if isDocPropsPart(name) {
		return true
	}

	switch docType {
	case DocumentTypeDOCX:
		// Word: the main document plus the parts that carry user-visible prose.
		// "main" is included alongside "document" because a producer may name the
		// body part word/main.xml; the extractor accepts it, so the redactor must.
		if !strings.HasPrefix(name, "word/") {
			return false
		}
		for _, part := range []string{"document", "main", "header", "footer", "footnote", "endnote", "comment"} {
			if strings.Contains(name, part) {
				return true
			}
		}
		return false

	case DocumentTypeXLSX:
		// Excel: worksheets and the shared string table.
		return strings.HasPrefix(name, "xl/worksheets/") || name == "xl/sharedstrings.xml"

	case DocumentTypePPTX:
		// PowerPoint: slides, layouts, masters.
		return strings.HasPrefix(name, "ppt/slides/") ||
			strings.HasPrefix(name, "ppt/slidelayouts/") ||
			strings.HasPrefix(name, "ppt/slidemasters/")

	case DocumentTypeODF:
		// OpenDocument keeps everything in a flat set of parts at the package root,
		// the same set for text, spreadsheet and presentation:
		//
		//	content.xml  body text -- paragraphs, headings, spans, table cells
		//	meta.xml     the Dublin Core and meta: properties #515 made reportable
		//	styles.xml   master-page headers and footers, which carry running text
		//
		// styles.xml is included because an ODF header or footer lives there rather
		// than in a part of its own; the OOXML arm reaches the equivalent through its
		// "header"/"footer" name match. Omitting it would leave a value reported from a
		// running header in cleartext -- and because parentPartResidue then refuses the
		// write, the visible symptom would be a file that can never be redacted rather
		// than a quiet leak.
		//
		// settings.xml is deliberately NOT included: it holds view state and
		// configuration, the extractor reports nothing from it, and rewriting it risks
		// breaking a document for no recall gain.
		return name == "content.xml" || name == "meta.xml" || name == "styles.xml"

	default:
		return false
	}
}

// docPropsValueElements are the OOXML document-property elements whose character
// data is a value rather than structure.
//
// The XML decoder reports local names, so namespace prefixes (dc:, cp:, dcterms:)
// are already stripped — "creator", not "dc:creator". Deliberately excluded are
// the numeric/structural properties that carry no free text and no PII:
// Pages, Words, Characters, Lines, Paragraphs, revision, version, TotalTime,
// AppVersion, DocSecurity, ScaleCrop, LinksUpToDate, SharedDoc, HyperlinksChanged,
// and the dcterms date fields.
var docPropsValueElements = map[string]bool{
	// docProps/core.xml — Dublin Core + cp:
	"title":          true,
	"subject":        true,
	"creator":        true,
	"keywords":       true,
	"description":    true,
	"lastModifiedBy": true,
	"category":       true,
	"contentStatus":  true,
	"identifier":     true,

	// docProps/app.xml — extended properties
	"Company":            true,
	"Manager":            true,
	"Application":        true,
	"Template":           true,
	"HyperlinkBase":      true,
	"PresentationFormat": true,
	"TitlesOfParts":      true,
	"HeadingPairs":       true,

	// docProps/custom.xml — author-defined property values.
	//
	// Every SCALAR value type, not only the string ones. A custom property named
	// "MemberId" or "RecordId" is routinely written as <vt:i4>, and with only the string
	// types listed the redactor never extracted that character data, so no replacement
	// was ever registered for the part and a reported value was skipped. Measured on a
	// .docx whose only property is <vt:i4>729183640</vt:i4>: the scan reports it, and
	// before this the value came back byte-identical from --enable-redaction at rc 0.
	// See #373.
	//
	// Numeric here does not mean harmless: an account, member, patient or case number is
	// a number, and a date of birth is a date. Which of them is SENSITIVE is the
	// validators' decision, not this map's — nothing here creates a finding. This list
	// only decides where an ALREADY REPORTED value can be located and masked, so a wider
	// list cannot over-redact; it can only stop a reported value being missed.
	"lpwstr":   true,
	"lpstr":    true,
	"bstr":     true,
	"i1":       true,
	"i2":       true,
	"i4":       true,
	"i8":       true,
	"int":      true,
	"ui1":      true,
	"ui2":      true,
	"ui4":      true,
	"ui8":      true,
	"uint":     true,
	"r4":       true,
	"r8":       true,
	"decimal":  true,
	"cy":       true,
	"date":     true,
	"filetime": true,
	"clsid":    true,
	"error":    true,
	// Excluded, deliberately: "bool" (true/false carries nothing reportable) and the
	// binary families — blob, oblob, storage, stream, ostorage, ostream, vstream, cf. A
	// same-length text replacement inside base64 produces invalid base64, so a value
	// reported from one of those must NOT be rewritten in place. If it ever is reported,
	// parentPartResidue refuses the document rather than shipping a corrupt part, which
	// is the honest outcome.
	//
	// That refusal is also why this list being incomplete is no longer a leak: since the
	// residue check landed, a value the redactor cannot locate makes the write fail
	// loudly instead of attesting success. The list decides whether redaction can
	// SUCCEED, not whether a miss is disclosed.
}

// isDocPropsValueElement reports whether an element's character data is a
// document-property VALUE that may carry sensitive text.
func isDocPropsValueElement(local string) bool {
	return docPropsValueElements[local]
}

// extractTextFromXML extracts text content from an XML file
func (or *OfficeRedactor) extractTextFromXML(fileName string, content []byte, docType OfficeDocumentType, baseOffset int) (string, []OfficeTextPosition, error) {
	var extractedText strings.Builder
	var positions []OfficeTextPosition

	// Parse XML
	decoder := xml.NewDecoder(bytes.NewReader(content))
	var currentPath []string
	var currentElement xml.StartElement
	textOffset := baseOffset

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("XML parsing error: %w", err)
		}

		switch t := token.(type) {
		case xml.StartElement:
			currentPath = append(currentPath, t.Name.Local)
			currentElement = t

		case xml.EndElement:
			if len(currentPath) > 0 {
				currentPath = currentPath[:len(currentPath)-1]
			}

		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && or.isTextElement(currentPath, docType) {
				// Create position info
				position := OfficeTextPosition{
					FileName:       fileName,
					XMLPath:        strings.Join(currentPath, "/"),
					DocumentOffset: textOffset,
					Text:           text,
					ElementInfo: OfficeElementInfo{
						ElementName: currentElement.Name.Local,
						Attributes:  or.extractAttributes(currentElement),
						ParentPath:  strings.Join(currentPath[:len(currentPath)-1], "/"),
					},
				}

				positions = append(positions, position)
				extractedText.WriteString(text)
				if extractedText.Len() > textOffset {
					extractedText.WriteString(" ") // Add space between text elements
				}
				textOffset = baseOffset + extractedText.Len()
			}
		}
	}

	return extractedText.String(), positions, nil
}

// isTextElement determines if the current XML path represents a text element
func (or *OfficeRedactor) isTextElement(path []string, docType OfficeDocumentType) bool {
	if len(path) == 0 {
		return false
	}

	lastElement := path[len(path)-1]

	// Document-properties elements, checked before the per-format switch.
	//
	// Selecting docProps/* is only half the fix: its values do not live in w:t or
	// in a cell, they live in dc:creator, dc:title, cp:keywords, Company,
	// Manager, Template and so on. Without this the part would be selected,
	// extracted to an empty string, and nothing would be rewritten — the same
	// silent no-op as before, just reached differently.
	if isDocPropsValueElement(lastElement) {
		return true
	}

	switch docType {
	case DocumentTypeDOCX:
		// Word text elements: w:t (text), w:delText (deleted text)
		return lastElement == "t" || lastElement == "delText"

	case DocumentTypeXLSX:
		// Excel text elements: t (text in shared strings), v (cell value), f (formula)
		return lastElement == "t" || lastElement == "v" || lastElement == "f"

	case DocumentTypePPTX:
		// PowerPoint text elements: a:t (text)
		return lastElement == "t"

	case DocumentTypeODF:
		return odfValueElements[lastElement]

	default:
		return false
	}
}

// odfValueElements are the ODF local names whose character data is a value rather than
// structure, across content.xml, meta.xml and styles.xml.
//
// Local names only: the decoder strips prefixes, so this is "p" not "text:p" and
// "initial-creator" not "meta:initial-creator". That is what makes it namespace-agnostic,
// and it is the same choice the ODF metadata extractor made for meta.xml.
//
// Every metadata name here is taken from odfMeta in
// meta-extractors/meta-extract-officelib/odf-extractor.go rather than from the ODF spec
// directly. The redactor must cover exactly what the SCANNER reports: a name the extractor
// never reads produces no finding and needs no rewrite, while a name it reads and this map
// omits becomes a reported value the redactor cannot remove — which parentPartResidue turns
// into a refusal to write. Keeping the two lists derived from the same source is what stops
// that drift.
var odfValueElements = map[string]bool{
	// content.xml / styles.xml body text.
	//
	// "p" carries essentially all ODF prose, including inside a spreadsheet cell
	// (table:table-cell > text:p) and a slide (draw:frame > draw:text-box > text:p), which
	// is why one entry covers all three document kinds. "span" is inline formatting inside
	// a paragraph, "h" a heading, "a" a hyperlink's display text.
	"p":    true,
	"span": true,
	"h":    true,
	"a":    true,

	// meta.xml properties. The two identity fields are ODF's inverse of OOXML's --
	// meta:initial-creator is the author and dc:creator the last editor (ODF 1.2 §4.3.2).
	"initial-creator": true,
	"creator":         true,
	"title":           true,
	"subject":         true,
	"description":     true,
	"language":        true,
	"keyword":         true,
	"generator":       true,
	"printed-by":      true,

	// meta:user-defined, ODF's analogue of docProps/custom.xml, where matter numbers,
	// client names and case references end up. Its value is character data; its name is an
	// attribute and is not a value to redact.
	"user-defined": true,

	// Deliberately absent, matching the OOXML arm's reasoning: the date and counter fields
	// (creation-date, date, print-date, editing-cycles, editing-duration) carry no free
	// text and no PII, and rewriting a date would corrupt the document for no gain.
	//
	// Also absent: meta:template. Its value is an xlink:href ATTRIBUTE, not character data,
	// so no chardata rule can reach it — this walker only rewrites character data. A
	// reported template path therefore survives into parentPartResidue and the write is
	// REFUSED with the value named, rather than a copy being written with the path still in
	// it. That is the disclosed outcome, not the silent one, and it is the same trade the
	// OOXML arm makes for values it cannot locate. Tracked separately rather than bodged
	// here, because attribute rewriting is a change to the walker, not to this table.
}

// extractAttributes extracts attributes from an XML start element
func (or *OfficeRedactor) extractAttributes(element xml.StartElement) map[string]string {
	attributes := make(map[string]string)
	for _, attr := range element.Attr {
		attributes[attr.Name.Local] = attr.Value
	}
	return attributes
}

// redactOfficeContent performs redaction on Office document content
func (or *OfficeRedactor) redactOfficeContent(zipContents *OfficeZipContents, extractedText string, textPositions []OfficeTextPosition, matches []detector.Match, strategy redactors.RedactionStrategy, docType OfficeDocumentType) ([]redactors.RedactionMapping, *OfficeZipContents, error) {
	var redactionMap []redactors.RedactionMapping
	modifiedContents := &OfficeZipContents{
		Files: make(map[string][]byte, len(zipContents.Files)),
		Order: make([]string, 0, len(zipContents.Files)),
	}

	// Copy all files initially, walking the recorded order rather than the map
	// so the copy carries the source package's entry order forward.
	for _, fileName := range zipContents.orderedNames() {
		modifiedContents.addFile(fileName, zipContents.Files[fileName])
	}

	// Restore bounded (display-truncated) consolidated match texts to their
	// Match texts are already normalized by RedactDocument, before BOTH consumers —
	// see the comment there. Doing it here reached only this function's local slice,
	// which is what let a cluster through to the embedded-part gate.

	// Collapse overlapping matches to their widest span so a smaller match
	// contained in a larger one doesn't get redacted first and hide the larger
	// match's un-redacted head. See redactors.ResolveOverlaps.
	matches = redactors.ResolveOverlaps(matches)

	// Where a value lives depends only on the value, so resolve each distinct text
	// once. Without this, a document dense in one repeated value walks the whole
	// extracted text per match: measured on a 243KB body holding one SSN 4000 times
	// plus the same SSN in docProps/core.xml, redaction went 0.73s -> 1.60s, because
	// core.xml is concatenated after the body so every match scanned the entire body
	// before finding it. That is quadratic in document size, the shape already
	// tracked for the redaction path.
	partCache := make(map[string]matchLocation)

	// Replacements are ACCUMULATED per part and applied once, after every match has
	// been resolved.
	//
	// Rewriting per match meant one bytes.ReplaceAll over the whole part per distinct
	// value, so N distinct values cost N full scans of the part — quadratic in document
	// size. Measured end to end, growth converged on 4x per doubling (3.26x at
	// 4k->8k, 3.68x at 8k->16k), and 8000 values over a 484KB part scanned 3.9GB at
	// 1.1GB/s, i.e. memory-bandwidth-bound. Extrapolated to maxOfficeEntryBytes, the
	// tool's own 50MB per-part cap, that is roughly 930k findings and ~11.6 HOURS: a
	// hang on input the scanner itself accepts, with no redaction-side execution budget
	// to cut it short.
	//
	// One batched pass per part replaces that with O(part + total match bytes).
	pending := make(map[string]*partReplacements)

	// Computed once: see distinctPartCount for why building it per match was quadratic.
	partCount := distinctPartCount(textPositions)

	// Process each match
	for _, match := range matches {
		mapping, err := or.redactMatch(modifiedContents, extractedText, textPositions, match, strategy, docType, partCache, pending, partCount)
		if err != nil {
			or.logEvent("match_redaction_failed", false, map[string]interface{}{
				"match_type": match.Type,
				"match_line": match.LineNumber,
				"error":      err.Error(),
			})
			continue
		}

		if mapping != nil {
			redactionMap = append(redactionMap, *mapping)
		}
	}

	// Flush before returning: the caller inspects modifiedContents for residue in
	// embedded parts, so an unapplied replacement would read as a leak.
	if err := or.applyPendingRedactions(modifiedContents, pending); err != nil {
		return nil, nil, err
	}

	return redactionMap, modifiedContents, nil
}

// partReplacements is the set of value -> replacement rewrites pending for one part.
//
// order preserves first-seen order so the applied result does not depend on Go's map
// iteration. The map is written ONCE per value: with a format-preserving or synthetic
// strategy two matches carrying the same text can generate different replacements, and
// the previous code applied the first and skipped the rest, so first-write-wins keeps
// that behaviour.
type partReplacements struct {
	order []string
	repl  map[string]string
}

// add records a rewrite, keeping the first replacement seen for a value.
func (p *partReplacements) add(value, replacement string) {
	if p.repl == nil {
		p.repl = make(map[string]string)
	}
	if _, seen := p.repl[value]; seen {
		return
	}
	p.repl[value] = replacement
	p.order = append(p.order, value)
}

// applyPendingRedactions rewrites each part in a single pass.
//
// Ordering is load-bearing twice over:
//
//   - Parts are applied in sorted name order so the output is byte-identical run to
//     run, rather than following map iteration.
//   - Within a part, values are offered LONGEST FIRST. strings.Replacer compares the
//     old strings in argument order at each position and never overlaps a replacement,
//     so the longest match wins — mirroring how ResolveOverlaps keeps the widest span.
//     That is what keeps partially-overlapping values leak-safe: a shorter value nested
//     in a longer one must not consume bytes the longer one needed and strand its head
//     in cleartext, which is the failure the overlap pass exists to prevent.
//     Equal-length values are ordered lexicographically, again for determinism.
func (or *OfficeRedactor) applyPendingRedactions(zipContents *OfficeZipContents, pending map[string]*partReplacements) error {
	if len(pending) == 0 {
		return nil
	}

	names := make([]string, 0, len(pending))
	for name := range pending {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		pr := pending[name]
		if pr == nil || len(pr.order) == 0 {
			continue
		}

		xmlContent, exists := zipContents.Files[name]
		if !exists {
			return fmt.Errorf("XML file not found: %s", name)
		}

		values := make([]string, len(pr.order))
		copy(values, pr.order)
		sort.SliceStable(values, func(i, j int) bool {
			if len(values[i]) != len(values[j]) {
				return len(values[i]) > len(values[j])
			}
			return values[i] < values[j]
		})

		args := make([]string, 0, len(values)*2)
		for _, v := range values {
			args = append(args, v, pr.repl[v])
		}

		replacer := strings.NewReplacer(args...)
		modifiedContent, charDataRewrites := rewritePartText(xmlContent, replacer)
		zipContents.addFile(name, modifiedContent)

		or.logEvent("xml_content_modified", true, map[string]interface{}{
			"file_name":         name,
			"original_size":     len(xmlContent),
			"modified_size":     len(modifiedContent),
			"values":            len(values),
			"chardata_rewrites": charDataRewrites,
		})
	}

	return nil
}

// residueIdentifyPasses counts how many times the residue check has entered its
// per-value identification loop.
//
// It exists for one guard: the identification loop is O(values x text) and must stay
// off the successful path. Measured when it was NOT: +0.00s, +0.01s, +0.02s then
// +0.09s as the reported-value count doubled through 500/1000/2000/4000, i.e. about
// 4.5x per doubling.
//
// A counter rather than a timing assertion, because the quadratic here is pure
// strings.Contains work that allocates nothing — so an allocation-based guard is blind
// to it (verified: restoring the quadratic passed an allocation ratio test) — and
// wall-clock thresholds are not portable to the Windows runner.
var residueIdentifyPasses atomic.Uint64

// parentPartResidue returns the reported values still present in the document's own
// XML parts after redaction, comparing on DECODED text.
//
// Decoding is the whole point. The defect this guards against is a value whose stored
// spelling differs from its reported form, so a raw-byte search for the reported value
// would not find "Fairbanks &amp; Kettleworth" while looking for
// "Fairbanks & Kettleworth" and would cheerfully report no residue — certifying the
// exact leak it exists to catch. Tokenizing and comparing the decoded character data
// and attribute values is what makes the check mean anything.
//
// Scope is deliberately narrow, because a false refusal turns a working redaction into
// an error:
//
//   - Only XML parts. Binary entries (thumbnails, embedded media) belong to the
//     embedded path, which has its own residue check and its own refusal.
//   - Only values at or above minResidueValueLen, matching the embedded value set. A
//     shorter value produces meaningless hits and is not something redaction targets.
//   - A part that does not tokenize is SKIPPED rather than treated as residue. Absence
//     cannot be established there, but neither can presence, and refusing on a
//     malformed part the redactor never claimed to rewrite would fail closed on the
//     wrong thing.
//
// # Cost
//
// Two stages, and the split is deliberate. A naive "one strings.Contains per value per
// part" is O(values x text) and measured quadratic: on a .docx with 4000 distinct
// reported values the identification scan cost +0.00s, +0.01s, +0.02s then +0.09s as
// the value count doubled — about 4.5x per doubling. Small in absolute terms, but this
// repo has repeatedly been bitten by exactly that shape once inputs grew.
//
// So the common case pays only a single trie pass. strings.Replacer builds one trie
// over all the values and scans each part once, independent of how many values there
// are; if nothing matched, there is no residue and we are done. The per-value
// identification loop runs ONLY when a hit has already been found, i.e. only on the
// path that is about to refuse to write the document, where an extra pass is free
// relative to failing the run.
func parentPartResidue(contents *OfficeZipContents, matches []detector.Match) []detector.Match {
	if contents == nil || len(matches) == 0 {
		return nil
	}

	wanted := make([]string, 0, len(matches))
	byText := make(map[string]detector.Match, len(matches))
	for _, m := range matches {
		if len(m.Text) < minResidueValueLen {
			continue
		}
		if _, dup := byText[m.Text]; dup {
			continue
		}
		byText[m.Text] = m
		wanted = append(wanted, m.Text)
	}
	if len(wanted) == 0 {
		return nil
	}

	// Sorted part order so the reported residue list is stable run to run.
	names := make([]string, 0, len(contents.Files))
	for name := range contents.Files {
		if strings.HasSuffix(strings.ToLower(name), ".xml") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	// Stage 1: one trie pass per part over ALL values at once. Replacing every value
	// with nothing and comparing is a presence oracle whose cost does not grow with the
	// number of values.
	probeArgs := make([]string, 0, len(wanted)*2)
	for _, v := range wanted {
		probeArgs = append(probeArgs, v, "")
	}
	probe := strings.NewReplacer(probeArgs...)

	texts := make([]string, 0, len(names))
	anyHit := false
	for _, name := range names {
		text, ok := decodedPartText(contents.Files[name])
		if !ok {
			continue
		}
		texts = append(texts, text)
		if !anyHit && probe.Replace(text) != text {
			anyHit = true
		}
	}
	if !anyHit {
		return nil
	}

	// Stage 2: name the offenders. Only reached when the document is already going to
	// be refused, so the per-value scan is not on any successful path.
	residueIdentifyPasses.Add(1)
	found := make(map[string]struct{}, len(wanted))
	for _, text := range texts {
		for _, v := range wanted {
			if _, already := found[v]; already {
				continue
			}
			if strings.Contains(text, v) {
				found[v] = struct{}{}
			}
		}
	}

	out := make([]detector.Match, 0, len(found))
	for _, v := range wanted {
		if _, ok := found[v]; ok {
			out = append(out, byText[v])
		}
	}
	return out
}

// residueTypes lists the distinct finding types of a residue set, sorted, for a message
// that must not carry the values themselves.
//
// A match with no Type still has to be counted as something an operator can see, so it
// is named "unknown" rather than dropped — a residue that reports fewer types than
// values would understate what is still in the file.
func residueTypes(residue []detector.Match) []string {
	seen := make(map[string]struct{}, len(residue))
	out := make([]string, 0, len(residue))
	for _, m := range residue {
		t := m.Type
		if t == "" {
			t = "unknown"
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// decodedPartText concatenates a part's entity-decoded character data and attribute
// values. It reports false when the part cannot be tokenized, so the caller can skip
// it rather than guess.
func decodedPartText(content []byte) (string, bool) {
	var sb strings.Builder
	sb.Grow(len(content) / 2)

	dec := xml.NewDecoder(bytes.NewReader(content))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
			// A separator keeps two adjacent runs from concatenating into a value that
			// is in neither of them.
			sb.WriteByte('\n')
		case xml.StartElement:
			// Attribute values are covered because the raw replacer rewrites them, so a
			// value living in one is in scope for the refusal too.
			for _, a := range t.Attr {
				sb.WriteString(a.Value)
				sb.WriteByte('\n')
			}
		}
	}
	return sb.String(), true
}

// rewritePartText applies repl to an XML part, matching character data on its
// DECODED form so a value's stored spelling cannot hide it.
//
// # The defect this exists for
//
// extractTextFromXML reads part text through encoding/xml, so the text offered to
// the validators is entity-decoded: the value the report names is "Fairbanks &
// Kettleworth", never the "Fairbanks &amp; Kettleworth" that is actually on disk.
// Rewriting used to run the replacer over the RAW part bytes, so the literal never
// occurred, the replacer was a no-op for that value, and RedactDocument still
// returned Success with failed_redactions:0. Measured before this: a .docx whose
// Company property held an ampersand came back from --enable-redaction with the
// company name intact — confirmed by exiftool reading it out of the "redacted"
// copy — while a sibling value in the same part masked correctly.
//
// This needs no attacker. XML REQUIRES '&' in character data to be written "&amp;",
// so every document whose text or properties contain an ampersand was affected.
//
// # Why enumerating escaped spellings cannot fix it
//
// embedded.XMLEscapeVariants offers the "&amp;"/"&apos;" spellings as extra
// replacer keys, which covers the predefined entities and nothing else. '&' also
// introduces character references, so ANY character at ANY offset can be respelled:
// "449-87-41&#48;0", "&#52;49-87-4100" and "449&#45;87&#45;4100" are all the same
// value, as is the &#x30; hex form. The spellings are combinatorial, so only letting
// the codec canonicalize them is complete.
//
// # Why this is a strict superset of the old behaviour
//
// Character data is matched on its decoded form and re-emitted escaped. Everything
// else — markup, attribute values, and any character data that did not change — is
// handed to the SAME raw replacer the old code used, over the byte ranges between
// rewrites. So every replacement the old code made is still made (including a value
// sitting in an attribute, which is not character data and would otherwise have been
// lost), and the entity-spelled cases are newly covered.
//
// A tokenizer error is not fatal: encoding/xml rejects an undefined entity such as
// "&foo;", and a part that cannot be tokenized simply falls through to the raw
// replacer for its remainder, which is exactly what shipped before. The residue
// check is what turns a miss into a refusal rather than a silent success.
//
// # Cost
//
// One tokenizing pass plus the replacer applied to disjoint regions summing to at
// most len(content), so the work stays linear in part size — the same order as the
// single whole-part Replace it replaces. The replacer is built ONCE per part by the
// caller and must stay that way: building it per token would make this quadratic in
// the number of values, which is the shape that has bitten this repo repeatedly.
//
// Returns the rewritten part and the number of character-data spans rewritten
// through the decoded path, which the caller logs.
func rewritePartText(content []byte, repl *strings.Replacer) ([]byte, int) {
	dec := xml.NewDecoder(bytes.NewReader(content))

	var out bytes.Buffer
	out.Grow(len(content) + len(content)/8)

	prev, rewrites := 0, 0
	for {
		// InputOffset gives the end of the last token and the start of the next, so
		// reading it either side of Token() brackets the token's byte span exactly.
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			// io.EOF, or a part encoding/xml refuses. Either way the tail is emitted
			// below through the raw replacer, preserving the previous behaviour.
			break
		}
		end := int(dec.InputOffset())

		cd, ok := tok.(xml.CharData)
		if !ok {
			continue
		}
		decoded := string(cd)
		replaced := repl.Replace(decoded)
		if replaced == decoded {
			continue
		}

		// Everything since the last rewrite, still through the raw replacer.
		out.WriteString(repl.Replace(string(content[prev:start])))
		escapeCharData(&out, replaced)
		prev = end
		rewrites++
	}

	out.WriteString(repl.Replace(string(content[prev:])))
	return out.Bytes(), rewrites
}

// escapeCharData writes s as XML character data.
//
// Only '&', '<' and '>' are escaped — the set character data actually requires —
// rather than using xml.EscapeText, which also rewrites quotes and turns newlines
// into "&#xA;". Keeping the escaping minimal keeps the rewritten part as close to the
// original bytes as possible, so a redaction shows up in a diff as the redaction and
// nothing else.
//
// '&' is escaped UNCONDITIONALLY. A decoded value can legitimately contain an
// ampersand followed by entity-looking text — "&amp;lt;" decodes to the literal
// "&lt;" — so an escaper that tried to be clever and skip '&' before a known entity
// name would silently corrupt that value on the way back out.
func escapeCharData(out *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			out.WriteString("&amp;")
		case '<':
			out.WriteString("&lt;")
		case '>':
			out.WriteString("&gt;")
		default:
			out.WriteByte(s[i])
		}
	}
}

// positionForOffset returns the extracted-text position covering off.
//
// textPositions is built in extraction order with strictly ascending
// DocumentOffset, so this binary searches rather than scanning. A linear scan here
// is what makes the caller quadratic on a document with many occurrences.
func positionForOffset(textPositions []OfficeTextPosition, off int) *OfficeTextPosition {
	i := sort.Search(len(textPositions), func(i int) bool {
		return textPositions[i].DocumentOffset > off
	}) - 1
	if i < 0 {
		return nil
	}
	if off < textPositions[i].DocumentOffset+len(textPositions[i].Text) {
		return &textPositions[i]
	}
	return nil
}

// matchLocation is where a value lives in the extracted text: the offset of its
// first occurrence and the distinct parts holding it.
//
// It depends only on the VALUE, not on which match reported it, so it is cached per
// distinct text for the life of one document — see partCache in
// redactOfficeContent.
type matchLocation struct {
	firstOffset int // -1 when the value is not in the extracted text
	parts       []OfficeTextPosition
}

// partsHoldingMatch returns the distinct Office parts holding text, in
// first-occurrence order.
//
// Resolving only the FIRST occurrence is what leaked. A value present in two parts
// -- say an SSN in both word/document.xml and docProps/core.xml -- produces two
// matches, and strings.Index gave both the same offset, so both selected the same
// part. The rewrite is scoped to the part it is recorded against, so
// the other part kept the value in CLEARTEXT while the scan reported success and
// exited 0. Which part leaked was decided by zip entry order, because extractedText
// is concatenated in that order: reversing the two entries moved the residue from
// docProps/core.xml to word/document.xml.
//
// The walk stops as soon as every part is accounted for. Without that bound this is
// called once per match and scans the whole extracted text each time, so a document
// dense in one repeated value would be quadratic in the number of matches -- the
// shape already tracked for the redaction path, not one to add to.
func partsHoldingMatch(extractedText string, textPositions []OfficeTextPosition, text string) []OfficeTextPosition {
	return locateMatch(extractedText, textPositions, text, distinctPartCount(textPositions)).parts
}

// locateMatch performs the single walk behind partsHoldingMatch, also reporting the
// first occurrence's offset so the caller does not need a second strings.Index pass.
// distinctPartCount counts the distinct part names in textPositions.
//
// Hoisted out of locateMatch, and that hoist is the difference between quadratic and
// linear. textPositions carries one entry per TEXT ELEMENT, not per part — 16000 <w:t>
// runs produce 16000 entries that all name word/document.xml — so building this set
// inside locateMatch meant 16000 map assignments per call, once per distinct value:
// 256M map writes for a 16000-finding document. A CPU profile put
// runtime.mapassign_faststr at 21% of total and locateMatch at 37% cumulative.
//
// The set depends only on the document, so it is computed once per redaction.
func distinctPartCount(textPositions []OfficeTextPosition) int {
	if len(textPositions) == 0 {
		return 0
	}
	// Almost always 1-5 parts, so a small map with a fast path for the common run of
	// consecutive entries naming the same part.
	distinct := make(map[string]struct{}, 4)
	last := ""
	for _, p := range textPositions {
		if p.FileName == last {
			continue
		}
		last = p.FileName
		distinct[p.FileName] = struct{}{}
	}
	return len(distinct)
}

func locateMatch(extractedText string, textPositions []OfficeTextPosition, text string, partCount int) matchLocation {
	loc := matchLocation{firstOffset: -1}
	if text == "" || len(textPositions) == 0 {
		return loc
	}
	if partCount <= 0 {
		partCount = distinctPartCount(textPositions)
	}

	seen := make(map[string]struct{}, partCount)
	for base := 0; base+len(text) <= len(extractedText); {
		i := strings.Index(extractedText[base:], text)
		if i < 0 {
			break
		}
		off := base + i
		if loc.firstOffset < 0 {
			loc.firstOffset = off
		}
		if pos := positionForOffset(textPositions, off); pos != nil {
			if _, dup := seen[pos.FileName]; !dup {
				seen[pos.FileName] = struct{}{}
				loc.parts = append(loc.parts, *pos)
				if len(seen) == partCount {
					break // every part holds it; nothing further to find
				}
			}
		}
		base = off + len(text) // non-overlapping: the same bytes are redacted once
	}
	return loc
}

// redactMatch redacts a single match in the Office document
func (or *OfficeRedactor) redactMatch(zipContents *OfficeZipContents, extractedText string, textPositions []OfficeTextPosition, match detector.Match, strategy redactors.RedactionStrategy, docType OfficeDocumentType, partCache map[string]matchLocation, pending map[string]*partReplacements, partCount int) (*redactors.RedactionMapping, error) {
	// Every part that holds the value, not just the one holding its first
	// occurrence -- see partsHoldingMatch. Cached per distinct value.
	loc, cached := partCache[match.Text]
	if !cached {
		loc = locateMatch(extractedText, textPositions, match.Text, partCount)
		if partCache != nil {
			partCache[match.Text] = loc
		}
	}

	matchPos := loc.firstOffset
	if matchPos < 0 {
		return nil, fmt.Errorf("match text not found in extracted content")
	}
	parts := loc.parts
	if len(parts) == 0 {
		return nil, fmt.Errorf("could not find Office position for match")
	}
	officePosition := &parts[0]

	// Generate replacement text
	replacement, err := or.generateReplacement(match.Text, match.Type, strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate replacement: %w", err)
	}

	// RECORD the rewrite for every part that holds the value, rather than applying it
	// here. applyPendingRedactions performs one pass per part once all matches are
	// resolved; rewriting per match is what made this quadratic in document size.
	//
	// The part must exist now, not at flush time, so a missing part is still reported
	// against the match that needed it.
	redactedParts := make([]string, 0, len(parts))
	for i := range parts {
		name := parts[i].FileName
		if _, exists := zipContents.Files[name]; !exists {
			return nil, fmt.Errorf("failed to apply XML redaction in %s: XML file not found", name)
		}
		redactedParts = append(redactedParts, name)

		pr := pending[name]
		if pr == nil {
			pr = &partReplacements{}
			pending[name] = pr
		}
		pr.add(match.Text, replacement)
	}

	// Create redaction mapping
	mapping := redactors.RedactionMapping{
		RedactedText: replacement,
		Position: redactors.TextPosition{
			Line:      match.LineNumber,
			StartChar: matchPos,
			EndChar:   matchPos + len(match.Text),
		},
		DataType:   match.Type,
		Strategy:   strategy,
		Confidence: match.Confidence,

		Metadata: map[string]interface{}{
			"office_file": officePosition.FileName,
			// Every part the value was rewritten in. office_file names only the
			// first and stays for compatibility; a cross-part value is visible
			// only here.
			"office_files":    redactedParts,
			"xml_path":        officePosition.XMLPath,
			"element_info":    officePosition.ElementInfo,
			"document_type":   docType.String(),
			"position_method": "xml_text_extraction",
		},
	}

	or.logEvent("office_redaction_applied", true, map[string]interface{}{
		"match_type":         match.Type,
		"file_name":          officePosition.FileName,
		"file_names":         redactedParts,
		"part_count":         len(redactedParts),
		"replacement_length": len(replacement),
		"confidence":         match.Confidence,
		"document_type":      docType.String(),
	})

	return &mapping, nil
}

// repackageOfficeDocument repackages the modified ZIP contents into a new Office document
func (or *OfficeRedactor) repackageOfficeDocument(contents *OfficeZipContents, outputPath string) error {
	// Ensure output directory exists
	if or.outputManager != nil {
		if err := or.outputManager.EnsureDirectoryExists(outputPath); err != nil {
			return fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create ZIP writer
	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// Write all files to ZIP in the order they appeared in the source package.
	// Ranging contents.Files directly here made the redacted document's entry
	// order random per run, which broke byte reproducibility and regularly moved
	// [Content_Types].xml out of the first slot that OPC requires it to occupy.
	for _, fileName := range contents.orderedNames() {
		content := contents.Files[fileName]

		// ODF 1.2 §3.3: the `mimetype` entry must be FIRST in the package, stored
		// UNCOMPRESSED, and readable by a byte sniff at a fixed offset. zipWriter.Create
		// satisfies none of that — it deflates, and it streams.
		//
		// Order is already right for free: orderedNames replays the source package's own
		// entry order, and a conforming producer wrote mimetype first.
		//
		// CreateRaw, not CreateHeader, and that distinction is the whole fix. Go's zip
		// writer streams, so both Create and CreateHeader set general-purpose bit 3 and
		// defer the CRC and the sizes to a trailing DATA DESCRIPTOR, leaving zeros in the
		// local header. CreateRaw takes the CRC and both sizes up front and emits no
		// descriptor. Measured on the local header of the first entry:
		//
		//	CreateHeader   flag=0x0008  crc=00000000  csize=0   usize=0   -> LibreOffice REFUSES
		//	CreateRaw      flag=0x0000  crc=0c32c65e  csize=39  usize=39  -> opens
		//
		// LibreOffice is the oracle here, and nothing cheaper substitutes for it: with the
		// descriptor form, `file(1)` still said "OpenDocument Text", zip.testzip() passed,
		// and content.xml/meta.xml both parsed as XML — yet `soffice --convert-to txt`
		// answered "source file could not be loaded". Isolated by rebuilding the same parts
		// with python: mimetype-STORED-plus-deflated-rest opened, and so did a package
		// carrying BOTH redacted parts, which is what ruled out the compression mix and the
		// rewritten XML and left the container as the only candidate.
		var fileWriter io.Writer
		if fileName == "mimetype" {
			fileWriter, err = zipWriter.CreateRaw(&zip.FileHeader{
				Name:               fileName,
				Method:             zip.Store,
				CRC32:              crc32.ChecksumIEEE(content),
				CompressedSize64:   uint64(len(content)),
				UncompressedSize64: uint64(len(content)),
			})
		} else {
			fileWriter, err = zipWriter.Create(fileName)
		}
		if err != nil {
			return fmt.Errorf("failed to create ZIP entry for %s: %w", fileName, err)
		}

		_, err = fileWriter.Write(content)
		if err != nil {
			return fmt.Errorf("failed to write content for %s: %w", fileName, err)
		}
	}

	or.logEvent("office_document_repackaged", true, map[string]interface{}{
		"output_path": outputPath,
		"file_count":  len(contents.Files),
	})

	return nil
}

// generateReplacement generates a replacement string based on the redaction strategy
// generateReplacement delegates to the shared replacement package.
func (or *OfficeRedactor) generateReplacement(originalText, dataType string, strategy redactors.RedactionStrategy) (string, error) {
	return replacement.Generate(originalText, dataType, strategy), nil
}

// calculateOverallConfidence calculates the overall confidence for the redaction
func (or *OfficeRedactor) calculateOverallConfidence(redactionMap []redactors.RedactionMapping) float64 {
	if len(redactionMap) == 0 {
		return 1.0
	}
	total := 0.0
	for _, m := range redactionMap {
		total += m.Confidence
	}
	return total / float64(len(redactionMap))
}

// logEvent logs an event if observer is available
func (or *OfficeRedactor) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if or.observer != nil {
		or.observer.StartTiming("office_redactor", operation, "")(success, metadata)
	}
}

// GetComponentName returns the component name for observability
func (or *OfficeRedactor) GetComponentName() string {
	return "office_redactor"
}

// SetPositionCorrelationEnabled enables or disables position correlation
func (or *OfficeRedactor) SetPositionCorrelationEnabled(enabled bool) {
	or.enablePositionCorrelation = enabled
}

// SetConfidenceThreshold sets the minimum confidence threshold for position-based redaction
func (or *OfficeRedactor) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0.0 && threshold <= 1.0 {
		or.confidenceThreshold = threshold
	}
}

// SetFallbackToSimple controls whether to fall back to simple text replacement on correlation failure
func (or *OfficeRedactor) SetFallbackToSimple(fallback bool) {
	or.fallbackToSimple = fallback
}

// GetPositionCorrelationStats returns statistics about position correlation performance
func (or *OfficeRedactor) GetPositionCorrelationStats() map[string]interface{} {
	return map[string]interface{}{
		"correlation_enabled":  or.enablePositionCorrelation,
		"confidence_threshold": or.confidenceThreshold,
		"fallback_enabled":     or.fallbackToSimple,
		"correlator_type":      fmt.Sprintf("%T", or.positionCorrelator),
	}
}
