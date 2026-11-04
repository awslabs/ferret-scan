// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// RedactionAuditLog contains audit information about redactions performed on a document
type RedactionAuditLog struct {
	// DocumentID is a unique identifier for this document
	DocumentID string `json:"document_id"`

	// RedactionTimestamp is when the redaction was performed
	RedactionTimestamp time.Time `json:"redaction_timestamp"`

	// FerretVersion is the version of Ferret-Scan that performed the redaction
	FerretVersion string `json:"ferret_version"`

	// OriginalPath is the path to the original document
	OriginalPath string `json:"original_path"`

	// RedactedPath is the path to the redacted document
	RedactedPath string `json:"redacted_path"`

	// OriginalFileHash is a sha256 of the original document, for integrity verification.
	//
	// Omitted when it could not be computed (an unreadable input), for the same reason as
	// RedactedFileHash below.
	OriginalFileHash string `json:"original_file_hash,omitempty"`

	// RedactedFileHash is a sha256 of the redacted document, for integrity verification.
	//
	// Omitted rather than written as "" when there is no digest to report. Until this was populated
	// the field was present and empty in EVERY audit log — SetRedactedFileHash had no callers — and a
	// declared-but-always-empty field is worse than an absent one: a consumer cannot tell "not
	// computed" from "computed as the empty string". A sha256 is never legitimately empty, so absent
	// now means exactly one thing: no redacted artifact existed to attest to. That happens for real —
	// the Office redactor refuses to write a partial redaction, and an unregistered file type
	// produces no output — and in both cases the run says so on stderr.
	RedactedFileHash string `json:"redacted_file_hash,omitempty"`

	// RedactionSummary contains summary statistics about the redaction
	RedactionSummary RedactionSummary `json:"redaction_summary"`

	// ContentRedactions contains audit information about content redactions performed
	ContentRedactions []ContentRedaction `json:"content_redactions"`

	// MetadataRedactions lists metadata removed rather than rewritten: one entry per EXIF field an
	// image redaction dropped, or one for a PNG's ancillary chunks (#865). These used to be written
	// as content redactions of type IMAGE_METADATA at a constant confidence, and this was always [].
	MetadataRedactions []MetadataRedaction `json:"metadata_redactions"`
}

// RedactionSummary contains summary statistics about redactions performed
type RedactionSummary struct {
	// TotalRedactions is the number of entries in content_redactions and metadata_redactions.
	TotalRedactions int `json:"total_redactions"`

	// DataTypes is a list of data types that were redacted
	DataTypes []string `json:"data_types"`

	// Strategy is the strategy the run asked the redactors for, by name ("simple",
	// "format_preserving", "synthetic"). It used to be left unset, which serialised as 0.
	Strategy RedactionStrategy `json:"strategy"`

	// ProcessingTimeMs is how long the redactor took on this document, in milliseconds. It replaces
	// processing_time, a unit-less duration that nothing set and so always read 0.
	ProcessingTimeMs float64 `json:"processing_time_ms"`

	// SuccessfulRedactions equals TotalRedactions: an entry is recorded only for a document whose
	// redacted copy was written and verified to hold none of its reported values.
	SuccessfulRedactions int `json:"successful_redactions"`

	// FailedRedactions is 0 by construction, for the same reason. A document that could not be
	// redacted has no audit entry; the run reports it as not redacted instead.
	FailedRedactions int `json:"failed_redactions"`
}

// EmbeddedMediaRef contains information about embedded media
type EmbeddedMediaRef struct {
	// ExtractedPath is the path to the extracted media file
	ExtractedPath string `json:"extracted_path"`

	// OriginalLocation is the location within the parent document
	OriginalLocation string `json:"original_location"`

	// MediaType is the MIME type of the media
	MediaType string `json:"media_type"`

	// RedactedPath is the path to the redacted media file
	RedactedPath string `json:"redacted_path,omitempty"`

	// Redacted indicates whether this media was redacted
	Redacted bool `json:"redacted"`

	// RedactionMethod describes how the media was redacted
	RedactionMethod string `json:"redaction_method,omitempty"`
}

// ContentRedaction represents audit information for a single content redaction operation
type ContentRedaction struct {
	// ID is a unique identifier for this redaction
	ID string `json:"id"`

	// TargetType indicates what was redacted (parent_document, embedded_media)
	TargetType string `json:"target_type"`

	// TargetPath is the path to the target file (for embedded media)
	TargetPath string `json:"target_path,omitempty"`

	// DataType is the type of sensitive data that was redacted
	DataType string `json:"data_type"`

	// RedactedText is the text written over the value. Where a format rewritten in place merged the
	// value with an overlapping one (audio, video), it is that merged span's mask; where the value
	// occurs more than once, what was written at its first occurrence.
	RedactedText string `json:"redacted_text"`

	// Strategy names the rendering RedactedText is: the strategy the redactor was called with, or
	// AuditMask where a format rewritten in place wrote a run of '*' instead of a rendering of that
	// strategy that keeps part of the value (RedactionMapping.Masked).
	Strategy AuditStrategy `json:"strategy"`

	// RequestedStrategy is the strategy the redactor was called with, present exactly when Strategy
	// is AuditMask (#865). It is a pointer so that simple, the zero RedactionStrategy, is written
	// rather than omitted.
	RequestedStrategy *RedactionStrategy `json:"requested_strategy,omitempty"`

	// Confidence is the detection confidence of the finding, on 0-1: the report's confidence / 100.
	//
	// For a text-family file (plaintext, and SVG and RTF, which delegate to it) this used to be the
	// position correlator's placement score instead (0.95 / 100 = 0.0095 for every exact match,
	// whatever the finding scored). That score is now Placement.Score.
	Confidence float64 `json:"confidence"`

	// Line is the 1-based line of the finding, as in the report's line_number. Absent when the
	// finding has none. Audio, video and legacy Office entries carry it too since #865; they used to
	// record no position at all.
	Line int `json:"line,omitempty"`

	// Placement says how a text-family redactor located the value it rewrote. Absent for every other
	// redactor, which locates a value by searching for it.
	Placement *Placement `json:"placement,omitempty"`

	// MemberTypes names, one entry per finding and sorted, every finding this one write covered when
	// it redacted an overlap group: findings on one line whose values shared bytes, written once over
	// their union (#773). DataType is then the group's label. Absent for a write covering one finding.
	MemberTypes []string `json:"member_types,omitempty"`

	// Timestamp is when this redaction was performed
	Timestamp time.Time `json:"timestamp"`
}

// AuditStrategy is a content redaction's strategy as the audit log records it: the name of the
// strategy whose rendering was written, or AuditMask. It is not a RedactionStrategy because a mask is
// not one: no run can ask for it, and ParseRedactionStrategy refuses the name.
type AuditStrategy string

// AuditMask is the strategy of an entry whose value a format rewritten in place at its own byte length
// (audio, video, legacy Office) overwrote with a run of '*' where the requested strategy's rendering
// keeps part of it (RedactionMapping.Masked, #865). Those entries used to say format_preserving beside
// a mask.
const AuditMask AuditStrategy = "mask"

// auditStrategyOf is the audit strategy of a redaction: AuditMask for a masked one, otherwise the
// name of the strategy the redactor was called with ("unknown" for a value outside the definition,
// which Valid rejects so the export fails rather than writing it).
func auditStrategyOf(m RedactionMapping) (AuditStrategy, *RedactionStrategy) {
	if m.Masked {
		requested := m.Strategy
		return AuditMask, &requested
	}
	return AuditStrategy(m.Strategy.String()), nil
}

// Valid reports whether a is one of the three strategies' names or AuditMask.
func (a AuditStrategy) Valid() bool {
	if a == AuditMask {
		return true
	}
	s, err := ParseRedactionStrategy(string(a))
	return err == nil && s.Valid()
}

// Placement records how the text-family redactor located a value: Method is its position_method
// ("position_correlation" when the correlator placed it, "simple_text_search" when it fell back to
// searching) and Score is the 0-1 placement score the redactor computed, already reduced when the
// position had to be corrected. It is the only record of a fuzzy or relocated match (#519).
type Placement struct {
	Method string   `json:"method"`
	Score  *float64 `json:"score,omitempty"`
}

// MetadataRedaction represents audit information for a metadata redaction operation
type MetadataRedaction struct {
	// TargetType indicates what was redacted (parent_document, embedded_media)
	TargetType string `json:"target_type"`

	// TargetPath is the path to the target file (for embedded media)
	TargetPath string `json:"target_path,omitempty"`

	// Field is the metadata field that was redacted
	Field string `json:"field"`

	// RedactedValue is the replacement value (null if removed)
	RedactedValue interface{} `json:"redacted_value"`

	// Action describes the action taken (removed, replaced, anonymized)
	Action string `json:"action"`

	// Timestamp is when this redaction was performed
	Timestamp time.Time `json:"timestamp"`
}

// NewRedactionAuditLog creates a new RedactionAuditLog
func NewRedactionAuditLog(documentID, originalPath, redactedPath, ferretVersion string) *RedactionAuditLog {
	return &RedactionAuditLog{
		DocumentID:         documentID,
		RedactionTimestamp: time.Now(),
		FerretVersion:      ferretVersion,
		OriginalPath:       originalPath,
		RedactedPath:       redactedPath,
		RedactionSummary: RedactionSummary{
			TotalRedactions:      0,
			DataTypes:            []string{},
			SuccessfulRedactions: 0,
			FailedRedactions:     0,
		},
		ContentRedactions:  make([]ContentRedaction, 0),
		MetadataRedactions: make([]MetadataRedaction, 0),
	}
}

// AddContentRedaction adds a content redaction to the index
func (ri *RedactionAuditLog) AddContentRedaction(redaction ContentRedaction) {
	if redaction.ID == "" {
		redaction.ID = ri.generateRedactionID()
	}
	if redaction.Timestamp.IsZero() {
		redaction.Timestamp = time.Now()
	}
	ri.ContentRedactions = append(ri.ContentRedactions, redaction)

	// Update summary statistics
	ri.RedactionSummary.TotalRedactions++
	ri.RedactionSummary.SuccessfulRedactions++

	// Add data type if not already present -- every member's, for a group write, since each of
	// those values was redacted by it.
	for _, dt := range append([]string{redaction.DataType}, redaction.MemberTypes...) {
		found := false
		for _, have := range ri.RedactionSummary.DataTypes {
			if have == dt {
				found = true
				break
			}
		}
		if !found {
			ri.RedactionSummary.DataTypes = append(ri.RedactionSummary.DataTypes, dt)
		}
	}
}

// AddMetadataRedaction adds a metadata redaction to the index
func (ri *RedactionAuditLog) AddMetadataRedaction(redaction MetadataRedaction) {
	if redaction.Timestamp.IsZero() {
		redaction.Timestamp = time.Now()
	}
	ri.MetadataRedactions = append(ri.MetadataRedactions, redaction)

	// Update summary statistics
	ri.RedactionSummary.TotalRedactions++
	ri.RedactionSummary.SuccessfulRedactions++
	if !containsString(ri.RedactionSummary.DataTypes, metadataDataType) {
		ri.RedactionSummary.DataTypes = append(ri.RedactionSummary.DataTypes, metadataDataType)
	}
}

// metadataDataType is the data type a metadata removal counts under in the summary's data_types,
// as it did when removals were recorded as content redactions.
const metadataDataType = "IMAGE_METADATA"

func containsString(list []string, s string) bool {
	for _, have := range list {
		if have == s {
			return true
		}
	}
	return false
}

// SetRedactionSummary sets the redaction summary information
func (ri *RedactionAuditLog) SetRedactionSummary(summary RedactionSummary) {
	ri.RedactionSummary = summary
}

// SetOriginalFileHash sets the verification hash for the original document
func (ri *RedactionAuditLog) SetOriginalFileHash(hash string) {
	ri.OriginalFileHash = hash
}

// SetRedactedFileHash sets the verification hash for the redacted document
func (ri *RedactionAuditLog) SetRedactedFileHash(hash string) {
	ri.RedactedFileHash = hash
}

// generateRedactionID generates a unique ID for a redaction
func (ri *RedactionAuditLog) generateRedactionID() string {
	data := fmt.Sprintf("%s-%d-%d", ri.DocumentID, time.Now().UnixNano(), len(ri.ContentRedactions))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter ID
}

// ToJSON converts the redaction index to JSON
func (ri *RedactionAuditLog) ToJSON() ([]byte, error) {
	return json.MarshalIndent(ri, "", "  ")
}

// GetContentRedactionsByDataType returns all content redactions for a specific data type
func (ri *RedactionAuditLog) GetContentRedactionsByDataType(dataType string) []ContentRedaction {
	var result []ContentRedaction
	for _, redaction := range ri.ContentRedactions {
		if redaction.DataType == dataType {
			result = append(result, redaction)
		}
	}
	return result
}

// GetMetadataRedactionsByField returns all metadata redactions for a specific field
func (ri *RedactionAuditLog) GetMetadataRedactionsByField(field string) []MetadataRedaction {
	var result []MetadataRedaction
	for _, redaction := range ri.MetadataRedactions {
		if redaction.Field == field {
			result = append(result, redaction)
		}
	}
	return result
}

// GetTotalRedactionCount returns the total number of redactions
func (ri *RedactionAuditLog) GetTotalRedactionCount() int {
	return len(ri.ContentRedactions) + len(ri.MetadataRedactions)
}

// Validate validates the redaction index for completeness and consistency
func (ri *RedactionAuditLog) Validate() error {
	if ri.DocumentID == "" {
		return fmt.Errorf("document_id cannot be empty")
	}

	if ri.OriginalPath == "" {
		return fmt.Errorf("original_path cannot be empty")
	}

	if ri.RedactedPath == "" {
		return fmt.Errorf("redacted_path cannot be empty")
	}

	if ri.RedactionTimestamp.IsZero() {
		return fmt.Errorf("redaction_timestamp cannot be zero")
	}

	if !ri.RedactionSummary.Strategy.Valid() {
		return fmt.Errorf("redaction_summary.strategy %d is not a redaction strategy", int(ri.RedactionSummary.Strategy))
	}

	// Validate content redactions
	for i, redaction := range ri.ContentRedactions {
		if redaction.ID == "" {
			return fmt.Errorf("content_redactions[%d].id cannot be empty", i)
		}
		if redaction.DataType == "" {
			return fmt.Errorf("content_redactions[%d].data_type cannot be empty", i)
		}
		if redaction.Confidence < 0 || redaction.Confidence > 1 {
			return fmt.Errorf("content_redactions[%d].confidence must be between 0 and 1", i)
		}
		if !redaction.Strategy.Valid() {
			return fmt.Errorf("content_redactions[%d].strategy %q is not a redaction strategy or %q", i, redaction.Strategy, AuditMask)
		}
		// requested_strategy says what a mask stood in for, so it is there exactly when the entry is
		// a mask, and names a strategy a run can ask for.
		if (redaction.Strategy == AuditMask) != (redaction.RequestedStrategy != nil) {
			return fmt.Errorf("content_redactions[%d].requested_strategy must be present exactly when strategy is %q", i, AuditMask)
		}
		if redaction.RequestedStrategy != nil && !redaction.RequestedStrategy.Valid() {
			return fmt.Errorf("content_redactions[%d].requested_strategy %d is not a redaction strategy", i, int(*redaction.RequestedStrategy))
		}
	}

	// Validate metadata redactions
	for i, redaction := range ri.MetadataRedactions {
		if redaction.Field == "" {
			return fmt.Errorf("metadata_redactions[%d].field cannot be empty", i)
		}
		if redaction.Action == "" {
			return fmt.Errorf("metadata_redactions[%d].action cannot be empty", i)
		}
	}

	return nil
}

// GenerateDocumentHash generates a hash for the original document content
func GenerateDocumentHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// HashFile is GenerateDocumentHash over a file, without reading it into memory.
//
// The audit trail records a verification hash of the original, and computing it used to cost the
// file's whole size in RSS: os.ReadFile followed by sha256.Sum256. Measured on an 80 MB video,
// peak resident memory rose from 30 MB for a scan to 111 MB for the same scan with redaction
// enabled — the difference being one buffer nothing keeps. sha256 is a streaming hash, so a
// 32 KB io.Copy produces the identical digest at a constant cost, and it does so for every
// redactor rather than only for the streaming ones.
//
// An unreadable file returns an empty hash, matching what the caller did with a read error
// before: the audit entry records no hash rather than the redaction failing over its own
// bookkeeping.
func HashFile(path string) string {
	f, err := os.Open(filepath.Clean(path)) // #nosec G304 -- path already vetted by the caller
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
