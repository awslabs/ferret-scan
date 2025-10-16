// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	// OriginalFileHash is a hash of the original document for integrity verification
	OriginalFileHash string `json:"original_file_hash"`

	// RedactedFileHash is a hash of the redacted document for integrity verification
	RedactedFileHash string `json:"redacted_file_hash"`

	// RedactionSummary contains summary statistics about the redaction
	RedactionSummary RedactionSummary `json:"redaction_summary"`

	// ContentRedactions contains audit information about content redactions performed
	ContentRedactions []ContentRedaction `json:"content_redactions"`

	// MetadataRedactions contains audit information about metadata redactions performed
	MetadataRedactions []MetadataRedaction `json:"metadata_redactions"`

	// RedactionConfig contains the configuration used for redaction
	RedactionConfig *RedactionConfigSnapshot `json:"redaction_config,omitempty"`
}

// RedactionSummary contains summary statistics about redactions performed
type RedactionSummary struct {
	// TotalRedactions is the total number of redactions performed
	TotalRedactions int `json:"total_redactions"`

	// DataTypes is a list of data types that were redacted
	DataTypes []string `json:"data_types"`

	// Strategy is the redaction strategy used
	Strategy RedactionStrategy `json:"strategy"`

	// ProcessingTime is the time taken to perform redaction
	ProcessingTime time.Duration `json:"processing_time"`

	// SuccessfulRedactions is the number of successful redactions
	SuccessfulRedactions int `json:"successful_redactions"`

	// FailedRedactions is the number of failed redactions
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

	// RedactedText is the replacement text (for audit purposes)
	RedactedText string `json:"redacted_text"`

	// Strategy is the redaction strategy used
	Strategy RedactionStrategy `json:"strategy"`

	// Confidence is the confidence level of the detection
	Confidence float64 `json:"confidence"`

	// Timestamp is when this redaction was performed
	Timestamp time.Time `json:"timestamp"`
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

// RedactionConfigSnapshot contains a snapshot of the redaction configuration
type RedactionConfigSnapshot struct {
	// DefaultStrategy is the default redaction strategy used
	DefaultStrategy string `json:"default_strategy"`

	// DocumentTypeSettings contains the document type settings used
	DocumentTypeSettings map[string]interface{} `json:"document_type_settings"`

	// DataTypeSettings contains the data type settings used
	DataTypeSettings map[string]interface{} `json:"data_type_settings"`

	// PositionCorrelationSettings contains the position correlation settings
	PositionCorrelationSettings map[string]interface{} `json:"position_correlation_settings"`
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

	// Add data type if not already present
	found := false
	for _, dt := range ri.RedactionSummary.DataTypes {
		if dt == redaction.DataType {
			found = true
			break
		}
	}
	if !found {
		ri.RedactionSummary.DataTypes = append(ri.RedactionSummary.DataTypes, redaction.DataType)
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

// SetRedactionConfig sets the redaction configuration snapshot
func (ri *RedactionAuditLog) SetRedactionConfig(config *RedactionConfigSnapshot) {
	ri.RedactionConfig = config
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

// FromJSON creates a RedactionIndex from JSON data
func FromJSON(data []byte) (*RedactionAuditLog, error) {
	var index RedactionAuditLog
	err := json.Unmarshal(data, &index)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal redaction index: %w", err)
	}
	return &index, nil
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

// GenerateContextHash generates a hash for surrounding context
func GenerateContextHash(context string) string {
	hash := sha256.Sum256([]byte(context))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter hash
}
