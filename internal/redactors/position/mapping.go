// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package position

import (
	"encoding/json"
	"fmt"
	"time"

	"ferret-scan/internal/redactors"
)

// PositionMappingManager manages position mappings for documents
type PositionMappingManager struct {
	// mappings stores position mappings by document ID
	mappings map[string]*DocumentPositionMapping

	// correlator is the position correlator to use
	correlator PositionCorrelator
}

// DocumentPositionMapping contains all position mappings for a document
type DocumentPositionMapping struct {
	// DocumentID is the unique identifier for the document
	DocumentID string `json:"document_id"`

	// DocumentType is the type of document (PDF, DOCX, etc.)
	DocumentType string `json:"document_type"`

	// CreationTime is when this mapping was created
	CreationTime time.Time `json:"creation_time"`

	// Mappings contains all position mappings for this document
	Mappings []redactors.PositionMapping `json:"mappings"`

	// Statistics contains mapping statistics
	Statistics MappingStatistics `json:"statistics"`

	// Metadata contains additional mapping metadata
	Metadata map[string]interface{} `json:"metadata"`
}

// MappingStatistics contains statistics about position mappings
type MappingStatistics struct {
	// TotalMappings is the total number of position mappings
	TotalMappings int `json:"total_mappings"`

	// HighConfidenceMappings is the number of high-confidence mappings (>= 0.8)
	HighConfidenceMappings int `json:"high_confidence_mappings"`

	// MediumConfidenceMappings is the number of medium-confidence mappings (0.5-0.8)
	MediumConfidenceMappings int `json:"medium_confidence_mappings"`

	// LowConfidenceMappings is the number of low-confidence mappings (< 0.5)
	LowConfidenceMappings int `json:"low_confidence_mappings"`

	// AverageConfidence is the average confidence score
	AverageConfidence float64 `json:"average_confidence"`

	// MethodCounts contains counts by correlation method
	MethodCounts map[string]int `json:"method_counts"`
}

// NewPositionMappingManager creates a new position mapping manager
func NewPositionMappingManager(correlator PositionCorrelator) *PositionMappingManager {
	if correlator == nil {
		correlator = NewDefaultPositionCorrelator()
	}

	return &PositionMappingManager{
		mappings:   make(map[string]*DocumentPositionMapping),
		correlator: correlator,
	}
}

// CreateMapping creates position mappings for a document
func (pmm *PositionMappingManager) CreateMapping(documentID, documentType string, extractedText string, originalContent []byte, positions []redactors.TextPosition) (*DocumentPositionMapping, error) {
	if documentID == "" {
		return nil, fmt.Errorf("document ID cannot be empty")
	}

	if len(positions) == 0 {
		return nil, fmt.Errorf("no positions provided")
	}

	// Correlate positions
	correlations, err := pmm.correlator.CorrelatePositions(positions, extractedText, originalContent, documentType)
	if err != nil {
		return nil, fmt.Errorf("failed to correlate positions: %w", err)
	}

	// Convert correlations to position mappings
	mappings := make([]redactors.PositionMapping, 0, len(correlations))
	for _, correlation := range correlations {
		if correlation.OriginalPosition != nil {
			mapping := redactors.PositionMapping{
				ExtractedPosition: correlation.ExtractedPosition,
				OriginalPosition:  *correlation.OriginalPosition,
				DocumentType:      documentType,
				PageNumber:        correlation.OriginalPosition.Page,
				Region:            correlation.OriginalPosition.BoundingBox,
				ConfidenceScore:   correlation.ConfidenceScore,
			}
			mappings = append(mappings, mapping)
		}
	}

	// Calculate statistics
	stats := pmm.calculateStatistics(correlations)

	// Create document position mapping
	docMapping := &DocumentPositionMapping{
		DocumentID:   documentID,
		DocumentType: documentType,
		CreationTime: time.Now(),
		Mappings:     mappings,
		Statistics:   stats,
		Metadata: map[string]interface{}{
			"extracted_text_length": len(extractedText),
			"original_content_size": len(originalContent),
			"correlator_config": map[string]interface{}{
				"confidence_threshold":   pmm.correlator.GetConfidenceThreshold(),
				"context_window_size":    pmm.correlator.GetContextWindowSize(),
				"fuzzy_matching_enabled": pmm.correlator.IsFuzzyMatchingEnabled(),
			},
		},
	}

	// Store the mapping
	pmm.mappings[documentID] = docMapping

	return docMapping, nil
}

// GetMapping retrieves a position mapping by document ID
func (pmm *PositionMappingManager) GetMapping(documentID string) (*DocumentPositionMapping, bool) {
	mapping, exists := pmm.mappings[documentID]
	return mapping, exists
}

// GetAllMappings returns all position mappings
func (pmm *PositionMappingManager) GetAllMappings() map[string]*DocumentPositionMapping {
	// Return a copy to prevent external modification
	result := make(map[string]*DocumentPositionMapping)
	for id, mapping := range pmm.mappings {
		result[id] = mapping
	}
	return result
}

// RemoveMapping removes a position mapping
func (pmm *PositionMappingManager) RemoveMapping(documentID string) error {
	if _, exists := pmm.mappings[documentID]; !exists {
		return fmt.Errorf("mapping for document %s not found", documentID)
	}

	delete(pmm.mappings, documentID)
	return nil
}

// UpdateCorrelator updates the position correlator
func (pmm *PositionMappingManager) UpdateCorrelator(correlator PositionCorrelator) {
	if correlator != nil {
		pmm.correlator = correlator
	}
}

// GetCorrelator returns the current position correlator
func (pmm *PositionMappingManager) GetCorrelator() PositionCorrelator {
	return pmm.correlator
}

// ExportMapping exports a position mapping to JSON
func (pmm *PositionMappingManager) ExportMapping(documentID string) ([]byte, error) {
	mapping, exists := pmm.mappings[documentID]
	if !exists {
		return nil, fmt.Errorf("mapping for document %s not found", documentID)
	}

	return json.MarshalIndent(mapping, "", "  ")
}

// ExportAllMappings exports all position mappings to JSON
func (pmm *PositionMappingManager) ExportAllMappings() ([]byte, error) {
	exportData := struct {
		ExportTime time.Time                           `json:"export_time"`
		Mappings   map[string]*DocumentPositionMapping `json:"mappings"`
		Summary    map[string]interface{}              `json:"summary"`
	}{
		ExportTime: time.Now(),
		Mappings:   pmm.mappings,
		Summary: map[string]interface{}{
			"total_documents": len(pmm.mappings),
			"correlator_type": fmt.Sprintf("%T", pmm.correlator),
		},
	}

	return json.MarshalIndent(exportData, "", "  ")
}

// ImportMapping imports a position mapping from JSON
func (pmm *PositionMappingManager) ImportMapping(data []byte) (*DocumentPositionMapping, error) {
	var mapping DocumentPositionMapping
	if err := json.Unmarshal(data, &mapping); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mapping: %w", err)
	}

	// Validate the mapping
	if err := pmm.validateMapping(&mapping); err != nil {
		return nil, fmt.Errorf("invalid mapping: %w", err)
	}

	// Store the mapping
	pmm.mappings[mapping.DocumentID] = &mapping

	return &mapping, nil
}

// ValidateMapping validates a position mapping
func (pmm *PositionMappingManager) validateMapping(mapping *DocumentPositionMapping) error {
	if mapping.DocumentID == "" {
		return fmt.Errorf("document ID cannot be empty")
	}

	if mapping.DocumentType == "" {
		return fmt.Errorf("document type cannot be empty")
	}

	if mapping.CreationTime.IsZero() {
		return fmt.Errorf("creation time cannot be zero")
	}

	// Validate individual mappings
	for i, posMapping := range mapping.Mappings {
		if err := pmm.validatePositionMapping(&posMapping); err != nil {
			return fmt.Errorf("invalid position mapping at index %d: %w", i, err)
		}
	}

	return nil
}

// validatePositionMapping validates a single position mapping
func (pmm *PositionMappingManager) validatePositionMapping(mapping *redactors.PositionMapping) error {
	// Validate extracted position
	if mapping.ExtractedPosition.Line < 1 {
		return fmt.Errorf("extracted position line must be >= 1")
	}

	if mapping.ExtractedPosition.StartChar < 0 {
		return fmt.Errorf("extracted position start char must be >= 0")
	}

	if mapping.ExtractedPosition.EndChar < mapping.ExtractedPosition.StartChar {
		return fmt.Errorf("extracted position end char must be >= start char")
	}

	// Validate confidence score
	if mapping.ConfidenceScore < 0.0 || mapping.ConfidenceScore > 1.0 {
		return fmt.Errorf("confidence score must be between 0.0 and 1.0")
	}

	// Validate original position
	if mapping.OriginalPosition.Page < 0 {
		return fmt.Errorf("original position page must be >= 0")
	}

	if mapping.OriginalPosition.CharOffset < 0 {
		return fmt.Errorf("original position char offset must be >= 0")
	}

	return nil
}

// calculateStatistics calculates mapping statistics from correlations
func (pmm *PositionMappingManager) calculateStatistics(correlations []*PositionCorrelation) MappingStatistics {
	stats := MappingStatistics{
		TotalMappings: len(correlations),
		MethodCounts:  make(map[string]int),
	}

	if len(correlations) == 0 {
		return stats
	}

	totalConfidence := 0.0

	for _, correlation := range correlations {
		confidence := correlation.ConfidenceScore
		totalConfidence += confidence

		// Categorize by confidence
		if confidence >= 0.8 {
			stats.HighConfidenceMappings++
		} else if confidence >= 0.5 {
			stats.MediumConfidenceMappings++
		} else {
			stats.LowConfidenceMappings++
		}

		// Count by method
		method := correlation.Method.String()
		stats.MethodCounts[method]++
	}

	stats.AverageConfidence = totalConfidence / float64(len(correlations))

	return stats
}

// GetMappingStatistics returns aggregated statistics for all mappings
func (pmm *PositionMappingManager) GetMappingStatistics() map[string]interface{} {
	totalMappings := 0
	totalHighConfidence := 0
	totalMediumConfidence := 0
	totalLowConfidence := 0
	totalConfidence := 0.0
	methodCounts := make(map[string]int)
	documentTypes := make(map[string]int)

	for _, mapping := range pmm.mappings {
		stats := mapping.Statistics
		totalMappings += stats.TotalMappings
		totalHighConfidence += stats.HighConfidenceMappings
		totalMediumConfidence += stats.MediumConfidenceMappings
		totalLowConfidence += stats.LowConfidenceMappings
		totalConfidence += stats.AverageConfidence * float64(stats.TotalMappings)

		// Aggregate method counts
		for method, count := range stats.MethodCounts {
			methodCounts[method] += count
		}

		// Count document types
		documentTypes[mapping.DocumentType]++
	}

	averageConfidence := 0.0
	if totalMappings > 0 {
		averageConfidence = totalConfidence / float64(totalMappings)
	}

	return map[string]interface{}{
		"total_documents":            len(pmm.mappings),
		"total_mappings":             totalMappings,
		"high_confidence_mappings":   totalHighConfidence,
		"medium_confidence_mappings": totalMediumConfidence,
		"low_confidence_mappings":    totalLowConfidence,
		"average_confidence":         averageConfidence,
		"method_counts":              methodCounts,
		"document_types":             documentTypes,
	}
}

// FindMappingByPosition finds a position mapping by extracted position
func (pmm *PositionMappingManager) FindMappingByPosition(documentID string, position redactors.TextPosition) (*redactors.PositionMapping, error) {
	mapping, exists := pmm.mappings[documentID]
	if !exists {
		return nil, fmt.Errorf("mapping for document %s not found", documentID)
	}

	// Find the mapping that contains this position
	for _, posMapping := range mapping.Mappings {
		if pmm.positionContains(posMapping.ExtractedPosition, position) {
			return &posMapping, nil
		}
	}

	return nil, fmt.Errorf("no mapping found for position %+v", position)
}

// positionContains checks if a position range contains another position
func (pmm *PositionMappingManager) positionContains(container, contained redactors.TextPosition) bool {
	if container.Line != contained.Line {
		return false
	}

	return contained.StartChar >= container.StartChar && contained.EndChar <= container.EndChar
}

// Clear removes all position mappings
func (pmm *PositionMappingManager) Clear() {
	pmm.mappings = make(map[string]*DocumentPositionMapping)
}

// GetMappingCount returns the total number of mappings
func (pmm *PositionMappingManager) GetMappingCount() int {
	return len(pmm.mappings)
}
