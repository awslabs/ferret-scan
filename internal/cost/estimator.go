// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cost

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CostEstimate represents the estimated cost breakdown for GenAI services
type CostEstimate struct {
	TotalCost        float64 `json:"total_cost"`
	TextractCost     float64 `json:"textract_cost"`
	ComprehendCost   float64 `json:"comprehend_cost"`
	TranscribeCost   float64 `json:"transcribe_cost"`
	FileCount        int     `json:"file_count"`
	EstimatedPages   int     `json:"estimated_pages"`
	EstimatedChars   int64   `json:"estimated_chars"`
	EstimatedMinutes float64 `json:"estimated_minutes"`
}

// Estimator calculates GenAI service costs
type Estimator struct {
	TextractCostPerPage       float64
	ComprehendCostPer100Chars float64
	TranscribeCostPerMinute   float64
}

// NewEstimator creates a new cost estimator with current AWS pricing
func NewEstimator() *Estimator {
	return &Estimator{
		TextractCostPerPage:       0.0015, // $0.0015 per page
		ComprehendCostPer100Chars: 0.0001, // $0.0001 per 100 characters
		TranscribeCostPerMinute:   0.024,  // $0.024 per minute
	}
}

// EstimateFiles calculates the estimated cost for processing multiple files
func (e *Estimator) EstimateFiles(filePaths []string, genaiServices map[string]bool) (*CostEstimate, error) {
	estimate := &CostEstimate{
		FileCount: len(filePaths),
	}

	for _, filePath := range filePaths {
		fileEst, err := e.estimateFile(filePath, genaiServices)
		if err != nil {
			continue // Skip files we can't estimate
		}

		estimate.TotalCost += fileEst.TotalCost
		estimate.TextractCost += fileEst.TextractCost
		estimate.ComprehendCost += fileEst.ComprehendCost
		estimate.TranscribeCost += fileEst.TranscribeCost
		estimate.EstimatedPages += fileEst.EstimatedPages
		estimate.EstimatedChars += fileEst.EstimatedChars
		estimate.EstimatedMinutes += fileEst.EstimatedMinutes
	}

	return estimate, nil
}

// estimateFile calculates cost for a single file
func (e *Estimator) estimateFile(filePath string, genaiServices map[string]bool) (*CostEstimate, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	estimate := &CostEstimate{}

	// Estimate based on file type and size
	switch {
	case isImageFile(ext):
		if genaiServices["textract"] {
			estimate.EstimatedPages = 1
			estimate.TextractCost = e.TextractCostPerPage
		}
		// Images typically have minimal text for Comprehend
		if genaiServices["comprehend"] {
			estimate.EstimatedChars = 500 // Metadata + OCR text
			estimate.ComprehendCost = float64(estimate.EstimatedChars) / 100.0 * e.ComprehendCostPer100Chars
		}

	case isDocumentFile(ext):
		if genaiServices["textract"] {
			// Estimate pages based on file size (rough approximation)
			estimate.EstimatedPages = int(info.Size() / (50 * 1024)) // ~50KB per page
			if estimate.EstimatedPages < 1 {
				estimate.EstimatedPages = 1
			}
			estimate.TextractCost = float64(estimate.EstimatedPages) * e.TextractCostPerPage
		}
		if genaiServices["comprehend"] {
			// Estimate characters based on file size
			estimate.EstimatedChars = info.Size() / 2 // Rough text extraction ratio
			estimate.ComprehendCost = float64(estimate.EstimatedChars) / 100.0 * e.ComprehendCostPer100Chars
		}

	case isAudioFile(ext):
		if genaiServices["transcribe"] {
			// Estimate duration based on file size (rough approximation)
			estimate.EstimatedMinutes = float64(info.Size()) / (1024 * 1024) // ~1MB per minute
			if estimate.EstimatedMinutes < 0.1 {
				estimate.EstimatedMinutes = 0.1
			}
			estimate.TranscribeCost = estimate.EstimatedMinutes * e.TranscribeCostPerMinute
		}
		if genaiServices["comprehend"] {
			// Transcribed text for Comprehend
			estimate.EstimatedChars = int64(estimate.EstimatedMinutes * 1000) // ~1000 chars per minute
			estimate.ComprehendCost += float64(estimate.EstimatedChars) / 100.0 * e.ComprehendCostPer100Chars
		}

	case isTextFile(ext):
		if genaiServices["comprehend"] {
			// Direct text analysis
			estimate.EstimatedChars = info.Size()
			estimate.ComprehendCost = float64(estimate.EstimatedChars) / 100.0 * e.ComprehendCostPer100Chars
		}
	}

	estimate.TotalCost = estimate.TextractCost + estimate.ComprehendCost + estimate.TranscribeCost
	return estimate, nil
}

// FormatCostSummary returns a human-readable cost breakdown
func (e *CostEstimate) FormatCostSummary() string {
	if e.TotalCost == 0 {
		return "Estimated cost: $0.00 (no GenAI services needed)"
	}

	summary := fmt.Sprintf("Estimated cost: $%.4f", e.TotalCost)

	var breakdown []string
	if e.TextractCost > 0 {
		breakdown = append(breakdown, fmt.Sprintf("Textract: $%.4f", e.TextractCost))
	}
	if e.ComprehendCost > 0 {
		breakdown = append(breakdown, fmt.Sprintf("Comprehend: $%.4f", e.ComprehendCost))
	}
	if e.TranscribeCost > 0 {
		breakdown = append(breakdown, fmt.Sprintf("Transcribe: $%.4f", e.TranscribeCost))
	}

	if len(breakdown) > 0 {
		summary += " (" + strings.Join(breakdown, ", ") + ")"
	}

	return summary
}

// FormatDetailedSummary returns detailed cost information
func (e *CostEstimate) FormatDetailedSummary() string {
	summary := e.FormatCostSummary() + "\n"
	summary += fmt.Sprintf("Files: %d", e.FileCount)

	if e.EstimatedPages > 0 {
		summary += fmt.Sprintf(", Pages: %d", e.EstimatedPages)
	}
	if e.EstimatedChars > 0 {
		summary += fmt.Sprintf(", Characters: %d", e.EstimatedChars)
	}
	if e.EstimatedMinutes > 0 {
		summary += fmt.Sprintf(", Audio: %.1f min", e.EstimatedMinutes)
	}

	return summary
}

// Helper functions for file type detection
func isImageFile(ext string) bool {
	imageExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".bmp": true, ".tiff": true, ".tif": true, ".webp": true,
	}
	return imageExts[ext]
}

func isDocumentFile(ext string) bool {
	docExts := map[string]bool{
		".pdf": true, ".docx": true, ".xlsx": true, ".pptx": true,
		".odt": true, ".ods": true, ".odp": true,
	}
	return docExts[ext]
}

func isAudioFile(ext string) bool {
	audioExts := map[string]bool{
		".mp3": true, ".wav": true, ".m4a": true, ".flac": true,
	}
	return audioExts[ext]
}

func isTextFile(ext string) bool {
	textExts := map[string]bool{
		".txt": true, ".log": true, ".csv": true, ".json": true,
		".xml": true, ".yaml": true, ".yml": true, ".md": true,
	}
	return textExts[ext]
}
