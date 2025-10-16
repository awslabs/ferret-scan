// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textract_extractor_lib

// GENAI_DISABLED: This entire file has been disabled as part of GenAI feature removal
// The AWS SDK v2 dependencies required for this functionality have been removed from go.mod
// to reduce binary size and eliminate cloud service dependencies.

/*
import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/textract"
	"github.com/aws/aws-sdk-go-v2/service/textract/types"
)
*/

/*
// ExtractedContent represents the content extracted by Textract
type ExtractedContent struct {
	Filename     string
	DocumentType string
	PageCount    int
	WordCount    int
	CharCount    int
	LineCount    int
	Text         string
	Confidence   float64
}

// ExtractText extracts text from a document using Amazon Textract
func ExtractText(filePath, region string) (*ExtractedContent, error) {
	// Validate and clean the file path to prevent path traversal
	if strings.Contains(filePath, "..") {
		return nil, fmt.Errorf("path traversal not allowed in file path")
	}
	cleanPath := filepath.Clean(filePath)

	// Read the file
	// #nosec G304 - path traversal protection implemented above with strings.Contains check and filepath.Clean
	fileData, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Create context with timeout for AWS operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create Textract client
	client := textract.NewFromConfig(cfg)

	// Prepare the input
	input := &textract.DetectDocumentTextInput{
		Document: &types.Document{
			Bytes: fileData,
		},
	}

	// Call Textract
	result, err := client.DetectDocumentText(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("textract API call failed: %w", err)
	}

	// Process the results
	content := &ExtractedContent{
		Filename:     filepath.Base(filePath),
		DocumentType: getDocumentType(filePath),
		PageCount:    1, // DetectDocumentText processes single page
	}

	var textBuilder strings.Builder
	var totalConfidence float32
	var confidenceCount int

	for _, block := range result.Blocks {
		if block.BlockType == types.BlockTypeLine {
			if block.Text != nil {
				textBuilder.WriteString(*block.Text)
				textBuilder.WriteString("\n")
				content.LineCount++
			}
			if block.Confidence != nil {
				totalConfidence += *block.Confidence
				confidenceCount++
			}
		}
	}

	content.Text = textBuilder.String()
	content.CharCount = len(content.Text)
	content.WordCount = countWords(content.Text)

	if confidenceCount > 0 {
		content.Confidence = float64(totalConfidence) / float64(confidenceCount)
	}

	return content, nil
}

// getDocumentType determines the document type based on file extension
func getDocumentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".pdf":
		return "PDF Document"
	case ".png":
		return "PNG Image"
	case ".jpg", ".jpeg":
		return "JPEG Image"
	case ".tiff", ".tif":
		return "TIFF Image"
	default:
		return "Document"
	}
}

// countWords counts the number of words in the text
func countWords(text string) int {
	if text == "" {
		return 0
	}
	words := strings.Fields(text)
	return len(words)
}

// IsSupportedFileType checks if the file type is supported by Textract
func IsSupportedFileType(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	supportedTypes := map[string]bool{
		".pdf":  true,
		".png":  true,
		".jpg":  true,
		".jpeg": true,
		".tiff": true,
		".tif":  true,
	}
	return supportedTypes[ext]
}

// ValidateAWSCredentials checks if AWS credentials are available
func ValidateAWSCredentials(region string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Try to get credentials
	_, err = cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("AWS credentials not found or invalid: %w", err)
	}

	return nil
}

// EstimateTextractCost provides a rough cost estimate for processing a file
func EstimateTextractCost(filePath string) (float64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to get file info: %w", err)
	}

	// Textract pricing is per page for PDFs, per image for images
	// As of 2024: $0.0015 per page/image for DetectDocumentText
	const costPerPage = 0.0015

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".pdf" {
		// For PDFs, estimate pages based on file size (rough estimate)
		// Average PDF page is about 100KB
		estimatedPages := int(fileInfo.Size() / (100 * 1024))
		if estimatedPages < 1 {
			estimatedPages = 1
		}
		return float64(estimatedPages) * costPerPage, nil
	} else {
		// For images, it's one page
		return costPerPage, nil
	}
}
*/
