// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"
	"strings"

	textract_extractor_lib "ferret-scan/internal/preprocessors/text-extractors/textract-extractor-lib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run textract-example.go <file1.pdf> [file2.png] ...")
		fmt.Println("Supported formats: PDF, PNG, JPEG, TIFF")
		fmt.Println("Note: Requires AWS credentials and incurs costs (~$0.0015 per page/image)")
		return
	}

	region := "us-east-1"
	if len(os.Args) > 2 && strings.HasPrefix(os.Args[1], "--region=") {
		region = strings.TrimPrefix(os.Args[1], "--region=")
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	// Process each file provided as argument
	for _, filePath := range os.Args[1:] {
		processFile(filePath, region)
		fmt.Println("\n" + strings.Repeat("=", 70) + "\n")
	}
}

func processFile(filePath, region string) {
	// Check if file type is supported
	if !textract_extractor_lib.IsSupportedFileType(filePath) {
		fmt.Printf("Error: Unsupported file type for %s\n", filePath)
		return
	}

	// Validate AWS credentials
	if err := textract_extractor_lib.ValidateAWSCredentials(region); err != nil {
		fmt.Printf("AWS credentials error: %v\n", err)
		return
	}

	// Estimate cost
	if cost, err := textract_extractor_lib.EstimateTextractCost(filePath); err == nil {
		fmt.Printf("Estimated cost: $%.4f\n", cost)
	}

	// Extract text using Textract
	content, err := textract_extractor_lib.ExtractText(filePath, region)
	if err != nil {
		fmt.Printf("Error processing %s: %v\n", filePath, err)
		return
	}

	// Print file info
	fmt.Printf("=== Textract OCR Results for %s ===\n\n", filePath)

	// Display document information
	fmt.Printf("Document type: %s\n", content.DocumentType)
	fmt.Printf("Page count: %d\n", content.PageCount)
	fmt.Printf("Word count: %d\n", content.WordCount)
	fmt.Printf("Character count: %d\n", content.CharCount)
	fmt.Printf("Line count: %d\n", content.LineCount)
	fmt.Printf("Confidence: %.2f%%\n", content.Confidence)

	// Print the extracted text
	fmt.Println("\nExtracted Text:")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(content.Text)
}
