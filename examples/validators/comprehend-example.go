// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	comprehend_analyzer_lib "ferret-scan/internal/validators/comprehend/comprehend-analyzer-lib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run comprehend-example.go <text-file> [--region=us-east-1]")
		fmt.Println("Note: Requires AWS credentials and incurs costs (~$0.0001 per 100 characters)")
		return
	}

	region := "us-east-1"
	filePath := os.Args[1]

	if len(os.Args) > 2 && strings.HasPrefix(os.Args[2], "--region=") {
		region = strings.TrimPrefix(os.Args[2], "--region=")
	}

	processFile(filePath, region)
}

func processFile(filePath, region string) {
	// Read the text file
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file %s: %v\n", filePath, err)
		return
	}
	defer file.Close()

	textBytes, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filePath, err)
		return
	}

	text := string(textBytes)
	if strings.TrimSpace(text) == "" {
		fmt.Printf("File %s is empty or contains no text\n", filePath)
		return
	}

	// Validate AWS credentials
	if err := comprehend_analyzer_lib.ValidateAWSCredentials(region); err != nil {
		fmt.Printf("AWS credentials error: %v\n", err)
		return
	}

	// Estimate cost
	cost := comprehend_analyzer_lib.EstimateComprehendCost(len(text))
	fmt.Printf("Estimated cost: $%.6f\n", cost)

	// Analyze PII using Comprehend
	result, err := comprehend_analyzer_lib.AnalyzePII(text, filePath, region)
	if err != nil {
		fmt.Printf("Error analyzing %s: %v\n", filePath, err)
		return
	}

	// Print results
	fmt.Printf("\n=== Comprehend PII Analysis for %s ===\n\n", filePath)
	fmt.Printf("Document type: %s\n", result.DocumentType)
	fmt.Printf("Has PII: %v\n", result.HasPII)
	fmt.Printf("Has PHI: %v\n", result.HasPHI)
	fmt.Printf("Risk level: %s\n", result.RiskLevel)
	fmt.Printf("PII entities found: %d\n\n", len(result.PIIEntities))

	if len(result.PIIEntities) > 0 {
		fmt.Println("Detected PII Entities:")
		fmt.Println(strings.Repeat("-", 60))
		for i, entity := range result.PIIEntities {
			fmt.Printf("%d. Type: %s\n", i+1, entity.Type)
			fmt.Printf("   Text: %s\n", entity.Text)
			fmt.Printf("   Confidence: %.2f%%\n", entity.Confidence*100)
			fmt.Printf("   Position: %d-%d\n\n", entity.BeginOffset, entity.EndOffset)
		}
	}
}
