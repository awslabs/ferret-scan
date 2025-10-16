// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"
	"strings"

	"ferret-scan/internal/validators/creditcard"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run creditcard-example.go <text-file>")
		fmt.Println("Detects credit card numbers in text files")
		return
	}

	filePath := os.Args[1]
	processFile(filePath)
}

func processFile(filePath string) {
	// Create validator
	validator := creditcard.NewValidator()

	// Validate the file
	matches, err := validator.Validate(filePath)
	if err != nil {
		fmt.Printf("Error processing %s: %v\n", filePath, err)
		return
	}

	// Print results
	fmt.Printf("=== Credit Card Detection Results for %s ===\n\n", filePath)
	fmt.Printf("Credit card numbers found: %d\n\n", len(matches))

	if len(matches) > 0 {
		fmt.Println("Detected Credit Cards:")
		fmt.Println(strings.Repeat("-", 60))
		for i, match := range matches {
			fmt.Printf("%d. Type: %s\n", i+1, match.Type)
			fmt.Printf("   Text: %s\n", match.Text)
			fmt.Printf("   Confidence: %.1f%%\n", match.Confidence)
			fmt.Printf("   Line: %d\n", match.LineNumber)
			if match.Context.FullLine != "" {
				fmt.Printf("   Context: %s\n", match.Context.FullLine)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("No credit card numbers detected.")
	}
}
