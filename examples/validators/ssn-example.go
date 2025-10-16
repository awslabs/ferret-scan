// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"

	"ferret-scan/internal/validators/ssn"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ssn-example.go <text-file>")
		return
	}

	validator := ssn.NewValidator()
	matches, err := validator.Validate(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("SSNs found: %d\n", len(matches))
	for i, match := range matches {
		fmt.Printf("%d. %s (%.1f%% confidence)\n", i+1, match.Text, match.Confidence)
	}
}
