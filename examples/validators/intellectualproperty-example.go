// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run intellectualproperty-example.go <text-file>")
		return
	}

	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	validator := intellectualproperty.NewValidator()
	cfg, _ := config.LoadConfig("")
	validator.Configure(cfg)

	matches, err := validator.ValidateContent(string(content), os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("IP items found: %d\n", len(matches))
	for i, match := range matches {
		fmt.Printf("%d. %s: %s (%.1f%% confidence)\n", i+1, match.Type, match.Text, match.Confidence)
	}
}
