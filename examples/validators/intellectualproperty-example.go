// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"

	"ferret-scan/internal/config"
	"ferret-scan/internal/validators/intellectualproperty"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run intellectualproperty-example.go <text-file>")
		return
	}

	validator := intellectualproperty.NewValidator()
	cfg, _ := config.LoadConfig("")
	validator.Configure(cfg)

	matches, err := validator.Validate(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("IP items found: %d\n", len(matches))
	for i, match := range matches {
		fmt.Printf("%d. %s: %s (%.1f%% confidence)\n", i+1, match.Type, match.Text, match.Confidence)
	}
}
