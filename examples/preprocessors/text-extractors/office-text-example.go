// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"

	text_extract_officetextlib "ferret-scan/internal/preprocessors/text-extractors/text-extract-officetextlib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run office-text-example.go <file.docx>")
		return
	}

	content, err := text_extract_officetextlib.ExtractText(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Format: %s\n", content.Format)
	fmt.Printf("Words: %d, Chars: %d\n", content.WordCount, content.CharCount)
	fmt.Printf("Text:\n%s\n", content.Text)
}
