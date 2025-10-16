// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"

	text_extract_pdftextlib "ferret-scan/internal/preprocessors/text-extractors/text-extract-pdftextlib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run pdf-text-example.go <file.pdf>")
		return
	}

	content, err := text_extract_pdftextlib.ExtractText(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Filename: %s\n", content.Filename)
	fmt.Printf("Words: %d, Chars: %d, Pages: %d\n", content.WordCount, content.CharCount, content.PageCount)
	fmt.Printf("Text:\n%s\n", content.Text)
}
