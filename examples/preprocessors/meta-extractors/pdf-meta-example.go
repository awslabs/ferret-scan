// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"

	meta_extract_pdflib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-pdflib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run pdf-meta-example.go <file.pdf>")
		return
	}

	metadata, err := meta_extract_pdflib.ExtractMetadata(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("File: %s\n", metadata.Filename)
	fmt.Printf("Type: %s\n", metadata.MimeType)
	fmt.Printf("Version: %s\n", metadata.Version)
	fmt.Printf("Pages: %d\n", metadata.PageCount)
	fmt.Printf("Title: %s\n", metadata.Title)
	fmt.Printf("Author: %s\n", metadata.Author)
	fmt.Printf("Creator: %s\n", metadata.Creator)
	fmt.Printf("Producer: %s\n", metadata.Producer)
	for key, value := range metadata.Properties {
		fmt.Printf("%s: %s\n", key, value)
	}
}
