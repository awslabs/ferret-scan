// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"

	meta_extract_exiflib "ferret-scan/internal/preprocessors/meta-extractors/meta-extract-exiflib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run exif-example.go <image.jpg>")
		return
	}

	exifData, err := meta_extract_exiflib.ExtractExif(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("File: %s\n", exifData.FilePath)
	fmt.Printf("Tags: %d\n", len(exifData.Tags))
	fmt.Println("EXIF Data:")
	for _, key := range exifData.GetSortedKeys() {
		fmt.Printf("%s: %s\n", key, exifData.Tags[key])
	}
}
