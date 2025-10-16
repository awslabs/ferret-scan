// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples
// +build examples

package main

import (
	"fmt"
	"os"
	"strings"

	transcribe_extractor_lib "ferret-scan/internal/preprocessors/audio-extractors/transcribe-extractor-lib"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run transcribe-example.go <audio.mp3> [--region=us-east-1] [--bucket=my-bucket]")
		fmt.Println("Supported formats: MP3, WAV, M4A, FLAC")
		fmt.Println("Options:")
		fmt.Println("  --region=<region>  AWS region (default: us-east-1)")
		fmt.Println("  --bucket=<bucket>  S3 bucket name (optional, creates temporary if not specified)")
		fmt.Println("Note: Requires AWS credentials and incurs costs (~$0.024 per minute)")
		return
	}

	region := "us-east-1"
	bucket := ""
	filePath := ""

	// Parse arguments
	for i, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "--region=") {
			region = strings.TrimPrefix(arg, "--region=")
		} else if strings.HasPrefix(arg, "--bucket=") {
			bucket = strings.TrimPrefix(arg, "--bucket=")
		} else if arg == "--file" && i+1 < len(os.Args)-1 {
			filePath = os.Args[i+2]
		} else if !strings.HasPrefix(arg, "--") && filePath == "" {
			filePath = arg
		}
	}

	if filePath == "" {
		fmt.Println("Error: No audio file specified")
		return
	}

	processFile(filePath, region, bucket)
}

func processFile(filePath, region, bucket string) {
	// Check if file type is supported
	if !transcribe_extractor_lib.IsSupportedAudioType(filePath) {
		fmt.Printf("Error: Unsupported audio type for %s\n", filePath)
		return
	}

	// Validate AWS credentials
	if err := transcribe_extractor_lib.ValidateAWSCredentials(region); err != nil {
		fmt.Printf("AWS credentials error: %v\n", err)
		return
	}

	// Estimate cost
	if cost, err := transcribe_extractor_lib.EstimateTranscribeCost(filePath); err == nil {
		fmt.Printf("Estimated cost: $%.4f\n", cost)
	}

	// Transcribe audio using Transcribe
	if bucket != "" {
		fmt.Printf("Using S3 bucket: %s\n", bucket)
	} else {
		fmt.Println("Using auto-generated temporary bucket")
	}
	content, err := transcribe_extractor_lib.TranscribeText(filePath, region, bucket)
	if err != nil {
		fmt.Printf("Error processing %s: %v\n", filePath, err)
		return
	}

	// Print results
	fmt.Printf("=== Transcribe Audio Results for %s ===\n\n", filePath)
	fmt.Printf("Audio type: %s\n", content.AudioType)
	fmt.Printf("Duration: %.1f seconds\n", content.Duration)
	fmt.Printf("Word count: %d\n", content.WordCount)
	fmt.Printf("Character count: %d\n", content.CharCount)
	fmt.Printf("Confidence: %.2f%%\n", content.Confidence)
	fmt.Printf("Job name: %s\n", content.JobName)

	fmt.Println("\nTranscribed Text:")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(content.Text)
}
