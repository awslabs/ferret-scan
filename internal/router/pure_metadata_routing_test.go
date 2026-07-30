// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// TestPureMetadataKeepsDocumentBody is the leak gate.
//
// RouteContent used to set DocumentBody = "" for a file whose ProcessedContent
// came from a single *_metadata preprocessor. dual_path_bridge.go gates the entire
// document path on `DocumentBody != ""`, so for those files exactly 1 of the 19
// validators ran: METADATA.
//
// That is the routing outcome for EVERY media type — .jpg/.png/.gif/.tiff/.webp,
// .wav/.mp3/.flac/.m4a, .mp4/.mov — because only one preprocessor is capable for
// those extensions, so ProcessorType carries no "+" and lands in this arm.
//
// The METADATA validator cannot cover for it: it is a field-NAME allowlist scanner
// that emits one coarse type per matching line, so an SSN or a card number inside a
// metadata value is either skipped outright (the field name is not on the list) or
// reported as a single AUTHOR_INFO/DOCUMENT_COMMENTS row. Measured end-to-end: an
// EXIF ImageDescription carrying an SSN, an email and a phone number produced ZERO
// findings of any type at any confidence, and the tool reported the file clean.
func TestPureMetadataKeepsDocumentBody(t *testing.T) {
	const metadataText = "ImageDescription: SSN 456-45-6789 email jane.smith@acmecorp.io\n"

	for _, processorType := range []string{
		"image_metadata",
		"pdf_metadata",
		"office_metadata",
		"audio_metadata",
		"video_metadata",
	} {
		t.Run(processorType, func(t *testing.T) {
			cr := NewContentRouter()
			routed, err := cr.RouteContent(&preprocessors.ProcessedContent{
				Text:          metadataText,
				ProcessorType: processorType,
				OriginalPath:  "asset.bin",
			})
			if err != nil {
				t.Fatalf("RouteContent: %v", err)
			}

			if routed.DocumentBody == "" {
				t.Fatalf("DocumentBody is empty for %s. dual_path_bridge gates the whole "+
					"document path on DocumentBody != \"\", so every text validator is "+
					"skipped and only METADATA runs — an SSN in this text goes unreported "+
					"and the file is declared clean.", processorType)
			}
			if !strings.Contains(routed.DocumentBody, "456-45-6789") {
				t.Errorf("DocumentBody does not carry the metadata text for %s: %q",
					processorType, routed.DocumentBody)
			}

			// The metadata path must keep working — this widens coverage, it does not
			// move the text from one path to the other.
			if len(routed.Metadata) == 0 {
				t.Errorf("%s: Metadata is empty; the metadata path must still receive the "+
					"content as well as the document path", processorType)
			}
		})
	}
}

// TestCombinedPreprocessorsUnaffected pins the boundary of the change.
//
// .pdf/.docx/.xlsx have TWO capable preprocessors, so ProcessorType contains "+",
// identifyPreprocessorType returns "combined_preprocessors", and they route down a
// different branch that always preserved a body. Those file types must be
// byte-identical before and after.
func TestCombinedPreprocessorsUnaffected(t *testing.T) {
	cr := NewContentRouter()
	routed, err := cr.RouteContent(&preprocessors.ProcessedContent{
		Text:          "quarterly numbers\n",
		ProcessorType: "Text Extractor+office_metadata",
		OriginalPath:  "report.docx",
	})
	if err != nil {
		t.Fatalf("RouteContent: %v", err)
	}
	if routed.DocumentBody == "" {
		t.Error("combined-preprocessor routing lost its document body; this branch is " +
			"not the one being changed and must be unaffected")
	}
}

// TestPlainTextRoutingUnaffected is the other boundary: a plain text file already
// took the document path, and must be unchanged.
func TestPlainTextRoutingUnaffected(t *testing.T) {
	cr := NewContentRouter()
	const body = "SSN 456-45-6789\n"
	routed, err := cr.RouteContent(&preprocessors.ProcessedContent{
		Text:          body,
		ProcessorType: "plaintext",
		OriginalPath:  "notes.txt",
	})
	if err != nil {
		t.Fatalf("RouteContent: %v", err)
	}
	if routed.DocumentBody != body {
		t.Errorf("plain-text DocumentBody = %q, want %q", routed.DocumentBody, body)
	}
}
