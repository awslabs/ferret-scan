// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// TestSeparateCombinedOutput_BodySectionsAreNotFused is the regression test for
// the section-join defect.
//
// splitByPreprocessorSeparators TrimSpace-es each section, so a section carries
// no trailing newline. separateCombinedPreprocessorOutput then wrote consecutive
// document-body sections back to back with nothing between them, so the last line
// of one section and the first line of the next collapsed onto a single logical
// line. A validator that scans line by line then sees one fused line instead of
// two — which can merge two adjacent values into one unrecognized token or split
// a boundary value, i.e. a recall bug at every body-section seam.
func TestSeparateCombinedOutput_BodySectionsAreNotFused(t *testing.T) {
	cr := NewContentRouter()

	// Two document-body sections (a non-metadata preprocessor name). The last line
	// of the first and the first line of the second must stay on separate lines.
	content := strings.Join([]string{
		"--- text ---",
		"first body line",
		"LAST-LINE-OF-SECTION-A",
		"--- text ---",
		"FIRST-LINE-OF-SECTION-B",
		"second body line",
	}, "\n")

	pc := &preprocessors.ProcessedContent{
		Text:          content,
		OriginalPath:  "combined.txt",
		ProcessorType: "text+text",
	}

	body, _, err := cr.separateCombinedPreprocessorOutput(pc)
	if err != nil {
		t.Fatalf("separateCombinedPreprocessorOutput: %v", err)
	}

	// The fusion signature: the two boundary tokens adjacent with no newline.
	fused := "LAST-LINE-OF-SECTION-AFIRST-LINE-OF-SECTION-B"
	if strings.Contains(body, fused) {
		t.Errorf("body sections were fused at the seam:\n%s", body)
	}

	// Both boundary tokens must survive as their own lines.
	lines := strings.Split(body, "\n")
	haveA, haveB := false, false
	for _, ln := range lines {
		switch strings.TrimSpace(ln) {
		case "LAST-LINE-OF-SECTION-A":
			haveA = true
		case "FIRST-LINE-OF-SECTION-B":
			haveB = true
		}
	}
	if !haveA || !haveB {
		t.Errorf("boundary lines did not survive as separate lines (A=%v B=%v):\n%s", haveA, haveB, body)
	}
}

// TestRouteContent_PageBreakSeamKeepsLinesSeparate is the end-to-end version, and
// it uses the real trigger: a PDF processed by "pdf_metadata+Text Extractor"
// carries "--- PAGE BREAK ---" markers, which split() treats as document-body
// section boundaries. So every page boundary in every multi-page PDF ran through
// this code, and the last line of one page fused with the first line of the next.
//
// Here a value the extractor happens to split across a page break (a real
// occurrence for long values near the bottom of a page) must reassemble onto one
// line rather than being welded to unrelated text from the next page.
func TestRouteContent_PageBreakSeamKeepsLinesSeparate(t *testing.T) {
	cr := NewContentRouter()

	// "Text Extractor" body, a page break, then the next page's body. The SSN's
	// tail sits at the top of page 2. With the seam collapsed, "536-22-" and
	// "8765" end up on separate lines from each other's neighbours correctly;
	// the defect welded "...bottom of page one536-22-" together.
	content := strings.Join([]string{
		"--- Text Extractor ---",
		"Report continues to the bottom of page one",
		"--- PAGE BREAK ---",
		"Employee record follows",
		"SSN 536-22-8765 on file",
	}, "\n")

	pc := &preprocessors.ProcessedContent{
		Text:          content,
		OriginalPath:  "report.pdf",
		ProcessorType: "pdf_metadata+Text Extractor",
	}

	routed, err := cr.RouteContent(pc)
	if err != nil {
		t.Fatalf("RouteContent: %v", err)
	}

	if strings.Contains(routed.DocumentBody, "page one"+"Employee") {
		t.Errorf("page boundary was fused:\n%s", routed.DocumentBody)
	}

	// Each source line must appear intact on its own line in the routed body.
	want := []string{
		"Report continues to the bottom of page one",
		"Employee record follows",
		"SSN 536-22-8765 on file",
	}
	bodyLines := strings.Split(routed.DocumentBody, "\n")
	for _, w := range want {
		found := false
		for _, ln := range bodyLines {
			if strings.TrimSpace(ln) == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("line %q did not survive intact in routed body:\n%s", w, routed.DocumentBody)
		}
	}
}
