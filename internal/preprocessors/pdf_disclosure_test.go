// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	textextractpdftextlib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/text-extractors/text-extract-pdftextlib"
)

// TestPDFExtractionDisclosure covers every branch of the completeness decision, including
// the one no real document reaches.
//
// The pages-failed branch is why this test exists as a unit test rather than a fixture
// scan: 60 real PDFs and 24 deliberately damaged ones (truncated at 50% and 90%, %%EOF
// removed, a 512-byte run zeroed) produced whole-file failures and budget truncation but
// never a partial page failure. Shipping that branch on the strength of having read it
// would leave the one case it exists for untested.
//
// The ORDERING cases are the substance. Two conditions can hold at once, and the wrong
// precedence produces a true disclosure under a false heading — which sends an operator to
// fix the wrong thing and is the failure this whole disclosure exists to avoid.
func TestPDFExtractionDisclosure(t *testing.T) {
	const ext = ".pdf"

	cases := []struct {
		name       string
		c          textextractpdftextlib.TextContent
		text       string
		wantCause  coverage.Cause
		wantSubstr []string
		wantEmpty  bool
	}{
		{
			name:      "complete extraction says nothing",
			c:         textextractpdftextlib.TextContent{PageCount: 3, PagesScanned: 3},
			text:      "some body text",
			wantCause: coverage.CauseUnset,
			wantEmpty: true,
		},
		{
			name:       "budget truncation names both numbers and the remainder",
			c:          textextractpdftextlib.TextContent{PageCount: 200, PagesScanned: 50},
			text:       "text from the first 50",
			wantCause:  coverage.CauseCutShort,
			wantSubstr: []string{"first 50 of 200", "page budget", "remaining 150", "NOT scanned"},
		},
		{
			name:       "pages reached and failed",
			c:          textextractpdftextlib.TextContent{PageCount: 12, PagesScanned: 12, PagesFailed: 3},
			text:       "text from the nine that worked",
			wantCause:  coverage.CauseCutShort,
			wantSubstr: []string{"3 of 12", "could not be read", "NOT scanned"},
		},
		{
			name:       "no text at all",
			c:          textextractpdftextlib.TextContent{PageCount: 4, PagesScanned: 4},
			text:       "   \n\t ",
			wantCause:  coverage.CauseNoText,
			wantSubstr: []string{"no text extracted", "held no document text"},
		},
		{
			// ORDERING: truncated AND empty. Must report truncation — an image-only PDF that
			// was ALSO cut short is first of all cut short, and "held no document text" would
			// send the operator to OCR a document whose later pages were never opened.
			name:       "truncated and empty reports truncation, not emptiness",
			c:          textextractpdftextlib.TextContent{PageCount: 60, PagesScanned: 50},
			text:       "",
			wantCause:  coverage.CauseCutShort,
			wantSubstr: []string{"first 50 of 60", "page budget"},
		},
		{
			// ORDERING: truncated AND pages failed. Truncation wins, because raising the
			// budget is the action that changes the outcome most.
			name:       "truncated and pages failed reports truncation",
			c:          textextractpdftextlib.TextContent{PageCount: 100, PagesScanned: 50, PagesFailed: 2},
			text:       "partial",
			wantCause:  coverage.CauseCutShort,
			wantSubstr: []string{"first 50 of 100", "page budget"},
		},
		{
			// ORDERING: pages failed AND no text. Failure wins: "held no document text"
			// would claim the file has no text layer when in fact reading it failed.
			name:       "all pages failed reports the failure, not emptiness",
			c:          textextractpdftextlib.TextContent{PageCount: 5, PagesScanned: 5, PagesFailed: 5},
			text:       "",
			wantCause:  coverage.CauseCutShort,
			wantSubstr: []string{"5 of 5", "could not be read"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warn, cause := pdfExtractionDisclosure(&c.c, c.text, ext)

			if cause != c.wantCause {
				t.Errorf("cause = %v, want %v", cause, c.wantCause)
			}
			if c.wantEmpty {
				if warn != "" {
					t.Errorf("expected no warning for a complete extraction, got %q", warn)
				}
				return
			}
			if warn == "" {
				t.Fatalf("expected a warning, got none")
			}
			for _, sub := range c.wantSubstr {
				if !strings.Contains(warn, sub) {
					t.Errorf("warning %q does not contain %q", warn, sub)
				}
			}
			// Every non-empty disclosure must name the file type, or an operator reading a
			// multi-file run cannot tell which kind of file it is about.
			if !strings.Contains(warn, ext) {
				t.Errorf("warning %q does not name the extension", warn)
			}
		})
	}
}

// TestPagesFailedIsNotConflatedWithTheBudget pins the distinction the two CauseCutShort
// branches exist to preserve.
//
// Both return the same cause, deliberately — the operator-facing string is "coverage cut
// short", which is true of both — so the only thing separating them is the warning text.
// If those texts ever converge, the operator loses the ability to tell "raise the budget"
// from "this file is damaged", and there would be no reason for two branches.
func TestPagesFailedIsNotConflatedWithTheBudget(t *testing.T) {
	budget := textextractpdftextlib.TextContent{PageCount: 100, PagesScanned: 50}
	failed := textextractpdftextlib.TextContent{PageCount: 50, PagesScanned: 50, PagesFailed: 50}

	wBudget, cBudget := pdfExtractionDisclosure(&budget, "x", ".pdf")
	wFailed, cFailed := pdfExtractionDisclosure(&failed, "x", ".pdf")

	if cBudget != cFailed {
		t.Fatalf("premise changed: the two branches no longer share a cause (%v vs %v); "+
			"if they now differ, this test should assert the causes instead of the strings",
			cBudget, cFailed)
	}
	if wBudget == wFailed {
		t.Errorf("the two branches produce identical warnings (%q), so an operator cannot "+
			"tell a budget from a damaged file and one of the branches is pointless", wBudget)
	}
	if !strings.Contains(wBudget, "page budget") {
		t.Errorf("the budget warning no longer names the budget: %q", wBudget)
	}
	if strings.Contains(wFailed, "page budget") {
		t.Errorf("the failure warning claims a budget fired when none did: %q", wFailed)
	}
}
