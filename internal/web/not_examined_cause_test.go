// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
)

// #417. The UI collapsed the CLI's six causes into one bool and one prose line, so an upload where
// three files failed for three different reasons reported one of them — and reported it as whichever
// wording summarizeIncompleteFiles happened to produce.
//
// The response now carries a per-file list using the same six spellings the CLI prints, so an operator
// reading the browser and an operator reading the terminal see the same words for the same file.

// TestUploadRefusalCarriesItsCause is the property: a disclosed refusal names its cause.
//
// A .docx whose bytes are not a ZIP is refused by the router with a processable TYPE, which is the
// coverageGap-true half — the tool could have found something and did not.
func TestUploadRefusalCarriesItsCause(t *testing.T) {
	got := scanResponseFor(t, "SSN",
		[2]string{"real.txt", "Employee SSN 449-87-4100"},
		[2]string{"broken.docx", "this is definitely not a zip archive"},
	)

	// The findings of the good file must survive — that is #416 and it must not regress.
	if len(got.Results) == 0 {
		t.Fatal("the readable file's findings were discarded; one refused upload must not empty the batch")
	}
	if !got.Incomplete {
		t.Fatal("the refusal was not disclosed at all")
	}
	if len(got.NotExamined) == 0 {
		t.Fatal("Incomplete is set but NotExamined is empty, so a UI can say THAT coverage was lost " +
			"and not WHAT was lost — which is the whole of #417")
	}

	var found bool
	for _, ne := range got.NotExamined {
		if !strings.Contains(ne.Path, "broken.docx") {
			continue
		}
		found = true
		if ne.Cause == "" {
			t.Error("cause is empty for a refusal whose site knows it; the UI would have to guess, and " +
				"the prose classifier it would fall back to defaults to \"coverage cut short\", which " +
				"claims the file was partly scanned")
		}
		if ne.Detail == "" {
			t.Error("detail is empty; the cause is coarse and the detail is what an operator acts on")
		}
	}
	if !found {
		t.Errorf("broken.docx is not in NotExamined: %+v", got.NotExamined)
	}
}

// TestNotExaminedUsesTheSameWordsAsTheCLI is what makes the two surfaces comparable.
//
// The value of a shared taxonomy is that an operator can carry a phrase from the browser to a grep over
// CI logs. A cause rendered with different wording here would look like a different problem.
func TestNotExaminedUsesTheSameWordsAsTheCLI(t *testing.T) {
	got := scanResponseFor(t, "SSN",
		[2]string{"ok.txt", "Employee SSN 449-87-4100"},
		[2]string{"broken.docx", "not a zip"},
	)

	allowed := map[string]bool{
		"cannot read": true, "cannot parse": true,
		"no body text (metadata still scanned)": true, "coverage cut short": true,
		"symlink not followed": true, "file too large to scan": true,
	}
	for _, ne := range got.NotExamined {
		if ne.Cause == "" {
			continue // unknown is allowed; a wrong spelling is not
		}
		if !allowed[ne.Cause] {
			t.Errorf("cause %q is not one of the six the CLI prints. A UI showing a seventh spelling "+
				"reads as a different problem from the same file on the command line.", ne.Cause)
		}
	}
}

// TestCompleteScanOmitsNotExamined keeps the wire format unchanged for the common case.
//
// The field is omitempty so a clean scan's JSON is byte-identical to before it existed. A UI that
// renders a "not examined" section on the presence of the key must not start showing an empty one.
func TestCompleteScanOmitsNotExamined(t *testing.T) {
	got := scanResponseFor(t, "SSN", [2]string{"clean.txt", "Employee SSN 449-87-4100"})
	if got.Incomplete {
		t.Skipf("this fixture reported incomplete (%s), so it cannot test the complete case",
			got.IncompleteReason)
	}
	if got.NotExamined != nil {
		t.Errorf("a complete scan returned NotExamined = %+v, want nil", got.NotExamined)
	}
}

// TestOversizeRefusalCarriesTooLargeAndTheCLIsWording pins the one refusal a multipart test cannot
// reach.
//
// The existing oversize test skips because it would have to move router.MaxFileSize bytes through a
// request body, so this refusal's cause went unpinned — a mutation deleting it survived the whole suite.
// Asserting the constructor instead costs nothing and catches that.
//
// The wording is asserted too, not just the cause: it is deliberately identical to the CLI's
// causeTooLarge string so an operator comparing the browser with the terminal sees one reason.
func TestOversizeRefusalCarriesTooLargeAndTheCLIsWording(t *testing.T) {
	r := oversizeRefusal("big.docx")

	if !r.coverageGap {
		t.Error("an oversize file of a processable type is lost coverage and must be disclosed")
	}
	if r.cause != coverage.CauseTooLarge {
		t.Errorf("cause = %q, want %q", r.cause, coverage.CauseTooLarge)
	}
	if got, want := r.cause.String(), "file too large to scan"; got != want {
		t.Errorf("cause renders as %q, want %q — the CLI prints that exact phrase", got, want)
	}
	if !strings.Contains(r.reason, "file too large to scan") {
		t.Errorf("reason = %q; it must repeat the CLI's wording so the two surfaces agree", r.reason)
	}
	if !strings.Contains(r.Error(), "big.docx") {
		t.Errorf("Error() = %q, want the display name in it", r.Error())
	}
}

// TestRouterRefusalCarriesCannotRead pins the other refusal a request-level test cannot reach.
//
// An upload always lands in a readable regular temp file, so the router-declined path is not
// triggerable through multipart — which is why a mutation deleting its cause survived the suite. The
// constructor is asserted directly instead.
//
// "cannot read" and not "cannot parse": the router declines before any preprocessor looks at the bytes,
// so nothing is known about the content. Claiming a parse failure would assert something that was never
// attempted.
func TestRouterRefusalCarriesCannotRead(t *testing.T) {
	t.Run("processable type is disclosed", func(t *testing.T) {
		r := routerRefusal("thing.docx", "Unreadable: not a regular file", true)
		if !r.coverageGap {
			t.Error("a processable type the router declined is lost coverage and must be disclosed")
		}
		if r.cause != coverage.CauseUnreadable {
			t.Errorf("cause = %q, want %q", r.cause, coverage.CauseUnreadable)
		}
		if got, want := r.cause.String(), "cannot read"; got != want {
			t.Errorf("cause renders as %q, want %q", got, want)
		}
	})

	t.Run("unprocessable type stays a benign skip", func(t *testing.T) {
		r := routerRefusal("thing.zzz", "unsupported type", false)
		if r.coverageGap {
			t.Error("a type nothing could have read is a benign skip; disclosing it trains operators " +
				"to ignore the warnings that matter")
		}
	})
}
