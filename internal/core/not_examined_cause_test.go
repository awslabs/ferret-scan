// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// #432 and #391. A coverage-loss record reached this layer with only prose, and this layer then
// described it using the NAME OF THE FIELD it read it out of.
//
// EmptyExtractionFiles is a mixed channel: it carries no-text, unparseable and cut-short warnings
// alike. Stamping "no document text extracted from" on all of them told an operator that a file whose
// body could not be PARSED had been read and found empty — the opposite of what happened.
//
// Measured through pkg/scan on a valid OOXML package with no word/document.xml:
//
//	before   IncompleteReason: no document text extracted from …/nobody.docx: …
//	after    IncompleteReason: cannot parse: …/nobody.docx: …

// TestCollectNotExaminedFlattensEveryChannel is #391: a library consumer used to get one prose line
// for the whole run, so a scan with one unreadable file and forty partly-scanned ones told it about one.
func TestCollectNotExaminedFlattensEveryChannel(t *testing.T) {
	stats := &parallel.ProcessingStats{
		EmptyExtractionFiles: []parallel.FileDiagnostic{
			{FilePath: "/a/empty.docx", Reason: "no body part", Cause: coverage.CauseUnparseable},
		},
		FailedFiles: []parallel.FileDiagnostic{
			{FilePath: "/a/gone.txt", Reason: "permission denied", Cause: coverage.CauseUnreadable},
		},
		IncompleteFiles: []parallel.FileDiagnostic{
			{FilePath: "/a/slow.pdf", Reason: "context deadline exceeded", Cause: coverage.CauseCutShort},
		},
		// Present on purpose: a redaction failure is NOT a coverage loss. The file was scanned and its
		// findings are in Matches, so listing it here would send an operator looking for missed content.
		UnredactedFiles: []parallel.FileDiagnostic{
			{FilePath: "/a/locked.pdf", Reason: "no redactor for .pdf"},
		},
	}

	got := collectNotExamined(stats)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 (one per diagnostic channel): %+v", len(got), got)
	}

	byPath := map[string]NotExaminedFile{}
	for _, ne := range got {
		byPath[ne.Path] = ne
	}
	for path, want := range map[string]coverage.Cause{
		"/a/empty.docx": coverage.CauseUnparseable,
		"/a/gone.txt":   coverage.CauseUnreadable,
		"/a/slow.pdf":   coverage.CauseCutShort,
	} {
		ne, ok := byPath[path]
		if !ok {
			t.Errorf("%s is missing from the list", path)
			continue
		}
		if ne.Cause != want {
			t.Errorf("%s: cause = %q, want %q", path, ne.Cause, want)
		}
		if ne.Detail == "" {
			t.Errorf("%s: Detail is empty; the cause is coarse and the detail is what an operator acts on", path)
		}
	}
	if _, leaked := byPath["/a/locked.pdf"]; leaked {
		t.Error("an UnredactedFiles entry reached the not-examined list. A redaction failure is not a " +
			"coverage loss: that file WAS scanned and its findings are reported.")
	}
}

// TestCollectNotExaminedToleratesNilStats keeps the aggregation off the error paths.
func TestCollectNotExaminedToleratesNilStats(t *testing.T) {
	if got := collectNotExamined(nil); got != nil {
		t.Errorf("collectNotExamined(nil) = %+v, want nil", got)
	}
	if got := collectNotExamined(&parallel.ProcessingStats{}); got != nil {
		t.Errorf("empty stats produced %+v, want nil", got)
	}
}

// TestIncompleteReasonNamesTheCauseNotTheBucket is #432 stated as the property.
//
// The assertion is deliberately about the PREFIX rather than the whole string: the detail is the
// producer's and must pass through untouched, while the label is this layer's and was wrong.
func TestIncompleteReasonNamesTheCauseNotTheBucket(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cause      coverage.Cause
		wantPrefix string
	}{
		{"a body that could not be parsed", coverage.CauseUnparseable, "cannot parse:"},
		{"a genuinely empty body", coverage.CauseNoText, "no body text (metadata still scanned):"},
		{"a partly scanned container", coverage.CauseCutShort, "coverage cut short:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := incompleteReasonFor(parallel.FileDiagnostic{
				FilePath: "/a/f.docx", Reason: "the producer's own detail", Cause: tc.cause,
			}, 1, 1)
			if !strings.HasPrefix(reason, tc.wantPrefix) {
				t.Errorf("reason = %q, want it to begin %q. The label came from the FIELD NAME, so "+
					"every entry in this channel was described as having no document text.",
					reason, tc.wantPrefix)
			}
			if !strings.Contains(reason, "the producer's own detail") {
				t.Errorf("reason = %q dropped the producer's detail, which is the part an operator acts on", reason)
			}
		})
	}
}

// TestIncompleteReasonFallsBackWhenNoCauseWasStated keeps a producer this change has not reached
// behaving exactly as it did before.
func TestIncompleteReasonFallsBackWhenNoCauseWasStated(t *testing.T) {
	reason := incompleteReasonFor(parallel.FileDiagnostic{
		FilePath: "/a/f.docx", Reason: "some detail",
	}, 1, 1)
	if !strings.HasPrefix(reason, "no document text extracted from") {
		t.Errorf("reason = %q; with no stated cause the historical wording must be preserved, or this "+
			"change silently relabels every producer it has not yet reached", reason)
	}
}
