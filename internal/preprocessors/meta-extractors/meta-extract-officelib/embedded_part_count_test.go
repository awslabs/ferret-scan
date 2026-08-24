// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"fmt"
	"strings"
	"testing"
)

// #379: neither existing cap bounds the NUMBER of embedded parts. MaxEmbeddedMediaSize bounds one
// part and embedded.BudgetBytes bounds their total bytes; an empty part charges nothing against
// either, so a container can declare unboundedly many.
//
// Measured at HEAD on .docx files whose media entries hold an 8-byte PNG signature and nothing
// else — the cost is linear, but with a per-part constant large enough that linear is not safe:
//
//	  1,000 parts    1.0s     50MB RSS      122KB input
//	 10,000 parts    9.0s     50MB RSS      1.2MB input
//	 50,000 parts   43.8s    352MB RSS      6.2MB input
//	200,000 parts  184.3s   1182MB RSS     25.2MB input
//
// A zip entry costs the attacker about 128 bytes, so 25MB of input buys three minutes of CPU and
// 1.2GB of memory. With the cap the same file takes 4.1s and 156MB.
//
// The cap creates a coverage loss, which is the reason these tests care as much about the
// DISCLOSURE as about the bound: an undisclosed skip would trade a slow scan for a silent one, and
// only reported findings reach the redactor.

// TestPartsBeyondTheCapAreDisclosedWithTheirOwnCause is the property that keeps this bound from
// becoming a silent miss.
//
// The message must name the count cap. An earlier design folded these into the same counter as
// extraction failures, which reports the right number under the wrong cause — it would tell an
// operator that thousands of parts failed to READ when in fact they were never attempted, sending
// them to look for a corrupt document.
func TestPartsBeyondTheCapAreDisclosedWithTheirOwnCause(t *testing.T) {
	const over = 12
	docx := buildDocxWithParts(t, maxEmbeddedParts+over, 8)

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(docx)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}
	defer CleanupEmbeddedMedia(media)

	if len(media) != maxEmbeddedParts {
		t.Errorf("extracted %d parts, want exactly maxEmbeddedParts (%d): the cap must bind, and "+
			"must not bind early", len(media), maxEmbeddedParts)
	}

	joined := strings.Join(notExamined, "\n")
	if len(notExamined) == 0 {
		t.Fatalf("%d parts went unexamined and nothing was disclosed. A silent skip here trades a "+
			"slow scan for a scan that reports clean — the failure this whole area keeps "+
			"reproducing.", over)
	}

	// The count, the cap and the true total all have to be in the text: the count alone does not
	// tell an operator whether to raise the cap or to distrust the document.
	for _, want := range []string{
		fmt.Sprintf("%d embedded part(s) beyond the %d-part limit", over, maxEmbeddedParts),
		fmt.Sprintf("container declares %d", maxEmbeddedParts+over),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("disclosure does not contain %q.\ngot:\n%s", want, joined)
		}
	}

	// And it must not be reported as a read failure, which is a different cause with a different
	// remedy.
	if strings.Contains(joined, "was not examined: ") {
		t.Errorf("parts past the cap were reported as per-part extraction failures.\ngot:\n%s", joined)
	}
}

// TestTheWalkFinishesSoTheDisclosedCountIsTrue pins why the loop keeps walking past the cap instead
// of breaking out.
//
// Breaking is cheaper and makes the number unknowable, so the note would have to say "some" — which
// is the difference between a report an operator can act on and one they can only worry about.
// Asserted at two different overshoots so a hardcoded or clamped number cannot pass.
func TestTheWalkFinishesSoTheDisclosedCountIsTrue(t *testing.T) {
	for _, over := range []int{1, 37} {
		t.Run(fmt.Sprintf("over_%d", over), func(t *testing.T) {
			docx := buildDocxWithParts(t, maxEmbeddedParts+over, 8)
			media, notExamined, err := ExtractEmbeddedMediaForProcessing(docx)
			if err != nil {
				t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
			}
			defer CleanupEmbeddedMedia(media)

			want := fmt.Sprintf("%d embedded part(s) beyond the %d-part limit", over, maxEmbeddedParts)
			if got := strings.Join(notExamined, "\n"); !strings.Contains(got, want) {
				t.Errorf("want %q; the walk must finish to know the count.\ngot:\n%s", want, got)
			}
		})
	}
}

// TestAtTheCapNothingIsRefused is the off-by-one, and the guard against a cap that quietly costs
// coverage on real documents.
//
// Measured on 420 real Office documents: the most embedded parts in any one file was 361, median 0,
// mean 7. So a correct cap refuses nothing in that corpus — output was byte-identical across all
// 420 once the report's timing field was normalised. A cap that fired one part early would start
// eating real coverage while every synthetic over-cap test still passed.
func TestAtTheCapNothingIsRefused(t *testing.T) {
	docx := buildDocxWithParts(t, maxEmbeddedParts, 8)

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(docx)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}
	defer CleanupEmbeddedMedia(media)

	if len(media) != maxEmbeddedParts {
		t.Errorf("extracted %d of %d parts at exactly the cap; the cap must not bind here",
			len(media), maxEmbeddedParts)
	}
	if len(notExamined) != 0 {
		t.Errorf("a document exactly at the cap disclosed %d note(s): %v. Nothing was skipped, so "+
			"nothing should be reported — a spurious incompleteness warning teaches operators to "+
			"ignore the real ones.", len(notExamined), notExamined)
	}
}

// TestBothLoopsCapAtTheSameCount guards the pair, not either half.
//
// The metadata loop's admission decides EmbeddedMediaCount and the EmbeddedMedia_N_* properties;
// the processing loop's decides what actually gets scanned. Those properties are rendered into the
// text every validator reads. If only one loop capped, the metadata would advertise parts the scan
// never looked at, or the scan would examine parts the metadata never mentioned.
func TestBothLoopsCapAtTheSameCount(t *testing.T) {
	docx := buildDocxWithParts(t, maxEmbeddedParts+5, 8)

	md, err := ExtractMetadata(docx)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	metaCount := countProperty(t, md)

	media, _, err := ExtractEmbeddedMediaForProcessing(docx)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}
	defer CleanupEmbeddedMedia(media)

	if want := fmt.Sprintf("%d", maxEmbeddedParts); metaCount != want {
		t.Errorf("EmbeddedMediaCount = %q, want %q. Both loops walk the same archive against the "+
			"same cap; a count above the cap means the metadata advertises parts nothing scanned.",
			metaCount, want)
	}
	if fmt.Sprintf("%d", len(media)) != metaCount {
		t.Errorf("the metadata loop counted %s parts but the processing loop extracted %d — the two "+
			"admission paths disagree about membership", metaCount, len(media))
	}
}
