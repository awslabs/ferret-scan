// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// The ExtractionWarning channel carries two different statements, and this side used to file
// every one of them under "no body text (metadata still scanned)":
//
//	"no text extracted from .docx: no document body part was found"      <- the body WAS empty
//	"embedded part %q was not examined: declares N bytes, over the cap"  <- the body was fine
//
// The second is a container whose own text was read and scanned normally, with one part
// unexamined — coverage cut short, not an empty body. Reporting it as "no body text" asserts a
// failure that did not happen, which is precisely what the cause taxonomy exists to prevent.
//
// Every string below is the real wording of a real producer, copied from the code that builds
// it. That is the point of the table: a new producer whose phrasing lands in the wrong bucket
// fails HERE rather than in an operator's report, where nobody can tell.
func TestEveryExtractionWarningProducerLandsInTheRightBucket(t *testing.T) {
	cases := []struct {
		producer string
		reason   string
		want     unscannedCause
	}{
		{
			producer: "office text extractor, body part missing (text-extract-officetextlib)",
			reason:   "no text extracted from .docx: no document body part was found in the archive, so document content was NOT scanned",
			want:     causeNoText,
		},
		{
			producer: "office text extractor, body parts held no text",
			reason:   "no text extracted from .pptx: 3 body part(s) were read but held no text",
			want:     causeNoText,
		},
		{
			producer: "PDF extractor failed (text_preprocessor.pdfExtractionWarning)",
			reason:   "no text extracted from .pdf: malformed PDF: xref not found, so document content was NOT scanned",
			want:     causeNoText,
		},
		{
			producer: "PDF parsed but held no text layer",
			reason:   "no text extracted from .pdf: the file parsed but held no document text, so page content was NOT scanned",
			want:     causeNoText,
		},
		{
			producer: "router-prefixed no-text warning",
			reason:   "Text Extractor: no text extracted from .docx: no document body part was found in the archive, so document content was NOT scanned",
			want:     causeNoText,
		},
		{
			producer: "embedded part refused for size (#374, this change)",
			reason:   `office_metadata: embedded part "attachment.docx" was not examined: declares 52433928 bytes, over the 52428800-byte embedded cap (possible decompression bomb)`,
			want:     causeCutShort,
		},
		{
			producer: "embedded part unreadable (#374, this change)",
			reason:   `office_metadata: embedded part "broken.jpg" was not examined: flate: corrupt input before offset 1`,
			want:     causeCutShort,
		},
		{
			producer: "embedded container past the nesting bound (base_metadata_preprocessor)",
			reason:   `office_metadata: embedded item "attachment.docx" was not examined: embedded container nesting limit reached`,
			want:     causeCutShort,
		},
		{
			producer: "WAV chunk walk stopped early (meta-extract-audiolib)",
			reason:   "audio_metadata: audio metadata may be incomplete: the WAV chunk layout could not be walked to the end",
			want:     causeCutShort,
		},
		{
			producer: "WAV missing pad byte (padByteNote)",
			reason:   "audio_metadata: the WAV chunk layout omits a required pad byte after an odd-length chunk; metadata was recovered by realigning, but the file is malformed and may be truncated",
			want:     causeCutShort,
		},
		{
			producer: "both at once: an empty body AND an unexamined part",
			reason:   `Text Extractor: no text extracted from .docx: no document body part was found in the archive, so document content was NOT scanned; office_metadata: embedded part "attachment.docx" was not examined: declares 52433928 bytes, over the 52428800-byte embedded cap`,
			want:     causeCutShort,
		},
	}

	for _, c := range cases {
		if got := classifyExtractionWarning(c.reason); got != c.want {
			t.Errorf("%s\n  reason: %q\n  cause = %q, want %q",
				c.producer, c.reason, got.String(), c.want.String())
		}
	}
}

// The joined case deserves its own statement, because it is the one a substring test gets
// wrong: a leading no-text warning would hide an unexamined embedded document behind it, and
// the file would be filed under the milder cause.
func TestANoTextWarningCannotHideAnUnexaminedPart(t *testing.T) {
	noText := "no text extracted from .docx: no document body part was found in the archive"
	unexamined := `embedded part "attachment.docx" was not examined: over the embedded cap`

	if got := classifyExtractionWarning(noText); got != causeNoText {
		t.Fatalf("the no-text half alone = %q, want %q", got.String(), causeNoText.String())
	}
	for _, joined := range []string{noText + "; " + unexamined, unexamined + "; " + noText} {
		if got := classifyExtractionWarning(joined); got != causeCutShort {
			t.Errorf("joined warning classified as %q, want %q — one unexamined part means "+
				"coverage really was cut short, whichever order the segments arrive in\n  %q",
				got.String(), causeCutShort.String(), joined)
		}
	}
}

// The cause must survive the whole collectUnscanned path, not just the classifier: an entry
// that is classified correctly and then reported under a different cause is no better.
func TestUnexaminedEmbeddedPartReachesTheReportAsCutShort(t *testing.T) {
	entries := collectUnscanned(
		nil,
		[]parallel.FileDiagnostic{{
			FilePath: "/scan/outer_big.docx",
			Reason:   `office_metadata: embedded part "attachment.docx" was not examined: declares 52433928 bytes, over the 52428800-byte embedded cap (possible decompression bomb)`,
		}},
		nil,
		nil,
		nil,
	)

	if len(entries) != 1 {
		t.Fatalf("collectUnscanned produced %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Cause != causeCutShort {
		t.Errorf("cause = %q, want %q: this container's own body text was read and scanned, so "+
			"claiming it had no body text describes a failure that did not happen",
			entries[0].Cause.String(), causeCutShort.String())
	}
	if !strings.Contains(entries[0].Detail, "attachment.docx") {
		t.Errorf("detail = %q, want it to name the part that was not examined", entries[0].Detail)
	}
}
