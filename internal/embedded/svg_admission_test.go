// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package embedded

import (
	"sort"
	"testing"
)

// #314: .svg was excluded from the embedded TEXT pipeline and is no longer.
//
// SkipTextPipeline gates both halves -- the read side
// (preprocessors/base_metadata_preprocessor.go) and the write side
// (redactors/office/redactor.go) -- so this one predicate decided that an embedded
// drawing was neither scanned nor redacted. Measured on a .docx carrying one .svg with
// an SSN, an email, a name and a phone in its <text>/<title>/<desc>:
//
//	standalone .svg   4 findings (SSN 100, BUSINESS 98, PERSON_NAME 92, PHONE 15)
//	embedded in .docx 0 findings, exit 0, 0 bytes of stderr,
//	                  exit 0 again under --fail-on-incomplete,
//	                  and no redacted copy written at all
//
// The exclusion's stated reason was real -- 943 findings, 817 of them PHONE, on a 64KB
// SVG of integer-coordinate glyph paths -- but the cure was the wrong one. The prose-only
// extractor (text-extract-svgtextlib) removes the flood at the source, so the exclusion
// buys nothing and costs the coverage.

// TestSVGIsAdmittedToTheTextPipeline is the recall half.
func TestSVGIsAdmittedToTheTextPipeline(t *testing.T) {
	for _, name := range []string{
		"word/media/diagram1.svg",
		"word/media/DIAGRAM1.SVG",
		"ppt/media/image7.svg",
		"xl/media/chart.svg",
	} {
		if SkipTextPipeline(name) {
			t.Errorf("SkipTextPipeline(%q) is still true.\n"+
				"This predicate gates BOTH the read side and the redaction side, so a true here "+
				"means the part is neither scanned nor redacted, silently. The flood that justified "+
				"it is now removed at the source by the prose-only SVG extractor.", name)
		}
	}
}

// TestBinaryMetafilesStayExcluded is the other half, and it is not a formality.
//
// .emf, .wmf and .wdp have no text reader anywhere in this tool. Admitting them would
// make a part reach a preprocessor, extract nothing, and report Success with zero
// findings -- indistinguishable from a clean part, and strictly worse than the
// exclusion, which at least does not claim to have looked. That is #400's lesson.
func TestBinaryMetafilesStayExcluded(t *testing.T) {
	for _, name := range []string{
		"word/media/image1.emf",
		"word/media/image2.wmf",
		"word/media/image3.wdp",
		"word/media/IMAGE4.EMF",
	} {
		if !SkipTextPipeline(name) {
			t.Errorf("SkipTextPipeline(%q) is false, so a binary metafile with no extractor would "+
				"be routed to the text pipeline and report Success with zero findings", name)
		}
	}
}

// TestSVGStaysByteInspectable is the invariant the redaction dispatch gate rests on.
//
// redactEmbeddedParts SKIPS a part when a byte scan of it finds none of the reported
// values, and that reading is only sound for a format whose text is stored in the clear.
// An .svg is XML text, so it qualifies -- but the property has to be asserted, because
// if it ever stopped holding, an embedded drawing holding a reported value would be
// judged harmless and shipped.
func TestSVGStaysByteInspectable(t *testing.T) {
	const part = "word/media/diagram1.svg"
	body := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><text>452-11-9384</text></svg>`)

	if !ResidueInspectable(part) {
		t.Error("ResidueInspectable(.svg) is false, so every embedded SVG would be ALWAYS dispatched " +
			"and a clean one re-encoded for nothing")
	}
	if !ContentInspectable(part, body) {
		t.Error("ContentInspectable(.svg) is false; an SVG's text is uncompressed, so a byte scan is " +
			"a sound test for the absence of a value in it")
	}
	// The polarity that matters: the value IS findable in the raw bytes, which is what
	// makes "byte scan found nothing" mean "holds nothing".
	if got := valuesFindable(body, "452-11-9384"); !got {
		t.Error("the value is not findable in an SVG's raw bytes, which breaks the dispatch gate's premise")
	}
}

// valuesFindable is a local restatement of the residue premise, kept in this file so the
// test does not depend on an unexported helper elsewhere.
func valuesFindable(content []byte, value string) bool {
	return len(value) > 0 && indexOf(content, value) >= 0
}

func indexOf(haystack []byte, needle string) int {
	n := len(needle)
	for i := 0; i+n <= len(haystack); i++ {
		if string(haystack[i:i+n]) == needle {
			return i
		}
	}
	return -1
}

// TestSkippedSetIsExactlyTheThreeMetafiles locks the whole set, so adding a fourth
// entry is a decision someone makes here rather than a side effect.
func TestSkippedSetIsExactlyTheThreeMetafiles(t *testing.T) {
	var got []string
	for ext := range vectorGraphicsExts {
		got = append(got, ext)
	}
	sort.Strings(got)

	want := []string{".emf", ".wdp", ".wmf"}
	if len(got) != len(want) {
		t.Fatalf("the text-pipeline exclusion set is %v, want %v.\n"+
			"Every entry here is a type whose content is NEITHER scanned NOR redacted, silently, so the "+
			"set must hold only formats this tool has no reader for at all.", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("exclusion set[%d] = %q, want %q (full set %v)", i, got[i], want[i], got)
		}
	}
}
