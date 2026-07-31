// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// The legacy fallback must carry provenance structurally, like the routed path.
//
// It is reached whenever routing or dual-path processing fails, and EnableFallbackMode
// defaults to true, so it is live rather than theoretical. It used to learn where an
// embedded archive member began by reading the "--- Embedded Media N (name) ---" line
// out of the extracted text — the same forgeable channel this change removes elsewhere.
// Deleting that reader without giving this path the structural equivalent silently
// re-attributed real embedded findings to the container: measured on a .docx carrying an
// embedded .wav, AUDIO_ARTIST_IDENTITY, EMAIL and IMAGE_AUTHOR moved from
// "real_embed.docx -> audio1.wav" to the container path, and because
// generateFindingHash folds filepath.Base(Filename), 3 of 11 suppression rules written
// against the old attribution stopped matching.
//
// Two properties have to hold together, and fixing only the first breaks the second:
// each unit is attributed to the member it came from, AND its line numbers stay
// file-relative. A validator handed one section counts lines from 1 inside it, so
// without rebasing by LineOffset the reported lines shift (21 -> 6, 8 -> 1) and the
// suppression hash — which embeds the line number — invalidates every saved rule for
// any container with more than one section.

// TestLegacyMetadataUnitsUseDeclaredProvenance pins the first property.
func TestLegacyMetadataUnitsUseDeclaredProvenance(t *testing.T) {
	content := &preprocessors.ProcessedContent{
		OriginalPath: "report.docx",
		Text:         "Author: Jane Analyst\n\n--- Embedded Media 1 (audio1.wav) ---\nArtist: john.doe@example.com\n",
		Sections: []preprocessors.ContentSection{
			{
				Name:       "office_metadata",
				Kind:       preprocessors.SectionKindMetadata,
				Text:       "Author: Jane Analyst",
				SourceFile: "report.docx",
				LineOffset: 0,
			},
			{
				Name:       "embedded",
				Kind:       preprocessors.SectionKindMetadata,
				Text:       "Artist: john.doe@example.com",
				SourceFile: "report.docx -> audio1.wav",
				LineOffset: 3,
			},
		},
	}

	units := legacyMetadataUnits(content)
	if len(units) != 2 {
		t.Fatalf("got %d units, want one per declared section (2)", len(units))
	}

	if units[1].sourceFile != "report.docx -> audio1.wav" {
		t.Errorf("embedded section attributed to %q, want the archive member it came from.\n"+
			"Attributing it to the container loses real provenance and, because the "+
			"suppression hash folds the filename, invalidates rules written against it.",
			units[1].sourceFile)
	}
	if units[1].lineOffset != 3 {
		t.Errorf("lineOffset = %d, want 3: without it the validator's section-relative "+
			"lines are reported as file-relative and every saved suppression rule for "+
			"this file stops matching", units[1].lineOffset)
	}
}

// TestLegacyMetadataUnitsFailClosedWithoutSections is the floor. A caller that builds
// ProcessedContent by hand, or an older preprocessor that does not declare sections,
// must still get its text scanned — losing a precise label is acceptable, losing the
// scan is not.
func TestLegacyMetadataUnitsFailClosedWithoutSections(t *testing.T) {
	content := &preprocessors.ProcessedContent{
		OriginalPath: "report.docx",
		Text:         "Author: Jane Analyst\nssn 449-87-4100\n",
	}

	units := legacyMetadataUnits(content)
	if len(units) != 1 {
		t.Fatalf("got %d units, want exactly 1 covering the whole text", len(units))
	}
	if units[0].text != content.Text {
		t.Errorf("unit text = %q, want the whole extraction %q — a narrowed unit would "+
			"leave part of the file unscanned on this path", units[0].text, content.Text)
	}
	if units[0].sourceFile != "report.docx" {
		t.Errorf("sourceFile = %q, want the container path", units[0].sourceFile)
	}
	if units[0].lineOffset != 0 {
		t.Errorf("lineOffset = %d, want 0: the single unit starts at the top of the "+
			"extraction, so nothing should be added to its line numbers", units[0].lineOffset)
	}
}

// TestLegacyMetadataUnitsSkipEmptySections keeps the unit list free of sections with
// nothing to scan, matching what the routed path does.
func TestLegacyMetadataUnitsSkipEmptySections(t *testing.T) {
	content := &preprocessors.ProcessedContent{
		OriginalPath: "report.docx",
		Text:         "Author: Jane Analyst\n",
		Sections: []preprocessors.ContentSection{
			{Name: "office_metadata", Kind: preprocessors.SectionKindMetadata, Text: "Author: Jane Analyst"},
			{Name: "empty", Kind: preprocessors.SectionKindMetadata, Text: "   \n\t\n"},
		},
	}

	units := legacyMetadataUnits(content)
	if len(units) != 1 {
		t.Fatalf("got %d units, want 1 — the whitespace-only section should be skipped", len(units))
	}
}

// TestLegacyMetadataUnitsHandlesNil guards the degenerate input rather than panicking
// inside an error-recovery path, which is the last place a crash is welcome.
func TestLegacyMetadataUnitsHandlesNil(t *testing.T) {
	if units := legacyMetadataUnits(nil); units != nil {
		t.Errorf("got %v, want nil for nil content", units)
	}
}
