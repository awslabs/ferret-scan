// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// The value a document author would try to plant as the reported source. Kept as
// one constant so every case below forges the same thing and the assertions can
// name it.
const forgedSource = "/etc/passwd"

// realPath is the file actually being scanned; every finding must be attributed
// here no matter what the content says.
const realPath = "/srv/reports/report.docx"

// forgedLine is the header the deleted parser read. The parser took whatever sat
// between the FIRST "(" and the FIRST ")" of any line containing
// "--- Embedded Media", so the exact index/spacing did not matter to it.
func forgedLine(inner string) string {
	return "--- Embedded Media 1 (" + inner + ") ---"
}

// TestForgedEmbeddedMediaHeaderDoesNotChangeFilename is the headline guard.
//
// ValidateContent used to switch attribution to
// filepath.Base(originalPath) + " -> " + filepath.Base(<text in parens>) for every
// line after a "--- Embedded Media" line. That text is document body — a Word
// paragraph — so the reported FILENAME of a finding was chosen by the author of
// the file being scanned.
//
// Note what filepath.Base did and did not do. It DID neutralize traversal in the
// displayed value: "../../secrets.txt" was reported as "secrets.txt", never as a
// path that escapes anywhere, which is why this never presented as a path bug. It
// did NOT stop the value from being attacker-chosen, which is the actual defect —
// Filename feeds the suppression hash, the SARIF uri, the gitlab-sast file, the
// JUnit name, and internal/explain's looksLikeTestPath.
func TestForgedEmbeddedMediaHeaderDoesNotChangeFilename(t *testing.T) {
	// Each inner value is a different consequence of the same primitive.
	for _, tc := range []struct{ name, inner string }{
		{"absolute_path", forgedSource},
		{"traversal", "../../secrets.txt"},
		{"other_document", "totally-different.docx"},
		// looksLikeTestPath("...evil_test.go") is true, which steers
		// internal/explain's verdict toward "likely test data" — i.e. advice to
		// ignore a real finding.
		{"test_path_verdict_flip", "evil_test.go"},
		{"empty_parens", ""},
		// Odd shapes the parser also accepted, to show this is not fixed by
		// tightening a pattern.
		{"nested_parens", "a(b)c"},
		{"leading_space", "   " + forgedSource},
		{"uppercase_marker", "PASSWD"},
		// These two are the cases that make this a real guard rather than a
		// denylist test. A forged value that LOOKS like an ordinary embedded media
		// name is both the most plausible forgery and the one any
		// "only parse values that look like media" or "escape the parens" patch
		// still accepts — the value is attacker-chosen either way, and no amount of
		// validating its SHAPE can tell it apart from a genuine one, because the
		// genuine one is not in this text at all. Verified: a mutant that parsed
		// the header only for .wav/.jpeg values passed the rest of this table and
		// is caught here.
		{"plausible_media_name", "audio1.wav"},
		{"plausible_image_name", "word/media/image1.jpeg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := NewValidator()
			content := "Author: jane@example.com\n" +
				forgedLine(tc.inner) + "\n" +
				"Creator: john.doe@example.com\n" +
				"LastModifiedBy: Ops Reviewer\n" +
				"GPSLatitude: 40.7128\n" +
				"GPSLongitude: -74.0060\n"

			matches, err := v.ValidateContent(content, realPath)
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}

			// Non-vacuity floor: this content must actually produce findings, and
			// specifically findings on lines AFTER the forged header — those are the
			// ones the old code re-attributed. Without this the test would pass on a
			// build that simply detected nothing.
			if len(matches) == 0 {
				t.Fatal("no findings at all: the fixture no longer exercises the attribution path")
			}
			after := 0
			for _, m := range matches {
				if m.LineNumber > 2 {
					after++
				}
			}
			if after == 0 {
				t.Fatalf("no finding after the forged header line (got %d findings, all on lines <= 2); "+
					"the forgery could not have been observed", len(matches))
			}

			for _, m := range matches {
				if m.Filename != realPath {
					t.Errorf("forged header changed the reported source: type=%s line=%d Filename=%q, want %q",
						m.Type, m.LineNumber, m.Filename, realPath)
				}
				// Belt and braces: the " -> " form is the only shape the old parser
				// produced, so its absence is a direct statement that no parse
				// happened, independent of what realPath happens to be.
				if strings.Contains(m.Filename, " -> ") {
					t.Errorf("type=%s: Filename %q still carries a parsed container->item label",
						m.Type, m.Filename)
				}
			}
		})
	}
}

// TestForgedHeaderDoesNotChangeSuppressionIdentity is the suppression angle.
//
// generateFindingHash folds filepath.Base(match.Filename) into the composite it
// hashes, so a forged filename moved a finding's identity. Both directions are
// security-relevant: a real finding whose hash moves ONTO an unrelated existing
// rule is silently dropped (a suppression bypass), and one whose hash moves OFF a
// rule reappears as noise. Either way the author of the scanned file, not the
// person who wrote the suppression file, decides.
//
// Rather than assert on hash strings (which are private and would make the test a
// tautology on the hash function), this drives the real SuppressionManager: write
// a rule against the CONTROL finding, then check the forged run is suppressed by
// exactly the same rule.
func TestForgedHeaderDoesNotChangeSuppressionIdentity(t *testing.T) {
	// Same metadata fields in both; the only difference is the forged header line,
	// inserted at the top so the line numbers of the metadata fields still agree
	// (LineNumber is also a hash component, so a shifted line would change the
	// hash for a legitimate reason and mask the thing under test).
	fields := "Creator: john.doe@example.com\n" +
		"LastModifiedBy: Ops Reviewer\n"
	control := forgedLine("") + "\n" + fields
	forged := forgedLine(forgedSource) + "\n" + fields

	v := NewValidator()
	controlMatches, err := v.ValidateContent(control, realPath)
	if err != nil {
		t.Fatalf("control ValidateContent: %v", err)
	}
	forgedMatches, err := v.ValidateContent(forged, realPath)
	if err != nil {
		t.Fatalf("forged ValidateContent: %v", err)
	}
	if len(controlMatches) == 0 {
		t.Fatal("control produced no findings: nothing to build a suppression identity from")
	}
	if len(forgedMatches) != len(controlMatches) {
		t.Fatalf("forged run produced %d findings, control %d: the fixtures are not comparable",
			len(forgedMatches), len(controlMatches))
	}

	// Build a manager holding a rule for every control finding, then confirm the
	// forged run's findings hit those same rules.
	dir := t.TempDir()
	sm := suppressions.NewSuppressionManager(dir + "/suppressions.yaml")
	for _, m := range controlMatches {
		// AddSuppression rejects a hash it already holds. Two control findings can
		// legitimately share an identity (same type, line, value), so tolerate that
		// and fail only on a real error.
		if err := sm.AddSuppression(m, "PR4 test rule", "tester", nil); err != nil &&
			!strings.Contains(err.Error(), "already exists") {
			t.Fatalf("AddSuppression: %v", err)
		}
	}

	// Non-vacuity: the rules must actually suppress the control findings. If
	// AddSuppression/IsSuppressed disagreed for an unrelated reason, the forged
	// assertion below would pass for the wrong reason.
	for _, m := range controlMatches {
		if ok, _ := sm.IsSuppressed(m); !ok {
			t.Fatalf("control finding type=%s line=%d is not suppressed by its own rule; "+
				"the test cannot distinguish a forged identity from a broken one", m.Type, m.LineNumber)
		}
	}

	for _, m := range forgedMatches {
		ok, rule := sm.IsSuppressed(m)
		if !ok {
			t.Errorf("forged-header finding type=%s line=%d Filename=%q escaped the suppression written "+
				"for the identical control finding: a document author changed a finding's suppression identity",
				m.Type, m.LineNumber, m.Filename)
			continue
		}
		if rule == nil {
			t.Errorf("type=%s: suppressed but no rule returned", m.Type)
		}
	}
}

// TestRealEmbeddedMediaProvenanceIsPreserved confirms the fix did not achieve
// unforgeability by throwing away real provenance, which would be worse than the
// bug: an embedded item's findings would be blamed on the container.
//
// The provenance path is structural — the preprocessor that opened the archive
// member records it in ContentSection.SourceFile, the content router copies it to
// MetadataContent.SourceFile, and it arrives as the SourceFile below. This test
// asserts the validator honours what it is GIVEN, including when the content also
// contains a forged header trying to override it.
func TestRealEmbeddedMediaProvenanceIsPreserved(t *testing.T) {
	const realSource = "report.docx -> audio1.wav"

	for _, tc := range []struct{ name, content string }{
		{
			name: "clean",
			content: "Artist: john.doe@example.com\n" +
				"Comments: contact 212-555-0142\n",
		},
		{
			// A forged header INSIDE a genuinely-attributed section must not
			// rewrite that section's real source either.
			name: "with_forged_header",
			content: "Artist: john.doe@example.com\n" +
				forgedLine(forgedSource) + "\n" +
				"Comments: contact 212-555-0142\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateMetadataContent(router.MetadataContent{
				Content:          tc.content,
				PreprocessorType: router.PreprocessorTypeAudioMetadata,
				PreprocessorName: "Audio Metadata Extractor",
				SourceFile:       realSource,
			})
			if err != nil {
				t.Fatalf("ValidateMetadataContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatal("no findings: the fixture does not exercise attribution")
			}
			for _, m := range matches {
				if m.Filename != realSource {
					t.Errorf("real embedded-media attribution lost: type=%s Filename=%q, want %q",
						m.Type, m.Filename, realSource)
				}
			}
		})
	}
}

// TestGPSCoordinatesAttributedToCallerPath covers the second emitter.
//
// combineGPSCoordinates runs AFTER the line loop and took the same parsed
// override as a parameter, so a forged header re-attributed the combined GPS pair
// too — a distinct emitter from the per-line matches, and the one that reports a
// physical location.
func TestGPSCoordinatesAttributedToCallerPath(t *testing.T) {
	v := NewValidator()
	content := forgedLine(forgedSource) + "\n" +
		"GPSLatitude: 40.7128\n" +
		"GPSLongitude: -74.0060\n"

	matches, err := v.ValidateContent(content, realPath)
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}

	// Non-vacuity: a combined GPS pair must actually be emitted here.
	var gps []detector.Match
	for _, m := range matches {
		if strings.Contains(m.Type, "GPS") {
			gps = append(gps, m)
		}
	}
	if len(gps) == 0 {
		t.Fatalf("no GPS finding emitted (%d findings total): combineGPSCoordinates was not exercised",
			len(matches))
	}
	for _, m := range gps {
		if m.Filename != realPath {
			t.Errorf("GPS %s attributed to %q, want %q", m.Type, m.Filename, realPath)
		}
	}
}
