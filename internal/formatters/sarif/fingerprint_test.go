// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// Every SARIF result carries the finding's line-move-stable identity under
// partialFingerprints, so a consumer that keyed a decision on a finding (an
// external suppression store, a report differ, GitHub alert tracking) keeps
// matching it after an edit above it moved its line. The suppression engine
// already had this identity — rule files re-anchor on it — but SARIF never
// exposed it, so every SARIF consumer was stuck pinning lines.
func fingerprintMatch() detector.Match {
	const line = `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	return detector.Match{
		Text: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Type: "AWS_SECRET_ACCESS_KEY",
		Confidence: 95, LineNumber: 12, Filename: "src/config.py", Validator: "secrets",
		StartColumn: 26, EndColumn: 66,
		Context: detector.ContextInfo{
			FullLine:   line,
			BeforeText: "import os\n",
			AfterText:  "\nclient = boto3.client()",
		},
	}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestEveryResultCarriesTheIdentityFingerprint(t *testing.T) {
	mapper := NewVulnerabilityMapper(NewRuleManager())
	match := fingerprintMatch()

	result, err := mapper.MapToSARIFResult(match, formatters.FormatterOptions{})
	if err != nil {
		t.Fatalf("MapToSARIFResult: %v", err)
	}
	got := result.PartialFingerprints[suppressions.FindingIdentityFingerprintName]
	if !hex64.MatchString(got) {
		t.Fatalf("result fingerprint %q is not a 64-char hex sha256", got)
	}
	if want := suppressions.FindingIdentityFingerprint(match); got != want {
		t.Fatalf("formatter wrote %q, the identity function says %q", got, want)
	}

	// A suppressed result is the same finding; it carries the same identity.
	suppressedResult, err := mapper.MapSuppressedMatch(
		detector.SuppressedMatch{Match: match, RuleReason: "accepted"},
		formatters.FormatterOptions{},
	)
	if err != nil {
		t.Fatalf("MapSuppressedMatch: %v", err)
	}
	if sup := suppressedResult.PartialFingerprints[suppressions.FindingIdentityFingerprintName]; sup != got {
		t.Fatalf("suppressed result fingerprint %q differs from the reported one %q", sup, got)
	}
}

// The fingerprint's one promise: the line number is NOT an input. An unrelated
// edit above the finding moves its line and changes nothing else; the identity
// must hold, or every consumer keyed on it resurrects the finding — the exact
// defect line-pinned suppressions have.
func TestFingerprintSurvivesALineMove(t *testing.T) {
	before := fingerprintMatch()
	after := fingerprintMatch()
	after.LineNumber = 319

	if suppressions.FindingIdentityFingerprint(before) != suppressions.FindingIdentityFingerprint(after) {
		t.Fatal("a pure line move changed the fingerprint")
	}
}

// Everything that IS identity still participates: a different matched value, a
// different file basename or different context windows is a different finding.
func TestFingerprintChangesWithTheIdentity(t *testing.T) {
	base := fingerprintMatch()
	want := suppressions.FindingIdentityFingerprint(base)

	value := fingerprintMatch()
	value.Text = "AKIAIOSFODNN7EXAMPLE"
	file := fingerprintMatch()
	file.Filename = "src/other.py"
	context := fingerprintMatch()
	context.Context.BeforeText = "def helper():\n"

	for name, m := range map[string]detector.Match{
		"matched value": value, "file basename": file, "context window": context,
	} {
		if suppressions.FindingIdentityFingerprint(m) == want {
			t.Errorf("changing the %s did not change the fingerprint", name)
		}
	}

	// Confidence is a score, not identity (the suppression engine's own rule):
	// retuning a detector must not invalidate stored fingerprints.
	rescored := fingerprintMatch()
	rescored.Confidence = 40
	if suppressions.FindingIdentityFingerprint(rescored) != want {
		t.Error("a confidence change moved the fingerprint; scores are not identity")
	}
}

// Two findings for different values on ONE line have different context windows
// and values, so they get distinct fingerprints — the case a line-granular
// suppression cannot split.
func TestSameLineFindingsGetDistinctFingerprints(t *testing.T) {
	first := fingerprintMatch()
	second := fingerprintMatch()
	second.Text = "AKIAIOSFODNN7EXAMPLE"
	second.StartColumn, second.EndColumn = 1, 21

	if suppressions.FindingIdentityFingerprint(first) == suppressions.FindingIdentityFingerprint(second) {
		t.Fatal("two different values on one line share a fingerprint")
	}
}

// The flip side of line-move stability, pinned deliberately: identical
// repeated lines ARE one identity. Re-anchoring refuses this case as
// ambiguous; the fingerprint publishes it, and the docs tell consumers to
// combine it with the location when copies must be told apart. If this test
// starts failing, the collision semantics changed and the docs and key
// version must move with it.
func TestIdenticalRepeatedLinesShareOneFingerprint(t *testing.T) {
	first := fingerprintMatch()
	second := fingerprintMatch()
	second.LineNumber = 319 // same content, another copy of the line

	if suppressions.FindingIdentityFingerprint(first) != suppressions.FindingIdentityFingerprint(second) {
		t.Fatal("identical repeated lines no longer share a fingerprint")
	}
}

// The v5 formula trims outer edges: re-indenting the line, a trailing \r, and
// edge whitespace on the windows are not identity. The fingerprint leans on
// exactly that property for its stability promise, so it is pinned here.
func TestFingerprintSurvivesReindentAndCRLF(t *testing.T) {
	want := suppressions.FindingIdentityFingerprint(fingerprintMatch())

	reindented := fingerprintMatch()
	reindented.Context.FullLine = "    " + reindented.Context.FullLine + "  "
	cr := fingerprintMatch()
	cr.Context.FullLine = cr.Context.FullLine + "\r"
	edges := fingerprintMatch()
	edges.Context.BeforeText = "  " + edges.Context.BeforeText
	edges.Context.AfterText = edges.Context.AfterText + " \r"

	if got := suppressions.FindingIdentityFingerprint(reindented); got != want {
		t.Error("re-indenting the line changed the fingerprint")
	}
	if got := suppressions.FindingIdentityFingerprint(cr); got != want {
		t.Error("a trailing \\r changed the fingerprint")
	}
	if got := suppressions.FindingIdentityFingerprint(edges); got != want {
		t.Error("edge whitespace on the windows changed the fingerprint")
	}
}

// A finding with no recorded context (historically the contextless
// validators) still fingerprints: stable, well-formed, and distinct from the
// same finding with context.
func TestEmptyContextFindingsStillFingerprint(t *testing.T) {
	bare := fingerprintMatch()
	bare.Context = detector.ContextInfo{}

	got := suppressions.FindingIdentityFingerprint(bare)
	if !hex64.MatchString(got) {
		t.Fatalf("empty-context fingerprint %q is not a 64-char hex sha256", got)
	}
	if got == suppressions.FindingIdentityFingerprint(fingerprintMatch()) {
		t.Fatal("empty-context finding shares a fingerprint with the contextful one")
	}
}

// FullLine's contribution is capped (the suppression hash's maxHashLineLen,
// 8192 bytes): two pathological single-line inputs differing only past the
// cap share a fingerprint. Pinned so the bound is a documented behavior, not
// a surprise.
func TestFingerprintCapsTheLineContribution(t *testing.T) {
	long := strings.Repeat("a", 9000)
	first := fingerprintMatch()
	first.Context.FullLine = long + "X"
	second := fingerprintMatch()
	second.Context.FullLine = long + "Y"

	if suppressions.FindingIdentityFingerprint(first) != suppressions.FindingIdentityFingerprint(second) {
		t.Fatal("lines differing only past the 8192-byte cap got distinct fingerprints")
	}
	third := fingerprintMatch()
	third.Context.FullLine = "b" + long
	if suppressions.FindingIdentityFingerprint(first) == suppressions.FindingIdentityFingerprint(third) {
		t.Fatal("lines differing inside the cap share a fingerprint")
	}
}
