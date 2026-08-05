// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"os"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
)

// The tests below guard the GATE, not the product. A scoring harness fails in a
// specific and dangerous way: it keeps reporting a number that no longer means
// what it claims. Each test here kills one way that can happen.

func allCases() []Case { return append(GatedCases(), QuarantinedCases()...) }

// TestLabelsResolve — every label must actually be present in its own fixture.
//
// A typo'd label is not a detection failure, it is a corpus bug, and it would
// arrive as a permanent FN that someone might "fix" by weakening the validator.
func TestLabelsResolve(t *testing.T) {
	for _, c := range allCases() {
		lines := strings.Split(c.Input, "\n")
		for _, lb := range c.Labels {
			if lb.Line < 1 || lb.Line > len(lines) {
				t.Fatalf("%s: label line %d is outside the input (%d lines)", c.Name, lb.Line, len(lines))
			}
			if len(lb.Value) < minLabelBytes {
				t.Fatalf("%s line %d: label value is %d bytes, below the %d-byte floor; "+
					"a short label can be 'covered' by an unrelated fragment",
					c.Name, lb.Line, len(lb.Value), minLabelBytes)
			}
			if !strings.Contains(lines[lb.Line-1], lb.Value) {
				t.Fatalf("%s line %d: labelled value is not present on that line. "+
					"Ground truth must come from the fixture's own bytes.", c.Name, lb.Line)
			}
		}
	}
}

// TestValueOccursOnce — the invariant that makes the (line, value) key sound.
//
// detector.Match carries no byte offset, so a value appearing twice on one line
// cannot be attributed to a specific occurrence. Rather than pretend otherwise,
// the corpus forbids the case and this test fails loudly the day someone adds it.
func TestValueOccursOnce(t *testing.T) {
	for _, c := range allCases() {
		lines := strings.Split(c.Input, "\n")
		for _, lb := range c.Labels {
			if n := strings.Count(lines[lb.Line-1], lb.Value); n != 1 {
				t.Fatalf("%s line %d: labelled value occurs %d times on one line. "+
					"Match has no byte offset, so occurrences are indistinguishable; "+
					"split the case or relabel it.", c.Name, lb.Line, n)
			}
		}
	}
}

// TestChecksAreReal — an unknown check name FAILS OPEN.
//
// Measured: core.ScanContent with Checks:["SSNN"] returns err=nil and zero
// matches. A typo would therefore run no validators, find nothing, and score
// precision 1.000 over an empty numerator — a perfect grade for a broken harness.
func TestChecksAreReal(t *testing.T) {
	valid := map[string]bool{}
	for _, n := range core.CheckNames() {
		valid[n] = true
	}

	for _, c := range allCases() {
		if len(c.Checks) == 0 {
			t.Fatalf("%s: empty Checks silently means ALL validators; spell them out", c.Name)
		}
		for _, ck := range c.Checks {
			if strings.EqualFold(ck, "all") {
				t.Fatalf("%s: Checks must name validators explicitly, not %q", c.Name, ck)
			}
			if !valid[ck] {
				t.Fatalf("%s: check %q is not in core.CheckNames(). An unknown name does "+
					"NOT error — it runs zero validators and scores a false perfect.", c.Name, ck)
			}
		}
	}
}

// TestEveryLabelIsSatisfiedToday — no aspirational labels.
//
// A label the tool has never satisfied sits permanently in the recall
// denominator, so the headline number understates reality and never moves. Wishes
// belong in an issue; the quarantine (SSNUndecided) holds anything undecided.
func TestEveryLabelIsSatisfiedToday(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for _, c := range GatedCases() {
		out, misses, _, err := ScoreCase(c, cfg)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if out.FNMissed > 0 {
			t.Fatalf("%s: %d labelled value(s) are not detected at all today:\n  %s\n"+
				"A never-satisfied label poisons the recall denominator. If this is a "+
				"known gap, move the case to SSNUndecided and open an issue.",
				c.Name, out.FNMissed, strings.Join(misses, "\n  "))
		}
	}
}

// TestCorpusHasPositivesAndNegatives — an all-negative corpus scores precision
// 1.000 at recall 0 and looks excellent while proving nothing.
func TestCorpusHasPositivesAndNegatives(t *testing.T) {
	var pos, neg, labels int
	for _, c := range GatedCases() {
		if c.Negative {
			neg++
		}
		if len(c.Labels) > 0 {
			pos++
			labels += len(c.Labels)
		}
	}
	if pos == 0 || neg == 0 || labels == 0 {
		t.Fatalf("corpus needs both polarities: positives=%d negatives=%d labels=%d", pos, neg, labels)
	}
}

// TestBandsMatchShared — the gate must not drift from the product's own bands.
//
// band() delegates to shared.GetConfidenceLevel; this pins the boundaries so a
// product threshold change cannot silently reinterpret every recorded MinBand.
func TestBandsMatchShared(t *testing.T) {
	cases := []struct {
		conf float64
		want Band
	}{
		{0, BandLow}, {59.9, BandLow}, {60, BandMedium}, {89.9, BandMedium}, {90, BandHigh}, {100, BandHigh},
	}
	for _, tc := range cases {
		if got := band(tc.conf); got != tc.want {
			t.Errorf("band(%.1f) = %s, want %s (shared.GetConfidenceLevel says %q). "+
				"The gate's bands must track the product's.",
				tc.conf, got, tc.want, shared.GetConfidenceLevel(tc.conf))
		}
	}
}

// TestHygiene — the scan must not depend on the developer's machine.
//
// Measured: LoadConfigOrDefault("") discovers ~/.ferret-scan/config.yaml and
// changed the enabled-validator count (2 vs 0) depending on the home directory.
// A user suppression file could likewise delete a labelled finding and read as a
// regression in CI but not locally.
func TestHygiene(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for _, c := range GatedCases() {
		sc := scanConfig(c, cfg)
		if sc.SuppressionManager != nil {
			t.Fatalf("%s: SuppressionManager must be nil; it would read the user's file", c.Name)
		}
		if sc.ValidatorBudgets != nil {
			t.Fatalf("%s: ValidatorBudgets must be nil; a budget makes results partial", c.Name)
		}
		res, err := core.ScanContent(c.Input, sc)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if res.SuppressedCount != 0 {
			t.Fatalf("%s: %d matches were suppressed; the score would silently exclude them",
				c.Name, res.SuppressedCount)
		}
		if res.Incomplete {
			t.Fatalf("%s: scan incomplete (%s); 'did not finish' must never score as 'clean'",
				c.Name, res.IncompleteReason)
		}
	}
}

// TestCoverMinBytes — the TP rule cannot be satisfied by a degenerate report.
func TestCoverMinBytes(t *testing.T) {
	const label = "130-07-5728"
	if covers("-", label) {
		t.Error("a 1-byte report must not cover an 11-byte label; recall would be trivially perfect")
	}
	// An 8-byte prefix DOES count: it clears the length floor and is contained by
	// the label, which is the intended bidirectional rule (a validator may report a
	// narrower span than the label, e.g. stopping before a trailing character).
	if !covers("130-07-5", label) {
		t.Error("an 8-byte substring clears the length floor and is contained by the label, " +
			"so it must count; the floor exists only to reject degenerate short reports")
	}
	if covers("130-07", label) {
		t.Error("a 6-byte report is below the length floor and must not count")
	}
	if !covers(label, label) {
		t.Error("exact match must count")
	}
	if !covers("SSN 130-07-5728.", label) {
		t.Error("a wider report containing the label must count")
	}
}

// TestNegativeCasesHaveNoLabels — a case cannot be both polarities.
func TestNegativeCasesHaveNoLabels(t *testing.T) {
	for _, c := range GatedCases() {
		if c.Negative && len(c.Labels) > 0 {
			t.Fatalf("%s is Negative but carries %d labels", c.Name, len(c.Labels))
		}
		if !c.Negative && len(c.Labels) == 0 {
			t.Fatalf("%s has no labels and is not marked Negative, so it scores nothing", c.Name)
		}
	}
}

// TestOriginAndRationalePresent — a hand-labelled corpus is only as trustworthy as
// its provenance. A label with no stated reason cannot be reviewed, and review is
// the ONLY defence against a wrong label.
func TestOriginAndRationalePresent(t *testing.T) {
	for _, c := range allCases() {
		if strings.TrimSpace(c.Origin) == "" {
			t.Errorf("%s: Origin is empty; a label with no provenance cannot be audited", c.Name)
		}
		if strings.TrimSpace(c.Rationale) == "" {
			t.Errorf("%s: Rationale is empty; state WHY this shape must behave this way", c.Name)
		}
	}
}

// TestSourceIsASCII — Windows CI safety.
//
// Some fixtures MUST contain non-ASCII bytes, because handling them is the point:
// a UTF-8 BOM ahead of a CSV header, an em-dash beside an SSN. What must not
// happen is those bytes sitting raw in the .go file, where an editor or a
// re-encoding toolchain can rewrite them and silently change the fixture.
//
// So the assertion is about the SOURCE FILE, not the decoded values: cases_ssn.go
// must be pure ASCII, with every non-ASCII byte written as an explicit \u escape.
// (Comments are excluded — prose may contain typographic characters.)
func TestSourceIsASCII(t *testing.T) {
	src, err := os.ReadFile("cases_ssn.go")
	if err != nil {
		t.Fatalf("read corpus source: %v", err)
	}
	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue // prose
		}
		for j := 0; j < len(line); j++ {
			if line[j] > 127 {
				t.Errorf("cases_ssn.go:%d has a raw non-ASCII byte 0x%02x in code; write it "+
					"as an explicit \\u escape so re-encoding cannot alter the fixture",
					i+1, line[j])
				break
			}
		}
	}
}

// TestByteSensitiveFixturesSurvive — the escapes must actually decode to the bytes
// the fixture is testing. An escape that silently produced ASCII would turn a BOM
// case into an ordinary CSV case and quietly reduce coverage.
func TestByteSensitiveFixturesSurvive(t *testing.T) {
	// Written as escapes for the same reason the corpus is: a raw BOM in Go source
	// is rejected outright by the compiler ("illegal byte order mark"), and a raw
	// em-dash is the kind of byte a re-encoding editor rewrites.
	want := map[string]string{
		"c33_bom_ssn_header":    "\ufeff",
		"c47_bom_ssn_first_col": "\ufeff",
		"p16_em_dash":           "\u2014",
	}
	seen := map[string]bool{}
	for _, c := range allCases() {
		if w, ok := want[c.Name]; ok {
			seen[c.Name] = true
			if !strings.Contains(c.Input, w) {
				t.Errorf("%s no longer contains the byte sequence it exists to test (%q); "+
					"the escape was lost", c.Name, w)
			}
		}
	}
	for n := range want {
		if !seen[n] {
			t.Errorf("byte-sensitive case %s is missing from the corpus", n)
		}
	}
}

// TestResidueIgnoresRedactionMarkers — the metric must not score the redactor's own
// output as a leak.
//
// Measured before the fix: the "simple" strategy writes "[EMAIL-REDACTED]", whose
// substring "EMAIL" matched the labelled address "alice.morgan@northwind-labs.com",
// so a perfectly redacted CSV reported 5 bytes of residue. That is a false alarm in
// the direction that erodes trust in the gate.
func TestResidueIgnoresRedactionMarkers(t *testing.T) {
	const value = "alice.morgan@northwind-labs.com"
	original := "name,email,dept\nA Morgan," + value + ",Finance\n"
	redacted := "name,email,dept\nA Morgan,[EMAIL-REDACTED],Finance\n"

	if got := longestResidueRaw(value, redacted); got == 0 {
		t.Fatalf("precondition lost: the raw scan no longer sees the marker collision, "+
			"so this test proves nothing (value=%q)", value)
	}
	if got := longestResidue(value, original, redacted); got != 0 {
		t.Errorf("longestResidue = %d, want 0: the only surviving bytes come from the "+
			"redactor's own placeholder, not from the original value", got)
	}

	// And a REAL leak must still be caught after the filtering.
	leaky := "name,email,dept\nA Morgan," + value + ",Finance\n"
	if got := longestResidue(value, original, leaky); got != len(value) {
		t.Errorf("longestResidue on a real leak = %d, want %d; marker filtering must not "+
			"hide surviving payload", got, len(value))
	}
}

// TestUnscoredChecksAreAccountedFor — every check must be either scored or listed
// with a reason.
//
// A check that is silently absent reads as "covered" to anyone glancing at the
// scorecard. This forces the gap to be named. It also fails when a NEW validator is
// added, which is the right moment to decide whether to score it.
func TestUnscoredChecksAreAccountedFor(t *testing.T) {
	scored := map[string]bool{}
	for _, c := range GatedCases() {
		for _, ck := range c.Checks {
			scored[ck] = true
		}
	}
	for _, fc := range ContainerCases() {
		for _, ck := range fc.Checks {
			scored[ck] = true
		}
	}

	for _, name := range core.CheckNames() {
		if scored[name] {
			if reason, listed := UnscoredChecks[name]; listed {
				t.Errorf("%s is BOTH scored and listed in UnscoredChecks (%q); remove the "+
					"stale entry so the list stays trustworthy", name, reason)
			}
			continue
		}
		if _, listed := UnscoredChecks[name]; !listed {
			t.Errorf("%s has no corpus case and no entry in UnscoredChecks. An unmeasured "+
				"check that is simply absent looks covered; name the gap and the reason.", name)
		}
	}

	// And the reverse: a name in the list that is not a real check is a typo that
	// would silently excuse nothing.
	valid := map[string]bool{}
	for _, n := range core.CheckNames() {
		valid[n] = true
	}
	for name := range UnscoredChecks {
		if !valid[name] {
			t.Errorf("UnscoredChecks lists %q, which is not in core.CheckNames()", name)
		}
	}
}

// TestFixtureCredentialsAreWellFormed — the runtime assembly must not have changed
// what the validator sees.
//
// The credential fixtures are concatenated at init (see fixture_credentials.go) so a
// literal token does not sit in committed source and trip GitHub push protection.
// That is a real risk of silent breakage: if a split dropped a character or a prefix,
// the SECRETS case would quietly stop being a credential and the corpus would score
// a shape that no longer matters. This asserts the assembled values are still exactly
// what the validator recognises, by checking the labels resolve AND the shapes hold.
func TestFixtureCredentialsAreWellFormed(t *testing.T) {
	if got := len(fakeGitHubToken); got != 40 {
		t.Errorf("fakeGitHubToken is %d bytes, want 40 (ghp_ + 36); the split dropped "+
			"or added a character and the value is no longer token-shaped", got)
	}
	if !strings.HasPrefix(fakeGitHubToken, "ghp_") {
		t.Error("fakeGitHubToken lost its ghp_ prefix, so it is no longer a GitHub token shape")
	}
	if !strings.HasPrefix(fakeAWSAccessKeyID, "AKIA") || len(fakeAWSAccessKeyID) != 20 {
		t.Errorf("fakeAWSAccessKeyID is not AKIA + 16 chars (got %d bytes)", len(fakeAWSAccessKeyID))
	}

	// And the corpus must actually USE them, or the constants are dead weight and the
	// SECRETS coverage is imaginary.
	var usedGH, usedAWS bool
	for _, c := range GatedCases() {
		if strings.Contains(c.Input, fakeGitHubToken) {
			usedGH = true
		}
		if strings.Contains(c.Input, fakeAWSAccessKeyID) {
			usedAWS = true
		}
	}
	if !usedGH {
		t.Error("no case contains fakeGitHubToken; the GITHUB_TOKEN shape is unmeasured")
	}
	if !usedAWS {
		t.Error("no case contains fakeAWSAccessKeyID; the AWS_ACCESS_KEY shape is unmeasured")
	}
}
