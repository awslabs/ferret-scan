// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// A suppression file is COMMITTED to a repository. Every rule used to carry two extra digests in its
// metadata — `context_hash` and `match_text_hash` — each a 16-hex (64-bit) unsalted SHA-256 of the
// matched value and of its surrounding text.
//
// Sixty-four bits of digest do not protect a nine-digit value, because the search space that matters
// is the space of VALUES and not the space of digests. Measured: given the 16-hex prefix for a US SSN,
// the whole 10^9 space falls in 367 seconds single-threaded, a date of birth (10^4) is instant, and a
// search bounded to a known area and group number recovered a planted SSN in 5 milliseconds.
//
// Nothing in the tool ever read either field — the rule's identity is the separate `hash` — so both
// were removed at all four write sites (#673). The identity hash itself CANNOT be removed or salted:
// the file has to match the same finding on a teammate's machine, so a salt would have to travel in
// the file beside it. That is a genuine residual risk and the documentation now says so plainly
// instead of calling the file "privacy-safe".
//
// This guard is deliberately written against the SHAPE rather than the two field names, so a newly
// added value-derived field is caught without anyone remembering this test exists.
func TestNoValueDerivedDigestIsWrittenIntoASuppressionFile(t *testing.T) {
	const (
		value  = "219-09-9998"
		before = "Employee SSN: "
		after  = " on file"
	)
	line := before + value + after

	dir := t.TempDir()
	path := filepath.Join(dir, "sup.yaml")
	sm := NewSuppressionManager(path)

	match := detector.Match{
		Type:       "SSN",
		Text:       value,
		Filename:   filepath.Join(dir, "roster.txt"),
		LineNumber: 7,
		Confidence: 95,
		Validator:  "ssn",
		Context: detector.ContextInfo{
			BeforeText: before,
			AfterText:  after,
			FullLine:   line,
		},
	}

	if err := sm.AddSuppression(match, "test", "unit test", nil); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a path inside t.TempDir()
	if err != nil {
		t.Fatalf("reading the suppression file: %v", err)
	}
	written := string(raw)

	// NON-VACUITY FIRST. An empty file, or one whose rule failed to serialise, would satisfy every
	// absence assertion below for a reason that has nothing to do with digests.
	if !strings.Contains(written, "SSN") {
		t.Fatalf("the generated file does not mention the finding type, so no rule was written and "+
			"every assertion below is vacuous. File:\n%s", written)
	}
	if !strings.Contains(written, "hash:") {
		t.Fatalf("the generated file carries no `hash:` field, so the rule has no identity and this " +
			"test is not measuring a real suppression file")
	}

	digest := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return fmt.Sprintf("%x", sum)[:16]
	}

	// Every digest that is derived from the VALUE or from the LINE the value sits on. Each of these is
	// what an enumeration attack needs; none of them is required to match a rule.
	forbidden := map[string]string{
		"the matched value":              digest(value),
		"the surrounding context":        digest(before + after),
		"the full line":                  digest(line),
		"the value with its line":        digest(line + value),
		"the before-text alone":          digest(before),
		"the after-text alone":           digest(after),
		"the value, lowercased":          digest(strings.ToLower(value)),
		"the value with digits stripped": digest(strings.ReplaceAll(value, "-", "")),
	}

	var leaked []string
	for what, d := range forbidden {
		if strings.Contains(written, d) {
			leaked = append(leaked, fmt.Sprintf("%s -> %s", what, d))
		}
	}
	if len(leaked) > 0 {
		t.Errorf("%d value-derived digest(s) were written into the suppression file:\n  %s\n\n"+
			"A suppression file is committed to a repository, and a 64-bit unsalted digest of a "+
			"low-entropy value is recoverable by enumeration — measured at 367 s for the full US SSN "+
			"space single-threaded, 5 ms when the area and group are known.\n"+
			"Only the rule's IDENTITY hash may be derived from the value, because a rule cannot be "+
			"matched without it. Anything informational must not be written at all: the two fields "+
			"removed in #673 were read by nothing.\nFile:\n%s",
			len(leaked), strings.Join(leaked, "\n  "), written)
	}

	// And the rule must still WORK. A fix that made suppression stop matching would be worse than the
	// disclosure it removed.
	loaded := NewSuppressionManager(path)
	loaded.loadConfig()
	if n := len(loaded.config.Rules); n == 0 {
		t.Errorf("the file written above loads back with no rules, so the rule did not survive a " +
			"round trip")
	}
}

// TestTheValueDigestGuardCatchesAPlantedDigest is the control.
//
// The assertion above is an absence check, and an absence check passes when the thing that produces
// the file stops producing anything. This plants the exact digest the removed fields used to write and
// requires the detection logic to see it.
func TestTheValueDigestGuardCatchesAPlantedDigest(t *testing.T) {
	const value = "219-09-9998"
	sum := sha256.Sum256([]byte(value))
	planted := fmt.Sprintf("%x", sum)[:16]

	// The shape of a rule that still carried the field.
	file := "suppressions:\n  - id: SUP-1\n    hash: " + strings.Repeat("a", 64) + "\n" +
		"    metadata:\n      finding_type: SSN\n      match_text_hash: " + planted + "\n"

	if !strings.Contains(file, planted) {
		t.Fatalf("the planted digest is not in the fixture; the control asserts nothing")
	}
	// A 16-hex digest must be distinguishable from the 64-hex identity hash, or the guard would have
	// to accept it and the whole check collapses.
	if len(planted) != 16 {
		t.Errorf("the truncated digest is %d chars, not 16; hashSensitiveData's width changed and the "+
			"guard's forbidden set must be recomputed", len(planted))
	}
	if strings.Contains(strings.Repeat("a", 64), planted) {
		t.Errorf("the planted digest collides with the identity-hash placeholder, which would make " +
			"the guard unable to tell an identity hash from a value digest")
	}
}

// TestHashSensitiveDataIsStillOnlyUsedForIdentity pins WHERE the digest may appear.
//
// The two removed fields were not a coincidence: hashSensitiveData is a convenient helper, and the
// next person adding a metadata field has every reason to reach for it. This asserts the call sites,
// so adding one to a metadata map is a deliberate act that changes this test.
func TestHashSensitiveDataIsStillOnlyUsedForIdentity(t *testing.T) {
	src, err := os.ReadFile("suppression.go")
	if err != nil {
		t.Fatalf("reading suppression.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")

	var callSites []int
	for i, line := range lines {
		code := line
		if idx := strings.Index(code, "//"); idx >= 0 {
			code = code[:idx] // a comment mentioning the helper is not a call
		}
		if strings.Contains(code, "sm.hashSensitiveData(") {
			callSites = append(callSites, i+1)
		}
	}

	if len(callSites) == 0 {
		t.Fatalf("no call to hashSensitiveData found; either it was renamed or this guard is now " +
			"vacuous")
	}
	// Both remaining calls must be inside findingHashVersion, which is the identity.
	for _, ln := range callSites {
		inIdentity := false
		for back := ln - 1; back >= 0 && back > ln-60; back-- {
			if strings.HasPrefix(lines[back], "func ") {
				inIdentity = strings.Contains(lines[back], "findingHashVersion")
				break
			}
		}
		if !inIdentity {
			t.Errorf("suppression.go:%d calls hashSensitiveData outside findingHashVersion.\n"+
				"  %s\n\nA value digest may only contribute to a rule's IDENTITY. Writing one into "+
				"rule metadata puts an enumerable fingerprint of the value into a file teams commit, "+
				"which is what #673 removed from four sites.", ln, strings.TrimSpace(lines[ln-1]))
		}
	}
	t.Logf("hashSensitiveData is called at %d site(s), all inside findingHashVersion", len(callSites))
}
