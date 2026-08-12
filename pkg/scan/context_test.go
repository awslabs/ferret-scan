// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/goldencorpus"
)

// findByValidator returns the first finding produced by the named validator.
// Tests select on the validator rather than indexing Findings, because the
// order of the slice is the order validators complete, not source order.
func findByValidator(t *testing.T, findings []Finding, validator string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Validator == validator {
			return f
		}
	}
	t.Fatalf("no finding from validator %q in %d findings", validator, len(findings))
	return Finding{}
}

// TestContextExposedOnBothEntryPoints locks the context fields on the two public
// scan paths. Both go through mapResult, so this is really asserting that the
// mapping keeps the data rather than dropping it as it did before.
func TestContextExposedOnBothEntryPoints(t *testing.T) {
	const line = "Corporate card 4111-1111-1111-1111 expires soon\n"

	path := filepath.Join(t.TempDir(), "ctx.txt")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	fileResult, err := ScanFile(context.Background(), path, FileOptions{Checks: []string{"CREDIT_CARD"}})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	textResult, err := ScanText(context.Background(), line, TextOptions{Checks: []string{"CREDIT_CARD"}})
	if err != nil {
		t.Fatalf("ScanText: %v", err)
	}

	for _, tc := range []struct {
		entry    string
		findings []Finding
	}{
		{"ScanFile", fileResult.Findings},
		{"ScanText", textResult.Findings},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			f := findByValidator(t, tc.findings, "creditcard")

			if !strings.Contains(f.ContextBefore, "Corporate card") {
				t.Errorf("ContextBefore = %q, want it to contain the preceding text", f.ContextBefore)
			}
			if !strings.Contains(f.ContextAfter, "expires soon") {
				t.Errorf("ContextAfter = %q, want it to contain the following text", f.ContextAfter)
			}
			if got, want := f.FullLine, strings.TrimSuffix(line, "\n"); got != want {
				t.Errorf("FullLine = %q, want %q", got, want)
			}

			// The context brackets the match; it never restates it. A caller
			// that concatenated before+text+after must not get the value twice.
			if strings.Contains(f.ContextBefore, f.Text) {
				t.Errorf("ContextBefore %q must exclude the matched value %q", f.ContextBefore, f.Text)
			}
			if strings.Contains(f.ContextAfter, f.Text) {
				t.Errorf("ContextAfter %q must exclude the matched value %q", f.ContextAfter, f.Text)
			}
			if !strings.Contains(f.FullLine, f.Text) {
				t.Errorf("FullLine %q must contain the matched value %q", f.FullLine, f.Text)
			}
			if got := f.ContextBefore + f.Text + f.ContextAfter; !strings.Contains(f.FullLine, got) {
				t.Errorf("before+text+after = %q is not a span of FullLine %q", got, f.FullLine)
			}
		})
	}
}

// TestContextDoesNotSpanLines guards the documented single-line contract. A
// caller building an LLM prompt from context needs to know the blast radius of
// what it is about to send; "the neighbouring lines too" is a different and much
// larger promise than the one this package makes.
func TestContextDoesNotSpanLines(t *testing.T) {
	body := strings.Join([]string{
		"UNRELATED-PRECEDING-LINE",
		"Corporate card 4111-1111-1111-1111 expires soon",
		"UNRELATED-FOLLOWING-LINE",
	}, "\n") + "\n"

	r, err := ScanText(context.Background(), body, TextOptions{Checks: []string{"CREDIT_CARD"}})
	if err != nil {
		t.Fatal(err)
	}
	f := findByValidator(t, r.Findings, "creditcard")

	for name, got := range map[string]string{
		"ContextBefore": f.ContextBefore,
		"ContextAfter":  f.ContextAfter,
		"FullLine":      f.FullLine,
	} {
		if strings.Contains(got, "\n") {
			t.Errorf("%s = %q contains a newline; context is documented as single-line", name, got)
		}
		for _, leaked := range []string{"PRECEDING", "FOLLOWING"} {
			if strings.Contains(got, leaked) {
				t.Errorf("%s = %q leaked text from a neighbouring line", name, got)
			}
		}
	}
	if f.LineNumber != 2 {
		t.Errorf("LineNumber = %d, want 2", f.LineNumber)
	}
}

// TestContextIsValidUTF8 covers the reason the mapping trims rune fragments.
// Validators cut their context windows at byte offsets, so a run of multi-byte
// runes before the match gets sliced mid-rune. Handing that to a gomobile
// consumer means a mangled Java/Swift string, and to json.Marshal means a silent
// U+FFFD substitution, so the public fields are repaired at the boundary.
func TestContextIsValidUTF8(t *testing.T) {
	// Long enough that the window boundary lands inside the run of CJK runes
	// rather than before it.
	const line = "請注意這張公司信用卡的號碼是機密資料絕對不可以外流給任何人知道 4111-1111-1111-1111 這是機密資料絕對不可以外流給任何人知道請注意\n"

	r, err := ScanText(context.Background(), line, TextOptions{Checks: []string{"CREDIT_CARD"}})
	if err != nil {
		t.Fatal(err)
	}
	f := findByValidator(t, r.Findings, "creditcard")

	if f.ContextBefore == "" || f.ContextAfter == "" {
		t.Fatalf("fixture produced no context to check (before=%q after=%q)", f.ContextBefore, f.ContextAfter)
	}
	for name, got := range map[string]string{
		"ContextBefore": f.ContextBefore,
		"ContextAfter":  f.ContextAfter,
	} {
		if !utf8.ValidString(got) {
			t.Errorf("%s = %q is not valid UTF-8", name, got)
		}
	}
	// The repair trims, never pads: what survives is still a suffix/prefix of
	// the line's own bytes.
	if !strings.Contains(line, f.ContextBefore) {
		t.Errorf("ContextBefore %q is not a substring of the input line", f.ContextBefore)
	}
	if !strings.Contains(line, f.ContextAfter) {
		t.Errorf("ContextAfter %q is not a substring of the input line", f.ContextAfter)
	}
}

// TestContextExcludedFromJSON locks the `json:"-"` decision. Finding carries no
// tags on its other fields, so an existing caller's marshaled output is a
// stable shape it may already be persisting or shipping; three new raw-content
// fields must not appear in it just because the struct grew.
func TestContextExcludedFromJSON(t *testing.T) {
	r, err := ScanText(context.Background(),
		"Corporate card 4111-1111-1111-1111 expires soon\n",
		TextOptions{Checks: []string{"CREDIT_CARD"}})
	if err != nil {
		t.Fatal(err)
	}
	f := findByValidator(t, r.Findings, "creditcard")
	if f.ContextBefore == "" {
		t.Fatal("fixture produced no context, so the exclusion is not actually being tested")
	}

	encoded, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"ContextBefore", "ContextAfter", "FullLine", "Corporate card"} {
		if strings.Contains(string(encoded), unwanted) {
			t.Errorf("marshaled Finding contains %q; context must not widen the JSON surface:\n%s",
				unwanted, encoded)
		}
	}
	// The pre-existing shape is untouched.
	if !strings.Contains(string(encoded), `"Text":"4111-1111-1111-1111"`) {
		t.Errorf("marshaled Finding lost its existing fields:\n%s", encoded)
	}
}

// TestBackfilledValidatorsRecordContext covers the three validators that used to
// record no context at all.
//
// SECRETS was the costly one — "real key or documentation example" is the question
// context exists to answer, and the fixture below is `AKIAIOSFODNN7EXAMPLE`, the
// key from AWS's own docs. A caller reading blank context cannot tell "not
// recorded" from "the value stood alone", so a silent regression here would
// quietly degrade every context-dependent decision a consumer makes.
//
// This is deliberately not named for a universal claim: METADATA records FullLine
// and never before/after, which TestMetadataRecordsFullLineOnly pins.
func TestBackfilledValidatorsRecordContext(t *testing.T) {
	cases := []struct {
		validator     string
		input         string
		before, after string
	}{
		{"secrets", "AWS key AKIAIOSFODNN7EXAMPLE rotate quarterly\n", "AWS key ", " rotate quarterly"},
		{"PERSON_NAME", "Owner is Michael Thompson per HR record\n", "Owner is ", " per HR record"},
		{"cloud_resources", "Bucket arn:aws:s3:::prod-customer-exports listed here\n", "Bucket ", " listed here"},
	}
	for _, tc := range cases {
		t.Run(tc.validator, func(t *testing.T) {
			r, err := ScanText(context.Background(), tc.input, TextOptions{})
			if err != nil {
				t.Fatal(err)
			}
			f := findByValidator(t, r.Findings, tc.validator)

			if !strings.Contains(f.ContextBefore, strings.TrimSpace(tc.before)) {
				t.Errorf("ContextBefore = %q, want it to contain %q", f.ContextBefore, tc.before)
			}
			if !strings.Contains(f.ContextAfter, strings.TrimSpace(tc.after)) {
				t.Errorf("ContextAfter = %q, want it to contain %q", f.ContextAfter, tc.after)
			}
			if got, want := f.FullLine, strings.TrimSuffix(tc.input, "\n"); got != want {
				t.Errorf("FullLine = %q, want %q", got, want)
			}
			if strings.Contains(f.ContextBefore, f.Text) || strings.Contains(f.ContextAfter, f.Text) {
				t.Errorf("context must exclude the matched value %q (before=%q after=%q)",
					f.Text, f.ContextBefore, f.ContextAfter)
			}
		})
	}
}

// TestMultiLineSecretReportsNoContext pins the one documented empty case, so
// "empty" keeps meaning "not applicable to a match spanning lines" rather than
// drifting back into "some validators just don't bother".
func TestMultiLineSecretReportsNoContext(t *testing.T) {
	// Synthetic, structurally-shaped PEM block: the detector keys on the armour,
	// and no real key material is needed to exercise the path. Assembled from
	// split literals at runtime, following the convention in
	// internal/validators/secrets/validator_test.go (buildTestToken), so the
	// armour never appears contiguously in source and static secret scanners in
	// the pre-commit path do not flag this file.
	armour := func(edge string) string {
		return "-----" + edge + " OPENSSH " + "PRIVATE KEY" + "-----\n"
	}
	input := armour("BEGIN") +
		strings.Repeat("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2\n", 3) +
		armour("END")

	r, err := ScanText(context.Background(), input, TextOptions{Checks: []string{"SECRETS"}})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range r.Findings {
		if !strings.Contains(f.Text, "\n") {
			continue // single-line finding; covered by the test above
		}
		found = true
		if f.ContextBefore != "" || f.ContextAfter != "" || f.FullLine != "" {
			t.Errorf("multi-line %s finding reports context (before=%q after=%q fullline=%q); "+
				"a match spanning lines has no single line to describe",
				f.Type, f.ContextBefore, f.ContextAfter, f.FullLine)
		}
	}
	if !found {
		t.Skip("fixture produced no multi-line finding; nothing to assert")
	}
}

// TestMetadataRecordsFullLineOnly pins the third shape the Finding doc comment
// describes: METADATA reports the document property it read, not an offset inside
// a line, so it fills FullLine and leaves before/after permanently empty.
//
// Without this, a caller reading the doc comment's list of exceptions would
// reasonably conclude METADATA carries before/after. It never has. Backfilling it
// is tracked separately, and needs its own suppression-hash compatibility variant:
// METADATA's existing identities already fold a POPULATED FullLine together with
// an empty before/after pair, so it is a different migration from the one the
// contextless validators needed.
func TestMetadataRecordsFullLineOnly(t *testing.T) {
	// A real .docx carrying document properties, built with the corpus helper so
	// the metadata path runs exactly as it does in production.
	docx := goldencorpus.BuildDOCX("Michael Thompson", "Michael Thompson",
		[]string{"Quarterly summary. Nothing sensitive in the body."})

	path := filepath.Join(t.TempDir(), "props.docx")
	if err := os.WriteFile(path, docx, 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := ScanFile(context.Background(), path, FileOptions{Checks: []string{"METADATA"}})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	var seen int
	for _, f := range r.Findings {
		if f.Validator != "metadata" {
			continue
		}
		seen++
		if f.FullLine == "" {
			t.Errorf("%s finding has no FullLine; METADATA is documented as recording it", f.Type)
		}
		if f.ContextBefore != "" || f.ContextAfter != "" {
			t.Errorf("%s finding now records before/after (before=%q after=%q). That is an "+
				"improvement, but it changes the documented contract: update the Finding doc "+
				"comment, and check the suppression finding-hash first — Context.BeforeText and "+
				"AfterText are folded into a finding's identity, so populating them rewrites the "+
				"hash of every METADATA finding and existing operator rules stop matching.",
				f.Type, f.ContextBefore, f.ContextAfter)
		}
	}
	if seen == 0 {
		t.Fatal("fixture produced no METADATA findings, so the assertion is vacuous")
	}
}
