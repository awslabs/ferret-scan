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

// TestEverySingleLineValidatorRecordsContext is the coverage floor: a validator
// that finds a value on one line must report the text around it.
//
// These three were the exceptions, and SECRETS was the costly one — "real key or
// documentation example" is the question context exists to answer, and the
// fixture below is `AKIAIOSFODNN7EXAMPLE`, the key from AWS's own docs. A caller
// reading blank context on a finding cannot tell "not recorded" from "the value
// stood alone", so a silent regression here would quietly degrade every
// context-dependent decision a consumer makes.
func TestEverySingleLineValidatorRecordsContext(t *testing.T) {
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
