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

func TestTrimRuneFragments(t *testing.T) {
	const cjk = "資料" // 3 bytes per rune

	cases := []struct {
		name         string
		in, wantHead string
		wantTail     string
	}{
		{"empty", "", "", ""},
		{"ascii untouched", "abc", "abc", "abc"},
		{"clean multibyte untouched", cjk, cjk, cjk},
		{"encoded replacement char kept", "�", "�", "�"},
		// A window cut one byte into a 3-byte rune leaves two continuation
		// bytes at the head; cut two bytes in, one leading byte at the tail.
		{"head fragment trimmed", cjk[1:], cjk[3:], cjk[1:]},
		{"tail fragment trimmed", cjk[:4], cjk[:4], cjk[:3]},
		{"tail lead byte trimmed", cjk[:5], cjk[:5], cjk[:3]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimLeadingRuneFragment(tc.in); got != tc.wantHead {
				t.Errorf("trimLeadingRuneFragment(%q) = %q, want %q", tc.in, got, tc.wantHead)
			}
			if got := trimTrailingRuneFragment(tc.in); got != tc.wantTail {
				t.Errorf("trimTrailingRuneFragment(%q) = %q, want %q", tc.in, got, tc.wantTail)
			}
		})
	}
}

// TestTrimIsBoundedNotSanitizing pins the deliberate limit on the repair: it
// fixes a cut edge, it does not scrub malformed input. A caller scanning
// genuinely mis-encoded content still sees that content.
func TestTrimIsBoundedNotSanitizing(t *testing.T) {
	// Invalid bytes sitting past the boundary region survive.
	const inner = "ok\xff\xfe more text"
	if got := trimLeadingRuneFragment(inner); got != inner {
		t.Errorf("trimLeadingRuneFragment(%q) = %q, want it unchanged", inner, got)
	}
	// At most utf8.UTFMax-1 bytes come off either edge.
	longRun := strings.Repeat("\x80", 16)
	if got := trimLeadingRuneFragment(longRun); len(longRun)-len(got) > utf8.UTFMax-1 {
		t.Errorf("trimmed %d bytes from the head, want at most %d", len(longRun)-len(got), utf8.UTFMax-1)
	}
	if got := trimTrailingRuneFragment(longRun); len(longRun)-len(got) > utf8.UTFMax-1 {
		t.Errorf("trimmed %d bytes from the tail, want at most %d", len(longRun)-len(got), utf8.UTFMax-1)
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

// TestValidatorsWithoutContextAreDocumented locks the gap the doc comment
// promises, in both directions.
//
// SECRETS, PERSON_NAME and CLOUD_RESOURCES never populate Match.Context, so
// their findings report blank context however much text surrounds them. That is
// worth a test rather than a footnote: it is the case where a caller is most
// likely to mistake "not recorded" for "the value stood alone", and SECRETS is
// where the real-vs-example question is hardest.
//
// If a change starts populating context for one of these, this test fails on
// purpose. The fix is to update the Finding doc comment and drop the validator
// from this list — and to check the suppression finding-hash first, since
// Context participates in it and attaching context silently rewrites the
// identity of every finding of that type.
func TestValidatorsWithoutContextAreDocumented(t *testing.T) {
	cases := []struct {
		validator string
		input     string
	}{
		{"secrets", "AWS key AKIAIOSFODNN7EXAMPLE rotate quarterly\n"},
		{"PERSON_NAME", "Owner is Michael Thompson per HR record\n"},
		{"cloud_resources", "Bucket arn:aws:s3:::prod-customer-exports listed here\n"},
	}
	for _, tc := range cases {
		t.Run(tc.validator, func(t *testing.T) {
			r, err := ScanText(context.Background(), tc.input, TextOptions{})
			if err != nil {
				t.Fatal(err)
			}
			f := findByValidator(t, r.Findings, tc.validator)

			if f.ContextBefore != "" || f.ContextAfter != "" || f.FullLine != "" {
				t.Errorf("validator %q now populates context (before=%q after=%q fullline=%q).\n"+
					"This is an improvement, but it changes the documented contract: update the "+
					"Finding doc comment and confirm the suppression finding-hash impact "+
					"(internal/suppressions.findingHashVersion reads all three fields, so existing "+
					"rules for %s findings stop matching once they are populated).",
					tc.validator, f.ContextBefore, f.ContextAfter, f.FullLine, f.Type)
			}
		})
	}
}
