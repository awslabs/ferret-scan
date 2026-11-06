// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Part 2 of #888: a passport number written with lowercase letters was never a
// candidate. The value patterns and the format anchors were [A-Z]-only, so
// "Passport Number: gk123456" produced nothing from any validator and stayed in
// cleartext under --enable-redaction, while "Passport Number: GK123456" scored 85.
// Measured on main: 0 of 13 labelled lowercase or Title-case values reported.
//
// Lowercase is admitted by a second, mixed-case pass that only runs on lines with a
// passport label, behind a label-adjacency gate and a placeholder guard. Uppercase
// values keep today's path.

func scanPassport(t *testing.T, content string) []detector.Match {
	t.Helper()
	got, err := NewValidator().ValidateContent(content, "/test/mixed.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	return got
}

func findText(ms []detector.Match, text string) (detector.Match, bool) {
	for _, m := range ms {
		if m.Text == text {
			return m, true
		}
	}
	return detector.Match{}, false
}

// TestMixedCaseLabelledValuesAreReported is the recall gate: every labelled layout
// the gate admits reports the value with its ORIGINAL bytes as Text (that is what
// the redactor masks) and with exactly the confidence of the same value written in
// uppercase. On main every row here reports nothing.
func TestMixedCaseLabelledValuesAreReported(t *testing.T) {
	rows := []struct {
		name, content, value string
	}{
		{"form", "Passport Number: gk123456\n", "gk123456"},
		{"form Title case", "Passport Number: Gk123456\n", "Gk123456"},
		{"form US shape", "Passport Number: k12345678\n", "k12345678"},
		{"form EU shape", "Passport Number: de1234567\n", "de1234567"},
		{"form EU shape, non-ISO prefix", "Passport Number: ya1234567\n", "ya1234567"},
		{"snake-case key", "passport_number: gk123456\n", "gk123456"},
		{"prose with 'no is'", "my passport no is gk123456 thanks\n", "gk123456"},
		{"bare colon", "passport: ya1234567\n", "ya1234567"},
		{"abbreviated label in a sentence", "Passport No: k12345678 issued 2019.\n", "k12345678"},
		{"prose, label word then value", "She showed passport gk123456 at the gate.\n", "gk123456"},
		{"travel document label", "Travel document number: gk123456\n", "gk123456"},
		{"label on the line above", "Passport Number\ngk123456\n", "gk123456"},
		{"label on the line above, bulleted value", "Passport Number\n- gk123456\n", "gk123456"},
		{"CSV passport column", "name,passport_number,country\nJane Roe,gk123456,CA\n", "gk123456"},
		{"CSV passport column, Title case", "name,passport_number,country\nJohn Doe,Ya1234567,FI\n", "Ya1234567"},
		{"second value on a line with an uppercase one", "Passport Number: GK123456, old passport number: gk654321\n", "gk654321"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, ok := findText(scanPassport(t, r.content), r.value)
			if !ok {
				t.Fatalf("%q: %s not reported; a labelled passport number is PII in either case, "+
					"and an unreported value is never redacted", r.content, r.value)
			}
			upper := asciiUpper(r.value)
			twin, ok := findText(scanPassport(t, strings.Replace(r.content, r.value, upper, 1)), upper)
			if !ok {
				t.Fatalf("control: the uppercase twin %s of %q is not reported", upper, r.content)
			}
			if got.Confidence != twin.Confidence {
				t.Errorf("%q: %s scores %v, its uppercase twin %v: letter case moved the score",
					r.content, r.value, got.Confidence, twin.Confidence)
			}
			if got.Metadata["country"] != twin.Metadata["country"] {
				t.Errorf("%q: %s is bucket %v, its uppercase twin %v", r.content, r.value,
					got.Metadata["country"], twin.Metadata["country"])
			}
		})
	}
}

// TestMixedCaseUncoveredLayout pins the layout the gate deliberately does not
// cover, so a change to it is a visible decision: a label AFTER the value.
func TestMixedCaseUncoveredLayout(t *testing.T) {
	if got := scanPassport(t, "gk123456 (passport number)\n"); len(got) != 0 {
		t.Errorf("label after the value: got %d findings, want 0 (not covered by the "+
			"mixed-case gate, see the package README)", len(got))
	}
}

// TestMixedCaseDecoysStayUnreported is the precision gate. Every input here has
// the word "passport" near a lowercase token of a passport shape, which is exactly
// what the mixed-case pass would report without its gate and guard. Measured with
// neither: 19 findings in 10 of the 12 files in the first group at 72.5-100, and
// all 9 labelled placeholders at 85.
func TestMixedCaseDecoysStayUnreported(t *testing.T) {
	decoys := []string{
		// The word "passport" near a lowercase identifier.
		"image: registry.example.com/team/passport:v20241012",
		"2026-10-12T09:14:03Z INFO passport-svc req=ab4820715 user=gk123456 status=200\n" +
			"2026-10-12T09:14:04Z INFO passport-svc req=cd5931826 user=ya1234567 status=200\n" +
			"2026-10-12T09:14:05Z WARN passport-svc req=ef6042937 trace=k12345678 latency=812ms\n" +
			"2026-10-12T09:14:06Z INFO passport-svc session=mn7153048 user=qr482071 status=302",
		"passport.serializeUser((user, done) => done(null, user.id)); // e.g. usr482071\n" +
			"const token = passport.authenticate('jwt', { session: false }); // kid ab4820715",
		"The passport's strengths include visa-free access to many countries.",
		"passport photo booth saved img482071.jpg",
		"passport renewal ticket user48207 assigned to agent",
		"git log: fe4820715 update passport validator docs",
		"See /wiki/passport/ab482071 for the passport index.",
		"passport seat gk123456 is free",
		"passport release r20241012 and b20241012 tagged",
		"Passport applications require photographs, signature and documents.",
		"Both passports were renewed in spring.",
		// Labelled placeholders: each passes the label gate.
		"passport_number: redacted1",
		"Passport Number: password1",
		"passport: pending12",
		"passport no: unknown00",
		"Passport Number: document2",
		"Passport Number: missing01",
		"passport_number: tbd123456",
		"Passport Number: abc123456",
		"passport_number: sample001",
		// Placeholder words nobody listed, caught by the isLikelyWord arm.
		"Passport Number: invalid01",
		"Passport Number: deleted01",
		// A lowercase value in a column that is not the passport column.
		"name,passport_number,ref\nJane Roe,GK123456,ab1234567\n",
		// "passport" glued to a preceding word is not a label.
		"xpassport: gk123456",
		// A label line vouches for the value written under it, not for a token
		// inside the next field's line.
		"Passport Number: invalid01\nimage: registry.example.com/team/passport:v20241012",
		"Passport Number\nReference: gk123456",
		// Lowercase MRZ: ICAO 9303 defines the zone over A-Z, 0-9 and "<" only.
		"p<gbrsmith<<john<albert<<<<<<<<<<<<<<<<<<<<<\nl898902c36gbr7408122m1204159ze184226b<<<<<10",
	}
	for _, d := range decoys {
		got := scanPassport(t, d+"\n")
		for _, m := range got {
			if hasASCIILower(m.Text) {
				t.Errorf("%q: reported %q at %v; a lowercase token beside the word passport is "+
					"not a labelled passport number", d, m.Text, m.Confidence)
			}
		}
	}
}

// TestMixedCaseGateWindowIsExact pins the two edges of the label window: the label
// and its separators must fit in the 50 bytes before the value, and the word
// boundary before the label is a boundary of the line, not of the window.
func TestMixedCaseGateWindowIsExact(t *testing.T) {
	sep50 := strings.Repeat(" ", mixedCaseLabelGateWindow-len("passport")) // label fills the window exactly
	rows := []struct {
		name, line string
		want       int
	}{
		{"label fills the window, space before it", " passport" + sep50 + "gk123456", 1},
		{"label fills the window, glued to a word", "xpassport" + sep50 + "gk123456", 0},
		{"label one byte too far", " passport " + sep50 + "gk123456", 0},
	}
	for _, r := range rows {
		if got := len(scanPassport(t, r.line+"\n")); got != r.want {
			t.Errorf("%s: got %d findings, want %d", r.name, got, r.want)
		}
	}
}

// TestUppercasePlaceholdersAreUnchanged is the control for the placeholder guard:
// it applies to mixed-case candidates only, so every uppercase placeholder reported
// before #888 is reported exactly as before. Narrowing those is a separate change.
func TestUppercasePlaceholdersAreUnchanged(t *testing.T) {
	for _, r := range []struct {
		content, value string
		want           float64
	}{
		{"passport_number: REDACTED1\n", "REDACTED1", 85},
		{"Passport Number: PASSWORD1\n", "PASSWORD1", 85},
		{"Passport Number: INVALID01\n", "INVALID01", 100},
	} {
		got, ok := findText(scanPassport(t, r.content), r.value)
		if !ok || got.Confidence != r.want {
			t.Errorf("%q: got (%v, reported=%v), want %v as on main", r.content, got.Confidence, ok, r.want)
		}
	}
}
