// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tagmeta

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// What a plan writes over each match is what its audit entry records (#865). Synthetic values: a
// reserved-domain address and an unassignable NANP number.
//
// The fixture is the issue's: one WAV comment holding an email, reported as the address (BUSINESS)
// and, by the metadata check, as the whole field (EMAIL). Plan merges the two into one span and writes
// one 28-byte mask; their entries used to say "j*******@example.com" and
// "c***************@example.com", neither of which is in the file, each beside format_preserving.
const (
	writtenEmail = "jane.doe@example.com"
	writtenField = "contact " + writtenEmail
	writtenPhone = "(555) 010-0199"
)

func writtenFixture() ([]byte, []Region, []detector.Match) {
	buf := []byte("ICMT\x00" + writtenField + "\x00IART\x00Phone " + writtenPhone + "\x00")
	return buf, []Region{{Start: 0, End: len(buf), Label: "INFO"}}, []detector.Match{
		{Text: writtenEmail, Type: "BUSINESS", LineNumber: 5},
		{Text: writtenField, Type: "EMAIL", LineNumber: 5},
		{Text: writtenPhone, Type: "PHONE", LineNumber: 6},
	}
}

// occursWhole reports whether text is in buf as a whole: as a mask, not inside a longer run of
// '*', because a 20-byte mask is also "in" a file that holds only a 28-byte one.
func occursWhole(buf []byte, text string) bool {
	pat := []byte(text)
	for off := 0; off+len(pat) <= len(buf); {
		i := bytes.Index(buf[off:], pat)
		if i < 0 {
			return false
		}
		at := off + i
		end := at + len(pat)
		if (at == 0 || buf[at-1] != MaskByte) && (end == len(buf) || buf[end] != MaskByte) {
			return true
		}
		off = at + 1
	}
	return false
}

func TestPlanWrittenRecordsTheMergedSpansMask(t *testing.T) {
	for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
		orig, regions, matches := writtenFixture()
		plan, perMatch, written := PlanWritten(orig, regions, matches, st)

		// PlanWritten plans exactly what Plan does.
		if p, n := Plan(orig, regions, matches, st); !reflect.DeepEqual(p, plan) || !reflect.DeepEqual(n, perMatch) {
			t.Fatalf("%s: PlanWritten planned %v/%v, Plan %v/%v", st, plan, perMatch, p, n)
		}
		out := append([]byte(nil), orig...)
		Apply(out, plan)

		mask := strings.Repeat("*", len(writtenField))
		for i := 0; i < 2; i++ {
			if written[i].Text != mask {
				t.Errorf("%s %s: written %q, want the merged span's %d-byte mask", st, matches[i].Type, written[i].Text, len(mask))
			}
			// The mask stands in for format_preserving's rendering, which keeps the domain; under
			// simple it is simple's own rendering.
			if want := st == redactors.RedactionFormatPreserving; written[i].Masked != want {
				t.Errorf("%s %s: Masked = %v, want %v", st, matches[i].Type, written[i].Masked, want)
			}
		}
		// The phone shares no bytes with them: its own rendering, as asked.
		if want := (Written{Text: SameLengthReplacement(writtenPhone, "PHONE", st)}); written[2] != want {
			t.Errorf("%s PHONE: written %+v, want %+v", st, written[2], want)
		}
		for i, w := range written {
			if !occursWhole(out, w.Text) {
				t.Errorf("%s %s: %q is not what the output holds (%q)", st, matches[i].Type, w.Text, out)
			}
		}
	}
}

// A value written in UTF-16 is recorded as its text, at the width written. A partial rendering that
// does not encode to the value's UTF-16 width is a mask standing in for it; a rendering that is all
// '*' (a name's) is not, at any width.
func TestPlanWrittenRecordsAWideOccurrenceAtItsWidth(t *testing.T) {
	cases := []struct {
		value, typ string
		masked     bool
	}{
		// "josé" is 5 bytes and 4 code units: its rendering "j****@example.com" fits the UTF-8 bytes
		// but not the UTF-16 ones, which are masked whole.
		{"josé@example.com", "EMAIL", true},
		{"José Ramírez", "PERSON_NAME", false},
	}
	for _, c := range cases {
		fp := replacement.FormatPreserving(c.value, c.typ)
		if len(UTF16LE(fp)) == len(UTF16LE(c.value)) || isMask(fp) == c.masked {
			t.Fatalf("fixture %q no longer exercises this case: its rendering is %q", c.value, fp)
		}
		wide := UTF16LE(c.value)
		buf := append(append([]byte("\xff\xfe"), wide...), 0, 0)
		matches := []detector.Match{{Text: c.value, Type: c.typ}}
		plan, perMatch, written := PlanWritten(buf, []Region{{Start: 0, End: len(buf)}}, matches, redactors.RedactionFormatPreserving)
		if perMatch[0] != 1 {
			t.Fatalf("%q: located %d times", c.value, perMatch[0])
		}
		out := append([]byte(nil), buf...)
		Apply(out, plan)
		want := Written{Text: strings.Repeat("*", len(wide)/2), Masked: c.masked}
		if written[0] != want {
			t.Errorf("%q: written %+v, want %+v", c.value, written[0], want)
		}
		if !bytes.Contains(out, UTF16LE(written[0].Text)) {
			t.Errorf("%q: the output does not hold %q in UTF-16", c.value, written[0].Text)
		}
	}
}

// The entry describes the match's FIRST occurrence: a value written alone at one offset and inside a
// merged span at a later one records its own rendering. A value the plan did not locate records
// nothing.
func TestPlanWrittenDescribesTheFirstOccurrence(t *testing.T) {
	const card = "4123456789012349"
	buf := []byte("A " + card + " B ref " + card + "-7 C")
	matches := []detector.Match{
		{Text: card, Type: "VISA"},
		{Text: card + "-7", Type: "ACCOUNT"},
		{Text: "not in the buffer", Type: "SSN"},
	}
	_, perMatch, written := PlanWritten(buf, []Region{{Start: 0, End: len(buf)}}, matches, redactors.RedactionFormatPreserving)
	if perMatch[0] != 2 {
		t.Fatalf("card located %d times, want 2", perMatch[0])
	}
	if want := (Written{Text: replacement.FormatPreserving(card, "VISA")}); written[0] != want {
		t.Errorf("card: written %+v, want its own rendering at its first occurrence, %+v", written[0], want)
	}
	if written[2] != (Written{}) {
		t.Errorf("an unlocated match recorded %+v", written[2])
	}
}

func TestWrittenAsMask(t *testing.T) {
	fp, simple, synthetic := redactors.RedactionFormatPreserving, redactors.RedactionSimple, redactors.RedactionSynthetic
	mask := func(n int) string { return strings.Repeat("*", n) }
	for _, c := range []struct {
		what, value, typ, text string
		strategy               redactors.RedactionStrategy
		want                   bool
	}{
		{"format_preserving's rendering", writtenEmail, "BUSINESS", "j*******@example.com", fp, false},
		{"a mask where it keeps the domain", writtenEmail, "BUSINESS", mask(20), fp, true},
		{"a wider merged mask", writtenEmail, "BUSINESS", mask(28), fp, true},
		{"a mask where it keeps nothing either", "AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY", mask(20), fp, false},
		{"simple's own mask", writtenEmail, "BUSINESS", mask(28), simple, false},
		{"a mask under synthetic", writtenEmail, "BUSINESS", mask(20), synthetic, true},
		{"no text", writtenEmail, "BUSINESS", "", fp, false},
	} {
		if got := WrittenAsMask(c.value, c.typ, c.text, c.strategy); got != c.want {
			t.Errorf("%s: WrittenAsMask(%q, %s) = %v, want %v", c.what, c.text, c.strategy, got, c.want)
		}
	}
}
