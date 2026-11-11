// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The relocation half of #915: before the copy is written every value the overwrite was asked to
// remove is looked for again, in every form the extractor reads, and a value still there refuses the
// file. These pin what "still there" means, and what it must not mean.

func TestStillPresentFindsEveryFormTheExtractorReads(t *testing.T) {
	const ssn = "449-87-4100"
	unit := func(text, typ string) legacyWriteUnit {
		return legacyWriteUnit{match: detector.Match{Text: text, Type: typ}, group: redactors.OverlapGroup{Members: []int{0}}}
	}
	cases := []struct {
		name    string
		logical [][]byte
		typed   []typedValue
		value   string
		want    bool
	}{
		{"8-bit in a stream", [][]byte{[]byte("body"), []byte("SSN " + ssn + " here")}, nil, ssn, true},
		{"UTF-16LE in a stream", [][]byte{toUTF16LE("SSN " + ssn)}, nil, ssn, true},
		{"a typed property's decoded text", nil, []typedValue{{rendering: "1928374650"}}, "1928374650", true},
		{"masked", [][]byte{[]byte("SSN ***-**-**** here")}, nil, ssn, false},
		{"absent", [][]byte{[]byte("nothing")}, []typedValue{{rendering: "0"}}, ssn, false},
		// A value that is only the mask byte is what a redacted copy holds; writing the mask over it
		// changes nothing, so it would always look present, and it discloses nothing.
		{"mask-only value", [][]byte{[]byte("Author: ********")}, nil, "********", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stillPresent([]legacyWriteUnit{unit(c.value, "SSN")}, nil, c.logical, c.typed)
			if (len(got) > 0) != c.want {
				t.Errorf("stillPresent = %v, want present=%v", got, c.want)
			}
		})
	}
}

func TestRefusalNamesTypesAndCountsButNoValue(t *testing.T) {
	err := refuseUnrewritten("/out/report.doc",
		[]unrewrittenValue{{types: []string{"CUSTOM_PROPERTY"}}},
		[]unrewrittenValue{{types: []string{"SSN"}}, {types: []string{"SSN", "PERSON_NAME"}}})
	if err == nil {
		t.Fatal("no refusal for a copy that would keep three reported values")
	}
	msg := err.Error()
	for _, want := range []string{"refusing to write report.doc", "1 reported value(s) (types CUSTOM_PROPERTY) were not found in any stream",
		"2 reported value(s) (types PERSON_NAME, SSN) were still present after the overwrite"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q lacks %q", msg, want)
		}
	}
	if refuseUnrewritten("/out/report.doc", nil, nil) != nil {
		t.Error("a copy that keeps nothing was refused")
	}
}

// The decoys: "not located" is not the test, and the relocation must not turn an ordinary redaction
// into a refusal. The same value reported on two lines is overwritten everywhere by the first unit, so
// the second locates nothing; a value inside a longer one reported on another line is gone once the
// longer one is written. Both pass on the parent commit and must still pass.
func TestRedaction_AValueAnEarlierWriteRemovedIsNotAMiss(t *testing.T) {
	src := writeFixture(t, docFixture(t), "decoys.doc")
	r := NewLegacyOLERedactor(nil, nil)
	for _, strategy := range r.GetSupportedStrategies() {
		t.Run(strategy.String(), func(t *testing.T) {
			matches := []detector.Match{
				{Text: testAuthor, Type: "PERSON_NAME", LineNumber: 3, Confidence: 90},
				{Text: testAuthor, Type: "PERSON_NAME", LineNumber: 9, Confidence: 90},
				{Text: "Jane", Type: "PERSON_NAME", LineNumber: 11, Confidence: 60},
				{Text: testSSN, Type: "SSN", LineNumber: 1, Confidence: 100},
			}
			out := filepath.Join(t.TempDir(), "redacted.doc")
			if _, err := r.RedactDocument(src, out, matches, strategy); err != nil {
				t.Fatalf("an ordinary redaction was refused: %v", err)
			}
		})
	}
}
