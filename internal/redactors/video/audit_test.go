// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package video

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The video redactor's mappings, which the audit log records (#865), are what was written over each
// value: two values sharing bytes in one tag are merged into one span and written as one mask, and
// both mappings say that mask, beside the finding's line. They used to say each value's own
// rendering, which the file does not hold, and no line.
func TestTheMappingsAreWhatTheTagsHold(t *testing.T) {
	const field = "contact " + strategyEmail
	src := mp4With(t, t.TempDir(), "merged.mp4", atom("meta", []byte{0, 0, 0, 0}, atom("ilst",
		itunesTag("\xa9cmt", field),
		itunesTag("\xa9ART", "Phone "+strategyPhone))))
	matches := []detector.Match{
		{Text: strategyEmail, Type: "BUSINESS", Confidence: 53, LineNumber: 4},
		{Text: field, Type: "EMAIL", Confidence: 50, LineNumber: 4},
		{Text: strategyPhone, Type: "PHONE", Confidence: 90, LineNumber: 7},
	}
	line := map[string]int{"BUSINESS": 4, "EMAIL": 4, "PHONE": 7}
	mask := strings.Repeat("*", len(field))
	for _, c := range []struct {
		strategy redactors.RedactionStrategy
		want     map[string]redactors.RedactionMapping
	}{
		{redactors.RedactionSimple, map[string]redactors.RedactionMapping{
			"BUSINESS": {RedactedText: mask}, "EMAIL": {RedactedText: mask},
			"PHONE": {RedactedText: strings.Repeat("*", len(strategyPhone))}}},
		{redactors.RedactionFormatPreserving, map[string]redactors.RedactionMapping{
			"BUSINESS": {RedactedText: mask, Masked: true}, "EMAIL": {RedactedText: mask, Masked: true},
			"PHONE": {RedactedText: "(***) ***-0199"}}},
	} {
		after, res, _, err := redactUnder(t, src, matches, c.strategy)
		if err != nil {
			t.Fatalf("%s: %v", c.strategy, err)
		}
		if len(res.RedactionMap) != len(c.want) {
			t.Fatalf("%s: %d mappings, want %d", c.strategy, len(res.RedactionMap), len(c.want))
		}
		for _, m := range res.RedactionMap {
			w := c.want[m.DataType]
			if m.RedactedText != w.RedactedText || m.Masked != w.Masked || m.Position.Line != line[m.DataType] || m.Strategy != c.strategy {
				t.Errorf("%s %s: mapping text %q masked %v line %d strategy %s; want %q %v %d %s", c.strategy, m.DataType,
					m.RedactedText, m.Masked, m.Position.Line, m.Strategy, w.RedactedText, w.Masked, line[m.DataType], c.strategy)
			}
			if !holdsWhole(after, m.RedactedText) {
				t.Errorf("%s %s: %q is not what the file holds", c.strategy, m.DataType, m.RedactedText)
			}
		}
	}
}

// A value in two homes (moov/udta and an XMP packet after it) is written once per home, here as the
// merged mask in udta and as its own rendering in the packet; its mapping describes the first, as a
// file read from the start meets it.
func TestAValueInTwoHomesRecordsItsFirst(t *testing.T) {
	const field = "contact " + strategyEmail
	src := mp4WithXMP(t, t.TempDir(), "two-homes.mp4", strategyEmail, itunesTag("\xa9cmt", field))
	matches := []detector.Match{
		{Text: strategyEmail, Type: "BUSINESS", Confidence: 53, LineNumber: 4},
		{Text: field, Type: "EMAIL", Confidence: 50, LineNumber: 4},
	}
	after, res, _, err := redactUnder(t, src, matches, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(after, []byte("<dc:title>j*******@example.com</dc:title>")) {
		t.Fatal("the packet copy is not written with its own rendering; the fixture no longer has two renderings")
	}
	for _, m := range res.RedactionMap {
		if m.DataType != "BUSINESS" {
			continue
		}
		if m.RedactedText != strings.Repeat("*", len(field)) || !m.Masked || m.Metadata["occurrences"] != 2 {
			t.Errorf("BUSINESS: mapping text %q masked %v occurrences %v; want udta's merged mask, masked, 2",
				m.RedactedText, m.Masked, m.Metadata["occurrences"])
		}
		return
	}
	t.Fatal("no BUSINESS mapping")
}

// holdsWhole reports whether text occurs in buf other than inside a longer mask.
func holdsWhole(buf []byte, text string) bool {
	pat := []byte(text)
	for off := 0; off+len(pat) <= len(buf); {
		i := bytes.Index(buf[off:], pat)
		if i < 0 {
			return false
		}
		at, end := off+i, off+i+len(pat)
		if (at == 0 || buf[at-1] != '*') && (end == len(buf) || buf[end] != '*') {
			return true
		}
		off = at + 1
	}
	return false
}
