// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #968: one name on two lines, reported on one, held on neither.
//
// The shapes are the two measured in the public corpus: a CSV whose name column runs into more letters
// on a line the validator did not report, and an HTML page whose member id is followed by `_` and a
// suffix. Before, the completeness sweep left an occurrence alone whenever a letter, digit or `_`
// abutted it, so 33 reported values (174 occurrences) stayed in two copies at exit 0. The interior line
// is the golden corpus's rule, kept: a value with word bytes on BOTH sides is part of a different token.
func TestAReportedValueIsMaskedOnALineWhereItWasNotReported(t *testing.T) {
	for _, tc := range []struct {
		name, value, typ, reported, unreported string
	}{
		{"name running into more letters", "Jane Q Public", "PERSON_NAME",
			"author,Jane Q Public,2004", "notes,see Jane Q Publicson memo,2005"},
		{"member id followed by _", "ABC123456789012345", "INSURANCE_MEMBER_ID",
			"<td>member ABC123456789012345</td>", `<a href="#ABC123456789012345_2">x</a>`},
	} {
		for _, strategy := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
			t.Run(tc.name+"/"+strategy.String(), func(t *testing.T) {
				const interior = "cache 0xAAABC123456789012345FF evicted"
				content := tc.reported + "\n" + tc.unreported + "\n" + interior + "\n"
				matches := []detector.Match{{Text: tc.value, Type: tc.typ, LineNumber: 1, Confidence: 90,
					Context: detector.ContextInfo{FullLine: tc.reported}}}
				pr := NewPlainTextRedactor(nil, nil)
				out, _, err := pr.RedactString(content, matches, strategy)
				if err != nil {
					t.Fatalf("RedactString: %v", err)
				}
				if n := strings.Count(out, tc.value); n > 0 {
					lines := strings.Split(out, "\n")
					if strings.Contains(lines[0], tc.value) || strings.Contains(lines[1], tc.value) {
						t.Errorf("the reported value survives %d time(s) in the copy:\n%s", n, out)
					}
				}
				if !strings.Contains(out, interior) {
					t.Errorf("a value inside a longer token was rewritten:\n%s", out)
				}
			})
		}
	}
}
