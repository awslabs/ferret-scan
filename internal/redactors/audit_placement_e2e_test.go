// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The text-family redactor's placement names how it located each value (#865): the correlator step
// (exact, fuzzy, heuristic) and whether the placed position had to be found again by searching. The
// issue's dup.txt (one card twice on one line) logged position_correlation 0.8 and 0.56, so fuzzy
// and corrected were implied by the score and never said. Decoded loosely so the test compiles, and
// fails, on a tree without the fields.
func TestTheTextRedactorNamesHowItPlacedEachValue(t *testing.T) {
	cases := auditCases()
	byFile := map[string]auditCase{}
	for _, name := range []string{"plaintext_redactor", "svg_redactor"} {
		for _, c := range cases[name] {
			byFile[c.file] = c
		}
	}
	want := map[string][]string{
		// method/correlation/corrected per entry, sorted.
		"sample.txt": {
			"position_correlation/exact/false", "position_correlation/exact/false", "position_correlation/exact/false",
			"position_correlation/exact/false", "position_correlation/exact/false",
		},
		"dup.txt": {"position_correlation/fuzzy/false", "position_correlation/fuzzy/true"},
		// The SVG's address is on an extracted line the correlator cannot place: text search, which
		// names no correlator step.
		"draw.svg": {"position_correlation/exact/false", "simple_text_search//false"},
	}
	for file, w := range want {
		c := byFile[file]
		name := "plaintext_redactor"
		if strings.HasSuffix(file, ".svg") {
			name = "svg_redactor"
		}
		for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving, redactors.RedactionSynthetic} {
			run, ok := runOracleCase(t, name, c, st)
			if !ok {
				t.Fatalf("%s: refused", run.what)
			}
			var env struct {
				AuditLogs map[string]struct {
					ContentRedactions []struct {
						Placement map[string]any `json:"placement"`
					} `json:"content_redactions"`
				} `json:"audit_logs"`
			}
			if err := json.Unmarshal(run.raw, &env); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, d := range env.AuditLogs {
				for _, e := range d.ContentRedactions {
					p := e.Placement
					corr, _ := p["correlation"].(string)
					corrected, _ := p["corrected"].(bool)
					got = append(got, fmt.Sprintf("%v/%s/%v", p["method"], corr, corrected))
				}
			}
			sort.Strings(got)
			if strings.Join(got, " ") != strings.Join(w, " ") {
				t.Errorf("%s placements = %v, want %v", run.what, got, w)
			}
		}
	}
}
