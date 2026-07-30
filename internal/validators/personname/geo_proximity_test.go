// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// TestAddressOnSameLineKeepsTheName is the leak gate.
//
// The business (-20), product (-8) and geographic (-35) penalties used to apply to
// the whole LINE regardless of where the pattern sat relative to the name. Summed
// and clamped to -50, that took a solid two-token name from 92 to 42, below the
// >= 50 emit threshold — so an ordinary mailing record or CSV row lost the person's
// name entirely. A name absent from the report is never handed to the redactor
// either, so the cleartext value survives into the output: on a two-row CSV of
// names and addresses the CLI reported nothing and wrote NO redacted file at all.
//
// Every line here carries a real person name AND an address and/or company on the
// same line, which is the normal shape of the data this tool exists to find.
func TestAddressOnSameLineKeepsTheName(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"csv export row", "Sarah Brooks,Acme Inc,1425 Oak Drive,Springfield,IL", "Sarah Brooks"},
		{"clinical note", "Patient Sarah Brooks, 42 River Road, admitted Monday", "Sarah Brooks"},
		{"prose with company", "Contact Sarah Brooks at 1425 Elm Avenue for the Acme Inc account", "Sarah Brooks"},
		{"pipe-delimited", "Sarah Brooks | Acme Corp | 1425 Elm Street", "Sarah Brooks"},
		{"second csv row", "Michael Rivera,Globex LLC,88 Lake Street,Portland,OR", "Michael Rivera"},
		{"shipping label", "Ship to Jennifer Alvarez, 210 Mountain Road, Boulder CO", "Jennifer Alvarez"},
		{"employee record", "Employee: Daniel Fischer, 9 Valley Drive, ext 4417", "Daniel Fischer"},
		{"prose address", "Karen Whitfield lives at 77 Creek Boulevard in the city", "Karen Whitfield"},
		{"invoice line", "invoice for Thomas Bennett, 5 County Road, Acme Industries", "Thomas Bennett"},
		{"suite address", "Deborah Callahan, 1200 State Street, Suite 300", "Deborah Callahan"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(tc.line, "record.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("no findings: the name %q is on this line together with an "+
					"address/company, and a line-global context penalty dropped it. An "+
					"unreported name is not redacted either, so it stays cleartext in the "+
					"output.\n  line: %q", tc.want, tc.line)
			}
			var found bool
			var got []string
			for _, m := range matches {
				got = append(got, m.Text)
				if strings.Contains(m.Text, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("findings %v do not include %q\n  line: %q", got, tc.want, tc.line)
			}
		})
	}
}

// TestPlaceNamesStaySuppressed is the other direction: proximity-gating the
// penalties must not turn place names, org names and address fragments into
// people.
//
// The five lines NOT listed here that this corpus originally contained
// ("Phoenix Arizona to Denver Colorado route", "Palo Alto and Menlo Park offices",
// "Grand Canyon National Park Arizona", "Charlotte North Carolina and Austin
// Texas", "Devon Cornwall and Kent counties") are reported as names BOTH before and
// after the proximity gate — they are a separate, pre-existing issue: those place
// words are themselves entries in the first-name database, so they score on their
// own merits and the geographic penalty only masked them incidentally. They are
// deliberately excluded so this test asserts what the change is responsible for.
func TestPlaceNamesStaySuppressed(t *testing.T) {
	cases := []string{
		"123 Main Street, Springfield, IL 62704",
		"River Valley Industries Inc, 400 Commerce Drive",
		"Golden Gate Boulevard runs through the city",
		"Mountain View California is the county seat",
		"Salt Lake City, Utah",
		"Cedar Creek Road crosses Pine Valley Avenue",
		"Acme Manufacturing Corp, Industrial Drive",
		"terraform apply -target module.database",
		"aws ec2 describe-instances --region us-east-1",
		"See the installation guide in the readme documentation",
		"Samsung Galaxy and Nike Air product catalog",
		"Boulder County Colorado state records",
		"Elm Street Elementary School District",
		"the Hudson River valley region",
		"Jordan Lake State Recreation Area",
		"Madison Avenue advertising firm",
	}

	for _, line := range cases {
		v := NewValidator()
		matches, err := v.ValidateContent(line, "doc.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		if len(matches) > 0 {
			var got []string
			for _, m := range matches {
				got = append(got, m.Text)
			}
			t.Errorf("reported %v as person name(s) on a line that names no person — "+
				"the proximity gate must not let place/org/address text score as people.\n  line: %q",
				got, line)
		}
	}
}

// TestSpecificPatternPenaltyIsProximityGated pins the mechanism directly, so a
// future change that reverts to line-global scoring fails here with a reason even
// if the corpus above happens to still pass.
//
// Same words, same name, only the DISTANCE between them varies.
func TestSpecificPatternPenaltyIsProximityGated(t *testing.T) {
	v := NewValidator()

	// "drive" adjacent to the name: still penalized.
	near := "Oak Drive Sarah Brooks"
	// "drive" far from the name, past specificPatternProximity: not penalized.
	far := "Sarah Brooks" + strings.Repeat(" x", specificPatternProximity) + " Oak Drive"

	nearCache := v.newLineContextCache(strings.ToLower(near))
	farCache := v.newLineContextCache(strings.ToLower(far))

	if len(nearCache.geoIndices) == 0 || len(farCache.geoIndices) == 0 {
		t.Fatalf("premise broken: both lines must contain a geographic pattern "+
			"(near=%v far=%v)", nearCache.geoIndices, farCache.geoIndices)
	}

	nearScore := v.analyzeContextCached("Sarah Brooks", strings.Index(strings.ToLower(near), "sarah"), nearCache)
	farScore := v.analyzeContextCached("Sarah Brooks", strings.Index(strings.ToLower(far), "sarah"), farCache)

	if !(farScore > nearScore) {
		t.Errorf("far=%.1f near=%.1f: a geographic word %d+ bytes from the name must "+
			"penalize it LESS than one adjacent to it. Equal scores mean the penalty is "+
			"being applied line-globally again.", farScore, nearScore, specificPatternProximity)
	}
}

// TestDistantPatternCannotMaskAnAdjacentOne guards against penalty evasion.
//
// specificPatternIndices originally recorded only the FIRST matching pattern per
// family (a `break` after the first hit). That was harmless while the penalty was
// line-global, but under proximity gating the recorded offsets decide whether a
// name is penalized — so one distant match could hide an adjacent one:
//
//	"oak drive sarah brooks"                        geo=[4]  -> penalty FIRES
//	"avenue" + 60 dots + " oak drive sarah brooks"  geo=[0]  -> penalty SILENT
//
// Identical adjacent "oak drive", but prepending the alphabetically-earlier
// "avenue" far away suppressed the penalty entirely (-50 became -15; through the
// CLI the finding rose from 57 to 69). Attacker-controllable, and the same class
// of hazard as the map-order issue: what changed was never the score for a given
// pattern, only WHICH offset got recorded.
func TestDistantPatternCannotMaskAnAdjacentOne(t *testing.T) {
	v := NewValidator()
	v.ensureNamesLoaded()

	const control = "oak drive sarah brooks"
	// "avenue" sorts before "oak drive"'s "drive", and sits far from the name.
	padded := "avenue" + strings.Repeat(".", 60) + " oak drive sarah brooks"

	score := func(line string) float64 {
		cache := v.newLineContextCache(strings.ToLower(line))
		nameIndex := strings.Index(cache.lowerLine, "sarah")
		if nameIndex < 0 {
			t.Fatalf("premise broken: name not found in %q", line)
		}
		if len(cache.geoIndices) == 0 {
			t.Fatalf("premise broken: no geographic pattern located in %q", line)
		}
		return v.analyzeContextCached("sarah brooks", nameIndex, cache)
	}

	controlScore := score(control)
	paddedScore := score(padded)

	if paddedScore != controlScore {
		t.Errorf("padding the line with a distant, alphabetically-earlier geographic "+
			"pattern changed the score for an IDENTICAL adjacent one: control=%.1f "+
			"padded=%.1f. Every offset per family must be collected, or a far match "+
			"masks a near one and the penalty can be evaded.", controlScore, paddedScore)
	}
}

// TestGeoPatternIterationIsDeterministic guards the map-order fix.
//
// The geographic scan used to range geoPatternsMap directly and break on the first
// hit. The SCORE was the same whichever pattern won, which is why this was
// invisible — but the recorded byte OFFSET was not order-independent, and the
// offset now decides whether a name is penalized. Iterating a sorted slice makes
// the winner deterministic.
func TestGeoPatternIterationIsDeterministic(t *testing.T) {
	// A line holding several geographic patterns, so map order would have a choice.
	const line = "sarah brooks, 1 oak drive, elm street, river road, lake city"
	v := NewValidator()

	first := v.newLineContextCache(line).geoIndices
	if len(first) == 0 {
		t.Fatal("premise broken: line must contain a geographic pattern")
	}
	for i := 0; i < 50; i++ {
		got := v.newLineContextCache(line).geoIndices
		if len(got) != len(first) || (len(got) > 0 && got[0] != first[0]) {
			t.Fatalf("run %d produced geoIndices %v, first run produced %v — the "+
				"geographic scan is order-dependent", i, got, first)
		}
	}

	// And the sorted accessor itself must be sorted, which is what makes it stable.
	patterns := v.getSortedGeoPatterns()
	if len(patterns) == 0 {
		t.Fatal("getSortedGeoPatterns returned nothing")
	}
	for i := 1; i < len(patterns); i++ {
		if patterns[i-1] > patterns[i] {
			t.Errorf("getSortedGeoPatterns not sorted at %d: %q > %q",
				i, patterns[i-1], patterns[i])
		}
	}
}

// TestFirstWordKeywordIndexMatchesContainsWordKeyword locks the invariant the
// proximity gate depends on: the index helper and the boolean helper must agree
// about whether a pattern is present. If they diverge, a pattern could be "found"
// at an offset the boolean check rejects (or vice versa), and the penalty would
// fire on substring hits like "state" inside "estate".
func TestFirstWordKeywordIndexMatchesContainsWordKeyword(t *testing.T) {
	v := NewValidator()
	lines := []string{
		"sarah brooks, 1425 oak drive, springfield",
		"the real estate listing was driven by demand", // substring traps
		"acme inc and globex llc",
		"nothing relevant here at all",
		"lakefront property near riverside", // more substring traps
		"street",                            // whole line is the pattern
		"city,county,state",                 // punctuation boundaries
	}
	families := [][]string{
		v.getSortedBusinessPatterns(),
		v.getSortedProductPatterns(),
		v.getSortedGeoPatterns(),
	}

	for _, line := range lines {
		for _, family := range families {
			for _, pattern := range family {
				contains := containsWordKeyword(line, pattern)
				idx := firstWordKeywordIndex(line, pattern)
				if contains != (idx >= 0) {
					t.Errorf("disagreement on pattern %q in %q: containsWordKeyword=%v "+
						"firstWordKeywordIndex=%d", pattern, line, contains, idx)
				}
				if idx >= 0 && !strings.HasPrefix(line[idx:], pattern) {
					t.Errorf("firstWordKeywordIndex(%q, %q)=%d does not point at the pattern",
						line, pattern, idx)
				}
			}
		}
	}
}
