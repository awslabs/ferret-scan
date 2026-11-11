// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// TestCommaFormIsNotTakenAcrossAList is the precision half of #936: comment lines of this package
// that list names or places, where main @ 2fb4719 reported "Surname, Given" across the comma between
// two items. Each wantGone value is what main reported, at the confidence given; each wantKept value
// is a name the list holds, which must now be reported on its own instead of being folded into the
// span (the redactor rewrites the span, so the fold left the head of the first name in cleartext).
func TestCommaFormIsNotTakenAcrossAList(t *testing.T) {
	cases := []struct {
		where    string
		line     string
		wantGone []string
		wantKept []string
	}{
		{"technical_terms.go:340 (100, 93)",
			"// person's name: Will Smith, May Chen, An Nguyen, He Zhang, Many (a surname).",
			[]string{"Smith, May Chen", "Nguyen, He Zhang"},
			[]string{"Will Smith", "May Chen", "An Nguyen", "He Zhang"}},
		{"technical_terms.go:379 (99 twice)",
			"// Real people score 100 in the same run — Robin Yang, David Ward, Marco Rossi, Will Smith, May Chen,",
			[]string{"Yang, David Ward", "Rossi, Will Smith"},
			[]string{"Robin Yang", "David Ward", "Marco Rossi", "Will Smith", "May Chen"}},
		{"technical_terms.go:357 (97 twice): single-word cities",
			"// Houston, Madison, Jackson, Phoenix and Charlotte — and the finding is reported. The leading word was",
			[]string{"Houston, Madison", "Jackson, Phoenix"}, nil},
		{"validator.go:856 (99)",
			"// people — Will Smith, May Chen, An Nguyen — so the data is authoritative and the",
			[]string{"Smith, May Chen"}, []string{"Will Smith", "May Chen"}},
		{"validator.go:878 (99)",
			`// words that belong to real people (Will Smith, May Chen, An Nguyen); "Santa", "Val", "Isla" and`,
			[]string{"Smith, May Chen"}, []string{"Will Smith", "May Chen"}},
		{"CHANGELOG.md:1877 (91), an excerpt: surnames joined by 'or'",
			"`La`, `Le`, `Fort`, `Lake` and `Villa` are surnames. `La Paz` is therefore **still reported**, deliberately: overriding the data to catch one capital city would delete every person named La, Le or Lake, and an unreported name is never handed to the redactor.",
			[]string{"La, Le"}, nil},
		{"font_name_test.go:12 (67): joined by 'and'",
			"// fire: Roman, Black and Vera are surnames.",
			[]string{"Roman, Black"}, nil},
	}
	for _, c := range cases {
		t.Run(c.where, func(t *testing.T) {
			got := map[string]float64{}
			for _, m := range scanText(t, c.line+"\n") {
				got[m.Text] = m.Conf
			}
			for _, gone := range c.wantGone {
				if conf, ok := got[gone]; ok {
					t.Errorf("%q reported at %.0f: the comma separates two list items", gone, conf)
				}
			}
			for _, kept := range c.wantKept {
				if _, ok := got[kept]; !ok {
					t.Errorf("%q not reported (got %v): a name the list holds must reach the redactor", kept, got)
				}
			}
		})
	}
}

// TestGenuineCommaFormsKeepTheirConfidence is the recall half: a "Surname, Given" written as one,
// alone, after a label, with a middle name that is also a surname, or followed by something that is
// not another name, keeps EXACTLY the confidence main @ 2fb4719 gives it.
func TestGenuineCommaFormsKeepTheirConfidence(t *testing.T) {
	cases := []struct {
		why  string
		line string
		name string
		conf float64
	}{
		{"alone (#936's control)", "Smith, John", "Smith, John", 100},
		{"after a label", "Patient: Torres, Michael", "Torres, Michael", 100},
		{"after a label word that is not a name", "Patient Torres, Michael", "Torres, Michael", 100},
		{"a middle name that is also a surname", "Torres, Michael James", "Torres, Michael James", 100},
		{"followed by a department", "Torres, Michael, Finance", "Torres, Michael", 97},
		{"followed by a suffix", "Torres, Michael, MD", "Torres, Michael", 97},
		{"followed by a lowercase word", "Torres, Michael and others", "Torres, Michael", 97},
		{"the documented example", "Torres, Michael   →  Dubois, Regan      (the same person, written the same way)",
			"Torres, Michael", 100},
		{"control (#935)", "Signed by Will Smith today.", "Will Smith", 92},
		{"control (#935)", "Signed by May Chen today.", "May Chen", 92},
		{"control (#935)", "Signed by Jean-Claude Van Damme today.", "Jean-Claude Van Damme", 93},
		{"control (#935)", "Signed by Dr. Sarah Johnson today.", "Dr. Sarah Johnson", 100},
	}
	for _, c := range cases {
		t.Run(c.why+"/"+c.name, func(t *testing.T) {
			var got []string
			for _, m := range scanText(t, c.line+"\n") {
				got = append(got, m.Text)
				if m.Text == c.name {
					if m.Conf != c.conf {
						t.Errorf("%q confidence %.0f, want %.0f (unchanged from main)", c.name, m.Conf, c.conf)
					}
					return
				}
			}
			t.Errorf("%q not reported (got %q); it is a real name and must reach the redactor",
				c.name, strings.Join(got, " | "))
		})
	}
}

// TestListWordBoundaries pins the two one-word reads: the word before the candidate is read only
// across spaces and only as a whole Title-Case word, and the continuation needs a comma, "and", "or"
// or "&" followed by a Title-Case name.
func TestListWordBoundaries(t *testing.T) {
	before := []struct {
		line, at, want string
	}{
		{"Will Smith, May", "Smith", "Will"},
		{"Will   Smith, May", "Smith", "Will"},
		{"will Smith, May", "Smith", ""}, // not Title-Case
		{"WILL Smith, May", "Smith", ""}, // not Title-Case
		{"Will-Smith, May", "Smith", ""}, // a hyphen, not a space
		{"Smith, May", "Smith", ""},      // nothing before
		{"(Smith, May", "Smith", ""},     // punctuation before
		{"Will,Smith, May", "Smith", ""}, // a comma, not a space
	}
	for _, c := range before {
		got := titleWordBefore(c.line, strings.Index(c.line, c.at))
		if got != c.want {
			t.Errorf("titleWordBefore(%q at %q) = %q, want %q", c.line, c.at, got, c.want)
		}
	}

	v := NewValidator()
	v.ensureNamesLoaded()
	cont := []struct {
		after string
		want  bool
	}{
		{", Jackson", true},
		{",  Jackson", true},
		{" and Charlotte", true},
		{" or Lake", true},
		{" & Vera", true},
		{",Jackson", false},      // no space after the comma
		{", Finance", false},     // not a name
		{", MD", false},          // not Title-Case
		{" and others", false},   // lowercase
		{" andrew Smith", false}, // "and" must be a whole word
		{"", false},              // end of line
		{",", false},             // a trailing comma alone
		{" Jackson", false},      // no separator
	}
	for _, c := range cont {
		line := "Houston, Madison" + c.after
		if got := v.continuesAsName(line, len("Houston, Madison")); got != c.want {
			t.Errorf("continuesAsName(%q) = %v, want %v", line, got, c.want)
		}
	}
}
