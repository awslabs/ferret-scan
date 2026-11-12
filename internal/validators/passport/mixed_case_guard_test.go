// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"regexp"
	"strings"
	"testing"
)

// Structural guards for the #888 mixed-case pass: the per-line cap, the ASCII-only
// value patterns, and the agreement and disjointness of patterns and anchors.

// TestUppercaseValueIsNotStarvedByLowercaseWords is why the mixed-case pass is a
// second pass. The per-line hit cap (maxMatchesPerLinePerPattern) bounds each
// regex's hits; every 9-character word is EU-shaped once lowercase is admitted, so
// a single widened pass would spend the cap on words and never reach an uppercase
// passport later on a long line, which main reports.
func TestUppercaseValueIsNotStarvedByLowercaseWords(t *testing.T) {
	line := strings.Repeat("signature ", maxMatchesPerLinePerPattern+100) + "Passport Number: DE1234567"

	// Precondition, so the assertion below means something: the widened EU shape
	// alone exhausts the cap before it reaches the value.
	hits := NewValidator().compiledMixedCase["EU"].FindAllStringIndex(line, maxMatchesPerLinePerPattern)
	if len(hits) != maxMatchesPerLinePerPattern || hits[len(hits)-1][0] >= strings.Index(line, "DE1234567") {
		t.Fatalf("fixture no longer exhausts the per-line cap before the value (%d hits)", len(hits))
	}

	if _, ok := findText(scanPassport(t, line+"\n"), "DE1234567"); !ok {
		t.Errorf("DE1234567 after %d lowercase EU-shaped words is not reported: lowercase "+
			"candidates used up the per-line cap the uppercase value needs", maxMatchesPerLinePerPattern+100)
	}
}

// TestValuePatternsAreASCIIOnly is the reason the mixed-case patterns spell
// [A-Za-z] instead of (?i). Go folds U+212A (Kelvin sign) and U+017F (long s) into
// (?i)[A-Z], so a (?i) pattern admits a value that is not ASCII, and every later
// check that slices the value by byte would cut a rune in half.
func TestValuePatternsAreASCIIOnly(t *testing.T) {
	traps := []string{"\u212aA123456", "\u017fA123456", "G\u212a123456", "DE12345\u212a6", "\u212a12345678"}

	// The trap is real: these are exactly the inputs a (?i) pattern accepts.
	if !regexp.MustCompile(`(?i)^[A-Z]{2}\d{6}$`).MatchString(traps[0]) ||
		!regexp.MustCompile(`(?i)\b[A-Z]{2}\d{6}\b`).MatchString(traps[2]) {
		t.Fatal("precondition: (?i)[A-Z] no longer folds U+212A, so this guard tests nothing")
	}

	v := NewValidator()
	type named struct {
		name string
		re   *regexp.Regexp
	}
	var all []named
	for name, re := range v.compiledPatterns {
		all = append(all, named{"pattern " + name, re})
	}
	for name, re := range v.compiledMixedCase {
		all = append(all, named{"mixed-case pattern " + name, re})
	}
	all = append(all,
		named{"anchor US", reUSPassport}, named{"anchor UK", reUKPassport},
		named{"anchor Canada", reCanadaPassport}, named{"anchor EU", reEUPassport},
		named{"anchor CanadaCurrent", reCanadaCurrentPassport}, named{"anchor Germany", reGermanPassport})
	for _, n := range all {
		if strings.Contains(n.re.String(), "(?i)") {
			t.Errorf("%s is %s: a value pattern must not use (?i)", n.name, n.re)
		}
		for _, s := range traps {
			for _, in := range []string{s, "Passport Number: " + s, asciiUpper(s)} {
				if hit := n.re.FindString(in); hit != "" {
					t.Errorf("%s matches %q in %q: a non-ASCII rune was accepted as a letter", n.name, hit, in)
				}
			}
		}
	}
	for _, s := range traps {
		if got := scanPassport(t, "Passport Number: "+s+"\n"); len(got) != 0 {
			t.Errorf("Passport Number: %q reported %q", s, got[0].Text)
		}
	}
}

// caseExemplars lists, for every pattern in patternOrder, values the pattern must
// match in full: uppercase ones, and the lowercase or Title-case ones its
// mixed-case pattern must match. A pattern with no exemplars fails the agreement
// guard, so a bucket cannot be added without saying what it matches.
var caseExemplars = map[string]struct{ upper, mixed []string }{
	"MRZ_TD3_L2": {upper: []string{"L898902C36GBR7408122M1204159ZE184226B<<<<<10"}},
	"MRZ_TD3":    {upper: []string{"P<GBRSMITH<<JOHN<ALBERT<<<<<<<<<<<<<<<<<<<<<"}},
	"MRZ":        {upper: []string{"P<GBRSMITH<<JOHN<ALBERT<<<<<<<<<<<<<<<<<<<<<<"}},
	"US":         {upper: []string{"C12345678"}, mixed: []string{"c12345678"}},
	"UK":         {upper: []string{"100000001"}},
	"Canada":     {upper: []string{"GK123456"}, mixed: []string{"gk123456", "Gk123456", "gK123456"}},
	"EU":         {upper: []string{"DE1234567", "CF12X4567"}, mixed: []string{"de1234567", "De1234567", "cf12x4567"}},
	// #888 Part 3. R123456KX is deliberately listed only under CanadaCurrent:
	// it is the documented DE / CA-current overlap (TestGermanCanadaOverlapRule).
	"CanadaCurrent": {upper: []string{"R123456KX", "A100001BC"}, mixed: []string{"r123456kx", "R123456kx"}},
	"Germany":       {upper: []string{"C1234567K", "C01X00T47", "L0R9T3CFG"}, mixed: []string{"c1234567k", "C1234567k"}},
}

// uppercaseOnlyBuckets are the patterns that deliberately have no mixed-case form.
var uppercaseOnlyBuckets = map[string]string{
	"MRZ_TD3_L2": "ICAO 9303 defines the zone over A-Z, 0-9 and '<'",
	"MRZ_TD3":    "ICAO 9303 defines the zone over A-Z, 0-9 and '<'",
	"MRZ":        "ICAO 9303 defines the zone over A-Z, 0-9 and '<'",
	"UK":         "the shape has no letters",
}

// TestCaseExemplarsAgreeWithTheirBucket is the agreement guard: the pattern that
// claims a value, the format anchor determineCountry checks it against, and the
// mixed-case form all agree on which bucket the value is in. A widened pattern
// whose anchor was left uppercase-only is exactly the #888 shape (patterns widened
// alone report 0 of 13: every widened candidate fails the anchor and is skipped).
func TestCaseExemplarsAgreeWithTheirBucket(t *testing.T) {
	v := NewValidator()
	for _, name := range v.patternOrder {
		ex, ok := caseExemplars[name]
		if !ok || len(ex.upper) == 0 {
			t.Errorf("%s: no uppercase exemplars; every bucket must say what it matches", name)
			continue
		}
		for _, s := range ex.upper {
			if got := v.compiledPatterns[name].FindString(s); got != s {
				t.Errorf("%s does not match its exemplar %q in full (got %q)", name, s, got)
			}
			if got := v.determineCountry(s); got != name {
				t.Errorf("determineCountry(%q) = %q, want %q", s, got, name)
			}
		}
		mixed := v.compiledMixedCase[name]
		if why, upperOnly := uppercaseOnlyBuckets[name]; upperOnly {
			if mixed != nil {
				t.Errorf("%s has a mixed-case pattern, but it is uppercase-only: %s", name, why)
			}
			for _, s := range ex.upper {
				if l := strings.ToLower(s); l != s && v.compiledPatterns[name].MatchString(l) {
					t.Errorf("%s matches lowercase %q: %s", name, l, why)
				}
			}
			continue
		}
		if mixed == nil || len(ex.mixed) == 0 {
			t.Errorf("%s has letters but no mixed-case pattern or no mixed-case exemplars: a "+
				"lowercase value of this shape would never be a candidate", name)
			continue
		}
		for _, s := range ex.mixed {
			if got := mixed.FindString(s); got != s {
				t.Errorf("mixed-case %s does not match %q in full (got %q)", name, s, got)
			}
			canon := asciiUpper(s)
			if len(canon) != len(s) {
				t.Errorf("asciiUpper(%q) changed the length", s)
			}
			if got := v.determineCountry(canon); got != name {
				t.Errorf("determineCountry(asciiUpper(%q)) = %q, want %q: the anchor and the "+
					"pattern disagree, so the candidate would be skipped", s, got, name)
			}
			if !v.compiledPatterns[name].MatchString(canon) {
				t.Errorf("%s does not match asciiUpper(%q) = %q", name, s, canon)
			}
		}
	}
}

// TestNationalAnchorsAreDisjoint is the disjointness guard: no national exemplar
// passes another bucket's anchor. keepOutermostSpans copies the higher confidence
// onto an identical surviving span, so two buckets that both claimed one value
// would make its score depend on which pattern claimed it first. The one
// exception is the documented DE / CA-current overlap.
func TestNationalAnchorsAreDisjoint(t *testing.T) {
	anchors := map[string]func(string) bool{
		"US": reUSPassport.MatchString, "UK": reUKPassport.MatchString,
		"Canada": reCanadaPassport.MatchString, "EU": reEUPassport.MatchString,
		"CanadaCurrent": reCanadaCurrentPassport.MatchString, "Germany": isGermanPassport,
	}
	for owner := range anchors {
		ex := caseExemplars[owner]
		values := append([]string{}, ex.upper...)
		for _, s := range ex.mixed {
			values = append(values, asciiUpper(s))
		}
		for _, s := range values {
			for other, match := range anchors {
				if other == owner || !match(s) {
					continue
				}
				// The one documented overlap (TestGermanCanadaOverlapRule): allowed
				// only while determineCountry resolves it to its documented owner.
				if owner == "CanadaCurrent" && other == "Germany" &&
					NewValidator().determineCountry(s) == "CanadaCurrent" {
					continue
				}
				t.Errorf("%q (a %s exemplar) also passes the %s anchor", s, owner, other)
			}
		}
	}
}
