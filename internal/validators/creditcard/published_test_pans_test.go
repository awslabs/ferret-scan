// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// Tests that need published_test_pans.go itself (#883). The behaviour tests that also compile
// against main are in published_test_pans_behavior_test.go.

// TestPublishedTestPANsAreWellFormed enforces the admission rule's mechanical half: every block
// cites an https:// page and an ISO date, and every value is digits only, of a length the
// validator reports, Luhn-valid, and in sorted order with no duplicate inside its block.
func TestPublishedTestPANsAreWellFormed(t *testing.T) {
	v := NewValidator()
	if len(publishedTestPANBlocks) == 0 {
		t.Fatal("no published test PAN blocks")
	}
	vendors := map[string]bool{}
	entries := 0
	for _, b := range publishedTestPANBlocks {
		if b.vendor == "" || vendors[b.vendor] {
			t.Errorf("block vendor %q is empty or repeated", b.vendor)
		}
		vendors[b.vendor] = true
		if !strings.HasPrefix(b.url, "https://") || strings.ContainsAny(b.url, " \t\n") {
			t.Errorf("%s: url %q is not an https:// URL", b.vendor, b.url)
		}
		if _, err := time.Parse("2006-01-02", b.retrieved); err != nil {
			t.Errorf("%s: retrieved %q is not an ISO date: %v", b.vendor, b.retrieved, err)
		}
		if len(b.pans) == 0 {
			t.Errorf("%s: no values", b.vendor)
		}
		for i, p := range b.pans {
			if !isBareDigitRun(p) || !v.isValidLength(p) || !v.luhnCheck(p) {
				t.Errorf("%s: %q is not a Luhn-valid 13/14/15/16/19-digit number", b.vendor, p)
			}
			if i > 0 && b.pans[i-1] >= p {
				t.Errorf("%s: %q follows %q: values must be sorted with no duplicate", b.vendor, p, b.pans[i-1])
			}
		}
		entries += len(b.pans)
	}
	if n := len(publishedTestPANSet); n == 0 || n > entries {
		t.Errorf("publishedTestPANSet holds %d values from %d block entries", n, entries)
	}
}

// listedCorpusValues are the listed values the golden and score corpora may carry, each with
// why it is not a genuine-card positive there. Any other listed value in a corpus fails: if a
// vendor starts publishing a value a corpus uses as a real card, replace the fixture rather
// than exempting the value, or the corpus stops testing what it claims.
var listedCorpusValues = map[string]string{
	"4012888888881881": "goldencorpus context_keywords_snake_case, on an `account_number_test:` " +
		"line whose negative word floors the card at 15 on main as well",
}

// corpusDigitRun finds digit runs whose groups may be separated by one space or hyphen, and
// corpusBareRun each bare run inside one.
var (
	corpusDigitRun = regexp.MustCompile(`\d(?:[ -]?\d)*`)
	corpusBareRun  = regexp.MustCompile(`\d+`)
)

// listedValues returns every listed value once, in block order, so a test's inputs and its
// failure output are the same on every run.
func listedValues() []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range publishedTestPANBlocks {
		for _, p := range b.pans {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// TestNoCorpusCardFixtureIsListed reads the golden and score corpora's sources and fails on a
// listed value that listedCorpusValues does not account for, and on an account that is stale.
func TestNoCorpusCardFixtureIsListed(t *testing.T) {
	v := NewValidator()
	found := map[string][]string{}
	scanned := 0
	for _, dir := range []string{"goldencorpus", "scorecorpus"} {
		files, err := filepath.Glob(filepath.Join("..", "..", dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			scanned++
			text := string(data)
			// A grouped run, and each bare run inside it, so a value written next to other
			// digits with a single space between is not missed.
			for _, run := range append(corpusDigitRun.FindAllString(text, -1), corpusBareRun.FindAllString(text, -1)...) {
				clean := v.cleanCreditCardNumber(run)
				if _, listed := publishedTestPANSet[clean]; listed {
					found[clean] = append(found[clean], dir+"/"+filepath.Base(f))
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("read no corpus source: the corpora moved, and this test would pass vacuously")
	}
	for value, where := range found {
		if _, ok := listedCorpusValues[value]; !ok {
			t.Errorf("%s is a published test number and appears in %v. A corpus positive must be a "+
				"real-shaped card: replace the fixture, or account for it in listedCorpusValues", value, where)
		}
	}
	for value := range listedCorpusValues {
		if _, ok := found[value]; !ok {
			t.Errorf("listedCorpusValues accounts for %s, which no corpus carries any more", value)
		}
	}
}

// withoutList returns a validator that does not consult the published list: the same scan as
// the shipped validator in every other respect.
func withoutList() *Validator {
	v := NewValidator()
	v.publishedTestPANs = nil
	return v
}

// listedForms is every line shape the issue measured, for one value.
func listedForms(p string) []string {
	return []string{
		p,
		"Card number: " + p,
		`{"number": "` + p + `", "exp_month": 12, "exp_year": 2030, "cvc": "123"}`,
		"name,card_number,exp\nJordan Q," + p + ",12/30\n",
		`card_number = "` + p + `"`,
		groupDigits(p, " "),
		groupDigits(p, "-"),
		"| Number | CVC |\n|---|---|\n| " + groupDigits(p, " ") + " | Any 3 digits |\n",
		"Test card: " + p,
	}
}

// expectCapped is what the cap may change on a listed value's match: its confidence to
// min(before, 15), not_test to false and the ceiling to 15. Nothing else.
func expectCapped(before detector.Match) detector.Match {
	want := before
	if want.Confidence > testValueCeiling {
		want.Confidence = testValueCeiling
	}
	want.Metadata = make(map[string]any, len(before.Metadata)+1)
	for k, val := range before.Metadata {
		want.Metadata[k] = val
	}
	checks := map[string]bool{}
	for k, val := range before.Metadata["validation_checks"].(map[string]bool) {
		checks[k] = val
	}
	checks["not_test"] = false
	want.Metadata["validation_checks"] = checks
	want.Metadata[confidenceCeilingKey] = testValueCeiling
	return want
}

// pairedWithListedCard reports whether m is a security code paired with a card whose value is
// on the published list, among the findings of the same scan.
func pairedWithListedCard(v *Validator, m detector.Match, all []detector.Match) bool {
	if m.Metadata[cardFrameKey] != frameSecurityCode || m.Metadata["paired"] != true {
		return false
	}
	for _, c := range all {
		if c.LineNumber != m.Metadata["paired_card_line"] {
			continue
		}
		if _, listed := publishedTestPANSet[v.cleanCreditCardNumber(c.Text)]; listed {
			return true
		}
	}
	return false
}

// expectCappedCode is what the cap may change on a security code paired with a listed value:
// its confidence to min(before, 15) and its ceiling to the card's 15. Nothing else.
func expectCappedCode(before detector.Match) detector.Match {
	want := before
	if want.Confidence > testValueCeiling {
		want.Confidence = testValueCeiling
	}
	want.Metadata = make(map[string]any, len(before.Metadata)+1)
	for k, val := range before.Metadata {
		want.Metadata[k] = val
	}
	want.Metadata[confidenceCeilingKey] = testValueCeiling
	return want
}

// TestPublishedTestPANCapIsMinOfTheUncappedScore toggles the list over every listed value in
// every measured shape: the finding set, Text, LineNumber, Type and Context are identical, and
// a listed value's confidence is exactly min(before, 15). A displayed form whose digits are not
// the listed value (the 4-4-4-4-3 grouping of a 19-digit value matches its first 16 digits
// only) is not listed, and must not move at all.
func TestPublishedTestPANCapIsMinOfTheUncappedScore(t *testing.T) {
	on, off := NewValidator(), withoutList()
	moved := 0
	for _, p := range listedValues() {
		for _, content := range listedForms(p) {
			after, _ := on.ValidateContent(content, "probe.txt")
			before, _ := off.ValidateContent(content, "probe.txt")
			if len(after) != len(before) {
				t.Fatalf("%q: %d matches with the list, %d without", content, len(after), len(before))
			}
			for i := range after {
				want := before[i]
				if _, listed := publishedTestPANSet[on.cleanCreditCardNumber(before[i].Text)]; listed {
					want = expectCapped(before[i])
				} else if pairedWithListedCard(on, before[i], before) {
					// A security code takes its card's score and ceiling (#905), so the cap
					// reaches the code beside a listed value as well.
					want = expectCappedCode(before[i])
				}
				if !reflect.DeepEqual(after[i], want) {
					t.Errorf("%q: with the list\n  got  %+v\n  want %+v", content, after[i], want)
				}
				if after[i].Confidence != before[i].Confidence {
					moved++
				}
			}
		}
	}
	if moved == 0 {
		t.Fatal("toggling the list moved no score: the comparison is vacuous")
	}
}

// TestPublishedTestPANCapSurvivesTheBridge toggles the list through the document bridge, in a
// CSV document whose tabular boost (+20) is what lifted capped values on main.
func TestPublishedTestPANCapSurvivesTheBridge(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("name,card_number,exp\n")
	for _, p := range listedValues() {
		doc.WriteString("Jordan Q," + p + ",12/30\n")
	}
	after := bridgeScan(t, NewValidator(), doc.String(), "cards.csv")
	before := bridgeScan(t, withoutList(), doc.String(), "cards.csv")
	byLine := map[int]detector.Match{}
	for _, m := range before {
		byLine[m.LineNumber] = m
	}
	if len(after) != len(before) || len(after) != len(publishedTestPANSet) {
		t.Fatalf("%d matches with the list, %d without, %d rows", len(after), len(before), len(publishedTestPANSet))
	}
	for _, m := range after {
		b := byLine[m.LineNumber]
		if m.Text != b.Text || m.Type != b.Type {
			t.Errorf("line %d: %s %q with the list, %s %q without", m.LineNumber, m.Type, m.Text, b.Type, b.Text)
		}
		if want := min(b.Confidence, testValueCeiling); m.Confidence != want {
			t.Errorf("%q: reported %.1f with the list, want min(%.1f, 15) = %.1f", m.Text, m.Confidence, b.Confidence, want)
		}
	}
}

// sameBINControl draws a Luhn-valid number with p's first six digits and length that is not
// listed (#566's control, as the issue's same_bin_control does it).
func sameBINControl(v *Validator, p string, rng *rand.Rand) string {
	for {
		body := []byte(p[:6])
		for len(body) < len(p)-1 {
			body = append(body, byte('0'+rng.IntN(10)))
		}
		if c := withCheckDigit(v, string(body)); c != "" {
			if _, listed := publishedTestPANSet[c]; !listed {
				return c
			}
		}
	}
}

// withCheckDigit appends the digit that makes body Luhn-valid.
func withCheckDigit(v *Validator, body string) string {
	for d := byte('0'); d <= '9'; d++ {
		if c := body + string(d); v.luhnCheck(c) {
			return c
		}
	}
	return ""
}

// TestSameBINControlsAndNearMissesAreUntouched: for every listed value, a random same-BIN
// control and a near miss (one digit after the BIN changed, check digit recomputed) score and
// carry exactly what they do without the list. The lookup is on exact values, not prefixes.
func TestSameBINControlsAndNearMissesAreUntouched(t *testing.T) {
	on, off := NewValidator(), withoutList()
	rng := rand.New(rand.NewPCG(13, 883))
	checked := 0
	for _, b := range publishedTestPANBlocks {
		for _, p := range b.pans {
			body := []byte(p[:len(p)-1])
			body[6] = '0' + (body[6]-'0'+1)%10
			near := withCheckDigit(on, string(body))
			for _, c := range []string{sameBINControl(on, p, rng), near} {
				if _, listed := publishedTestPANSet[c]; listed {
					continue // a near miss that is itself published is not a control
				}
				for _, content := range []string{c, "Card number: " + c, "name,card_number\nJordan Q," + c + "\n"} {
					after, _ := on.ValidateContent(content, "probe.txt")
					before, _ := off.ValidateContent(content, "probe.txt")
					if !reflect.DeepEqual(after, before) {
						t.Errorf("control %s in %q moved:\n  got  %+v\n  want %+v", c, content, after, before)
					}
					checked++
				}
				m := onlyMatch(t, on, "Card number: "+c, c)
				if cs := checksOf(t, m); cs["not_test"] && cs["not_repeating"] {
					if ce, ok := ceilingOf(m); ok {
						t.Errorf("control %s on a labelled line carries a %.1f ceiling", c, ce)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no control was checked")
	}
}

// TestSuppressionRuleForTheUncappedFindingStillMatches: a rule written for a listed value's
// finding as main reported it (the list off) still suppresses the capped finding, because the
// current rule format hashes type, line, line text, context and value but not confidence.
func TestSuppressionRuleForTheUncappedFindingStillMatches(t *testing.T) {
	sm := suppressions.NewSuppressionManager(filepath.Join(t.TempDir(), "suppressions.yaml"))
	content := "Card number: 378282246310005\n{\"number\": \"3566002020360505\", \"cvc\": \"123\"}\nname,card_number\nJordan Q,6011000990139424\n"
	before, _ := withoutList().ValidateContent(content, "cards.txt")
	after, _ := NewValidator().ValidateContent(content, "cards.txt")
	// Three cards, and the labelled "cvc" beside the second one (#905), which takes its card's
	// score and so moves with it.
	if len(before) != 4 || len(after) != 4 {
		t.Fatalf("want 4 findings each way, got %d without the list and %d with it", len(before), len(after))
	}
	for _, m := range before {
		if m.Confidence <= testValueCeiling {
			t.Fatalf("precondition: %q scores %.1f without the list; the case would not show a demotion", m.Text, m.Confidence)
		}
		if err := sm.AddSuppression(m, "published test card", "test", nil); err != nil {
			t.Fatalf("AddSuppression(%q): %v", m.Text, err)
		}
	}
	for _, m := range after {
		if ok, _ := sm.IsSuppressed(m); !ok {
			t.Errorf("%s %q at %.1f: the rule written for its uncapped finding no longer suppresses it", m.Type, m.Text, m.Confidence)
		}
	}
	// A rule must not suppress a different value on the same line shape.
	control, _ := NewValidator().ValidateContent("Card number: "+syntheticControl+"\n", "cards.txt")
	if ok, _ := sm.IsSuppressed(control[0]); ok {
		t.Error("an unrelated value is suppressed: the check above proves nothing")
	}
}
