// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Synthetic values throughout: 512010001 (area 512), the repo's fixture address and names.

func bodyMatch(line string, n int, typ, text, validator string, conf float64) detector.Match {
	return detector.Match{Text: text, Type: typ, Validator: validator, Confidence: conf, LineNumber: n,
		Context: detector.ContextInfo{FullLine: line}}
}

var tagRE = regexp.MustCompile(`<[^>]*>`)

// redactDocxBody redacts a .docx built from lines and returns the body text, one paragraph per line.
func redactDocxBody(t *testing.T, lines []string, ms []detector.Match, st redactors.RedactionStrategy) (string, *redactors.RedactionResult, error) {
	t.Helper()
	dir := t.TempDir()
	src := writeDocx(t, dir, "in.docx", lines...)
	out := filepath.Join(dir, "out.docx")
	res, err := NewOfficeRedactor(nil, nil).RedactDocument(src, out, ms, st)
	if err != nil {
		return "", nil, err
	}
	doc := string(readPartsInsideZip(t, out)["word/document.xml"])
	doc = strings.ReplaceAll(doc, "</w:p>", "\n")
	return strings.TrimSpace(tagRE.ReplaceAllString(doc, "")), res, nil
}

const officeResidence = "Residence: 77 August Lane, Boise ID 83702"

func officeResidenceMatches() []detector.Match {
	return []detector.Match{
		bodyMatch(officeResidence, 1, "US_STREET_ADDRESS", "77 August Lane", "physical_address", 95),
		bodyMatch(officeResidence, 1, "PERSON_NAME", "August Lane", "PERSON_NAME", 92),
		bodyMatch(officeResidence, 1, "PERSON_NAME", "Lane, Boise", "PERSON_NAME", 67),
	}
}

// The Office writer recorded each member as its own value and the longest-first replacer wrote the
// earlier-starting one, stranding the later one's tail: "[US_STREET_ADDRESS-REDACTED], Boise".
func TestOfficeOverlapGroupIsOneValue(t *testing.T) {
	want := map[redactors.RedactionStrategy]string{
		redactors.RedactionSimple:           "Residence: [US_STREET_ADDRESS-REDACTED] ID 83702",
		redactors.RedactionFormatPreserving: "Residence: ********************* ID 83702",
	}
	for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving, redactors.RedactionSynthetic} {
		body, res, err := redactDocxBody(t, []string{officeResidence}, officeResidenceMatches(), st)
		if err != nil {
			t.Fatalf("%s: %v", st, err)
		}
		if w, ok := want[st]; ok && body != w {
			t.Errorf("%s: got %q, want %q", st, body, w)
		}
		for _, leak := range []string{"77", "August", "Lane", "Boise"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: %q survived: %q", st, leak, body)
			}
		}
		if len(res.RedactionMap) != 1 || !reflect.DeepEqual(res.RedactionMap[0].Metadata[redactors.OverlapMemberTypesKey],
			[]string{"PERSON_NAME", "PERSON_NAME", "US_STREET_ADDRESS"}) {
			t.Errorf("%s: want one mapping naming every member, got %+v", st, res.RedactionMap)
		}
	}
}

// A value a group touches takes the STRICTER rendering everywhere it appears, because Office replaces
// by value: a lone SSN with the same digits, recorded first, used to hand its "*****0001" to the
// PASSPORT+SSN line as well.
func TestOfficeStricterRenderingWinsForAGroupedValue(t *testing.T) {
	l1, l2 := "SSN 512010001", "Passport number: 512010001"
	ms := []detector.Match{
		bodyMatch(l1, 1, "SSN", "512010001", "ssn", 90),
		bodyMatch(l2, 2, "PASSPORT", "512010001", "passport", 100),
		bodyMatch(l2, 2, "SSN", "512010001", "ssn", 50),
	}
	body, _, err := redactDocxBody(t, []string{l1, l2}, ms, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if body != "SSN *********\nPassport number: *********" {
		t.Fatalf("got %q", body)
	}
	// A value NO group touches keeps first-write-wins: two lone findings of different types.
	l3 := "Passport 512010002"
	ms = []detector.Match{
		bodyMatch("SSN 512010002", 1, "SSN", "512010002", "ssn", 90),
		bodyMatch(l3, 2, "PASSPORT", "512010002", "passport", 100),
	}
	body, _, err = redactDocxBody(t, []string{"SSN 512010002", l3}, ms, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if body != "SSN *****0002\nPassport *****0002" {
		t.Fatalf("an ungrouped value must keep its first-write-wins rendering, got %q", body)
	}
}

func TestOfficeIdenticalSpanRendersByTheRule(t *testing.T) {
	line := "Passport number: 512010001"
	for _, order := range [][]string{{"PASSPORT", "SSN"}, {"SSN", "PASSPORT"}} {
		conf := map[string]float64{"PASSPORT": 100, "SSN": 50}
		var ms []detector.Match
		for _, typ := range order {
			ms = append(ms, bodyMatch(line, 1, typ, "512010001", strings.ToLower(typ), conf[typ]))
		}
		for st, want := range map[redactors.RedactionStrategy]string{
			redactors.RedactionSimple:           "Passport number: [PASSPORT-REDACTED]",
			redactors.RedactionFormatPreserving: "Passport number: *********",
		} {
			body, _, err := redactDocxBody(t, []string{line}, ms, st)
			if err != nil {
				t.Fatal(err)
			}
			if body != want {
				t.Errorf("order %v %s: got %q, want %q", order, st, body, want)
			}
		}
	}
}

// A group whose union is in no part refuses the document instead of writing what it can.
func TestOfficeUnwritableGroupRefuses(t *testing.T) {
	_, _, err := redactDocxBody(t, []string{"Residence: 77 August Lane,", "Boise ID 83702"}, officeResidenceMatches(), redactors.RedactionFormatPreserving)
	if err == nil {
		t.Fatal("a group that cannot be located must refuse the document")
	}
	if strings.Contains(err.Error(), "August") || !strings.Contains(err.Error(), "US_STREET_ADDRESS") {
		t.Fatalf("the refusal must name types, never values: %v", err)
	}
}
