// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Synthetic values throughout: the repo's fixture names and addresses, 512010001 (area 512).

func oleMatch(line string, n int, typ, text, validator string, conf float64) detector.Match {
	return detector.Match{Text: text, Type: typ, Validator: validator, Confidence: conf, LineNumber: n,
		Context: detector.ContextInfo{FullLine: line}}
}

// legacyContainers builds the same body text as a .doc, .xls and .ppt main stream.
func legacyContainers(body string) map[string][]byte {
	return map[string][]byte{
		".doc": olefixture.LegacyDoc(body, nil),
		".xls": olefixture.MustBuild([]olefixture.Stream{{Name: olefixture.StreamWorkbook, Data: []byte(body)}}),
		".ppt": olefixture.MustBuild([]olefixture.Stream{{Name: olefixture.StreamPowerPoint, Data: []byte(body)}}),
	}
}

func mainStream(ext string) string {
	return map[string]string{".doc": olefixture.StreamWordDocument, ".xls": olefixture.StreamWorkbook, ".ppt": olefixture.StreamPowerPoint}[ext]
}

func redactLegacy(t *testing.T, ext string, data []byte, ms []detector.Match, st redactors.RedactionStrategy) (string, *redactors.RedactionResult, error) {
	t.Helper()
	src := writeFixture(t, data, "in"+ext)
	out := filepath.Join(t.TempDir(), "out"+ext)
	res, err := NewLegacyOLERedactor(nil, nil).RedactDocument(src, out, ms, st)
	if err != nil {
		return "", nil, err
	}
	return string(streamContents(t, out)[mainStream(ext)]), res, nil
}

const mlk = "Located at 100 Martin Luther King Blvd"

func mlkMatches(n int) []detector.Match {
	// Input order as the scan delivers it: PERSON_NAME sorts before PHYSICAL_ADDRESS by check name,
	// which is exactly the order that masked the name first and stranded "100" and "Blvd".
	return []detector.Match{
		oleMatch(mlk, n, "PERSON_NAME", "Martin Luther King", "PERSON_NAME", 93),
		oleMatch(mlk, n, "US_STREET_ADDRESS", "100 Martin Luther King Blvd", "physical_address", 65),
	}
}

// Containment leaked in legacy OLE because nothing resolved overlaps there: "100 ****************** Blvd".
func TestLegacyContainedGroupIsWrittenWhole(t *testing.T) {
	for ext, data := range legacyContainers(mlk + "\r") {
		for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
			got, res, err := redactLegacy(t, ext, data, mlkMatches(1), st)
			if err != nil {
				t.Fatalf("%s %s: %v", ext, st, err)
			}
			if want := "Located at " + strings.Repeat("*", 27) + "\r"; got != want {
				t.Errorf("%s %s: got %q, want %q", ext, st, got, want)
			}
			if len(res.RedactionMap) != 1 || res.RedactionMap[0].Metadata[redactors.OverlapGroupKindKey] != "contained" {
				t.Errorf("%s %s: want one mapping for the group, got %+v", ext, st, res.RedactionMap)
			}
		}
	}
}

func TestLegacyPartialGroupIsMaskedWhole(t *testing.T) {
	line := "Residence: 77 August Lane, Boise ID 83702"
	ms := []detector.Match{
		oleMatch(line, 1, "PERSON_NAME", "August Lane", "PERSON_NAME", 92),
		oleMatch(line, 1, "PERSON_NAME", "Lane, Boise", "PERSON_NAME", 67),
		oleMatch(line, 1, "US_STREET_ADDRESS", "77 August Lane", "physical_address", 95),
	}
	for ext, data := range legacyContainers(line + "\r") {
		got, res, err := redactLegacy(t, ext, data, ms, redactors.RedactionFormatPreserving)
		if err != nil {
			t.Fatalf("%s: %v", ext, err)
		}
		if want := "Residence: " + strings.Repeat("*", 21) + " ID 83702\r"; got != want {
			t.Errorf("%s: got %q, want %q", ext, got, want)
		}
		if !reflect.DeepEqual(res.RedactionMap[0].Metadata[redactors.OverlapMemberTypesKey], []string{"PERSON_NAME", "PERSON_NAME", "US_STREET_ADDRESS"}) {
			t.Errorf("%s: the mapping must name every member, got %+v", ext, res.RedactionMap[0].Metadata)
		}
	}
}

// A short value reported alone on one line used to be overwritten first (input order) everywhere it
// occurs, including inside a longer value on another line, which then could not be found.
func TestLegacyLongestValueIsWrittenFirst(t *testing.T) {
	alone := "Signed: Martin Luther King"
	body := alone + "\r" + mlk + "\r"
	ms := append([]detector.Match{oleMatch(alone, 1, "PERSON_NAME", "Martin Luther King", "PERSON_NAME", 90)}, mlkMatches(2)...)
	got, _, err := redactLegacy(t, ".doc", olefixture.LegacyDoc(body, nil), ms, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	want := "Signed: " + strings.Repeat("*", 18) + "\rLocated at " + strings.Repeat("*", 27) + "\r"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLegacyIdenticalGroupKeepsNoDigitAMemberHides(t *testing.T) {
	line := "Passport number: 512010001"
	ms := []detector.Match{
		oleMatch(line, 1, "SSN", "512010001", "ssn", 50),
		oleMatch(line, 1, "PASSPORT", "512010001", "passport", 100),
	}
	got, _, err := redactLegacy(t, ".doc", olefixture.LegacyDoc(line+"\r", nil), ms, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Passport number: *********\r" {
		t.Fatalf("got %q", got)
	}
}

// A group not found verbatim in any stream refuses the file rather than writing part of it.
func TestLegacyUnwritableGroupRefuses(t *testing.T) {
	_, _, err := redactLegacy(t, ".doc", olefixture.LegacyDoc("Located at 100 Martin\rLuther King Blvd\r", nil), mlkMatches(1), redactors.RedactionFormatPreserving)
	if err == nil {
		t.Fatal("a group that cannot be located must refuse the file")
	}
	if strings.Contains(err.Error(), "Martin") || !strings.Contains(err.Error(), "US_STREET_ADDRESS") {
		t.Fatalf("the refusal must name types, never values: %v", err)
	}
}
