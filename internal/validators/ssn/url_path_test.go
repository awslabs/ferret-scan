// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"strings"
	"testing"
	"time"
)

// Every test here goes through ValidateContent, so this file compiles against main's code and
// each test function can be run there to show it fails (#804).

// resumeRow is the issue's tab-separated contact row with an e-mail domain that is not
// "example". On main, "example" costs the row 65 points: -15 as a negative keyword, -40 as a
// test-data marker and -10 for a negative keyword on a tabular line, and that is what kept the
// issue's own reproducer at 30 LOW. With an ordinary domain the row is the shape that reached
// HIGH on main: base 70 for a bare value with a valid area number, plus +25 from
// isEnhancedTabularData for two or more tabs, uncapped because the line is tabular.
const resumeRow = "Candidate\tMichael O\thttps://www.linkedin.com/in/michael-o-291135150\t555-0100\tm.o@mail.invalid"

func confidences(t *testing.T, v *Validator, line, file string) []float64 {
	t.Helper()
	got, err := v.ValidateContent(line, file)
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	out := make([]float64, 0, len(got))
	for _, m := range got {
		out = append(out, m.Confidence)
	}
	return out
}

// The digits at the end of a URL's path are a resource identifier, not an SSN.
//
// Main @ 0501dcd reports every row: the issue's two lines at 50 and 30, resumeRow at 95 HIGH
// (also as a .docx paragraph), the "Social:" line at 95 HIGH (one positive keyword, no cap off a
// table) and the rest at 50.
func TestURLPathComponentIsNotAnSSN(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		file string
	}{
		{"issue line 1", "Profile: https://www.linkedin.com/in/michael-o-291135150", "resume.txt"},
		{"issue line 2", "Candidate\tMichael O\thttps://www.linkedin.com/in/michael-o-291135150\t555-0100\tm.o@example.com", "resume.txt"},
		{"tab row that reached HIGH", resumeRow, "resume.txt"},
		{"same row from a docx", resumeRow, "resume.docx"},
		{"a docx table cell on its own line", "https://www.linkedin.com/in/michael-o-291135150", "resume.docx"},
		{"social-media label, not an identifier label", "Social: https://www.linkedin.com/in/michael-o-291135150", "resume.txt"},
		{"csv row", "Michael O,https://www.linkedin.com/in/michael-o-291135150,555-0100", "contacts.txt"},
		{"whole path segment after '/'", "https://vimeo.com/291135150", "notes.txt"},
		{"trailing slash", "https://www.linkedin.com/in/michael-o-291135150/", "notes.txt"},
		{"query after the path", "https://www.linkedin.com/in/michael-o-291135150?trk=profile", "notes.txt"},
		{"sentence period after the url", "See https://www.linkedin.com/in/michael-o-291135150.", "notes.txt"},
		{"markdown link", "[LinkedIn](https://www.linkedin.com/in/michael-o-291135150)", "README.md"},
		{"html attribute", `<a href="https://www.linkedin.com/in/michael-o-291135150">profile</a>`, "page.html"},
		{"plain http", "http://www.linkedin.com/in/michael-o-291135150", "notes.txt"},
		{"scheme in capitals", "HTTPS://WWW.LINKEDIN.COM/IN/MICHAEL-O-291135150", "notes.txt"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := confidences(t, v, c.line, c.file); len(got) != 0 {
				t.Errorf("a URL path component was reported as an SSN at %v: %s", got, c.line)
			}
		})
	}
}

// The rule's edges. Each row that is still reported keeps main's exact confidence, which is the
// scope proof: the rule removes the URL path component and nothing beside it. The first three
// rows are the issue's own acceptance controls.
//
// The rows reported as 0 pair with the row above them and are dropped on the branch only.
func TestURLVetoBoundaries(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		want []float64 // confidences on the branch; nil means no finding
	}{
		// The issue's acceptance controls, at main's confidence.
		{"issue control: labelled bare value", "SSN: 291135150", []float64{95}},
		{"issue control: dashed value", "291-13-5150", []float64{60}},
		{"issue control: query value", "?ssn=291135150", []float64{95}},

		{"bare value alone", "291135150", []float64{50}},

		// A query value after '=' is not a path component.
		{"query value inside a url", "https://hr.invalid/lookup?ssn=291135150", []float64{100}},
		{"same value as a path segment", "https://hr.invalid/lookup/291135150", nil},

		// The query and the fragment are outside the path.
		{"slug tail inside the query", "https://www.linkedin.com/in/x?ref=a-291135150", []float64{50}},
		{"slug tail before the query", "https://www.linkedin.com/in/a-291135150?ref=x", nil},
		{"slug tail inside the fragment", "https://a.invalid/page#a-291135150", []float64{50}},
		{"slug tail before the fragment", "https://a.invalid/page/a-291135150#top", nil},

		// A file name is kept: a scan named by its holder's SSN is a leak shape.
		{"file name with an extension", "https://files.invalid/scans/291135150.pdf", []float64{50}},
		{"sentence period is not an extension", "See https://files.invalid/scans/291135150.", nil},

		// Stored-file schemes are not web URLs.
		{"s3 object key", "s3://scans/archive/doe-john-291135150", []float64{50}},
		{"file url", "file:///srv/scans/doe-john-291135150", []float64{50}},
		{"ftp url", "ftp://files.invalid/scans/291135150", []float64{50}},
		{"same key over https", "https://scans.invalid/archive/doe-john-291135150", nil},

		// A field after a quote or a comma is not part of the URL before it.
		{"next json field", `{"url":"https://a.invalid/x","file":"/scans/291135150"}`, []float64{85}},
		{"same path inside the url", `{"url":"https://a.invalid/scans/291135150"}`, nil},
		{"next csv field", "https://a.invalid/x,doe-291135150", []float64{50}},
		{"next semicolon-separated field", "https://a.invalid/x;doe-291135150", []float64{50}},
		{"same slug inside the url", "https://a.invalid/x/doe-291135150", nil},

		// Only the bare form: the dashed form is how an SSN is written.
		{"dashed value in a slug", "https://www.linkedin.com/in/michael-291-13-5150", []float64{60}},
		{"bare value in the same slug", "https://www.linkedin.com/in/michael-291135150", nil},

		// Residual, pinned so a change to it is deliberate: without a scheme the token is not
		// recognised as a URL.
		{"slug with no scheme", "linkedin.com/in/michael-o-291135150", []float64{50}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := confidences(t, v, c.line, "notes.txt")
			if !equalConfidences(got, c.want) {
				t.Errorf("%s\n  got %v, want %v", c.line, got, c.want)
			}
		})
	}
}

func equalConfidences(got, want []float64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The veto yields to a label that names the identifier, and only to such a label.
//
// "SSN: https://hr.invalid/people/291135150" is the case the veto must not delete: a reported
// finding is the only kind the redactor masks. "Social:" and "HR:" are domain words from the
// positive list and do not lift it: on a resume they label a profile link, and main scores the
// "Social:" line 95 HIGH.
func TestURLVetoYieldsToAnIdentifierLabel(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		want []float64
	}{
		{"ssn label", "SSN: https://hr.invalid/people/291135150", []float64{100}},
		{"employee id label", "Employee ID https://hr.invalid/people/291135150", []float64{100}},
		{"taxpayer id label", "taxpayer id: https://hr.invalid/people/291135150", []float64{100}},
		{"social is a profile label", "Social: https://www.linkedin.com/in/michael-o-291135150", nil},
		{"hr is a domain word", "HR: https://www.linkedin.com/in/michael-o-291135150", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := confidences(t, v, c.line, "notes.txt")
			if !equalConfidences(got, c.want) {
				t.Errorf("%s\n  got %v, want %v", c.line, got, c.want)
			}
		})
	}
}

// A column header naming the identifier keeps the value, exactly as a label on the line does;
// the same column under a neutral header is dropped.
func TestURLVetoReadsTheColumnHeader(t *testing.T) {
	v := NewValidator()

	const rows = "Michael O,https://hr.invalid/people/291135150,active\n" +
		"Jane Q,https://hr.invalid/people/449874100,active\n" +
		"Ravi K,https://hr.invalid/people/130075728,inactive\n"

	labelled := len(confidences(t, v, "name,ssn_link,status\n"+rows, "people.csv"))
	neutral := len(confidences(t, v, "name,profile_link,status\n"+rows, "people.csv"))

	if labelled != 3 {
		t.Errorf("under an ssn_link header, %d of 3 values were reported; the header names the "+
			"identifier, so all three must stay reported", labelled)
	}
	if neutral != 0 {
		t.Errorf("under a profile_link header, %d of 3 URL path components were reported as SSNs",
			neutral)
	}
}

// The decision is per OCCURRENCE, like the decimal-fraction guard beside it: the same digits
// standing alone elsewhere on the line keep the finding, in either order, and a value is dropped
// only when every occurrence is a URL path component.
func TestURLVetoIsDecidedPerOccurrence(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		want []float64
	}{
		{"bare occurrence first", "SSN: 291135150 https://vimeo.com/291135150", []float64{95, 95}},
		{"bare occurrence last", "https://vimeo.com/291135150 SSN: 291135150", []float64{95, 95}},
		{"every occurrence in a url", "https://vimeo.com/291135150 https://www.linkedin.com/in/a-291135150", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := confidences(t, v, c.line, "notes.txt")
			if !equalConfidences(got, c.want) {
				t.Errorf("%s\n  got %v, want %v", c.line, got, c.want)
			}
		})
	}
}

// The scheme scan is one forward pass per line. A 1MB single line holding one URL with ~87K slug
// tails must finish inside the same ceiling as TestSSNValidator_SingleLineDoSRegression and report
// nothing; a backward search from each candidate would be quadratic here.
//
// The tail is 291135150 because it scores on its own. A repdigit run such as 219099999 is
// already dropped on main as an obvious test sequence, which would make this test pass there for
// a reason unrelated to the URL.
func TestURLVetoOnASingleLongLine(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in -short mode")
	}

	const targetBytes = 1 << 20
	var sb strings.Builder
	sb.Grow(targetBytes + 32)
	sb.WriteString("https://a.invalid/")
	for sb.Len() < targetBytes {
		sb.WriteString("x-291135150/")
	}

	ceiling := 30 * time.Second
	if raceEnabled {
		ceiling = 180 * time.Second
	}

	v := NewValidator()
	start := time.Now()
	got, err := v.ValidateContent(sb.String(), "long.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("%d URL path components on one line were reported as SSNs", len(got))
	}
	if elapsed > ceiling {
		t.Errorf("1MB single URL line took %v (> %v ceiling)", elapsed, ceiling)
	}
	t.Logf("1MB single URL line: %d findings in %v", len(got), elapsed)
}
