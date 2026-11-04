// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Tests for the label-adjacent shapes of #857: standard ways of writing a date
// of birth that produced no finding of any type even directly after "Date of
// Birth:", "DOB" or {"dob": ...}, so --enable-redaction left them in cleartext.

// dobMatches returns the DATE_OF_BIRTH findings v reports for one line.
func dobMatches(t *testing.T, v *Validator, line string) []detector.Match {
	t.Helper()
	matches, err := v.ValidateContent(line, "dob.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", line, err)
	}
	var out []detector.Match
	for _, m := range matches {
		if m.Type == "DATE_OF_BIRTH" {
			out = append(out, m)
		}
	}
	return out
}

// renderMatches is a stable one-line view of findings for failure messages and
// comparisons: "90[1987-03-14]@15", or "-" for none.
func renderMatches(ms []detector.Match) string {
	if len(ms) == 0 {
		return "-"
	}
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = fmt.Sprintf("%.0f[%s]@%d", m.Confidence, m.Text, len(m.Context.BeforeText))
	}
	return strings.Join(parts, " ")
}

const (
	// recognised: matched by the original patterns, labelled or not.
	recognised = "recognised"
	// labelAdjacentOnly: reported only after an adjacent DOB label.
	labelAdjacentOnly = "label-adjacent"
)

// shapeCoverage is the explicit coverage list over every shape #857 measured,
// in the issue's order, plus its two `Sept` forms and five non-English forms.
// span is the finding text expected after an adjacent label ("" = none). A
// change that starts or stops matching any shape fails
// TestLabelAdjacentShapeCoverage until this list is updated, so recall cannot
// drift silently in either direction.
var shapeCoverage = []struct {
	value, span, status string
}{
	{"03/14/1987", "03/14/1987", recognised},
	{"14/03/1987", "14/03/1987", recognised},
	{"3/14/1987", "3/14/1987", recognised},
	{"03-14-1987", "03-14-1987", recognised},
	{"14-03-1987", "14-03-1987", recognised},
	{"14.03.1987", "14.03.1987", recognised},
	{"14.3.1987", "14.3.1987", recognised},
	{"1987-03-14", "1987-03-14", recognised},
	{"1987-03-14 00:00:00", "1987-03-14", recognised},
	{"03/14/87", "03/14/87", recognised},
	{"14.03.87", "14.03.87", recognised},
	{"March 14, 1987", "March 14, 1987", recognised},
	{"Mar 14, 1987", "Mar 14, 1987", recognised},
	{"March 14th, 1987", "March 14th, 1987", recognised},
	{"14 March 1987", "14 March 1987", recognised},
	{"14 Mar 1987", "14 Mar 1987", recognised},
	// ISO 8601 date-times: the span is the date part, as for the SQL datetime.
	{"1987-03-14T00:00:00Z", "1987-03-14", labelAdjacentOnly},
	{"1987-03-14T00:00:00.000Z", "1987-03-14", labelAdjacentOnly},
	{"1987-03-14T00:00:00+00:00", "1987-03-14", labelAdjacentOnly},
	{"1987-03-14T00:00:00", "1987-03-14", labelAdjacentOnly},
	// Year-first numerics and unpadded ISO.
	{"1987/03/14", "1987/03/14", labelAdjacentOnly},
	{"1987.03.14", "1987.03.14", labelAdjacentOnly},
	{"1987-3-14", "1987-3-14", labelAdjacentOnly},
	// Month names in any case.
	{"MARCH 14, 1987", "MARCH 14, 1987", labelAdjacentOnly},
	{"march 14, 1987", "march 14, 1987", labelAdjacentOnly},
	{"14 MAR 1987", "14 MAR 1987", labelAdjacentOnly},
	{"14-MAR-1987", "14-MAR-1987", labelAdjacentOnly}, // Oracle DD-MON-YYYY
	// Joined tokens and two-digit years.
	{"14-Mar-1987", "14-Mar-1987", labelAdjacentOnly},
	{"14/Mar/1987", "14/Mar/1987", labelAdjacentOnly},
	{"14MAR1987", "14MAR1987", labelAdjacentOnly}, // SAS DATE9.
	{"1987-Mar-14", "1987-Mar-14", labelAdjacentOnly},
	{"Mar-14-1987", "Mar-14-1987", labelAdjacentOnly},
	{"14-Mar-87", "14-Mar-87", labelAdjacentOnly}, // Oracle DD-MON-RR
	// Punctuation and prose.
	{"Mar. 14, 1987", "Mar. 14, 1987", labelAdjacentOnly},
	{"14 Mar. 1987", "14 Mar. 1987", labelAdjacentOnly},
	{"March 14,1987", "March 14,1987", labelAdjacentOnly},
	{"14th of March 1987", "14th of March 1987", labelAdjacentOnly},
	{"1987 March 14", "1987 March 14", labelAdjacentOnly},
	// Out of scope, measured in #857.
	{"14. 3. 1987", "", "unsupported: spaced numerics collide with table and grid rows"},
	{"14 03 1987", "", "unsupported: spaced numerics collide with table and grid rows"},
	{"19870314", "", "unsupported: compact digits collide with order numbers and backup names"},
	{"14031987", "", "unsupported: compact digits collide with ticket and order numbers"},
	{"870314", "", "unsupported: compact digits collide with one-time codes"},
	// The two `Sept` forms.
	{"Sept. 14, 1987", "Sept. 14, 1987", labelAdjacentOnly},
	{"14 Sept 1987", "14 Sept 1987", labelAdjacentOnly},
	// Non-English month names: no validator carries non-English vocabulary.
	{"14. März 1987", "", "unsupported: non-English month name"},
	{"14 mars 1987", "", "unsupported: non-English month name"},
	{"14 de marzo de 1987", "", "unsupported: non-English month name"},
	{"1987年3月14日", "", "unsupported: CJK date"},
	{"1987년 3월 14일", "", "unsupported: CJK date"},
}

// acceptanceLabelStyles are the five label styles of #857's acceptance criteria.
var acceptanceLabelStyles = []string{
	"Date of Birth: %s",
	"DOB %s",
	`{"dob": "%s"}`,
	`{"dateOfBirth": "%s"}`,
	"<DateOfBirth>%s</DateOfBirth>",
}

// TestLabelAdjacentShapeCoverage is #857's acceptance criterion: every in-scope
// shape gives exactly one DATE_OF_BIRTH at >= 90, with the stated span, under
// each of the five label styles, and the label-adjacent shapes give nothing
// without a label. Recognised shapes keep their unlabelled score of 5.
func TestLabelAdjacentShapeCoverage(t *testing.T) {
	v := NewValidator()
	for _, sc := range shapeCoverage {
		for _, style := range acceptanceLabelStyles {
			line := fmt.Sprintf(style, sc.value)
			got := dobMatches(t, v, line)
			if sc.span == "" {
				if len(got) != 0 {
					t.Errorf("%s shape %q: %q reported %s, want nothing", sc.status, sc.value, line, renderMatches(got))
				}
				continue
			}
			if len(got) != 1 || got[0].Text != sc.span || got[0].Confidence < 90 {
				t.Errorf("%s shape %q: %q reported %s, want exactly one finding [%s] at >= 90",
					sc.status, sc.value, line, renderMatches(got), sc.span)
			}
		}

		line := fmt.Sprintf("Reference %s recorded.", sc.value)
		got := dobMatches(t, v, line)
		switch sc.status {
		case recognised:
			if len(got) != 1 || got[0].Text != sc.span || got[0].Confidence != 5 {
				t.Errorf("recognised shape %q without a label: %q reported %s, want [%s] at 5 as before",
					sc.value, line, renderMatches(got), sc.span)
			}
		default:
			if len(got) != 0 {
				t.Errorf("%s shape %q without a label: %q reported %s, want nothing",
					sc.status, sc.value, line, renderMatches(got))
			}
		}
	}
}

// TestRecognisedShapesAreByteIdentical pins the 16 shapes the original patterns
// recognised, under the issue's four contexts, to main's Text, LineNumber,
// BeforeText, AfterText and confidence. Each value below was produced by main
// (b0a9163). The label-adjacent path runs after the original patterns and never
// keeps a candidate that overlaps one of theirs, so none of these may move: a
// moved span would orphan every suppression rule written against it.
func TestRecognisedShapesAreByteIdentical(t *testing.T) {
	rows := []struct {
		line, text, before, after string
		confidence                float64
	}{
		{"Date of Birth: 03/14/1987", "03/14/1987", "Date of Birth: ", "", 90},
		{"DOB 03/14/1987", "03/14/1987", "DOB ", "", 90},
		{"{\"dob\": \"03/14/1987\"}", "03/14/1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 03/14/1987 recorded.", "03/14/1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 14/03/1987", "14/03/1987", "Date of Birth: ", "", 90},
		{"DOB 14/03/1987", "14/03/1987", "DOB ", "", 90},
		{"{\"dob\": \"14/03/1987\"}", "14/03/1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 14/03/1987 recorded.", "14/03/1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 3/14/1987", "3/14/1987", "Date of Birth: ", "", 90},
		{"DOB 3/14/1987", "3/14/1987", "DOB ", "", 90},
		{"{\"dob\": \"3/14/1987\"}", "3/14/1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 3/14/1987 recorded.", "3/14/1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 03-14-1987", "03-14-1987", "Date of Birth: ", "", 90},
		{"DOB 03-14-1987", "03-14-1987", "DOB ", "", 90},
		{"{\"dob\": \"03-14-1987\"}", "03-14-1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 03-14-1987 recorded.", "03-14-1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 14-03-1987", "14-03-1987", "Date of Birth: ", "", 90},
		{"DOB 14-03-1987", "14-03-1987", "DOB ", "", 90},
		{"{\"dob\": \"14-03-1987\"}", "14-03-1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 14-03-1987 recorded.", "14-03-1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 14.03.1987", "14.03.1987", "Date of Birth: ", "", 90},
		{"DOB 14.03.1987", "14.03.1987", "DOB ", "", 90},
		{"{\"dob\": \"14.03.1987\"}", "14.03.1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 14.03.1987 recorded.", "14.03.1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 14.3.1987", "14.3.1987", "Date of Birth: ", "", 90},
		{"DOB 14.3.1987", "14.3.1987", "DOB ", "", 90},
		{"{\"dob\": \"14.3.1987\"}", "14.3.1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 14.3.1987 recorded.", "14.3.1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 1987-03-14", "1987-03-14", "Date of Birth: ", "", 90},
		{"DOB 1987-03-14", "1987-03-14", "DOB ", "", 90},
		{"{\"dob\": \"1987-03-14\"}", "1987-03-14", "{\"dob\": \"", "\"}", 90},
		{"Reference 1987-03-14 recorded.", "1987-03-14", "Reference ", " recorded.", 5},
		{"Date of Birth: 1987-03-14 00:00:00", "1987-03-14", "Date of Birth: ", " 00:00:00", 90},
		{"DOB 1987-03-14 00:00:00", "1987-03-14", "DOB ", " 00:00:00", 90},
		{"{\"dob\": \"1987-03-14 00:00:00\"}", "1987-03-14", "{\"dob\": \"", " 00:00:00\"}", 90},
		{"Reference 1987-03-14 00:00:00 recorded.", "1987-03-14", "Reference ", " 00:00:00 recorded.", 5},
		{"Date of Birth: 03/14/87", "03/14/87", "Date of Birth: ", "", 90},
		{"DOB 03/14/87", "03/14/87", "DOB ", "", 90},
		{"{\"dob\": \"03/14/87\"}", "03/14/87", "{\"dob\": \"", "\"}", 90},
		{"Reference 03/14/87 recorded.", "03/14/87", "Reference ", " recorded.", 5},
		{"Date of Birth: 14.03.87", "14.03.87", "Date of Birth: ", "", 90},
		{"DOB 14.03.87", "14.03.87", "DOB ", "", 90},
		{"{\"dob\": \"14.03.87\"}", "14.03.87", "{\"dob\": \"", "\"}", 90},
		{"Reference 14.03.87 recorded.", "14.03.87", "Reference ", " recorded.", 5},
		{"Date of Birth: March 14, 1987", "March 14, 1987", "Date of Birth: ", "", 90},
		{"DOB March 14, 1987", "March 14, 1987", "DOB ", "", 90},
		{"{\"dob\": \"March 14, 1987\"}", "March 14, 1987", "{\"dob\": \"", "\"}", 90},
		{"Reference March 14, 1987 recorded.", "March 14, 1987", "Reference ", " recorded.", 5},
		{"Date of Birth: Mar 14, 1987", "Mar 14, 1987", "Date of Birth: ", "", 90},
		{"DOB Mar 14, 1987", "Mar 14, 1987", "DOB ", "", 90},
		{"{\"dob\": \"Mar 14, 1987\"}", "Mar 14, 1987", "{\"dob\": \"", "\"}", 90},
		{"Reference Mar 14, 1987 recorded.", "Mar 14, 1987", "Reference ", " recorded.", 5},
		{"Date of Birth: March 14th, 1987", "March 14th, 1987", "Date of Birth: ", "", 90},
		{"DOB March 14th, 1987", "March 14th, 1987", "DOB ", "", 90},
		{"{\"dob\": \"March 14th, 1987\"}", "March 14th, 1987", "{\"dob\": \"", "\"}", 90},
		{"Reference March 14th, 1987 recorded.", "March 14th, 1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 14 March 1987", "14 March 1987", "Date of Birth: ", "", 90},
		{"DOB 14 March 1987", "14 March 1987", "DOB ", "", 90},
		{"{\"dob\": \"14 March 1987\"}", "14 March 1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 14 March 1987 recorded.", "14 March 1987", "Reference ", " recorded.", 5},
		{"Date of Birth: 14 Mar 1987", "14 Mar 1987", "Date of Birth: ", "", 90},
		{"DOB 14 Mar 1987", "14 Mar 1987", "DOB ", "", 90},
		{"{\"dob\": \"14 Mar 1987\"}", "14 Mar 1987", "{\"dob\": \"", "\"}", 90},
		{"Reference 14 Mar 1987 recorded.", "14 Mar 1987", "Reference ", " recorded.", 5},
	}
	v := NewValidator()
	for _, r := range rows {
		got := dobMatches(t, v, r.line)
		if len(got) != 1 {
			t.Errorf("%q: got %s, want exactly one finding [%s]", r.line, renderMatches(got), r.text)
			continue
		}
		m := got[0]
		if m.Text != r.text || m.LineNumber != 1 || m.Context.BeforeText != r.before ||
			m.Context.AfterText != r.after || m.Confidence != r.confidence {
			t.Errorf("%q moved from main:\n  got  text=%q line=%d before=%q after=%q conf=%.0f\n"+
				"  want text=%q line=1 before=%q after=%q conf=%.0f",
				r.line, m.Text, m.LineNumber, m.Context.BeforeText, m.Context.AfterText, m.Confidence,
				r.text, r.before, r.after, r.confidence)
		}
	}
}

// TestLabelAdjacentLabelForms covers the label and gap spellings beyond the
// acceptance styles. Scoring is analyzeContext's, unchanged: a strong label
// gives 90, "born on" 85 (two weak keywords), "birthday" 70 (one).
func TestLabelAdjacentLabelForms(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{"born on 1987-03-14T00:00:00Z", "85[1987-03-14]@8"},
		{"Patient was born on 14 MAR 1987 in Springfield.", "85[14 MAR 1987]@20"},
		{"birthday: 14 MAR 1987", "70[14 MAR 1987]@10"},
		{"| Date of Birth | 14-MAR-1987 |", "90[14-MAR-1987]@18"},
		{"Date of Birth\t14-MAR-1987", "90[14-MAR-1987]@14"},
		{"D.O.B.: 14-MAR-1987", "90[14-MAR-1987]@8"},
		{"d.o.b 1987/03/14", "90[1987/03/14]@6"},
		{"DATE_OF_BIRTH=1987/03/14", "90[1987/03/14]@14"},
		{"date-of-birth: 14MAR1987", "90[14MAR1987]@15"},
		{`{"patientDob": "1987-03-14T00:00:00Z"}`, "90[1987-03-14]@16"},
		{`"DateOfBirth":"14MAR1987"`, "90[14MAR1987]@15"},
		{"member_dob: Mar. 14, 1987", "90[Mar. 14, 1987]@12"},
		{"dob=[14-MAR-1987]", "90[14-MAR-1987]@5"},
		{"Date of Birth (14-MAR-1987)", "90[14-MAR-1987]@15"},
		{"DOB:14-MAR-1987", "90[14-MAR-1987]@4"},
		{"birthdate: 1987 March 14th", "90[1987 March 14th]@11"},
		// The gap bound: eight gap bytes admit, nine do not.
		{"DOB" + strings.Repeat(" ", 8) + "14-MAR-1987", "90[14-MAR-1987]@11"},
		{"DOB" + strings.Repeat(" ", 9) + "14-MAR-1987", "-"},
	}
	v := NewValidator()
	for _, c := range cases {
		if got := renderMatches(dobMatches(t, v, c.line)); got != c.want {
			t.Errorf("%q: got %s, want %s", c.line, got, c.want)
		}
	}
}

// TestLabelAdjacencyIsRequired is the precision half. The new shapes are what
// timestamps, log lines and file names are made of, so a DOB keyword elsewhere
// on the line must not admit them: only a label that ENDS just before the
// value, with nothing but gap bytes between.
func TestLabelAdjacencyIsRequired(t *testing.T) {
	lines := []string{
		"14-MAR-1987",
		"Reference 14-MAR-1987 recorded.",
		"Patient age 39, seen 2024-03-14T09:00:00Z", // "age" is not an admitting label
		"years old as of 14-MAR-1987",               // nor is "years old"
		"birth: 14-MAR-1987",                        // nor is "birth"
		`{"dob": null, "createdAt": "2024-03-14T10:22:01Z"}`,
		`"dob_updated_at": "2024-03-14T10:22:01Z"`,
		`{"dobUpdatedAt": "2024-03-14T10:22:01Z"}`,
		`{"birthdayReminderAt": "2024-03-14T09:00:00Z"}`,
		"deploy dob-service 1987/03/14 now",
		"xdob: 14-MAR-1987", // no word boundary before the label
		"DOB14-MAR-1987",    // no boundary between label and value
		"DOB of spouse: 14-MAR-1987",
		"DOB - 14-MAR-1987", // '-' is not a gap byte
		"born in Springfield, 14 MAR 1987",
		"DOB: 14-Mar 1987", // two different joiners
		"DOB: 14MAR.1987",  // a period with no whitespace after it
		"DOB: Mar141987",   // no joiner between two numbers
		"DOB: 1987/03-14",  // mixed separators
		"DOB: 1987-03-14T", // a 'T' with no time
	}
	v := NewValidator()
	for _, line := range lines {
		if got := dobMatches(t, v, line); len(got) != 0 {
			t.Errorf("%q: reported %s, want nothing", line, renderMatches(got))
		}
	}
}

// TestLabelAdjacentKeepsOriginalSpans: where a shape is both recognised and
// label-adjacent (Title-case month names), the original pattern's span wins and
// the value is reported once.
func TestLabelAdjacentKeepsOriginalSpans(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{"DOB March 14, 1987", "90[March 14, 1987]@4"},
		{"DOB 14 March 1987", "90[14 March 1987]@4"},
		{"Date of Birth: Saturday, March 14, 1987", "90[March 14, 1987]@25"},
		{"DOB 1987-03-14 00:00:00", "90[1987-03-14]@4"},
		{"DOB 14-MAR-1987 (previously recorded as 1987-03-14)", "90[1987-03-14]@40 90[14-MAR-1987]@4"},
	}
	v := NewValidator()
	for _, c := range cases {
		if got := renderMatches(dobMatches(t, v, c.line)); got != c.want {
			t.Errorf("%q: got %s, want %s", c.line, got, c.want)
		}
	}
}

// TestLabelAdjacentDecoysMatchMain runs the decoys of #857. Each must give
// exactly what main gives (the results below are main's at b0a9163), with one
// intended exception: the labelled DOB on the "Name: Jane Doe" line is now
// reported, and the visit timestamp beside it still is not.
func TestLabelAdjacentDecoysMatchMain(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{"2024-03-14T10:22:01Z INFO request served", "-"},
		{`{"createdAt": "2024-03-14T10:22:01.123Z", "status": "ok"}`, "-"},
		{`{"lastLogin": "2019-03-14T00:00:00Z"}`, "-"},
		{`{"dobUpdatedAt": "2024-03-14T10:22:01Z"}`, "-"},
		{`{"birthdayReminderAt": "2024-03-14T09:00:00Z"}`, "-"},
		{"1987-03-14,2024-03-14T10:22:01Z", "5[1987-03-14]@0"},
		{`{"id":"u-0001","dob":"1987-03-14","createdAt":"2024-03-14T10:22:01.123Z","updatedAt":"2024-05-02T08:00:00.000Z","lastLogin":"2019-03-14T00:00:00Z"}`, "90[1987-03-14]@22"},
		{`{"ts":"2024-03-14T10:22:01Z","level":"warn","msg":"cache age exceeded"}`, "-"},
		{`{"dob": null, "createdAt": "2024-03-14T10:22:01Z"}`, "-"},
		{`"dob_updated_at": "2024-03-14T10:22:01Z"`, "-"},
		{"Patient age 39, seen 2024-03-14T09:00:00Z", "-"},
		{"certifi==2024.02.02", "-"},
		{"See https://example.com/blog/2019/03/14/release-notes for details", "-"},
		{"/var/logs/2019/03/14/app.log rotated", "-"},
		{"Order 19870314 shipped", "-"},
		{"backup_20240314.tar.gz", "-"},
		{"Ticket 14031987 closed", "-"},
		{"Your verification code is 870314", "-"},
		{"Grid row: 12 05 2019 44 07", "-"},
		{"Version 2024.01.15 released today", "-"},
		{`"created_at": "2024-03-15T10:00:00Z"`, "-"},
		{"Test DOB: 1987/03/14", "-"},
		{"Date of Birth: 14 MAR 1987 (sample)", "-"},
		{"pip install dob==2024.03.14", "-"},
		{"dob: 2024.03.14 release notes", "-"},
		{"deploy dob-service 2024.03.14 build 7", "-"},
		{"DOB: 14-MAR-1987 (test)", "-"},
		{"Sample DOB: 14-MAR-1987", "-"},
		// Precision defects #857 found while measuring, out of its scope; pinned
		// here so a change to them is deliberate.
		{"2024-03-14 10:22:01 WARN cache age exceeded", "70[2024-03-14]@0"},
		{"deploy dob-service 2024-03-14 build 7", "90[2024-03-14]@19"},
		// The intended change.
		{"Name: Jane Doe, DOB: 14-MAR-1987, Last visit: 2024-03-14T09:00:00Z", "90[14-MAR-1987]@21"},
	}
	v := NewValidator()
	for _, c := range cases {
		if got := renderMatches(dobMatches(t, v, c.line)); got != c.want {
			t.Errorf("%q: got %s, want %s", c.line, got, c.want)
		}
	}
}

// TestNeverExtractedShapesAreNowLive gives two suppression assertions in
// adversarial_test.go real companions. That file asserts that `"created_at":
// "2024-03-15T10:00:00Z"` and "Version 2024.01.15 released today" give nothing,
// but on main neither value was ever EXTRACTED, so both held whatever the
// negative-keyword and version logic did. Both shapes are extractable now, so
// each refusal is shown here to be the thing that stops a live candidate.
func TestNeverExtractedShapesAreNowLive(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		line, want string
	}{
		// The ISO date-time shape is live...
		{`{"dob": "2024-03-15T10:00:00Z"}`, "90[2024-03-15]@9"},
		// ...and beside a DOB it is the adjacency gate that keeps it out.
		{`{"dob":"1987-03-14","created_at":"2024-03-15T10:00:00Z"}`, "90[1987-03-14]@8"},
		// The dotted year-first shape is live...
		{"dob: 2024.01.15", "90[2024.01.15]@5"},
		// ...and on a version line the version refusal is what stops it.
		{"dob: 2024.01.15 release", "-"},
		{"pip install dob==2024.03.14", "-"},
		{"dob: 2024.03.14 release notes", "-"},
		// The refusal is for '.', which semver and CalVer share; not for '/'.
		{"dob: 2024/01/15 release", "90[2024/01/15]@5"},
	}
	for _, c := range cases {
		if got := renderMatches(dobMatches(t, v, c.line)); got != c.want {
			t.Errorf("%q: got %s, want %s", c.line, got, c.want)
		}
	}
}

// TestLabelStemsCoverEveryAdmittingLabel is what makes the prefilter sound: a
// line can admit a label-adjacent value only through an admitting label, and
// every spelling of every admitting label contains a stem.
func TestLabelStemsCoverEveryAdmittingLabel(t *testing.T) {
	for _, stem := range labelStems {
		if strings.ContainsAny(stem, " \t_-") {
			t.Errorf("stem %q holds a separator; label semantics may drop or change separators, "+
				"so the stem would not survive every spelling", stem)
		}
	}
	for _, label := range admittingLabels {
		covered := false
		for _, word := range strings.Fields(label) {
			for _, stem := range labelStems {
				if strings.Contains(word, stem) {
					covered = true
				}
			}
		}
		if !covered {
			t.Errorf("admitting label %q contains no label stem inside one word, so the prefilter "+
				"would skip lines that hold it", label)
		}
	}
	for _, line := range []string{"DOB", "Date Of Birth", "D.O.B.", "BORN", "BiRtHdAy", `{"patientDob":`} {
		if !hasLabelStem(line) {
			t.Errorf("hasLabelStem(%q) = false", line)
		}
	}
	for _, line := range []string{"", "d.o", "2024-03-14T10:22:01Z INFO request served", "double bird"} {
		if hasLabelStem(line) {
			t.Errorf("hasLabelStem(%q) = true", line)
		}
	}
}

// TestLabelStemPrefilterChangesNoFinding: with the prefilter off, every line of
// the shape table, the label forms and the decoys yields byte-identical
// findings.
func TestLabelStemPrefilterChangesNoFinding(t *testing.T) {
	var lines []string
	for _, sc := range shapeCoverage {
		for _, style := range acceptanceLabelStyles {
			lines = append(lines, fmt.Sprintf(style, sc.value))
		}
		lines = append(lines, fmt.Sprintf("Reference %s recorded.", sc.value),
			fmt.Sprintf("Patient age 39, seen %s", sc.value))
	}
	lines = append(lines,
		"Patient was born on 14 MAR 1987 in Springfield.",
		"birthday: 14 MAR 1987",
		`{"dob": null, "createdAt": "2024-03-14T10:22:01Z"}`,
		"Name: Jane Doe, DOB: 14-MAR-1987, Last visit: 2024-03-14T09:00:00Z",
		"/var/logs/2019/03/14/app.log rotated",
		"2024-03-14T10:22:01Z INFO request served",
	)

	on := NewValidator()
	off := NewValidator()
	off.skipLabelStemPrefilter = true
	for _, line := range lines {
		a, b := renderMatches(dobMatches(t, on, line)), renderMatches(dobMatches(t, off, line))
		if a != b {
			t.Errorf("%q: prefilter on %s, off %s", line, a, b)
		}
	}
}

// TestLabelAdjacentDenseLineTiming guards the label-adjacent path against the
// quadratic shapes the original path already had to remove (see
// TestWorstCaseSingleLineTiming): a ~1MB single line of DISTINCT labelled values
// in every new family. Every value is admitted, so the overlap test and the
// gate run once per value; both must stay per-candidate constant.
func TestLabelAdjacentDenseLineTiming(t *testing.T) {
	months := []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}
	var sb strings.Builder
	for i := 0; sb.Len() < 1<<20; i++ {
		y, m, d := 1900+i%110, 1+(i/110)%12, 1+(i/1320)%28
		switch i % 3 {
		case 0:
			fmt.Fprintf(&sb, `"dob": "%04d-%02d-%02dT00:00:00Z", `, y, m, d)
		case 1:
			fmt.Fprintf(&sb, "DOB: %02d-%s-%04d, ", d, months[m-1], y)
		default:
			fmt.Fprintf(&sb, "dob %04d/%02d/%02d ", y, m, d)
		}
	}
	line := sb.String()

	v := NewValidator()
	start := time.Now()
	matches, err := v.ValidateContent(line, "dense.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	t.Logf("dense label-adjacent line: len=%d bytes, matches=%d, elapsed=%s", len(line), len(matches), elapsed)
	// Non-vacuity: the ceiling below means nothing if the values stop matching.
	if len(matches) < 30000 {
		t.Fatalf("got %d matches on a line of ~40k labelled values; the timing would measure nothing", len(matches))
	}
	if raceEnabled {
		t.Logf("timing assertion skipped under -race")
		return
	}
	const ceiling = 5 * time.Second
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a ~1MB line of labelled values took %s, exceeding %s", elapsed, ceiling)
	}
}
