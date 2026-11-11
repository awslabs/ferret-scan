// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
)

// The values below use area code 297, which NANPA reserves (N9X) and never assigns, so none is a
// real subscriber; 2166136261 is Go's FNV-32 offset basis.

// onlyPhone scans content and returns its single PHONE finding, failing the test unless there is
// exactly one.
func onlyPhone(t *testing.T, content string) detector.Match {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "evidence.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	if len(matches) != 1 {
		var got []string
		for _, m := range matches {
			got = append(got, m.Text)
		}
		t.Fatalf("ValidateContent(%q): want exactly one PHONE finding, got %d %q", content, len(matches), got)
	}
	return matches[0]
}

// TestBareRunScore pins the reference every "no evidence" case below is compared with: a bare
// ten-digit run that the North American plan can assign scores 100 + 5 (country) - 20 (no
// evidence) = 85.
func TestBareRunScore(t *testing.T) {
	m := onlyPhone(t, "2972030405\n")
	if m.Confidence != 85 {
		t.Fatalf("bare run: confidence %v, want 85", m.Confidence)
	}
	if got := m.Metadata["context_impact"]; got != -20.0 {
		t.Fatalf("bare run: context_impact %v, want -20", got)
	}
}

// TestNoKeywordCreditInsideALongerWord: a positive keyword counts only as a whole word. On main
// each of these lines scored 100 HIGH from a keyword fused into an unrelated word ("string" ->
// "ring", "next" -> "ext", "hotel" -> "tel", "network" -> "work", "homepage" -> "home",
// "worker" -> "work", "callback" -> "call", "cancellation" -> "cell"), or from "number".
func TestNoKeywordCreditInsideALongerWord(t *testing.T) {
	for _, line := range []string{
		"String value 2972030405 parsed",
		"next cursor 2972030405",
		"hotel booking 2972030405",
		"network packets 2972030405",
		"homepage 2972030405",
		"worker 2972030405",
		"callback 2972030405",
		"cancellation 2972030405",
		"Tracking number: 2972030405",
		"Customer number 2972030405",
	} {
		m := onlyPhone(t, line+"\n")
		if m.Confidence != 85 || m.Metadata["context_impact"] != -20.0 {
			t.Errorf("%q: confidence %v, context_impact %v; want 85 and -20, the bare run's score (keywords %q)",
				line, m.Confidence, m.Metadata["context_impact"], m.Context.PositiveKeywords)
		}
	}
}

// TestNoCreditFromTheMatchItself: the digits of a match are never their own evidence. On main the
// "800" keyword fired inside "2972800405", and a bare toll-free run counted its own area code.
func TestNoCreditFromTheMatchItself(t *testing.T) {
	for _, line := range []string{
		"Order 2972800405 shipped on 2024-03-01",
		"8002010001",
		"Reservations 8772010001",
	} {
		if m := onlyPhone(t, line+"\n"); m.Confidence != 85 {
			t.Errorf("%q: confidence %v, want 85 (no evidence)", line, m.Confidence)
		}
	}
	// A FORMATTED toll-free number is its own evidence: the area code is written as one.
	for _, line := range []string{"1-800-201-0001", "(888) 201-0001"} {
		m := onlyPhone(t, line+"\n")
		if m.Confidence < 90 {
			t.Errorf("%q: confidence %v, want HIGH (formatted toll-free area code)", line, m.Confidence)
		}
		if _, capped := m.Metadata["confidence_ceiling"]; capped {
			t.Errorf("%q: a formatted toll-free number is corroborated and must not carry confidence_ceiling", line)
		}
	}
}

// TestKeywordCaseDoesNotChangeTheScore: keywords are matched on the lower-cased line, so a
// sentence-initial capital no longer decides the weight. On main "Employee number" scored 100 and
// "employee number" 85, "Phone: ... (batch)" 78 and "phone: ... (batch)" 85.
func TestKeywordCaseDoesNotChangeTheScore(t *testing.T) {
	for _, pair := range [][2]string{
		{"Employee number 2972030405", "employee number 2972030405"},
		{"Phone: 297-201-0001 (batch)", "phone: 297-201-0001 (batch)"},
		{"SKU 297-201-0001 restocked", "sku 297-201-0001 restocked"},
	} {
		a, b := onlyPhone(t, pair[0]+"\n"), onlyPhone(t, pair[1]+"\n")
		if a.Confidence != b.Confidence {
			t.Errorf("%q scored %v but %q scored %v; case must not change the score",
				pair[0], a.Confidence, pair[1], b.Confidence)
		}
	}
	if m := onlyPhone(t, "Employee number 2972030405\n"); m.Confidence != 50 {
		t.Errorf("Employee number: confidence %v, want 50 (100 + 5 - 20 - 35)", m.Confidence)
	}
	if m := onlyPhone(t, "Phone: 297-201-0001 (batch)\n"); m.Confidence != 85 {
		t.Errorf("Phone: ... (batch): confidence %v, want 85 (100 + 5 + 15 - 35)", m.Confidence)
	}
}

// TestTabAndSpacesScoreAlike: line punctuation is not phone evidence. On main a tab, two commas,
// two semicolons or two pipes added +15, so Go's FNV offset basis scored 100 HIGH after a tab and
// 85 after four spaces.
func TestTabAndSpacesScoreAlike(t *testing.T) {
	tab := onlyPhone(t, "\toffset32 = 2166136261\n")
	sp := onlyPhone(t, "    offset32 = 2166136261\n")
	if tab.Confidence != sp.Confidence || tab.Confidence >= 90 {
		t.Fatalf("tab-indented %v, space-indented %v: want equal and below 90", tab.Confidence, sp.Confidence)
	}
	for _, line := range []string{
		"\tMaxUint32 = 1<<32 - 1 // 4294967295",
		"2024-03-01,2972030405,42.50,USD",
		"seed(a, b, 2972030405)",
		"| 2972030405 | active |",
		"Jane Roe,2972010001,Boston",
	} {
		if m := onlyPhone(t, line+"\n"); m.Confidence != 85 {
			t.Errorf("%q: confidence %v, want 85 (delimiters are not evidence)", line, m.Confidence)
		}
	}
}

// TestNamesNextToANumberAreNotNegative: negative keywords are whole words too. On main "Ricardo"
// carried "card", "Klein" and "Stein" carried "ein", and a phone number beside a name scored 50 or
// 25.
func TestNamesNextToANumberAreNotNegative(t *testing.T) {
	for _, line := range []string{
		"Ricardo 297-201-0001",
		"Ms. Klein 297-201-0001",
		"Reach Ricardo Stein on 297-201-0001 or by email.",
		"Contact Jane Klein at 297-201-0001",
	} {
		if m := onlyPhone(t, line+"\n"); m.Confidence < 60 {
			t.Errorf("%q: confidence %v, want MEDIUM or above (negative keywords %q)", line, m.Confidence, m.Context.NegativeKeywords)
		}
	}
	// A whole negative word still counts, as the full -35.
	if m := onlyPhone(t, "credit card 297-201-0001\n"); m.Confidence >= 60 {
		t.Errorf("credit card: confidence %v, want below 60 (two negative words)", m.Confidence)
	}
}

// TestPhoneWordsAndLabelsAreEvidence: the words, phrases and labels that name a phone raise the
// score; a generic word does so only as the value's label.
func TestPhoneWordsAndLabelsAreEvidence(t *testing.T) {
	for _, line := range []string{
		"Direct line 297-201-0001",
		"Charlotte office: 297-201-0001",
		"Dr. Robinson, cell 297-201-0001",
		"Call anytime: 297-201-0001",
		"SMS sent to 2972010001",
		"Fax 297.201.0001",
		"Emergency contact: 297-201-0001",
		`{"work": "297-201-0001"}`,
	} {
		m := onlyPhone(t, line+"\n")
		if m.Confidence < 90 {
			t.Errorf("%q: confidence %v, want HIGH (evidence %q)", line, m.Confidence, m.Context.PositiveKeywords)
		}
	}
	// "Work" without a colon labels nothing: a bare run's score.
	if m := onlyPhone(t, "Work 297-201-0001\n"); m.Confidence != 85 {
		t.Errorf("Work without a label: confidence %v, want 85", m.Confidence)
	}
}

// TestQuotedPhoneNumberWithEvidence: a whole quoted string is a value like any other, so it passes
// the structural gate when something names it a phone. On main every one of these scored 5 or 40:
// the gate's terminators do not include a closing quote. Without evidence the -100 stays.
func TestQuotedPhoneNumberWithEvidence(t *testing.T) {
	for _, content := range []string{
		`{"phone": "2972010001"}`,
		`phone = '2972010001'`,
		`"mobileNumber": "2972010001",`,
		`{"contact_no": "2972010001"}`,
		`msisdn = '2972010001'`,
		`INSERT INTO t (id, phone) VALUES (7, '2972010001');`,
		"name,phone,city\nJane Roe,\"2972010001\",Boston",
	} {
		if m := onlyPhone(t, content+"\n"); m.Confidence < 60 {
			t.Errorf("%q: confidence %v, want MEDIUM or above", content, m.Confidence)
		}
	}
	for _, content := range []string{`{"order_id": "2972030405"}`, `{"sku": "2972030405"}`} {
		if m := onlyPhone(t, content+"\n"); m.Confidence >= 60 {
			t.Errorf("%q: confidence %v, want below 60 (nothing names it a phone)", content, m.Confidence)
		}
	}
}

// TestColumnHeaderNamesThePhone: in a delimited document the column header is the value's label
// (+15). A header that names something else adds nothing and removes nothing.
func TestColumnHeaderNamesThePhone(t *testing.T) {
	for _, content := range []string{
		"name,phone,city\nJane Roe,2972010001,Boston\n",
		"name,mobileNumber,city\nJane Roe,2972010001,Boston\n",
		"name\ttelephone\tcity\nJane Roe\t(297) 201-0001\tBoston\n",
	} {
		m := onlyPhone(t, content)
		if m.Confidence < 90 || m.Metadata["context_impact"] != 15.0 {
			t.Errorf("%q: confidence %v, context_impact %v; want HIGH and +15 from the header",
				content, m.Confidence, m.Metadata["context_impact"])
		}
	}
	m := onlyPhone(t, "customer,order_id,total\nJane Roe,2972030405,42.50\n")
	if m.Confidence != 85 || m.Metadata["confidence_ceiling"] != 85.0 {
		t.Errorf("order_id column: confidence %v, ceiling %v; want 85 and a published 85",
			m.Confidence, m.Metadata["confidence_ceiling"])
	}
}

// TestUncorroboratedMatchesPublishTheirCeiling: the ceilings are metadata the document bridge reads
// after it adds +20 to a CSV-typed document, so they must be on every finding they bound.
func TestUncorroboratedMatchesPublishTheirCeiling(t *testing.T) {
	cases := []struct {
		content string
		want    any // nil: no ceiling published
	}{
		{"2972030405\n", 85.0},
		{"Reference 197-201-0001 was assigned.\n", 85.0},
		{"name,phone,city\nJane Roe,415-555-0123,Boston\n", 15.0},
		{"Call 415-555-0123\n", 15.0},
		{"Phone: 297-201-0001\n", nil},
		{"+44 161 496 0958\n", nil},
		{"+44 20 7946 0958\n", 15.0}, // Ofcom's London drama block (#930)
	}
	for _, c := range cases {
		m := onlyPhone(t, c.content)
		got, ok := m.Metadata["confidence_ceiling"]
		if c.want == nil {
			if ok {
				t.Errorf("%q: published confidence_ceiling %v, want none", c.content, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("%q: confidence_ceiling = %v, want %v", c.content, got, c.want)
		}
		if ceiling, _ := c.want.(float64); m.Confidence > ceiling {
			t.Errorf("%q: confidence %v above its own ceiling %v", c.content, m.Confidence, ceiling)
		}
	}
}

// TestValidCountryIsThreeState: a ten-digit number the North American plan cannot assign keeps
// its finding but loses the +5, the passed check and the US/CA label, and --explain stops saying it
// passed the country check. On main "197-201-0001" passed with US/CA for having ten digits.
func TestValidCountryIsThreeState(t *testing.T) {
	syn := explain.NewSignalSynthesizer()
	for _, line := range []string{
		"Reference 197-201-0001 was assigned.",
		"Reference (097) 201-0001 was assigned.",
		"Ref 4112010001",
		"EGN: 9001010000",
	} {
		m := onlyPhone(t, line+"\n")
		checks, _ := m.Metadata["validation_checks"].(map[string]bool)
		if checks["valid_country"] {
			t.Errorf("%q: valid_country passed; the North American plan cannot assign it", line)
		}
		if m.Metadata["country"] == "US/CA" {
			t.Errorf("%q: country US/CA for a NANP-impossible number", line)
		}
		if m.Confidence != 80 {
			t.Errorf("%q: confidence %v, want 80 (100 - 20, without the +5)", line, m.Confidence)
		}
		if r := syn.Explain(m).Rationale; strings.Contains(r, "valid country") {
			t.Errorf("%q: --explain says %q", line, r)
		}
	}
	// The control keeps all three.
	m := onlyPhone(t, "Reference 297-201-0001 was assigned.\n")
	checks, _ := m.Metadata["validation_checks"].(map[string]bool)
	if !checks["valid_country"] || m.Metadata["country"] != "US/CA" || m.Confidence != 85 {
		t.Errorf("control: valid_country %v, country %v, confidence %v; want true, US/CA, 85",
			checks["valid_country"], m.Metadata["country"], m.Confidence)
	}
	if r := syn.Explain(m).Rationale; !strings.Contains(r, "valid country") {
		t.Errorf("control: --explain no longer reports the passed country check: %q", r)
	}

}

// TestAnalyzeContextMatchesTheScanningPath: the interface method scores a match the way
// ValidateContent does (without a document, so without a header).
func TestAnalyzeContextMatchesTheScanningPath(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"String value 2972030405 parsed",
		"Phone: 297-201-0001 (batch)",
		"{\"phone\": \"2972010001\"}",
		"Ricardo 297-201-0001",
		"i-2972030405",
	} {
		matches, _ := v.ValidateContent(line, "x.txt")
		for _, m := range matches {
			got := v.AnalyzeContext(m.Text, detector.ContextInfo{FullLine: line})
			if got != m.Metadata["context_impact"] {
				t.Errorf("%q: AnalyzeContext %v, ValidateContent context_impact %v", line, got, m.Metadata["context_impact"])
			}
		}
	}
	if got := v.AnalyzeContext("2972030405", detector.ContextInfo{FullLine: "no match here"}); got != -100 {
		t.Errorf("match not on the line: %v, want -100", got)
	}
}

// TestLongLineScoresLikeAShortOne: the evidence cache is per line on every line length, so a
// match scores the same at the start of a long line as on its own.
func TestLongLineScoresLikeAShortOne(t *testing.T) {
	short := onlyPhone(t, "Direct line 297-201-0001 or Ricardo\n")
	long := "Direct line 297-201-0001 or Ricardo " + strings.Repeat("x", 2*hoistContextLineThreshold) + "\n"
	m := onlyPhone(t, long)
	if m.Confidence != short.Confidence || m.Metadata["context_impact"] != short.Metadata["context_impact"] {
		t.Errorf("long line: confidence %v impact %v; short line: %v %v",
			m.Confidence, m.Metadata["context_impact"], short.Confidence, short.Metadata["context_impact"])
	}
}
