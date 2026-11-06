// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// emissionSnapshot is the set of findings (line, text) main reported on emissionCorpus, captured
// from main before the scoring change of #882 and committed. It is the reference for
// TestReportedSetIsUnchangedByScoring; regenerate it only from a main checkout, with
// PHONE_EMISSION_SNAPSHOT_UPDATE=1, never from a branch, or the test compares a branch with itself.
const emissionSnapshot = "testdata/emission_main.txt"

// emissionCorpus is built to sit on the emission boundary. Its values score low before context
// (timestamp-shaped, mostly-zero, sequential and repeated runs, NANP-impossible and reserved
// numbers), and its carriers are the words on which the old and the new keyword arithmetic disagree:
// a keyword in Title case or capitals, inside a longer word ("latest", "String", "Ricardo",
// "network"), a whole negative word, a quoted value, a delimiter-rich line. Where the two disagree
// in sign on a low base, scoring with the new arithmetic would change which matches are reported,
// which is exactly what this test forbids.
func emissionCorpus() string {
	values := []string{
		"1234567890", "1700000000", "2024030112", "1999123199", "2022872112", "1000000000",
		"0000123456", "0012345678", "0020240301", "4111111111", "1112223333", "2972030405",
		"2166136261", "9001010000", "00421337", "0044207946", "197-201-0001", "(097) 201-0001",
		"212-555-0142", "297-201-0001", "555-123-4567", "1-800-201-0001", "+1234567891011",
		"+12972010001",
	}
	carriers := []string{
		"%s", "latest %s", "Test %s", "TEST %s", "test %s", "Example %s", "examples %s",
		"String %s", "Phone %s", "phone %s", "PHONE: %s", "\t%s", "a,b,%s", "x | %s | y",
		`"%s"`, `{"phone": "%s"}`, `{"id": "%s"}`, `phone = '%s'`, "Ricardo %s", "SKU %s",
		"sku %s", "timestamp %s", "build %s", "version: %s", "card %s", "Card %s",
		"Employee %s", "employee number %s", "Ricardo Stein %s", "network %s", "hotel %s",
		"Call %s", "call %s", "credit card %s", "Credit Card %s", "Test Example %s",
		"mock data %s", "Mock %s", "the latest example %s", "samples %s", "Sample %s",
		"Order %s shipped on 2024-03-01", "seed(a, b, %s)", "2024-03-01,%s,42.50,USD",
	}
	var b strings.Builder
	for _, c := range carriers {
		for _, v := range values {
			b.WriteString(fmt.Sprintf(c, v))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// reportedSet renders the findings as sorted "line<TAB>text" rows: what decides redaction.
// Confidence is deliberately absent; it is what #882 moves.
func reportedSet(t *testing.T, content string) []string {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "emission.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	rows := make([]string, 0, len(matches))
	for _, m := range matches {
		rows = append(rows, fmt.Sprintf("%d\t%s", m.LineNumber, m.Text))
	}
	sort.Strings(rows)
	return rows
}

// TestReportedSetIsUnchangedByScoring: #882 changes what a PHONE finding scores, never whether it is
// reported. Redaction rewrites every reported finding whatever its confidence, so the reported set
// is what decides the redacted bytes; this compares it, row for row, with the set main reported on
// the same corpus.
func TestReportedSetIsUnchangedByScoring(t *testing.T) {
	got := reportedSet(t, emissionCorpus())
	path := filepath.FromSlash(emissionSnapshot)
	if os.Getenv("PHONE_EMISSION_SNAPSHOT_UPDATE") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.Join(got, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d rows to %s", len(got), path)
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	want := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	inWant := make(map[string]int, len(want))
	for _, r := range want {
		inWant[r]++
	}
	inGot := make(map[string]int, len(got))
	for _, r := range got {
		inGot[r]++
	}
	var added, lost []string
	for r, n := range inGot {
		for ; n > inWant[r]; n-- {
			added = append(added, r)
		}
	}
	for r, n := range inWant {
		for ; n > inGot[r]; n-- {
			lost = append(lost, r)
		}
	}
	sort.Strings(added)
	sort.Strings(lost)
	if len(added) > 0 || len(lost) > 0 {
		t.Fatalf("the reported set moved: %d findings main did not report, %d main reported are gone "+
			"(a lost finding is left in cleartext by redaction)\nadded: %q\nlost: %q",
			len(added), len(lost), added, lost)
	}
	if len(got) < 500 {
		t.Fatalf("only %d findings: the corpus no longer exercises the boundary it was built for", len(got))
	}
}
