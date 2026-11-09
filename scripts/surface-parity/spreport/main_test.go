// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The redaction check counts a value only as a token of its own. The decoy case is the one measured
// on the golden inputs: the reported member ID BEEF1234567 also sits inside 0xDEADBEEF12345678.
func TestContainsTokenIgnoresAValueInsideALongerRun(t *testing.T) {
	for _, tc := range []struct {
		hay, needle string
		want        bool
	}{
		{"cache blob 0xDEADBEEF12345678 evicted", "BEEF1234567", false},
		{"member id: BEEF1234567\n", "BEEF1234567", true},
		{"BEEF1234567", "BEEF1234567", true},
		{"id=BEEF1234567;", "BEEF1234567", true},
		{"xBEEF1234567 and BEEF1234567.", "BEEF1234567", true}, // the second occurrence stands alone
		{"mail me at a.b@example.com!", "a.b@example.com", true},
		{"SSN 449-87-4100 on file", "449-87-4100", true},
		{"SSN 1449-87-41000 on file", "449-87-4100", false},
		{"[SSN-REDACTED]", "449-87-4100", false},
	} {
		if got := containsToken([]byte(tc.hay), []byte(tc.needle), 1); got != tc.want {
			t.Errorf("containsToken(%q, %q) = %v, want %v", tc.hay, tc.needle, got, tc.want)
		}
	}
	// UTF-16LE, as the legacy Office formats store text.
	if !containsToken(utf16LE("id: E1122334455 end"), utf16LE("E1122334455"), 2) {
		t.Error("a UTF-16LE value standing alone was not found")
	}
	if containsToken(utf16LE("idE1122334455x"), utf16LE("E1122334455"), 2) {
		t.Error("a UTF-16LE value glued to letters on both sides was counted")
	}
}

func TestSurvivesSearchesEveryForm(t *testing.T) {
	v := `a<b&c>d@example.com`
	if !survives([][]byte{[]byte("<w:t>a&lt;b&amp;c&gt;d@example.com</w:t>")}, v) {
		t.Error("the XML-escaped form was not found")
	}
	if survives([][]byte{[]byte("<w:t>[EMAIL-REDACTED]</w:t>")}, v) {
		t.Error("a redacted part was reported as keeping the value")
	}
}

// Normalisation removes the set root and the clock, and nothing else.
func TestNormalizeCLIStripsRootsAndClocksOnly(t *testing.T) {
	raw := []byte(`{"stats":{"total_files":1,"duration_seconds":0.5},"results":[
		{"filename":"b.txt","line_number":2,"type":"SSN","text":"x","confidence":100,
		 "metadata":{"source_file":"/home/ferret/in/b.txt","reconstruction_timestamp":"1794061970"}},
		{"filename":"a.txt","line_number":1,"type":"EMAIL","text":"y","confidence":33.5}]}`)
	got, _, err := normalizeCLI(raw, "/home/ferret/in")
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, gone := range []string{"duration_seconds", "/home/ferret/in", "1794061970"} {
		if strings.Contains(s, gone) {
			t.Errorf("normalised output still holds %q:\n%s", gone, s)
		}
	}
	for _, kept := range []string{`"total_files": 1`, `"source_file": "b.txt"`, `"confidence": 33.5`, `"reconstruction_timestamp": "<TIMESTAMP>"`} {
		if !strings.Contains(s, kept) {
			t.Errorf("normalised output lost %q:\n%s", kept, s)
		}
	}
	if strings.Index(s, `"a.txt"`) > strings.Index(s, `"b.txt"`) {
		t.Errorf("results are not in file order:\n%s", s)
	}
}

func TestAllowlistRefusesAnEntryWithoutAnIssue(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "allow.tsv")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := loadAllowlist(write("cli-web\t^a\\.txt\tthe web differs\n")); err == nil {
		t.Error("an entry with no issue reference was accepted")
	}
	if _, err := loadAllowlist(write("cli-container-cli\t^a\tmechanism (#907)\n")); err == nil {
		t.Error("an entry for a pair that must be identical was accepted")
	}
	// The pattern spells the tab between fields as the regular-expression escape \t, because a literal
	// tab ends the field.
	got, err := loadAllowlist(write("# comment\n\ncli-web\t^content/x\\.txt\\tSSN\\t\tmechanism (#907)\n"))
	if err != nil || len(got) != 1 {
		t.Fatalf("a well-formed entry did not load: %v %+v", err, got)
	}
	if !got[0].pattern.MatchString("content/x.txt\tSSN\t3\t100.00") || got[0].pattern.MatchString("content/x.txt\tEMAIL\t3\t100.00") {
		t.Errorf("pattern %q does not select the SSN difference alone", got[0].raw)
	}
}

// The CLI names a finding inside an embedded attachment "<container basename> -> <member>"; /scan
// names it by the upload. Measured on a real .pptx: 58 findings in 14 embedded images.
func TestContainerResolverAttributesMembersToTheirContainer(t *testing.T) {
	resolve := containerResolver([][2]string{
		{"00001", "pptx/deck.pptx"},
		{"00002", "docx/a.docx"},
		{"00003", "other/a.docx"},
		{"00004", "txt/arrow -> in name.txt"},
	})
	for _, tc := range []struct {
		in, want string
		moved    bool
	}{
		{"deck.pptx -> image3.png", "pptx/deck.pptx", true},
		{"pptx/deck.pptx -> image3.png", "pptx/deck.pptx", true},
		{"a.docx -> embedded.doc", "a.docx -> embedded.doc", false}, // two inputs are called a.docx
		{"pptx/deck.pptx", "pptx/deck.pptx", false},
		{"txt/arrow -> in name.txt", "txt/arrow -> in name.txt", false}, // a real file name
	} {
		got, moved := resolve(tc.in)
		if got != tc.want || moved != tc.moved {
			t.Errorf("resolve(%q) = %q, %v; want %q, %v", tc.in, got, moved, tc.want, tc.moved)
		}
	}
}

func TestMultisetDiffCountsDuplicates(t *testing.T) {
	f := finding{rel: "a", typ: "SSN", line: "1", conf: "100.00", sha: "x"}
	g := finding{rel: "a", typ: "SSN", line: "2", conf: "100.00", sha: "y"}
	onlyA, onlyB := multisetDiff([]finding{f, f, g}, []finding{f, g, g})
	if len(onlyA) != 1 || onlyA[0] != f || len(onlyB) != 1 || onlyB[0] != g {
		t.Errorf("onlyA=%v onlyB=%v, want one f and one g", onlyA, onlyB)
	}
}
