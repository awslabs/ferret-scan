// SPDX-License-Identifier: Apache-2.0

package context

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for #849. DetectStructure typed a whole document from its first 2000 characters, and counted
// as a CSV row any line with two commas and as a TSV row any line with two tabs, indentation tabs
// included. CSV, TSV and FixedWidth are tabular_boost, +20 on every finding of every validator in the
// document, so a tab-separated title block gave 800 lines of prose that boost (#787), and so did the
// indentation of Go source and the commas of ordinary prose.

// proseLines returns n lines of prose with no tab and at most one comma a line.
func proseLines(n int) []string {
	base := []string{
		"The planning review covered the roadmap and the hiring plan for the next two quarters.",
		"Each team presented its milestones and the risks it expects to carry into the new year.",
		"The platform group asked for more time to finish the storage migration before launch.",
		"Customer support reported that response times improved after the queue was rebalanced.",
		"We agreed to revisit the budget in March once the first quarter numbers are available.",
		"Several attendees noted that the onboarding checklist still lacks an owner, again.",
	}
	out := make([]string, n)
	for i := range out {
		out[i] = base[i%len(base)]
	}
	return out
}

// commaProseLines returns n lines of paragraph-per-line prose, the shape a document extraction
// produces: six lines in twelve hold two or more commas, and no one count is on more than three.
func commaProseLines(n int) []string {
	base := []string{
		"The quarterly review is scheduled for the second week of the month.",
		"During the review, the team discussed the roadmap, the hiring plan and the budget.",
		"Customer support reported faster responses after the queue was rebalanced, as planned.",
		"If the migration slips, we will move the launch, notify customers, and update the status page.",
		"Nothing in the current plan depends on the vendor contract being renewed early.",
		"Support, sales and marketing all said the new dashboard saves them time.",
		"After the audit, security asked for logging, alerting, retention, and an access review.",
		"The design document is linked from the project page, with its open questions.",
		"Owners for each checklist step, the escalation path, and the rota are now on the wiki.",
		"We compared three options, priced each one, asked two customers, kept notes, and chose the cheapest.",
		"The next readout will cover the results of the pilot in detail.",
		"The pilot ran in two regions, with four teams, for six weeks.",
	}
	out := make([]string, n)
	for i := range out {
		out[i] = base[i%len(base)]
	}
	return out
}

// rows returns n delimited rows of three fields.
func rows(n int, sep string) []string {
	out := []string{strings.Join([]string{"name", "team", "region"}, sep)}
	for i := 1; i < n; i++ {
		out = append(out, strings.Join([]string{"member" + strings.Repeat("x", i%7), "platform", "eu-west"}, sep))
	}
	return out
}

func doc(parts ...[]string) string {
	var all []string
	for _, p := range parts {
		all = append(all, p...)
	}
	return strings.Join(all, "\n") + "\n"
}

// TestDetectStructureTypesTheWholeDocument is the issue's first item: a title block of ten table rows
// types neither a short nor a long prose document, wherever it sits, and a table below a page of prose
// is typed by the table. On main the first four rows typed TSV, CSV, TSV and Unknown.
func TestDetectStructureTypesTheWholeDocument(t *testing.T) {
	sd := NewStructureDetector()
	tsvTitle := rows(10, "\t")
	csvTitle := rows(10, ",")
	for _, c := range []struct{ name, content, want string }{
		// 800 lines (70 KB) is past the every-line bounds, so this is the windowed sample.
		{"TSV title block above 800 prose lines", doc(tsvTitle, proseLines(800)), "Unknown"},
		{"CSV title block above 800 prose lines", doc(csvTitle, proseLines(800)), "Unknown"},
		// 200 lines (17 KB) is inside them: every line.
		{"TSV title block above 200 prose lines", doc(tsvTitle, proseLines(200)), "Unknown"},
		{"a table below a page of prose", doc(proseLines(30), rows(800, "\t")), "TSV"},
		// Controls.
		{"800 prose lines", doc(proseLines(800)), "Unknown"},
		{"TSV title block below 800 prose lines", doc(proseLines(800), tsvTitle), "Unknown"},
		{"an 800-row TSV table", doc(rows(800, "\t")), "TSV"},
		{"an 800-row CSV table", doc(rows(800, ",")), "CSV"},
	} {
		if got, share := sd.DetectStructure(c.content, "readout.txt"); got != c.want {
			t.Errorf("%s: DetectStructure = %s (%.3f), want %s", c.name, got, share, c.want)
		}
	}
}

// tabSource is Go-shaped source with no blank line, every nested line indented by two or more tabs.
const tabSource = "package orders\n" +
	"func (s *Server) handle(req *Request) error {\n" +
	"\tif req == nil {\n" +
	"\t\treturn errNilRequest\n" +
	"\t}\n" +
	"\tfor _, item := range req.Items {\n" +
	"\t\tif item.Count > 0 {\n" +
	"\t\t\ts.total += item.Count\n" +
	"\t\t\tif s.total > s.limit {\n" +
	"\t\t\t\ts.flush()\n" +
	"\t\t\t\ts.total = 0\n" +
	"\t\t\t}\n" +
	"\t\t}\n" +
	"\t}\n" +
	"\treturn nil\n" +
	"}\n"

// TestDelimitedRowsAreFieldsNotLayout is the issue's second item. Indentation tabs are layout and
// separate no fields, and commas are ordinary punctuation, so a CSV table is rows of one field count
// that do not end a sentence. On main the first three rows typed TSV, CSV and CSV.
func TestDelimitedRowsAreFieldsNotLayout(t *testing.T) {
	sd := NewStructureDetector()
	xlsxRows := []string{ // the spreadsheet extractor writes each non-empty cell and a tab
		"Name\tEmail\tPhone\tNotes\t", "Jane\tjane@orders.invalid\t555-0100\t",
		"Bob\tbob@orders.invalid\t555-0101\tnight shift\t", "Amy\tamy@orders.invalid\t",
	}
	// Prose in which one comma count holds most lines: three-item lists. It ends its sentences.
	listProse := doc(strings.Split(strings.Repeat("We reviewed the roadmap, the budget, and the hiring plan.\n"+
		"Support, sales, and marketing joined the call.\n"+
		"The next review is in March.\n", 100), "\n")[:300])
	for _, c := range []struct{ name, content, want string }{
		{"tab-indented source", tabSource, "Unknown"},
		{"prose with two to four commas a line", doc(commaProseLines(400)), "Unknown"},
		{"prose of three-item lists", listProse, "Unknown"},
		// Controls.
		{"the same source indented with spaces", strings.ReplaceAll(tabSource, "\t", "    "), "Unknown"},
		{"a TSV table", doc(rows(40, "\t")), "TSV"},
		{"a CSV table", doc(rows(40, ",")), "CSV"},
		{"a CSV table whose quoted fields hold commas",
			"name,address,country\n\"Doe, Jane\",\"1 Main St, Springfield\",US\n\"Roe, Sam\",\"2 Elm St, Shelbyville\",US\n", "CSV"},
		{"spreadsheet rows of different widths", doc(xlsxRows), "TSV"},
	} {
		if got, share := sd.DetectStructure(c.content, "input.txt"); got != c.want {
			t.Errorf("%s: DetectStructure = %s (%.3f), want %s", c.name, got, share, c.want)
		}
	}

	for line, want := range map[string]bool{
		"Support, sales, and marketing joined the call.": true,
		"Is it done, tested, and released?  ":            true,
		"Jane,jane@orders.invalid,US":                    false,
		"1,Jane,\"Called back.\"":                        false,
		"":                                               false,
	} {
		if got := endsSentence(line); got != want {
			t.Errorf("endsSentence(%q) = %v, want %v", line, got, want)
		}
	}

	for _, c := range []struct {
		line  string
		delim byte
		want  int
	}{
		{"a,b,c", ',', 2},
		{"\"Doe, Jane\",42,NY", ',', 2},
		{"name\temail\tcountry", '\t', 2},
		{"a\tb\t", '\t', 2},
		{"\t\t\ts.total += item.Count", '\t', 0},
		{"\t\tkey\tvalue", '\t', 1},
		// Stated cost: an empty first cell is indistinguishable from indentation.
		{"\tB\tC", '\t', 1},
	} {
		if got := delimiterCount(c.line, c.delim); got != c.want {
			t.Errorf("delimiterCount(%q, %q) = %d, want %d", c.line, c.delim, got, c.want)
		}
	}
}

// TestStructureSampleIsBounded pins the sample's shape: every line of a document inside the bounds
// (less the empty element a trailing newline splits into, #788), and past them structureWindows
// windows of one length that start at the first line and end at the last, with no line longer than
// structureLineBytes.
func TestStructureSampleIsBounded(t *testing.T) {
	small := doc(proseLines(50))
	if got := structureSample(small); len(got) != 50 || got[49] != proseLines(50)[49] {
		t.Errorf("a 50-line document samples %d lines, want all 50", len(got))
	}

	numbered := make([]string, 100000)
	for i := range numbered {
		numbered[i] = "line " + strings.Repeat("x", i%40)
	}
	numbered[0], numbered[len(numbered)-1] = "first", "last"
	got := structureSample(doc(numbered))
	if len(got) > structureSampleLines || len(got)%structureWindows != 0 {
		t.Errorf("a 100,000-line document samples %d lines, want at most %d in %d equal windows",
			len(got), structureSampleLines, structureWindows)
	}
	if got[0] != "first" || got[len(got)-1] != "last" {
		t.Errorf("the windows run from %q to %q, want the first line to the last", got[0], got[len(got)-1])
	}

	long := doc(strings.Split(strings.Repeat(strings.Repeat("field, ", 400)+"\n", 3000), "\n")[:3000])
	got = structureSample(long)
	if len(got) < structureWindows {
		t.Errorf("a document of 2,800-byte lines samples %d lines, want at least one per window", len(got))
	}
	for _, line := range got {
		if len(line) > structureLineBytes {
			t.Fatalf("a sampled line is %d bytes, want at most %d", len(line), structureLineBytes)
		}
	}
}

// TestStructurePrefiltersAreNecessaryConditions proves the cheap test in front of each pattern moves
// no share: on every ASCII line of a corpus where the test says no, the pattern does not match. The
// corpus is this package's own source plus seeded random lines built from every pattern's literals in
// mixed case, beside separators, digits and whitespace runs. A non-ASCII line skips the test, and the
// last check shows why: `ſ` folds to `s` under `(?i)`, and its line still types Report.
func TestStructurePrefiltersAreNecessaryConditions(t *testing.T) {
	var corpus []string
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		corpus = append(corpus, strings.Split(string(b), "\n")...)
	}
	frags := []string{
		"select", "SeLeCt", "insert", "UPDATE", "delete", "Create", "alter", "DROP", "selected", "_drop",
		"from:", "FROM :", "to:", "To:", "subject:", "Date:", "date :",
		"function", "Class", "IMPORT", "include", "def ", "def\t", "def", "Def\n",
		"report", "SUMMARY", "subtotal", "Total", "balance",
		"<", ">", "<?xml", "<a href>", "< b>", "=", ":", "-", ";", "{", "}", "[", "]",
		"2026-01-02 03:04:05", "2026-01-02T03:04:05", "2026-1-2 3:4:5",
		"   ", "\t\t\t", " ", "\t", "\f", "\r", "  ", "word", "a_key", "x1", "Value", strings.Repeat("y", 25),
	}
	rng := rand.New(rand.NewSource(849))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := 1 + rng.Intn(12); n > 0; n-- {
			b.WriteString(frags[rng.Intn(len(frags))])
		}
		corpus = append(corpus, b.String())
	}

	sd := NewStructureDetector()
	checked := 0
	for _, line := range corpus {
		lower, ascii := lowerASCII(line)
		if !ascii {
			continue
		}
		for name, p := range sd.patterns {
			if p.may == nil || p.may(line, lower) {
				continue
			}
			checked++
			if p.re.MatchString(line) {
				t.Errorf("%s: the cheap test rejects %q, which the pattern matches", name, line)
			}
		}
	}
	if checked < 10000 {
		t.Fatalf("only %d rejections checked; the corpus no longer exercises the tests", checked)
	}
	t.Logf("%d rejections checked over %d lines", checked, len(corpus))

	if _, ascii := lowerASCII("ſummary"); ascii {
		t.Fatal(`lowerASCII("ſummary") reports ASCII`)
	}
	if got, _ := sd.DetectStructure("ſummary of the quarter\nſummary of the year\n", "notes.txt"); got != "Report" {
		t.Errorf("a line spelling summary with U+017F types %s, want Report as the pattern alone gives", got)
	}
}
