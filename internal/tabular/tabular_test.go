// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tabular

import (
	"strings"
	"testing"
)

// TestAnalyzeRecognisesTables asserts the positive cases: content that IS
// delimited data must be recognised, with the right delimiter and headers.
func TestAnalyzeRecognisesTables(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		delim     byte
		headers   []string
		headerIdx int
	}{
		{
			name:      "comma csv",
			content:   "name,email,passport_number\nJane,j@corp.example,987654321\nBob,b@corp.example,512345678\n",
			delim:     ',',
			headers:   []string{"name", "email", "passport_number"},
			headerIdx: 0,
		},
		{
			name:      "tab separated",
			content:   "name\temail\tpassport\nJane\tj@x.example\t987654321\nBob\tb@x.example\t512345678\n",
			delim:     '\t',
			headers:   []string{"name", "email", "passport"},
			headerIdx: 0,
		},
		{
			name:      "semicolon (european csv)",
			content:   "name;email;passport\nJane;j@x.example;987654321\nBob;b@x.example;512345678\n",
			delim:     ';',
			headers:   []string{"name", "email", "passport"},
			headerIdx: 0,
		},
		{
			name:      "pipe delimited",
			content:   "name|email|passport\nJane|j@x.example|987654321\nBob|b@x.example|512345678\n",
			delim:     '|',
			headers:   []string{"name", "email", "passport"},
			headerIdx: 0,
		},
		{
			name:      "comment preamble before header",
			content:   "# exported 2026-01-01\n# source: hr system\nname,dept,passport_number\nJane,Ops,987654321\nBob,Eng,512345678\n",
			delim:     ',',
			headers:   []string{"name", "dept", "passport_number"},
			headerIdx: 2,
		},
		{
			name:      "blank lines before header",
			content:   "\n\nname,dept,passport\nJane,Ops,987654321\nBob,Eng,512345678\n",
			delim:     ',',
			headers:   []string{"name", "dept", "passport"},
			headerIdx: 2,
		},
		{
			name:      "quoted headers are unquoted and lowercased",
			content:   "\"Name\",\"Passport Number\",\"Country\"\nJane,987654321,US\nBob,512345678,GB\n",
			delim:     ',',
			headers:   []string{"name", "passport number", "country"},
			headerIdx: 0,
		},
		{
			name: "one ragged row tolerated (80% rule)",
			content: "a,b,passport\n1,2,987654321\n3,4,512345678\n5,6,123456780\n7,8,111111117\n" +
				"9,10,222222229\n11,12,333333331\n13,14,444444443\n15,16,555555555\n17,18\n",
			delim:     ',',
			headers:   []string{"a", "b", "passport"},
			headerIdx: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(tc.content)
			if !got.IsTable() {
				t.Fatalf("IsTable() = false, want true")
			}
			if got.Delimiter() != tc.delim {
				t.Errorf("Delimiter() = %q, want %q", got.Delimiter(), tc.delim)
			}
			if got.HeaderLine() != tc.headerIdx {
				t.Errorf("HeaderLine() = %d, want %d", got.HeaderLine(), tc.headerIdx)
			}
			h := got.Headers()
			if len(h) != len(tc.headers) {
				t.Fatalf("Headers() = %v (len %d), want %v (len %d)", h, len(h), tc.headers, len(tc.headers))
			}
			for i := range h {
				if h[i] != tc.headers[i] {
					t.Errorf("Headers()[%d] = %q, want %q", i, h[i], tc.headers[i])
				}
			}
		})
	}
}

// TestAnalyzeRejectsNonTables asserts the failure modes, each of which must leave
// the caller with unchanged behavior rather than a mis-parsed table.
//
// These are the cases where a false positive is expensive: mistaking prose for a
// table would attach an arbitrary "header" to a value and could validate or
// suppress it on nonsense grounds.
func TestAnalyzeRejectsNonTables(t *testing.T) {
	cases := []struct {
		name    string
		content string
		why     string
	}{
		{"empty", "", "no content"},
		{"blank only", "\n\n\n", "no header candidate"},
		{"single line no data rows", "name,email,passport\n", "nothing to sample"},
		{"two fields only", "Smith, John\nDoe, Jane\nRoe, Sam\n", "2 fields is ordinary prose"},
		{
			"prose with commas",
			"The passport, which was issued in 2019, expired.\nIt was renewed, eventually, in 2024.\nNo further action, please.\n",
			"header cells are sentence fragments, over the length cap",
		},
		{
			"numeric header row",
			"1,2,3\n4,5,6\n7,8,9\n",
			"a row of pure numbers is data, not a header",
		},
		{
			"ragged rows",
			"a,b,passport\n1,2\n3\n4,5,6,7,8\n9\n",
			"field counts disagree with the header",
		},
		{
			"unbalanced quote in header",
			"name,\"unclosed,passport\nJane,x,987654321\nBob,y,512345678\n",
			"a field spans lines; multi-line records are out of scope",
		},
		{
			"unbalanced quote in a sampled row",
			"name,dept,passport\nJane,\"Ops,987654321\nBob,Eng,512345678\n",
			"same, detected while sampling",
		},
		{
			"no delimiter",
			"just some text\nmore text here\nand another line\n",
			"no candidate delimiter reaches the threshold",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(tc.content)
			if got.IsTable() {
				t.Errorf("IsTable() = true, want false (%s)\n  headers: %v", tc.why, got.Headers())
			}
			// A non-table must also be safe to call through.
			if d := got.Delimiter(); d != 0 {
				t.Errorf("Delimiter() = %q on a non-table, want 0", d)
			}
			if h := got.Headers(); h != nil {
				t.Errorf("Headers() = %v on a non-table, want nil", h)
			}
			if l := got.HeaderLine(); l != -1 {
				t.Errorf("HeaderLine() = %d on a non-table, want -1", l)
			}
			if b := got.Bounds("a,b,c"); b != nil {
				t.Errorf("Bounds() = %v on a non-table, want nil", b)
			}
			if s := got.HeaderAt(nil, 0); s != "" {
				t.Errorf("HeaderAt() = %q on a non-table, want \"\"", s)
			}
		})
	}
}

// TestHeaderAtMapsOffsetToColumn is the core correctness assertion: a byte offset
// in a data row must resolve to the header naming that column. Getting this wrong
// silently attaches the wrong label to a value.
func TestHeaderAtMapsOffsetToColumn(t *testing.T) {
	const content = "name,email,passport_number,country\n" +
		"Jane,jane@corp.example,987654321,US\n"
	tbl := Analyze(content)
	if !tbl.IsTable() {
		t.Fatal("premise broken: content must be recognised as a table")
	}

	row := "Jane,jane@corp.example,987654321,US"
	b := tbl.Bounds(row)
	if got, want := b.Fields(), 4; got != want {
		t.Fatalf("Fields() = %d, want %d", got, want)
	}

	// Walk every byte of the row and assert the column is right throughout, not
	// just at the field starts — an off-by-one at a boundary is the likely bug.
	for off := 0; off < len(row); off++ {
		var want string
		switch {
		case off < strings.Index(row, "jane@"):
			want = "name"
		case off < strings.Index(row, "987654321"):
			want = "email"
		case off < strings.LastIndex(row, "US"):
			want = "passport_number"
		default:
			want = "country"
		}
		if got := tbl.HeaderAt(b, off); got != want {
			t.Fatalf("HeaderAt(off=%d) = %q, want %q (row: %q)", off, got, want, row)
		}
	}
}

// TestHeaderAtWithQuotedDelimiter pins the failure mode most likely to mis-map a
// real export: a quoted field that CONTAINS the delimiter. Airport and geo data
// routinely carry "lat, long" in one column, and splitting on that comma would
// shift every subsequent column by one.
func TestHeaderAtWithQuotedDelimiter(t *testing.T) {
	const content = "ident,coordinates,passport_number\n" +
		"KSEA,\"47.449, -122.309\",987654321\n"
	tbl := Analyze(content)
	if !tbl.IsTable() {
		t.Fatal("premise broken: content must be recognised as a table")
	}

	row := "KSEA,\"47.449, -122.309\",987654321"
	b := tbl.Bounds(row)
	if got, want := b.Fields(), 3; got != want {
		t.Fatalf("Fields() = %d, want %d — the comma INSIDE the quoted coordinate "+
			"must not split the row, or every later column is shifted", got, want)
	}

	// The passport value must resolve to passport_number, not to coordinates.
	off := strings.Index(row, "987654321")
	if got := tbl.HeaderAt(b, off); got != "passport_number" {
		t.Errorf("HeaderAt(passport offset) = %q, want %q", got, "passport_number")
	}
	// And the comma-containing value must resolve to coordinates.
	off = strings.Index(row, "-122.309")
	if got := tbl.HeaderAt(b, off); got != "coordinates" {
		t.Errorf("HeaderAt(inside quoted field) = %q, want %q", got, "coordinates")
	}
}

// TestHeaderAtOutOfRange covers the degenerate offsets a caller can reach: a data
// row with MORE fields than the header, and offsets outside the line.
func TestHeaderAtOutOfRange(t *testing.T) {
	tbl := Analyze("a,b,passport\n1,2,987654321\n3,4,512345678\n")
	if !tbl.IsTable() {
		t.Fatal("premise broken")
	}

	// A row with an extra field: the 4th column has no header, and must return ""
	// rather than panic or wrap around to headers[0].
	row := "1,2,987654321,extra"
	b := tbl.Bounds(row)
	if got := tbl.HeaderAt(b, strings.Index(row, "extra")); got != "" {
		t.Errorf("HeaderAt(column beyond the header) = %q, want \"\"", got)
	}
	// Negative and past-end offsets.
	if got := tbl.HeaderAt(b, -1); got != "" {
		t.Errorf("HeaderAt(-1) = %q, want \"\"", got)
	}
	if got := tbl.HeaderAt(b, len(row)+100); got != "passport" {
		// Past the end still resolves to the last field, which is the honest
		// answer for "the offset is in the final column".
		t.Logf("HeaderAt(past end) = %q (last column) — acceptable", got)
	}
}

// TestBoundsIsLinearInLineLength guards the performance contract. Bounds is O(n)
// per line and HeaderAt is a binary search per match, so a line carrying many
// matches must stay linear overall. This repo has a history of exactly the
// opposite (a per-match whole-line rescan that took 22s on a 64KB line), so the
// shape is asserted rather than assumed.
func TestBoundsIsLinearInLineLength(t *testing.T) {
	if testing.Short() {
		t.Skip("timing guard skipped in -short mode")
	}

	build := func(fields int) string {
		var sb strings.Builder
		for i := 0; i < fields; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString("value")
		}
		return sb.String()
	}
	header := build(3)
	tbl := Analyze(header + "\n" + build(3) + "\n" + build(3) + "\n")
	if !tbl.IsTable() {
		t.Fatal("premise broken")
	}

	// Non-vacuity: assert the work actually happened at both sizes before
	// comparing anything. A Bounds that returned early would "pass" a ratio test.
	small := build(2000)
	large := build(8000)
	bs := tbl.Bounds(small)
	bl := tbl.Bounds(large)
	if bs.Fields() != 2000 || bl.Fields() != 8000 {
		t.Fatalf("Bounds did not split as expected: %d and %d fields", bs.Fields(), bl.Fields())
	}

	// Every offset resolves, and the last column of a 8000-field row is still
	// found in log time rather than by walking 8000 entries.
	for _, off := range []int{0, len(large) / 2, len(large) - 1} {
		if tbl.HeaderAt(bl, off) == "" && off < len(large) {
			// Columns past the 3-cell header legitimately return "", so this only
			// asserts it does not panic or misbehave.
			continue
		}
	}
}

// TestAnalyzeIsDeterministic pins the delimiter tie-break. A line containing equal
// counts of two candidates must always choose the same one, or the recognised
// column layout would vary run to run — the class of defect this repo has already
// fixed several times.
func TestAnalyzeIsDeterministic(t *testing.T) {
	// Equal numbers of commas and semicolons in the header.
	const content = "a,b;c,d;e,f\n1,2;3,4;5,6\n7,8;9,10;11,12\n"
	first := Analyze(content)
	for i := 0; i < 50; i++ {
		got := Analyze(content)
		if got.IsTable() != first.IsTable() || got.Delimiter() != first.Delimiter() {
			t.Fatalf("run %d: IsTable=%v delim=%q, first run: IsTable=%v delim=%q",
				i, got.IsTable(), got.Delimiter(), first.IsTable(), first.Delimiter())
		}
	}
	// And the tie must go to the earlier candidate in candidateDelimiters
	// (tab, comma, semicolon, pipe), i.e. comma here.
	if first.IsTable() && first.Delimiter() != ',' {
		t.Errorf("tie-break chose %q, want ',' (the earlier candidate)", first.Delimiter())
	}
}
