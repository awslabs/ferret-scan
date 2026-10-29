// SPDX-License-Identifier: Apache-2.0

package context

import (
	"strings"
	"testing"
)

// Tests for #788: the Configuration share is a property of the content, not of its layout. Until #788
// every share was taken over each element of strings.Split(sample, "\n"), so a trailing newline added
// an empty line to the denominator, comment and blank lines counted against Configuration, and its
// key pattern was anchored at column 0. Every pair below types identically now and typed differently
// on main.

type structure struct {
	typ   string
	share float64
}

func detect(sd *StructureDetector, content string) structure {
	typ, share := sd.DetectStructure(content, "input.txt")
	return structure{typ, share}
}

// TestDetectStructureIgnoresLayout is the issue's list: each content is compared with the same lines
// laid out without the layout under test, and must type the same with the same share. The controls
// at the end pin what the fix leaves alone.
func TestDetectStructureIgnoresLayout(t *testing.T) {
	sd := NewStructureDetector()

	// #785's file A: six credential lines, four of them commented out, two live assignments. With
	// its trailing newline it was 2 of 7 lines (0.286, Unknown); without it 2 of 6 (0.333,
	// Configuration), and the difference was +15 on every secrets candidate in the file.
	fileA := strings.Join([]string{
		";password=v1",
		"    #db_password=v2",
		"#api_key=v3",
		"redirect: https://app.orders.invalid/cb",
		"Server=db.orders.invalid;Password=v4;Encrypt=true",
		";password=v5",
	}, "\n")

	for _, c := range []struct{ name, got, want, wantType string }{
		{"trailing newline", "a=1\nb=2\n", "a=1\nb=2", "Configuration"},
		// The trailing element left every share's denominator, not only Configuration's: two CSV rows
		// were 2 of 7 lines (0.286, Unknown) with the newline and 2 of 6 (CSV, +20) without.
		{"trailing newline, CSV share", "name,email,country\nJane,jane@orders.invalid,US\nnote\nnote\nnote\nnote\n",
			"name,email,country\nJane,jane@orders.invalid,US\nnote\nnote\nnote\nnote", "CSV"},
		{"#785 file A, trailing newline", fileA + "\n", fileA, "Configuration"},
		{"CRLF line endings", "a=1\r\nb=2\r\n", "a=1\nb=2", "Configuration"},
		{"comment lines", "# Database settings\n; rotate quarterly\n// owner: platform\npassword=x\nuser=y\n",
			"password=x\nuser=y", "Configuration"},
		{"commented-out assignments", "#password=x\n    #db_password=y\nuser=z\n", "user=z", "Configuration"},
		{"blank lines", "user=app\n\n\n\n\nhost=db\n\n\n\n\nport=5432\n", "user=app\nhost=db\nport=5432", "Configuration"},
		{"indented INI keys", "[db]\n    host = db.orders.invalid\n    port = 5432\n    password = x\n",
			"[db]\nhost = db.orders.invalid\nport = 5432\npassword = x", "Configuration"},
		{"indented YAML map", "database:\n  host: db\n  port: 5432\n  user: app\n",
			"database:\nhost: db\nport: 5432\nuser: app", "Configuration"},
		{"tab-indented key", "\tpassword = x\n\tuser = y\n", "password = x\nuser = y", "Configuration"},
	} {
		got, want := detect(sd, c.got), detect(sd, c.want)
		if got != want {
			t.Errorf("%s: DetectStructure(%q) = %v, want %v, what %q gives", c.name, c.got, got, want, c.want)
		}
		if got.typ != c.wantType {
			t.Errorf("%s: DetectStructure(%q) types %q, want %q", c.name, c.got, got.typ, c.wantType)
		}
	}

	// Controls. A sample of nothing but comments and blank lines has no structure. Tab-indented
	// source whose blank lines separate its blocks types as it did: the other shares still count blank
	// lines, because the TSV pattern counts indentation tabs and the blank lines are what keep such a
	// file under the threshold (3 of 12 lines here, 3 of 9 without the blank lines).
	for _, c := range []struct{ name, content, wantType string }{
		{"comments and blank lines only", "# just a comment\n\n; another\n// and another\n\n", "Unknown"},
		{"tab-indented source with blank lines", "if ready {\n\t\tstart()\n\t}\n\nif done {\n\t\tstop()\n\t}\n\n" +
			"if late {\n\t\tretry()\n\t}\n\n", "Unknown"},
	} {
		if got := detect(sd, c.content); got.typ != c.wantType {
			t.Errorf("control %s: DetectStructure(%q) = %v, want %s", c.name, c.content, got, c.wantType)
		}
	}
}
