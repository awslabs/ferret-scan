// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tabular

import (
	"reflect"
	"testing"
)

// A two-column CSV is a table when it carries the evidence three columns do not need (#1018):
// header cells that read as column names, three or more rows that all have two fields, and a
// digit in the data. Without the floor relaxing, phone,qty and passport_number,country files got no
// header credit in any validator that reads one.
func TestTwoColumnTables(t *testing.T) {
	cases := []struct {
		name    string
		content string
		headers []string
	}{
		{"phone and qty", "phone,qty\n2972010001,3\n2972010002,4\n2972010003,5\n", []string{"phone", "qty"}},
		{"qty and phone", "qty,phone\n3,2972010001\n4,2972010002\n5,2972010003\n", []string{"qty", "phone"}},
		{"passport column", "passport_number,country\nC1234567K,GB\nR123456KX,GB\n12CF34567,FR\n", []string{"passport_number", "country"}},
		{"tab separated", "id\tphone\n1\t2972010001\n2\t2972010002\n3\t2972010003\n", []string{"id", "phone"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbl := Analyze(c.content)
			if !tbl.IsTable() {
				t.Fatalf("not recognised as a table:\n%s", c.content)
			}
			if got := tbl.Headers(); !reflect.DeepEqual(got, c.headers) {
				t.Fatalf("headers %q, want %q", got, c.headers)
			}
		})
	}
}

// What stays out, and why: each is prose or a list a header would mislabel.
func TestTwoColumnNonTables(t *testing.T) {
	cases := []struct{ name, content string }{
		{"names, no digit", "Smith, John\nDoe, Jane\nRoe, Sam\nLee, Kim\n"},
		{"two data rows only", "phone,qty\n2972010001,3\n2972010002,4\n"},
		{"one data row", "phone,qty\n2972010001,3\n"},
		{"a row with three fields", "phone,qty\n2972010001,3\n2972010002,4\n2972010003,5,x\n"},
		{"digit in the header", "In 2020, 45 people\nleft the room, quietly\nand they, all\nwent home, 2 by 2\n"},
		{"a long header cell", "this header cell has far too many words, qty\n1,2\n3,4\n5,6\n"},
		{"all-word table", "name,city\nJane,Boston\nBob,Austin\nSam,Denver\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if tbl := Analyze(c.content); tbl.IsTable() {
				t.Fatalf("recognised as a table with headers %q:\n%s", tbl.Headers(), c.content)
			}
		})
	}
}

// The column a match is in resolves in a two-column table as it does in a wider one.
func TestTwoColumnHeaderAt(t *testing.T) {
	content := "qty,phone\n3,2972010001\n4,2972010002\n5,2972010003\n"
	tbl := Analyze(content)
	line := "3,2972010001"
	if got := tbl.HeaderAt(tbl.Bounds(line), 2); got != "phone" {
		t.Fatalf("HeaderAt(2) = %q, want phone", got)
	}
	if got := tbl.HeaderAt(tbl.Bounds(line), 0); got != "qty" {
		t.Fatalf("HeaderAt(0) = %q, want qty", got)
	}
}
