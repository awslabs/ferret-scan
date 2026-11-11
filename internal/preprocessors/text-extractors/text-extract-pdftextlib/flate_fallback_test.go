// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractpdftextlib

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #944: a FlateDecode stream with a corrupt 2-byte zlib header in the cross-reference stream or an
// object stream made the library panic, and the whole document was skipped although its page
// content stream was intact. Measured on main @ 2fb4719 with the issue's generator (ported below):
// xref_good.pdf 1 finding; xref_bad.pdf and objstm_bad.pdf 0 findings and "PDF library panic on
// <file>: zlib: invalid header, so document content was NOT scanned".

const flateFixtureValue = "user00001@example.com"

// flateCorruption says which stream of the fixture is damaged and how.
type flateCorruption int

const (
	corruptNone flateCorruption = iota
	corruptXrefHeader
	corruptObjStmHeader
	corruptXrefBody   // header AND the deflate body: not repairable
	corruptObjStmBody // header AND the deflate body: not repairable
)

// buildObjStmPDF is the issue's synthetic generator: a PDF 1.5 file whose catalog, page tree and
// page live in an object stream (6) indexed by a cross-reference stream (7); the page's content
// stream (4) and font (5) are ordinary objects. Built in memory (TEST_PLAN dimension 12).
func buildObjStmPDF(t *testing.T, c flateCorruption) []byte {
	t.Helper()
	compress := func(b []byte) []byte {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	damage := func(z []byte, body bool) []byte {
		z = append([]byte("XX"), z[2:]...)
		if body {
			for i := 2; i < len(z) && i < 8; i++ {
				z[i] = 0xff
			}
		}
		return z
	}

	content := []byte("BT /F1 24 Tf 72 700 Td (Contact: " + flateFixtureValue + ") Tj ET")
	inner := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
	}
	var hdr, body bytes.Buffer
	for i, obj := range inner {
		fmt.Fprintf(&hdr, "%d %d ", i+1, body.Len())
		body.WriteString(obj + "\n")
	}
	objstm := compress(append(append(hdr.Bytes(), '\n'), body.Bytes()...))
	switch c {
	case corruptObjStmHeader:
		objstm = damage(objstm, false)
	case corruptObjStmBody:
		objstm = damage(objstm, true)
	}

	var out bytes.Buffer
	out.WriteString("%PDF-1.5\n")
	off := map[int]int{}
	add := func(n int, raw []byte) {
		off[n] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", n)
		out.Write(raw)
		out.WriteString("\nendobj\n")
	}
	stream := func(dict string, data []byte) []byte {
		return append(append([]byte(dict+"\nstream\n"), data...), []byte("\nendstream")...)
	}
	cz := compress(content)
	add(4, stream(fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", len(cz)), cz))
	add(5, []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
	add(6, stream(fmt.Sprintf("<< /Type /ObjStm /N 3 /First %d /Length %d /Filter /FlateDecode >>", hdr.Len()+1, len(objstm)), objstm))

	row := func(typ byte, f2 uint32, f3 uint16) []byte {
		b := make([]byte, 7)
		b[0] = typ
		binary.BigEndian.PutUint32(b[1:5], f2)
		binary.BigEndian.PutUint16(b[5:7], f3)
		return b
	}
	var rows bytes.Buffer
	rows.Write(row(0, 0, 65535))
	for n := 1; n <= 3; n++ {
		rows.Write(row(2, 6, uint16(n-1)))
	}
	for _, n := range []int{4, 5, 6} {
		rows.Write(row(1, uint32(off[n]), 0))
	}
	xoff := out.Len()
	rows.Write(row(1, uint32(xoff), 0))
	x := compress(rows.Bytes())
	switch c {
	case corruptXrefHeader:
		x = damage(x, false)
	case corruptXrefBody:
		x = damage(x, true)
	}
	add(7, stream(fmt.Sprintf("<< /Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length %d >>", len(x)), x))
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", xoff)
	return out.Bytes()
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCorruptFlateHeaderInDocumentStreamsIsRecovered is the #944 acceptance: the two damaged files
// yield the same text as the intact one. On main both returned an error and no text.
func TestCorruptFlateHeaderInDocumentStreamsIsRecovered(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    flateCorruption
	}{
		{"xref_good.pdf", corruptNone},
		{"xref_bad.pdf", corruptXrefHeader},
		{"objstm_bad.pdf", corruptObjStmHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractText(writeFixture(t, tc.name, buildObjStmPDF(t, tc.c)))
			if err != nil {
				t.Fatalf("ExtractText: %v (the page content stream is intact, so the document is readable)", err)
			}
			if !strings.Contains(got.Text, flateFixtureValue) {
				t.Errorf("text %q lacks %q", got.Text, flateFixtureValue)
			}
			if got.PageCount != 1 || got.PagesScanned != 1 || got.PagesFailed != 0 {
				t.Errorf("pages count/scanned/failed = %d/%d/%d, want 1/1/0", got.PageCount, got.PagesScanned, got.PagesFailed)
			}
		})
	}
}

// TestUnrepairableDocumentStreamNamesItsCause: where the deflate body is damaged too, nothing can
// be recovered; the call must return (no panic escapes) and the error must say which part of the
// document was unreadable rather than "library panic".
func TestUnrepairableDocumentStreamNamesItsCause(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    flateCorruption
		want string
	}{
		{"xref_body_bad.pdf", corruptXrefBody, "cross-reference section unreadable"},
		{"objstm_body_bad.pdf", corruptObjStmBody, "document catalog or page tree unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractText(writeFixture(t, tc.name, buildObjStmPDF(t, tc.c)))
			if err == nil {
				t.Fatalf("ExtractText succeeded on an unrecoverable file; text %q", got.Text)
			}
			if strings.Contains(err.Error(), "panic") {
				t.Errorf("error %q still says panic; it should name the unreadable part", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
			t.Logf("disclosed cause: %v", err)
		})
	}
}

func TestRepairFlateHeaders(t *testing.T) {
	good := buildObjStmPDF(t, corruptNone)
	for _, tc := range []struct {
		name string
		in   []byte
		want int
		// same reports that the output must equal the input byte for byte.
		same bool
	}{
		{"intact file is untouched", good, 0, true},
		{"xref header repaired", buildObjStmPDF(t, corruptXrefHeader), 1, false},
		{"objstm header repaired", buildObjStmPDF(t, corruptObjStmHeader), 1, false},
		{"non-Flate stream untouched", []byte("1 0 obj\n<< /Length 4 /Filter /DCTDecode >>\nstream\nXXab\nendstream\nendobj\n"), 0, true},
		{"unfiltered stream untouched", []byte("1 0 obj\n<< /Length 4 >>\nstream\nXXab\nendstream\nendobj\n"), 0, true},
		{"Flate second in the array untouched", []byte("1 0 obj\n<< /Length 4 /Filter [/ASCII85Decode /FlateDecode] >>\nstream\nXXab\nendstream\nendobj\n"), 0, true},
		{"Flate first in the array repaired", []byte("1 0 obj\n<< /Length 4 /Filter [ /FlateDecode /ASCII85Decode ] >>\r\nstream\r\nXXab\nendstream\nendobj\n"), 1, false},
		{"unknown filter name untouched", []byte("1 0 obj\n<< /Length 4 /Filter /FlateDecodeX >>\nstream\nXXab\nendstream\nendobj\n"), 0, true},
		{"previous object's filter is not this stream's", []byte("1 0 obj\n<< /Filter /FlateDecode >>\nendobj\n2 0 obj\n<< /Length 4 >>\nstream\nXXab\nendstream\nendobj\n"), 0, true},
		{"keyword without EOL untouched", []byte("1 0 obj\n<< /Filter /FlateDecode >>streamXXab\nendstream\nendobj\n"), 0, true},
		{"a stream-like byte run inside a body untouched", []byte("1 0 obj\n<< /Length 20 /Filter /FlateDecode >>\nstream\nx\x9c>>\nstream\nXXab\nendstream\nendobj\n"), 0, true},
		{"a dictionary longer than a page is still read", []byte("1 0 obj\n<< /Filter /FlateDecode " + strings.Repeat("/K 1 ", 2000) + ">>\nstream\nXXab\nendstream\nendobj\n"), 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), tc.in...)
			if got := repairFlateHeaders(data); got != tc.want {
				t.Errorf("repaired %d, want %d", got, tc.want)
			}
			if len(data) != len(tc.in) {
				t.Fatalf("length changed %d -> %d; offsets would move", len(tc.in), len(data))
			}
			if tc.same != bytes.Equal(data, tc.in) {
				t.Errorf("output equal to input = %v, want %v", !tc.same, tc.same)
			}
		})
	}
}

func TestValidZlibHeader(t *testing.T) {
	for _, h := range [][2]byte{{0x78, 0x9c}, {0x78, 0x01}, {0x78, 0xda}, {0x58, 0x85}} {
		if !validZlibHeader(h[0], h[1]) {
			t.Errorf("%x rejected", h)
		}
	}
	for _, h := range [][2]byte{{'X', 'X'}, {0x78, 0x9d}, {0x88, 0x98}, {0x78, 0xbb}} {
		if validZlibHeader(h[0], h[1]) {
			t.Errorf("%x accepted", h)
		}
	}
}
