// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package video

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// tailMoovMP4 writes a file with the moov AFTER a large mdat — the layout ffmpeg and every camera
// produce by default.
//
// Every other fixture in this package writes moov FIRST, which is the faststart layout that a
// second ffmpeg pass produces and that nothing writes by accident. A write side tested only against
// the easy layout could grow an assumption about it without anything failing.
//
// The mdat is a hole made with Truncate, so a 12MB fixture costs no test memory and, on a sparse
// filesystem, no disk. Its bytes are never read by the walk, which is what makes that affordable.
func tailMoovMP4(t *testing.T, dir, filename string, mdatBytes int64, udtaChildren ...[]byte) string {
	t.Helper()

	ftyp := atom("ftyp", []byte("isomiso2mp41"))
	moov := atom("moov", atom("mvhd", make([]byte, 100)), atom("udta", udtaChildren...))

	mdatHeader := make([]byte, 8)
	binary.BigEndian.PutUint32(mdatHeader[0:4], uint32(8+mdatBytes))
	copy(mdatHeader[4:8], "mdat")

	p := filepath.Join(dir, filename)
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create %s: %v", filename, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close %s: %v", filename, err)
		}
	}()

	for _, b := range [][]byte{ftyp, mdatHeader} {
		if _, err := f.Write(b); err != nil {
			t.Fatalf("write %s: %v", filename, err)
		}
	}
	end := int64(len(ftyp) + len(mdatHeader))
	if err := f.Truncate(end + mdatBytes); err != nil {
		t.Fatalf("truncate %s: %v", filename, err)
	}
	if _, err := f.WriteAt(moov, end+mdatBytes); err != nil {
		t.Fatalf("write moov in %s: %v", filename, err)
	}
	return p
}

// A value in a moov that sits past the old 10MB read bound must still be redactable.
//
// The detection side stopped walking at a 10MB file offset, so a value beyond it was never reported
// and this path was never exercised (#398). Now that those findings are reported, the write side has
// to reach them — a reported finding in a file the redactor cannot touch would be a worse outcome
// than the original silence, because the run would claim success.
//
// The walk here has no positional bound and reads only atom headers, so this holds at any offset; the
// fixture is 12MB purely because that is just past where detection used to give up.
func TestTailMoovValueBeyondTenMegabytesIsRedactable(t *testing.T) {
	dir := t.TempDir()
	const mdatBytes = 12 << 20

	src := tailMoovMP4(t, dir, "tail.mp4", mdatBytes,
		atom("meta", []byte{0, 0, 0, 0}, atom("ilst",
			itunesTag("\xa9cmt", "Employee SSN "+testSSN),
			itunesTag("\xa9ART", testName))))

	info, err := os.Stat(src)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() < mdatBytes {
		t.Fatalf("fixture is %d bytes, expected at least %d", info.Size(), mdatBytes)
	}

	out, res, err := redact(t, src, []detector.Match{match("SSN", testSSN), match("PERSON_NAME", testName)})
	if err != nil {
		t.Fatalf("RedactDocument on a tail-moov file: %v", err)
	}
	if !res.Success {
		t.Fatalf("result = %+v, want success: the walk did not reach a moov past 10MB", res)
	}

	before, after := mustRead(t, src), mustRead(t, out)
	if len(before) != len(after) {
		t.Fatalf("size changed from %d to %d", len(before), len(after))
	}
	for _, v := range []string{testSSN, testName} {
		if bytes.Contains(after, []byte(v)) {
			t.Errorf("%q survives in the redacted copy of a tail-moov file, and the run reported "+
				"success — a reported value that is not removed is the leak this whole path exists "+
				"to prevent", v)
		}
	}
	if len(res.RedactionMap) != 2 {
		t.Errorf("RedactionMap has %d entries, want 2", len(res.RedactionMap))
	}

	// The change must be confined to the metadata at the END of the file. Anything written inside
	// the mdat region would corrupt the media while the container still parses.
	firstDiff := -1
	for i := range before {
		if before[i] != after[i] {
			firstDiff = i
			break
		}
	}
	if firstDiff < 0 {
		t.Fatal("no bytes changed at all, so the assertions above are vacuous")
	}
	if int64(firstDiff) < mdatBytes {
		t.Errorf("the first changed byte is at offset %d, inside the %d-byte media region: the "+
			"redactor is writing over the payload, not the trailing metadata", firstDiff, int64(mdatBytes))
	}
}
