// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This drives the REAL BINARY over a real file, because the defect it guards lived in
// a place no in-memory test can reach.
//
// #659 was in the raw-byte metadata path: a preprocessor takes a 5MB chunk of the
// FILE and cuts a window around marker words. Reaching it requires a file on disk with
// a video extension, so extension dispatch and the preprocessor both run. The
// in-memory guard in pkg/scan sees none of that.
//
// It also cost me a wrong conclusion: the first unit test I wrote for this compared
// the extracted window byte-for-byte and FAILED against the correct fix, because the
// window necessarily contains the padding bytes that differ between the two inputs.
// The binary test was right and the unit test was wrong. buildScanner's comment in
// config_provenance_precommit_test.go records the same lesson from an earlier defect:
// "a unit test on the function passes with the gate wrong. That is exactly how this
// shipped."
//
// The control is byte-length-identical: ASCII 'q' repeated to the same original byte
// count. Removing the hostile run instead would shift every following offset for a
// reason unrelated to case folding, so the comparison would not isolate it.
func TestVideoMetadataWindowSurvivesLengthChangingRunes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildScanner(t)

	// \u escapes, not literals: U+212A is visually identical to an ASCII "K", and a
	// fixture holding the ASCII letter tests nothing. That happened twice while
	// writing these tests, passing both times.
	hostiles := []struct {
		name  string
		s     string
		bytes int
	}{
		{"U+212A KELVIN SIGN (3->1)", "\u212a", 3},
		{"U+0130 CAPITAL I WITH DOT (2->1)", "\u0130", 2},
		{"U+023A (2->3, grows)", "\u023a", 2},
	}

	// "user" is one of the eleven markers the raw-byte path searches for; the SSN sits
	// inside the +/-50 byte window cut around it.
	body := func(pad string) string {
		return "HEADER " + pad + " padding text user metadata SSN 219-09-9999 tail padding more\n"
	}

	countSSN := func(path string) (int, string) {
		out, _ := exec.Command(bin, "--file", path, "--config", os.DevNull,
			"--checks", "all", "--format", "json", "--limit", "0").CombinedOutput()
		i := bytes.IndexByte(out, '{')
		if i < 0 {
			t.Fatalf("no JSON scanning %s:\n%s", filepath.Base(path), out)
		}
		var doc struct {
			Results []struct{ Type string } `json:"results"`
		}
		if err := json.Unmarshal(out[i:], &doc); err != nil {
			t.Fatalf("parsing output for %s: %v", filepath.Base(path), err)
		}
		n := 0
		var types []string
		for _, r := range doc.Results {
			types = append(types, r.Type)
			if r.Type == "SSN" {
				n++
			}
		}
		return n, strings.Join(types, ",")
	}

	for _, h := range hostiles {
		t.Run(h.name, func(t *testing.T) {
			for _, n := range []int{4, 12, 20, 40} {
				dir := t.TempDir()
				hPath := filepath.Join(dir, "hostile.mp4")
				cPath := filepath.Join(dir, "control.mp4")
				hData := []byte(body(strings.Repeat(h.s, n)))
				cData := []byte(body(strings.Repeat("q", h.bytes*n)))
				if len(hData) != len(cData) {
					t.Fatalf("n=%d: hostile %d bytes vs control %d — the comparison would "+
						"attribute an offset shift to folding", n, len(hData), len(cData))
				}
				if err := os.WriteFile(hPath, hData, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cPath, cData, 0o600); err != nil {
					t.Fatal(err)
				}

				// Non-vacuity: the control must find the value, or "hostile matches
				// control" is satisfied by both finding nothing.
				cGot, cTypes := countSSN(cPath)
				if cGot == 0 {
					t.Fatalf("n=%d: the CONTROL found no SSN (types: %s), so this comparison "+
						"cannot detect a loss", n, cTypes)
				}
				hGot, hTypes := countSSN(hPath)
				if hGot != cGot {
					t.Errorf("n=%d (%d bytes, identical to the control): %d SSN finding(s) with "+
						"the hostile run, %d with the ASCII control.\n  control types: %s\n"+
						"  hostile types: %s\n"+
						"The runes are not part of the value, so they must not change what is "+
						"reported. Losing it is a redaction bypass: only reported findings reach "+
						"the redactor.", n, len(hData), hGot, cGot, cTypes, hTypes)
				}
			}
		})
	}
}
