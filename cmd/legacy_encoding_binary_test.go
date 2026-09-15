// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This drives the REAL BINARY, and for this defect that is not a preference — it is the only
// way to see it.
//
// The redactor package, called directly, ALWAYS preserved the bytes: RedactDocument(src, dst)
// re-reads the file and transcodes correctly, and a unit test on it passes both before and
// after the fix. The corruption lived in the CLI path, because the worker pool prefers
// RedactContent (the EXTRACTED text) over RedactDocument (the file), and extraction had
// already deleted the bytes via strings.ToValidUTF8(content, "").
//
// So a package-level test on the redactor is not merely weaker here, it is BLIND. Measured
// before the fix, on the same input:
//
//	redactor package  "Employee Jos\xe9 Garc\xeda, SSN [SSN-REDACTED]"   bytes preserved
//	real binary       "Employee Jos Garca, SSN [SSN-REDACTED]"           bytes DELETED
//
// buildScanner's own comment records the same lesson from an earlier defect: "a unit test on
// the function passes with the gate wrong. That is exactly how this shipped."

// legacyFixture is cp1252/latin-1 text: four high bytes in ordinary prose, plus an SSN on a
// separate line so redaction genuinely runs and the output file exists.
//
// Written as explicit byte escapes rather than a Go string literal, because a .go file is
// UTF-8 and cannot contain these bytes as themselves — the fixture has to be assembled.
func legacyFixture() []byte {
	return []byte("R\xe9sum\xe9 notes: caf\xe9 receipts and na\xefve estimates.\n" +
		"Employee SSN 219-09-9999 on the W-2 form.\n")
}

// TestBinaryPreservesLegacyBytesOutsideRedactedSpans is the byte-fidelity contract on the
// artifact: everything except the redacted span must survive unchanged.
func TestBinaryPreservesLegacyBytesOutsideRedactedSpans(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildScanner(t)

	for _, strategy := range []string{"simple", "format_preserving", "synthetic"} {
		t.Run(strategy, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "in.txt")
			outDir := filepath.Join(dir, "out")
			original := legacyFixture()
			if err := os.WriteFile(in, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(bin, "--file", in, "--config", os.DevNull, "--checks", "all",
				"--enable-redaction", "--redaction-strategy", strategy,
				"--redaction-output-dir", outDir, "--format", "json", "--limit", "0")
			if out, err := cmd.CombinedOutput(); err != nil {
				// A non-zero exit is not itself a failure here; the artifact is what matters.
				t.Logf("scan exited with %v:\n%s", err, out)
			}

			redacted := findOnlyFile(t, outDir)
			// Non-vacuity: an empty output directory passes a naive byte comparison, and a
			// missing file would make every assertion below trivially true.
			if len(redacted) == 0 {
				t.Fatalf("the redacted artifact is empty, so this test asserts nothing")
			}

			// The first line contains no finding, so it must be byte-identical.
			wantLine1 := bytes.SplitN(original, []byte("\n"), 2)[0]
			gotLine1 := bytes.SplitN(redacted, []byte("\n"), 2)[0]
			if !bytes.Equal(gotLine1, wantLine1) {
				t.Errorf("line 1 was modified even though it holds no finding.\n"+
					"  original: %q\n  redacted: %q\n\n"+
					"Every byte outside a redacted span must survive. Deleting bytes the tool "+
					"could not decode corrupts the user's document while reporting success, and "+
					"it also hides any value containing such a byte from detection.",
					wantLine1, gotLine1)
			}

			// And count them, so a partial loss is caught too.
			wantHigh := countHighBytes(original)
			gotHigh := countHighBytes(redacted)
			if wantHigh == 0 {
				t.Fatal("the fixture has no high bytes; this test cannot detect their loss")
			}
			if gotHigh < wantHigh {
				t.Errorf("%d of %d non-ASCII bytes were lost from the artifact", wantHigh-gotHigh, wantHigh)
			}

			// The SSN must still be gone — fidelity must not have been bought by skipping
			// redaction.
			if bytes.Contains(redacted, []byte("219-09-9999")) {
				t.Errorf("the SSN survived redaction under %s; byte fidelity must not come at the "+
					"cost of the redaction itself", strategy)
			}
		})
	}
}

// TestBinaryDetectsValuesContainingLegacyBytes is the RECALL half, and the more important
// one: the deletion did not only damage the artifact, it hid findings.
//
// Before the fix, "Employee José García" reached the validators as "Employee Jos Garca" and
// was not reported as a PERSON_NAME at all. Under this project's sink rule a value that is
// not reported is not redacted, so the corruption was also a leak.
func TestBinaryDetectsValuesContainingLegacyBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	bin := buildScanner(t)

	dir := t.TempDir()
	in := filepath.Join(dir, "name.txt")
	// "Employee José García, SSN ..." in cp1252.
	if err := os.WriteFile(in,
		[]byte("Employee Jos\xe9 Garc\xeda, SSN 219-09-9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _ := exec.Command(bin, "--file", in, "--config", os.DevNull,
		"--checks", "all", "--format", "json", "--limit", "0").CombinedOutput()

	// The SSN is the control: it is pure ASCII and was always found, so if it is missing the
	// scan itself failed and the PERSON_NAME assertion would be meaningless.
	if !bytes.Contains(out, []byte("SSN")) {
		t.Fatalf("the control finding (SSN) is missing, so this test cannot judge the name:\n%s", out)
	}
	if !bytes.Contains(out, []byte("PERSON_NAME")) {
		t.Errorf("a person's name containing legacy bytes was not reported.\n%s\n\n"+
			"The name reaches the validators through the plaintext extraction path; deleting "+
			"bytes it could not decode turned \"Jos\\xe9 Garc\\xeda\" into \"Jos Garca\", which "+
			"no name pattern matches. A value that is not reported is not redacted.", out)
	}
}

func findOnlyFile(t *testing.T, dir string) []byte {
	t.Helper()
	var found []byte
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		found = b
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if found == nil {
		t.Fatalf("no redacted artifact was written under %s", dir)
	}
	return found
}

func countHighBytes(b []byte) int {
	n := 0
	for _, c := range b {
		if c > 127 {
			n++
		}
	}
	return n
}

// Both INPUT CHANNELS must treat a legacy file the same way.
//
// cmd/stdin.go does not go through the file router, so it never called DetectTextEncoding; it
// coerced with strings.ToValidUTF8(content, "�") under a comment claiming this "match[ed]
// what plaintext_preprocessor does for files". Fixing the file path alone therefore left the
// pipe shape from the tool's own documentation — `cat sensitive.log | ferret-scan --stdin
// --enable-redaction > clean.log` — still destroying every accented byte and still reporting
// one fewer finding, because José García does not match PERSON_NAME once its accents are gone.
//
// The assertion is CHANNEL AGREEMENT rather than a hardcoded count: whatever scanning the file
// by path finds, piping the identical bytes must find too. A count baked in here would go stale
// the first time a validator's scoring moved, and the property worth protecting is not "3
// findings" but "the way you feed the tool does not change what it sees".
//
// Note what that invariant does and does not catch, because it is easy to over-read. On the
// unfixed tool BOTH channels report 2 — the path deletes the accents, stdin replaces them, and
// they agree by being wrong in the same direction. Agreement alone would have passed there. It
// earns its place on the INTERMEDIATE state: with only the file path fixed, path reports 3 and
// stdin still reports 2, which is precisely the half-finished condition this change was in
// before the stdin channel was found. The byte assertions below are what fail on the unfixed
// tool; this one is what fails on a partial fix.
func TestStdinAgreesWithTheFilePathOnALegacyFile(t *testing.T) {
	bin := buildScanner(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "roster.txt")
	// cp1252/latin-1 bytes: é í é ÿ é £ ° ½ ö Ø — every one invalid as UTF-8.
	raw := []byte("Employee Roster\r\n" +
		"Name: Jos\xe9 Garc\xeda   SSN: 449-87-4100\r\n" +
		"Notes: caf\xe9 allowance \xa350, temp \xb020C, \xbd day off\r\n" +
		"Manager: Bj\xf6rn \xd8stergaard\r\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	countFindings := func(t *testing.T, out []byte) int {
		t.Helper()
		var doc struct {
			Results []struct {
				Type string `json:"type"`
			} `json:"results"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			snippet := string(out)
			if len(snippet) > 400 {
				snippet = snippet[:400] + "…"
			}
			t.Fatalf("parsing findings JSON: %v\n%s", err, snippet)
		}
		return len(doc.Results)
	}

	// Scan by path.
	byPath := exec.Command(bin, "--file", path, "--config", os.DevNull,
		"--checks", "all", "--format", "json", "--limit", "0")
	pathOut, err := byPath.Output()
	if err != nil {
		t.Fatalf("scanning by path: %v", err)
	}
	wantN := countFindings(t, pathOut)
	if wantN == 0 {
		t.Fatal("scanning by path found nothing, so channel agreement would be vacuous")
	}

	// Scan the identical bytes on stdin.
	byStdin := exec.Command(bin, "--stdin", "--config", os.DevNull,
		"--checks", "all", "--format", "json", "--limit", "0")
	byStdin.Stdin = bytes.NewReader(raw)
	stdinOut, err := byStdin.Output()
	if err != nil {
		t.Fatalf("scanning stdin: %v", err)
	}
	if gotN := countFindings(t, stdinOut); gotN != wantN {
		t.Errorf("stdin reported %d findings, the same bytes by path reported %d — the input "+
			"channel changed what the scanner can see, which for a legacy file means values "+
			"went unreported and therefore unredacted", gotN, wantN)
	}

	// And the redaction gateway must stream the legacy bytes back, not replacement runes.
	gw := exec.Command(bin, "--stdin", "--config", os.DevNull, "--checks", "all", "--enable-redaction")
	gw.Stdin = bytes.NewReader(raw)
	var clean bytes.Buffer
	gw.Stdout = &clean
	if err := gw.Run(); err != nil {
		// Findings make the exit code non-zero by design; only a missing artifact is fatal.
		if clean.Len() == 0 {
			t.Fatalf("redaction gateway produced no output: %v", err)
		}
	}
	got := clean.Bytes()
	if n := bytes.Count(got, []byte("�")); n > 0 {
		t.Errorf("redacted stdout carries %d U+FFFD replacement runes; the legacy bytes were "+
			"coerced instead of decoded", n)
	}
	for _, frag := range [][]byte{
		[]byte("caf\xe9"), []byte("Bj\xf6rn"), []byte("\xd8stergaard"),
		{0xA3}, {0xB0}, {0xBD},
	} {
		if !bytes.Contains(got, frag) {
			t.Errorf("redacted stdout lost the legacy bytes %q, which hold no finding", frag)
		}
	}
	if bytes.Contains(got, []byte("449-87-4100")) {
		t.Error("redacted stdout still carries the SSN")
	}
}
