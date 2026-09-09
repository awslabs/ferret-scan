// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import "testing"

// TestNormalizePaths_CrossPlatform locks the cross-OS behavior of NormalizePaths.
// The golden file-mode snapshots are generated on one OS (Unix, `/` separators)
// but the test suite runs on Windows in CI too — where Match.Filename carries `\`
// separators (and `\\` inside JSON string values). NormalizePaths must collapse
// all of these to the same "<TMPDIR>/<basename>" form so the committed snapshots
// match on every platform. This is a regression test for the Windows CI failure
// where file-mode goldens diverged.
func TestNormalizePaths_CrossPlatform(t *testing.T) {
	cases := []struct {
		name   string
		tmpDir string
		input  string
		want   string
	}{
		{
			name:   "unix raw path",
			tmpDir: "/var/folders/xx/T/TestX/001",
			input:  "match in /var/folders/xx/T/TestX/001/notes.txt here",
			want:   "match in <TMPDIR>/notes.txt here",
		},
		{
			name:   "windows raw path (backslash)",
			tmpDir: `C:\Users\ci\AppData\Local\Temp\TestX001`,
			input:  `match in C:\Users\ci\AppData\Local\Temp\TestX001\notes.txt here`,
			want:   "match in <TMPDIR>/notes.txt here",
		},
		{
			name:   "windows JSON-escaped path (double backslash)",
			tmpDir: `C:\Users\ci\Temp\TestX001`,
			input:  `"filename": "C:\\Users\\ci\\Temp\\TestX001\\notes.txt"`,
			want:   `"filename": "<TMPDIR>/notes.txt"`,
		},
		{
			name:   "unix path inside JSON value",
			tmpDir: "/tmp/TestX001",
			input:  `"source_file": "/tmp/TestX001/people.csv"`,
			want:   `"source_file": "<TMPDIR>/people.csv"`,
		},
		{
			name:   "empty tmpDir is a no-op",
			tmpDir: "",
			input:  "unchanged content",
			want:   "unchanged content",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NormalizePaths(c.input, c.tmpDir)
			if got != c.want {
				t.Errorf("NormalizePaths mismatch:\n  tmpDir: %q\n  input:  %q\n  got:    %q\n  want:   %q", c.tmpDir, c.input, got, c.want)
			}
		})
	}
}

// TestFileURIsNormalizeIdenticallyOnEveryPlatform pins the convergence that keeps SARIF snapshots
// platform-independent.
//
// The temp dir is spelled differently on the two platforms in a way that survives separator
// normalization: a POSIX temp dir INCLUDES its leading slash, so `file:///private/var/x/n.txt`
// collapses to `file://<TMPDIR>/n.txt` — two slashes, the third absorbed into the sentinel — while a
// Windows temp dir does not, so the same correct URI `file:///C:/Users/x/n.txt` collapses to
// `file:///<TMPDIR>/n.txt` — three.
//
// Measured before the canonicalisation, all three spellings:
//
//	posix                 -> "uri": "file://<TMPDIR>/notes.txt"
//	windows native        -> "uri": "file:///<TMPDIR>/notes.txt"
//	windows json-escaped  -> "uri": "file:///<TMPDIR>/notes.txt"
//
// That difference is an artefact of what the sentinel swallowed, and left alone it makes every SARIF
// snapshot platform-specific. It broke windows-latest on 18 golden subtests the moment the SARIF writer
// started emitting the RFC 8089 three-slash form for absolute paths (#633) — the writer was right and
// the snapshot encoded the POSIX accident.
func TestFileURIsNormalizeIdenticallyOnEveryPlatform(t *testing.T) {
	const want = `"uri": "file://<TMPDIR>/notes.txt"`

	for _, tc := range []struct {
		name   string
		in     string
		tmpDir string
	}{
		{
			name:   "posix, temp dir carries its leading slash",
			in:     `"uri": "file:///private/var/folders/x/T/abc/notes.txt"`,
			tmpDir: "/private/var/folders/x/T/abc",
		},
		{
			name:   "windows, forward slashes as the SARIF writer emits them",
			in:     `"uri": "file:///C:/Users/runneradmin/AppData/Local/Temp/abc/notes.txt"`,
			tmpDir: `C:\Users\runneradmin\AppData\Local\Temp\abc`,
		},
		{
			name:   "windows, JSON-escaped backslashes",
			in:     `"uri": "file:///C:\\Users\\runneradmin\\AppData\\Local\\Temp\\abc\\notes.txt"`,
			tmpDir: `C:\Users\runneradmin\AppData\Local\Temp\abc`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizePaths(tc.in, tc.tmpDir); got != want {
				t.Errorf("NormalizePaths(...) = %s, want %s — a snapshot that differs by platform makes "+
					"every SARIF golden unusable on one of them", got, want)
			}
		})
	}
}

// TestTheURICanonicalisationDoesNotTouchOtherURIs is the must-NOT-fire half: the rewrite is anchored on
// the sentinel, so a real three-slash file URI outside the temp dir — and any other scheme — is left
// exactly as it is. A blanket `file:///` → `file://` would corrupt output rather than normalise it.
func TestTheURICanonicalisationDoesNotTouchOtherURIs(t *testing.T) {
	for _, in := range []string{
		`"uri": "file:///etc/hosts"`,
		`"uri": "file:///C:/Windows/notepad.exe"`,
		`"uri": "https://example.com/a"`,
		`"helpUri": "file:///usr/share/doc/thing"`,
	} {
		if got := NormalizePaths(in, "/private/var/folders/x/T/abc"); got != in {
			t.Errorf("NormalizePaths(%s) = %s, want it unchanged — the canonicalisation must be anchored "+
				"on the <TMPDIR> sentinel, not applied to every file URI", in, got)
		}
	}
}
