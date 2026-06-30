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
