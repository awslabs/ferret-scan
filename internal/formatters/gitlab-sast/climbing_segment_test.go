// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import "testing"

// #562 exposed a second instance of the same defect in this package. The scan gate refused a path
// whose NAME contained "..", so such a file was never scanned and this formatter never saw a finding
// from one. With the scan fixed, the formatter's own substring test took over and dropped it —
// silently, because the loop in formatter.go `continue`s past a vulnerability that fails validation
// and logs it only under --verbose.
//
// Measured before this fix, on two byte-identical files in one directory differing only in name:
//
//	json         findings=2
//	sarif        findings=2
//	gitlab-sast  findings=1   with "status": "success" and nothing on stderr
//
// A GitLab gate read a successful security report with a real SSN missing from it, which is why this
// is a leak rather than a cosmetic difference.

func TestClimbingSegmentIsRefusedButATwoDotFilenameIsNot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		path  string
		climb bool
	}{
		// Must be ACCEPTED: ".." inside a filename is an ordinary name.
		{"two dots inside a filename", "report..final.txt", false},
		{"a date range", "2024..2025.csv", false},
		{"trailing dots before the extension", "notes...draft.txt", false},
		{"two dots in a directory name", "a..b/c.txt", false},
		{"a bare double dot as a name part", "x/y..z", false},
		{"an ordinary relative path", "src/internal/main.go", false},
		{"a single dot segment", "./a.txt", false},

		// Must be REFUSED: a ".." path SEGMENT climbs.
		{"leading climb", "../secrets.txt", true},
		{"double climb", "../../etc/passwd", true},
		{"climb in the middle", "a/../../b.txt", true},
		{"trailing climb", "a/b/..", true},
		{"windows separator climb", `a\..\b.txt`, true},
		{"windows leading climb", `..\secrets.txt`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathHasClimbingSegment(tc.path); got != tc.climb {
				t.Errorf("pathHasClimbingSegment(%q) = %v, want %v", tc.path, got, tc.climb)
			}
		})
	}
}

// TestTheLocationValidatorAgreesWithTheSegmentRule drives the real validator rather than the helper,
// so a future edit that stops CALLING the helper is caught too — testing the helper alone would leave
// that mutation surviving.
func TestTheLocationValidatorAgreesWithTheSegmentRule(t *testing.T) {
	v := NewSchemaValidator()

	loc := func(file string) *GitLabLocation {
		return &GitLabLocation{File: file, StartLine: 1, EndLine: 1}
	}

	if err := v.validateLocation(loc("report..final.txt")); err != nil {
		t.Errorf("a filename containing \"..\" was refused by the location validator: %v\n"+
			"That is the #562 defect: the finding is dropped from the report and the scan still "+
			"reports success, so a gate sees a clean run.", err)
	}
	if err := v.validateLocation(loc("../../etc/passwd")); err == nil {
		t.Error("a path with a genuine \"..\" climbing segment was ACCEPTED by the location " +
			"validator. The GitLab schema expects a repo-relative path that does not climb, so this " +
			"widening went too far.")
	}
}
