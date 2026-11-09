// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestReportCommit(t *testing.T) {
	saved := GitCommit
	t.Cleanup(func() { GitCommit = saved })

	cases := []struct{ injected, want string }{
		// goreleaser's .Commit: the full id, which self-flags as a secret in a report (#904).
		{"5fecf59c1decc766139bfe5af752e80884d120c4", "5fecf59c1dec"},
		{"5FECF59C1DECC766139BFE5AF752E80884D120C4", "5FECF59C1DEC"},
		// The Makefile's `git rev-parse --short`: already short, kept.
		{"5fecf59", "5fecf59"},
		{"5fecf59c1dec", "5fecf59c1dec"},
		// A suffixed id keeps its suffix and loses the digits that self-flag.
		{"5fecf59c1decc766139bfe5af752e80884d120c4-dirty", "5fecf59c1dec-dirty"},
		// A development build, and anything that does not start with a long hex id: as injected.
		{"unknown", "unknown"},
		{"v2.5.3", "v2.5.3"},
		{"", ""},
	}
	for _, tc := range cases {
		GitCommit = tc.injected
		if got := ReportCommit(); got != tc.want {
			t.Errorf("ReportCommit() with GitCommit=%q = %q, want %q", tc.injected, got, tc.want)
		}
	}
}
