// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// --checks must mean the same thing whatever the input source.
//
// It did not. File mode ran the value through parseChecksToRun, which upper-cased it
// and exited 1 on an unrecognized name. Stdin mode ran it through parseChecksList,
// which did neither and handed the raw strings to core.ParseChecksToRun — whose loop
// has no else branch, so an unknown name is discarded with no error and no warning.
// Measured on the same fixture and the same binary:
//
//	--checks ssn --file fx.txt   -> 1 finding      --stdin -> 0 findings, rc 0, silent
//	--checks BOGUS --file fx.txt -> rc 1           --stdin -> 0 findings, rc 0, silent
//	--checks ALL --file fx.txt   -> rc 1           --stdin -> 0 findings, rc 0, silent
//
// Running zero validators and reporting clean is the worst outcome a scanner has. The
// documented streaming gateway made it worse still: with --stdin --enable-redaction,
// a typo'd check name echoed the input back BYTE-IDENTICAL at rc 0, so a pipeline
// built on that pattern passed cleartext through while appearing to redact.
//
// Both paths now share normalizeChecksArg. These tests exist because a shared helper
// is only a convention until something asserts the two callers still agree.

// checksCases is the table both parsers must agree on.
var checksCases = []struct {
	arg      string
	wantErr  bool
	wantAll  bool     // nil result: every validator
	wantList []string // canonical names, when not wantAll and not wantErr
	why      string
}{
	{arg: "", wantAll: true, why: "no flag means every check"},
	{arg: "all", wantAll: true, why: "the documented sentinel"},
	{arg: "ALL", wantAll: true, why: "the sentinel is case-insensitive; uppercase used to select NOTHING"},
	{arg: "  all  ", wantAll: true, why: "surrounding whitespace must not defeat the sentinel"},
	{arg: "SSN", wantList: []string{"SSN"}, why: "canonical name"},
	{arg: "ssn", wantList: []string{"SSN"}, why: "lowercase is accepted and upper-cased, as file mode always did"},
	{arg: " ssn , email ", wantList: []string{"SSN", "EMAIL"}, why: "whitespace around names is trimmed"},
	{arg: "SSN,SSN", wantList: []string{"SSN", "SSN"}, why: "a repeat is harmless: the result seeds a presence map"},

	{arg: "BOGUS_CHECK", wantErr: true, why: "an unknown name must never mean 'scan nothing'"},
	{arg: "ADDRESS", wantErr: true, why: "plausible-but-wrong: the real id is PHYSICAL_ADDRESS"},
	{arg: "CARD", wantErr: true, why: "plausible-but-wrong: the real id is CREDIT_CARD"},
	{arg: "NAME", wantErr: true, why: "plausible-but-wrong: the real id is PERSON_NAME"},
	{arg: "SSN,BOGUS", wantErr: true, why: "one bad name in a list must fail the whole list, not silently drop half"},
	{arg: "all,SSN", wantErr: true, why: "'all' mixed with names used to silently select only SSN"},
	{arg: "ALL,ssn", wantErr: true, why: "same, in the case that previously selected nothing at all"},
}

func TestNormalizeChecksArg(t *testing.T) {
	for _, tc := range checksCases {
		t.Run(strings.ReplaceAll(tc.arg, " ", "_"), func(t *testing.T) {
			got, err := normalizeChecksArg(tc.arg)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeChecksArg(%q) returned nil error and %v.\n%s\n"+
						"Accepting this silently runs zero validators and reports clean.",
						tc.arg, got, tc.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeChecksArg(%q) errored: %v\n%s", tc.arg, err, tc.why)
			}
			if tc.wantAll {
				if got != nil {
					t.Errorf("normalizeChecksArg(%q) = %v, want nil (every check).\n%s", tc.arg, got, tc.why)
				}
				return
			}
			if len(got) != len(tc.wantList) {
				t.Fatalf("normalizeChecksArg(%q) = %v, want %v\n%s", tc.arg, got, tc.wantList, tc.why)
			}
			for i := range got {
				if got[i] != tc.wantList[i] {
					t.Errorf("normalizeChecksArg(%q)[%d] = %q, want %q\n%s",
						tc.arg, i, got[i], tc.wantList[i], tc.why)
				}
			}
		})
	}
}

// TestFileAndStdinParsersAgree is the parity gate.
//
// parseChecksToRun (file mode) exits the process on a bad name, so it cannot be
// called with invalid input from a test. What CAN be asserted is that both parsers
// derive from the same function and produce the same SELECTION for every input that
// is valid — which is the half a silent divergence would break.
func TestFileAndStdinParsersAgree(t *testing.T) {
	for _, tc := range checksCases {
		if tc.wantErr {
			// Both reject via the same normalizeChecksArg call; the error path is
			// covered above. parseChecksToRun would os.Exit(1) here.
			continue
		}
		t.Run(strings.ReplaceAll(tc.arg, " ", "_"), func(t *testing.T) {
			fileSel := parseChecksToRun(tc.arg)

			stdinList, err := parseChecksList(tc.arg)
			if err != nil {
				t.Fatalf("parseChecksList(%q) errored where file mode accepted: %v", tc.arg, err)
			}

			// Reduce the stdin list to the same shape as the file-mode map.
			stdinSel := map[string]bool{}
			for _, c := range core.CheckNames() {
				stdinSel[c] = false
			}
			if stdinList == nil {
				for c := range stdinSel {
					stdinSel[c] = true
				}
			} else {
				for _, c := range stdinList {
					stdinSel[c] = true
				}
			}

			for _, c := range core.CheckNames() {
				if fileSel[c] != stdinSel[c] {
					t.Errorf("--checks %q: check %s is %v in file mode but %v on stdin.\n"+
						"The same flag must select the same validators whatever the input source.",
						tc.arg, c, fileSel[c], stdinSel[c])
				}
			}
		})
	}
}

// TestEveryCanonicalNameIsAccepted — the recall half.
//
// A validation gate that rejects a legitimate name is worse than the fail-open it
// replaced: it stops a scan that would have found something. Every name the engine
// publishes must survive its own validator, in both cases.
func TestEveryCanonicalNameIsAccepted(t *testing.T) {
	names := core.CheckNames()
	if len(names) == 0 {
		t.Fatal("core.CheckNames() is empty; this test would pass vacuously")
	}
	for _, name := range names {
		for _, spelling := range []string{name, strings.ToLower(name)} {
			got, err := normalizeChecksArg(spelling)
			if err != nil {
				t.Errorf("normalizeChecksArg(%q) rejected a name core.CheckNames() publishes: %v",
					spelling, err)
				continue
			}
			if len(got) != 1 || got[0] != name {
				t.Errorf("normalizeChecksArg(%q) = %v, want exactly [%s]", spelling, got, name)
			}
		}
	}

	// And the whole list at once, which is what a --checks line generated from
	// CheckNames() looks like.
	all, err := normalizeChecksArg(strings.Join(names, ","))
	if err != nil {
		t.Fatalf("the full published list was rejected: %v", err)
	}
	if len(all) != len(names) {
		t.Errorf("full list round-tripped to %d names, want %d", len(all), len(names))
	}
}
