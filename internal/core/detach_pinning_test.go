// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

// The end-to-end pinning guard for #337.
//
// Every string on a finding used to be a substring of the file's whole extracted content, and
// a Go substring retains its parent's entire backing array — so one finding kept that file's
// buffer alive until the process exited. detector.DetachMatches, called at the scan
// convergence, replaces those strings with copies.
//
// This test drives a REAL scan through ScanContent and then asserts, by data pointer, that
// nothing reachable from any returned Match still points into the content. It is deliberately
// a pointer test and not a heap test:
//
//   - A heap measurement depends on GC timing and on whether the source buffer happens to be
//     live in the measuring scope, so it is flaky and easy to misread.
//   - A VALUE test cannot see the defect at all. A zero-length substring (`line[0:0]`, which
//     every match at column 0 produces) compares `== ""` while still carrying the document's
//     data pointer and pinning the whole buffer. That is why the walk below charges empty
//     strings like any other, and why the fixture is built to contain them.
//
// The walk covers exported strings reachable through structs, slices, arrays, maps (keys AND
// values), interfaces and pointers, so a validator that starts stashing content in a new
// metadata shape is caught rather than assumed safe.

// pinsInto reports whether s's backing array lies inside src's. Length is ignored on purpose.
func pinsInto(s, src string) bool {
	if len(src) == 0 {
		return false
	}
	base := uintptr(unsafe.Pointer(unsafe.StringData(src)))
	return uintptr(unsafe.Pointer(unsafe.StringData(s))) >= base &&
		uintptr(unsafe.Pointer(unsafe.StringData(s))) < base+uintptr(len(src))
}

// visitStrings calls visit for every exported string reachable from v.
func visitStrings(v reflect.Value, path string, depth int, visit func(path, s string)) {
	if depth > 12 || !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		visit(path, v.String())
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue // unexported: reflection cannot read it safely, and the fix cannot set it
			}
			visitStrings(v.Field(i), path+"."+t.Field(i).Name, depth+1, visit)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			visitStrings(v.Index(i), fmt.Sprintf("%s[%d]", path, i), depth+1, visit)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			visitStrings(k, path+".<key>", depth+1, visit)
			visitStrings(v.MapIndex(k), fmt.Sprintf("%s[%v]", path, k), depth+1, visit)
		}
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			visitStrings(v.Elem(), path+"*", depth+1, visit)
		}
	}
}

// pinningFixture builds content that is mostly filler, with findings from several validators
// spread thinly through it. Sparse on purpose: DetachMatches declines when the finding-bearing
// text is most of the buffer, so a dense fixture would measure the decline, not the detach.
//
// Findings are placed at column 0 and flush against end-of-line as well as mid-line, so the
// zero-length windows that defeat a value-based guard are present.
func pinningFixture() string {
	var sb strings.Builder
	filler := "This line is ordinary prose that contains nothing sensitive whatsoever.\n"

	for block := 0; block < 60; block++ {
		for i := 0; i < 40; i++ {
			sb.WriteString(filler)
		}
		// Column 0: the match starts at byte 0 of its line, so BeforeText is line[0:0].
		fmt.Fprintf(&sb, "user%02d@example.com is the contact for this account\n", block)
		// Flush right: the match ends at end-of-line, so AfterText is line[len:len].
		fmt.Fprintf(&sb, "Please email the owner at owner%02d@example.com\n", block)
		// Mid-line, several validators on one line.
		fmt.Fprintf(&sb, "Employee SSN: 4%02d-87-4100 phone 415-555-%04d\n", block%90+10, block)
		fmt.Fprintf(&sb, "Card 4111-1111-1111-1111 issued to Marcus Holloway on file\n")
		fmt.Fprintf(&sb, "Server 10.0.%d.15 hosts the internal service\n", block%250)
	}
	return sb.String()
}

func TestFindingsDoNotPinTheScannedContent(t *testing.T) {
	content := pinningFixture()

	res, err := ScanContent(content, ContentScanConfig{
		VirtualPath: "<pinning-fixture>",
		Checks:      []string{"all"},
		LogWriter:   io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanContent: %v", err)
	}

	// --- non-vacuity, before trusting any conclusion ---

	if len(res.Matches) < 20 {
		t.Fatalf("only %d findings; the fixture is not exercising enough of the pipeline to "+
			"detect pinning", len(res.Matches))
	}
	validators := map[string]bool{}
	emptyWindows := 0
	for i := range res.Matches {
		validators[res.Matches[i].Validator] = true
		if res.Matches[i].Context.BeforeText == "" || res.Matches[i].Context.AfterText == "" {
			emptyWindows++
		}
	}
	if len(validators) < 3 {
		t.Fatalf("findings came from only %d validator(s) %v; this guard is meant to cover "+
			"several metadata shapes", len(validators), validators)
	}
	if emptyWindows == 0 {
		t.Fatalf("no finding has an empty context window, so the zero-length case — the one a " +
			"value-based guard cannot see — is not covered by this fixture")
	}

	// Self-test: a known substring of content MUST be reported as pinning, or the detector
	// below is broken and would pass no matter what the fix did.
	probe := content[100:120]
	if !pinsInto(probe, content) {
		t.Fatalf("pinsInto failed its own self-test: a substring of content was not detected")
	}
	if pinsInto(strings.Clone(probe), content) {
		t.Fatalf("pinsInto reported a CLONE as pinning; the check is not discriminating")
	}

	// --- the assertion ---

	var offenders []string
	pinnedBytes := 0
	for i := range res.Matches {
		m := res.Matches[i]
		visitStrings(reflect.ValueOf(m), fmt.Sprintf("Match[%d](%s)", i, m.Validator), 0,
			func(path, s string) {
				if pinsInto(s, content) {
					if len(offenders) < 15 {
						offenders = append(offenders, fmt.Sprintf("%s len=%d", path, len(s)))
					}
					// One surviving alias retains the WHOLE buffer, so charge all of it.
					pinnedBytes += len(content)
				}
			})
	}

	if len(offenders) > 0 {
		t.Errorf("%d finding string(s) still point into the %d-byte scanned content, so every "+
			"one of them retains the entire buffer.\nFirst offenders:\n  %s\n"+
			"Charged %d bytes retained.",
			len(offenders), len(content), strings.Join(offenders, "\n  "), pinnedBytes)
	}
}

// TestDeclinedDetachIsScopedToDenseContent documents the deliberate non-improvement so it
// cannot quietly become the behaviour everywhere.
//
// A single-line minified document is left aliased by design: the copy would be as large as the
// buffer it frees. This asserts the shape is still recognised as dense — if the budget ever
// starts accepting it, this test says so and the decision can be re-made deliberately.
func TestDeclinedDetachIsScopedToDenseContent(t *testing.T) {
	// One line, most of which is a single finding-bearing blob.
	content := strings.Repeat("x", 512<<10) + " contact alice@example.com now"

	res, err := ScanContent(content, ContentScanConfig{
		VirtualPath: "<dense-fixture>",
		Checks:      []string{"EMAIL"},
		LogWriter:   io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("no findings, so this fixture measures nothing")
	}

	pinned := false
	for i := range res.Matches {
		visitStrings(reflect.ValueOf(res.Matches[i]), "m", 0, func(_, s string) {
			if pinsInto(s, content) {
				pinned = true
			}
		})
	}
	if !pinned {
		t.Logf("NOTE: the dense single-line shape is now being detached. That is an " +
			"improvement, not a failure — but the budget in detector.DetachMatches changed, " +
			"so re-check that the transient copy is acceptable and update this test.")
	}
}
