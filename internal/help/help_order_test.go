// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package help

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// fakeProvider is a minimal help Provider so the test does not depend on the
// real validator packages (which would create an import cycle).
type fakeProvider struct {
	info CheckInfo
}

func (f fakeProvider) GetCheckInfo() CheckInfo { return f.info }

func newTestSystem(names ...string) *System {
	h := NewSystem(true)
	for _, name := range names {
		h.RegisterProvider(fakeProvider{info: CheckInfo{
			Name:             name,
			ShortDescription: "desc for " + name,
		}})
	}
	return h
}

// captureStdout runs fn with output redirected to a pipe and returns what it
// wrote. ShowChecksHelp prints directly to stdout, so this is the only way to
// assert on its output. color.Output has to be swapped too: fatih/color
// captures the real stdout at package init, so the colored lines (including the
// suggested example) would otherwise bypass an os.Stdout swap entirely.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	origColor := color.Output
	os.Stdout = w
	color.Output = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = orig
	color.Output = origColor
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatalf("close read end: %v", err)
	}
	return out
}

// TestShowChecksHelpExampleIsDeterministic pins the suggested example check.
// It used to be picked by breaking out of a range over the providers MAP, so
// `--help checks` recommended a different check on every invocation (10
// distinct suggestions in 12 runs), which reads like the tool changed.
func TestShowChecksHelpExampleIsDeterministic(t *testing.T) {
	h := newTestSystem("SSN", "EMAIL", "CREDIT_CARD", "PHONE", "PASSPORT", "VIN", "OTP", "METADATA")
	seen := make(map[string]int)
	for i := 0; i < 40; i++ {
		out := captureStdout(t, h.ShowChecksHelp)
		// Anchor on "Example:" — the earlier "use: ferret-scan --help <check>"
		// instruction line also matches the bare prefix.
		exIdx := strings.LastIndex(out, "Example:")
		if exIdx < 0 {
			t.Fatalf("Example: section missing from output:\n%s", out)
		}
		idx := strings.Index(out[exIdx:], "ferret-scan --help ")
		if idx < 0 {
			t.Fatalf("example line missing from output:\n%s", out)
		}
		rest := out[exIdx+idx+len("ferret-scan --help "):]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[:nl]
		}
		seen[strings.TrimSpace(rest)]++
	}
	if len(seen) != 1 {
		t.Fatalf("suggested example varied across 40 runs: %v", seen)
	}
	// The alphabetically first registered check.
	if _, ok := seen["CREDIT_CARD"]; !ok {
		t.Fatalf("expected the alphabetically first check as the example, got %v", seen)
	}
}

// TestShowChecksHelpListIsSortedAndComplete asserts the rewritten single-pass
// collection still lists every registered check, in name order, each with its
// own description. The previous version re-scanned all providers per name to
// find the description again; a name/description mismatch would misdescribe a
// check to the user.
func TestShowChecksHelpListIsSortedAndComplete(t *testing.T) {
	names := []string{"SSN", "EMAIL", "CREDIT_CARD", "PHONE", "PASSPORT"}
	h := newTestSystem(names...)
	out := captureStdout(t, h.ShowChecksHelp)

	prev := ""
	found := 0
	for _, line := range strings.Split(out, "\n") {
		for _, name := range names {
			if !strings.Contains(line, name) || !strings.Contains(line, "desc for "+name) {
				continue
			}
			found++
			if prev != "" && name < prev {
				t.Fatalf("check %q listed after %q: list is not sorted\n%s", name, prev, out)
			}
			prev = name
		}
	}
	if found != len(names) {
		t.Fatalf("listed %d of %d checks with matching descriptions:\n%s", found, len(names), out)
	}
}

// TestShowChecksHelpEmptyRegistry guards the len(rows) > 0 branch: with no
// providers registered the example must fall back to a placeholder rather than
// panic on rows[0].
func TestShowChecksHelpEmptyRegistry(t *testing.T) {
	h := NewSystem(true)
	out := captureStdout(t, h.ShowChecksHelp)
	exIdx := strings.LastIndex(out, "Example:")
	if exIdx < 0 {
		t.Fatalf("Example: section missing from output:\n%s", out)
	}
	if !strings.Contains(out[exIdx:], "ferret-scan --help <check>") {
		t.Fatalf("empty registry should print the <check> placeholder:\n%s", out)
	}
}
