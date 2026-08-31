// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// #381: a filename comes from the scanned tree, so its bytes are chosen by whoever created
// the file — a contributor to a repository, an upload directory, an extracted archive. The
// text report wrote it out raw.
//
// Two attacks, both reproduced end to end on the CLI before this was fixed:
//
//   - "\x1b[2K\r" (erase line, carriage return) blanks the finding's own row. Replayed
//     through a CSI interpreter the report showed 2 finding rows while the summary said
//     "Findings: 3" — a HIGH SSN finding was gone from the operator's screen while still
//     being counted.
//   - "\n\nNo sensitive information found. Scan complete: 0 findings." adds that sentence
//     to the report as its own line.
//
// Exit codes are unaffected, so machine gates are not fooled. The damage is to the report a
// human reads at a glance.

// erasePayload is the row-erasure filename, verbatim from the reproduction.
const erasePayload = "quarterly-report.txt\x1b[2K\r"

// fabricatePayload is the line-fabrication filename.
const fabricatePayload = "ok.txt\n\nNo sensitive information found. Scan complete: 0 findings."

func hostileMatch(filename string) detector.Match {
	return detector.Match{
		Text:       "449-87-4100",
		LineNumber: 1,
		Type:       "SSN",
		Confidence: 100,
		Filename:   filename,
		Validator:  "ssn",
		Context:    detector.ContextInfo{FullLine: "SSN: 449-87-4100"},
	}
}

func formatText(t *testing.T, matches []detector.Match, noColor bool) string {
	t.Helper()
	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		// Without this the formatter prints "No matches found at the specified confidence
		// levels" and every assertion below passes on an EMPTY report. Two of these tests
		// did exactly that before it was added.
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		NoColor:         noColor,
		Limit:           0,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(out, "No matches found") {
		t.Fatalf("the formatter filtered every finding out, so nothing here is being "+
			"tested:\n%s", out)
	}
	return out
}

// TestTheTextReportEmitsNoBorrowedControlBytes.
//
// The formatter's own "\n" is the only control byte allowed through. Everything else came
// from the filename.
func TestTheTextReportEmitsNoBorrowedControlBytes(t *testing.T) {
	for _, payload := range []string{erasePayload, fabricatePayload, "evil\x1b[31mRED\x1b[0m.txt"} {
		t.Run(strings.SplitN(payload, "\x1b", 2)[0], func(t *testing.T) {
			out := formatText(t, []detector.Match{hostileMatch(payload)}, true)
			for i := 0; i < len(out); i++ {
				c := out[i]
				if c == '\n' {
					continue // the formatter's own line breaks
				}
				if c < 0x20 || c == 0x7F {
					t.Fatalf("byte 0x%02x at offset %d is a borrowed control byte.\n"+
						"surrounding: %q", c, i, out[max(0, i-40):min(len(out), i+20)])
				}
			}
		})
	}
}

// TestTheTextReportIsUnchangedByAnsiWhenColourIsOn.
//
// Sanitizing must NOT be gated on NoColor. The bytes are attacker data, not ferret's
// styling, so "the operator asked for colour" is not a reason to pass an escape sequence
// through. With colour on the formatter emits its own ANSI, so this asserts the borrowed
// payload specifically rather than counting all escapes.
func TestTheTextReportIsUnchangedByAnsiWhenColourIsOn(t *testing.T) {
	for _, noColor := range []bool{true, false} {
		out := formatText(t, []detector.Match{hostileMatch(erasePayload)}, noColor)
		if strings.Contains(out, "\x1b[2K") {
			t.Errorf("NoColor=%v: the borrowed erase-line sequence \\x1b[2K reached the "+
				"output. Sanitizing is unconditional by design.", noColor)
		}
		if strings.Contains(out, "quarterly-report.txt\x1b") {
			t.Errorf("NoColor=%v: the filename is still followed by a raw ESC", noColor)
		}
	}
}

// TestTheFindingRowSurvivesTerminalRendering is the test the issue asked for, and the one
// that states the actual harm: not "are there control bytes" but "does the operator still
// see the finding".
func TestTheFindingRowSurvivesTerminalRendering(t *testing.T) {
	matches := []detector.Match{
		hostileMatch("clean-one.txt"),
		hostileMatch(erasePayload),
		hostileMatch("clean-two.txt"),
	}
	out := formatText(t, matches, true)

	rendered := renderCSI(out)
	rows := 0
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, "[HIGH") {
			rows++
		}
	}
	if rows != len(matches) {
		t.Errorf("after terminal rendering %d of %d finding rows are visible:\n%s\n\n"+
			"A row erased from the screen while the summary still counts it is the whole "+
			"defect (#381).", rows, len(matches), rendered)
	}
	if strings.Contains(rendered, "No sensitive information found") {
		t.Error("the rendered report claims no sensitive information was found")
	}
}

// TestNoFabricatedLineSurvivesRendering: the second payload, asserted after rendering
// because a newline is invisible in a byte scan of the escaped form.
func TestNoFabricatedLineSurvivesRendering(t *testing.T) {
	out := formatText(t, []detector.Match{hostileMatch(fabricatePayload)}, true)
	rendered := renderCSI(out)

	for _, line := range strings.Split(rendered, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "No sensitive information found. Scan complete: 0 findings." {
			t.Errorf("the filename fabricated a whole report line:\n%s", rendered)
		}
	}
}

// TestTheVerboseMatchFoundLineIsSanitized.
//
// A separate sink, and one my first pass missed: "Match found in %s on line %d" is written
// only on the --verbose path, so a mutation removing its sanitization SURVIVED the whole
// text-formatter suite. Every write of a borrowed string needs its own case; one sanitized
// site does not cover its neighbour.
// Runs BOTH colour settings, and that is the whole point of the change here. The first version
// of this test hardcoded NoColor: true — the branch that was already correct — while the
// coloured branch printed the filename raw. So `--verbose` leaked on the DEFAULT invocation and
// this test passed: measured on origin/main, 1 raw ESC byte with colour and 0 without (#544).
//
// A safety test that only exercises the arm that already works cannot fail on the arm that does
// not. Both emitters now derive their filename from one sanitized value before branching, and
// this loop is what holds that.
func TestTheVerboseMatchFoundLineIsSanitized(t *testing.T) {
	for _, noColor := range []bool{true, false} {
		t.Run(colourLabel(noColor), func(t *testing.T) {
			verboseSinkIsSanitized(t, noColor)
		})
	}
}

func colourLabel(noColor bool) string {
	if noColor {
		return "no-color"
	}
	return "colour"
}

func verboseSinkIsSanitized(t *testing.T, noColor bool) {
	t.Helper()
	out, err := NewFormatter().Format([]detector.Match{hostileMatch(erasePayload)}, nil,
		formatters.FormatterOptions{
			ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
			NoColor:         noColor,
			Verbose:         true,
			ShowMatch:       true,
			Limit:           0,
		})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	// Non-vacuity: the verbose line must actually be present, or this proves nothing.
	if !strings.Contains(out, "Match found in") {
		t.Fatalf("the verbose \"Match found in\" line is absent, so this sink is untested:\n%s", out)
	}
	for i := 0; i < len(out); i++ {
		if c := out[i]; c != '\n' && (c < 0x20 || c == 0x7F) {
			t.Fatalf("byte 0x%02x at offset %d is a borrowed control byte on the verbose "+
				"path.\nsurrounding: %q", c, i, out[max(0, i-50):min(len(out), i+20)])
		}
	}
	if rendered := renderCSI(out); !strings.Contains(rendered, "Match found in") {
		t.Errorf("the verbose line was erased by terminal rendering:\n%s", rendered)
	}
}

// TestAnOrdinaryFilenameIsPrintedUnchanged bounds the blast radius. If this fix escaped
// ordinary paths the report would become unreadable, which is worse than the defect.
func TestAnOrdinaryFilenameIsPrintedUnchanged(t *testing.T) {
	for _, name := range []string{
		"report.txt",
		"/home/user/Documents/quarterly-report.txt",
		"rapport-café.txt",
		"報告書.txt",
	} {
		out := formatText(t, []detector.Match{hostileMatch(name)}, true)
		// getSmartFilename may shorten a path, so assert on the base name.
		base := name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			base = name[i+1:]
		}
		if !strings.Contains(out, base) {
			t.Errorf("ordinary filename %q does not appear in the report as %q:\n%s", name, base, out)
		}
		if strings.Contains(out, `\x`) {
			t.Errorf("ordinary filename %q produced an escape sequence in the report", name)
		}
	}
}

// renderCSI is a minimal terminal emulator: CR, LF, CUU (cursor up) and EL (erase in line).
// Those four are enough to render every payload in #381, and a full emulator would obscure
// what is being asserted.
func renderCSI(s string) string {
	data := []byte(s)
	screen := [][]byte{{}}
	row, col := 0, 0

	put := func(b byte) {
		for len(screen[row]) < col {
			screen[row] = append(screen[row], ' ')
		}
		if col < len(screen[row]) {
			screen[row][col] = b
		} else {
			screen[row] = append(screen[row], b)
		}
		col++
	}

	for i := 0; i < len(data); {
		switch b := data[i]; {
		case b == '\r':
			col = 0
			i++
		case b == '\n':
			row++
			for len(screen) <= row {
				screen = append(screen, []byte{})
			}
			col = 0
			i++
		case b == 0x1b && i+1 < len(data) && data[i+1] == '[':
			j := i + 2
			params := 0
			hasParams := false
			for j < len(data) && data[j] >= '0' && data[j] <= '9' {
				params = params*10 + int(data[j]-'0')
				hasParams = true
				j++
			}
			// Skip any remaining parameter bytes (';', etc.) we do not interpret.
			for j < len(data) && data[j] >= 0x30 && data[j] <= 0x3b {
				j++
			}
			if j >= len(data) {
				i++
				continue
			}
			switch data[j] {
			case 'K': // erase in line
				switch params {
				case 1:
					for k := 0; k < col && k < len(screen[row]); k++ {
						screen[row][k] = ' '
					}
				case 2:
					screen[row] = []byte{}
				default:
					if col < len(screen[row]) {
						screen[row] = screen[row][:col]
					}
				}
			case 'A': // cursor up
				n := params
				if !hasParams {
					n = 1
				}
				row -= n
				if row < 0 {
					row = 0
				}
			}
			i = j + 1
		default:
			put(b)
			i++
		}
	}

	lines := make([]string, 0, len(screen))
	for _, r := range screen {
		lines = append(lines, strings.TrimRight(string(r), " "))
	}
	return strings.Join(lines, "\n")
}

// TestRenderCSIActuallyErases is the harness's own non-vacuity check.
//
// Without it, a renderCSI that silently ignored the escape sequences would make every test
// above pass on the unfixed formatter — the assertions would be measuring a no-op emulator
// rather than a fixed formatter.
func TestRenderCSIActuallyErases(t *testing.T) {
	if got := renderCSI("visible\x1b[2K\rgone"); strings.Contains(got, "visible") {
		t.Errorf("renderCSI did not honour \\x1b[2K\\r: %q still shows the erased text.\n"+
			"With this emulator inert, every rendering test here would pass on the unfixed "+
			"formatter.", got)
	}
	if got := renderCSI("a\nb"); got != "a\nb" {
		t.Errorf("renderCSI mangled ordinary text: %q", got)
	}
	if got := renderCSI("abc\rX"); got != "Xbc" {
		t.Errorf("renderCSI did not honour CR: %q, want %q", got, "Xbc")
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
