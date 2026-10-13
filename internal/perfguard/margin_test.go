// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestMarginIsMeasuredOnTheProtectedSide(t *testing.T) {
	for _, tc := range []struct {
		ratio, bound float64
		d            Direction
		want         float64
	}{
		{4.0, 8.0, StayBelow, 2.0},    // linear code at half the bound
		{7.06, 8.0, StayBelow, 1.133}, // macos-latest's worst correct target at 2 pairs
		{16.0, 8.0, StayAbove, 2.0},   // a quadratic control at twice the bound
		{9.72, 8.0, StayAbove, 1.215},
		{10.0, 8.0, StayBelow, 0.8}, // failing
		{0, 8.0, StayBelow, 0},      // no reading
	} {
		if got := Margin(tc.ratio, tc.bound, tc.d); fmt.Sprintf("%.3f", got) != fmt.Sprintf("%.3f", tc.want) {
			t.Errorf("Margin(%v, %v, %v) = %.3f, want %.3f", tc.ratio, tc.bound, tc.d, got, tc.want)
		}
	}
}

type captureLog struct{ lines []string }

func (c *captureLog) Helper() {}
func (c *captureLog) Logf(format string, args ...any) {
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func TestReportMarginWarnsOnlyWhenThinAndOnlyUnderActions(t *testing.T) {
	var out bytes.Buffer
	saved := annotations
	annotations = &out
	t.Cleanup(func() { annotations = saved })
	t.Setenv("ImageOS", "macos26")
	t.Setenv("ImageVersion", "20260907.0351.1")

	g := Growth{Ratio: 7.06, Clock: "cpu", Samples: []float64{7.06, 7.4, 7.2, 7.1}}

	t.Setenv("GITHUB_ACTIONS", "")
	l := &captureLog{}
	ReportMargin(l, "driverslicense", g, 8.0, StayBelow)
	if out.Len() != 0 {
		t.Errorf("annotation printed outside GitHub Actions: %q", out.String())
	}
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "margin 1.13x") || !strings.Contains(l.lines[0], "macos26/20260907.0351.1") {
		t.Errorf("the log line must carry the margin and the runner image on every run: %q", l.lines)
	}

	t.Setenv("GITHUB_ACTIONS", "true")
	ReportMargin(&captureLog{}, "driverslicense", g, 8.0, StayBelow)
	ann := out.String()
	if !strings.HasPrefix(ann, "::warning title=perfguard margin under 1.5x::driverslicense: 7.06x") || strings.Count(ann, "\n") != 1 {
		t.Errorf("a thin margin under Actions must print exactly one ::warning line at the start of a line, got %q", ann)
	}

	out.Reset()
	ReportMargin(&captureLog{}, "personname", Growth{Ratio: 4.1, Clock: "cpu"}, 8.0, StayBelow)
	ReportMargin(&captureLog{}, "quadratic control", Growth{Ratio: 15.5, Clock: "cpu"}, 8.0, StayAbove)
	if out.Len() != 0 {
		t.Errorf("a healthy margin must not warn: %q", out.String())
	}
}

func TestRunnerFallsBackToLocal(t *testing.T) {
	t.Setenv("ImageOS", "")
	t.Setenv("ImageVersion", "")
	if r := Runner(); !strings.HasPrefix(r, "local ") {
		t.Errorf("Runner() = %q, want it to say local when no image is set", r)
	}
}
