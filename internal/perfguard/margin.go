// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// ThinMargin is the repository's margin rule for a growth bound: every reading the bound governs
// should sit at least 1.5x from it, on the side the assertion protects. Inside that the assertion
// still passes, but one runner-image change or one noisier neighbour fails it — and #546, #620,
// #643 and #649 were each a bound discovered thin by a red build rather than before one.
//
// ReportMargin is what turns the rule into a signal. A bound is a tuned value, and a tuned value
// goes stale silently unless something reports its distance from the readings on every run.
const ThinMargin = 1.5

// Direction says which side of its bound a correct reading belongs on.
type Direction int

const (
	// StayBelow is a regression guard or a linear control: correct code must read under the bound.
	StayBelow Direction = iota
	// StayAbove is a control proving a genuine regression is still caught: it must read over it.
	StayAbove
)

// Margin is how far ratio sits from bound on the side d protects — bound/ratio for StayBelow,
// ratio/bound for StayAbove. Under 1.0 the assertion fails; under ThinMargin it passes thinly.
// A non-positive input has no meaningful margin and returns 0, which reads as failing.
func Margin(ratio, bound float64, d Direction) float64 {
	if ratio <= 0 || bound <= 0 {
		return 0
	}
	if d == StayAbove {
		return ratio / bound
	}
	return bound / ratio
}

// Logger is the part of testing.TB that ReportMargin needs; taking it rather than testing.TB keeps
// the testing package out of this one's imports.
type Logger interface {
	Helper()
	Logf(format string, args ...any)
}

// annotations is where the workflow-command copy of a thin margin goes. A variable so the test can
// capture it.
var annotations io.Writer = os.Stdout

// ReportMargin logs one assertion's margin on every run and, when it is thin under GitHub Actions,
// also prints it as a ::warning workflow command so it appears in the run's annotations without
// anyone reading the log. Call it only on the branch where the assertion actually runs — not where
// the tick gate or the race gate declined — so a reported margin is always one that was asserted.
//
// The warning goes to stdout directly, not through t.Logf: t.Logf prefixes "file.go:NN: ", and
// GitHub parses a workflow command only at the start of a line. Like every t.Logf line, it is shown
// for a passing package only under `go test -v`, which is why go-test.yml's report step exists.
func ReportMargin(l Logger, name string, g Growth, bound float64, d Direction) {
	l.Helper()
	m := Margin(g.Ratio, bound, d)
	side := "below"
	if d == StayAbove {
		side = "above"
	}
	line := fmt.Sprintf("%s: %.2fx, must stay %s %.2f — margin %.2fx (rule %.1fx), %d pairs, %s clock, %s",
		name, g.Ratio, side, bound, m, ThinMargin, len(g.Samples), g.Clock, Runner())
	l.Logf("margin %s", line)
	if m < ThinMargin && os.Getenv("GITHUB_ACTIONS") == "true" {
		// Workflow-command data must escape %, CR and LF, or the message is cut short or misparsed.
		esc := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(line)
		fmt.Fprintf(annotations, "::warning title=perfguard margin under %.1fx::%s\n", ThinMargin, esc)
	}
}

// Runner names the machine a reading came from: the GitHub-hosted image and its version when the
// runner sets them (ImageOS, ImageVersion), then GOOS/GOARCH. A margin that moves on the day the
// image moves is the image's doing, not the code's — and without this in the line, that is a
// fact someone has to reconstruct from the job's setup log.
func Runner() string {
	img := os.Getenv("ImageOS")
	if v := os.Getenv("ImageVersion"); v != "" {
		img += "/" + v
	}
	if img == "" {
		img = "local"
	}
	r := img + " " + runtime.GOOS + "/" + runtime.GOARCH
	if raceEnabled {
		r += " -race"
	}
	return r
}
