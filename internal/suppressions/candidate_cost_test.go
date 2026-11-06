// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// One finding's candidate hashes must cost the same on a 64 KiB line and on an 8 MiB one. FullLine is
// the whole line, which for minified or one-line input is the whole file, and the candidates are
// computed for every finding, so any per-finding pass over it makes the suppression layer quadratic.
// The line is capped at maxHashLineLen inside the hash, and otherLineEnding reads only the line's last
// byte. Only the line grows between the two sizes; the value sits at its end, so the other-line-ending
// variants are computed too. Each reading is the minimum of 200 calls, so load on the host moves both
// sizes alike.

// onLongLine is an SSN at the end of a line of about n bytes.
func onLongLine(n int) detector.Match {
	line := strings.Repeat("filler text ", n/12) + "ssn 123-45-6780"
	at := len(line) - len("123-45-6780")
	return detector.Match{Type: "SSN", Text: line[at:], Filename: "one-line.min.js", LineNumber: 1, Confidence: 90,
		Validator: "ssn", Context: detector.LineContext(line, at, len(line))}
}

// growth is the cost of f on the 8 MiB line over its cost on the 64 KiB line.
func growth(f func(detector.Match)) float64 {
	fastest := func(m detector.Match) time.Duration {
		best := time.Duration(math.MaxInt64)
		for i := 0; i < 200; i++ {
			start := time.Now()
			f(m)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	small, big := onLongLine(64<<10), onLongLine(8<<20)
	fastest(small) // warm up
	return float64(fastest(big)) / float64(max(fastest(small), time.Nanosecond))
}

// TestTheLineEndingIsReadFromTheLastByte guards otherLineEnding alone, where the check is O(1).
// Measured: 1.00x correct, also under -race; 97-111x (97x under -race) with
// strings.Contains(FullLine, "\r") in its place, the first version of #885's fix. The threshold is 5x.
func TestTheLineEndingIsReadFromTheLastByte(t *testing.T) {
	if len(otherLineEnding(onLongLine(64<<10))) == 0 {
		t.Fatal("fixture error: the finding gets no other-line-ending variant")
	}
	ratio := growth(func(m detector.Match) { otherLineEnding(m) })
	t.Logf("otherLineEnding, 8 MiB line / 64 KiB line: %.2fx", ratio)
	if ratio > 5 {
		t.Errorf("otherLineEnding costs %.1fx more on an 8 MiB line than on a 64 KiB one: it reads the whole line, "+
			"once per finding", ratio)
	}
}

// TestCandidateCostDoesNotGrowWithTheLine guards the whole candidate set, so a hash of the uncapped line
// is caught too. Measured: 1.01-1.12x correct (1.06x under -race); 124-141x with maxHashLineLen raised
// past the line. The threshold is 3x. (The Contains above reads only 2.0-3.7x here, because hashing the
// capped line dominates this cost; the guard above is the one that catches it.)
func TestCandidateCostDoesNotGrowWithTheLine(t *testing.T) {
	sm := &SuppressionManager{}
	ratio := growth(func(m detector.Match) { sm.findingHashCandidates(m) })
	t.Logf("candidate hashes, 8 MiB line / 64 KiB line: %.2fx", ratio)
	if ratio > 3 {
		t.Errorf("one finding's candidate hashes cost %.1fx more on an 8 MiB line than on a 64 KiB one; something "+
			"reads the whole FullLine per finding", ratio)
	}
}
