// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/creditcard"
	"github.com/awslabs/ferret-scan/v2/internal/validators/email"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ipaddress"
	"github.com/awslabs/ferret-scan/v2/internal/validators/phone"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ssn"
)

// This file is the second half of the Phase 0 regression net (the first being
// the golden snapshots): a COMPLEXITY guard. The v2 audit found that ~12 of 13
// validators shared an O(n^2) per-line rescan pattern, fixed ad hoc. As the
// consolidation introduces a shared scanning primitive (Move C), there is a real
// risk of reintroducing quadratic behavior. These tests assert that each
// validator's runtime grows roughly LINEARLY with input size on a dense,
// match-bearing input — so a regression to O(n^2) fails loudly here instead of
// silently becoming a DoS vector in production.
//
// The assertion is deliberately loose (it allows a large constant-factor and
// GC/scheduler noise) because we are catching algorithmic class changes
// (linear -> quadratic), not micro-benchmarking. A 10x input that takes ~10x
// time passes; one that takes ~100x fails.

// validatorUnderTest is the minimal shape every validator exposes.
type validatorUnderTest interface {
	ValidateContent(content string, originalPath string) ([]detector.Match, error)
}

// complexityTargets are validators driven directly (bypassing the bridge stack)
// so the timing reflects the validator's own scanning cost, not orchestration.
// Each builder returns a fresh validator and a single-line unit of input that
// the validator will scan densely.
var complexityTargets = []struct {
	name      string
	new       func() validatorUnderTest
	unit      string // one "row" of input; repeated to scale size
	threshold time.Duration
}{
	{
		name: "ssn",
		new:  func() validatorUnderTest { return ssn.NewValidator() },
		// Dense near-SSN tokens on one line stress the per-match context rescan.
		unit:      "ssn 449-87-4100 and 555-12-3456 and 111-22-3333 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "ipaddress",
		new:       func() validatorUnderTest { return ipaddress.NewValidator() },
		unit:      "ip 203.0.113.42 host 10.0.0.5 gw 192.168.1.1 dns 8.8.8.8 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "email",
		new:       func() validatorUnderTest { return email.NewValidator() },
		unit:      "mail a@b.com x@y.org user@example.net admin@corp.co ",
		threshold: 5 * time.Second,
	},
	{
		name:      "phone",
		new:       func() validatorUnderTest { return phone.NewValidator() },
		unit:      "call 212-555-0142 or 415-555-0199 or 312-555-0123 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "creditcard",
		new:       func() validatorUnderTest { return creditcard.NewValidator() },
		unit:      "card 4532015112830366 5425233430109903 374245455400126 ",
		threshold: 5 * time.Second,
	},
}

// TestValidatorComplexityIsSubQuadratic checks that doubling input size does not
// roughly quadruple runtime for any validator. It measures at two sizes and
// asserts the growth ratio stays well under the quadratic expectation.
func TestValidatorComplexityIsSubQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("complexity guard skipped in -short mode")
	}

	for _, tgt := range complexityTargets {
		tgt := tgt
		t.Run(tgt.name, func(t *testing.T) {
			// Two single-line inputs: base and 4x. A single long line is the
			// worst case for the per-line rescan pattern.
			const baseReps = 400
			baseLine := strings.Repeat(tgt.unit, baseReps)
			bigLine := strings.Repeat(tgt.unit, baseReps*4) // 4x size

			// Absolute ceiling: even the big input must finish quickly. With
			// bounded execution and linear scanning this is generous; an O(n^2)
			// blowup on a dense line would blow past it.
			tBase := timeValidate(t, tgt.new(), baseLine)
			tBig := timeValidate(t, tgt.new(), bigLine)

			if tBig > tgt.threshold {
				t.Errorf("%s: 4x input took %v (> %v ceiling) — possible O(n^2) regression on a single long line",
					tgt.name, tBig, tgt.threshold)
			}

			// Relative growth: 4x input under linear scaling is ~4x time; under
			// quadratic it is ~16x. Fail above 12x (generous headroom for
			// constant factors, GC, and measurement noise on small absolute
			// times). Only meaningful when the base time is large enough to
			// measure; below 2ms the ratio is dominated by noise.
			if tBase > 2*time.Millisecond {
				ratio := float64(tBig) / float64(tBase)
				if ratio > 12.0 {
					t.Errorf("%s: 4x input took %.1fx longer (base=%v big=%v) — superlinear growth suggests an O(n^2) regression",
						tgt.name, ratio, tBase, tBig)
				}
			}
		})
	}
}

// timeValidate runs ValidateContent once and returns the wall-clock duration.
func timeValidate(t *testing.T, v validatorUnderTest, content string) time.Duration {
	t.Helper()
	start := time.Now()
	if _, err := v.ValidateContent(content, "<complexity>"); err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	return time.Since(start)
}
