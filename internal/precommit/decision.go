// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package precommit

import "github.com/awslabs/ferret-scan/v2/internal/detector"

// Decision is the ONE answer to "does this run block the commit, and what do we tell the user".
//
// # The defect this type exists to make impossible
//
// The message and the exit code were decided in different packages from different inputs, and
// neither consulted the other:
//
//	the message    internal/formatters/text/formatter.go printed "High confidence issues found -
//	               commit blocked for security." whenever ANY match had Confidence >= 90
//	the exit code  precommit.exitCodeFor consulted PrecommitConfig.ExitOnFindings, which comes from
//	               FERRET_PRECOMMIT_EXIT_ON
//
// So with FERRET_PRECOMMIT_EXIT_ON=none the tool printed "commit blocked for security" and exited 0
// — the commit proceeded. Measured across the whole matrix with a genuine HIGH finding present, only
// `none` diverged:
//
//	EXIT_ON     rc   prints "commit blocked"
//	unset        1   yes
//	none         0   YES   <-- the lie
//	low          1   yes
//	medium       1   yes
//	high         1   yes
//
// `none` is what a team sets while adopting the tool, so the one configuration chosen by people who
// do not yet trust the gate was the one that lied to them.
//
// Returning both together is the fix, not a tidy-up: Blocking, ExitCode and Message are derived from
// one evaluation of one policy, so a future edit cannot move one without the others. The formatter
// receives the MESSAGE and renders it; it no longer decides policy. TestDecisionMessageAgreesWithExitCode
// asserts the agreement as an invariant over the whole input space rather than trusting that.
type Decision struct {
	// Blocking is true when this run should stop the commit.
	Blocking bool

	// ExitCode is what the process must exit with: 1 blocks, 2 means the tool malfunctioned,
	// 0 is a pass. --fail-on-incomplete may still escalate a 0 to 3 afterwards; that is a
	// different question (did the scan SEE everything) and is resolved separately.
	ExitCode int

	// Message is the user-facing verdict line, or "" when there is nothing to assert.
	//
	// Empty rather than a "not blocked" sentence on purpose: pre-commit output is deliberately
	// quiet on a developer's every commit, and a run that does not block should add no line at
	// all. A caller that renders this unconditionally therefore stays silent by default.
	Message string
}

// blockedMessage is the exact wording the formatter used before this type existed, preserved
// verbatim so no test, docs page or user's grep changes behaviour.
const blockedMessage = "High confidence issues found - commit blocked for security."

// Resolve answers both questions from the matches themselves.
//
// It takes MATCHES rather than a pre-computed confidence string because the string was the seam the
// bug lived in: the exit path derived it in cmd/main.go, the stdin path derived it again in
// cmd/stdin.go with a second copy of the same band arithmetic, and the formatter used a third
// spelling (`Confidence >= 90`) inline. Three derivations of "how bad is the worst finding" cannot be
// kept in step by review. One function, one input.
//
// Tool malfunction is handled by WithToolError, not here, so this function's answer depends only on
// the findings and the configured policy.
func Resolve(matches []detector.Match, config *PrecommitConfig) Decision {
	level := HighestConfidenceLevel(matches)
	if len(matches) > 0 && config != nil && config.ShouldExitOnFindings(level) {
		return Decision{Blocking: true, ExitCode: 1, Message: blockedMessage}
	}
	return Decision{}
}

// WithToolError escalates a non-blocking decision to exit 2 when the tool itself malfunctioned.
//
// Split from Resolve rather than being a third parameter to it, because the two callers need the
// answer at DIFFERENT times: the formatter needs the message before the run finishes, while whether
// the tool malfunctioned is only known after it. Passing hasErrors to Resolve would have meant
// calling the finding policy twice with different arguments — exactly the shape that let the message
// and the exit code drift apart in the first place.
//
// This way the finding policy is evaluated ONCE, and this step can only move ExitCode. It cannot
// touch Message, and TestToolErrorNeverChangesTheMessage asserts that over the input space, so the
// verdict the user read is always the verdict that decided the exit.
//
// A blocking decision is left alone: a blocked commit is the more actionable answer, and it already
// exits non-zero.
func (d Decision) WithToolError(hasErrors bool) Decision {
	if d.Blocking || !hasErrors {
		return d
	}
	d.ExitCode = 2
	return d
}

// HighestConfidenceLevel returns the band of the highest-confidence match: "high", "medium", "low",
// or "" when there are no matches.
//
// The 90/60 boundaries match the confidence contract used across the formatters. They are repeated
// here rather than imported because internal/formatters must not depend on this package — the
// formatter consumes a Decision.Message and nothing else, which is what keeps the dependency
// one-way. The same constants appear at a dozen sites module-wide; unifying all of them is a
// separate change, and doing it here would pull most of the formatter packages into this PR.
func HighestConfidenceLevel(matches []detector.Match) string {
	highest := ""
	for _, m := range matches {
		switch {
		case m.Confidence >= 90:
			// Nothing outranks high, so the answer is final.
			return "high"
		case m.Confidence >= 60:
			highest = "medium"
		default:
			if highest != "medium" {
				highest = "low"
			}
		}
	}
	return highest
}
