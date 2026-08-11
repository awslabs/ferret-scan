// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import "sort"

// The registry is the seam that keeps this package check-agnostic.
//
// Everything that scores (Score, ScoreSink, NewBaseline) reads GatedCases() and
// never a per-check variable, so adding a validator to the gate means adding ONE
// file with its cases and one Register call — no edit to score.go, sink.go or
// baseline.go. That property is the whole reason the corpus can grow past its
// first check.
//
// It matters because the first version of this package scored SSN only, which made
// the headline numbers look authoritative while 18 of the tool's 19 checks were
// unmeasured. Nothing about the machinery is SSN-specific; only the labelled data
// is, and labelling data is per-check judgement work reviewed one validator at a
// time. 16 of 19 are scored now; see UnscoredChecks for the remaining two and
// METADATA, which is covered by the container cases.
type checkCorpus struct {
	// Check is the core.CheckNames() spelling this corpus scores.
	Check string
	// Gated are scored and ratcheted against the baseline.
	Gated []Case
	// Quarantined are counted and printed but never scored, for shapes whose
	// correct polarity is a product decision rather than a harness one.
	Quarantined []Case
	// Containers are file-based cases; see FileCase.
	Containers []FileCase
}

var registry []checkCorpus

// Register adds a check's corpus. Called from each cases_<check>.go init.
func Register(c checkCorpus) { registry = append(registry, c) }

func init() {
	Register(checkCorpus{
		Check:       "SSN",
		Gated:       SSNCases,
		Quarantined: SSNUndecided,
		Containers:  SSNContainerCases,
	})

	// The other checks that fire on plain text. Grouped as one
	// entry per file rather than one per check, because a case names its own Checks
	// and the scorer aggregates per check name — the grouping here is only about
	// where the data lives.
	Register(checkCorpus{
		Check:       "multi",
		Gated:       MultiCheckCases,
		Quarantined: MultiCheckQuarantine,
	})

	// PERSON_NAME has its own file because it carries the most NEGATIVES of any
	// check: the validator's database gate is simultaneously its false-positive
	// defence and its recall ceiling, so both directions need pinning before either
	// is changed. See cases_personname.go.
	Register(checkCorpus{
		Check:       "PERSON_NAME",
		Gated:       PersonNameCases,
		Quarantined: PersonNameQuarantine,
	})
}

// UnscoredChecks are checks with no case in this corpus yet, each with the reason.
//
// IMPORTANT: none of these is a broken validator. An earlier draft of this package
// called them "inert" after probing them with values that happen to be excluded or
// out of scope BY DESIGN — a corpus authoring error, not a product defect. Each
// reason below was root-caused before being written down:
//
//   - IP_ADDRESS is now SCORED (ip_public_routable, ip_negative_reserved_ranges).
//     The first draft wrongly called it inert after probing it only with reserved
//     ranges the validator deliberately never reports.
//
//   - OTP works, within its designed scope: provisioning SECRETS — otpauth:// URIs,
//     base32 seeds, recovery-code blocks (measured: the otpauth URI matches). It
//     deliberately does not match a transient 6-digit code in prose, and should not:
//     a bare 6-digit number carries no identifying structure, so matching it would
//     be a false-positive factory. Its own test table asserts exactly the URI shapes.
//
//   - SOCIAL_MEDIA works when its config block is present. It is config-gated by
//     design and the shipped patterns in examples/ferret.yaml are valid RE2
//     (verified by compiling them). Measured with that config: "@margaret_chen"
//     and a twitter.com URL both detected at HIGH. Scoring it requires threading a
//     non-default config through the harness, which the Case type does not support
//     yet.
//
// So this list is a TODO for the corpus, not a bug list for the product.
// TestUnscoredChecksAreAccountedFor keeps it honest: every name in core.CheckNames()
// must either be scored or appear here with a reason.
var UnscoredChecks = map[string]string{
	"OTP": "scope is provisioning secrets (otpauth:// URIs, base32 seeds, recovery " +
		"codes), verified working; transient 6-digit codes are deliberately out of scope.",
	"SOCIAL_MEDIA": "config-gated by design; verified working with the shipped " +
		"examples/ferret.yaml patterns. Scoring needs per-case config support.",
}

// GatedCases returns every scored case across all registered checks.
func GatedCases() []Case {
	var out []Case
	for _, c := range registry {
		out = append(out, c.Gated...)
	}
	return out
}

// QuarantinedCases returns every counted-but-unscored case.
func QuarantinedCases() []Case {
	var out []Case
	for _, c := range registry {
		out = append(out, c.Quarantined...)
	}
	return out
}

// ContainerCases returns every file-based case.
func ContainerCases() []FileCase {
	var out []FileCase
	for _, c := range registry {
		out = append(out, c.Containers...)
	}
	return out
}

// RegisteredChecks names the checks with a corpus, sorted.
func RegisteredChecks() []string {
	out := make([]string, 0, len(registry))
	for _, c := range registry {
		out = append(out, c.Check)
	}
	sort.Strings(out)
	return out
}
