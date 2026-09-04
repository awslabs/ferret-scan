// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// confidenceCeilingKey is the metadata key dual_path_bridge.clampToCeiling reads.
//
// Declared locally rather than imported from internal/validators, which is the convention the
// secrets, ipaddress and ssn validators already follow and which the bridge's own comment explains:
// "The key is a plain string rather than an import from one validator package so any validator can
// use the mechanism without the bridge depending on it."
//
// It is not merely stylistic. internal/validators has a test that imports this package, so importing
// internal/validators from here is an import cycle — measured: `imports .../validators/email from
// explain_rationale_test.go, imports .../validators from tld_ceiling.go: import cycle not allowed in
// test`. A plain string has no such edge.
const confidenceCeilingKey = "confidence_ceiling"

// An address whose last label is not a real top-level domain is weak evidence, and until now it was
// the strongest evidence this validator produced.
//
// Measured at f91ad60, `--checks EMAIL --confidence all`:
//
//	a@b.notatld       HIGH 90        log@app.log        HIGH 90
//	x@y.zzzzz         HIGH 90        data@set.parquet   HIGH 90
//	backup@db.sql     HIGH 90        report@2024.csv    HIGH 90
//	jane@example.com  LOW  40   <- a real address shape, 50 points LOWER
//
// A meaningless suffix outscored a plausible address. The arithmetic is the whole story: an
// unrecognised TLD cost -10 from a base of 100, so every `word@word.ext` filename landed at 90.
//
// # Why a ceiling and not the -10, and not a veto
//
// The -10 was itself a deliberate repair. CalculateConfidence's comment records that a -100 "zero it
// out" penalty was removed because the TLD list was incomplete and silently dropped real email on
// delegated gTLDs — and in this tool an unreported value never reaches the redactor, so a suppressed
// address stays cleartext. That reasoning is right and this change keeps it: nothing is suppressed.
//
// A ceiling is the mechanism dual_path_bridge.clampToCeiling provides for exactly this shape, and its
// contract states the property that matters here: "a demoted finding is still reported and still
// redacted". So `log@app.log` stops being a HIGH finding while a real address on a gTLD delegated
// after this list was generated is still reported — one band lower, which is recoverable, rather than
// absent, which is not.
//
// It is declared as metadata rather than clamped here because the +15 tabular boost and the context
// adjustment are both applied downstream; a validator that clamps its own return value has no way to
// make the bound stick.
//
// # This only became a usable signal once the list was fixed
//
// The list this rests on was 48% complete — 684 entries against IANA's 1438, missing 767 real TLDs
// including the four the -100 comment names. A ceiling keyed on "unrecognised" would have demoted
// real corporate email on more than half of all TLDs. Completing the list (see tlds.go) is what makes
// the signal mean anything; the ceiling is what keeps the list being out of date cheap.
//
// Reported by an external contributor scanning coding-agent tool output, where `user@1.service` and
// `report@2024-01-15.csv` broke systemctl and file operations (#587). Note their report's premise is
// narrower than the defect: it is not about systemd, and of the twelve systemd unit suffixes only
// `.target` and `.link` are real TLDs — `.service` is not.

// unrecognisedTLDCeiling is the confidence an address with an unrecognised TLD may not exceed.
//
// 55, inside the LOW band (the bands are 90 and 60), so an unrecognised TLD is excluded from
// `--confidence high` and from `--confidence high,medium` alike — the two views a reviewer uses.
//
// A first version used 75 (MEDIUM), on the reasoning that tlds.go is a snapshot of a growing registry
// so this population would be a MIX of filenames and genuine addresses on TLDs delegated since.
// Measurement refuted that. The 767 TLDs the old list was missing were not missing because they were
// new:
//
//	ccTLDs missing            0 of 248     (all delegated pre-2000)
//	punycode/IDN missing    151 of 151     (an entire category never added)
//	missing gTLDs                          .amazon .google .aws .bmw .gucci .hsbc -- the 2013-16 round
//	pre-2007 TLDs missing     none
//
// So the gap was a CURATION failure, not staleness, and with the list complete "unrecognised TLD"
// means genuinely-not-a-TLD rather than possibly-recent. LOW is the honest band for that.
//
// The condition attached to it: ICANN's next gTLD round is expected, and if this snapshot goes stale
// while the ceiling is LOW, real corporate email on a new gTLD is buried below the reviewer's view.
// LOW is correct PROVIDED staleness is detectable, which is what `make check-tlds` and the weekly
// workflow exist for. If either is ever removed, this constant should go back to MEDIUM.
const unrecognisedTLDCeiling = 55.0

// applyUnrecognisedTLDCeiling declares the ceiling on a match whose TLD was not recognised.
//
// Reads the validation checks rather than re-deriving the TLD, so the ceiling cannot disagree with
// the check that set it.
func applyUnrecognisedTLDCeiling(m *detector.Match, checks map[string]bool) {
	if m == nil || m.Metadata == nil || checks == nil {
		return
	}
	if valid, present := checks["valid_tld"]; !present || valid {
		return
	}
	m.Metadata[confidenceCeilingKey] = unrecognisedTLDCeiling
}
