// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"strings"
	"testing"
)

// #587, reported by an external contributor scanning coding-agent tool output, where `user@1.service`
// and `report@2024-01-15.csv` broke systemctl and file operations.
//
// The defect was arithmetic: an unrecognised TLD cost -10 from a base of 100, so every
// `word@word.ext` filename landed at 90, HIGH. Measured before the fix:
//
//	a@b.notatld       HIGH 90        log@app.log        HIGH 90
//	backup@db.sql     HIGH 90        data@set.parquet   HIGH 90
//	jane@example.com  LOW  40   <- a real address shape, 50 points LOWER

// TestAnUnrecognisedTLDIsCeilinged is the must-demote half.
//
// It reads the METADATA on a real Match from ValidateContent, not the raw score from
// CalculateConfidence. A first version asserted only that checks["valid_tld"] was false and logged the
// confidence — proved vacuous by mutation: deleting the metadata assignment entirely left it green, so
// it tested the check that triggers the ceiling and never the ceiling.
func TestAnUnrecognisedTLDIsCeilinged(t *testing.T) {
	for _, addr := range []string{
		"report@2024-01-15.csv", "log@app.log", "backup@db.sql",
		"data@set.parquet", "archive@2024.tar", "a@b.notatld",
		"x@y.zzzzz", "cron@daily.timer",
	} {
		matches, err := NewValidator().ValidateContent(addr, "probe.txt")
		if err != nil {
			t.Fatalf("%s: ValidateContent: %v", addr, err)
		}
		if len(matches) == 0 {
			t.Errorf("%s: no finding at all — a suppressed value never reaches the redactor, so this "+
				"must be reported, only demoted", addr)
			continue
		}
		got, ok := matches[0].Metadata[confidenceCeilingKey].(float64)
		if !ok {
			t.Errorf("%s: no confidence ceiling declared (metadata keys: %v)", addr, keysOf(matches[0].Metadata))
			continue
		}
		if got != unrecognisedTLDCeiling {
			t.Errorf("%s: ceiling %.0f, want %.0f", addr, got, unrecognisedTLDCeiling)
		}
	}
}

// TestARecognisedTLDCarriesNoCeiling is the companion: the mechanism must not fire on real addresses.
func TestARecognisedTLDCarriesNoCeiling(t *testing.T) {
	for _, addr := range []string{"x@corp.amazon", "jane@company.com", "z@eng.aws", "dev@x.dev"} {
		matches, err := NewValidator().ValidateContent(addr, "probe.txt")
		if err != nil {
			t.Fatalf("%s: ValidateContent: %v", addr, err)
		}
		if len(matches) == 0 {
			t.Errorf("%s: not reported at all", addr)
			continue
		}
		if v, present := matches[0].Metadata[confidenceCeilingKey]; present {
			t.Errorf("%s: ceilinged at %v despite a recognised TLD", addr, v)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestTheCeilingIsInsideTheLowBand pins the constant against the band boundaries rather than
// hardcoding the number twice.
//
// The value moved once already: it shipped as 75 (MEDIUM) on the reasoning that the caught population
// would be a mix of filenames and real addresses on newly delegated TLDs. Measurement refuted that —
// the 767 TLDs the old list was missing were not recent, they were 151 IDNs and the 2013-16 brand
// round — so it became 55. If someone moves it again, this says which property has to hold.
func TestTheCeilingIsInsideTheLowBand(t *testing.T) {
	const highBand, mediumBand = 90.0, 60.0
	if unrecognisedTLDCeiling >= mediumBand {
		t.Errorf("unrecognisedTLDCeiling = %.0f, which is not below the MEDIUM boundary of %.0f — an "+
			"unrecognised TLD would still appear in a `--confidence high,medium` run, which is the "+
			"view a reviewer uses and the case #587 reported",
			unrecognisedTLDCeiling, mediumBand)
	}
	if unrecognisedTLDCeiling <= 0 {
		t.Errorf("unrecognisedTLDCeiling = %.0f; a ceiling of zero would erase the finding, and a "+
			"suppressed value is never handed to the redactor", unrecognisedTLDCeiling)
	}
	if unrecognisedTLDCeiling >= highBand {
		t.Error("ceiling is at or above the HIGH boundary, so it does nothing")
	}
}

// TestARecognisedTLDIsNeverCeilinged is the must-NOT-demote half, and every fixture is a TLD the OLD
// list was missing — so this doubles as the regression test for the list itself.
func TestARecognisedTLDIsNeverCeilinged(t *testing.T) {
	// .amazon, .google, .aws and .phd are the four that CalculateConfidence's comment names as the
	// reason a -100 penalty had to be removed: the list did not know them, so real email on them was
	// being suppressed. They were still being penalised -10 when this change was written.
	for _, addr := range []string{
		"x@corp.amazon", "y@team.google", "z@eng.aws", "a@b.phd",
		"jane@company.com", "ops@team.io", "dev@x.dev",
	} {
		_, checks := NewValidator().CalculateConfidence(addr)
		if !checks["valid_tld"] {
			t.Errorf("%s: TLD not recognised, so a real address would be capped into the LOW band", addr)
		}
	}
}

// TestTheTLDListIsTheWholeRootZone is the guard for the claim that broke this in the first place.
//
// The list it replaced was labelled "Complete IANA TLD list - updated December 2024" and held 684
// entries against IANA's 1438 — 48% complete, missing every one of the 151 internationalised TLDs and
// all 248 ccTLDs present. Nobody noticed because nothing checked. This does not fetch anything (a test
// that reaches the network fails closed on an offline runner); `make check-tlds` and the weekly
// workflow do that. What this pins is the shape a hand-edit would break.
func TestTheTLDListIsTheWholeRootZone(t *testing.T) {
	if len(ianaTLDs) < 1400 {
		t.Errorf("ianaTLDs holds %d entries; the IANA root zone had 1438 when this was generated. A "+
			"list materially smaller than that is being hand-maintained again, which is how it "+
			"reached 48%% completeness before", len(ianaTLDs))
	}

	// Categories, not a spot check: each of these was entirely or partly absent from the old list,
	// so each is a way the same failure would recur.
	var ccTLDs, idn int
	for tld := range ianaTLDs {
		if strings.HasPrefix(tld, "xn--") {
			idn++
		} else if len(tld) == 2 {
			ccTLDs++
		}
	}
	if ccTLDs < 240 {
		t.Errorf("only %d two-letter ccTLDs; IANA has 248", ccTLDs)
	}
	if idn < 140 {
		t.Errorf("only %d internationalised (xn--) TLDs; IANA has 151, and the old list had NONE of "+
			"them — an entire category never curated", idn)
	}

	// Entries that are not TLDs admit fakes. The old list had 13.
	for _, notATLD := range []string{"csv", "log", "sql", "parquet", "tar", "notatld", "zzzzz", "timer", "service"} {
		if _, present := ianaTLDs[notATLD]; present {
			t.Errorf("%q is in ianaTLDs but is not a delegated TLD, so `x@y.%s` would score as a "+
				"real address", notATLD, notATLD)
		}
	}
}
