// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	stdctx "context"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/execguard"
)

// These tests use only the validator's public scan, run through execguard.ValidateContent so the
// additive normalized pass (which folds Unicode dashes to '-') runs as it does in the CLI. They
// name no helper the fix added, so they compile against the validator as it was before #862 and
// fail there; see that issue for the measurements.

// scanIBANTexts returns every IBAN text the validator reports for content, as the CLI's
// chokepoint would, sorted.
func scanIBANTexts(t *testing.T, content string) []string {
	t.Helper()
	ms, err := execguard.ValidateContent(stdctx.Background(), "bank_account", NewValidator(), content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var out []string
	for _, m := range ms {
		if m.Type == "IBAN" {
			out = append(out, m.Text)
		}
	}
	sort.Strings(out)
	return out
}

// TestIssue862ReproReportsEveryIBAN is the issue's repro.txt: 14 IBANs, of which main reported 4.
// Line 8 is grouped by U+2013 EN DASH, found through the normalized pass and reported in its
// original bytes.
func TestIssue862ReproReportsEveryIBAN(t *testing.T) {
	lines := []string{
		"IBAN: DE43 1234 5678 9012 3456 78 BIC: EXMPDEFF",
		"IBAN: ES98 1234 5678 9012 3456 7890 BIC: EXMPESMM",
		"IBAN: ES52 2345 6789 0123 4567 8901",
		"pay to IBAN PL04 1234 5678 9012 3456 7890 1234 per invoice",
		"IBAN BE53 1234 5678 9012 EUR",
		"IBAN: AT11 1234 5678 9012 3456 for payroll",
		"IBAN: DE35-2345-6789-0123-4567-89",
		"IBAN: DE79\u20133456\u20137890\u20131234\u20135678\u201390",
		"IBAN: EG801234567890123456789012345",
		"IBAN: RU3212345678901234567890123456789",
		"IBANs: ES81 3456 7890 1234 5678 9012 DE82 4567 8901 2345 6789 01",
		"IBANs: DE63 5678 9012 3456 7890 12 ES84 4567 8901 2345 6789 0123",
	}
	want := []string{
		"DE43 1234 5678 9012 3456 78",
		"ES98 1234 5678 9012 3456 7890",
		"ES52 2345 6789 0123 4567 8901",
		"PL04 1234 5678 9012 3456 7890 1234",
		"BE53 1234 5678 9012",
		"AT11 1234 5678 9012 3456",
		"DE35-2345-6789-0123-4567-89",
		"DE79\u20133456\u20137890\u20131234\u20135678\u201390",
		"EG801234567890123456789012345",
		"RU3212345678901234567890123456789",
		"ES81 3456 7890 1234 5678 9012",
		"DE82 4567 8901 2345 6789 01",
		"DE63 5678 9012 3456 7890 12",
		"ES84 4567 8901 2345 6789 0123",
	}
	sort.Strings(want)
	got := scanIBANTexts(t, strings.Join(lines, "\n"))
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("reported %d IBANs:\n  %s\nwant %d:\n  %s", len(got), strings.Join(got, "\n  "), len(want), strings.Join(want, "\n  "))
	}
}

// TestIssue862FifteenRegistryCountriesAreReported: one synthetic IBAN, compact, for each registry
// country the hand-written map lacked. Main reported none of them.
func TestIssue862FifteenRegistryCountriesAreReported(t *testing.T) {
	// Built as #862's iban_sweep.py builds them: 'a' -> X, 'n'/'c' -> 1234567890..., real check digits.
	values := []string{
		"BI1412345678901234567890123", "DJ9012345678901234567890123", "EG801234567890123456789012345",
		"FK39XX345678901234", "HN23XXXX56789012345678901234", "LY37123456789012345678901",
		"MN181234567890123456", "NI81XXXX56789012345678901234", "OM311234567890123456789",
		"RU3212345678901234567890123456789", "SD5012345678901234", "SO861234567890123456789",
		"ST86123456789012345678901", "SV94XXXX56789012345678901234", "YE37XXXX5678901234567890123456",
	}
	var lines []string
	for _, iban := range values {
		lines = append(lines, "IBAN: "+iban)
	}
	got := scanIBANTexts(t, strings.Join(lines, "\n"))
	sort.Strings(values)
	if strings.Join(got, "|") != strings.Join(values, "|") {
		t.Errorf("reported %d of %d: %q", len(got), len(values), got)
	}
}

// TestIssue862UnderscoreJoinedIBANNeedsALabel: a labelled '_' join is reported, an unlabelled one
// is not. Main reported none of the four.
func TestIssue862UnderscoreJoinedIBANNeedsALabel(t *testing.T) {
	cases := map[string]bool{
		"iban_DE68012345678901234567":            true,
		"bank_iban_DE68 0123 4567 8901 2345 67":  true,
		"statement_DE68012345678901234567.pdf":   false,
		"DE68012345678901234567_2026.pdf":        false,
		"iban: DE68012345678901234567 (control)": true,
	}
	for line, want := range cases {
		if got := scanIBANTexts(t, line); want != (len(got) == 1) {
			t.Errorf("%q: reported %q, want reported=%v", line, got, want)
		}
	}
}

// TestIssue862StructureViolatingValuesAreNotIBANs: values main reported at 85 that cannot be an
// IBAN of their country, because a character sits where the registry allows only a digit.
func TestIssue862StructureViolatingValuesAreNotIBANs(t *testing.T) {
	for _, line := range []string{
		"build id DE34EXAMPLE00000000000",
		"license key BE16 KEYE XAMP LE00",
		"ref DE40PR7DXBFIZXPGVRA6UH",
		"0000c360: 3a1c 0e2b be05 d761 ff60 affe  :..+...a.`..",
	} {
		if got := scanIBANTexts(t, line); len(got) != 0 {
			t.Errorf("%q reported as IBAN %q", line, got)
		}
	}
}
