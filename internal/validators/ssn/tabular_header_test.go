// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	stdctx "context"
	"strings"
	"testing"
)

// A value's column header must count as context for that value.
//
// Keyword scanning is per-LINE, so a CSV header row — which is a different line
// from the values it labels — was invisible to it. Measured on identical text
// before this change:
//
//	"Phone: 130-07-5728"                       ->  55  (negative keyword seen)
//	"a,phone,c" / "x,130-07-5728,z"            -> 100  (header unseen)
//
// Same word, same validator, 45 points apart, decided purely by whether the label
// sat beside the value or above it. The keyword list already covered
// tracking/invoice/sku/serial/account/phone/zip; it simply never got to read the
// header.

// csvWith builds a 3-column CSV with the given header on the middle column.
//
// Three columns because tabular.Analyze requires >= 3 fields: two is commonly
// ordinary prose carrying one comma ("Smith, John"), and treating that as a table
// would be worse than missing it.
func csvWith(header string) string {
	return "a," + header + ",c\n" +
		"x1,130-07-5728,y\n" +
		"x2,214-89-6712,y\n" +
		"x3,301-45-7788,y\n"
}

func scanCSV(t *testing.T, header string) (conf float64, count int) {
	t.Helper()
	ms, err := NewValidator().ValidateContentCtx(stdctx.Background(), csvWith(header), "t.csv")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	if len(ms) == 0 {
		return 0, 0
	}
	return ms[0].Confidence, len(ms)
}

// TestContradictingHeaderDemotesButStillReports is the core contract.
//
// Demoted below MEDIUM so the value leaves the default review surface and stops
// blocking a pre-commit hook — but STILL REPORTED, because only reported findings
// reach the redactor. A dropped finding would be cleartext in the redacted output,
// which is the worst failure this tool has.
func TestContradictingHeaderDemotesButStillReports(t *testing.T) {
	// Headers the validator's own negativeKeywords already cover. Nothing here is
	// new vocabulary; the fix is that the header is now readable at all.
	for _, header := range []string{
		"tracking_number", "phone", "zip_code", "account_number", "invoice_number",
		"part_number", "product_code", "routing_number", "serial_number", "sku",
		"transaction_id",
	} {
		t.Run(header, func(t *testing.T) {
			conf, n := scanCSV(t, header)

			if n == 0 {
				t.Fatalf("no finding at all under a %q column. The demotion must never "+
					"delete the finding: an unreported value is never handed to the "+
					"redactor, so it stays in cleartext in the output.", header)
			}
			if n != 3 {
				t.Errorf("got %d findings, want 3 — every row must still be reported "+
					"and therefore redactable", n)
			}
			if conf >= 60 {
				t.Errorf("confidence %.0f under a %q column is still >= MEDIUM, so it "+
					"remains on the default review surface and still blocks a pre-commit "+
					"hook. The same keywords inline score 55.", conf, header)
			}
			if conf <= 0 {
				t.Errorf("confidence %.0f means the finding was effectively erased", conf)
			}
		})
	}
}

// TestSupportingHeaderIsUnaffected — recall must not move.
//
// This is the half that matters most: a column that says "ssn" must stay HIGH. The
// national-identifier headers are included because the SSN validator's own
// positiveKeywords contain "national id", "government id", "federal id" and
// "tax id" — it was built to fire on them, and the score corpus labels them TRUE
// POSITIVES.
func TestSupportingHeaderIsUnaffected(t *testing.T) {
	for _, header := range []string{
		"ssn", "employee_ssn", "social_security_number", "taxpayer_id",
		"national_id", "govt_id", "sin", "nino", "socsec", "personnummer",
	} {
		t.Run(header, func(t *testing.T) {
			conf, n := scanCSV(t, header)
			if n != 3 {
				t.Fatalf("got %d findings under a %q column, want 3", n, header)
			}
			if conf < 90 {
				t.Errorf("confidence %.0f under a %q column: an identifier column must "+
					"stay HIGH. Losing recall here is a cleartext leak, not a cosmetic "+
					"regression.", conf, header)
			}
		})
	}
}

// TestHeaderCarryingBothSignalsIsNotDemoted — a supporting header wins.
//
// "employee_ssn" contains "employee id"-adjacent vocabulary, and some exports use
// headers that match a negative token incidentally. A column that says it holds
// SSNs must never be demoted for also matching something else.
func TestHeaderCarryingBothSignalsIsNotDemoted(t *testing.T) {
	// "account" is a negative keyword; "ssn" is positive. Support must win.
	for _, header := range []string{"ssn_account", "account_ssn", "payroll_account_ssn"} {
		t.Run(header, func(t *testing.T) {
			conf, n := scanCSV(t, header)
			if n == 0 {
				t.Fatalf("no finding under %q", header)
			}
			if conf < 60 {
				t.Errorf("confidence %.0f under %q: the header names it as an SSN column, "+
					"so the positive signal must outrank the incidental negative one", conf, header)
			}
		})
	}
}

// TestOnlyTheMatchesOwnColumnCounts — scoping.
//
// The header consulted is the one for THIS match's column, never the whole header
// row. Without that scoping a "zip_code" column would suppress the "employee_ssn"
// column beside it, turning a precision fix into a recall bug.
func TestOnlyTheMatchesOwnColumnCounts(t *testing.T) {
	// zip_code (negative) in column 1, employee_ssn (positive) in column 2. The
	// SSN-shaped values live in column 2 and must NOT be demoted by column 1.
	content := "zip_code,employee_ssn,dept\n" +
		"90210,130-07-5728,ops\n" +
		"10001,214-89-6712,fin\n" +
		"60601,301-45-7788,hr\n"

	ms, err := NewValidator().ValidateContentCtx(stdctx.Background(), content, "t.csv")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no findings")
	}
	for _, m := range ms {
		if m.Confidence < 90 {
			t.Errorf("value %q in the employee_ssn column scored %.0f: a negative header "+
				"on a DIFFERENT column must not demote it, or this precision fix becomes "+
				"a recall bug", m.Text, m.Confidence)
		}
	}
}

// TestNonTabularContentIsUnchanged — the conservative-recognizer guarantee.
//
// tabular.Analyze rejects anything that is not clearly delimited data: fewer than
// three fields, header cells that do not look like column names, ragged rows,
// unbalanced quotes. Everything it rejects must score exactly as it did before, so
// this change cannot reach ordinary prose.
func TestNonTabularContentIsUnchanged(t *testing.T) {
	cases := map[string]string{
		"prose":                "Employee SSN: 130-07-5728 on file.\n",
		"two fields only":      "tracking_number,130-07-5728\n",
		"prose with a comma":   "Smith, John has SSN 130-07-5728 in the record.\n",
		"ragged rows":          "a,tracking_number,c\nx,130-07-5728\ny,214-89-6712,z,extra\n",
		"no letters in header": "1,2,3\nx,130-07-5728,y\nz,214-89-6712,w\n",
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			ms, err := NewValidator().ValidateContentCtx(stdctx.Background(), content, "t.txt")
			if err != nil {
				t.Fatalf("ValidateContentCtx: %v", err)
			}
			if len(ms) == 0 {
				t.Fatalf("no finding: %q should still detect its SSN", content)
			}
			// The prose case carries an explicit "SSN:" label and must stay HIGH.
			if name == "prose" && ms[0].Confidence < 90 {
				t.Errorf("labelled prose SSN scored %.0f, want >= 90 — the header logic "+
					"must not reach non-tabular content", ms[0].Confidence)
			}
		})
	}
}

// TestDelimiterCoverageIsHonest records which delimiters the fix reaches.
//
// Measured: comma, tab, semicolon and pipe are recognised (and markdown tables come
// free via pipe). Colon, fixed-width alignment, caret and tilde are NOT, so a
// contradicted column in those layouts is still reported at its undemoted score.
//
// This is pinned rather than left implicit so the limit is discoverable from the
// tests, and so the day someone adds a delimiter the expectations move visibly.
// Fixed-width is the notable gap: it is alignment-based rather than delimited, so
// it needs column-position logic rather than another entry in a list.
func TestDelimiterCoverageIsHonest(t *testing.T) {
	demoted := map[string]bool{
		",":  true,
		"\t": true,
		";":  true,
		"|":  true,
		":":  false,
		"^":  false,
		"~":  false,
	}

	for delim, wantDemoted := range demoted {
		t.Run("delim_"+strings.TrimSpace(delim), func(t *testing.T) {
			content := "name" + delim + "tracking_number" + delim + "dept\n" +
				"a" + delim + "130-07-5728" + delim + "x\n" +
				"b" + delim + "214-89-6712" + delim + "y\n" +
				"c" + delim + "301-45-7788" + delim + "z\n"

			ms, err := NewValidator().ValidateContentCtx(stdctx.Background(), content, "t.txt")
			if err != nil {
				t.Fatalf("ValidateContentCtx: %v", err)
			}
			if len(ms) == 0 {
				t.Fatalf("no finding for delimiter %q", delim)
			}

			gotDemoted := ms[0].Confidence < 60
			if gotDemoted != wantDemoted {
				t.Errorf("delimiter %q: demoted=%v (conf %.0f), want demoted=%v.\n"+
					"If a delimiter was just added, update this map — it exists to keep the "+
					"supported set explicit rather than folklore.",
					delim, gotDemoted, ms[0].Confidence, wantDemoted)
			}
		})
	}
}
