// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "testing"

// onlyNPI returns the one NPI finding ValidateContent reports for line, failing the test when there
// is not exactly one.
func onlyNPI(t *testing.T, line string) (conf float64, md map[string]any) {
	t.Helper()
	ms, err := NewValidator().ValidateContent(line, "npi.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", line, err)
	}
	n := 0
	for _, m := range ms {
		if m.Type == "NPI" {
			n++
			conf, md = m.Confidence, m.Metadata
		}
	}
	if n != 1 {
		t.Fatalf("%q: %d NPI findings, want 1 (%v)", line, n, ms)
	}
	return conf, md
}

// #930: CMS's worked check-digit example read NPI 90 HIGH ("NPI: 1234567893") and 100 ("Provider
// NPI: 1234567893 on the claim.") on main @ 3aa380e. It is held at publishedExampleCeiling with the
// ceiling published and the reason in validation_checks: still reported, so still redacted.
func TestPublishedExampleNPIIsHeldAtLow(t *testing.T) {
	for _, line := range []string{
		"NPI: 1234567893",
		"Provider NPI: 1234567893 on the claim.",
		`{"npi": "1234567893"}`,
		"npi,name\n1234567893,Clinic\n",
		"NPI 1234567893 test example sample",
	} {
		conf, md := onlyNPI(t, line)
		if conf > publishedExampleCeiling {
			t.Errorf("%q: scored %.0f, want at most %.0f", line, conf, publishedExampleCeiling)
		}
		if md["confidence_ceiling"] != publishedExampleCeiling {
			t.Errorf("%q: confidence_ceiling = %v, want a published %.0f", line, md["confidence_ceiling"], publishedExampleCeiling)
		}
		checks, _ := md["validation_checks"].(map[string]bool)
		if v, ok := checks["not_published_example"]; !ok || v {
			t.Errorf("%q: validation_checks.not_published_example = %v (present %t), want false", line, v, ok)
		}
	}
}

// The controls: other NPI-Luhn-valid values, the nearest neighbour of the example included, keep the
// score they have on main @ 3aa380e and publish no ceiling. 1938475625 is the score corpus's
// replacement for the example (medical_npi_labelled).
func TestOtherNPIsKeepTheirScore(t *testing.T) {
	for _, c := range []struct {
		line string
		want float64
	}{
		{"NPI: 1234567885", 90},
		{"NPI: 1234567901", 90},
		{"Provider NPI: 1938475625 on the claim.", 100},
	} {
		conf, md := onlyNPI(t, c.line)
		if conf != c.want {
			t.Errorf("%q: scored %.0f, want %.0f (main)", c.line, conf, c.want)
		}
		if _, ok := md["confidence_ceiling"]; ok {
			t.Errorf("%q: published confidence_ceiling %v, want none", c.line, md["confidence_ceiling"])
		}
		if checks, _ := md["validation_checks"].(map[string]bool); checks != nil {
			if _, ok := checks["not_published_example"]; ok {
				t.Errorf("%q: recorded not_published_example for an unlisted NPI", c.line)
			}
		}
	}
}

// Every listed value is an NPI the validator would otherwise report: a typo in the table would
// silently cap nothing.
func TestPublishedExampleNPIsPassTheCheckDigit(t *testing.T) {
	for v := range publishedExampleNPIs {
		if !reNPI.MatchString(v) || !npiLuhnValid(v) {
			t.Errorf("%q is listed but is not an NPI-Luhn-valid NPI", v)
		}
	}
}
