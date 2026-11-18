// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"sort"
	"strings"
	"testing"
)

// #861 closeout: the help guard and the recall and decoy cases the issue's Tests section named for
// the score corpus (dl_gb_dvla, dl_ca_on_printed, ... and the negatives), kept here as validator
// tests. All values are synthetic.

// formatExemplars holds, for every format value a finding can carry, one labelled line that
// reports it. The help guard below checks both directions against help.go's SupportedFormats.
var formatExemplars = map[string]string{
	"CA_1L7D":     "Driver License Number: D1234567",
	"TX_PA_8D":    "Driver License Number: 12341234",
	"FL_MI_1L12D": "Driver License Number: W123412345612",
	"NY_GA_9D":    "Driver License Number: 123412345",
	"IL_1L11D":    "Driver License Number: W12341234512",
	"OH_2L6D":     "Driver License Number: XK123456",
	"NJ_1L14D":    "Driver License Number: W12341234512345",
	"WI_1L13D":    "Driver License Number: W1234123451234",
	"GB_DVLA":     "Driving licence number: WOMBA901010ZZ9AA",
	"CA_ON":       "Driving licence number: W1234-12345-12345",
	"CA_QC":       "Driving licence number: W1234-123456-12",
}

// TestHelpSupportedFormatsMatchEmittedFormats is the help guard (#861 box 11): the format values
// help.go documents are exactly the values the validator emits. A shape added without a help
// entry, or a help entry for a shape that no longer reports, fails here.
func TestHelpSupportedFormatsMatchEmittedFormats(t *testing.T) {
	documented := map[string]bool{}
	for _, entry := range NewValidator().GetCheckInfo().SupportedFormats {
		value, _, ok := strings.Cut(entry, ":")
		if !ok || value == "" || strings.ContainsAny(value, " \t") {
			t.Errorf("SupportedFormats entry %q does not start with a format value and a colon", entry)
			continue
		}
		if documented[value] {
			t.Errorf("SupportedFormats documents %s twice", value)
		}
		documented[value] = true
	}

	emitted := map[string]bool{}
	for want, line := range formatExemplars {
		got := dlFindings(t, line+"\n")
		if len(got) != 1 || got[0].format != want {
			t.Errorf("exemplar %q: want one %s finding, got %+v", line, want, got)
			continue
		}
		emitted[got[0].format] = true
	}

	var undocumented, unemitted []string
	for f := range emitted {
		if !documented[f] {
			undocumented = append(undocumented, f)
		}
	}
	for f := range documented {
		if !emitted[f] {
			unemitted = append(unemitted, f)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(unemitted)
	if len(undocumented) > 0 {
		t.Errorf("emitted but not in help.go SupportedFormats: %v", undocumented)
	}
	if len(unemitted) > 0 {
		t.Errorf("in help.go SupportedFormats but no exemplar emits it (add one to formatExemplars): %v", unemitted)
	}
}

// TestFormatExemplarsCoverEveryClassifiedShape keeps formatExemplars honest: every format value
// classifyMatch can return for a US shape has an exemplar, so the help guard cannot pass by
// leaving a shape out of both lists.
func TestFormatExemplarsCoverEveryClassifiedShape(t *testing.T) {
	v := NewValidator()
	for _, s := range []string{
		"D1234567", "12341234", "W123412345612", "123412345", "W12341234512", "XK123456",
		"W12341234512345", "W1234123451234",
	} {
		f := v.classifyMatch(s)
		if f == "" {
			t.Errorf("classifyMatch(%q) is empty", s)
			continue
		}
		if _, ok := formatExemplars[f]; !ok {
			t.Errorf("classifyMatch(%q) = %s, which has no exemplar", s, f)
		}
	}
}

// TestCloseout861RecallCases are the issue's recall cases, named as it named them.
func TestCloseout861RecallCases(t *testing.T) {
	cases := []struct {
		name, content, text, format string
		min                         float64
	}{
		{"dl_gb_dvla", "Driving licence number: WOMBA901010ZZ9AA\n", "WOMBA901010ZZ9AA", "GB_DVLA", 90},
		// 85 in the validator alone; the CLI scores the same rows in a .csv file at 100.
		{"dl_gb_dvla_csv_column", "name,driving_licence_number\nA. Wombat,WOMBA901010ZZ9AA\n", "WOMBA901010ZZ9AA", "GB_DVLA", 85},
		{"dl_ca_on_printed", "Ontario Driver's Licence No. W1234-12345-12345\n", "W1234-12345-12345", "CA_ON", 90},
		{"dl_ca_qc_printed", "Driving licence number: W1234-123456-12\n", "W1234-123456-12", "CA_QC", 90},
		{"dl_british_camel_json", `{"drivingLicenceNumber": "D1234567"}` + "\n", "D1234567", "CA_1L7D", 90},
		{"dl_driving_licence_label", "Driving licence: D1234567\n", "D1234567", "CA_1L7D", 90},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range dlFindings(t, tc.content) {
				if f.text == tc.text {
					if f.format != tc.format {
						t.Errorf("%q format = %s, want %s", tc.text, f.format, tc.format)
					}
					if f.confidence < tc.min {
						t.Errorf("%q confidence %.1f, want >= %.0f", tc.text, f.confidence, tc.min)
					}
					return
				}
			}
			t.Errorf("%q not reported in %q", tc.text, tc.content)
		})
	}
}

// TestCloseout861NegativeCases are the issue's negatives: licence-adjacent lines whose value is
// not a driving licence number. None is reported.
func TestCloseout861NegativeCases(t *testing.T) {
	cases := map[string]string{
		"dl_neg_license_checksum":      "License checksum: ABCD1234EFGH5678",
		"dl_neg_gb_month_13":           "Driving licence number: WOMBA913010ZZ9AA",
		"dl_neg_product_key":           "Driving licence key: ABCDE-12345-FGHIJ-67890-KLMNO",
		"dl_neg_license_issued_epoch":  `"licenseIssuedAt": 1728768000`,
		"dl_neg_roff_dl":               ".Dl 25 ctime=1084839148",
		"dl_neg_aws_license_config":    "arn:aws:license-manager:us-east-1:123456789012:license-configuration:lic-0123456789abcdef",
		"dl_neg_doxygen_anchor":        "Licensed under the Apache License.\n<a name=\"l00005\"></a><span class=\"lineno\">    5</span>",
		"dl_neg_non_state_2l13d_order": "Driver licence order ZZ1234567890123 shipped",
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		content := cases[name]
		t.Run(name, func(t *testing.T) {
			if got := dlFindings(t, content+"\n"); len(got) != 0 {
				t.Errorf("%q reported %+v", content, got)
			}
		})
	}
}
