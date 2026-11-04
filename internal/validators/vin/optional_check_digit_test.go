// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/tabular"
)

// Fixtures for #860. Each fails the position-9 check digit and has a WMI outside knownWMIs, so
// before #860 the scan dropped every one of them whatever surrounded it.
const (
	vinWVG     = "WVGZZZ5NZRA000502" // VW group filler shape: ZZZ in the VDS, Z at position 9
	vinTMB     = "TMBZZZ1KZRA000503" // Skoda, same shape
	vinVF1     = "VF1RJA00ZRA000506" // Renault, a non-check character at position 9
	vinVF1Bad  = "VF1RJA007RA000506" // the same VIN with a wrong digit at position 9 (check is 8)
	vinVF3Zero = "VF3ZZZ1KZ0A000607" // position 10 is 0, no model year code: base 55, not 60
	refToken   = "REF7TX29KD4M8PL2V" // a 17-character reference: no check digit, unknown WMI
)

// scanVINs returns the VIN findings for content as "text@confidence", in line order.
func scanVINs(t *testing.T, content string) []string {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q) error = %v", content, err)
	}
	var got []string
	for _, m := range matches {
		got = append(got, fmt.Sprintf("%s@%.0f", m.Text, m.Confidence))
	}
	return got
}

// TestCheckDigitRequired_Regions enumerates every character a VIN can start with. The check digit
// is compulsory exactly for North America (1-5 and 7) and China (H and L); every other region may
// leave it out. isNorthAmericanVIN, which this replaces, tested 1-5 only.
func TestCheckDigitRequired_Regions(t *testing.T) {
	v := NewValidator()
	const strict = "123457HL"
	for _, c := range "0123456789ABCDEFGHJKLMNPRSTUVWXYZ" {
		vin := string(c) + "ZZZZZ5NZRA000502"
		want := strings.ContainsRune(strict, c)
		if got := v.checkDigitRequired(vin); got != want {
			t.Errorf("checkDigitRequired(%s) = %v, want %v", vin, got, want)
		}
	}
	if v.checkDigitRequired("") {
		t.Error("checkDigitRequired(\"\") = true, want false")
	}
}

// TestOptionalCheckDigit_LabelPlacements is the recall half of #860: a non-North-American VIN with
// no valid check digit and a WMI the table lacks is reported wherever a VIN label sits beside it,
// heads its column or stands on the line above. Every placement scores at least 60, also when
// position 10 is 0; the scores are the validator's own, before the document-level adjustments the
// CLI applies.
func TestOptionalCheckDigit_LabelPlacements(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		want          []string
	}{
		{"VIN colon", "VIN: " + vinWVG, []string{vinWVG + "@100"}},
		{"VIN hash", "VIN# " + vinTMB, []string{vinTMB + "@100"}},
		{"log key", "ts=2024-01-01T10:00:00Z level=info vin=" + vinVF1 + " status=ok", []string{vinVF1 + "@100"}},
		{"lowercase key", "vin: " + vinVF1Bad, []string{vinVF1Bad + "@100"}},
		{"YAML", "owner_ref: A-1\nvin: " + vinWVG + "\nplate: XX-000-01", []string{vinWVG + "@100"}},
		{"JSON", `{"fleet_no": "F001", "vin": "` + vinWVG + `", "plate": "XX-000-01"}`, []string{vinWVG + "@100"}},
		{"snake_case key", "customer_vin: " + vinWVG, []string{vinWVG + "@100"}},
		// No positive keyword matches inside "vinnumber", so only the label boost applies.
		{"camelCase key", `{"vinNumber": "` + vinWVG + `"}`, []string{vinWVG + "@85"}},
		{"VIN in parentheses", "Damage to the vehicle (VIN " + vinVF1 + ") was reported", []string{vinVF1 + "@100"}},
		{"label after the value", vinTMB + " (VIN)", []string{vinTMB + "@100"}},
		{"Markdown table row", "| VIN | " + vinWVG + " |", []string{vinWVG + "@100"}},
		{"Markdown table column", "| fleet_no | vin | plate |\n|---|---|---|\n| F001 | " + vinWVG + " | XX-000-01 |",
			[]string{vinWVG + "@85"}},
		{"French form", "N° VIN : " + vinVF1, []string{vinVF1 + "@100"}},
		{"chassis number", "Chassis no. " + vinTMB, []string{vinTMB + "@100"}},
		{"German label", "Fahrgestellnummer: " + vinWVG, []string{vinWVG + "@85"}},
		{"German label, position 10 is 0", "Fahrgestellnummer: " + vinVF3Zero, []string{vinVF3Zero + "@80"}},
		{"Italian label", "Numero di telaio: " + vinVF1, []string{vinVF1 + "@85"}},
		{"label on the line above", "Vehicle Identification Number\n" + vinWVG, []string{vinWVG + "@85"}},
		{"label above, position 10 is 0", "Vehicle Identification Number\n" + vinVF3Zero, []string{vinVF3Zero + "@80"}},
		{"VIN alone above", "VIN\n" + vinWVG, []string{vinWVG + "@85"}},
		{"label above, bulleted value", "VINs\n- " + vinWVG, []string{vinWVG + "@85"}},
		{"YAML key above", "vin:\n  " + vinWVG, []string{vinWVG + "@85"}},
		{"CSV column", "fleet_no,vin,plate,first_registration\nF001," + vinWVG + ",XX-000-01,2024-01-01",
			[]string{vinWVG + "@85"}},
		{"CSV camelCase header", "fleetNo,vinNumber,plate\nF001," + vinWVG + ",XX-000-01",
			[]string{vinWVG + "@85"}},
		{"lowercase VIN", "vin: " + strings.ToLower(vinWVG), []string{strings.ToLower(vinWVG) + "@100"}},
		// The label word is itself 17 VIN-legal letters; only the value is reported.
		{"label word before the label", "FAHRGESTELLNUMMER (VIN): " + vinWVG, []string{vinWVG + "@100"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := scanVINs(t, tt.content)
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestOptionalCheckDigit_StaysUnreported is the precision half of #860: what a label cannot make a
// VIN, and where no label vouches, nothing is reported. The first group is the known limits the
// issue documents; a fix for one of them is welcome and flips its case.
func TestOptionalCheckDigit_StaysUnreported(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		want          []string
	}{
		// Known limits: no label, or one this rule does not read.
		{"bare", vinWVG, nil},
		{"bare in a sentence", vinTMB + " logged at the depot", nil},
		{"label in trailing prose", vinWVG + " is the vehicle identification number", nil},
		{"later list values", "VINs: " + vinWVG + ", " + vinTMB, []string{vinWVG + "@85"}},
		{"two-column CSV", "vin,plate\n" + vinWVG + ",XX-000-01", nil},
		{"XML element", "<VIN>" + vinWVG + "</VIN>", nil},
		{"HTML table cell", "<td>VIN</td><td>" + vinWVG + "</td>", nil},

		// The check digit is compulsory in North America and China.
		{"China L", "VIN: LSVZZZ5NZRA000502", nil},
		{"China H", "VIN: HZZZZZ5NZRA000504", nil},
		{"US 7", "VIN: 7FAZZZ5NZRA000503", nil},
		{"US 1", "VIN: 1HGZZZ5NZRA000505", nil},
		{"New Zealand 7A, a documented limit", "VIN: 7A1ZZZ5NZRA000506", nil},

		// Shapes a label cannot vouch for.
		{"first character 0", "vin=0VGZZZ5NZRA000502", nil},
		{"all lowercase hex", "VIN: 9f2a9c81d4e7b6a05", nil},
		{"all uppercase hex", "VIN: AF2A9C81D4E7B6A05", nil},
		{"all digits", "VIN: 80351110224678918", nil},
		{"mixed case", "VIN: WvGzzZ5nZrA000502", nil},
		{"camelCase identifier", "VIN: setHeaderValueMap", nil},
		{"label word, no value", "FAHRGESTELLNUMMER (VIN)", nil},

		// The bare word is French and Romanian for wine.
		{"Commande de vin", "Commande de vin " + refToken, nil},
		{"Commande de vins", "Commande de vins " + refToken, nil},
		{"title-case Vin", "un Vin " + refToken, nil},
		{"lowercase vin after the value", refToken + " vin rouge", nil},
		{"lowercase vin alone above", "vin\n" + refToken, nil},

		// The label must be the value's own.
		{"second token after a VIN", "VIN: 1HGBH41JXMN109186 updated " + refToken, []string{"1HGBH41JXMN109186@100"}},
		{"not adjacent", "VIN: pending, ref " + refToken, nil},
		{"key of the next value", "ref " + refToken + " VIN: pending", nil},
		{"prose above", "Please send me the VIN tomorrow\n" + refToken, nil},
		{"above vouches for the first value only", "VIN\n" + vinWVG + " " + refToken, []string{vinWVG + "@85"}},
		{"above, token inside the next field", "VIN\nReference: " + refToken, nil},
		{"above, token inside a sentence", "FAHRGESTELLNUMMER (VIN)\nCommande de vin " + refToken, nil},
		{"unlabelled CSV sibling column", "fleet_no,vin,ref,plate\nF001," + vinWVG + "," + refToken + ",XX-000-01",
			[]string{vinWVG + "@85"}},
		{"unknown WMI random token", "ref ABCDEFGH1JKLMNPRS in log", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := scanVINs(t, tt.content)
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestOptionalCheckDigit_EveryExemptRegion keeps the rule region-shaped: a labelled VIN with no
// valid check digit is reported for every first character whose region does not require the check
// digit, so no later change can fall back to a gate that only a WMI table opens.
func TestOptionalCheckDigit_EveryExemptRegion(t *testing.T) {
	v := NewValidator()
	for _, c := range "0123456789ABCDEFGHJKLMNPRSTUVWXYZ" {
		vin := string(c) + "ZZZZZ5NZRA000502"
		if v.detectManufacturer(vin) != "" || v.checkDigitValid(vin) {
			t.Fatalf("fixture %s must have an unknown WMI and fail the check digit", vin)
		}
		got := scanVINs(t, "VIN: "+vin)
		want := c != '0' && !v.checkDigitRequired(vin)
		if (len(got) == 1) != want || len(got) > 1 {
			t.Errorf("VIN: %s -> %v, want reported=%v", vin, got, want)
		}
	}
}

// TestOptionalCheckDigit_TableWMIScoresUnchanged pins the 26 non-North-American knownWMIs, which
// were admitted without a check digit before #860 and still are, at the confidence they had: the
// label boost is for the new path only, so no existing finding moves.
func TestOptionalCheckDigit_TableWMIScoresUnchanged(t *testing.T) {
	v := NewValidator()
	var wmis []string
	for w := range knownWMIs {
		if !v.checkDigitRequired(w) {
			wmis = append(wmis, w)
		}
	}
	sort.Strings(wmis)
	if len(wmis) != 26 {
		t.Fatalf("expected 26 non-North-American WMIs in knownWMIs, found %d", len(wmis))
	}
	for _, w := range wmis {
		vin := w + "ZZZ1KZRA000500"
		for _, tt := range []struct {
			layout, content string
			want            string
		}{
			{"bare", vin, vin + "@70"},
			{"VIN:", "VIN: " + vin, vin + "@100"},
			{"label above", "Vehicle Identification Number\n" + vin, vin + "@70"},
		} {
			got := scanVINs(t, tt.content)
			if len(got) != 1 || got[0] != tt.want {
				t.Errorf("%s %s: got %v, want [%s]", w, tt.layout, got, tt.want)
			}
		}
	}
}

// TestOptionalCheckDigit_RanksBelowVerified: the base of a label-admitted VIN (60, or 55 when
// position 10 is 0) stays below the 85 a checksum-verified one starts from, and where context does
// not saturate both, the verified VIN outranks it.
func TestOptionalCheckDigit_RanksBelowVerified(t *testing.T) {
	v := NewValidator()
	if base, checks := v.CalculateConfidence(vinWVG); base != 60 || checks["check_digit"] || checks["known_wmi"] {
		t.Errorf("CalculateConfidence(%s) = %.0f %v, want 60 without check digit or known WMI", vinWVG, base, checks)
	}
	if base, _ := v.CalculateConfidence(vinVF3Zero); base != 55 {
		t.Errorf("CalculateConfidence(%s) = %.0f, want 55", vinVF3Zero, base)
	}
	verified := "VF1RJA008RA000506" // vinVF1 with its check digit
	if got := scanVINs(t, "Vehicle Identification Number\n"+verified); len(got) != 1 || got[0] != verified+"@90" {
		t.Errorf("verified VIN under a label above: got %v, want [%s@90]", got, verified)
	}
}

// countTableAnalyses replaces analyzeTable with a counting wrapper for the test's duration.
func countTableAnalyses(t *testing.T) *int {
	t.Helper()
	n := 0
	orig := analyzeTable
	analyzeTable = func(content string) *tabular.Table {
		n++
		return orig(content)
	}
	t.Cleanup(func() { analyzeTable = orig })
	return &n
}

// TestOptionalCheckDigit_TableAnalysisIsLazy: the column-header lookup is the most expensive of the
// three placements, so it runs only for a candidate the other two did not admit, and at most once
// per document.
func TestOptionalCheckDigit_TableAnalysisIsLazy(t *testing.T) {
	calls := countTableAnalyses(t)

	// No candidate on the new path: verified VINs, a table WMI, strict-region and guard failures.
	noNewPath := "VIN: 1HGBH41JXMN109186\nVIN: WVWZZZ1JZ3W386752\nVIN: LSVZZZ5NZRA000502\n" +
		"VIN: 9f2a9c81d4e7b6a05\nref ABCDEFGH1JKLMNPRS0 in log\n"
	scanVINs(t, noNewPath)
	if *calls != 0 {
		t.Errorf("a document with no candidate on the optional-check-digit path ran tabular.Analyze %d times", *calls)
	}

	// New-path candidates that an adjacent label admits never need the header.
	scanVINs(t, "VIN: "+vinWVG+"\nvin="+vinTMB+"\n")
	if *calls != 0 {
		t.Errorf("adjacent labels ran tabular.Analyze %d times", *calls)
	}

	// A CSV of 50 rows whose VINs only the header admits: one analysis for the whole document.
	var b strings.Builder
	b.WriteString("fleet_no,vin,plate\n")
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "F%03d,WVGZZZ5NZRA%06d,XX-000-%02d\n", i, i, i)
	}
	if got := scanVINs(t, b.String()); len(got) != 50 {
		t.Errorf("CSV vin column: got %d findings, want 50", len(got))
	}
	if *calls != 1 {
		t.Errorf("a 50-row CSV ran tabular.Analyze %d times, want 1", *calls)
	}
}

// TestOptionalCheckDigit_DoSGuard keeps the new path linear. A ~1 MB line packed with candidates
// that reach it, labelled and unlabelled, and a 20,000-row CSV whose VINs only the header admits,
// each validate well within the ceiling the single-line guard above uses.
func TestOptionalCheckDigit_DoSGuard(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		want    int
	}{
		{"labelled single line", strings.Repeat("VIN: "+vinWVG+" ", 40000), 40000},
		{"unlabelled single line", strings.Repeat(vinWVG+" ", 55000), 0},
		{"CSV column", "fleet_no,vin,plate\n" + strings.Repeat("F001,"+vinWVG+",XX-000-01\n", 20000), 20000},
		{"label above every value", strings.Repeat("VIN\n"+vinWVG+"\n", 20000), 20000},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			matches, err := NewValidator().ValidateContent(tt.content, "worstcase.txt")
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(matches) != tt.want {
				t.Errorf("got %d matches, want %d", len(matches), tt.want)
			}
			if raceEnabled {
				t.Logf("%d bytes, %d matches (timing assertion skipped under -race)", len(tt.content), len(matches))
				return
			}
			const ceiling = 5 * time.Second
			if elapsed > ceiling {
				t.Fatalf("%d bytes took %s, exceeding %s: the optional-check-digit path may have gone quadratic",
					len(tt.content), elapsed, ceiling)
			}
			t.Logf("%d bytes, %d matches, validated in %s", len(tt.content), len(matches), elapsed)
		})
	}
}
