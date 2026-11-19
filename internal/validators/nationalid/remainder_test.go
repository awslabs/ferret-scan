// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// The tests of #884's remainder (MX_RFC, labelled check-failing values at LOW, the bare RUT) and of
// #1021 (filler words between label and value). Values are built at test time, as in validator_test.go.

func lastMoved(v string) string { // the same value with its last digit moved by one
	last := v[len(v)-1]
	if last == '9' {
		return v[:len(v)-1] + "0"
	}
	return v[:len(v)-1] + string(last+1)
}

// scanMatches returns the full matches, for the metadata the finding type drops.
func scanMatches(t *testing.T, line string) []map[string]any {
	t.Helper()
	ms, err := NewValidator().ValidateContent(line, "x.txt")
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, m := range ms {
		md := map[string]any{"type": m.Type, "text": m.Text, "confidence": m.Confidence}
		for k, v := range m.Metadata {
			md[k] = v
		}
		out = append(out, md)
	}
	return out
}

// TestRFCVerifierMatchesSampleRFCs: the SAT's check-digit arithmetic reproduces the last symbol of
// seven sample RFCs (a company's and a person's), recalled by the author and not read from an SAT page.
func TestRFCVerifierMatchesSampleRFCs(t *testing.T) {
	for _, r := range []string{"EKU9003173C9", "URE180429TM6", "IIA040805DZ4", "KAHO641101B39", "CACX7605101P8", "XIQB891116QE4", "GODE561231GR8"} {
		if got := rfc(r[:len(r)-1]); got != r {
			t.Errorf("rfc(%s) = %s", r[:len(r)-1], got)
		}
		if !Valid(TypeMXRFC, r) || !Valid(TypeMXRFC, strings.ToLower(r)) {
			t.Errorf("%s is not valid", r)
		}
		if Valid(TypeMXRFC, lastMoved(r)) && !strings.HasSuffix(r, "A") {
			t.Errorf("%s with its last symbol moved is valid", r)
		}
	}
}

// TestGenericRFCs: the SAT's two generic RFCs are reported at LOW 15 under a published ceiling, not
// dropped (redaction rewrites reported values only) and not HIGH. XAXX fails the verifier, XEXX passes.
func TestGenericRFCs(t *testing.T) {
	for _, tc := range []struct {
		rfc   string
		check bool
	}{{"XAXX010101000", false}, {"XEXX010101000", true}} {
		ms := scanMatches(t, "RFC: "+tc.rfc)
		if len(ms) != 1 || ms[0]["type"] != TypeMXRFC || ms[0]["confidence"] != 15.0 ||
			ms[0]["confidence_ceiling"] != 15.0 || ms[0]["checksum_valid"] != tc.check {
			t.Errorf("%s: %v", tc.rfc, ms)
		}
	}
	if got := scan(t, "XAXX010101000"); len(got) != 0 {
		t.Errorf("unlabelled generic RFC reported: %v", got)
	}
	// One digit away is no generic RFC: it is judged by the verifier like any other.
	if ms := scanMatches(t, "RFC: XAXX010101001"); len(ms) != 1 || ms[0]["confidence"] != 40.0 {
		t.Errorf("a neighbour of the generic RFC: %v", ms)
	}
}

// TestMXRFCShapes: persona moral (12) and física (13), the labels, and the shapes that are not RFCs.
func TestMXRFCShapes(t *testing.T) {
	moral := rfc("ABC010203XY")   // 11 symbols + verifier, padded: a company's 12-symbol RFC
	fisica := rfc("ABCD010203XY") // 12 symbols + verifier
	amp := rfc("A&B010203XY")
	for _, line := range []string{
		"RFC: " + moral, "RFC " + fisica, "rfc: " + strings.ToLower(fisica), "Registro Federal de Contribuyentes " + fisica,
		"Empresa RFC: " + amp,
	} {
		ms := scanMatches(t, line)
		if len(ms) != 1 || ms[0]["type"] != TypeMXRFC || ms[0]["confidence"].(float64) < 90 || ms[0]["check_digit_valid"] != true {
			t.Errorf("%q: %v", line, ms)
		}
	}
	for _, line := range []string{
		fisica, "Total " + fisica, // no label
		"RFC: " + rfc("ABCD011303XY"), // month 13
		"RFC: " + rfc("ABCD010230XY"), // 30 February
		"RFC: AB" + moral,             // 14 symbols
		"RFC: " + fisica[:12],         // 12 symbols with a person's date column
		"RFC 7231 and RFC 2119",       // the protocol documents
		"RFC: " + fisica + "9",        // glued
		"Nuestro RFC es muy importante, ya que identifica a cada persona", // prose with the label
	} {
		if got := scan(t, line); len(got) != 0 {
			t.Errorf("%q: got %v, want nothing", line, got)
		}
	}
}

// TestCheckFailingLabelledIsLow: a labelled value of the right shape and a wrong check digit is
// reported at LOW with checksum_valid=false (and no check_digit_valid), under a published ceiling.
func TestCheckFailingLabelledIsLow(t *testing.T) {
	c, r, cu := cpf("234567890"), rut("12345678"), cuil("2012345678")
	s1, cp, rf := sin("12345678"), curp("FAKE900101HDFXXX0"), rfc("ABCD010203XY")
	for _, tc := range []struct{ line, typ, text string }{
		{"CPF nº " + dotCPF(lastMoved(c)), TypeBRCPF, dotCPF(lastMoved(c))},
		{"CPF: " + lastMoved(c), TypeBRCPF, lastMoved(c)},
		{"RUT: " + dotRUT(lastMoved(r)), TypeCLRUT, dotRUT(lastMoved(r))},
		{"CUIL " + dashCUIL(lastMoved(cu)), TypeARCUIL, dashCUIL(lastMoved(cu))},
		{"Employee SIN: " + groupSIN(lastMoved(s1), " "), TypeCASIN, groupSIN(lastMoved(s1), " ")},
		{"CURP: " + lastMoved(cp), TypeMXCURP, lastMoved(cp)},
		{"RFC: " + lastMoved(rf), TypeMXRFC, lastMoved(rf)},
	} {
		ms := scanMatches(t, tc.line)
		if len(ms) != 1 || ms[0]["type"] != tc.typ || ms[0]["text"] != tc.text || ms[0]["confidence"] != 40.0 ||
			ms[0]["checksum_valid"] != false || ms[0]["confidence_ceiling"] != 40.0 {
			t.Errorf("%q: %v", tc.line, ms)
		}
		if _, has := ms[0]["check_digit_valid"]; has {
			t.Errorf("%q: a failing value carries check_digit_valid: %v", tc.line, ms)
		}
	}
	// A valid value keeps exactly the keys it had before this change: no checksum_valid, no ceiling.
	ms := scanMatches(t, "CPF nº "+dotCPF(c))
	if len(ms) != 1 || ms[0]["check_digit_valid"] != true {
		t.Fatalf("valid CPF: %v", ms)
	}
	for _, k := range []string{"checksum_valid", "confidence_ceiling"} {
		if _, has := ms[0][k]; has {
			t.Errorf("a valid value carries %s", k)
		}
	}
}

// TestCheckFailingStillNeedsShapeAndLabel: the structural rules and the label still gate the LOW report.
func TestCheckFailingStillNeedsShapeAndLabel(t *testing.T) {
	r, cp := rut("12345678"), curp("FAKE900101HDFXXX0")
	for _, line := range []string{
		"CPF: 111.111.111-11",              // repdigit
		"SIN: 023456789", "SIN: 823456789", // never-assigned and business series
		"RUT: 0" + r[:7] + "-1",                         // a RUT body never starts with 0
		"CUIL: 30-12345678-1",                           // not a personal prefix
		"CURP: " + curp("FAKE901301HDFXXX0")[:17] + "1", // month 13
		"CURP: " + curp("FAKE900101HZZXXX0")[:17] + "1", // unknown state
		"CURP: " + lastMoved(cp) + "0",                  // glued
		"CPF: 000.123.456-78",                           // the shape DrawSynthetic writes
		"Pago sin recargo: 123456789",                   // "sin" without capitals or a colon
	} {
		if got := scan(t, line); len(got) != 0 {
			t.Errorf("%q: got %v, want nothing", line, got)
		}
	}
}

// TestBareRUT: a RUT printed with no separators, under its label, 9 symbols (8-digit body) or 8
// (7-digit body); a K verifier too.
func TestBareRUT(t *testing.T) {
	r9, r8 := rut("12345678"), rut("5123456")
	for _, tc := range []struct {
		line, text string
		conf       float64
	}{
		{"RUT: " + r9, r9, 95}, {"RUN " + r8, r8, 90}, {"RUT: " + lastMoved(r9), lastMoved(r9), 40},
	} {
		got := scan(t, tc.line)
		if fmt.Sprint(got) != fmt.Sprint([]finding{{TypeCLRUT, tc.text, tc.conf}}) {
			t.Errorf("%q: got %v", tc.line, got)
		}
	}
	var withK string
	for b := 5000000; withK == "" && b < 9000000; b++ {
		if v := rut(fmt.Sprint(b)); strings.HasSuffix(v, "K") {
			withK = v
		}
	}
	if got := scan(t, "RUT: "+withK); len(got) != 1 || got[0].text != withK {
		t.Errorf("bare RUT with K %q: %v", withK, got)
	}
	if got := scan(t, "Total "+r9+" y "+r8); len(got) != 0 {
		t.Errorf("unlabelled bare RUTs: %v", got)
	}
}

// TestFillerWordsBetweenLabelAndValue is #1021: up to two filler words between label and value.
func TestFillerWordsBetweenLabelAndValue(t *testing.T) {
	s1, c := sin("12345678"), cpf("234567890")
	g := groupSIN(s1, " ")
	found := []string{
		"Our Social Insurance Number is " + g,
		"Employee SIN number is: " + g,
		"Social Insurance Number: " + g, // its own last word is a filler word
		"Social Insurance Number no. " + g,
		"SIN is " + g,
		"Mi CPF es " + dotCPF(c),
		"O CPF é " + dotCPF(c),
		"O número do CPF é " + dotCPF(c),
		"CPF no. " + dotCPF(c),
		"CPF nº " + dotCPF(c),
	}
	for _, line := range found {
		if got := scan(t, line); len(got) != 1 {
			t.Errorf("%q: got %v, want one finding", line, got)
		}
	}
	for _, line := range []string{
		"Our Social Insurance Number is not " + g,        // "not" is not filler
		"Our Social Insurance Number is the number " + g, // three words
		"SIN number is no. " + g,                         // three words
		"Nuestro CPF es el " + dotCPF(c),                 // "el" is not filler
		"O CPF e " + dotCPF(c),                           // unaccented "e" is "and"
		"cpf es " + dotCPF(c),                            // a lower-case acronym needs a strong separator
		"Pago sin es " + g,                               // "sin" lower-case
		"The SIN is the one in the " + g,                 // a sentence
	} {
		if got := scan(t, line); len(got) != 0 {
			t.Errorf("%q: got %v, want nothing", line, got)
		}
	}
}

// TestDrawSyntheticNeverReDetectsAtLow: a synthetic replacement, written beside its label, is neither
// HIGH nor the LOW check-failing report: 5,000 draws per type, bare and in the value's own separators.
func TestDrawSyntheticNeverReDetectsAtLow(t *testing.T) {
	rng := rand.New(rand.NewSource(884))
	keys := map[string]string{
		TypeBRCPF: "23456789092", TypeCLRUT: "123456785", TypeARCUIL: "20123456786",
		TypeCASIN: "123456782", TypeMXCURP: "FAKE900101HDFXXX09",
		TypeMXRFC: rfc("ABCD010203XY"), "MX_RFC_COMPANY_AMP": rfc("A&B010203XY"),
	}
	labels := map[string]string{
		TypeBRCPF: "CPF: ", TypeCLRUT: "RUT: ", TypeARCUIL: "CUIL: ", TypeCASIN: "SIN: ", TypeMXCURP: "CURP: ",
		TypeMXRFC: "RFC: ", "MX_RFC_COMPANY_AMP": "RFC: ",
	}
	for name, value := range keys {
		typ := strings.TrimSuffix(name, "_COMPANY_AMP")
		for n := 0; n < 5000; n++ {
			syn := DrawSynthetic(typ, Key(value), rng.Intn)
			rendered := RenderSynthetic(value, syn)
			if got := scan(t, labels[name]+rendered); len(got) != 0 {
				t.Fatalf("%s: synthetic %q (from %q) re-detects as %v", name, rendered, value, got)
			}
			if got := scan(t, labels[name]+syn); len(got) != 0 {
				t.Fatalf("%s: canonical synthetic %q re-detects as %v", name, syn, got)
			}
		}
	}
}
