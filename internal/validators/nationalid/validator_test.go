// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid

import (
	stdctx "context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Every positive in this file is BUILT at test time from a base and the check-digit functions, so no
// source line holds a label beside a valid value (the self-scan reads this file too). None is a
// published example.

func cpf(base9 string) string { return base9 + cpfCheck(base9) }
func rut(body string) string  { return body + string(rutCheck(body)) }
func cuil(base10 string) string {
	dv, ok := cuilCheck(base10)
	if !ok {
		panic("no CUIL check digit for " + base10)
	}
	return base10 + string(dv)
}
func sin(base8 string) string {
	for c := byte('0'); c <= '9'; c++ {
		if luhn(base8 + string(c)) {
			return base8 + string(c)
		}
	}
	panic("unreachable")
}
func curp(c17 string) string { return c17 + string(curpCheck(c17)) }

func dotCPF(d string) string { return d[0:3] + "." + d[3:6] + "." + d[6:9] + "-" + d[9:] }
func dotRUT(d string) string {
	body, dv := d[:len(d)-1], d[len(d)-1:]
	return body[:len(body)-6] + "." + body[len(body)-6:len(body)-3] + "." + body[len(body)-3:] + "-" + dv
}
func dashCUIL(d string) string { return d[0:2] + "-" + d[2:10] + "-" + d[10:] }
func groupSIN(d, sep string) string {
	return d[0:3] + sep + d[3:6] + sep + d[6:9]
}

// TestCheckDigitsMatchTheIssueAppendix pins each rule to the value #884's appendix computes with its
// Python reference.
func TestCheckDigitsMatchTheIssueAppendix(t *testing.T) {
	if got := cpfCheck("234567890"); got != "92" {
		t.Errorf("cpf_dv = %q, want 92", got)
	}
	if got := curpCheck("FAKE900101HDFXXX0"); got != '9' {
		t.Errorf("curp_dv = %q, want 9", got)
	}
	if got := rutCheck("12345678"); got != '5' {
		t.Errorf("rut_dv = %q, want 5", got)
	}
	if got, ok := cuilCheck("2012345678"); !ok || got != '6' {
		t.Errorf("cuit_dv = %q %v, want 6", got, ok)
	}
	if got := sin("12345678"); got[8] != '2' {
		t.Errorf("luhn_dv(12345678) = %q, want 2", got[8])
	}
	if got := sin("91234567"); got[8] != '5' {
		t.Errorf("luhn_dv(91234567) = %q, want 5", got[8])
	}
}

type finding struct {
	typ  string
	text string
	conf float64
}

func scan(t *testing.T, content string) []finding {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, "x.txt")
	if err != nil {
		t.Fatal(err)
	}
	var out []finding
	for _, m := range ms {
		out = append(out, finding{m.Type, m.Text, m.Confidence})
	}
	return out
}

// TestIssueSection1Lines is #884 §1, the values built from the same bases the issue used.
func TestIssueSection1Lines(t *testing.T) {
	c := cpf("234567890")
	r := rut("12345678")
	cu := cuil("2012345678")
	s1 := sin("12345678")
	s9 := sin("91234567")
	cp := curp("FAKE900101HDFXXX0")
	cases := []struct {
		line string
		want []finding
	}{
		{"CPF nº " + dotCPF(c), []finding{{TypeBRCPF, dotCPF(c), 95}}},
		{"Inscrição no CPF: " + dotCPF(c), []finding{{TypeBRCPF, dotCPF(c), 95}}},
		{"Número do CPF: " + c, []finding{{TypeBRCPF, c, 95}}},
		{"CURP: " + cp, []finding{{TypeMXCURP, cp, 95}}},
		{"curp: " + strings.ToLower(cp), []finding{{TypeMXCURP, strings.ToLower(cp), 95}}},
		{"RUT: " + dotRUT(r), []finding{{TypeCLRUT, dotRUT(r), 95}}},
		{"RUN " + r[:8] + "-" + r[8:], []finding{{TypeCLRUT, r[:8] + "-" + r[8:], 90}}},
		{"CUIL " + dashCUIL(cu), []finding{{TypeARCUIL, dashCUIL(cu), 90}}},
		{"Employee SIN: " + groupSIN(s1, " "), []finding{{TypeCASIN, groupSIN(s1, " "), 95}}},
		{"Social Insurance Number: " + groupSIN(s1, "-"), []finding{{TypeCASIN, groupSIN(s1, "-"), 95}}},
		{"Social Insurance Number: " + groupSIN(s9, " "), []finding{{TypeCASIN, groupSIN(s9, " "), 95}}},
		{"Numéro d’assurance sociale : " + groupSIN(s1, " "), []finding{{TypeCASIN, groupSIN(s1, " "), 95}}},
		{"NAS: " + s1, []finding{{TypeCASIN, s1, 95}}},
		{`{"cpf": "` + dotCPF(c) + `"}`, []finding{{TypeBRCPF, dotCPF(c), 95}}},
		{"Clave Única de Registro de Población " + cp, []finding{{TypeMXCURP, cp, 95}}},
	}
	for _, tc := range cases {
		got := scan(t, tc.line)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: got %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestDecoysReportNothing: the collision lines of #884 (Root cause details), unlabelled valid values,
// check-failing labelled values, the CPF repdigits, the SIN business series, the SSN shape under SIN,
// and values glued into longer numbers.
func TestDecoysReportNothing(t *testing.T) {
	c := cpf("234567890")
	r := rut("12345678")
	s1 := sin("12345678")
	cu := cuil("2012345678")
	cp := curp("FAKE900101HDFXXX0")
	bad := func(v string) string { // the same value with its last digit moved by one
		last := v[len(v)-1]
		if last == '9' {
			return v[:len(v)-1] + "0"
		}
		return v[:len(v)-1] + string(last+1)
	}
	lines := []string{
		// collision lines (#884)
		"Pago sin recargo: " + groupSIN(s1, " "),
		"Sinónimo " + groupSIN(s1, " "),
		"backup to the NAS " + groupSIN(s1, " "),
		"run " + r[:8] + "-" + r[8:] + " times",
		"Ñandú " + r[:8] + "-" + r[8:],
		"RFC 7231 " + groupSIN(s1, " "),
		// valid values, no label
		dotCPF(c), "Total " + dotRUT(r), dashCUIL(cu), groupSIN(s1, " "), cp,
		"build " + dotRUT(r), "Factura " + r[:8] + "-" + r[8:], "Codigo " + dashCUIL(cu),
		// labelled, check digit fails
		"CPF: " + dotCPF(bad(c)), "RUT: " + dotRUT(bad(r)), "CUIL: " + dashCUIL(bad(cu)),
		"SIN: " + groupSIN(bad(s1), " "), "CURP: " + bad(cp),
		// CPF repdigits pass the arithmetic and are never issued
		"CPF: 111.111.111-11", "CPF: 00000000000",
		// SIN: business series (8) and the never-assigned 0, both Luhn-valid
		"SIN: " + sin("82345678"), "SIN: " + sin("02345678"),
		// the SSN's 3-2-4 grouping under a SIN label is not a SIN shape
		"SIN: " + s1[:3] + "-" + s1[3:5] + "-" + s1[5:],
		// glued into a longer token
		"CPF: " + dotCPF(c) + "-1", "CPF: 9" + c, "RUT: v" + dotRUT(r), "SIN: " + groupSIN(s1, " ") + "0",
		// the label of another type
		"RUT: " + dotCPF(c), "CPF: " + dotRUT(r), "CURP: " + groupSIN(s1, " "),
		// lowercase acronym with no colon, label too far away
		"cpf " + dotCPF(c), "CPF " + strings.Repeat("x", 100) + " " + dotCPF(c),
		// CURP with an impossible date, an unknown state, a vowel in the consonant block
		"CURP: " + curp("FAKE901301HDFXXX0"), "CURP: " + curp("FAKE900101HZZXXX0"), "CURP: " + curp("FAKE900101HDFAXX0"),
	}
	for _, line := range lines {
		if got := scan(t, line); len(got) != 0 {
			t.Errorf("%q: got %v, want nothing", line, got)
		}
	}
}

// TestSeededRates is #884 §4's matrix on generated values: 60 per type, printed under its native
// label (all found) and printed with no label (none found).
func TestSeededRates(t *testing.T) {
	rng := rand.New(rand.NewSource(1717))
	digits := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte('0' + rng.Intn(10))
		}
		return string(b)
	}
	gen := map[string]func() (label, printed string){
		TypeBRCPF: func() (string, string) { return "CPF nº ", dotCPF(cpf(digits(9))) },
		TypeCLRUT: func() (string, string) {
			return "RUT: ", dotRUT(rut(fmt.Sprint(5000000 + rng.Intn(21000000))))
		},
		TypeARCUIL: func() (string, string) {
			for {
				base := []string{"20", "23", "24", "27"}[rng.Intn(4)] + digits(8)
				if dv, ok := cuilCheck(base); ok {
					return "CUIL ", dashCUIL(base + string(dv))
				}
			}
		},
		TypeCASIN: func() (string, string) {
			return "Employee SIN: ", groupSIN(sin(string("12345679"[rng.Intn(8)])+digits(7)), " ")
		},
		TypeMXCURP: func() (string, string) {
			for {
				letters := "BCDFGHJKLMNPQRSTVWXYZ"
				c17 := string(letters[rng.Intn(21)]) + string("AEIOU"[rng.Intn(5)]) +
					string(letters[rng.Intn(21)]) + string(letters[rng.Intn(21)]) +
					fmt.Sprintf("%02d%02d%02d", rng.Intn(100), 1+rng.Intn(12), 1+rng.Intn(28)) +
					string("HM"[rng.Intn(2)]) + []string{"DF", "JC", "NL", "NE", "YN"}[rng.Intn(5)] +
					string(letters[rng.Intn(21)]) + string(letters[rng.Intn(21)]) + string(letters[rng.Intn(21)]) +
					string("0A"[rng.Intn(2)])
				if v := curp(c17); validCURP(v) {
					return "CURP: ", v
				}
			}
		},
	}
	for _, typ := range Types {
		labelled, bare := 0, 0
		for i := 0; i < 60; i++ {
			l, v := gen[typ]()
			if got := scan(t, l+v); len(got) == 1 && got[0].typ == typ && got[0].text == v {
				labelled++
			}
			if got := scan(t, "Ref "+v); len(got) != 0 {
				bare++
			}
		}
		if labelled != 60 || bare != 0 {
			t.Errorf("%s: printed+label %d/60 (want 60), printed no label %d/60 (want 0)", typ, labelled, bare)
		}
	}
}

// TestValidRejectsUnknownTypes: Valid is the redaction arms' test, so it must not accept a value for
// a type it does not know.
func TestValidRejectsUnknownTypes(t *testing.T) {
	if Valid("SSN", cpf("234567890")) {
		t.Error("Valid accepted a CPF as an SSN")
	}
	for _, typ := range Types {
		if Valid(typ, "") {
			t.Errorf("Valid(%s, \"\") = true", typ)
		}
	}
}

func TestCancelledContextStops(t *testing.T) {
	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	cancel()
	content := strings.Repeat("CPF nº "+dotCPF(cpf("234567890"))+"\n", 5000)
	ms, err := NewValidator().ValidateContentCtx(ctx, content, "x.txt")
	if err == nil {
		t.Fatalf("cancelled scan returned no error and %d matches", len(ms))
	}
}
