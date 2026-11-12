// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid_test

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
	"github.com/awslabs/ferret-scan/v2/internal/validators/nationalid"
)

// labelled builds one labelled, valid value per type at test time from the validator's own scan of a
// generated line, so this file holds no literal label-and-value pair.
func positives(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	v := nationalid.NewValidator()
	// Each candidate is a base the test completes by trying every final symbol; the one the
	// validator reports is the valid value.
	bases := map[string]struct{ label, base string }{
		nationalid.TypeBRCPF:  {"CPF nº ", "234.567.890-9"},
		nationalid.TypeCLRUT:  {"RUT: ", "12.345.678-"},
		nationalid.TypeARCUIL: {"CUIL: ", "20-12345678-"},
		nationalid.TypeCASIN:  {"SIN: ", "123 456 78"},
		nationalid.TypeMXCURP: {"CURP: ", "FAKE900101HDFXXX0"},
	}
	for typ, b := range bases {
		for _, c := range "0123456789K" {
			ms, err := v.ValidateContent(b.label+b.base+string(c), "x.txt")
			if err != nil {
				t.Fatal(err)
			}
			if len(ms) == 1 && ms[0].Type == typ {
				out[typ] = ms[0].Text
				break
			}
		}
		if out[typ] == "" {
			t.Fatalf("no valid %s completes %q", typ, b.base)
		}
	}
	return out
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// TestRedactionArmsKeepNothingAndNeverReDetect: under every strategy, no letter or digit of the value
// survives in place, format_preserving and synthetic keep the separators, and a synthetic replacement
// fails the check digit, so the redacted copy re-scans clean (#669). 10,000 synthetic draws per type.
func TestRedactionArmsKeepNothingAndNeverReDetect(t *testing.T) {
	for typ, value := range positives(t) {
		simple, err := replacement.Generate(value, typ, redactors.RedactionSimple, nil)
		if err != nil || simple != "["+typ+"-REDACTED]" {
			t.Errorf("%s simple: %q %v", typ, simple, err)
		}
		fp, err := replacement.Generate(value, typ, redactors.RedactionFormatPreserving, nil)
		if err != nil || len(fp) != len(value) {
			t.Fatalf("%s format_preserving: %q %v", typ, fp, err)
		}
		for i := 0; i < len(value); i++ {
			if isAlnum(value[i]) && fp[i] != '*' || !isAlnum(value[i]) && fp[i] != value[i] {
				t.Errorf("%s format_preserving %q -> %q: byte %d", typ, value, fp, i)
				break
			}
		}
		for n := 0; n < 10000; n++ {
			syn, err := replacement.Generate(value, typ, redactors.RedactionSynthetic, redactors.NewSyntheticScope())
			if err != nil {
				t.Fatalf("%s synthetic: %v", typ, err)
			}
			if len(syn) != len(value) {
				t.Fatalf("%s synthetic %q -> %q: length changed", typ, value, syn)
			}
			for i := 0; i < len(value); i++ {
				if isAlnum(value[i]) != isAlnum(syn[i]) || !isAlnum(value[i]) && syn[i] != value[i] {
					t.Fatalf("%s synthetic %q -> %q: shape changed at byte %d", typ, value, syn, i)
				}
			}
			if nationalid.Valid(typ, syn) {
				t.Fatalf("%s synthetic %q -> %q passes the check digit", typ, value, syn)
			}
		}
		// The same number with and without separators takes one replacement in one scope.
		scope := redactors.NewSyntheticScope()
		a, _ := replacement.Generate(value, typ, redactors.RedactionSynthetic, scope)
		bare := strings.Map(func(r rune) rune {
			if r < 0x80 && isAlnum(byte(r)) {
				return r
			}
			return -1
		}, value)
		b, _ := replacement.Generate(bare, typ, redactors.RedactionSynthetic, scope)
		if nationalid.Key(a) != nationalid.Key(b) {
			t.Errorf("%s: %q and %q took different replacements %q, %q", typ, value, bare, a, b)
		}
	}
}

func TestMaskKeepsSeparatorsOnly(t *testing.T) {
	if got := nationalid.Mask("12.345.678-K"); got != "**.***.***-*" {
		t.Errorf("Mask = %q", got)
	}
}
