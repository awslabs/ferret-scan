// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"testing"
)

// Tests for where an unquoted assignment value ends (#932): at an escaped line break that starts
// the next record, and at `&` in a URL fragment's parameters. Values come from synth
// (source_gate_test.go), built at run time.

// texts returns the texts of the assignment-path findings. The quoted-entropy path, which can claim
// a whole quoted fixture string (`"api_key=...\npassword=...\n"`), is not what #932 bounds and is
// left out.
func texts(t *testing.T, v *Validator, content, path string) map[string]bool {
	t.Helper()
	ms, err := v.ValidateContent(content, path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range ms {
		if m.Metadata["detection_method"] != "high_entropy" {
			out[m.Text] = true
		}
	}
	return out
}

func TestValueEndsAtEscapedLineBreak(t *testing.T) {
	v := NewValidator()
	a, b := synth(31), synth(32)
	cases := []struct {
		name, content string
		want          []string // exactly these texts
	}{
		// The repository's own shapes: a short value plus the next record read as one secret.
		{"short value then record", `s := "password=x\nuser=y"` + "\n", nil},
		{"value then trailing escape", `s := "password=y\nuser=z\n"` + "\n", nil},
		{"value then escaped tab", `s := "password=x\n\tuser"` + "\n", nil},
		// A real value keeps its bytes and loses only the break and what follows.
		{"real value then record", `s := "api_key=` + a + `\npassword=` + b + `\n"` + "\n", []string{a, b}},
		// An escape inside a value with no record after it is part of the value.
		{"escape inside a value", "api_key=" + a + `\n` + b + "\n", []string{a + `\n` + b}},
	}
	for _, c := range cases {
		got := texts(t, v, c.content, "fixture.txt")
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("%s: got %v, want %q", c.name, got, w)
			}
		}
	}
}

func TestValueEndsAtFragmentParameter(t *testing.T) {
	v := NewValidator()
	a, b := synth(33), synth(34)
	got := texts(t, v, "redirect: https://app.invalid/cb#access_token="+a+"&refresh_token="+b+"&expires_in=3600\n", "settings.txt")
	if len(got) != 2 || !got[a] || !got[b] {
		t.Errorf("fragment parameters: got %v, want exactly %q and %q", got, a, b)
	}
	// A commented-out assignment (`#` at the start or after a space) is taken whole, as before.
	for _, line := range []string{"#password=" + a + "&x=" + b, "    #db_password=" + a + "&x=" + b} {
		got := texts(t, v, line+"\n", "settings.txt")
		if !got[a+"&x="+b] {
			t.Errorf("%q: got %v, want the whole value", line, got)
		}
	}
	// A quoted value that contains `&` is reported whole (the quoted patterns are not split).
	q := a + "&x=" + b
	if got := texts(t, v, `password = "`+q+`"`+"\n", "settings.txt"); !got[q] {
		t.Errorf("quoted value with &: got %v, want %q whole", got, q)
	}
}
