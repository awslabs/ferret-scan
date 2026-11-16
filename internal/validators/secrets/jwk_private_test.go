// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/json"
	"math/rand"
	"testing"
)

// Tests for JWK private members (jwk_private.go, #902 Part C). Every member value is random
// base64url drawn at run time from a fixed seed: no committed byte is key material.

const tB64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func tJSON(t *testing.T, v any, indent bool) string {
	t.Helper()
	var b []byte
	var err error
	if indent {
		b, err = json.MarshalIndent(v, "", "  ")
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// TestJWKPrivateMembersReported: every private member of an RSA, EC, OKP and oct key, pretty or on
// one line, single key or JWKS, is reported at >= 60 with its own detection_method; public members
// are not reported by this source.
func TestJWKPrivateMembersReported(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(9025))
	rsa := map[string]any{"kty": "RSA", "e": "AQAB", "n": tRand(r, tB64U, 342), "kid": "svc-orders"}
	for _, m := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		rsa[m] = tRand(r, tB64U, 171)
	}
	okp := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": tRand(r, tB64U, 43), "d": tRand(r, tB64U, 43)}
	ec := map[string]any{"kty": "EC", "crv": "P-256", "x": tRand(r, tB64U, 43), "y": tRand(r, tB64U, 43), "d": tRand(r, tB64U, 43)}
	oct := map[string]any{"kty": "oct", "alg": "HS256", "k": tRand(r, tB64U, 43)}
	cases := []struct {
		name    string
		content string
		private []string
	}{
		{"rsa pretty", tJSON(t, rsa, true), []string{"d", "p", "q", "dp", "dq", "qi"}},
		{"okp one line", tJSON(t, okp, false), []string{"d"}},
		{"ec jwks pretty", tJSON(t, map[string]any{"keys": []any{ec}}, true), []string{"d"}},
		{"oct one line", tJSON(t, oct, false), []string{"k"}},
	}
	for _, c := range cases {
		var key map[string]any
		switch c.name {
		case "rsa pretty":
			key = rsa
		case "okp one line":
			key = okp
		case "ec jwks pretty":
			key = ec
		default:
			key = oct
		}
		ms, err := v.ValidateContent(c.content, "jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range c.private {
			val := key[name].(string)
			m := findText(ms, val)
			if m == nil || m.Confidence < 60 || m.Metadata["detection_method"] != methodJWKPrivateMember {
				t.Errorf("%s: member %q not reported at >= 60 by %s: %+v", c.name, name, methodJWKPrivateMember, m)
			}
		}
		for _, name := range []string{"n", "x", "y"} {
			if val, ok := key[name].(string); ok {
				if m := findText(ms, val); m != nil && m.Metadata["detection_method"] == methodJWKPrivateMember {
					t.Errorf("%s: public member %q reported as private", c.name, name)
				}
			}
		}
	}
}

// TestJWKPrivateMembersNeedKty: a `d` in an object with no known `kty`, a public-only key, and a
// `d` in a sibling object of a key are not reported by this source.
func TestJWKPrivateMembersNeedKty(t *testing.T) {
	r := rand.New(rand.NewSource(9026))
	d := tRand(r, tB64U, 43)
	for name, content := range map[string]string{
		"no kty":         `{"alg": "ES256", "d": "` + d + `"}`,
		"unknown kty":    `{"kty": "XYZ", "d": "` + d + `"}`,
		"sibling object": `{"key": {"kty": "EC", "x": "` + tRand(r, tB64U, 43) + `"}, "meta": {"d": "` + d + `"}}`,
		"public only":    `{"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "` + d + `"}]}`,
		"short value":    `{"kty": "EC", "d": "AQAB"}`,
	} {
		if got := findJWKPrivateMembers(content); len(got) != 0 {
			t.Errorf("%s: got %d spans, want 0", name, len(got))
		}
	}
	// Nested and truncated: the member of the key object is found; an unclosed document still
	// reports what it holds.
	nested := `{"keys": [{"kty": "EC", "d": "` + d + `", "x": "` + tRand(r, tB64U, 43) + `"}]}`
	if got := findJWKPrivateMembers(nested); len(got) != 1 || nested[got[0].start:got[0].end] != d {
		t.Errorf("nested: got %v", got)
	}
	truncated := `{"kty": "OKP", "d": "` + d + `", "x": "`
	if got := findJWKPrivateMembers(truncated); len(got) != 1 || truncated[got[0].start:got[0].end] != d {
		t.Errorf("truncated: got %v", got)
	}
	// Escaped quotes inside a string do not end it.
	escaped := `{"note": "a \"kty\" here", "kty": "RSA", "d": "` + d + `"}`
	if got := findJWKPrivateMembers(escaped); len(got) != 1 {
		t.Errorf("escaped: got %v", got)
	}
}
