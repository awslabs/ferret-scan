// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #902 Part A: HTTP authentication credential carriers.
//
// Every value here is built at run time (base64 of a synthetic `user:pass`, a random-shaped opaque
// token, provider prefixes split with buildTestToken) so no committed fixture carries a real-shaped
// credential past the repo's pre-commit hooks or GitHub push protection. These tests fail to build
// on main (findHTTPAuthCredentials and the http_* methods do not exist there) and assert behaviour
// main lacks: on main @ 3df48acd every carrier below reported nothing (measured in the issue's
// 23-file reproduction).

// syntheticPassword is a plausible-looking credential: upper, lower and digit, so it clears
// plausibleUnquotedSecret, and no negative keyword or placeholder substring.
const syntheticPassword = "Zq7mX2kP9wR4sT6vB1nJ"

// opaqueToken is a 32-byte opaque token: long enough (>= 16) and high-entropy enough (>= 3.5) to be
// a Bearer credential rather than a word after the scheme name.
const opaqueToken = "xK7mZ2vX9pL4kR8tB1nW6yC3hJ5dF0sG"

func basicBlob(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func scanSecrets(t *testing.T, content, path string) []detector.Match {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, path)
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", path, err)
	}
	return ms
}

func findByMethod(ms []detector.Match, method string) (detector.Match, bool) {
	for _, m := range ms {
		if dm, _ := m.Metadata["detection_method"].(string); dm == method {
			return m, true
		}
	}
	return detector.Match{}, false
}

// TestHTTPAuthRecall covers every carrier's positive path: the credential is reported, at or above
// the reporting threshold (>= 60 so the documented pre-commit high,medium filter keeps it), with the
// detection_method that names the carrier, and the finding's Text is the credential exactly as
// written.
func TestHTTPAuthRecall(t *testing.T) {
	blob := basicBlob("svc-orders", syntheticPassword)
	cases := []struct {
		name, content, path, method, wantText string
	}{
		{"basic header", "GET /v1/orders HTTP/1.1\nAuthorization: Basic " + blob + "\n", "a.http", methodHTTPBasic, blob},
		{"proxy basic", "Proxy-Authorization: Basic " + blob + "\n", "a.http", methodHTTPBasic, blob},
		{"curl -H basic", `curl -H "Authorization: Basic ` + blob + `" https://api.example.com/` + "\n", "a.sh", methodHTTPBasic, blob},
		{"HAR value line", `   "value": "Basic ` + blob + `"` + "\n", "a.har", methodHTTPBasic, blob},
		{"npmrc _auth", "//registry.example.com/:_auth=" + blob + "\n", ".npmrc", methodNpmrcAuth, blob},
		{"bearer opaque", "Authorization: Bearer " + opaqueToken + "\n", "a.http", methodHTTPBearer, opaqueToken},
		{"token scheme on auth line", "Authorization: Token " + opaqueToken + "\n", "a.http", methodHTTPScheme, opaqueToken},
		{"netrc password same line", "machine api.example.com login svc-orders password " + syntheticPassword + "\n", ".netrc", methodNetrcPassword, syntheticPassword},
		{"curl -u user:pass", "curl -u svc-orders:" + syntheticPassword + " https://api.example.com/\n", "a.sh", methodCurlUserinfo, syntheticPassword},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms := scanSecrets(t, tc.content, tc.path)
			m, ok := findByMethod(ms, tc.method)
			if !ok {
				t.Fatalf("no %s finding; got %d findings %v", tc.method, len(ms), methodsOf(ms))
			}
			if m.Confidence < 60 {
				t.Errorf("confidence %.0f < 60 (pre-commit high,medium filter would drop it)", m.Confidence)
			}
			if m.Text != tc.wantText {
				t.Errorf("Text = %q, want the credential as written %q", m.Text, tc.wantText)
			}
		})
	}
}

// TestNetrcPasswordOnOwnLine covers the multi-line .netrc record: the password sits on its own line
// with no machine/login keyword, so detection relies on the file name.
func TestNetrcPasswordOnOwnLine(t *testing.T) {
	content := "machine api.example.com\n  login svc-orders\n  password " + syntheticPassword + "\n"
	if _, ok := findByMethod(scanSecrets(t, content, "/home/user/.netrc"), methodNetrcPassword); !ok {
		t.Fatal("password on its own line in a .netrc file was not detected")
	}
	// The same record body under a neutral name does not get the netrc password rule (no context word
	// on the password line), so a prose "password foo" elsewhere is not swept up.
	if _, ok := findByMethod(scanSecrets(t, "  password "+syntheticPassword+"\n", "notes.txt"), methodNetrcPassword); ok {
		t.Fatal("a bare 'password <v>' line outside a netrc context reported as netrc_password")
	}
}

// TestBasicCredentialNeverDisclosed is the non-disclosure acceptance criterion: the decoded user and
// password appear in no finding's Text and in no metadata value. The finding carries the base64 blob.
func TestBasicCredentialNeverDisclosed(t *testing.T) {
	blob := basicBlob("svc-orders", syntheticPassword)
	ms := scanSecrets(t, "Authorization: Basic "+blob+"\n", "a.http")
	m, ok := findByMethod(ms, methodHTTPBasic)
	if !ok {
		t.Fatal("no basic finding")
	}
	if strings.Contains(m.Text, syntheticPassword) || strings.Contains(m.Text, "svc-orders") {
		t.Errorf("decoded credential leaked into Text: %q", m.Text)
	}
	for k, v := range m.Metadata {
		if s, isStr := v.(string); isStr && (strings.Contains(s, syntheticPassword) || strings.Contains(s, "svc-orders:")) {
			t.Errorf("decoded credential leaked into metadata[%q] = %q", k, s)
		}
	}
}

// TestBearerTypeDerivedFromToken: a Bearer carrier does not flatten a typed token. A JWT keeps
// JWT_TOKEN and a provider-prefixed token keeps its provider type, because getSecretType reads the
// matched text.
func TestBearerTypeDerivedFromToken(t *testing.T) {
	jwt := jwtExample()
	if typ := NewValidator().getSecretType(jwt); typ != "JWT_TOKEN" {
		t.Errorf("JWT Bearer token typed %q, want JWT_TOKEN", typ)
	}
	gh := buildTestToken("ghp_", "zyxwvu9876543210TSRQPONMLKJIHGFEDCBA")
	if typ := NewValidator().getSecretType(gh); typ != "GITHUB_TOKEN" {
		t.Errorf("GitHub Bearer token typed %q, want GITHUB_TOKEN", typ)
	}
	// And end to end, the Bearer line carrying a JWT reports it as JWT_TOKEN.
	ms := scanSecrets(t, "Authorization: Bearer "+jwt+"\n", "a.http")
	if !hasType(ms, "JWT_TOKEN") {
		t.Errorf("Bearer JWT not reported as JWT_TOKEN; got %v", typesOf(ms))
	}
}

// TestBasicCredentialOK is the decode table from the issue: each shape and its verdict.
func TestBasicCredentialOK(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"valid user:pass", basicBlob("svc-orders", syntheticPassword), true},
		{"missing padding", strings.TrimRight(basicBlob("svc-orders", syntheticPassword), "="), true},
		{"invalid base64", "!!!!not base64!!!!", false},
		{"no colon", base64.StdEncoding.EncodeToString([]byte("nocolonhere12345")), false},
		{"control bytes", base64.StdEncoding.EncodeToString([]byte("svc\x01\x02:pass\x00word")), false},
		{"empty password, prose user", base64.StdEncoding.EncodeToString([]byte("alice:")), false},
		{"rfc7617 worked example (open)", base64.StdEncoding.EncodeToString([]byte("Aladdin:open sesame")), false},
		{"placeholder password", base64.StdEncoding.EncodeToString([]byte("user:your_password_here")), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.basicCredentialOK(tc.token); got != tc.want {
				t.Errorf("basicCredentialOK(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

// TestBearerTokenOK is the Bearer shape gate: short or low-entropy words after the scheme name are
// not credentials.
func TestBearerTokenOK(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"opaque 32-byte token", opaqueToken, true},
		{"too short", "abc123", false},
		{"low entropy repeat", strings.Repeat("ab", 12), false},
		{"placeholder", "your_token_here_000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.bearerTokenOK(tc.token); got != tc.want {
				t.Errorf("bearerTokenOK(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

// TestHTTPAuthDecoysSilent locks the negatives: scheme framing with no credential reports nothing.
// These mirror the secrets_structural_carrier_decoys golden case.
func TestHTTPAuthDecoysSilent(t *testing.T) {
	blob := basicBlob("Aladdin", "open sesame") // RFC 7617 example, dropped by negative keyword "open"
	decoys := []string{
		`WWW-Authenticate: Basic realm="orders"`,
		`AuthType Basic`,
		`Authorization: Basic ${ORDERS_BASIC_AUTH}`,
		`Authorization: Bearer $ORDERS_TOKEN`,
		`Authorization: Bearer {{ORDERS_TOKEN}}`,
		`Authorization: Basic <base64-encoded-credentials>`,
		`Authorization: Basic ` + blob,
		`Proxy-Authorization: Bearer <token>`,
	}
	for _, line := range decoys {
		t.Run(line, func(t *testing.T) {
			for _, method := range []string{methodHTTPBasic, methodHTTPBearer, methodHTTPScheme, methodNpmrcAuth, methodNetrcPassword, methodCurlUserinfo} {
				if _, ok := findByMethod(scanSecrets(t, line+"\n", "a.http"), method); ok {
					t.Errorf("decoy reported a %s finding: %q", method, line)
				}
			}
		})
	}
}

// --- helpers ---

func methodsOf(ms []detector.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		dm, _ := m.Metadata["detection_method"].(string)
		out = append(out, dm)
	}
	return out
}

func typesOf(ms []detector.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Type)
	}
	return out
}

func hasType(ms []detector.Match, typ string) bool {
	for _, m := range ms {
		if m.Type == typ {
			return true
		}
	}
	return false
}

// jwtExample builds a syntactically valid JWT whose header base64url-decodes to JSON declaring an
// algorithm, so isJWTToken accepts it. Built at run time; it authenticates nothing.
func jwtExample() string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"svc-orders"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("synthetic-signature-bytes-0001"))
	return hdr + "." + pay + "." + sig
}
