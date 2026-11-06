// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// Tests for #881 Part 1: the entropy path's character class. Secret-shaped values are assembled at
// run time; none is a real credential.

// hyphenatedValue is a base64url-shaped 43-byte value with a hyphen every nine bytes: what a JWK
// member, a base64url token or an `sk-...` key body looks like to the entropy path.
const hyphenatedValue = "Qm7xK" + "-T2vRw9pLz" + "-B4nYc8HdJ" + "-sF6gUa1Ek" + "-Xo3WqVr5"

// TestBase64ClassIsTheCharset is the class proof from #881 as a test: the compiled base64 class
// admits exactly the bytes of base64Charset. Before the fix it was the QuoteMeta of the charset,
// whose `\-_` tail parsed as the range `\`..`_`: `]` and `^` in, `-` out.
func TestBase64ClassIsTheCharset(t *testing.T) {
	v := NewValidator()
	for name, charset := range map[string]string{"base64": v.base64Charset, "hex": v.hexCharset} {
		re, err := syntax.Parse(`[`+regexClassBody(charset)+`]`, syntax.Perl)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		in := func(b byte) bool {
			for i := 0; i+1 < len(re.Rune); i += 2 {
				if rune(b) >= re.Rune[i] && rune(b) <= re.Rune[i+1] {
					return true
				}
			}
			return false
		}
		for b := 0; b < 128; b++ {
			if got, want := in(byte(b)), strings.IndexByte(charset, byte(b)) >= 0; got != want {
				t.Errorf("%s class: byte %q admitted=%v, charset holds it=%v", name, byte(b), got, want)
			}
		}
	}
	// The six bytes #881 names, through the compiled pattern itself.
	for _, c := range []struct {
		b     string
		admit bool
	}{{"-", true}, {"_", true}, {`\`, true}, {"]", false}, {"^", false}, {".", false}} {
		line := `"Qm7xKT2vRw` + c.b + `9pLzB4nYc8"`
		if got := v.base64Pattern.MatchString(line); got != c.admit {
			t.Errorf("base64Pattern on a value holding %q: matched=%v, want %v", c.b, got, c.admit)
		}
	}
	// The pattern the bug produced, kept here so the proof does not depend on history: it admits
	// `]` and rejects `-`, which is what this test fails on if the fix is reverted.
	old := regexp.MustCompile(`["']([` + regexp.QuoteMeta(v.base64Charset) + `]{20,})["']`)
	if old.MatchString(`"`+hyphenatedValue+`"`) || !old.MatchString(`"Qm7xKT2vRw]9pLzB4nYc8"`) {
		t.Fatal("precondition: QuoteMeta of the charset no longer drops '-'; the class proof is stale")
	}
}

// TestHyphenatedQuotedValuesReachTheEntropyPath: a quoted hyphenated value is a candidate, scored
// like its hyphen-free twin. Before #881 none of these reported anything.
func TestHyphenatedQuotedValuesReachTheEntropyPath(t *testing.T) {
	v := NewValidator()
	twin := strings.ReplaceAll(hyphenatedValue, "-", "_")
	for _, c := range []struct {
		name, content, path string
		min, max            float64
	}{
		// Unlabelled: the M24 cap, LOW, exactly as the hyphen-free twin.
		{"unlabelled cfg", `cfg = "` + hyphenatedValue + `"`, "app.txt", 55, 55},
		// A JSON key the quoted keyword pattern cannot see (`"client_secret"`), corroborated by its
		// tokens: only the entropy path could report this value, and it did not.
		{"client_secret member", `{"client_secret": "` + hyphenatedValue + `"}`, "creds.json", 90, 100},
		// An escaped notebook cell, which is why `\` stays in the class.
		{"escaped notebook cell", `{"source": ["key=\"` + hyphenatedValue + `\"\n"]}`, "nb.ipynb", 90, 100},
	} {
		t.Run(c.name, func(t *testing.T) {
			ms, err := v.ValidateContent(c.content+"\n", c.path)
			if err != nil {
				t.Fatal(err)
			}
			if len(ms) != 1 || !strings.Contains(ms[0].Text, hyphenatedValue) {
				t.Fatalf("want one finding over the hyphenated value, got %v", ms)
			}
			if ms[0].Confidence < c.min || ms[0].Confidence > c.max {
				t.Errorf("confidence %v, want %v..%v", ms[0].Confidence, c.min, c.max)
			}
			// The twin with `_` for `-` reported before the fix; the two must agree.
			tw, _ := v.ValidateContent(strings.ReplaceAll(c.content, hyphenatedValue, twin)+"\n", c.path)
			if len(tw) != 1 || tw[0].Confidence != ms[0].Confidence {
				t.Errorf("hyphen-free twin reports %v, the hyphenated value %v", tw, ms)
			}
		})
	}
}

// sriFor is a real integrity value: alg, `-`, and the standard base64 digest of seed.
func sriFor(alg, seed string) string {
	var sum []byte
	switch alg {
	case "sha1":
		s := sha1.Sum([]byte(seed))
		sum = s[:]
	case "sha256":
		s := sha256.Sum256([]byte(seed))
		sum = s[:]
	case "sha384":
		s := sha512.Sum384([]byte(seed))
		sum = s[:]
	case "sha512":
		s := sha512.Sum512([]byte(seed))
		sum = s[:]
	}
	return alg + "-" + base64.StdEncoding.EncodeToString(sum)
}

// TestSubresourceIntegrityDigestIsExact: the skip takes only a whole digest of its algorithm's
// exact length, in standard base64.
func TestSubresourceIntegrityDigestIsExact(t *testing.T) {
	for _, alg := range []string{"sha1", "sha256", "sha384", "sha512"} {
		d := sriFor(alg, "left-pad")
		if !isSubresourceIntegrityDigest(d) {
			t.Errorf("%s digest %q not recognised", alg, d)
		}
		body := strings.TrimPrefix(d, alg+"-")
		for name, not := range map[string]string{
			"one byte short": d[:len(d)-1],
			"one byte long":  d + "A",
			"url-safe bytes": alg + "-" + "-" + body[2:] + "_",
			"upper-case alg": strings.ToUpper(alg) + "-" + body,
			"glued prefix":   "x" + d,
			"no separator":   alg + body,
			"bad base64":     alg + "-" + strings.Repeat("!", len(body)),
		} {
			if isSubresourceIntegrityDigest(not) {
				t.Errorf("%s %s: %q recognised as a digest", alg, name, not)
			}
		}
	}
	for _, other := range []string{"md5-" + base64.StdEncoding.EncodeToString(make([]byte, 16)), "sha224-" + base64.StdEncoding.EncodeToString(make([]byte, 28)), hyphenatedValue} {
		if isSubresourceIntegrityDigest(other) {
			t.Errorf("%q recognised as a digest", other)
		}
	}
}

// TestIntegrityDecoysReportNothing is #881's decoy row: lockfile integrity members, a nix narHash,
// `<script integrity>` and CSP hash sources report nothing. Each is a quoted 28-88 byte
// high-entropy value the widened class admits, so without the digest skip each is a LOW finding.
func TestIntegrityDecoysReportNothing(t *testing.T) {
	v := NewValidator()
	for name, c := range map[string]struct{ content, path string }{
		"npm lockfile": {"{\n  \"packages\": {\n    \"node_modules/left-pad\": {\n      \"version\": \"1.3.0\",\n" +
			"      \"integrity\": \"" + sriFor("sha512", "left-pad") + "\"\n    },\n    \"node_modules/x\": {\n" +
			"      \"integrity\": \"" + sriFor("sha1", "x") + "\",\n      \"checksum\": \"" + sriFor("sha256", "x") + "\"\n    }\n  }\n}", "package-lock.json"},
		"nix narHash":      {"{\n  \"locked\": {\n    \"narHash\": \"" + sriFor("sha256", "nixpkgs") + "\",\n    \"type\": \"github\"\n  }\n}", "flake.lock"},
		"script integrity": {`<script src="/lib.min.js" integrity="` + sriFor("sha384", "lib") + `" crossorigin="anonymous"></script>`, "index.html"},
		"CSP hash sources": {`Content-Security-Policy: script-src 'self' '` + sriFor("sha256", "a") + `' '` + sriFor("sha512", "b") + `'`, "headers.conf"},
	} {
		ms, err := v.ValidateContent(c.content+"\n", c.path)
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != 0 {
			t.Errorf("%s: reported %d finding(s), want none: %v", name, len(ms), ms)
		}
	}
}

// TestHyphenatedObjectKeysAreNotCandidates: a hyphenated object key -- crypto/tls's BoGo test
// configuration names its tests that way -- is not an entropy candidate even on a line a keyword
// corroborates, while the same bytes as a VALUE are, and a hyphen-free key keeps main's behaviour.
func TestHyphenatedObjectKeysAreNotCandidates(t *testing.T) {
	v := NewValidator()
	count := func(line, path string) int {
		ms, err := v.ValidateContent(line+"\n", path)
		if err != nil {
			t.Fatal(err)
		}
		return len(ms)
	}
	for _, line := range []string{
		`        "NoCommonSignatureAlgorithms-TLS12-Fallback": "We don't support the legacy RSA exchange",`,
		`        "MLKEMKeyShareIncludedThird-X25519MLKEM768": "We don't return key shares in client preference order",`,
		`		"CurveTest-Client-X25519MLKEM768-TLS13": "PASS",`,
		`{'` + hyphenatedValue + `' : 'session key'}`,
	} {
		if n := count(line, "bogo_config.json"); n != 0 {
			t.Errorf("%q: %d finding(s), want none", line, n)
		}
	}
	if n := count(`{"session_key": "`+hyphenatedValue+`"}`, "x.json"); n != 1 {
		t.Errorf("the hyphenated value in value position: %d finding(s), want 1", n)
	}
	twin := `{'` + strings.ReplaceAll(hyphenatedValue, "-", "_") + `' : 'session key'}`
	if n := count(twin, "bogo_config.json"); n != 1 {
		t.Errorf("hyphen-free key: %d finding(s), want the one main reports", n)
	}
}

// TestWidenedClassDecoysStayLow: the values the widened class newly admits and nothing labels --
// an alphabet constant, RFC 3492 punycode samples in a Go test table -- are LOW findings whose
// ceiling is PUBLISHED, so the bridge's document-context adjustment cannot lift them: a test table
// of `{"a", "b"},` rows is typed CSV and gets +20 there, which took these to 75 before the ceiling
// was published.
func TestWidenedClassDecoysStayLow(t *testing.T) {
	v := NewValidator()
	for name, c := range map[string]struct{ content, path string }{
		"base64url alphabet": {"const encodeURL = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\"", "encoding.go"},
		"punycode table": {"var punycodeTestCases = [...]struct{ s, encoded string }{\n" +
			"\t{\"z\", \"-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n\"},\n" +
			"\t{\"w\", \"Hello-Another-Way--fc4qua05auwb3674vfr0b\"},\n}", "punycode_test.go"},
	} {
		ms, err := v.ValidateContent(c.content+"\n", c.path)
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) == 0 {
			t.Fatalf("%s: no finding; the value is no longer admitted, so this test proves nothing", name)
		}
		for _, m := range ms {
			ceiling, _ := m.Metadata[ConfidenceCeilingKey].(float64)
			if m.Confidence >= 60 || ceiling <= 0 || ceiling >= 60 {
				t.Errorf("%s: %q at %v with published ceiling %v, want LOW under a published ceiling below 60", name, m.Text, m.Confidence, ceiling)
			}
		}
	}
	// The cap is for the new population only: a hyphen-free unlabelled value keeps main's
	// behaviour, unpublished cap included.
	ms, _ := v.ValidateContent("const encodeStd = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"\n", "encoding.go")
	if len(ms) != 1 {
		t.Fatalf("hyphen-free alphabet: want one finding, got %v", ms)
	}
	if _, published := ms[0].Metadata[ConfidenceCeilingKey]; published {
		t.Errorf("hyphen-free alphabet publishes a ceiling; that would move findings main reports")
	}
}
