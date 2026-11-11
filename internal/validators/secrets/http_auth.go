// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
)

// HTTP authentication credential carriers (#902 Part A).
//
// `Authorization: Basic <base64>`, `Authorization: Bearer <token>`, a `(Proxy-)Authorization`
// line's other schemes, the `.npmrc` `_auth=` line, the `.netrc` `password` field and `curl -u
// user:pass` are ordinary ways to write a credential that no existing path could see: the keyword
// patterns anchor on a stem immediately before `=`/`:` (a scheme word is followed by a SPACE, and
// `auth` is not a token inside `Authorization`), the entropy path matches only QUOTED runs, and the
// provider literals match a vendor prefix. Measured on main @ 3df48acd, 0 of 19 header forms
// reported while the same value under `DB_PASSWORD=` reported at 100, so `--enable-redaction`
// exited 0 with every value in cleartext.
//
// These detectors are STRUCTURAL in the sense scopedCandidate.structural means (like the URI
// user-info source, #766): the value's position in a known grammar is its corroboration, so each
// finding is exempt from the M24 55-cap and scored against the entropy path's threshold of 50, and
// a test/dev marker demotes but does not drop it. They are never gated by the #753 lexical gate: a
// header or a record is a literal, not an expression. The matched TEXT is always the credential as
// written (for Basic/`_auth`, the base64 blob, never the decoded `user:pass`), so getSecretType
// types a JWT or a provider-prefixed Bearer token from its own bytes, and the decoded value never
// leaves this file.
//
// Precision is the issue's own bar: on 61,229 public files each filtered rule hit <= 5 lines. The
// filtering is the decode-and-validate pipeline below (a Basic blob must base64-decode to a
// printable `user:pass` whose credential clears plausibleUnquotedSecret, the placeholder tables and
// the negative-keyword list; a Bearer/scheme token needs >= 16 bytes and Shannon entropy >= 3.5),
// not the regexes, which are deliberately permissive so a credential is not missed by its framing.

const (
	methodHTTPBasic     = "http_basic_auth"
	methodNpmrcAuth     = "npmrc_auth"
	methodHTTPBearer    = "http_bearer_auth"
	methodHTTPScheme    = "http_auth_scheme"
	methodNetrcPassword = "netrc_password"
	methodCurlUserinfo  = "curl_userinfo"

	// httpAuthThreshold is the reporting threshold for every carrier here: 50, the entropy path's,
	// because these are structural sources like URI user info and not keyword patterns (threshold
	// 60). A base64 or token value scored 85 by CalculateConfidence clears it comfortably; a
	// test/dev penalty lands it at 55-60, still reported, never dropped.
	httpAuthThreshold = 50.0

	// bearerMinLen and bearerMinEntropy gate an opaque Bearer/scheme token so the scheme word in
	// prose ("bearer bonds", "reset the token") cannot carry a short low-entropy word to a finding.
	// 16 bytes is RFC 6750's practical floor for a b64token; 3.5 bits/byte rejects a dictionary word
	// while accepting any generated credential.
	bearerMinLen     = 16
	bearerMinEntropy = 3.5
)

// The scheme/record grammars. Each anchors on a literal scheme word or field name so Go's regexp
// prefilter stays cheap, and each is right-bounded by its own charset. None is header-anchored:
// a HAR file, a Postman collection and a `fetch` call put the header NAME on a different line or in
// a different key from the `Basic <blob>` value.
var (
	// A1: `Basic <base64>`. The capture is the base64 blob (padding included). `\b` keeps it from
	// firing inside a word; the decode pipeline is what rejects `Basic authentication` and the like.
	reBasicScheme = regexp.MustCompile(`(?i)\bbasic[ \t]+([A-Za-z0-9+/]{8,}={0,2})`)

	// A1': the `.npmrc` `_auth` line, `//registry/:_auth=<base64>` or a bare `_auth=<base64>`. Same
	// decode pipeline as Basic: the value is a base64 `user:pass`. `_authToken` is a Bearer-shaped
	// opaque token handled by A2's shape rules on its own line, not here.
	reNpmrcAuth = regexp.MustCompile(`(?:^|[:/])_auth[ \t]*=[ \t]*(\S+)`)

	// A2: `Bearer <token>`. The charset is RFC 6750 b64token plus `-._~`, which by construction
	// excludes every template shape the issue lists -- `$VAR`, `${...}`, `{{...}}`, `<...>` -- so a
	// template never produces a capture. Shape (length + entropy) is checked in code.
	reBearerScheme = regexp.MustCompile(`(?i)\bbearer[ \t]+([A-Za-z0-9._~+/-]{16,}={0,2})`)

	// A3: the `Token` scheme, evaluated ONLY on a `(Proxy-)Authorization` line (reAuthorizationLine),
	// where the precision table shows it costs nothing; unanchored it cost 4 FPs. Same shape gate as
	// Bearer.
	reSchemeToken       = regexp.MustCompile(`(?i)\btoken[ \t]+([A-Za-z0-9._~+/-]{16,}={0,2})`)
	reAuthorizationLine = regexp.MustCompile(`(?i)(?:proxy-)?authorization[ \t]*:`)

	// A4: the `.netrc` `password` field, `password <value>` (space-delimited, unlike the keyword
	// path's `password:`/`password=`). Only when the line also carries a netrc keyword
	// (machine/login/default/account/macdef) or the file is a .netrc/_netrc, so a prose
	// "password foo" does not fire.
	reNetrcPassword = regexp.MustCompile(`(?i)\bpassword[ \t]+(\S+)`)
	reNetrcContext  = regexp.MustCompile(`(?i)\b(?:machine|login|default|account|macdef)\b`)

	// A5: `curl -u user:pass` (and --user/-U/--proxy-user). The password (group 2) is the credential;
	// the user is not reported.
	reCurlUser = regexp.MustCompile(`(?:^|[ \t])(?:-u|--user|-U|--proxy-user)(?:[ \t]+|=)["']?([^\s:"']+):([^\s"']+)`)

	// reHTTPAuthPrefilter is the cheap whole-line gate: unless one scheme word / field name is
	// present, none of the detailed scans can match, so the common line pays one DFA pass and
	// returns. A superset of every detector's anchor.
	reHTTPAuthPrefilter = regexp.MustCompile(`(?i:basic|bearer|token|_auth|password)|--user|--proxy-user|[ \t]-[uU][ \t=]`)
)

// httpAuthCandidate is a credential this source found, carrying the detection_method that names the
// carrier it came from.
type httpAuthCandidate struct {
	candidate
	method string
}

// findHTTPAuthCredentials returns every HTTP-authentication credential on the line. The span is the
// credential exactly as written; a value appearing twice on a line is two candidates. Linear in the
// line length (a bounded number of literal-anchored regex passes, each linear).
func (v *Validator) findHTTPAuthCredentials(line, path string) []httpAuthCandidate {
	netrc := isNetrcPath(path)
	if !netrc && !reHTTPAuthPrefilter.MatchString(line) {
		return nil
	}

	var out []httpAuthCandidate

	// A1: Basic <base64 user:pass>.
	for _, m := range reBasicScheme.FindAllStringSubmatchIndex(line, -1) {
		s, e := m[2], m[3]
		if v.basicCredentialOK(line[s:e]) {
			out = append(out, httpAuthCandidate{candidate{text: line[s:e], start: s, end: e}, methodHTTPBasic})
		}
	}

	// A1': .npmrc _auth=<base64 user:pass>.
	for _, m := range reNpmrcAuth.FindAllStringSubmatchIndex(line, -1) {
		s, e := m[2], m[3]
		if v.basicCredentialOK(strings.Trim(line[s:e], `"'`)) {
			out = append(out, httpAuthCandidate{candidate{text: line[s:e], start: s, end: e}, methodNpmrcAuth})
		}
	}

	// A2: Bearer <token>, anywhere.
	for _, m := range reBearerScheme.FindAllStringSubmatchIndex(line, -1) {
		s, e := m[2], m[3]
		if v.bearerTokenOK(line[s:e]) {
			out = append(out, httpAuthCandidate{candidate{text: line[s:e], start: s, end: e}, methodHTTPBearer})
		}
	}

	// A3: Token <token>, only on a (Proxy-)Authorization line.
	if reAuthorizationLine.MatchString(line) {
		for _, m := range reSchemeToken.FindAllStringSubmatchIndex(line, -1) {
			s, e := m[2], m[3]
			if v.bearerTokenOK(line[s:e]) {
				out = append(out, httpAuthCandidate{candidate{text: line[s:e], start: s, end: e}, methodHTTPScheme})
			}
		}
	}

	// A4: .netrc password <value>.
	if netrc || reNetrcContext.MatchString(line) {
		for _, m := range reNetrcPassword.FindAllStringSubmatchIndex(line, -1) {
			s, e := m[2], m[3]
			if v.unquotedCarrierValueOK(line[s:e]) {
				out = append(out, httpAuthCandidate{candidate{text: line[s:e], start: s, end: e}, methodNetrcPassword})
			}
		}
	}

	// A5: curl -u user:pass (password only).
	for _, m := range reCurlUser.FindAllStringSubmatchIndex(line, -1) {
		s, e := m[4], m[5]
		if v.unquotedCarrierValueOK(line[s:e]) {
			out = append(out, httpAuthCandidate{candidate{text: line[s:e], start: s, end: e}, methodCurlUserinfo})
		}
	}

	return out
}

// basicCredentialOK reports whether a Basic/`_auth` base64 blob decodes to a printable `user:pass`
// whose credential is a plausible secret. The credential is the password, or the user name when the
// password is empty. The DECODED value is only inspected here; it is never stored on the finding, so
// it cannot reach any output format, the debug log or --explain (an acceptance criterion).
func (v *Validator) basicCredentialOK(token string) bool {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(token, "="))
		if err != nil {
			return false
		}
	}
	s := string(raw)
	if !isPrintableASCII(s) {
		return false
	}
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return false // Basic is user:pass; no colon is not a credential pair
	}
	cred := s[colon+1:]
	if cred == "" {
		cred = s[:colon]
	}
	if !plausibleUnquotedSecret(cred) || v.isObviousPlaceholder(cred) || v.matchesGlobalTestPatterns(cred) {
		return false
	}
	// The whole decoded pair is checked against the negative-keyword list: RFC 7617's worked example
	// decodes to `Aladdin:open sesame`, whose password clears plausibleUnquotedSecret (its space
	// defeats the all-lowercase rule) but carries the negative keyword "open".
	for _, nk := range v.negativeKeywords {
		if lineHasKeyword(s, nk) {
			return false
		}
	}
	return true
}

// bearerTokenOK reports whether an opaque Bearer/scheme token is long and random enough to be a
// credential rather than a word after the scheme name.
func (v *Validator) bearerTokenOK(token string) bool {
	if len(token) < bearerMinLen {
		return false
	}
	if shannonEntropyBytes(token) < bearerMinEntropy {
		return false
	}
	return !v.isObviousPlaceholder(token) && !v.matchesGlobalTestPatterns(token)
}

// unquotedCarrierValueOK applies the unquoted-value filters to a netrc/curl credential: the same
// plausibility and placeholder gates the unquoted assignment path uses, so a `password x`, a
// reference or a placeholder does not report.
func (v *Validator) unquotedCarrierValueOK(value string) bool {
	return plausibleUnquotedSecret(value) && !v.isObviousPlaceholder(value) && !v.matchesGlobalTestPatterns(value)
}

// isNetrcPath reports whether a path names a .netrc / _netrc file, where the password field reports
// wherever it sits (the records span lines). Basename only, so a directory called netrc elsewhere in
// the path is not mistaken for the file.
func isNetrcPath(path string) bool {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.ToLower(base)
	return base == ".netrc" || base == "_netrc" || base == "netrc"
}

// isPrintableASCII reports whether s is non-empty and every byte is printable ASCII (0x20-0x7e), the
// shape a real decoded `user:pass` has; control bytes or high bytes mean the blob was not Basic
// credentials.
func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// shannonEntropyBytes is the per-byte Shannon entropy of s, used to tell an opaque token from a word.
// Byte-wise (not over a named charset) because a Bearer token's alphabet is not fixed.
func shannonEntropyBytes(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}
