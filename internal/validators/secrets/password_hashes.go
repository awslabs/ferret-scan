// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/context"
)

// Password hashes: crypt(3) / PHC strings and their relatives (#902 Part C).
//
// A stored password hash is crackable offline, so it is a credential to keep out of a repository,
// but on main nothing could see one except by accident:
//
//   - the keyword patterns need a stem beside the value, so a shadow or htpasswd record, a kickstart
//     `rootpw --iscrypted`, a Dockerfile `chpasswd -e` and a bare line never reached them, and the
//     unquoted capture excludes a leading `$` (#395);
//   - where a stem and quotes did reach the value, the shell-variable veto dropped it whenever the
//     line had a `$` followed by a letter: `"$6$<salt>$..."` reads as the variable `$<salt>` when
//     the salt starts with a letter, so whether a hash was reported depended on its random salt
//     (main: 0/40 md5crypt, 1/40 sha512crypt, 5/40 bcrypt under `password: "<hash>"`).
//
// This file is an ADDITIVE, STRUCTURAL source like the HTTP-auth carriers (http_auth.go): the
// hash's own grammar is the corroboration, so a candidate is scored with structural=true against
// threshold 50, and it is appended after every other path has been arbitrated, dropped when its span
// equals or lies inside a finding another path reported (so a quoted hash some path already reports
// keeps that finding's Type, Text, line and detection_method). Two hooks reach outside it:
//
//   - CalculateConfidence scores a text that IS one exact hash (isPasswordHashText) as a specific
//     pattern, so a test/dev marker demotes it but never drops it; and
//   - processScopedCandidates does not apply the shell-variable veto to such a text, because the
//     grammar is right-bounded and exact: `"$USER$HOST$SUFFIX"` has the `$` shape of a hash but
//     matches no grammar, so it is still vetoed.
//
// The traditional 13-character DES crypt has no marker and is only recognised as field 2 of a
// shadow or passwd record, or of a two-field record in a file named like htpasswd.
const (
	methodPasswordHash   = "password_hash"
	methodPasswordRecord = "password_hash_record"

	passwordHashThreshold = 50.0

	// c64 is the crypt(3) base-64 alphabet.
	c64 = `[./0-9A-Za-z]`
)

var (
	// passwordHashGrammars are the exact, right-bounded hash grammars. Fixed-length tails are
	// bounded in code (hashBounded), since RE2 has no lookahead. Every alternative carries a
	// literal `$`, `{` or `*`, which is the cheap prefilter in findPasswordHashes.
	passwordHashGrammars = []string{
		`\$(?:1|apr1)\$` + c64 + `{1,8}\$` + c64 + `{22}`,                                                 // md5crypt, Apache apr1
		`\$5\$(?:rounds=\d{1,9}\$)?` + c64 + `{1,16}\$` + c64 + `{43}`,                                    // sha256crypt
		`\$6\$(?:rounds=\d{1,9}\$)?` + c64 + `{1,16}\$` + c64 + `{86}`,                                    // sha512crypt
		`(?:bcrypt_sha256\$)?\$2[abxy]?\$\d\d\$` + c64 + `{53}`,                                           // bcrypt (+ Django wrapper)
		`\$g?y\$` + c64 + `+\$` + c64 + `{1,86}\$` + c64 + `{43}`,                                         // yescrypt, gost-yescrypt
		`\$7\$` + c64 + `{14,}\$` + c64 + `{43}`,                                                          // scrypt (libxcrypt)
		`(?:argon2)?\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{11,}\$[A-Za-z0-9+/]{16,}`, // PHC argon2 (+ Django)
		`\$pbkdf2(?:-sha(?:1|256|512))?\$(?:i=)?\d+(?:,l=\d+)?\$[A-Za-z0-9+/.]{8,}\$[A-Za-z0-9+/.]{22,}`,  // passlib pbkdf2
		`pbkdf2_sha(?:1|256)\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/]{27,}={0,2}`,                                // Django pbkdf2
		`\{(?:SSHA|SSHA256|SSHA512|SHA|SHA256|SHA512|SMD5|MD5)\}[A-Za-z0-9+/]{20,}={0,2}`,                 // LDAP
		`\*[0-9A-F]{40}`, // MySQL 4.1+ PASSWORD()
	}

	rePasswordHash      = regexp.MustCompile(strings.Join(passwordHashGrammars, "|"))
	rePasswordHashExact = regexp.MustCompile(`^(?:` + strings.Join(passwordHashGrammars, "|") + `)$`)

	// DES crypt as field 2 of a record. Lock prefixes (`!`, `*`) are outside the capture: a locked
	// account's hash is still crackable offline. `x`, `*`, `!`, `!!` and empty are never 13 bytes.
	reShadowRecord   = regexp.MustCompile(`^\s*[A-Za-z_][A-Za-z0-9_.-]*\$?:[!*]*(` + c64 + `{13})(?::\d*){7}\s*$`)
	rePasswdRecord   = regexp.MustCompile(`^\s*[A-Za-z_][A-Za-z0-9_.-]*\$?:[!*]*(` + c64 + `{13}):\d+:\d+:[^:]*:[^:]*:[^:]*$`)
	reHtpasswdRecord = regexp.MustCompile(`^\s*[^\s:]+:(` + c64 + `{13})\s*$`)
)

// isC64Byte reports whether b is in the crypt(3) base-64 alphabet.
func isC64Byte(b byte) bool {
	return b == '.' || b == '/' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

// hashBounded reports whether the hash at line[s:e] stands alone: not glued to a preceding word or a
// `$` (Make's `$$`), and not followed by a byte that would continue its tail, which would make the
// fixed-length tail a prefix of something longer.
func hashBounded(line string, s, e int) bool {
	if s > 0 {
		p := line[s-1]
		if isAlnumByte(p) || p == '$' || p == '_' || (line[s] == '*' && p == '*') {
			return false
		}
	}
	if e < len(line) {
		n := line[e]
		if isC64Byte(n) || n == '+' || n == '=' {
			return false
		}
	}
	return true
}

// isPasswordHashText reports whether text is, in its entirety, one exact hash grammar. The byte
// prefilter keeps it free for every candidate that cannot be one.
func isPasswordHashText(text string) bool {
	if len(text) < 20 || !strings.ContainsAny(text, "${*") {
		return false
	}
	return rePasswordHashExact.MatchString(text)
}

// findPasswordHashes returns every password hash on the line: each exact grammar occurrence, plus a
// DES crypt in a shadow / passwd record (or an htpasswd record in a file named like one). Linear in
// the line length: one literal-prefiltered regex pass, and the record regexes only on a line with a
// colon.
func (v *Validator) findPasswordHashes(line, path string) []httpAuthCandidate {
	var out []httpAuthCandidate
	if strings.ContainsAny(line, "${*") {
		for _, m := range rePasswordHash.FindAllStringIndex(line, -1) {
			if hashBounded(line, m[0], m[1]) {
				out = append(out, httpAuthCandidate{candidate{text: line[m[0]:m[1]], start: m[0], end: m[1]}, methodPasswordHash})
			}
		}
	}
	if strings.IndexByte(line, ':') > 0 {
		rec := reShadowRecord.FindStringSubmatchIndex(line)
		if rec == nil {
			rec = rePasswdRecord.FindStringSubmatchIndex(line)
		}
		if rec == nil && isHtpasswdPath(path) {
			rec = reHtpasswdRecord.FindStringSubmatchIndex(line)
		}
		if rec != nil {
			s, e := rec[2], rec[3]
			if !v.isObviousPlaceholder(line[s:e]) {
				out = append(out, httpAuthCandidate{candidate{text: line[s:e], start: s, end: e}, methodPasswordRecord})
			}
		}
	}
	return out
}

// isHtpasswdPath reports whether a path's basename names an Apache password file (`.htpasswd`,
// `htpasswd`, `users.htpasswd`), the only place a bare `name:<13 bytes>` line is read as DES crypt.
func isHtpasswdPath(path string) bool {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	return strings.Contains(strings.ToLower(base), "htpasswd")
}

// appendPasswordHashResults scores this line's hash candidates and appends those whose span no
// reported finding already covers, exactly as appendHTTPAuthResults does (structural, threshold 50,
// scored in a call of its own so it can never raise another path's confidence).
func (v *Validator) appendPasswordHashResults(lineResults []spannedMatch, hashes []httpAuthCandidate, line string, lineNum int, originalPath, content string, contextInsights context.ContextInsights, lineHasShellVars bool, envType string, isShellScript bool, govKeyLine string) []spannedMatch {
	cands := make([]scopedCandidate, 0, len(hashes))
	for _, h := range hashes {
		cands = append(cands, scopedCandidate{candidate: h.candidate, method: h.method, threshold: passwordHashThreshold, structural: true})
	}
	scored := v.processScopedCandidates(dedupeScopedBySpan(cands), line, lineNum, originalPath, content, contextInsights, lineHasShellVars, envType, isShellScript, govKeyLine)
	for _, r := range scored {
		if !spanInsideAnyReported(r, lineResults) {
			lineResults = append(lineResults, r)
		}
	}
	return lineResults
}
