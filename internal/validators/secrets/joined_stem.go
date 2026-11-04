// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import "strings"

// Joined stems (#881 Part 4).
//
// A multi-word keyword stem's separator is optional -- `api[_-]?key` -- so every keyword pattern
// matches `apikey: <v>` and `apikey=<v>` and produces a candidate. Its confidence is then decided
// by lineHasAnyPositiveKeyword, which matches positiveKeywords as whole TOKENS: `api` and `key`
// are tokens of `api_key`, `api-key` and `apiKey`, and neither is a token of `apikey`. So the
// candidate counted as uncorroborated, the M24 cap held it at 55 under the keyword path's
// threshold of 60, and it was dropped: `apikey`, `authkey`, `servicekey`, `accountkey`, `dbkey`,
// `databasekey`, `privkey`, `privatekey`, `clientkey`, `accesskey`, `secretkey`, `accesstoken`
// and `APIKEY`, each with `:` or `=`, reported nothing at any confidence, while `api_key` reported
// the same value at 100; `apikey = "<v>"` reached the entropy path and reported 55.
//
// A joined stem on the line (or on the key line that governs a YAML block sequence) now
// corroborates every candidate on it, exactly as a positive keyword does, with one exception.

// joinedSecretStems are the multi-word stems of the keyword patterns written with no separator:
// `apikey` for `api[_-]?key`. Derived from the stem lists, so a multi-word stem added there
// corroborates its joined spelling with no second edit, and only stems the patterns already accept
// are listed. `secretaccesskey` is among them and also opens the AWS secret-key path; with it the
// joined spelling scores as `secret_access_key` does.
var joinedSecretStems = func() []string {
	var out []string
	for _, stem := range keywordPassStems() {
		if strings.Contains(stem, "[_-]?") {
			out = append(out, strings.ReplaceAll(stem, "[_-]?", ""))
		}
	}
	return out
}()

// lineHasJoinedStem reports whether a joined stem is a token of line, under lineHasKeyword's
// boundaries and case folding: `apikey:`, `APIKEY=`, `x-apikey:` and `apikeys:` do, `myapikey=`
// does not.
func lineHasJoinedStem(line string) bool {
	for _, stem := range joinedSecretStems {
		if lineHasKeyword(line, stem) {
			return true
		}
	}
	return false
}

// pathRootedValue reports whether a value is a file-system path rather than a credential: rooted
// (`/`, `./`, `../`, `~/`, or a drive letter and `:\` or `:/`) and containing a `.`. The joined-stem
// lift is withheld from these, and nothing else about them changes.
//
// Without it, certbot's renewal file -- `privkey = /etc/letsencrypt/live/<host>/privkey.pem` -- and
// `apikey = ./conf/abc.pem` would go from no finding to HIGH. `.` is in no base64 or hex alphabet,
// so a rooted value holding one is no base64 or hex secret, and the skip can only ever withhold the
// NEW lift: a value that reports on main through a positive keyword (`private_key = /etc/x.key`)
// keeps reporting, because that keyword corroborates it before this is consulted.
func pathRootedValue(value string) bool {
	v := strings.Trim(value, `"'`)
	rooted := strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") ||
		strings.HasPrefix(v, "~/") ||
		len(v) >= 3 && ('A' <= v[0] && v[0] <= 'Z' || 'a' <= v[0] && v[0] <= 'z') && v[1] == ':' && (v[2] == '\\' || v[2] == '/')
	return rooted && strings.Contains(v, ".")
}
