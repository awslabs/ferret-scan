// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp"
	"strings"
)

// The detect-secrets allowlist pragma is not a credential label (#933).
//
// ferret-scan appends `# pragma: allowlist secret` to every `hash:` line it writes into a
// suppression file (internal/suppressions, annotateHashesWithAllowlistPragma), and other projects
// use the same detect-secrets convention by hand. On main the pragma's own word `secret` counted as a
// positive keyword on its line, so it RAISED the value beside it: a quoted 64-hex rule hash read 55
// (LOW) alone and 95-100 (HIGH) with the pragma appended, 18 such lines in this repository.
//
// The decision here is the narrow one the issue allows: the pragma's words stop counting, and the
// pragma does NOT exempt its line. A comment anyone can type is not a suppression mechanism (that
// is what a suppression rule, with its reason and review, is for), so a real credential on a line
// carrying the pragma is reported exactly as it would be without the comment. blankAllowlistPragma
// overwrites the pragma's words with spaces of the same length before any path reads the line, so
// every span, line number and suppression hash on the line is unchanged.
var reAllowlistPragma = regexp.MustCompile(`(?i)pragma:[ \t]*allowlist(?:[ \t]+nextline)?[ \t]+secret`)

// blankAllowlistPragma returns line with every allowlist pragma's words replaced by spaces. The
// literal prefilter keeps the common line free of a regex pass.
func blankAllowlistPragma(line string) string {
	if !strings.Contains(line, "pragma") && !strings.Contains(line, "PRAGMA") && !strings.Contains(line, "Pragma") {
		return line
	}
	return reAllowlistPragma.ReplaceAllStringFunc(line, func(m string) string { return strings.Repeat(" ", len(m)) })
}
