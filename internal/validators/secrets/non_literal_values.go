// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp"
	"strings"
)

// Values that are not literals (#931, and the marker half of #981).
//
// The keyword-assignment path scores the right-hand side of `secret=`, `password=`, `token=` and
// their relatives as a credential, and the key name supplies the corroboration, so whatever sits on
// the right reads HIGH. Five shapes there carry no secret byte at all, and each read HIGH on main:
//
//   - a regular expression (`trade_secret: "\\b(Confidential|Trade\\s+Secret|...)"`, the shipped
//     config.yaml's own content patterns);
//   - a filesystem path (`private_key=/etc/ssl/private/server.key`);
//   - an expression: a member chain, a call, an index or a concatenation (`config.secret_key`,
//     `process.env.JWT_SECRET`, `os.getenv(DB_PASSWORD_ENV)`, `+joinedValues[2]+`);
//   - ferret-scan's own redaction output (`[API_KEY_OR_SECRET-REDACTED]`, and a `*` mask that kept
//     the value's separators, `****-****-****-****`), so a redacted copy re-scanned as still leaking;
//   - a provider prefix around a placeholder body (`glpat-` + 20 `x`, Slack's documented
//     `xoxb-not-a-real-token-this-will-not-work`).
//
// nonLiteralValue is VALUE-INTRINSIC, like isMaskedValue and typeAnnotationValue: it reads only the
// candidate's own bytes, never the key or the line, so relabelling cannot hide a credential with it,
// and each rule is a shape a generated credential cannot take (a backslash class escape beside a
// regex operator; path segments none of which mixes upper case, lower case and digits; identifier
// words joined by dots; the marker's exact bracket form; a body of one repeated character or of
// placeholder words). It is applied in processScopedCandidates to every candidate except the
// structural sources, whose grammars already decide what a value is. In a file the #753 lexical
// gate parses, the expression shapes are not applied to an unquoted (gateable) candidate the gate
// did not examine: there the gate decides, from the lexer, whether the value starts in code, and a
// value-shape rule on top of it would duplicate (and mask) that decision. A candidate the gate kept
// because its value starts inside a literal -- a Go string holding `process.env.JWT_SECRET` -- is
// text, and is judged here like every value in every other file.
var (
	// reRegexClassEscape is a backslash class escape, single or JSON/YAML-doubled: \b \s \d \w and
	// their negations. Beside a regex operator, it makes the value a regex.
	reRegexClassEscape = regexp.MustCompile(`\\{1,2}[bBsSdDwW]`)

	// reRedactionMarker is the `simple` strategy's marker, `[<TYPE>-REDACTED]` (TYPE in upper case,
	// with `_` or `-` inside: `[API_KEY_OR_SECRET-REDACTED]`, `[CREDIT-CARD-REDACTED]`).
	reRedactionMarker = regexp.MustCompile(`^\[[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)*-REDACTED\]$`)

	// reIdentWord is one identifier word in a conventional case: snake_case, UPPER_SNAKE,
	// camelCase or PascalCase, digits only at the end of a word.
	reIdentWord = regexp.MustCompile(`^(?:[a-z]+(?:_[a-z]+)*|[A-Z]+(?:_[A-Z]+)*|[a-z]+(?:[A-Z][a-z]+)+|(?:[A-Z][a-z]+)+)[0-9]*$`)

	// reCallArgs is what may follow the `(` of a call: identifiers, quoted names and commas.
	reCallArgs = regexp.MustCompile(`^[A-Za-z0-9_.$'" ,]*$`)

	// reIndexedIdent is an identifier with an optional constant index: `joinedValues[2]`.
	reIndexedIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?$`)

	// placeholderBodyWords are words that mark a provider-prefixed body as documentation.
	placeholderBodyWords = map[string]bool{
		"not": true, "fake": true, "example": true, "placeholder": true, "dummy": true, "sample": true,
		"your": true, "replace": true, "changeme": true, "redacted": true,
	}
)

// nonLiteralValue reports whether a candidate value is one of the non-literal shapes above;
// expressions says whether the expression shapes apply (see processScopedCandidates). The
// value is first trimmed of the punctuation a capture carries in from its context: a Markdown code
// span's backtick, a statement's `;` or `,`, a closing `)`, and a trailing `\n` escape (a JSON
// string ending in one, #981).
func nonLiteralValue(v string, expressions bool) bool {
	v = trimValueContext(v)
	if len(v) < 4 {
		return false
	}
	switch {
	case reRedactionMarker.MatchString(v):
		return true
	case isSeparatedMask(v):
		return true
	case strings.ContainsRune(v, '\\') && reRegexClassEscape.MatchString(v) && strings.ContainsAny(v, "()|[]+*?{}"):
		return true
	case pathRootedValue(v) && !strings.ContainsAny(v, " \t") && !anyRandomSegment(v):
		return true
	case expressions && (isMemberChain(v) || isDottedCall(v) || isConcatenation(v)):
		return true
	case providerPlaceholderBody(v):
		return true
	}
	return false
}

// trimValueContext strips the context punctuation nonLiteralValue documents.
func trimValueContext(v string) string {
	for {
		n := len(v)
		v = strings.TrimSuffix(v, `\n`)
		v = strings.TrimRight(v, "`;,)")
		v = strings.TrimLeft(v, "`")
		if len(v) == n {
			return v
		}
	}
}

// isSeparatedMask reports a format-preserving mask: at least 8 `*` and nothing but `*` and the
// separators such a mask keeps (`-`, ` `, `.`, `/`, `_`).
func isSeparatedMask(v string) bool {
	stars := 0
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '*':
			stars++
		case '-', ' ', '.', '/', '_':
		default:
			return false
		}
	}
	return stars >= 8
}

// anyRandomSegment reports whether some path segment mixes upper case, lower case and digits, the
// shape of generated bytes rather than of a name, so a rooted value such as `/Zq7.Kp9xW2` stays a
// candidate. pathRootedValue (joined_stem.go) supplies the rest of the path rule: rooted, and holding
// a `.`, which is in no base64 or hex alphabet.
func anyRandomSegment(v string) bool {
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
		var lo, up, dg bool
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			lo = lo || c >= 'a' && c <= 'z'
			up = up || c >= 'A' && c <= 'Z'
			dg = dg || c >= '0' && c <= '9'
		}
		if lo && up && dg {
			return true
		}
	}
	return false
}

// isMemberChain reports a dotted chain of at least two identifier words, optionally called:
// `config.secret_key`, `this.form.value.password`, `process.env.JWT_SECRET`.
func isMemberChain(v string) bool {
	v = strings.TrimSuffix(v, "()")
	if !strings.Contains(v, ".") {
		return false
	}
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if !reIdentWord.MatchString(p) {
			return false
		}
	}
	return len(parts) >= 2
}

// isDottedCall reports a call whose callee is a dotted chain of identifier words, with identifier or
// quoted-name arguments: `os.getenv(DB_PASSWORD_ENV`, `process.env.get("X"`. An undotted callee is
// not enough: `Pa55(word` is a password with a parenthesis in it.
func isDottedCall(v string) bool {
	open := strings.IndexByte(v, '(')
	if open < 0 || !isMemberChain(v[:open]) {
		return false
	}
	return reCallArgs.MatchString(strings.TrimSuffix(v[open+1:], ")"))
}

// isConcatenation reports an operand of a string concatenation captured with its operators:
// `+joinedValues[2]+`.
func isConcatenation(v string) bool {
	if !strings.HasPrefix(v, "+") && !strings.HasSuffix(v, "+") {
		return false
	}
	inner := strings.Trim(v, "+ ")
	if !reIndexedIdent.MatchString(inner) {
		return false
	}
	name := inner
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	return reIdentWord.MatchString(name)
}

// providerPlaceholderBody reports a provider-prefixed value whose body is a placeholder: one
// character repeated (`glpat-` + 20 `x`), or lower-case words joined by `-` at least one of which
// is a placeholder word (`xoxb-not-a-real-token-this-will-not-work`).
func providerPlaceholderBody(v string) bool {
	for _, p := range allProviderPrefixes {
		body, ok := strings.CutPrefix(v, p)
		if !ok || len(body) < 8 {
			continue
		}
		if strings.Count(body, body[:1]) == len(body) {
			return true
		}
		words := strings.Split(body, "-")
		if len(words) < 3 {
			continue
		}
		placeholder := false
		for _, w := range words {
			if w == "" || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" {
				placeholder = false
				break
			}
			placeholder = placeholder || placeholderBodyWords[w]
		}
		if placeholder {
			return true
		}
	}
	return false
}
