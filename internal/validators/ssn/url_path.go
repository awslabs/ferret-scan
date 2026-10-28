// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import "strings"

// A nine-digit run inside a web URL's path is a resource identifier, not an SSN (#804).
//
// The candidate pattern's bare alternative is \b\d{9}\b, and RE2's \b treats '-' and '/' as word
// boundaries, so the disambiguating tail of a profile slug is admitted as a bare SSN. Nothing
// downstream read where the digits sit. Measured on main @ 0501dcd, --checks SSN --confidence all,
// with <TAB> standing for a tab:
//
//	Profile: https://www.linkedin.com/in/michael-o-291135150                          SSN 50 LOW
//	Candidate<TAB>Michael O<TAB>https://www.linkedin.com/in/michael-o-291135150<TAB>
//	    555-0100<TAB>m.o@mail.invalid                                                  SSN 95 HIGH
//
// The 95 is the base 70 of a bare nine-digit value with a valid area number plus the +25 that
// isEnhancedTabularData awards any line with two tabs, and a tabular line is never capped. The same
// row as a .docx paragraph scores the same 95: the document path adds nothing to it.
//
// isPathComponent is a VETO, so every condition below narrows it toward the measured shape. A
// vetoed value is never reported and therefore never redacted, so the cost of a condition that is
// too wide is an SSN left in cleartext, while the cost of one that is too narrow is a false positive
// that main already reports today.

// isPathComponent reports whether the candidate at line[start:end] is a component of a web URL's
// path. All of these must hold:
//
//  1. The candidate is the bare nine-digit form. The hyphenated and spaced forms are how an SSN is
//     written down, and they are untouched.
//  2. The byte before it is '-', the word joint of a slug, or '/', a path separator. A value after
//     '=' is a query parameter's value: "?ssn=291135150" is a plausible place for a real SSN and
//     keeps its score.
//  3. It is not followed by '.' and a letter or digit. That is a file name, "291135150.pdf", and a
//     scanned document named by its holder's SSN is a real leak shape whether or not it is served
//     over https. A sentence's closing period ("...-291135150.") is followed by nothing or by a
//     space, so it does not count.
//  4. An http:// or https:// earlier on the line opens the URL holding it (see urlPathScanner).
//
// The caller may still keep a vetoed value when the line names the identifier: see
// labelsTheIdentifier.
func (s *urlPathScanner) isPathComponent(start, end int) bool {
	if end-start != 9 || start < 1 {
		return false
	}
	if prev := s.line[start-1]; prev != '-' && prev != '/' {
		return false
	}
	if end+1 < len(s.line) && s.line[end] == '.' && isASCIIAlnum(s.line[end+1]) {
		return false
	}
	return s.inPath(start)
}

// urlPathScanner decides condition 4 of isPathComponent for the candidates of one line, in a
// single forward pass.
//
// The candidate is inside a URL's path when, scanning back from it, an http:// or https:// is
// reached before any byte that ends a URL token (endsURLToken) and before any '?' or '#'. That is,
// the scheme opens the same URL, and the candidate is in its host or path rather than its query or
// fragment.
//
// Web schemes only. s3://, file://, ftp:// and smb:// name STORED FILES, where a file named by an SSN
// is the leak shape condition 3 protects, and none of them is where the false positive was found.
//
// Candidates arrive in increasing offset order (FindAllStringIndex), so the scan never rewinds and a
// line costs O(len(line) + candidates). Scanning back from each candidate instead would be
// O(candidates x token length), and this validator's 1MB single-line regression input carries about
// 87K candidates.
type urlPathScanner struct {
	line string
	pos  int // next byte not yet examined

	// Offsets of the most recent of each event before pos, or -1 when there has been none.
	stop   int // a byte that ends a URL token
	scheme int // the ':' of an http:// or https://
	query  int // a '?' or '#'
}

// newURLPathScanner returns a scanner for line, or nil when line holds no "://" at all, which is
// every line the rule cannot apply to.
func newURLPathScanner(line string) *urlPathScanner {
	if !strings.Contains(line, "://") {
		return nil
	}
	return &urlPathScanner{line: line, stop: -1, scheme: -1, query: -1}
}

// inPath reports whether the byte at start lies in the host or path of a web URL. start must not be
// smaller than on any previous call.
func (s *urlPathScanner) inPath(start int) bool {
	for ; s.pos < start; s.pos++ {
		switch c := s.line[s.pos]; {
		case endsURLToken(c):
			s.stop = s.pos
		case c == '?' || c == '#':
			s.query = s.pos
		case c == ':' && isWebScheme(s.line, s.pos):
			s.scheme = s.pos
		}
	}
	return s.scheme > s.stop && s.query < s.scheme
}

// endsURLToken reports whether b cannot sit between a URL's scheme and a component of the same URL.
//
// Whitespace and control bytes, and the bytes RFC 3986 never allows in a URL: '"', '<', '>', '\',
// '^', '`', '{', '|', '}'. The quote "'" is allowed by the RFC but delimits strings in code, and ','
// and ';' are allowed but separate CSV and JSON fields far more often than they sit inside a path. A
// minified JSON object has no whitespace at all, so without these a URL in one field would claim a
// value in the next: {"url":"https://a.invalid/x","file":"/w2/291135150"}.
//
// A byte at or above 0x80 does not end a token, so an internationalized path still counts as one URL.
func endsURLToken(b byte) bool {
	if b <= ' ' || b == 0x7f {
		return true
	}
	switch b {
	case '"', '\'', '<', '>', '\\', '^', '`', '{', '|', '}', ',', ';':
		return true
	}
	return false
}

// isWebScheme reports whether the ':' at line[i] begins the "://" of an http or https URL. The scheme
// is case-insensitive (RFC 3986 §3.1).
func isWebScheme(line string, i int) bool {
	if !strings.HasPrefix(line[i:], "://") {
		return false
	}
	return (i >= 4 && strings.EqualFold(line[i-4:i], "http")) ||
		(i >= 5 && strings.EqualFold(line[i-5:i], "https"))
}

func isASCIIAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// urlVetoLabels are the positive keywords that NAME an identifier number, as opposed to the domain
// words ("social", "benefits", "payroll", "hr", ...) that are also in the positive list.
//
// They are what labelsTheIdentifier reads, and the distinction is the reason this is a subset rather
// than the whole positive list: "Social: https://www.linkedin.com/in/..." is how a resume labels a
// social-media profile, and on main it already scores 95 HIGH from "social" alone. Letting every
// positive keyword lift the veto would keep that false positive. newLineContext caches these with
// the scored keywords, so the lookup below never rescans the line.
var urlVetoLabels = []string{
	"ssn", "social security", "ein", "tax id", "taxpayer id", "identification number",
	"employee id", "federal id", "government id", "national id", "personal id",
}

// labelsTheIdentifier reports whether this match's line, or its column header, names an identifier
// number, which keeps a value the URL veto would otherwise drop.
//
// The URL position is evidence that the digits are a resource ID. A label such as "SSN" beside it is
// stronger evidence the other way ("SSN: https://hr.invalid/people/291135150"), and when the two
// disagree this validator keeps the finding: being wrong then costs a false positive that main
// already reports, not an SSN left in cleartext. With a label present the value is scored exactly as
// on main.
func (v *Validator) labelsTheIdentifier(lc *lineContext) bool {
	for _, kw := range urlVetoLabels {
		if lc.keywordOnLine[kw] {
			return true
		}
		if lc.columnHeader != "" && containsKeyword(lc.columnHeader, kw) {
			return true
		}
	}
	return false
}
