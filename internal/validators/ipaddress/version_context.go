// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import "strings"

// The three shapes of #937, each read as an address at 100 HIGH on main @ 2fb4719:
//
//	where "::EC2" matches IPv6 pattern                        -> ::EC2     (this package's source)
//	matching `4.3.3.2` out of `...LibreOffice/4.3.3.2$...`    -> 4.3.3.2   (CHANGELOG.md)
//	`Application: Acme Server Manager 26.8.0.3` -> ...        -> 26.8.0.3  (CHANGELOG.md)
//
// The first is a fact about the value and is handled by the non-sensitive ranges in
// NewValidator: "::EC2" parses as ::ec2, inside ::/96, the deprecated IPv4-compatible block
// (RFC 4291, 2.5.5) that also holds :: and ::1 and that no current stack assigns to a host. A
// "::"-separated identifier whose segment is all hex letters lands there whenever the segment
// starts the token ("::EC2", "::CE", "::ACE"); isScopedIdentifierAt covers the other form, a
// hex-only head followed by a second "::".
//
// The other two are versions that the line-global keyword escape lifted to HIGH: one "server"
// or "IP_ADDRESS" anywhere on the line clears the ambiguity cap for every quad on it. The last
// two helpers narrow what that escape may lift; neither drops a finding.

// isScopedIdentifierAt reports whether an IPv6-shaped match is directly followed by a second
// "::" run, as the regex's match at the head of "Face::Add::Bead" is.
//
// An IPv6 address holds at most one "::" (RFC 4291, 2.2), so a token carrying two is a
// "::"-separated path (C++ scopes, CloudFormation and Ruby module names), not an address. The
// regex stops in front of the second run because it cannot take a group there, which is why
// this reads the bytes after the match rather than the match itself.
func isScopedIdentifierAt(match, line string, matchEnd int) bool {
	return strings.Contains(match, ":") && strings.HasPrefix(line[matchEnd:], "::")
}

// productVersionValues returns the dotted quads that occur on the line in the product-token
// position (isProductVersionAt) with no port or CIDR suffix, or nil when none does.
//
// A version is often quoted twice on one line, once bare and once where it came from: "matching
// `4.3.3.2` out of `Application: LibreOffice/4.3.3.2$Linux_X86_64`". The per-line dedup reports
// the first occurrence only, so the bare one was scored and the occurrence that says what the
// value is was skipped. The line names the value a version, so every occurrence of it on that
// line is held to the product-version ceiling.
//
// An occurrence with a suffix does not count: "Gateway/203.0.113.42:8443" is an address, because
// a port or CIDR welded to the value outranks the shape before it (hasStructuralSuffixAt), and
// counting it would demote the same address written as a URL elsewhere on the line.
//
// found is the IPv4_Standard pattern's matches on the line, so this costs one pass over
// matches the loop computes anyway and no second regex run.
func productVersionValues(line string, found [][]int) map[string]struct{} {
	var set map[string]struct{}
	for _, loc := range found {
		if !isProductVersionAt(line, loc[0]) || hasStructuralSuffixAt(line, loc[1]) {
			continue
		}
		if set == nil {
			set = make(map[string]struct{}, 1)
		}
		set[line[loc[0]:loc[1]]] = struct{}{}
	}
	return set
}

// hasProductValue reports whether clean is one of the line's product-token versions.
func hasProductValue(set map[string]struct{}, clean string) bool {
	if set == nil {
		return false
	}
	_, ok := set[clean]
	return ok
}

// maxNameWordLen bounds the backward scan in isNamedByNonAddressWordAt, so the per-match work
// stays constant on a line of letters: a product name word is never this long.
const maxNameWordLen = 32

// addressPrepositions are the prepositions that introduce a value rather than name it ("From
// 203.0.113.42 the server replied", "Via 203.0.113.42"). Prepositions are a closed word class
// and never a product name, so the escape applies after one exactly as it does on main. The
// list can only restore the main behaviour, never lower a score.
var addressPrepositions = map[string]struct{}{
	"at": {}, "behind": {}, "by": {}, "for": {}, "from": {}, "in": {}, "into": {}, "of": {},
	"on": {}, "over": {}, "per": {}, "through": {}, "to": {}, "via": {}, "with": {},
}

// isNamedByNonAddressWordAt reports whether the match directly follows a capitalised name that
// is not an IP keyword, with one space between them: "Manager 26.8.0.3", "Chrome 138.0.0.0".
//
// That word is the value's own label, so a keyword elsewhere on the line does not describe this
// value: in "Acme Server Manager 26.8.0.3" the keyword is part of the product name, and in
// "Manager 26.8.0.3 is indistinguishable from Server 10.0.0.1" it labels another value. The
// caller withholds the line-global keyword escape for such a match, which leaves it at the
// context-free cap (75, MEDIUM); a port or CIDR suffix and an IP-naming column header still
// lift it.
//
// The rule is deliberately weaker than the product token. A capitalised word before an address
// is ordinary prose, so the space form gets no ceiling of its own: with no keyword on the line
// it changes nothing. A name is a word of letters with an initial capital and at least one
// lower-case letter; an all-capitals token ("ACCEPT", "SRC") is a log field, not a name. When
// the word is itself a keyword ("Server 203.0.113.42 is down") or a preposition, the escape
// applies as before.
//
// Measured before it was written, with a scratch census of every text file under
// $(go env GOROOT)/src, $(go env GOMODCACHE), this repository and the public corpus by-format/
// (24,689 files): 6 lines carry a public quad after a capitalised non-keyword word with an IP
// keyword elsewhere on the line. 4 are this repository's CHANGELOG "Manager 26.8.0.3" lines (in
// the checkout and in the v2.5.3 module copy) and 2 are an RFC section number after "Per" in a
// net/http comment, which the preposition rule leaves as it was. None is an address.
func (v *Validator) isNamedByNonAddressWordAt(line string, matchIndex int) bool {
	end := matchIndex - 1
	if end < 2 || line[end] != ' ' {
		return false
	}
	start := end
	for start > 0 && end-start < maxNameWordLen && isASCIILetter(line[start-1]) {
		start--
	}
	if end-start < 2 || end-start >= maxNameWordLen {
		return false
	}
	// The word must stand alone: "x9Manager 1.2.3.4" or "a_Name 1.2.3.4" is the tail of a longer
	// token, not a name.
	if start > 0 {
		if c := line[start-1]; c == '_' || (c >= '0' && c <= '9') {
			return false
		}
	}
	if c := line[start]; c < 'A' || c > 'Z' {
		return false
	}
	if strings.IndexFunc(line[start+1:end], func(r rune) bool { return r >= 'a' && r <= 'z' }) < 0 {
		return false
	}
	word := strings.ToLower(line[start:end])
	if _, ok := addressPrepositions[word]; ok {
		return false
	}
	for _, kw := range v.positiveKeywords {
		if word == kw {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
