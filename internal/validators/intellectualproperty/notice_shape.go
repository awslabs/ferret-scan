package intellectualproperty

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Notice-shape filters (#934). The four IP regexes find a marker word or
// symbol; they cannot tell a notice from source code or markup that merely
// contains the word. These predicates reject the shapes that are never a
// notice: a keyword that is an alternative inside a regular expression, a
// keyword that is one element of a quoted string list, a trademark word or
// symbol whose "owner" is a function word, a lowercase "(r)" call argument,
// and a year-less copyright marker followed by a lowercase word (an atom
// name such as ©xyz, or prose such as "copyright notice"). They run on the
// default and on user-configured patterns alike, because they test the
// match's surroundings, not the pattern that produced it.

// noticeFunctionWords are words that never name a mark's owner. A trademark
// match whose leading word is one of these ("with trademark", "a ™") is
// prose about trademarks, not a mark.
var noticeFunctionWords = map[string]bool{
	"a": true, "an": true, "the": true, "and": true, "or": true, "nor": true,
	"with": true, "without": true, "for": true, "of": true, "to": true,
	"in": true, "on": true, "at": true, "by": true, "as": true, "is": true,
	"are": true, "was": true, "be": true, "no": true, "not": true, "any": true,
	"our": true, "your": true, "its": true, "their": true, "this": true,
	"that": true, "these": true, "those": true, "from": true, "into": true,
	"under": true, "per": true, "via": true, "plus": true, "each": true,
}

// isRegexAlternative reports whether line[start:end] sits inside regular
// expression syntax: delimited on both sides by regex metasyntax, at least
// one of which is unambiguous (an alternation bar or a backslash escape), so
// a parenthesised "(Confidential)" in prose is not mistaken for one.
func isRegexAlternative(line string, start, end int) bool {
	before, after := line[:start], line[end:]
	leftStrong := strings.HasSuffix(before, "|") || strings.HasSuffix(before, `\s+`) ||
		strings.HasSuffix(before, `\s*`) || strings.HasSuffix(before, `\b`)
	left := leftStrong || strings.HasSuffix(before, "(")
	rightStrong := strings.HasPrefix(after, "|") || strings.HasPrefix(after, `\`)
	right := rightStrong || strings.HasPrefix(after, ")")
	return left && right && (leftStrong || rightStrong)
}

// isQuotedListElement reports whether line[start:end] is exactly the content
// of a double-quoted string that has a quoted sibling across a comma, the
// shape of a string-literal list ({"Company Confidential", "Trade Secret"}).
func isQuotedListElement(line string, start, end int) bool {
	if start == 0 || end >= len(line) || line[start-1] != '"' || line[end] != '"' {
		return false
	}
	before := strings.TrimRight(line[:start-1], " \t")
	after := strings.TrimLeft(line[end+1:], " \t")
	if strings.HasPrefix(after, ",") && strings.HasPrefix(strings.TrimLeft(after[1:], " \t"), `"`) {
		return true
	}
	if strings.HasSuffix(before, ",") && strings.HasSuffix(strings.TrimRight(before[:len(before)-1], " \t"), `"`) {
		return true
	}
	return false
}

// isNonNoticeTrademark reports whether a trademark match is prose or code
// rather than a mark: the lowercase word "trademark" after a lowercase word
// ("with trademark", "when trademark"), a symbol after a function word
// ("a ™"), or a lowercase "(r)" (a call argument such as
// basename(r); the registered mark is an uppercase R). The registered-mark
// word form is kept whatever word precedes it: an article before it is the
// usual wording of a real notice.
func isNonNoticeTrademark(match, after string) bool {
	if strings.HasSuffix(match, "(r)") {
		return true
	}
	if strings.Contains(strings.ToLower(match), "registered") {
		return false
	}
	// "... is a trademark of <Owner>" is the canonical notice: it names the
	// owner, so the function word before it does not make it prose.
	if rest := strings.TrimLeft(after, " \t"); len(rest) != len(after) && len(rest) >= 2 &&
		strings.EqualFold(rest[:2], "of") && (len(rest) == 2 || !isWordByte(rest[2])) {
		return false
	}
	// A capitalised "Trademark" is a label in a notice ("Amazon Confidential
	// and Trademark."); only the lowercase word is prose about trademarks.
	if strings.HasSuffix(strings.ToLower(match), "trademark") && !strings.HasSuffix(match, "trademark") {
		return false
	}
	// The lowercase word after a lowercase word ("when trademark is
	// disabled") is prose: the word before a mark is its brand.
	if strings.HasSuffix(match, "trademark") {
		if r, _ := utf8.DecodeRuneInString(match); unicode.IsLower(r) {
			return true
		}
	}
	end := strings.IndexFunc(match, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' })
	if end < 0 {
		end = len(match)
	}
	return noticeFunctionWords[strings.ToLower(match[:end])]
}

// isNonNoticeCopyright reports whether a copyright match has neither a year
// nor an owner: after the marker (©, (c) or "copyright") and any spaces, the
// next character is a lowercase letter. That is an ISO BMFF / QuickTime atom
// name (©xyz, ©nam, ©day), prose ("copyright notice with ..."), or a call
// argument ("f(c) for c in ..."). A notice names its owner with a capital,
// or carries a year.
func isNonNoticeCopyright(match string) bool {
	var rest string
	switch {
	case strings.HasPrefix(match, "©"):
		rest = match[len("©"):]
	case len(match) >= 3 && strings.EqualFold(match[:3], "(c)"):
		rest = match[3:]
	case len(match) >= 9 && strings.EqualFold(match[:9], "copyright"):
		rest = match[9:]
	default:
		return false
	}
	rest = strings.TrimLeft(rest, " \t")
	r, _ := utf8.DecodeRuneInString(rest)
	return unicode.IsLower(r)
}

// isNonNoticeMatch is the single entry point detectPatternsByLine calls for
// each regex match before it becomes a finding. Quoted string lists are
// handled per line by dropQuotedListMatches, because they need the sibling
// matches.
func isNonNoticeMatch(ipType, line string, start, end int) bool {
	match := line[start:end]
	switch ipType {
	case "trademark":
		if isNonNoticeTrademark(match, line[end:]) {
			return true
		}
	case "copyright":
		if isNonNoticeCopyright(match) {
			return true
		}
	}
	return ipType != "patent" && isRegexAlternative(line, start, end)
}

// dropQuotedListMatches removes, from one line's matches, the ones at the
// given indices: two or more IP keywords that are each an element of a quoted
// string list ({"Company Confidential", "Trade Secret"}, a keyword table in
// code or a comment quoting example markers). A single quoted keyword with
// non-IP siblings (a CSV classification cell) is kept; the caller only calls
// this for two or more.
func dropQuotedListMatches(lineMatches map[int][]detector.Match, lineNum int, idx []int) {
	drop := make(map[int]bool, len(idx))
	for _, i := range idx {
		drop[i] = true
	}
	kept := lineMatches[lineNum][:0]
	for i, m := range lineMatches[lineNum] {
		if !drop[i] {
			kept = append(kept, m)
		}
	}
	if len(kept) == 0 {
		delete(lineMatches, lineNum)
		return
	}
	lineMatches[lineNum] = kept
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// laterCopyrightNotice recovers a real notice that a rejected copyright match
// swallowed: the copyright regex's entity class runs on through commas and
// parentheses, so in "copyright notices (e.g., Copyright 2023 Company Name)"
// the leftmost match starts at the prose word and covers the notice too. It
// finds the first later marker inside the match that is followed by a year or
// a capital (the cheap test, so the regex runs at most once per rejected
// match and the scan stays linear) and returns the regex match starting
// there, if it is itself a notice.
func laterCopyrightNotice(ipType string, re *regexp.Regexp, line string, start, end int) (int, int, bool) {
	if ipType != "copyright" || re == nil {
		return start, end, false
	}
	seg := line[start:end]
	for i := 1; i < len(seg); i++ {
		var n int
		switch rest := seg[i:]; {
		case strings.HasPrefix(rest, "©"):
			n = len("©")
		case len(rest) >= 3 && strings.EqualFold(rest[:3], "(c)"):
			n = 3
		case len(rest) >= 9 && strings.EqualFold(rest[:9], "copyright") && !isWordByte(seg[i-1]):
			n = 9
		default:
			continue
		}
		if isNonNoticeCopyright(line[start+i : end]) {
			i += n - 1
			continue
		}
		loc := re.FindStringIndex(line[start+i : end])
		if loc == nil || loc[0] != 0 {
			return start, end, false
		}
		s, e := start+i, start+i+loc[1]
		if isNonNoticeMatch(ipType, line, s, e) {
			return start, end, false
		}
		return s, e, true
	}
	return start, end, false
}
