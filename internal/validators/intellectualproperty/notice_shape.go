package intellectualproperty

import (
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
// rather than a mark: its leading word is a function word ("with trademark"
// with the word in lowercase, "a ™"), or it ends in a lowercase "(r)" (a call argument such as
// basename(r); the registered mark is written "(R)"). The "Registered
// Trademark" form is kept whatever precedes it ("is a registered trademark
// of ..." is the canonical notice).
func isNonNoticeTrademark(match string) bool {
	if strings.HasSuffix(match, "(r)") {
		return true
	}
	if strings.Contains(strings.ToLower(match), "registered") {
		return false
	}
	// A capitalised "Trademark" is a label in a notice ("Amazon Confidential
	// and Trademark."); only the lowercase word is prose about trademarks.
	if strings.HasSuffix(strings.ToLower(match), "trademark") && !strings.HasSuffix(match, "trademark") {
		return false
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
	lower := strings.ToLower(match)
	var rest string
	switch {
	case strings.HasPrefix(match, "©"):
		rest = match[len("©"):]
	case strings.HasPrefix(lower, "(c)"):
		rest = match[len("(c)"):]
	case strings.HasPrefix(lower, "copyright"):
		rest = match[len("copyright"):]
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
		if isNonNoticeTrademark(match) {
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
