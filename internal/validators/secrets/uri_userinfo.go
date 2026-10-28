// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"math"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/context"
)

// Credentials in URI user info (#766).
//
// `scheme://user:PASSWORD@host` and `https://TOKEN@host` are how DATABASE_URL, broker, proxy and
// registry URLs and JDBC DSNs carry a credential, and before this file no capture path could see
// one. Every other path anchors on something a URI does not have: a provider prefix, a key stem
// right before `=` or `:` (a URI password follows `user:`), or a quoted run without `:`, `@` or
// `.`. Measured through the CLI, 0 of 185 cases (25 schemes x 7 placements, plus lengths) reported
// anything while `DB_PASSWORD=<pw>` reported the same password at 100. Only findings reach the
// redactor, so a DATABASE_URL-only .env got no redacted copy and --pre-commit-mode exited 0.
//
// findURIUserinfo parses the RFC 3986 authority instead of matching a scheme list or a label. It
// is hand-written rather than net/url.Parse for two measured reasons: net/url reads
// `jdbc:postgresql://u:p@h/db` as an opaque `jdbc:` URI with no user, rejects the comma host list
// of `mongodb://u:p@h1:27017,h2/db` ("invalid port"), and both of those errors quote the whole raw
// URI, password included, which is a leak waiting for the first caller that logs an error.
//
// The tables below are the whole grammar and the whole disposition policy, in the order #766
// states them, so each row can be checked against the issue line by line.

// uriUserinfoMethod is the detection_method of every finding this source produces.
const uriUserinfoMethod = "uri_userinfo"

// uriUserinfoThreshold is the reporting threshold, 50: the entropy path's, because this is a
// structural source like it and not a keyword pattern (whose threshold is 60).
const uriUserinfoThreshold = 50.0

// uriUserinfoLowCeiling is the ceiling of a LOW disposition: 55, the same number as the M24 cap
// and unlabelledHexIdentifierCeiling, just under MEDIUM. It is published as the finding's
// ConfidenceCeilingKey because the document bridge adds its context adjustment AFTER this
// validator returns, and a ceiling applied only here would be lifted straight back.
const uriUserinfoLowCeiling = 55.0

// The authority grammar.
const (
	// uriAuthorityTerminators end the authority: RFC 3986's own `/ ? #`, plus the bytes that end a
	// URI written inside text -- whitespace, quotes, a backtick, angle brackets and a backslash.
	// None of them can appear in user info or a host unencoded.
	uriAuthorityTerminators = "/?#\"'`<>\\ \t\r\n\v\f"

	// uriAuthorityTrailingTrim is trimmed from the END of an authority, repeatedly: prose and code
	// put punctuation straight after a URI (`postgres://u:<pw>@host, then ...`, `connect(uri)`).
	// Only the end is trimmed, which is always the host's side of the last `@`, so it can shorten a
	// host but never a password.
	uriAuthorityTrailingTrim = ",;.!)]}"

	// uriUserinfoPunct is the punctuation RFC 3986 section 3.2.1 allows in user info besides ALPHA,
	// DIGIT and pct-encoded: unreserved `- . _ ~`, sub-delims `! $ & ' ( ) * + , ; =`, and `:`.
	// `@` is added because the split is at the LAST `@`, so an unencoded `@` in a password stays
	// in the password, as Go's net/url and WHATWG split it. Templates fail here by grammar alone:
	// `${X}` and double-brace forms carry braces, `%s` and `%(pw)s` are not valid pct-encodings,
	// and `<password>` ends the authority before its `@`.
	uriUserinfoPunct = "-._~!$&'()*+,;=:@"

	// uriRegNamePunct is the punctuation allowed in a host name: unreserved only. RFC 3986 also
	// allows sub-delims in a reg-name, but no resolvable host uses them, and `,` is taken by the
	// host list (`mongodb://u:p@h1:27017,h2:27017/db`).
	uriRegNamePunct = "-._~"
)

// uriUserOnlyMinLen, uriUserOnlyMinEntropy: a user name with no password is a candidate only when
// it is shaped like a token -- at least 20 bytes, letters and digits only and both present, and at
// least 3.5 bits per byte -- so `git@`, `alice@` and `app_user@` stay silent.
const (
	uriUserOnlyMinLen     = 20
	uriUserOnlyMinEntropy = 3.5
)

// uriDisposition is what a value's own bytes decide about it. No disposition reads the line, the
// key, the scheme or the host: every one of those is written by the author of the line, and a
// demotion an author can trigger is a suppression an author can trigger (TM-11).
type uriDisposition uint8

const (
	// uriScored: scored like any other candidate, every adjustment applying.
	uriScored uriDisposition = iota
	// uriLow: kept, and capped at uriUserinfoLowCeiling. Never dropped: `postgres:postgres` can be
	// the real password of a real database, and only a reported value is redacted.
	uriLow
	// uriNoCandidate: the bytes carry no secret at all.
	uriNoCandidate
)

// uriDefaultVocabulary is the default-credential vocabulary, matched against the WHOLE value in
// any case.
var uriDefaultVocabulary = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true, "secret": true,
	"guest": true, "postgres": true, "root": true, "admin": true, "changeme": true,
	"user": true, "username": true, "default": true, "test": true, "example": true, "demo": true,
}

// uriValueRules is the disposition table. The first row that matches decides; a value no row
// matches is uriScored. user is the user name for a password, or "" for a token in the user name.
var uriValueRules = []struct {
	name        string
	matches     func(value, user string) bool
	disposition uriDisposition
}{
	{"a reference: the whole value is $NAME or $(...)", func(v, _ string) bool { return isWholeReference(v) }, uriNoCandidate},
	{"mask output: only '*', or a provider prefix and then only '*' (#807)", func(v, _ string) bool { return isMaskedValue(v) }, uriNoCandidate},
	{"default-credential vocabulary", func(v, _ string) bool { return len(v) <= 8 && uriDefaultVocabulary[strings.ToLower(v)] }, uriLow},
	{"the user name repeated", func(v, u string) bool { return u != "" && strings.EqualFold(v, u) }, uriLow},
	{"implausible as a secret", func(v, _ string) bool { return !plausibleUnquotedSecret(v) || shoutySentinel.MatchString(v) }, uriLow},
}

// uriValueDisposition applies uriValueRules to one value.
func uriValueDisposition(value, user string) uriDisposition {
	for _, r := range uriValueRules {
		if r.matches(value, user) {
			return r.disposition
		}
	}
	return uriScored
}

// uriUserinfoCandidate is a candidate from this source, with its LOW disposition.
type uriUserinfoCandidate struct {
	candidate
	low bool
}

// findURIUserinfo returns the credential in the user info of every URI on the line: the password,
// or, when there is none, a user name shaped like a token. The span is the value exactly as
// written, percent-encoding included, so a redacted URI still parses and a value that appears
// twice on a line is two candidates.
//
// Linear in the line. Every authority ends at its first terminator, and the `/` of the next `://`
// is one, so authorities are disjoint; the scheme walk-back for one `://` stops at the previous
// authority's terminator. Each byte is therefore visited a bounded number of times however many
// URIs the line holds or however long one authority runs, which is what
// TestValidatorComplexityIsSubQuadratic's two uri targets pin. There is no length cap: a cap is a
// way for an author to hide a credential by making it long.
//
// Recall cost, stated: an unencoded `/`, `?` or `#` in a password ends the authority there, as it
// does for every URI parser, and that URI reports nothing.
func findURIUserinfo(line string) []uriUserinfoCandidate {
	if strings.IndexByte(line, '@') < 0 || !strings.Contains(line, "://") {
		return nil
	}
	var out []uriUserinfoCandidate
	from := 0
	for from < len(line) {
		i := strings.Index(line[from:], "://")
		if i < 0 {
			break
		}
		sep := from + i
		authStart := sep + 3
		end := authStart
		for end < len(line) && strings.IndexByte(uriAuthorityTerminators, line[end]) < 0 {
			end++
		}
		// The next "://" cannot start before end-1: its "/" would be a terminator inside this
		// authority. Resuming there keeps the scan linear and still finds `a://b://u:p@h`.
		from = authStart
		if end-1 > from {
			from = end - 1
		}

		// The trim set holds no '@', so the last '@' is the same before and after trimming.
		at := strings.LastIndexByte(line[authStart:end], '@')
		if at < 0 || !hasURIScheme(line, sep) {
			continue
		}
		at += authStart
		if !validURIHostList(line[at+1 : trimAuthorityEnd(line, at+1, end)]) {
			continue
		}
		userinfo := line[authStart:at]
		if !validURIUserinfo(userinfo) {
			continue
		}

		var c uriUserinfoCandidate
		if colon := strings.IndexByte(userinfo, ':'); colon >= 0 {
			if colon == len(userinfo)-1 {
				continue // `user:@host`: an empty password
			}
			start := authStart + colon + 1
			c.candidate = candidate{text: line[start:at], start: start, end: at}
			switch uriValueDisposition(c.text, userinfo[:colon]) {
			case uriNoCandidate:
				continue
			case uriLow:
				c.low = true
			}
		} else {
			if !uriUserOnlyToken(userinfo) {
				continue
			}
			c.candidate = candidate{text: userinfo, start: authStart, end: at}
			switch uriValueDisposition(userinfo, "") {
			case uriNoCandidate:
				continue
			case uriLow:
				c.low = true
			}
		}
		out = append(out, c)
	}
	return out
}

// hasURIScheme reports whether a scheme (RFC 3986 section 3.1, `ALPHA *( ALPHA / DIGIT / "+" /
// "-" / "." )`) ends at sep: the longest such run before `://`. `jdbc:mysql://` yields `mysql`,
// which is enough; the scheme is never reported or used beyond this.
func hasURIScheme(line string, sep int) bool {
	s := sep
	for s > 0 && isURISchemeByte(line[s-1]) {
		s--
	}
	for ; s < sep; s++ {
		if isASCIILetter(line[s]) {
			return true
		}
	}
	return false
}

func isURISchemeByte(b byte) bool {
	return isASCIILetter(b) || isASCIIDigit(b) || b == '+' || b == '-' || b == '.'
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// trimAuthorityEnd returns end less any uriAuthorityTrailingTrim bytes, but never below the
// closing bracket of an IP literal in the host (`(postgres://u:p@[::1])` keeps its `]`). Each
// step is O(1) and the bracket search is one pass over the host, so a host followed by a long run
// of punctuation stays linear.
func trimAuthorityEnd(line string, hostStart, end int) int {
	floor := hostStart
	if lb := strings.LastIndexByte(line[hostStart:end], '['); lb >= 0 {
		if rb := strings.IndexByte(line[hostStart+lb:end], ']'); rb >= 0 {
			floor = hostStart + lb + rb + 1
		}
	}
	for end > floor && strings.IndexByte(uriAuthorityTrailingTrim, line[end-1]) >= 0 {
		end--
	}
	return end
}

// validURIUserinfo reports whether s is `*( unreserved / pct-encoded / sub-delims / ":" / "@" )`.
func validURIUserinfo(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case isASCIILetter(b) || isASCIIDigit(b):
		case b == '%':
			if i+2 >= len(s) || !isHexByte(s[i+1]) || !isHexByte(s[i+2]) {
				return false
			}
			i += 2
		case strings.IndexByte(uriUserinfoPunct, b) >= 0:
		default:
			return false
		}
	}
	return true
}

// validURIHostList reports whether s is one or more host entries separated by `,`, each a
// non-empty reg-name, IPv4 address or bracketed IP literal with an optional `:port`. The comma
// list is MongoDB's replica-set form and the reason net/url cannot be used.
func validURIHostList(s string) bool {
	if s == "" {
		return false
	}
	for {
		comma := strings.IndexByte(s, ',')
		entry := s
		if comma >= 0 {
			entry = s[:comma]
		}
		if !validURIHostEntry(entry) {
			return false
		}
		if comma < 0 {
			return true
		}
		s = s[comma+1:]
	}
}

// validURIHostEntry reports whether s is `host [ ":" port ]` with a non-empty host.
func validURIHostEntry(s string) bool {
	host, port := s, ""
	if strings.HasPrefix(s, "[") {
		rb := strings.IndexByte(s, ']')
		if rb < 0 {
			return false
		}
		host, port = s[:rb+1], s[rb+1:]
		if !validURIIPLiteral(host[1 : len(host)-1]) {
			return false
		}
	} else {
		if colon := strings.IndexByte(s, ':'); colon >= 0 {
			host, port = s[:colon], s[colon:]
		}
		if !validURIRegName(host) {
			return false
		}
	}
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for i := 1; i < len(port); i++ {
		if !isASCIIDigit(port[i]) {
			return false
		}
	}
	return true
}

// validURIRegName reports whether s is a non-empty `*( unreserved / pct-encoded )`, which covers
// host names and IPv4 addresses.
func validURIRegName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case isASCIILetter(b) || isASCIIDigit(b):
		case b == '%':
			if i+2 >= len(s) || !isHexByte(s[i+1]) || !isHexByte(s[i+2]) {
				return false
			}
			i += 2
		case strings.IndexByte(uriRegNamePunct, b) >= 0:
		default:
			return false
		}
	}
	return true
}

// validURIIPLiteral reports whether s, the inside of `[...]`, is an IPv6 address (hex digits,
// `:` and `.`, with at least one `:`) or an IPvFuture (`v` HEXDIG+ `.` then unreserved,
// sub-delims or `:`). A zone (`%25eth0`) is accepted as pct-encoded unreserved bytes.
func validURIIPLiteral(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == 'v' || s[0] == 'V' {
		dot := strings.IndexByte(s, '.')
		if dot < 2 || dot == len(s)-1 {
			return false
		}
		for i := 1; i < dot; i++ {
			if !isHexByte(s[i]) {
				return false
			}
		}
		rest := s[dot+1:]
		return !strings.ContainsAny(rest, "@%") && validURIUserinfo(rest)
	}
	if strings.IndexByte(s, ':') < 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case isHexByte(b) || b == ':' || b == '.':
		case b == '%':
			// A zone ID: `%25` then unreserved bytes to the end.
			if !strings.HasPrefix(s[i:], "%25") || i+3 >= len(s) {
				return false
			}
			return validURIRegName(s[i+3:])
		default:
			return false
		}
	}
	return true
}

// isWholeReference reports whether a value is nothing but a variable reference: `$NAME` or
// `$(...)`. Only the WHOLE value counts; `$` inside a password is a sub-delim and stays a password.
// (`${NAME}` never gets here: braces fail the user-info grammar.)
func isWholeReference(v string) bool {
	if len(v) < 2 || v[0] != '$' {
		return false
	}
	if v[1] == '(' {
		return v[len(v)-1] == ')'
	}
	if !isASCIILetter(v[1]) && v[1] != '_' {
		return false
	}
	for i := 2; i < len(v); i++ {
		if !isASCIILetter(v[i]) && !isASCIIDigit(v[i]) && v[i] != '_' {
			return false
		}
	}
	return true
}

// uriUserOnlyToken reports whether a user name with no password is shaped like a token: see
// uriUserOnlyMinLen.
func uriUserOnlyToken(user string) bool {
	if len(user) < uriUserOnlyMinLen {
		return false
	}
	var letter, digit bool
	var counts [256]int
	for i := 0; i < len(user); i++ {
		b := user[i]
		switch {
		case isASCIILetter(b):
			letter = true
		case isASCIIDigit(b):
			digit = true
		default:
			return false
		}
		counts[b]++
	}
	if !letter || !digit {
		return false
	}
	var entropy float64
	n := float64(len(user))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy >= uriUserOnlyMinEntropy
}

// appendURIUserinfoResults scores this line's URI user-info candidates and appends those that
// clear the threshold to lineResults, which holds what every other path reported on the line
// after arbitration and the AWS merge.
//
// A candidate whose span equals or lies inside a span already reported keeps that finding and adds
// nothing (#766, Resolution 6): `DB_PASSWORD=<uri>` still reports the whole URI as it always has,
// and `https://x-access-token:<tok>@host` still reports the `token:` stem's wider span, with no
// nested second finding. An identical span is the same rule as dedupeScopedBySpan's first claim,
// applied to what was REPORTED rather than to what was proposed, so a claim that did not clear its
// own threshold cannot silence this one. A span that ENCLOSES an existing finding is kept, since
// the existing finding is untouched and the rest of the password is otherwise left in the clear.
//
// Scored in a call of its own. processScopedCandidates judges each candidate independently, so
// splitting the call changes nothing for the candidates already scored, and keeping these out of
// mergeBySpanKeepStrongest means one of them can never raise an AWS finding's confidence.
func (v *Validator) appendURIUserinfoResults(lineResults []spannedMatch, uris []uriUserinfoCandidate, line string, lineNum int, originalPath, content string, contextInsights context.ContextInsights, lineHasShellVars bool, envType string, isShellScript bool, govKeyLine string) []spannedMatch {
	cands := make([]scopedCandidate, 0, len(uris))
	for _, u := range uris {
		sc := scopedCandidate{candidate: u.candidate, method: uriUserinfoMethod, threshold: uriUserinfoThreshold, structural: true}
		if u.low {
			sc.ceiling = uriUserinfoLowCeiling
		}
		cands = append(cands, sc)
	}
	scored := v.processScopedCandidates(cands, line, lineNum, originalPath, content, contextInsights, lineHasShellVars, envType, isShellScript, govKeyLine)
	inside := spansInsideReported(scored, lineResults)
	for i, r := range scored {
		if !inside[i] {
			lineResults = append(lineResults, r)
		}
	}
	return lineResults
}

// spansInsideReported reports, for each candidate span (sorted by start), whether it lies within
// some span of reported (any order), in O(R log R + U), so a line with many findings and many URIs
// stays linear-ish rather than paying R x U comparisons. A finding another path already reported on
// the same or a wider span keeps that finding, exactly as on main: this source is additive, so it
// never adds a second, nested finding to a span that is already reported (#766, Resolution 6).
func spansInsideReported(cands []spannedMatch, reported []spannedMatch) []bool {
	inside := make([]bool, len(cands))
	if len(reported) == 0 || len(cands) == 0 {
		return inside
	}
	type span struct{ start, end int }
	rs := make([]span, len(reported))
	for i, r := range reported {
		rs[i] = span{r.start, r.end}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].start < rs[j].start })
	j, maxEnd := 0, -1
	for i, c := range cands {
		for j < len(rs) && rs[j].start <= c.start {
			if rs[j].end > maxEnd {
				maxEnd = rs[j].end
			}
			j++
		}
		inside[i] = maxEnd >= c.end
	}
	return inside
}
