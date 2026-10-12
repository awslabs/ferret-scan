// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"path/filepath"
	"regexp"
	"strings"
)

// The lexical gate on the unquoted-assignment family (#753).
//
// The unquoted family -- compileUnquotedPatterns (#395), its plural twin, and the #746/#749
// collection, list-tail and sequence paths -- captures whatever follows `keyword[=:]`. Its
// justification is config grammar: in .env, shell `export`, Dockerfile ENV, ini and unquoted YAML
// an unquoted right-hand side IS the literal. In an expression language it is not. A string there
// must be quoted, so an unquoted right-hand side in CODE position is an identifier, a member
// access, a call or a type, and the family can only produce false positives:
//
//	secret = config.secret_key            Python   HIGH 100 on v2.5.3
//	token: AuthToken                      TS       HIGH 100
//	password: this.form.value.password,   TS       HIGH 100
//
// Measured over 44,132 public source files, 139,068 findings came from this family and none was a
// credential (#753). A value-shape veto cannot close it, because `token: AuthToken` is
// byte-identical in a .ts file, where it is a type, and in a .yaml file, where it may be a value.
// What differs is the grammar of the file, so the gate reads the grammar.
//
// THE RULE. An unquoted-family candidate is dropped iff all three hold:
//
//  1. the file's extension is in the table below, and the gate is active for this file (it fails
//     open -- see lexLiterals -- when the lexer cannot vouch for its own state);
//  2. the candidate's VALUE START lies in CODE position: outside every string (delimiters
//     included), comment, docstring, regex literal and heredoc body;
//  3. the value is not a literal token: a backtick string whose template contains no `${` before
//     it closes, or a hex literal (isLiteralToken).
//
// Anchored on the value start, not on the keyword. `password = os.getenv("DB_PASSWORD", "<v>")`
// has its keyword in code, and the quoted fallback is still a hard-coded credential; a quoted
// collection element after a code-position head is the same case. The candidates whose value
// starts inside quotes keep reporting, which is the point.
//
// A template literal that contains `${` counts as CODE at its opening backtick: the value the
// unquoted capture takes from it, `${prefix}...`, is an interpolated expression. Its text
// segments are still literal, so a credential written inside the template text keeps reporting.
//
// THIS ONLY EVER DROPS CANDIDATES, and only from the unquoted family. Quoted keyword patterns,
// provider literals, the entropy path, the multi-line PEM path and the AWS secret-key path are
// never gated, and a quoted or entropy twin on the same span survives because the gate runs
// before the same-span dedupe. The justification is the language grammar, never the value: no
// value shape is consulted, so an author cannot make a credential disappear by choosing one.
//
// THE ACCEPTED LOSS: a bare credential pasted unquoted in code position, `API_KEY = <value>` in a
// .py. That is not a string in these languages and the program would not run; it is pinned by
// TestSourceGateAcceptedLossIsPinned.

// sourceLanguage is the lexical grammar a file is read with, or langNone for "not gated".
type sourceLanguage uint8

const (
	langNone sourceLanguage = iota
	langPython
	langJS
	langGo
	langHCL
)

func (l sourceLanguage) String() string {
	switch l {
	case langPython:
		return "python"
	case langJS:
		return "js"
	case langGo:
		return "go"
	case langHCL:
		return "hcl"
	}
	return "none"
}

// sourceLanguageFor maps a file name to its grammar by extension, and is the ONLY input that turns
// the gate on.
//
// The name is originalPath on every channel: a CLI path, a --stdin-name value, a ScanFile path and
// a ScanText or Redact label all arrive here the same way, so `--stdin-name x.ts` is gated exactly
// like a file called x.ts. No extension means no gate -- `<stdin>`, `<text>`, `clipboard`, a golden
// label -- and so does an extension that is not listed (.docx, .env.example, x.ts.txt). An absent
// entry is the safe direction: it keeps today's behaviour.
//
// .jsx and .tsx are deliberately absent. JSX text between tags is neither code nor a JS string, and
// this lexer does not model it. Other languages are added by measurement, not by guess.
func sourceLanguageFor(originalPath string) sourceLanguage {
	switch strings.ToLower(filepath.Ext(originalPath)) {
	case ".py", ".pyi", ".pyw":
		return langPython
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		return langJS
	case ".go":
		return langGo
	case ".tf", ".tfvars", ".hcl":
		return langHCL
	}
	return langNone
}

// maxLexBytes is the largest content the gate lexes. Above it the gate fails open.
//
// It is router.MaxFileSize, the ceiling on content this validator is handed in one piece by the
// file and stdin paths, duplicated rather than imported to keep this package's dependencies
// pointing one way. TestMaxLexBytesMatchesTheRouterCeiling fails if the two drift apart.
const maxLexBytes = 100 * 1024 * 1024

// maxInterpolationDepth bounds the template/interpolation stack. Real code nests a handful deep;
// a deeper stack is either adversarial input or a lexer that has lost the thread, and either way
// the gate fails open rather than holding a stack proportional to the file.
const maxInterpolationDepth = 256

// literalSet is a bitset over content byte offsets: a set bit means the byte is inside a literal
// (a string including its delimiters, a comment, a docstring, a regex literal, a heredoc body).
// Membership is O(1) per position, which is what keeps the per-candidate test free.
type literalSet []uint64

func newLiteralSet(n int) literalSet { return make(literalSet, (n+63)/64) }

func (s literalSet) has(off int) bool {
	if off < 0 || off>>6 >= len(s) {
		return false
	}
	return s[off>>6]&(1<<(uint(off)&63)) != 0
}

func (s literalSet) clear(off int) {
	if off >= 0 && off>>6 < len(s) {
		s[off>>6] &^= 1 << (uint(off) & 63)
	}
}

// setRange marks [from, to). Word-at-a-time, so a long literal costs its length over 64.
func (s literalSet) setRange(from, to int) {
	if from < 0 {
		from = 0
	}
	if max := len(s) << 6; to > max {
		to = max
	}
	for from < to && from&63 != 0 {
		s[from>>6] |= 1 << (uint(from) & 63)
		from++
	}
	for from+64 <= to {
		s[from>>6] = ^uint64(0)
		from += 64
	}
	for from < to {
		s[from>>6] |= 1 << (uint(from) & 63)
		from++
	}
}

// sourceGate is the per-file decision. A nil *sourceGate keeps every candidate, which is what an
// untyped file, an unlisted extension and every fail-open condition all reduce to.
type sourceGate struct {
	lit literalSet
}

// newSourceGate lexes content once for lang and returns the gate, or nil when the file is not
// gated or the gate failed open. The second result is the fail-open reason ("" when the gate is
// active or the language is langNone), kept so tests can tell WHICH condition disabled it.
func newSourceGate(content string, lang sourceLanguage) (*sourceGate, string) {
	if lang == langNone {
		return nil, ""
	}
	if len(content) > maxLexBytes {
		return nil, "content larger than maxLexBytes"
	}
	lit, reason := lexLiterals(content, lang)
	if reason != "" {
		return nil, reason
	}
	return &sourceGate{lit: lit}, ""
}

// drops reports whether an unquoted-family candidate whose value starts at valueStart on a line
// beginning at content offset lineStart is to be dropped. See the rule at the top of this file.
func (g *sourceGate) drops(line string, lineStart, valueStart int, value string) bool {
	if g == nil {
		return false
	}
	if g.lit.has(lineStart + valueStart) {
		return false
	}
	return !isLiteralToken(line, valueStart, value)
}

// hexLiteralToken is a numeric hex literal. In code position it is a constant, and a hard-coded key
// written as one is a literal credential: `secret_key = 0x...` keeps reporting.
var hexLiteralToken = regexp.MustCompile(`^0[xX][0-9a-fA-F]{8,}$`)

// isLiteralToken is condition (3): a value that is a literal even though it starts in code
// position.
//
// A backtick value is a literal when the template it opens closes before any `${`. In JS the lexer
// already marks such a template literal at its opening backtick, so this matters for the grammars
// where a backtick opens nothing (Python, HCL): there the decision is made from the line, and an
// unclosed backtick is not a literal. The scan stops at the first backtick or `${`, and every value
// it is asked about starts with a backtick, so the scans of distinct values never overlap: linear in
// the line.
func isLiteralToken(line string, valueStart int, value string) bool {
	if hexLiteralToken.MatchString(value) {
		return true
	}
	if value == "" || value[0] != '`' || valueStart+1 > len(line) {
		return false
	}
	rest := line[valueStart+1:]
	for k := 0; k < len(rest); k++ {
		switch rest[k] {
		case '\\':
			k++
		case '`':
			return true
		case '$':
			if k+1 < len(rest) && rest[k+1] == '{' {
				return false
			}
		}
	}
	return false
}

type lexMode uint8

const (
	modeCode lexMode = iota
	modeBlockComment
	modeString    // a single-line '...' or "..." (and a Go rune)
	modeTriple    // a Python triple-quoted string
	modeRaw       // a Go raw string
	modeTemplate  // JS template text
	modeHCLString // HCL quoted template text
	modeRegex     // a JS regex literal
	modeHeredoc   // an HCL heredoc body
)

// lexFrame is one open interpolation: `${` inside a JS template or an HCL quoted string.
type lexFrame struct {
	ret          lexMode // the text mode its closing brace returns to
	depth        int     // unmatched '{' inside the interpolation
	templateOpen int     // offset of the backtick that opened the enclosing JS template
}

// lexLiterals makes one forward pass over the whole content and returns the literal bitset, or a
// non-empty reason when the gate must fail open.
//
// One pass and no per-line rescans: every branch advances i, and the only backward looks (a Python
// string prefix, the byte before a JS '/') are bounded by a constant or by the whitespace run they
// skip, which is never revisited. See TestSourceLexerIsLinear.
//
// FAIL OPEN -- the gate is disabled for the whole file and it behaves exactly as today -- when:
//
//   - the content ends inside anything but code: an unclosed block comment, triple-quoted string,
//     template, raw string, heredoc or interpolation;
//   - a single-line string reaches the end of its line unterminated and without a continuation
//     backslash. That is a syntax error in every language here, so either this lexer is wrong
//     about the file or the file is not what its extension claims; a JS regex literal that does
//     not close on its line is treated the same way;
//   - template or interpolation nesting is unbalanced, or deeper than maxInterpolationDepth.
//
// Python note. A raw prefix (r, rb, br, fr, rf) changes what a backslash MEANS, not where the
// string ENDS: Python's tokenizer still lets a backslash keep the next character inside a raw
// literal, which is why r"\"" is a valid string. The boundary rule is therefore the same for raw
// and non-raw strings, and lexing r"[\"']" as no-escape would end it one byte early and fail open
// on valid code. An f-string is literal as a whole, replacement fields included.
func lexLiterals(content string, lang sourceLanguage) (literalSet, string) {
	n := len(content)
	lit := newLiteralSet(n)

	var (
		stack     []lexFrame
		mode      = modeCode
		start     int  // first byte of the literal span currently open
		quote     byte // closing delimiter of modeString / modeTriple
		tmplOpen  = -1 // backtick of the innermost open JS template
		inClass   bool // inside [...] of a regex
		lineStart int
		heredocID string
	)
	continuation := lang == langPython || lang == langJS

	i := 0
	for i < n {
		c := content[i]
		switch mode {
		case modeCode:
			switch {
			case c == '\n':
				i++
				lineStart = i
				continue
			case (c == '#' && (lang == langPython || lang == langHCL)) ||
				(c == '#' && lang == langJS && i == 0 && i+1 < n && content[1] == '!') ||
				(c == '/' && lang != langPython && i+1 < n && content[i+1] == '/'):
				eol := lineEnd(content, i)
				lit.setRange(i, eol)
				i = eol
				continue
			case c == '/' && lang != langPython && i+1 < n && content[i+1] == '*':
				mode, start = modeBlockComment, i
				i += 2
				continue
			case c == '"' || c == '\'':
				if lang == langHCL {
					if c == '\'' {
						break // not a string delimiter in HCL
					}
					mode, start = modeHCLString, i
					i++
					continue
				}
				if lang == langPython {
					start = pythonPrefixStart(content, i)
					if i+2 < n && content[i+1] == c && content[i+2] == c {
						mode, quote = modeTriple, c
						i += 3
						continue
					}
				} else {
					start = i
				}
				mode, quote = modeString, c
				i++
				continue
			case c == '`' && lang == langJS:
				mode, start, tmplOpen = modeTemplate, i, i
				i++
				continue
			case c == '`' && lang == langGo:
				mode, start = modeRaw, i
				i++
				continue
			case c == '/' && lang == langJS && regexCanStart(content, lineStart, i):
				mode, start, inClass = modeRegex, i, false
				i++
				continue
			case c == '<' && lang == langHCL && i+1 < n && content[i+1] == '<':
				if id, bodyStart, ok := hclHeredocOpener(content, i); ok {
					mode, heredocID = modeHeredoc, id
					i = bodyStart
					lineStart = i
					continue
				}
			case (c == '{' || c == '}') && len(stack) > 0:
				top := &stack[len(stack)-1]
				if c == '{' {
					top.depth++
				} else if top.depth > 0 {
					top.depth--
				} else {
					// The brace that closes the interpolation is code; the text resumes after it.
					mode, tmplOpen = top.ret, top.templateOpen
					stack = stack[:len(stack)-1]
					start = i + 1
				}
			}
			i++

		case modeBlockComment:
			if c == '*' && i+1 < n && content[i+1] == '/' {
				lit.setRange(start, i+2)
				mode = modeCode
				i += 2
				continue
			}
			if c == '\n' {
				lineStart = i + 1
			}
			i++

		case modeString:
			switch c {
			case '\\':
				if nl := newlineAt(content, i+1); nl > 0 {
					if !continuation {
						return nil, "string continued past the end of its line"
					}
					i += 1 + nl
					lineStart = i
					continue
				}
				i += 2
				continue
			case '\n':
				return nil, "unterminated single-line string"
			case quote:
				lit.setRange(start, i+1)
				mode = modeCode
			}
			i++

		case modeTriple:
			switch {
			case c == '\\':
				if i+1 < n && content[i+1] == '\n' {
					lineStart = i + 2
				}
				i += 2
				continue
			case c == '\n':
				lineStart = i + 1
			case c == quote && i+2 < n && content[i+1] == quote && content[i+2] == quote:
				lit.setRange(start, i+3)
				mode = modeCode
				i += 3
				continue
			}
			i++

		case modeRaw:
			if c == '`' {
				lit.setRange(start, i+1)
				mode = modeCode
			} else if c == '\n' {
				lineStart = i + 1
			}
			i++

		case modeTemplate:
			switch {
			case c == '\\':
				if i+1 < n && content[i+1] == '\n' {
					lineStart = i + 2
				}
				i += 2
				continue
			case c == '\n':
				lineStart = i + 1
			case c == '`':
				lit.setRange(start, i+1)
				mode = modeCode
			case c == '$' && i+1 < n && content[i+1] == '{':
				if len(stack) >= maxInterpolationDepth {
					return nil, "interpolation nested deeper than maxInterpolationDepth"
				}
				// The text so far is literal; the template's OPENING backtick is code, because
				// the value an unquoted capture takes from here is an interpolated expression.
				lit.setRange(start, i)
				lit.clear(tmplOpen)
				stack = append(stack, lexFrame{ret: modeTemplate, templateOpen: tmplOpen})
				mode = modeCode
				i += 2
				continue
			}
			i++

		case modeHCLString:
			switch {
			case c == '\\':
				if newlineAt(content, i+1) > 0 {
					return nil, "string continued past the end of its line"
				}
				i += 2
				continue
			case c == '\n':
				return nil, "unterminated single-line string"
			case c == '"':
				lit.setRange(start, i+1)
				mode = modeCode
			case (c == '$' || c == '%') && i+2 < n && content[i+1] == c && content[i+2] == '{':
				i += 3 // $${ and %%{ are the escapes for a literal ${ and %{
				continue
			case (c == '$' || c == '%') && i+1 < n && content[i+1] == '{':
				if len(stack) >= maxInterpolationDepth {
					return nil, "interpolation nested deeper than maxInterpolationDepth"
				}
				lit.setRange(start, i)
				stack = append(stack, lexFrame{ret: modeHCLString, templateOpen: -1})
				mode = modeCode
				i += 2
				continue
			}
			i++

		case modeRegex:
			switch c {
			case '\\':
				if newlineAt(content, i+1) > 0 {
					return nil, "regex literal continued past the end of its line"
				}
				i += 2
				continue
			case '\n':
				return nil, "regex literal not closed on its line"
			case '[':
				inClass = true
			case ']':
				inClass = false
			case '/':
				if !inClass {
					i++
					for i < n && isASCIILetter(content[i]) {
						i++
					}
					lit.setRange(start, i)
					mode = modeCode
					continue
				}
			}
			i++

		case modeHeredoc:
			eol := lineEnd(content, i)
			if strings.TrimSpace(content[i:eol]) == heredocID {
				mode = modeCode // the closing marker is code; its newline is handled there
				i = eol
				continue
			}
			lit.setRange(i, eol)
			if eol >= n {
				i = n
				continue
			}
			i = eol + 1
			lineStart = i
		}
	}

	if mode != modeCode {
		return nil, "content ends inside a literal"
	}
	if len(stack) > 0 {
		return nil, "unbalanced interpolation"
	}
	return lit, ""
}

// lineEnd returns the offset of the '\n' ending the line containing i, or len(s).
func lineEnd(s string, i int) int {
	if k := strings.IndexByte(s[i:], '\n'); k >= 0 {
		return i + k
	}
	return len(s)
}

// newlineAt returns the length of the line break starting at i ("\n" or "\r\n"), or 0.
func newlineAt(s string, i int) int {
	if i < len(s) && s[i] == '\n' {
		return 1
	}
	if i+1 < len(s) && s[i] == '\r' && s[i+1] == '\n' {
		return 2
	}
	return 0
}

// pythonPrefixStart returns where the string whose quote is at q starts: at a preceding r/b/f/u
// prefix (r, b, f, u, rb, br, fr, rf, any case) when there is one, else at q.
func pythonPrefixStart(s string, q int) int {
	k := q
	for k > 0 && q-k < 2 && strings.IndexByte("rRbBfFuU", s[k-1]) >= 0 {
		k--
	}
	if k == q {
		return q
	}
	switch strings.ToLower(s[k:q]) {
	case "r", "b", "f", "u", "rb", "br", "fr", "rf":
	default:
		return q
	}
	if k > 0 && isIdentByte(s[k-1]) {
		return q // the letters end an identifier, they are not a prefix
	}
	return k
}

// regexKeywords are the JS keywords after which a '/' begins an expression, i.e. a regex literal.
var regexKeywords = map[string]bool{
	"return": true, "typeof": true, "case": true, "void": true, "delete": true, "throw": true,
	"yield": true, "await": true, "else": true, "do": true, "in": true, "of": true,
	"instanceof": true, "new": true,
}

// maxRegexKeywordLen is the length of the longest entry in regexKeywords.
const maxRegexKeywordLen = len("instanceof")

// regexCanStart reports whether a JS '/' at i begins a regex literal rather than a division.
//
// The usual previous-significant-byte heuristic, and deliberately conservative: a regex is assumed
// only after a byte that cannot end an operand -- ( , = : [ ! & | ? { } ; and the arrow => -- after
// a keyword that begins an expression, or as the first significant byte of its line. Getting it wrong is safe in
// both directions. A division read as a regex either closes at a later '/' and marks text literal,
// which keeps candidates, or does not close on its line and fails the file open; a regex read as a
// division leaves its quote bytes in code, which ends in an unterminated string and fails open.
func regexCanStart(s string, lineStart, i int) bool {
	j := i - 1
	for j >= lineStart && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r') {
		j--
	}
	if j < lineStart {
		return true
	}
	switch s[j] {
	case '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';':
		return true
	case '>':
		// Only as the arrow `=>`, whose body may be a regex: `(o) => /^--x=/.test(o)`. Found by
		// the corpus probe, where it was the cause of 6 of the 7 regex fail-opens. A bare `>` is
		// left as division, the conservative reading.
		return j > lineStart && s[j-1] == '='
	}
	if !isIdentByte(s[j]) {
		return false
	}
	k := j
	for k >= lineStart && isIdentByte(s[k]) {
		if j-k >= maxRegexKeywordLen {
			return false // longer than any keyword
		}
		k--
	}
	return regexKeywords[s[k+1:j+1]]
}

// hclHeredocOpener parses `<<ID` or `<<-ID` at i followed by nothing but the end of the line, and
// returns the identifier and the offset of the body's first byte.
func hclHeredocOpener(s string, i int) (id string, bodyStart int, ok bool) {
	j := i + 2
	if j < len(s) && s[j] == '-' {
		j++
	}
	k := j
	for k < len(s) && (isASCIILetter(s[k]) || s[k] == '_' || (k > j && (s[k] == '-' || (s[k] >= '0' && s[k] <= '9')))) {
		k++
	}
	if k == j {
		return "", 0, false
	}
	eol := lineEnd(s, k)
	if strings.TrimSpace(s[k:eol]) != "" {
		return "", 0, false
	}
	if eol >= len(s) {
		return s[j:k], len(s), true
	}
	return s[j:k], eol + 1, true
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// isIdentByte reports whether b can be part of an identifier in any of these languages. Bytes of
// a multi-byte UTF-8 sequence count, since all four accept non-ASCII letters in identifiers.
func isIdentByte(b byte) bool {
	return isASCIILetter(b) || (b >= '0' && b <= '9') || b == '_' || b == '$' || b >= 0x80
}
