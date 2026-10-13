// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
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
// THE RULE. An unquoted-family candidate is dropped iff all of these hold:
//
//  1. the file's extension is in the table below, and the gate is active for this file (it fails
//     open -- see lexSource -- when the lexer cannot vouch for its own state);
//  2. the candidate's VALUE START lies in CODE position: outside every string (delimiters
//     included), comment, docstring, regex literal and heredoc body;
//  3. no byte of the captured value is the TEXT of a backtick string -- a JS template segment or
//     a Go raw string. A capture that starts in code can run into one -- atob(`<v>`),
//     strings.TrimSpace(`<v>`), `${PREFIX}<v>` -- and then the value is not a code expression: it
//     carries a literal the lexer itself classified, and is kept exactly as on main. For the
//     unquoted and plural patterns a backtick string is the only kind there is to run into, since
//     their value class stops at ' and ". A collection or list-tail ELEMENT can also run into a
//     QUOTED string, `token = head, decode("<v>")`, and that still drops: counting quoted text as
//     well costs tens of thousands of minified-code findings (see sourceGate.tick), so a short
//     credential in that one shape is reported only if a never-gated path finds it;
//  4. the value is not a literal token: a hex literal, or (where a backtick opens no string,
//     Python and HCL) a backtick string closed before any `${` (isLiteralToken).
//
// Anchored on the value start, not on the keyword. In `password = os.getenv(DB_PASSWORD_ENV,
// "<v>")` the keyword is in code; the unquoted capture `os.getenv(DB_PASSWORD_ENV` starts in code
// and is dropped, while the list-tail candidate that starts at the fallback's opening quote is
// kept. A quoted collection element after a code-position head is the same case. (With a QUOTED
// env-var name, `os.getenv("DB_PASSWORD", "<v>")`, the unquoted capture stops at the first quote
// and no keyword candidate reaches the fallback at all, on main or here; only the ungated entropy
// path can report it. The gate neither causes nor closes that gap.)
//
// A template literal whose FIRST byte after the backtick is `${` counts as CODE at its opening
// backtick: the value the unquoted capture takes from there, `${prefix}...`, starts with an
// interpolated expression. With literal text before the first `${` the backtick stays literal,
// like the opening quote of `"<v>" + suffix`. Template text segments are literal and backtick
// text (condition 3) either way, so a credential written inside the template text keeps reporting.
//
// THIS ONLY EVER DROPS CANDIDATES, and only from the unquoted family. Quoted keyword patterns,
// provider literals, the entropy path, the multi-line PEM path and the AWS secret-key path are
// never gated, and a candidate that a single-line one of them claims on exactly the same span is
// not gated either (validateContentCtx), so every span a never-gated path reports keeps main's
// type and confidence. The justification is the language grammar, never the value: no value shape is
// consulted, so an author cannot make a credential disappear by choosing one.
//
// THE ACCEPTED LOSS: a bare credential pasted unquoted in code position, `API_KEY = <value>` in a
// .py. That is not a string in these languages and the program would not run; it is pinned by
// TestSourceGateAcceptedLossIsPinned.

// sourceLanguage is the lexical grammar a file is read with, or langNone for "not gated".
type sourceLanguage uint8

const (
	langNone sourceLanguage = iota
	langPython
	// langJS is JavaScript, where JSX may occur. A JSX element fails the gate open (lexSource).
	langJS
	// langTS is TypeScript, lexed exactly as langJS but for one test: `<T` at an expression start
	// is a type parameter list or a type assertion there, never a JSX element, because TypeScript
	// accepts JSX only in .tsx. It is not a JSX opener, so it does not fail the file open.
	langTS
	langGo
	langHCL
)

func (l sourceLanguage) String() string {
	switch l {
	case langPython:
		return "python"
	case langJS:
		return "js"
	case langTS:
		return "ts"
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
// this lexer does not model it. JSX is just as common in .js, .mjs and .cjs files (Create React
// App, Next.js and React Native default to .js), so there a JSX element in code position fails the
// gate open for the whole file instead, which makes it behave exactly as if it were named .jsx.
// Other languages are added by measurement, not by guess.
func sourceLanguageFor(originalPath string) sourceLanguage {
	switch strings.ToLower(filepath.Ext(originalPath)) {
	case ".py", ".pyi", ".pyw":
		return langPython
	case ".js", ".mjs", ".cjs":
		return langJS
	case ".ts", ".mts", ".cts":
		return langTS
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

// clampRange limits [from, to) to the offsets the set covers.
func (s literalSet) clampRange(from, to int) (int, int) {
	if from < 0 {
		from = 0
	}
	if max := len(s) << 6; to > max {
		to = max
	}
	return from, to
}

// setRange marks [from, to). Word-at-a-time, so a long literal costs its length over 64.
func (s literalSet) setRange(from, to int) {
	from, to = s.clampRange(from, to)
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

// hasAny reports whether any offset in [from, to) is set. Word-at-a-time, like setRange, so a
// candidate costs its length over 64.
func (s literalSet) hasAny(from, to int) bool {
	from, to = s.clampRange(from, to)
	for from < to && from&63 != 0 {
		if s.has(from) {
			return true
		}
		from++
	}
	for from+64 <= to {
		if s[from>>6] != 0 {
			return true
		}
		from += 64
	}
	for from < to {
		if s.has(from) {
			return true
		}
		from++
	}
	return false
}

// sourceGate is the per-file decision. A nil *sourceGate keeps every candidate, which is what an
// untyped file, an unlisted extension and every fail-open condition all reduce to.
type sourceGate struct {
	// lit is every literal byte: strings with their delimiters and prefixes, comments, docstrings,
	// regex literals, heredoc bodies. It decides condition (2), the value start.
	lit literalSet
	// tick is the subset of lit that is the text of a BACKTICK string: each text segment of a JS
	// template (interpolations excluded) and the body of a Go raw string. It decides condition
	// (3): a value that carries written backtick text is not a code expression.
	//
	// Scoped to backtick strings because they are the only string kind the unquoted and plural
	// patterns can run INTO -- their value class stops at ' and ". The collection and list-tail
	// ELEMENT classes do admit quotes, and `a, b="text"` in minified JS is extremely common:
	// marking the text of quoted strings as well kept 35,974 more JS/TS findings than this set on
	// the measured corpus, every one on a source line of 200 or more characters and 35,963 of
	// them on lines of 1,000 or more (`HZ="X-Amzn-Bedrock-..."`, `AL=ae.enum(["Bedrock"`), plus 5
	// in Python (`name="proxy_auth")`). A quoted member of a collection is still reported on its
	// own span, by the element that starts at its opening quote.
	tick literalSet
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
	lit, tick, reason := lexSource(content, lang)
	if reason != "" {
		return nil, reason
	}
	return &sourceGate{lit: lit, tick: tick}, ""
}

// drops reports whether an unquoted-family candidate whose value starts at valueStart on a line
// beginning at content offset lineStart is to be dropped. See the rule at the top of this file.
func (g *sourceGate) drops(line string, lineStart, valueStart int, value string) bool {
	if g == nil {
		return false
	}
	at := lineStart + valueStart
	if g.lit.has(at) {
		return false // (2): the value starts inside a literal
	}
	if g.tick.hasAny(at, at+len(value)) {
		return false // (3): the value carries backtick-string text, so it is not a code expression
	}
	return !isLiteralToken(line, valueStart, value)
}

// hexLiteralToken is a numeric hex literal. In code position it is a constant, and a hard-coded key
// written as one is a literal credential: `secret_key = 0x...` keeps reporting.
var hexLiteralToken = regexp.MustCompile(`^0[xX][0-9a-fA-F]{8,}$`)

// isLiteralToken is condition (4): a value that is a literal even though it starts in code
// position.
//
// A backtick value is a literal when the template it opens closes before any `${`. In JS and Go the
// lexer already reads a backtick as a string, so such a value is kept by condition (2) or (3)
// before this is asked; this matters for the grammars where a backtick opens nothing (Python, HCL):
// there the decision is made from the line, and an unclosed backtick is not a literal. The scan
// stops at the first backtick or `${`, and every value it is asked about starts with a backtick, so
// the scans of distinct values never overlap: linear in the line.
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
	modeFmtSpec   // the format spec of a Python f-string replacement field, after its top-level ':'
)

// lexFrame is one open interpolation: `${` inside a JS template or an HCL quoted string, or a
// replacement field of a Python f-string or t-string.
type lexFrame struct {
	ret          lexMode // the text mode its closing brace returns to
	depth        int     // unmatched brackets inside the interpolation ('{' only, for JS and HCL)
	templateOpen int     // offset of the backtick that opened the enclosing JS template

	// A Python replacement field. The f-string stays literal as a whole, fields included, so the
	// frame only carries the string's own state across the field: its quote, whether it is
	// triple-quoted, and its first byte. depth counts every bracket, not just '{', because a ':'
	// at depth 0 starts the format spec.
	pyQuote  byte
	pyTriple bool
	pyStart  int
}

// lexLiterals is lexSource without the backtick-text set, for the tests that pin the literal set.
func lexLiterals(content string, lang sourceLanguage) (literalSet, string) {
	lit, _, reason := lexSource(content, lang)
	return lit, reason
}

// lexSource makes one forward pass over the whole content and returns the literal bitset and its
// backtick-text subset (see sourceGate), or a non-empty reason when the gate must fail open.
//
// One pass and no per-line rescans: every branch advances i, and every look away from i is bounded.
// The backward looks -- a Python string prefix, the keyword ending at prevSig before a JS '/', '<'
// or '(', the operand byte before a TypeScript '!', the rune a stray Windows-1252 quote byte may
// belong to -- each read at most a constant number of bytes. The one forward look that can fail,
// an HCL `<<ID` that is not a heredoc opener, stops at the first byte after the identifier that
// decides it, not at the end of the line, so a rejected opener costs its own bytes and no more.
// See TestSourceLexerIsLinear*.
//
// FAIL OPEN -- the gate is disabled for the whole file and it behaves exactly as today -- when:
//
//   - the content ends inside anything but code: an unclosed block comment, triple-quoted string,
//     template, raw string, heredoc or interpolation;
//   - a single-line string reaches the end of its line unterminated and without a continuation
//     backslash. That is a syntax error in every language here, so either this lexer is wrong
//     about the file or the file is not what its extension claims; a JS regex literal that does
//     not close on its line is treated the same way, and so is an f-string closed inside, or a
//     single-quoted one broken across lines in, a format spec;
//   - template or interpolation nesting is unbalanced, or deeper than maxInterpolationDepth;
//   - a JSX element appears in code position of a JavaScript file: a closing tag `</Name` or `</>`
//     (in .ts too, where it means the file is not TypeScript, e.g. a Qt Linguist translation), or
//     in .js/.mjs/.cjs an opening tag `<Name` or `<>` where an operand is expected. JSX text
//     between tags is neither code nor a string, so the file is treated like a .jsx file;
//   - a typographic quote appears in code position: a non-ASCII Unicode quotation mark (“ ” ‘ ’ „ «
//     » ‹ › ＂ 「 」 ...) or a Windows-1252 smart quote, see typographicQuoteAt. No grammar here
//     accepts one there, so the file is not valid source -- typically a credential pasted with
//     curly quotes, guillemets or full-width quotes -- and the lexer cannot know where the author
//     meant a string to be;
//   - the replacement character U+FFFD appears in code position. It stands for a byte a decoder
//     could not read -- Redact turns every invalid UTF-8 sequence into one before the gate, a raw
//     Windows-1252 quote included -- so the lexer cannot know whether that byte was a quote.
//
// Python note. A raw prefix (r, rb, br, fr, rf, tr, rt) changes what a backslash MEANS, not where
// the string ENDS: Python's tokenizer still lets a backslash keep the next character inside a raw
// literal, which is why r"\"" is a valid string. The boundary rule is therefore the same for raw
// and non-raw strings, and lexing r"[\"']" as no-escape would end it one byte early and fail open
// on valid code. An f-string (or 3.14 t-string) is literal as a whole, replacement fields
// included, but its fields are LEXED as code: since PEP 701 (3.12) a field may hold a string in the
// f-string's own quote, f"{d["k"]}", and ending the f-string at that inner quote would read the
// inner text as code while the quotes still pair up, so nothing would fail open. A ':' at bracket
// depth 0 starts the format spec, which is text again (a quote there is a fill character); `{{` is
// an escaped brace, and a backslash never escapes a brace.
func lexSource(content string, lang sourceLanguage) (lit, tick literalSet, reason string) {
	// TypeScript lexes exactly as JavaScript but for two tests: the JSX opener, and a '!' that may
	// be the postfix non-null assertion (regexCanStart).
	jsxOpener := lang == langJS
	ts := lang == langTS
	if lang == langTS {
		lang = langJS
	}
	n := len(content)
	lit = newLiteralSet(n)
	tick = newLiteralSet(n)

	var (
		stack     []lexFrame
		mode      = modeCode
		start     int  // first byte of the literal span currently open
		textStart int  // first byte of the JS template text segment currently open
		quote     byte // closing delimiter of modeString / modeTriple
		tmplOpen  = -1 // backtick of the innermost open JS template
		inClass   bool // inside [...] of a regex
		heredocID string
		fstr      bool // the Python string open in modeString/modeTriple is an f- or t-string
		// prevSig is the last significant byte the lexer has passed in code -- an operator, an
		// identifier byte, or the closing byte of a string, template or regex -- with whitespace,
		// newlines and comments skipped. A JS '/' and '<' are judged by it; -1 before any.
		prevSig = -1
		// JS parens in code: parenDepth counts the open ones, headerDepths the depths at which an
		// if/for/while/with header opened (capped, see maxHeaderParens), and headerClose is the
		// ')' that last closed one. A '/' right after headerClose starts the body: a regex.
		parenDepth   int
		headerDepths []int
		headerClose  = -1
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
					fstr = strings.ContainsAny(content[start:i], "fFtT")
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
				mode, start, textStart, tmplOpen = modeTemplate, i, i+1, i
				i++
				continue
			case c == '`' && lang == langGo:
				mode, start = modeRaw, i
				i++
				continue
			case c == '/' && lang == langJS && regexCanStart(content, prevSig, ts, headerClose):
				mode, start, inClass = modeRegex, i, false
				i++
				continue
			case c == '<' && lang == langJS && jsxTagAt(content, i, prevSig, headerClose, jsxOpener):
				return nil, nil, "JSX element in a JavaScript file"
			case c >= utf8.RuneSelf && typographicQuoteAt(content, i):
				return nil, nil, "typographic quote in code"
			case c == 0xEF && strings.HasPrefix(content[i:], "\uFFFD"):
				return nil, nil, "replacement character in code"
			case c >= utf8.RuneSelf && strayPunctuationAt(content, i):
				return nil, nil, "non-ASCII punctuation or symbol in code"
			case c == '<' && lang == langHCL && i+1 < n && content[i+1] == '<':
				if id, bodyStart, ok := hclHeredocOpener(content, i); ok {
					mode, heredocID = modeHeredoc, id
					i = bodyStart
					continue
				}
			case lang == langPython && len(stack) > 0 && strings.IndexByte("([{)]}:", c) >= 0:
				// Inside a Python replacement field (only fields push frames in Python).
				top := &stack[len(stack)-1]
				switch {
				case c == '(' || c == '[' || c == '{':
					top.depth++
				case (c == ')' || c == ']' || c == '}') && top.depth > 0:
					top.depth--
				case c == '}':
					// The field ends; the f-string's own state resumes.
					mode, quote, start, fstr = top.ret, top.pyQuote, top.pyStart, true
					stack = stack[:len(stack)-1]
				case c == ':' && top.depth == 0:
					mode = modeFmtSpec
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
					start, textStart = i+1, i+1
				}
			}
			if lang == langJS && c == '(' {
				parenDepth++
				if len(headerDepths) < maxHeaderParens && controlHeaderKeywordAt(content, prevSig) {
					headerDepths = append(headerDepths, parenDepth)
				}
			} else if lang == langJS && c == ')' && parenDepth > 0 {
				if k := len(headerDepths) - 1; k >= 0 && headerDepths[k] == parenDepth {
					headerDepths, headerClose = headerDepths[:k], i
				}
				parenDepth--
			}
			if c != ' ' && c != '\t' && c != '\r' {
				prevSig = i
			}
			i++

		case modeBlockComment:
			if c == '*' && i+1 < n && content[i+1] == '/' {
				lit.setRange(start, i+2)
				mode = modeCode
				i += 2
				continue
			}
			i++

		case modeString:
			switch c {
			case '\\':
				if fstr && i+1 < n && content[i+1] == '{' {
					i++ // a backslash never escapes a brace in an f-string: rf'\{{' and f'\{x}'
					continue
				}
				if nl := newlineAt(content, i+1); nl > 0 {
					if !continuation {
						return nil, nil, "string continued past the end of its line"
					}
					i += 1 + nl
					continue
				}
				i += 2
				continue
			case '\n':
				return nil, nil, "unterminated single-line string"
			case quote:
				lit.setRange(start, i+1)
				mode, prevSig = modeCode, i
			case '{':
				if fstr {
					opened, why := openPyField(content, &i, &stack, quote, false, start)
					if why != "" {
						return nil, nil, why
					}
					if opened {
						mode = modeCode
					}
					continue
				}
			}
			i++

		case modeTriple:
			switch {
			case c == '\\' && fstr && i+1 < n && content[i+1] == '{':
				i++
				continue
			case c == '\\':
				i += 2
				continue
			case c == quote && i+2 < n && content[i+1] == quote && content[i+2] == quote:
				lit.setRange(start, i+3)
				mode = modeCode
				i += 3
				continue
			case c == '{' && fstr:
				opened, why := openPyField(content, &i, &stack, quote, true, start)
				if why != "" {
					return nil, nil, why
				}
				if opened {
					mode = modeCode
				}
				continue
			}
			i++

		case modeRaw:
			if c == '`' {
				lit.setRange(start, i+1)
				tick.setRange(start+1, i)
				mode = modeCode
			}
			i++

		case modeTemplate:
			switch {
			case c == '\\':
				i += 2
				continue
			case c == '`':
				lit.setRange(start, i+1)
				tick.setRange(textStart, i)
				mode, prevSig = modeCode, i
			case c == '$' && i+1 < n && content[i+1] == '{':
				if len(stack) >= maxInterpolationDepth {
					return nil, nil, "interpolation nested deeper than maxInterpolationDepth"
				}
				// The text so far is literal. The template's OPENING backtick is code only when
				// the template starts with `${`: the value an unquoted capture takes from there
				// starts with an interpolated expression. After literal text it stays literal.
				lit.setRange(start, i)
				tick.setRange(textStart, i)
				if i == tmplOpen+1 {
					lit.clear(tmplOpen)
				}
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
					return nil, nil, "string continued past the end of its line"
				}
				i += 2
				continue
			case c == '\n':
				return nil, nil, "unterminated single-line string"
			case c == '"':
				lit.setRange(start, i+1)
				mode = modeCode
			case (c == '$' || c == '%') && i+2 < n && content[i+1] == c && content[i+2] == '{':
				i += 3 // $${ and %%{ are the escapes for a literal ${ and %{
				continue
			case (c == '$' || c == '%') && i+1 < n && content[i+1] == '{':
				if len(stack) >= maxInterpolationDepth {
					return nil, nil, "interpolation nested deeper than maxInterpolationDepth"
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
					return nil, nil, "regex literal continued past the end of its line"
				}
				i += 2
				continue
			case '\n':
				return nil, nil, "regex literal not closed on its line"
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
					mode, prevSig = modeCode, i-1
					continue
				}
			}
			i++

		case modeFmtSpec:
			// Text, like the f-string around it, except that '{' opens a nested field and '}' ends
			// this one. A quote here is a fill character, not a delimiter.
			top := &stack[len(stack)-1]
			switch {
			case c == '\\':
				i += 2
				continue
			case c == '\n' && !top.pyTriple:
				return nil, nil, "newline in the format spec of a single-quoted f-string"
			case c == top.pyQuote && (!top.pyTriple || (i+2 < n && content[i+1] == c && content[i+2] == c)):
				return nil, nil, "f-string closed inside a format spec"
			case c == '{':
				if len(stack) >= maxInterpolationDepth {
					return nil, nil, "interpolation nested deeper than maxInterpolationDepth"
				}
				stack = append(stack, lexFrame{ret: modeFmtSpec, templateOpen: -1,
					pyQuote: top.pyQuote, pyTriple: top.pyTriple, pyStart: top.pyStart})
				mode = modeCode
			case c == '}':
				mode, quote, start, fstr = top.ret, top.pyQuote, top.pyStart, true
				stack = stack[:len(stack)-1]
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
		}
	}

	if mode != modeCode {
		return nil, nil, "content ends inside a literal"
	}
	if len(stack) > 0 {
		return nil, nil, "unbalanced interpolation"
	}
	return lit, tick, ""
}

// openPyField handles a '{' at *i inside a Python f-string or t-string: `{{` is an escaped brace
// and stays text; anything else opens a replacement field, which PEP 701 (Python 3.12) lets
// contain any expression, including strings in the SAME quote as the f-string around it. The
// field is lexed as code so that such a string is found and the f-string does not end at its
// first quote; the f-string is still marked literal as a whole when its own closing quote is
// reached, so the drop set inside it does not change.
func openPyField(content string, i *int, stack *[]lexFrame, quote byte, triple bool, start int) (opened bool, reason string) {
	if *i+1 < len(content) && content[*i+1] == '{' {
		*i += 2
		return false, ""
	}
	if len(*stack) >= maxInterpolationDepth {
		return false, "interpolation nested deeper than maxInterpolationDepth"
	}
	ret := modeString
	if triple {
		ret = modeTriple
	}
	*stack = append(*stack, lexFrame{ret: ret, templateOpen: -1,
		pyQuote: quote, pyTriple: triple, pyStart: start})
	*i++
	return true, ""
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

// pythonPrefixStart returns where the string whose quote is at q starts: at a preceding r/b/f/u/t
// prefix (r, b, f, u, t, rb, br, fr, rf, tr, rt, any case) when there is one, else at q.
func pythonPrefixStart(s string, q int) int {
	k := q
	for k > 0 && q-k < 2 && strings.IndexByte("rRbBfFuUtT", s[k-1]) >= 0 {
		k--
	}
	if k == q {
		return q
	}
	switch strings.ToLower(s[k:q]) {
	case "r", "b", "f", "u", "t", "rb", "br", "fr", "rf", "tr", "rt":
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

// regexCanStart reports whether a JS '/' begins a regex literal rather than a division, judged by
// prevSig, the last significant byte before it (see lexSource; -1 at the start of the file).
//
// The usual previous-significant-token heuristic, and deliberately conservative: a regex is assumed
// only after a byte that cannot end an operand -- ( , = : [ ! & | ? { } ; and the arrow => -- or
// after a keyword that begins an expression. prevSig skips newlines and comments, because JS inserts
// no semicolon before a '/': a '/' that leads its line after an operand is a division, and reading it
// as a regex would close it at the first '/' of a trailing `//` or `/*` and leave that comment in
// code. A regex read as a division leaves its body in code: a quote in it opens a string, which
// normally runs off the end of the line and fails the file open -- but not when a later quote on
// the line closes it, e.g. one in a trailing comment, whose text then lands in code.
//
// Two bytes are read in context:
//
//   - a ')' ends an operand unless it is headerClose, the ')' that closed an if/for/while/with
//     header (lexSource tracks them). The body statement starts after it, so in `if (ok)` followed
//     by `/re/.exec(s)` the '/' is a regex, on the same line or the next. A `for await (...)`
//     header is not tracked and keeps the division reading;
//   - in TypeScript (ts) a '!' straight after an operand is the postfix non-null assertion, which
//     ends the operand: in `done! / total; // c` the '/' is a division. Only the one byte before
//     the '!' is read (operandEndsAt), so `a!! / b` and `a ! / b` keep the regex reading. A '!'
//     after a keyword (`return!/re/`), after headerClose, or after a space or a newline is a
//     prefix '!'. JavaScript has no postfix '!', so there every '!' is a prefix.
func regexCanStart(s string, prevSig int, ts bool, headerClose int) bool {
	j := prevSig
	if j < 0 {
		return true
	}
	switch s[j] {
	case '(', ',', '=', ':', '[', '&', '|', '?', '{', '}', ';':
		return true
	case '!':
		return !ts || j == 0 || j-1 == headerClose || !operandEndsAt(s, j-1)
	case ')':
		return j == headerClose
	case '>':
		// Only as the arrow `=>`, whose body may be a regex: `(o) => /^--x=/.test(o)`. Found by
		// the corpus probe, where it was the cause of 6 of the 7 regex fail-opens. A bare `>` is
		// left as division, the conservative reading.
		return j > 0 && s[j-1] == '='
	}
	if !isIdentByte(s[j]) {
		return false
	}
	k := j
	for k >= 0 && isIdentByte(s[k]) {
		if j-k >= maxRegexKeywordLen {
			return false // longer than any keyword
		}
		k--
	}
	// `default` begins an expression after `export` (`export default /re/`), but it is checked
	// apart from regexKeywords so the property `x.default / 2` keeps the division reading.
	return regexKeywords[s[k+1:j+1]] || keywordEndsAt(s, j, "default")
}

// operandEndsAt reports whether the byte at j ends an operand that a TypeScript postfix '!' can
// follow: ')' or ']', or the last byte of an identifier that is not one of regexKeywords. It reads
// that one byte, and for an identifier the keyword check's bounded look back.
func operandEndsAt(s string, j int) bool {
	switch {
	case s[j] == ')' || s[j] == ']':
		return true
	case isIdentByte(s[j]):
		return !regexCanStart(s, j, false, -1)
	}
	return false
}

// maxHeaderParens bounds lexSource's stack of open if/for/while/with headers. A header nested
// deeper is not recorded, so a '/' after its ')' keeps the division reading.
const maxHeaderParens = 256

// controlHeaderKeywordAt reports whether the identifier ending at j is if, for, while or with --
// the keywords whose '(' opens a header whose ')' is followed by a statement, never an operator.
func controlHeaderKeywordAt(s string, j int) bool {
	return keywordEndsAt(s, j, "if") || keywordEndsAt(s, j, "for") ||
		keywordEndsAt(s, j, "while") || keywordEndsAt(s, j, "with")
}

// jsxTagAt reports whether the '<' at i, in JS code position, is a JSX tag:
//
//   - a closing tag, `</Name` or the fragment `</>`. Neither JavaScript nor TypeScript has `</`
//     before a name outside JSX, short of comparing against a regex literal (`a </re/`), and JSX
//     text lives only between an opening and a closing tag, so every file holding JSX text has one;
//   - when opener is set (.js .mjs .cjs), an opening tag `<Name` or the fragment `<>` where an
//     operand is expected -- regexCanStart's positions, an if/for/while/with header's ')'
//     included, plus after `export default`. Outside JSX a '<' is never valid there. This catches
//     a closing tag the lexer cannot see, e.g. one hidden behind a `//` in the JSX text:
//     `<p>token=<v> see https://wiki</p>`. In TypeScript `<T` there is a type parameter list or an
//     assertion, so opener is unset for langTS.
//
// A misfire only fails the file open, the safe direction.
func jsxTagAt(s string, i, prevSig, headerClose int, opener bool) bool {
	if i+1 >= len(s) {
		return false
	}
	if s[i+1] == '/' {
		return i+2 < len(s) && (s[i+2] == '>' || jsxNameStart(s[i+2]))
	}
	if !opener || (s[i+1] != '>' && !jsxNameStart(s[i+1])) {
		return false
	}
	return regexCanStart(s, prevSig, false, headerClose)
}

// jsxNameStart reports whether b can start a JSX element name.
func jsxNameStart(b byte) bool { return isASCIILetter(b) || b == '_' || b == '$' || b >= 0x80 }

// keywordEndsAt reports whether the identifier ending at j is exactly kw (and not a property
// access such as x.default, or a private name such as this.#if).
func keywordEndsAt(s string, j int, kw string) bool {
	k := j - len(kw) + 1
	if j < 0 || k < 0 || s[k:j+1] != kw {
		return false
	}
	return k == 0 || (!isIdentByte(s[k-1]) && s[k-1] != '.' && s[k-1] != '#')
}

// typographicQuoteAt reports whether, at a byte >= 0x80 in code position, a quotation mark starts
// that no gated grammar accepts there:
//
//   - a rune with the Unicode Quotation_Mark property, or in the quote punctuation categories Pi
//     and Pf, other than ASCII " and ': “ ” ‘ ’ „ ‟ ‚ ‛ « » ‹ › ＂ ＇ 「 」 『 』 〝 〞 ｢ ｣ ⸂ ⸃ and the
//     rest of those tables. None is an identifier or whitespace character in Python, JS/TS, Go or
//     HCL;
//   - a Windows-1252 smart quote (‚ „ ‹ ‘ ’ “ ” › « »), in either spelling the lexer is handed. A
//     file or --stdin that is not UTF-8 is decoded as Latin-1, so 0x93 arrives as the C1 control
//     U+0093; ScanText hands the bytes over as they are, and a raw 0x93 is a quote only when it is
//     not a continuation byte of a valid rune (ë is C3 AB, 主 is E4 B8 BB). Redact's spelling,
//     U+FFFD, is a fail-open condition of its own (lexSource).
//
// A prime (′ ″) or a dingbat ornament (❝ ❞) is not a quotation mark; strayPunctuationAt fails the
// file open on those. The look back for a raw byte's rune is at most utf8.UTFMax-1 bytes.
func typographicQuoteAt(s string, i int) bool {
	c := s[i]
	if utf8.RuneStart(c) {
		r, w := utf8.DecodeRuneInString(s[i:])
		return w > 1 && (unicode.In(r, unicode.Quotation_Mark, unicode.Pi, unicode.Pf) ||
			(r < 0x100 && cp1252Quote(byte(r))))
	}
	if !cp1252Quote(c) {
		return false
	}
	for k := i - 1; k >= 0 && k >= i-(utf8.UTFMax-1); k-- {
		if utf8.RuneStart(s[k]) {
			_, w := utf8.DecodeRuneInString(s[k:])
			return k+w <= i // the rune that starts at k ends before i: the byte is stray
		}
	}
	return true // more continuation bytes in a row than any rune has
}

// strayPunctuationAt reports whether a non-ASCII punctuation or symbol rune that is not a quotation
// mark starts at i in code position: primes (′ ″), ornaments (❝ ❞), dashes, math and currency
// signs, emoji. A value written between two of them is pasted text, not source -- python3, node,
// gofmt and terraform fmt reject all of them in code -- so, as for a typographic quote, the lexer
// cannot know where the author meant a string to be, and the file fails open.
//
// The runes these grammars DO accept in code are excluded: connector punctuation (Pc, ‿), and the
// identifier extras Python and JS take from Unicode's Other_ID_Start and Other_ID_Continue (℘ ℮ ·
// ・). U+FFFD has its own reason above. On the 58,055-file public corpus the README cites, adding this
// changed no finding.
func strayPunctuationAt(s string, i int) bool {
	r, w := utf8.DecodeRuneInString(s[i:])
	if w < 2 || r == utf8.RuneError {
		return false
	}
	if !unicode.IsPunct(r) && !unicode.IsSymbol(r) {
		return false
	}
	return !unicode.In(r, unicode.Pc, unicode.Other_ID_Start, unicode.Other_ID_Continue)
}

// cp1252Quote reports whether b, read as Windows-1252, is a quotation mark: 0x82 ‚, 0x84 „, 0x8B ‹,
// 0x91 ‘, 0x92 ’, 0x93 “, 0x94 ”, 0x9B ›, 0xAB « or 0xBB ».
func cp1252Quote(b byte) bool {
	switch b {
	case 0x82, 0x84, 0x8B, 0x91, 0x92, 0x93, 0x94, 0x9B, 0xAB, 0xBB:
		return true
	}
	return false
}

// hclHeredocOpener parses `<<ID` or `<<-ID` at i followed by nothing but whitespace and the end of
// the line, and returns the identifier and the offset of the body's first byte.
//
// It reads only as far as the first byte after the identifier that is not whitespace, never to the
// end of the line: a rejected opener costs its identifier and the whitespace after it, so a line
// of thousands of `<<ID x` tokens is one pass, not one per token
// (TestSourceLexerIsLinearOnHCLHeredocOpeners).
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
	// The same test as strings.TrimSpace(rest of line) == "", stopping at the first non-space rune.
	eol := k
	for eol < len(s) && s[eol] != '\n' {
		r, size := utf8.DecodeRuneInString(s[eol:])
		if !unicode.IsSpace(r) {
			return "", 0, false
		}
		eol += size
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
