// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

// isAtAnnotationPosition reports whether the token at offset occupies a position a documentation
// annotation occupies.
//
// This is the second signal for the docPatterns vocabulary filter, and it exists because the word
// alone is not evidence. All 34 of those words -- author, note, see, link, code, post, table, column,
// service, entity, component, controller, hack, example among them -- are also plausible account
// names, so matching on the word suppressed the handle in every file type and every context,
// including unambiguous prose (#484).
//
// # There are TWO annotation shapes, not one
//
// A first version of this function accepted only the first shape and made precision WORSE, by 4,995
// findings on a 1,633-file real corpus. 4,950 of those were `@link`, because JSDoc and Javadoc have an
// INLINE tag family that is written mid-line inside braces:
//
//	JSDoc line:  " * @returns {@link Foo} the thing"   -- @returns is a BLOCK tag, @link an INLINE one
//
// Rejecting the inline form as "not at the start of a line" was correct about the position and wrong
// about the conclusion. So both shapes are accepted:
//
// BLOCK -- the token starts the line, or starts a comment body:
//
//	JSDoc/Javadoc continuation:   " * @author Jane"
//	opening a doc block:          "/** @author Jane"
//	line comment:                 "// @todo fix this"
//	Python, shell, YAML, Ruby:    "# @param x"
//	lisp, asm, ini:               "; @note"
//	SQL, Lua, Haskell:            "-- @see other"
//	bare, inside a doc block:     "@author Jane"
//
// INLINE -- the token sits immediately inside an opening brace:
//
//	{@link Foo}             JSDoc, Javadoc
//	{@code x == 1}          Javadoc
//	{@linkcode Bar}         JSDoc
//
// And the shape both must reject, which is the whole point:
//
//	Follow @author for updates on the launch.
//	Our support account on X is @note and the team replies within a day.
//
// # Why this is not redundant with earliestCommentMarker
//
// That check already handles `//` and `/*` appearing before the handle, and it runs a few lines below
// this one. It cannot cover the cases that matter most here: a JSDoc CONTINUATION line carries only a
// `*`, a Python or YAML comment carries only a `#`, a bare annotation inside a doc block carries no
// marker at all, and an inline `{@link}` has no comment marker to its left on that line either. Those
// are where the bulk of real annotations live -- `@returns` alone was 4,420 findings and `@link` 4,950.
//
// # The residual, stated rather than hidden
//
// A single `*` opens a JSDoc continuation AND a Markdown bullet, and the two are indistinguishable on
// one line, so a contributors list written as `* @author` is still suppressed. That is accepted
// deliberately: the JSDoc continuation dominates by orders of magnitude, and refusing a lone `*` would
// give up most of the filter's value. It is also far narrower than the behaviour it replaces, where
// `@author` was suppressed everywhere including plain prose.
//
// A single `-` is treated the other way for the same reason: `-` is overwhelmingly a Markdown bullet,
// while the SQL and Lua marker is `--`. Two dashes are required, so `- @author` in a bullet list stays
// reportable.
func isAtAnnotationPosition(line string, offset int) bool {
	if offset < 0 || offset > len(line) {
		return false
	}

	// INLINE shape first, because it needs no whitespace skipping: the brace is flush against the
	// token. `{ @link }` with a space is not something either tool emits.
	if offset > 0 && line[offset-1] == '{' {
		return true
	}

	i := skipSpacesLeft(line, offset-1)
	if i < 0 {
		return true // nothing but whitespace before it: line-initial
	}

	// At most one comment-opening run may sit between the start of the line and the token.
	switch line[i] {
	case '*', '/':
		// Covers `*`, `**`, `/*`, `/**` and `//` in one pass. Accepting `/` alone would also admit
		// a path fragment, but a path cannot be followed only by whitespace back to the start of
		// the line, which the check below requires.
		for i >= 0 && (line[i] == '*' || line[i] == '/') {
			i--
		}
	case '#':
		i--
	case ';':
		i--
	case '-':
		if i < 1 || line[i-1] != '-' {
			return false
		}
		for i >= 0 && line[i] == '-' {
			i--
		}
	default:
		return false
	}

	// Only whitespace may precede the marker. This is what stops a marker appearing mid-line from
	// counting -- `values = a * @author` is not a doc comment.
	return skipSpacesLeft(line, i) < 0
}

// skipSpacesLeft returns the index of the first non-space byte at or before i, or -1.
func skipSpacesLeft(line string, i int) int {
	for i >= 0 && (line[i] == ' ' || line[i] == '\t') {
		i--
	}
	return i
}
