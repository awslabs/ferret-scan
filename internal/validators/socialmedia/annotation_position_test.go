// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"
)

// #484: the doc-annotation filter suppressed a bare handle by WORD ALONE.
//
// All 34 words in docPatterns are also plausible account names, and the filter had no position check,
// so each one was suppressed in every file type and every context. Measured on merged main, two prose
// lines per word in a .txt file where the token can only be a handle:
//
//	docPatterns words reported   0 of 16
//	identically-shaped controls  4 of 4      (@schneems @tleish @dhh @jack)
//
// The controls are what make that non-vacuous. The suppression was silent -- "No matches found.",
// exit 0, and no redacted file at all -- and a suppressed finding is a cleartext leak, because only
// reported findings reach the redactor.
//
// A recall hunt confirmed the cost is real: `@yields` is a GitHub account credited in the `debug`
// package's CHANGELOG in the same credit-line shape as roughly twenty other real handles in that file.
//
// After the position gate, measured on the same corpora:
//
//	prose words reported          16 of 16   (controls still 4 of 4)
//	1,633 real CSS/JS files       10,225 -> 10,243, i.e. +18 findings, 0.18%
//
// Those 18 are all doc annotations used MID-LINE rather than at the start of a comment body --
// `* Default: @see stream.getDefaultHighWaterMark().` and `* -@return {...}` -- which is the
// irreducible residual of a line-local rule.

// TestAnnotationPositionAcceptsEveryBlockShape covers the languages a doc annotation appears in.
//
// The JSDoc CONTINUATION line is the one that matters most by volume: it carries only a `*`, so the
// pre-existing earliestCommentMarker check (which looks for `//` and `/*`) cannot see it, and
// `@returns` alone was 4,420 findings on the real corpus.
func TestAnnotationPositionAcceptsEveryBlockShape(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"jsdoc continuation", ` * @author Jane`},
		{"jsdoc continuation, tab indented", "\t\t * @param x"},
		{"doc block opener", `/** @author Jane`},
		{"line comment", `// @todo fix this`},
		{"hash comment", `# @param x`},
		{"semicolon comment", `; @note something`},
		{"sql double dash", `-- @see other_table`},
		{"bare, inside a doc block", `@author Jane`},
		{"indented bare", `    @author Jane`},
		{"block comment opener", `/* @deprecated */`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			off := strings.Index(tc.line, "@")
			if off < 0 {
				t.Fatalf("fixture %q has no @, so it tests nothing", tc.line)
			}
			if !isAtAnnotationPosition(tc.line, off) {
				t.Errorf("%q was not recognised as an annotation position, so this annotation now "+
					"reports as a TWITTER handle at confidence 100", tc.line)
			}
		})
	}
}

// TestAnnotationPositionAcceptsInlineTags is the shape a first version of this missed, and the miss
// made precision WORSE by 4,950 findings on `@link` alone.
//
// JSDoc and Javadoc have an inline tag family written mid-line inside braces. Rejecting it as "not at
// the start of a line" was right about the position and wrong about the conclusion.
func TestAnnotationPositionAcceptsInlineTags(t *testing.T) {
	for _, line := range []string{
		`{@link Foo}`,
		` * See {@link module:bar} for details`,
		` * @returns {@link Foo} the thing`,
		`{@code x == 1}`,
		` * {@linkcode Bar#baz}`,
	} {
		t.Run(line, func(t *testing.T) {
			// The LAST @ is the inline tag in the @returns case, which also has a block tag.
			off := strings.LastIndex(line, "@")
			if !isAtAnnotationPosition(line, off) {
				t.Errorf("%q: the inline tag was not recognised. `@link` alone was 4,950 findings "+
					"on a real corpus when this shape was missed.", line)
			}
		})
	}
}

// TestAnnotationPositionRejectsProse is the direction that must not break, and the reason #484 exists.
//
// A bare word in a sentence can only be somebody's account, and a suppressed finding is a cleartext
// leak. Each of these uses a word that IS in docPatterns, so before the gate every one was silently
// dropped.
func TestAnnotationPositionRejectsProse(t *testing.T) {
	for _, line := range []string{
		`Follow @author for updates on the launch.`,
		`Our support account on X is @note and the team replies within a day.`,
		`he is "@see" on twitter`,
		`credits: @code and @link maintain this`,
		`mention @table in your reply`,
		// A comment marker to the RIGHT says nothing about the handle.
		`Follow @author for updates // see also the docs`,
		// A marker mid-line is not a comment opener.
		`values = a * @author`,
		`total = 4 - @post`,
		// A single dash is a Markdown bullet, not a SQL comment: a contributors list must report.
		`- @author`,
		`  - @service`,
	} {
		t.Run(line, func(t *testing.T) {
			off := strings.Index(line, "@")
			if isAtAnnotationPosition(line, off) {
				t.Errorf("%q was treated as an annotation position, so a real handle is suppressed. "+
					"Only reported findings reach the redactor.", line)
			}
		})
	}
}

// TestTwoDashesAreAComment pins the asymmetry the single-dash rule creates, in both directions.
func TestTwoDashesAreAComment(t *testing.T) {
	if !isAtAnnotationPosition(`-- @see other`, strings.Index(`-- @see other`, "@")) {
		t.Error("`-- @see` is a SQL/Lua comment and should be an annotation position")
	}
	if isAtAnnotationPosition(`- @see other`, strings.Index(`- @see other`, "@")) {
		t.Error("`- @see` is a Markdown bullet. Treating it as a comment suppresses a contributors " +
			"list, which is a list of real handles.")
	}
}

// TestDocWordsInProseReachTheValidator is the end-to-end sink assertion.
//
// The unit cases above pin the predicate; this drives the real validator, because what decides whether
// the redactor ever sees a handle is the finding, not the predicate. Every word here is in docPatterns.
func TestDocWordsInProseReachTheValidator(t *testing.T) {
	v := newConfiguredValidator()

	for _, word := range []string{"author", "note", "see", "link", "code", "post", "table", "service"} {
		t.Run(word, func(t *testing.T) {
			content := "Follow @" + word + " for updates on the launch.\n" +
				"Our support account on X is @" + word + " and the team replies within a day.\n"
			matches, err := v.ValidateContent(content, "mentions.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			var got int
			for _, m := range matches {
				if strings.EqualFold(m.Type, "TWITTER") {
					got++
				}
			}
			if got == 0 {
				t.Errorf("@%s in unambiguous prose produced no TWITTER finding. It is in the "+
					"doc-annotation word list, and before the position gate that alone was enough to "+
					"suppress it everywhere -- silently, at exit 0, with no redacted file.", word)
			}
		})
	}
}

// TestRealAnnotationsAreStillFilteredByTheValidator is the other end-to-end direction.
//
// The gate must not cost the filter its purpose: a genuine annotation must still be suppressed, or
// this trade is a precision regression rather than a recall fix.
//
// Every tag here is one docPatterns actually contains. `@returns` is deliberately ABSENT from this
// fixture: the list holds `return` in the singular, so `@returns` has always reported and is the
// largest single item in the residual #483 recorded and left alone on purpose (4,420 findings on a
// 1,633-file corpus). A first version of this test used it and failed for that reason, which is worth
// keeping written down -- the filter is a word list, so "is a real annotation" and "is filtered" are
// not the same set.
func TestRealAnnotationsAreStillFilteredByTheValidator(t *testing.T) {
	v := newConfiguredValidator()

	content := "/**\n" +
		" * Does a thing.\n" +
		" * @author Jane\n" +
		" * @param x the input\n" +
		" * @return {@link Foo} the result\n" +
		" * @see {@link module:bar}\n" +
		" * @deprecated use the other one\n" +
		" */\n" +
		"# @param y\n" +
		"-- @see other_table\n"
	matches, err := v.ValidateContent(content, "lib.js")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	for _, m := range matches {
		if strings.EqualFold(m.Type, "TWITTER") {
			t.Errorf("a genuine doc annotation reported as a TWITTER handle (%q at %.0f). The "+
				"position gate must keep the filter working for real annotations.", m.Text, m.Confidence)
		}
	}
}
