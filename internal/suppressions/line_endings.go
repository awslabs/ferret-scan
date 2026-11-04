// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// otherLineEnding returns the finding as it would have been recorded in a copy of its file with the
// other line ending, so a rule an older formula wrote in an LF file matches the same finding in a
// CRLF copy and the other way round (#885). The older formulas digest the windows raw, and a CRLF
// line's `\r` is its last byte: it lands at the end of an after-window that reaches the line end, or,
// when there is no after-window, at the end of a value whose pattern swallows trailing whitespace (the
// intellectual-property span). Nothing else about a finding depends on the line ending: FullLine is
// trimmed, and the before-window ends where the value starts.
//
// A finding recorded with a `\r` (in AfterText or Text) yields its LF form. A finding from a line not
// ending in `\r` yields the CRLF forms when its after-window reaches the line end: the window with a `\r`
// appended, or, when the window is empty, an after-window of `\r` and the value with a `\r` appended,
// because which of the two a CRLF file gave depends on the validator. "Reaches the line end" is
// decided on AfterText alone (a non-empty suffix of FullLine, or empty with Text a suffix), because
// the intellectual-property validator's Text and AfterText are not always contiguous.
//
// Every variant keeps the finding's type, line, basename, line number, before-window and value
// (modulo the `\r`), so it can only match a rule written for this same finding.
func otherLineEnding(match detector.Match) []detector.Match {
	after, text, line := match.Context.AfterText, match.Text, match.Context.FullLine
	if strings.HasSuffix(after, "\r") || strings.HasSuffix(text, "\r") {
		lf := match
		lf.Context.AfterText = strings.TrimSuffix(after, "\r")
		lf.Text = strings.TrimSuffix(text, "\r")
		return []detector.Match{lf}
	}
	// A CRLF line ends in its `\r`. Only the end is looked at: FullLine can be a whole file on one
	// line, and this runs per finding, so scanning it would make the suppression layer quadratic.
	if strings.HasSuffix(line, "\r") {
		return nil
	}
	switch {
	case after != "" && strings.HasSuffix(line, after):
		crlf := match
		crlf.Context.AfterText = after + "\r"
		return []detector.Match{crlf}
	case after == "" && text != "" && strings.HasSuffix(line, text):
		inWindow, inValue := match, match
		inWindow.Context.AfterText = "\r"
		inValue.Text = text + "\r"
		return []detector.Match{inWindow, inValue}
	}
	return nil
}
