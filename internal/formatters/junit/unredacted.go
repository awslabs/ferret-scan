// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"encoding/xml"
	"fmt"
	"path/filepath"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// unredactedSuiteName is the suite that holds files whose values were not redacted.
//
// Separate from the not-examined suite because a consumer filtering by classname must
// be able to tell "we never read this file" from "we read it, reported values, and left
// them in cleartext". The two need different remedies and only one of them means an
// artifact downstream is unsafe.
const unredactedSuiteName = "unredacted"

// buildUnredactedSuite renders the redaction disclosure as a JUnit suite.
//
// <failure>, UNCONDITIONALLY — deliberately unlike buildNotExaminedSuite, which emits
// <skipped> and escalates to <error> only under --fail-on-incomplete. Three reasons:
//
//  1. <skipped> renders grey or is filtered out entirely on most CI dashboards, which
//     is the wrong presentation for "sensitive values are still in cleartext". The
//     whole defect being fixed here (#441) is that this outcome was invisible; emitting
//     it as a skip would keep it invisible in the one artifact CI actually renders.
//  2. It must not depend on --fail-on-incomplete. A team that has not set that flag
//     still needs to see this, and the flag governs the EXIT CODE. Tying the XML
//     verdict to it would mean the report changes meaning based on a flag about
//     something else.
//  3. Not <error>, which in JUnit means the run itself misbehaved. The run did not: it
//     scanned correctly, reported correctly, and refused to write a file it could not
//     sanitize. The refusal is right; the exposure is what failed.
func buildUnredactedSuite(options formatters.FormatterOptions) (TestSuite, bool) {
	if len(options.Unredacted) == 0 {
		return TestSuite{}, false
	}

	shown, total := formatters.CapUnredacted(options.Unredacted)
	values := formatters.UnredactedValueCount(options.Unredacted)

	suite := TestSuite{
		XMLName:   xml.Name{Local: "testsuite"},
		Name:      unredactedSuiteName,
		Time:      "0.000",
		TestCases: make([]TestCase, 0, len(shown)),
		// The summary states the TOTALS, so the cap above can never make the report
		// understate how much is exposed.
		SystemOut: formatters.UnredactedSummary(len(shown), total, values),
	}

	for _, uf := range shown {
		tc := TestCase{
			XMLName: xml.Name{Local: "testcase"},
			// The base name keeps the case list readable; the full path is in the
			// message, so nothing is lost.
			Name:      filepath.Base(uf.Path),
			ClassName: unredactedSuiteName,
			Time:      "0.000",
		}
		tc.Failure = &Failure{
			Message: uf.Message(),
			Type:    "Unredacted",
			Content: unredactedContent(uf),
		}
		suite.Failures++
		suite.TestCases = append(suite.TestCases, tc)
	}
	suite.Tests = len(suite.TestCases)

	return suite, true
}

// unredactedContent is the element body: what a reader needs in order to act.
//
// Deliberately does NOT begin with "Line ", because the shared limit-parity test counts
// finding lines by that prefix and these are not findings.
func unredactedContent(uf formatters.UnredactedFile) string {
	return fmt.Sprintf("%s\nCause: %s\n%d reported value(s) remain in cleartext at the "+
		"original path. The findings for this file are accurate; what did not happen is the "+
		"redaction, so no sanitized artifact exists for it.",
		uf.Path, uf.Cause, uf.ReportedValues)
}
