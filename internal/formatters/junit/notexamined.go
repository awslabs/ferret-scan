// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"encoding/xml"
	"fmt"
	"path/filepath"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// notExaminedSuiteName is the suite that holds unexamined files.
//
// A SEPARATE suite, not extra cases in the findings suite, so that suite's tests=
// attribute keeps meaning "files examined". Mixing the two makes a dashboard's test
// count a number that answers no question. This follows the existing
// suppressed-findings suite, which solved the same problem the same way.
const notExaminedSuiteName = "not-examined"

// buildNotExaminedSuite renders the not-examined disclosure as a JUnit suite.
//
// Returns false when there is nothing to disclose, so a complete scan is
// byte-for-byte unchanged.
//
// VALENCE, which is the whole design question here:
//
//   - default: <skipped>. Universal JUnit vocabulary, and non-failing in every
//     consumer — Jenkins, GitLab and the xunit family all count skipped separately
//     from failures. A file nobody could read is genuinely "not run", which is what
//     skipped means.
//   - --fail-on-incomplete: <error>. The operator has declared incomplete coverage a
//     failure and the process already exits 3, so the XML agrees with the exit code
//     rather than contradicting it.
//
// Emitting <error> unconditionally was rejected: it turns currently-green pipelines
// red on the first unreadable file. A disclosure that changes a build verdict without
// being asked is a behaviour change wearing a disclosure's clothes.
func buildNotExaminedSuite(options formatters.FormatterOptions) (TestSuite, bool) {
	if len(options.NotExamined) == 0 {
		return TestSuite{}, false
	}

	shown, total := formatters.CapNotExamined(options.NotExamined)

	suite := TestSuite{
		XMLName:   xml.Name{Local: "testsuite"},
		Name:      notExaminedSuiteName,
		Time:      "0.000",
		TestCases: make([]TestCase, 0, len(shown)),
		// The summary states the TOTAL, so the cap above can never make the report
		// understate how much was missed.
		SystemOut: formatters.NotExaminedSummary(len(shown), total),
	}

	for _, nf := range shown {
		tc := TestCase{
			XMLName: xml.Name{Local: "testcase"},
			// The base name keeps the case list readable; the full path is in the
			// message, so nothing is lost.
			Name:      filepath.Base(nf.Path),
			ClassName: notExaminedSuiteName,
			Time:      "0.000",
		}
		msg := nf.Message()
		if options.FailOnIncomplete {
			tc.Error = &Failure{
				Message: msg,
				Type:    "NotExamined",
				Content: notExaminedContent(nf),
			}
			suite.Errors++
		} else {
			tc.Skipped = &Skipped{
				Message: msg,
				Content: notExaminedContent(nf),
			}
		}
		suite.TestCases = append(suite.TestCases, tc)
	}
	suite.Tests = len(suite.TestCases)

	return suite, true
}

// notExaminedContent is the element body: the detail a reader needs to act, and the
// explicit statement that silence here is not a clean bill of health.
//
// Deliberately does NOT begin with "Line ", because the shared limit-parity test
// counts finding lines by that prefix and these are not findings.
func notExaminedContent(nf formatters.NotExaminedFile) string {
	return fmt.Sprintf("%s\nCause: %s\nFindings may be missing for this file; "+
		"the absence of findings is not evidence that it contains no sensitive data.",
		nf.Path, nf.Cause)
}
