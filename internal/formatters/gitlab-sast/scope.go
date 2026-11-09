// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"fmt"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// scanMessageLevelInfo is the GitLab schema's level for a fact that is not a problem.
const scanMessageLevelInfo = "info"

// addScopeMessages appends the scope of a NARROWED run to scan.messages (#904). A full-scope run has
// no scope and gains nothing, so its report keeps every byte.
//
// Before this, a GitLab Security Dashboard could not tell a narrowed scan from a clean one: the
// report has no field for which checks ran, and `--checks SSN` over a file holding an email address
// wrote the empty vulnerabilities array a clean full scan writes. Messages, not vulnerabilities: a
// check that did not run has no location, and a vulnerability entry would fabricate one.
//
//   - warn for checks that did not run, and for each validator whose sub-types config disabled (the
//     #623 disclosure, which this format never carried): the report cannot speak for those;
//   - info when the confidence filter hides a band, and when suppression rules hid findings.
//
// Called before the formatter's zero-matches early return, which is the path a narrowed scan that
// found nothing takes.
func addScopeMessages(report *GitLabSecurityReport, options formatters.FormatterOptions) {
	s := options.Scan
	if report == nil || s == nil {
		return
	}

	var msgs []GitLabScanMessage
	if len(s.ChecksNotRun) > 0 {
		// Worded so no count sits before "run": "19 checks did not run" scans as a street address.
		msgs = append(msgs, GitLabScanMessage{
			Level: scanMessageLevelWarn,
			Value: fmt.Sprintf("ferret-scan: checks not run for this scan (%d of %d): %s. This report "+
				"cannot be read as evidence that findings those checks detect are absent.",
				len(s.ChecksNotRun), s.TotalChecks(), strings.Join(s.ChecksNotRun, ", ")),
		})
	}

	validators := make([]string, 0, len(s.DisabledDetectionTypes))
	for name := range s.DisabledDetectionTypes {
		validators = append(validators, name)
	}
	sort.Strings(validators)
	for _, name := range validators {
		subTypes := s.DisabledDetectionTypes[name]
		msgs = append(msgs, GitLabScanMessage{
			Level: scanMessageLevelWarn,
			Value: fmt.Sprintf("ferret-scan: config disabled %d %s detection sub-type(s) for this scan: %s. "+
				"This report cannot be read as evidence that those sub-types are absent.",
				len(subTypes), name, strings.Join(subTypes, ", ")),
		})
	}

	if hidden := s.HiddenConfidenceLevels(); len(hidden) > 0 {
		msgs = append(msgs, GitLabScanMessage{
			Level: scanMessageLevelInfo,
			Value: fmt.Sprintf("ferret-scan: the confidence filter hid %s findings from this report.",
				strings.Join(hidden, " and ")),
		})
	}

	if options.Stats != nil && options.Stats.Suppressed > 0 {
		msgs = append(msgs, GitLabScanMessage{
			Level: scanMessageLevelInfo,
			Value: fmt.Sprintf("ferret-scan: %d finding(s) were suppressed by suppression rules and are not listed.",
				options.Stats.Suppressed),
		})
	}

	report.Scan.Messages = append(report.Scan.Messages, msgs...)
}
