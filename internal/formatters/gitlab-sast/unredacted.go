// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import "github.com/awslabs/ferret-scan/v2/internal/formatters"

// addUnredactedMessages appends the redaction disclosure to scan.messages.
//
// Same slot and same shape as addNotExaminedMessages, because the two are the same
// kind of statement about the run: a fact the consumer needs that is not a finding.
//
// NOT a vulnerability entry, which was the tempting alternative. The values in this
// file are ALREADY reported as vulnerabilities — that is what makes them unredacted —
// so adding another entry for the same bytes would double-count the exposure on the
// GitLab Security Dashboard and inflate every count derived from it. scan.messages is
// where "something about this run you should know" belongs.
//
// Called BEFORE the formatter's zero-matches early return, for the same reason the
// not-examined disclosure is: although a file with no findings cannot be unredacted,
// the early return is shared and a future change to either condition must not silently
// drop this.
//
// Level "warn" — GitLab's spelling, and deliberately not SARIF's "warning". Both
// formats are emitted by this codebase and the constant is named to make a
// copy-paste between them fail visibly.
func addUnredactedMessages(report *GitLabSecurityReport, options formatters.FormatterOptions) {
	if report == nil || len(options.Unredacted) == 0 {
		return
	}

	shown, total := formatters.CapUnredacted(options.Unredacted)
	values := formatters.UnredactedValueCount(options.Unredacted)

	msgs := make([]GitLabScanMessage, 0, len(shown)+1)
	// Summary first, so a consumer showing only the first message still learns values
	// are in cleartext, and it states the TOTALS so the cap cannot hide the scale.
	msgs = append(msgs, GitLabScanMessage{
		Level: scanMessageLevelWarn,
		Value: formatters.UnredactedSummary(len(shown), total, values),
	})
	for _, f := range shown {
		// f.Message() guarantees a non-empty string, which the schema requires
		// (value has minLength 1). A zero-valued UnredactedFile still yields a valid
		// message rather than an empty one that would fail validation.
		msgs = append(msgs, GitLabScanMessage{
			Level: scanMessageLevelWarn,
			Value: f.Message(),
		})
	}

	report.Scan.Messages = append(report.Scan.Messages, msgs...)
}
