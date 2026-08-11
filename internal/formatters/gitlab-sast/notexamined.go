// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import "github.com/awslabs/ferret-scan/v2/internal/formatters"

// scanMessageLevelWarn is the GitLab schema's level for a partial error.
//
// The v15.0.4 enum is [info, warn, fatal] and the schema describes "warn" as "a
// potentially recoverable problem, or a partial error" — which is what an
// unexamined file is. NOT "warning": that is SARIF's spelling and is invalid here,
// and the reverse is equally true. Both enums exist in this codebase, so the
// constant is named to make a copy-paste between them fail visibly.
const scanMessageLevelWarn = "warn"

// addNotExaminedMessages appends the not-examined disclosure to scan.messages.
//
// Called BEFORE the formatter's zero-matches early return: a clean-looking report
// over unreadable files is the case this exists for, and that is the path that
// returns early.
//
// Emits a leading summary line and then one line per file, capped. The summary
// comes first so a consumer that shows only the first message still learns coverage
// was incomplete, and it states the TOTAL, so the cap can never hide the scale.
func addNotExaminedMessages(report *GitLabSecurityReport, options formatters.FormatterOptions) {
	if report == nil || len(options.NotExamined) == 0 {
		return
	}

	shown, total := formatters.CapNotExamined(options.NotExamined)

	// Non-nil so the field marshals as [] rather than null if anything later
	// truncates it; omitempty on the field keeps a complete scan unchanged.
	msgs := make([]GitLabScanMessage, 0, len(shown)+1)
	msgs = append(msgs, GitLabScanMessage{
		Level: scanMessageLevelWarn,
		Value: formatters.NotExaminedSummary(len(shown), total),
	})
	for _, f := range shown {
		// f.Message() guarantees a non-empty string, which the schema requires
		// (value has minLength 1). A zero-valued NotExaminedFile still yields a
		// valid message rather than an empty one that would fail validation.
		msgs = append(msgs, GitLabScanMessage{
			Level: scanMessageLevelWarn,
			Value: f.Message(),
		})
	}

	report.Scan.Messages = append(report.Scan.Messages, msgs...)
}
