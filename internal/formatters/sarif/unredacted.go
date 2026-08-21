// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import "github.com/awslabs/ferret-scan/v2/internal/formatters"

// unredactedNotificationID is the descriptor id shared by every unredacted
// notification.
//
// One descriptor for the whole class, for the same reason not-examined has one:
// tool.driver.notifications has uniqueItems:true, so a per-file descriptor would
// duplicate the object and invalidate the document on a run with two unredactable
// files of the same cause.
//
// Distinct from notExaminedNotificationID because a consumer filtering on descriptor
// id must be able to tell "we never read this file" from "we read it, found values,
// and left them in cleartext" — the remedies are unrelated.
const unredactedNotificationID = "ferret-scan/not-redacted"

// attachUnredacted adds the unredacted disclosure to a SARIF run.
//
// Same slot as the not-examined disclosure —
// run.invocations[].toolExecutionNotifications[] — and the alternatives were rejected
// on the same evidence, which applies here with more force:
//
//   - a new run-level key: run.additionalProperties is FALSE in SARIF 2.1.0, so it is
//     invalid, and an invalid report is rejected whole. Losing the report to carry
//     the disclosure defeats the disclosure.
//   - a result with kind:"informational": GitHub renders results as code scanning
//     alerts, so "this file was not redacted" would appear as a PII finding at a
//     location. The values ARE reported already, as their own results; adding a
//     second alert for the same bytes would double-count the exposure.
//
// Appends to an existing invocation rather than adding a second one when
// attachNotExamined has already run: invocations[] means "one entry per tool
// invocation", and there was one invocation. Two entries would claim the tool ran
// twice.
//
// The disclosure is machine-readable only, since GitHub's UI does not surface
// toolExecutionNotifications. Accepted for the same reason as not-examined: a valid,
// quiet, programmatically-checkable statement beats a visible fabricated alert.
func attachUnredacted(run *SARIFRun, options formatters.FormatterOptions) {
	if run == nil || len(options.Unredacted) == 0 {
		return
	}

	shown, total := formatters.CapUnredacted(options.Unredacted)
	values := formatters.UnredactedValueCount(options.Unredacted)

	notifications := make([]SARIFNotification, 0, len(shown)+1)

	// Summary first, so a consumer that reads only the first notification still
	// learns values are in cleartext, and so the totals survive the cap.
	notifications = append(notifications, newUnredactedNotification(
		formatters.UnredactedSummary(len(shown), total, values)))
	for _, f := range shown {
		notifications = append(notifications, newUnredactedNotification(f.Message()))
	}

	// One invocation for one run: extend the existing entry if there is one.
	if len(run.Invocations) > 0 {
		run.Invocations[0].ToolExecutionNotifications = append(
			run.Invocations[0].ToolExecutionNotifications, notifications...)
	} else {
		run.Invocations = append(run.Invocations, SARIFInvocation{
			// True, always. This is the object's only required member, and false
			// means "the analysis did not complete", which consumers may treat as
			// grounds to discard the results. The analysis completed; the WRITE did
			// not, and the findings it produced are valid and must be kept.
			ExecutionSuccessful:        true,
			ToolExecutionNotifications: notifications,
		})
	}

	// Declare the descriptor the notifications reference, exactly once.
	for _, existing := range run.Tool.Driver.Notifications {
		if existing.ID == unredactedNotificationID {
			return
		}
	}
	run.Tool.Driver.Notifications = append(run.Tool.Driver.Notifications, SARIFRule{
		ID: unredactedNotificationID,
		ShortDescription: SARIFMessage{
			Text: "Findings were reported for this file but not redacted, so the values remain in cleartext",
		},
		FullDescription: SARIFMessage{
			Text: "The scanner reported sensitive values in this file but wrote no redacted copy, " +
				"so the original values are unchanged. The findings in this report are accurate; " +
				"what did not happen is the redaction. Treat any pipeline step that expected a " +
				"sanitized artifact for this file as not having received one.",
		},
	})
}

// newUnredactedNotification builds one notification.
//
// Level "warning" — the SARIF enum is none/note/warning/error. NOT "warn", which is
// GitLab's spelling and invalid here. Both formats are emitted by this codebase, so
// the distinction is called out at every site that could be copy-pasted.
//
// Warning rather than error for the same reason executionSuccessful stays true: the
// run produced valid results. "error" in SARIF describes the analysis failing, and a
// consumer may discard results on it — which would throw away the very findings that
// say what is in cleartext.
func newUnredactedNotification(text string) SARIFNotification {
	return SARIFNotification{
		Descriptor: &SARIFReportingDescriptorRef{ID: unredactedNotificationID},
		Level:      LevelWarning,
		Message:    SARIFMessage{Text: text},
	}
}
