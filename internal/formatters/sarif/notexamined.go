// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import "github.com/awslabs/ferret-scan/v2/internal/formatters"

// notExaminedNotificationID is the descriptor id shared by every not-examined
// notification.
//
// One descriptor for the whole class, cited by each notification, because
// tool.driver.notifications has uniqueItems:true — a per-file descriptor would
// duplicate the object and invalidate the document on a run with two unreadable
// files of the same cause.
const notExaminedNotificationID = "ferret-scan/not-examined"

// attachNotExamined adds the not-examined disclosure to a SARIF run.
//
// Slot choice: run.invocations[].toolExecutionNotifications[], whose spec
// description is precisely this ("runtime conditions detected by the tool during the
// analysis"). The alternatives were rejected on evidence, not taste:
//
//   - a new run-level key ("notExamined"): run.additionalProperties is FALSE in
//     SARIF 2.1.0, so this is invalid, and GitLab rejects an invalid report whole.
//   - a result with kind:"informational": GitHub renders results as dismissable code
//     scanning alerts, so files that were never read would appear as PII findings —
//     fabricating findings to report a gap is worse than the gap.
//   - artifacts[].roles: a closed 23-value enum with no member meaning "not
//     examined".
//
// The disclosure is machine-readable only: GitHub's UI does not surface
// toolExecutionNotifications. That is the accepted trade — a valid, quiet,
// programmatically-checkable statement beats a visible fake alert.
func attachNotExamined(run *SARIFRun, options formatters.FormatterOptions) {
	if run == nil || len(options.NotExamined) == 0 {
		return
	}

	shown, total := formatters.CapNotExamined(options.NotExamined)

	notifications := make([]SARIFNotification, 0, len(shown)+1)

	// Summary first, so a consumer that reads only the first notification still
	// learns coverage was incomplete, and so the total survives the cap.
	notifications = append(notifications, newNotExaminedNotification(
		formatters.NotExaminedSummary(len(shown), total)))
	for _, f := range shown {
		notifications = append(notifications, newNotExaminedNotification(f.Message()))
	}

	run.Invocations = append(run.Invocations, SARIFInvocation{
		// True, always. This is the object's only required member, and false means
		// "the analysis did not complete", which consumers may treat as grounds to
		// discard the results. The run succeeded; its coverage was partial.
		ExecutionSuccessful:        true,
		ToolExecutionNotifications: notifications,
	})

	// Declare the descriptor the notifications reference, exactly once.
	for _, existing := range run.Tool.Driver.Notifications {
		if existing.ID == notExaminedNotificationID {
			return
		}
	}
	run.Tool.Driver.Notifications = append(run.Tool.Driver.Notifications, SARIFRule{
		ID: notExaminedNotificationID,
		ShortDescription: SARIFMessage{
			Text: "A file could not be fully examined, so findings may be missing",
		},
		FullDescription: SARIFMessage{
			Text: "The scanner could not read, parse or extract text from this file. " +
				"Its contents were not examined, so the absence of findings for it is " +
				"not evidence that it contains no sensitive data.",
		},
	})
}

// newNotExaminedNotification builds one notification.
//
// Level "warning" — the SARIF enum is none/note/warning/error. NOT "warn", which is
// GitLab's spelling and invalid here. Both formats are emitted by this codebase, so
// the distinction is called out at every site that could be copy-pasted.
func newNotExaminedNotification(text string) SARIFNotification {
	return SARIFNotification{
		Descriptor: &SARIFReportingDescriptorRef{ID: notExaminedNotificationID},
		Level:      LevelWarning,
		Message:    SARIFMessage{Text: text},
	}
}
