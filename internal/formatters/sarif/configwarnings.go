// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// configWarningNotificationID is the descriptor id every configured-value warning cites.
//
// Its own id, not detection-disabled-by-config's: that one says configuration narrowed what the run
// looked for, on purpose; this one says a value the operator wrote could not be used at all, so what it
// configured did not happen. A consumer filtering on descriptor id must be able to tell the two apart.
const configWarningNotificationID = "ferret-scan/config-value-unusable"

// attachConfigWarnings carries the configured values the run's validators could not use (#903) into
// run.invocations[].toolConfigurationNotifications[], one notification per value, in the order
// Stats.ConfigWarnings lists them.
//
// The slot is the one SARIF 2.1.0 defines for this: the schema describes the invocation's
// toolConfigurationNotifications as "a list of conditions detected by the tool that are relevant to the
// tool's configuration", beside toolExecutionNotifications, which carries the runtime conditions (a file
// not examined, a value not redacted, coverage narrowed). The notification shape is the same
// {descriptor, level, message} the other disclosures use, because notification.additionalProperties is
// false; the descriptor is declared once in tool.driver.notifications, which has uniqueItems:true.
//
// Level "warning" for the reason newDisabledTypesNotification gives: a gate should be able to fail on
// a pattern that silently stopped detecting, and "error" would invite a consumer to discard results that
// are valid. executionSuccessful stays true for the same reason.
//
// The message is the warning line without the CLI's "Warning: " prefix. It names the value's path and
// what is wrong with it, never the value: an internal_urls entry is an internal hostname, and this
// document goes to CI logs and dashboards (see config.InvalidRegex).
//
// Nothing is added when there is no warning, so a run whose configuration is usable keeps every byte.
func attachConfigWarnings(run *SARIFRun, options formatters.FormatterOptions) {
	if run == nil || options.Stats == nil || len(options.Stats.ConfigWarnings) == 0 {
		return
	}

	notifications := make([]SARIFNotification, 0, len(options.Stats.ConfigWarnings))
	for _, line := range options.Stats.ConfigWarnings {
		notifications = append(notifications, SARIFNotification{
			Descriptor: &SARIFReportingDescriptorRef{ID: configWarningNotificationID},
			Level:      LevelWarning,
			Message:    SARIFMessage{Text: line},
		})
	}

	// One invocation for one run, extended if another disclosure created it.
	if len(run.Invocations) > 0 {
		run.Invocations[0].ToolConfigurationNotifications = append(
			run.Invocations[0].ToolConfigurationNotifications, notifications...)
	} else {
		run.Invocations = append(run.Invocations, SARIFInvocation{
			ExecutionSuccessful:            true,
			ToolConfigurationNotifications: notifications,
		})
	}

	for _, existing := range run.Tool.Driver.Notifications {
		if existing.ID == configWarningNotificationID {
			return
		}
	}
	run.Tool.Driver.Notifications = append(run.Tool.Driver.Notifications, SARIFRule{
		ID: configWarningNotificationID,
		ShortDescription: SARIFMessage{
			Text: "A configured value could not be used, so what it configured did not take effect",
		},
		FullDescription: SARIFMessage{
			Text: "A value under validators: in the configuration could not be used by its validator: a " +
				"regular expression RE2 rejects, an entry of the wrong type, or a scalar where a list " +
				"belongs. The value was dropped, so the detection, disable or allowlist it configured did " +
				"not happen for this run. The message names the value's path and the problem.",
		},
	})
}
