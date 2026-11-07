// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"fmt"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// attachScope discloses what a NARROWED run could report (#904): the scope as run.properties, one
// warning notification when checks did not run, and the commit on the driver. A full-scope run has
// no scope (formatters.NewScanScope returns nil) and gains nothing, so its document keeps every byte.
//
// Measured on main before this existed: `--checks SSN` over a file holding a copyright notice and an
// email address produced a valid SARIF document with zero results, zero notifications and the same
// three run keys as a clean scan of a neutral file. tool.driver.rules cannot stand in for the checks
// that ran, because it lists only rules that produced results.
//
// run.properties rather than a new run-level key, because run.additionalProperties is false in SARIF
// 2.1.0; the property bag is the spec's slot for tool-specific data, and the truncation disclosure
// already uses it, so the two are merged rather than one replacing the other.
//
// The notification reuses the detection-disabled-by-config descriptor rather than declaring a second
// one: tool.driver.notifications is one entry per class (uniqueItems:true), and "a check did not run"
// and "a sub-type was switched off" are the same class of fact, coverage narrowed by configuration.
func attachScope(run *SARIFRun, options formatters.FormatterOptions) {
	s := options.Scan
	if run == nil || s == nil {
		return
	}

	if run.Properties == nil {
		run.Properties = map[string]interface{}{}
	}
	run.Properties["ferretScanChecksRun"] = s.ChecksRun
	run.Properties["ferretScanChecksNotRun"] = s.ChecksNotRun
	if len(s.ChecksNotApplicable) > 0 {
		run.Properties["ferretScanChecksNotApplicable"] = s.ChecksNotApplicable
	}
	run.Properties["ferretScanConfidenceLevels"] = s.ConfidenceLevels
	if s.Profile != nil {
		run.Properties["ferretScanProfile"] = s.Profile.Name
		run.Properties["ferretScanProfileSelectedBy"] = s.Profile.SelectedBy
	}
	run.Properties["ferretScanConfigSource"] = s.Config.Source
	if s.Config.Name != "" {
		run.Properties["ferretScanConfigName"] = s.Config.Name
	}
	run.Properties["ferretScanSuppressionRulesEnabled"] = s.Suppressions.RulesEnabled
	if options.Stats != nil {
		run.Properties["ferretScanSuppressed"] = options.Stats.Suppressed
	}

	// version and semanticVersion stay plain semver; the commit rides in the driver's property bag,
	// 12 hex digits at most so the report does not self-flag as a secret (version.ReportCommit).
	if s.Tool != nil {
		if run.Tool.Driver.Properties == nil {
			run.Tool.Driver.Properties = map[string]interface{}{}
		}
		run.Tool.Driver.Properties["ferretScanCommit"] = s.Tool.Commit
	}

	if len(s.ChecksNotRun) == 0 {
		// Narrowed by the confidence filter or a disabled sub-type only: the properties say which,
		// and attachDisabledDetectionTypes carries the sub-types' own notification.
		return
	}
	// Worded so no count sits before "run": "19 checks did not run" scans as a street address.
	appendNarrowingNotifications(run, newDisabledTypesNotification(fmt.Sprintf(
		"Checks not run for this scan (%d of %d): %s. This report cannot be read as evidence that "+
			"findings those checks detect are absent.",
		len(s.ChecksNotRun), s.TotalChecks(), strings.Join(s.ChecksNotRun, ", "))))
}

// appendNarrowingNotifications adds notifications to the run's one invocation, creating it when no
// other disclosure has, and declares the shared descriptor exactly once.
func appendNarrowingNotifications(run *SARIFRun, notifications ...SARIFNotification) {
	if len(run.Invocations) > 0 {
		run.Invocations[0].ToolExecutionNotifications = append(
			run.Invocations[0].ToolExecutionNotifications, notifications...)
	} else {
		run.Invocations = append(run.Invocations, SARIFInvocation{
			// True, always. Its only required member, and false means "the analysis did not
			// complete", which consumers may treat as grounds to discard results. The analysis
			// completed exactly as configured; it was configured to look at less.
			ExecutionSuccessful:        true,
			ToolExecutionNotifications: notifications,
		})
	}

	for _, existing := range run.Tool.Driver.Notifications {
		if existing.ID == disabledTypesNotificationID {
			return
		}
	}
	run.Tool.Driver.Notifications = append(run.Tool.Driver.Notifications, SARIFRule{
		ID: disabledTypesNotificationID,
		ShortDescription: SARIFMessage{
			Text: "Configuration narrowed detection, so this report covers less than the full validator set",
		},
		FullDescription: SARIFMessage{
			Text: "A configuration file, a profile or a command-line flag stopped checks from running or " +
				"switched detection sub-types off for this run, so no finding of those could be produced " +
				"for any file. The results present are accurate; what cannot be concluded is that the " +
				"excluded checks or sub-types are absent. A config discovered in the working directory " +
				"governs the scan, so in CI this can be set by the same change the scan is reviewing.",
		},
	})
}
