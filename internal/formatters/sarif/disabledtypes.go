// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"fmt"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// disabledTypesNotificationID is the descriptor id shared by every narrowed-detection notification.
//
// One descriptor for the class, for the reason not-examined and not-redacted each have one:
// tool.driver.notifications has uniqueItems:true, so a per-validator descriptor would duplicate the
// object and invalidate the document on a run that narrowed two validators.
//
// Distinct from the other two ids because a consumer filtering on descriptor id must be able to
// tell three unrelated facts apart: a file was never read, a file was read and left in cleartext,
// and DETECTION ITSELF was narrowed so a whole class of finding could not be produced anywhere.
// Only the third means the report's silence about a category proves nothing.
const disabledTypesNotificationID = "ferret-scan/detection-disabled-by-config"

// attachDisabledDetectionTypes discloses that config switched detection sub-types off (#293).
//
// SARIF got this first because it is the format most likely to be consumed by a machine with nobody
// reading stderr — which is exactly the reader who would otherwise take a narrowed scan for a clean
// one. (JUnit, gitlab-sast and text now carry the sub-types too, in the scope block a narrowed run
// renders; csv has no slot. See formatters.ScanScope.) Measured before this existed: a copyright notice scanned with
// `--config` naming a file that disabled `copyright` produced a valid SARIF document with zero
// results, zero notifications, and zero bytes of stderr.
//
// Same slot and the same rejected alternatives as the other two disclosures:
// run.invocations[].toolExecutionNotifications[], because run.additionalProperties is FALSE in
// SARIF 2.1.0 so a new run-level key is invalid, and a result with kind:"informational" would
// render in GitHub as a code-scanning alert at a location — but this fact has no location at all,
// so it would have to fabricate one.
func attachDisabledDetectionTypes(run *SARIFRun, options formatters.FormatterOptions) {
	if run == nil || options.Stats == nil || len(options.Stats.DisabledDetectionTypes) == 0 {
		return
	}

	// Sorted: the source is a map, and notification order must not vary between runs of an
	// unchanged scan or a byte-comparison of two reports shows a difference that is not one.
	validators := make([]string, 0, len(options.Stats.DisabledDetectionTypes))
	for name := range options.Stats.DisabledDetectionTypes {
		validators = append(validators, name)
	}
	sort.Strings(validators)

	notifications := make([]SARIFNotification, 0, len(validators))
	for _, name := range validators {
		subTypes := options.Stats.DisabledDetectionTypes[name]
		notifications = append(notifications, newDisabledTypesNotification(fmt.Sprintf(
			"Config disabled %d %s detection sub-type(s) for this scan: %s. This report cannot be "+
				"read as evidence that those sub-types are absent.",
			len(subTypes), name, strings.Join(subTypes, ", "))))
	}

	// One invocation for one run, extended if another disclosure created it, and the descriptor the
	// notifications reference declared exactly once. Shared with attachScope, whose checks-not-run
	// notification is the same class of fact (#904).
	appendNarrowingNotifications(run, notifications...)
}

// newDisabledTypesNotification builds one notification.
//
// Level "warning" — the SARIF enum is none/note/warning/error. NOT "warn", which is GitLab's
// spelling and invalid here; both formats are emitted by this codebase.
//
// Warning rather than note: reduced coverage in a DLP report is the kind of thing a gate should be
// able to fail on. Not "error", for the reason executionSuccessful stays true — a consumer may
// discard results on error, and the results here are valid.
func newDisabledTypesNotification(text string) SARIFNotification {
	return SARIFNotification{
		Descriptor: &SARIFReportingDescriptorRef{ID: disabledTypesNotificationID},
		Level:      LevelWarning,
		Message:    SARIFMessage{Text: text},
	}
}
