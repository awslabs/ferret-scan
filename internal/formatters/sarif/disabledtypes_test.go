// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

func statsWithDisabled(m map[string][]string) formatters.FormatterOptions {
	return formatters.FormatterOptions{Stats: &formatters.ScanStats{DisabledDetectionTypes: m}}
}

func TestAttachDisabledDetectionTypes(t *testing.T) {
	t.Run("nothing disabled adds nothing", func(t *testing.T) {
		var run SARIFRun
		attachDisabledDetectionTypes(&run, statsWithDisabled(nil))
		if len(run.Invocations) != 0 || len(run.Tool.Driver.Notifications) != 0 {
			t.Errorf("an unnarrowed scan gained %d invocation(s) and %d descriptor(s); the document "+
				"must stay byte-identical", len(run.Invocations), len(run.Tool.Driver.Notifications))
		}
	})

	t.Run("nil Stats is not a panic", func(t *testing.T) {
		var run SARIFRun
		attachDisabledDetectionTypes(&run, formatters.FormatterOptions{})
		if len(run.Invocations) != 0 {
			t.Errorf("nil Stats produced %d invocation(s)", len(run.Invocations))
		}
	})

	t.Run("one notification per validator, with the sub-types named", func(t *testing.T) {
		var run SARIFRun
		attachDisabledDetectionTypes(&run, statsWithDisabled(
			map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright", "internal_url"}}))

		if len(run.Invocations) != 1 {
			t.Fatalf("got %d invocations, want 1", len(run.Invocations))
		}
		notes := run.Invocations[0].ToolExecutionNotifications
		if len(notes) != 1 {
			t.Fatalf("got %d notifications, want 1", len(notes))
		}
		if notes[0].Level != LevelWarning {
			t.Errorf("level = %q, want %q — a consumer gating on coverage needs something it can "+
				"fail on, and %q would let results be discarded", notes[0].Level, LevelWarning, LevelError)
		}
		if notes[0].Descriptor == nil || notes[0].Descriptor.ID != disabledTypesNotificationID {
			t.Errorf("descriptor = %v, want %q", notes[0].Descriptor, disabledTypesNotificationID)
		}
		for _, want := range []string{"INTELLECTUAL_PROPERTY", "copyright", "internal_url"} {
			if !strings.Contains(notes[0].Message.Text, want) {
				t.Errorf("message does not name %q: %q", want, notes[0].Message.Text)
			}
		}
		if !run.Invocations[0].ExecutionSuccessful {
			t.Error("executionSuccessful is false; that means the analysis did not complete and a " +
				"consumer may discard the results. The analysis completed — it was configured to " +
				"look at less")
		}
		if got := len(run.Tool.Driver.Notifications); got != 1 {
			t.Fatalf("declared %d descriptors, want exactly 1 (uniqueItems:true)", got)
		}
	})

	t.Run("two validators reuse ONE invocation and ONE descriptor", func(t *testing.T) {
		var run SARIFRun
		attachDisabledDetectionTypes(&run, statsWithDisabled(map[string][]string{
			"INTELLECTUAL_PROPERTY": {"copyright"},
			"ZZ_OTHER":              {"something"},
		}))
		if len(run.Invocations) != 1 {
			t.Fatalf("got %d invocations; invocations[] means one entry per tool invocation and "+
				"there was one run", len(run.Invocations))
		}
		if got := len(run.Invocations[0].ToolExecutionNotifications); got != 2 {
			t.Fatalf("got %d notifications, want 2", got)
		}
		// uniqueItems:true on tool.driver.notifications — a duplicate invalidates the document.
		if got := len(run.Tool.Driver.Notifications); got != 1 {
			t.Fatalf("declared %d descriptors for one class, want 1; a duplicate invalidates the "+
				"whole SARIF document", got)
		}
		// Sorted, so a byte comparison of two reports of the same scan does not show a difference
		// that is not one.
		first := run.Invocations[0].ToolExecutionNotifications[0].Message.Text
		if !strings.Contains(first, "INTELLECTUAL_PROPERTY") {
			t.Errorf("notifications are not in sorted validator order; first was %q", first)
		}
	})

	t.Run("appends to an invocation another disclosure created", func(t *testing.T) {
		run := SARIFRun{Invocations: []SARIFInvocation{{
			ExecutionSuccessful:        true,
			ToolExecutionNotifications: []SARIFNotification{{Message: SARIFMessage{Text: "pre-existing"}}},
		}}}
		attachDisabledDetectionTypes(&run, statsWithDisabled(
			map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}}))
		if len(run.Invocations) != 1 {
			t.Fatalf("got %d invocations, want 1 — a second entry claims the tool ran twice",
				len(run.Invocations))
		}
		notes := run.Invocations[0].ToolExecutionNotifications
		if len(notes) != 2 || notes[0].Message.Text != "pre-existing" {
			t.Fatalf("existing notification was not preserved: %+v", notes)
		}
	})

	t.Run("the document still serialises", func(t *testing.T) {
		var run SARIFRun
		attachDisabledDetectionTypes(&run, statsWithDisabled(
			map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}}))
		b, err := json.Marshal(run)
		if err != nil {
			t.Fatalf("marshalling the run: %v", err)
		}
		if !strings.Contains(string(b), "toolExecutionNotifications") {
			t.Errorf("the disclosure did not survive serialisation: %s", b)
		}
		// The GitLab spelling is invalid in SARIF and both formats live in this repo.
		if strings.Contains(string(b), `"level":"warn"`) {
			t.Error(`serialised level is "warn", which is GitLab's spelling and invalid in SARIF`)
		}
	})
}
