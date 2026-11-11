// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

func statsWithConfigWarnings(lines ...string) formatters.FormatterOptions {
	return formatters.FormatterOptions{Stats: &formatters.ScanStats{ConfigWarnings: lines}}
}

const (
	warnPattern  = "config value validators.cloud_resources.custom_patterns[0]: not a valid RE2 regular expression — skipped"
	warnProvider = "config value validators.cloud_resources.enabled_providers.aws: expected true or false — ignored"
)

// TestAttachConfigWarnings pins SARIF's slot for a configured value the validators could not use (#903):
// run.invocations[].toolConfigurationNotifications[], which the SARIF 2.1.0 schema describes as "a list
// of conditions detected by the tool that are relevant to the tool's configuration", one notification per
// warning, each citing ONE declared descriptor (tool.driver.notifications has uniqueItems:true).
func TestAttachConfigWarnings(t *testing.T) {
	t.Run("no warning adds nothing", func(t *testing.T) {
		var run SARIFRun
		attachConfigWarnings(&run, statsWithConfigWarnings())
		if len(run.Invocations) != 0 || len(run.Tool.Driver.Notifications) != 0 {
			t.Errorf("a usable config gained %d invocation(s) and %d descriptor(s); the document must stay "+
				"byte-identical", len(run.Invocations), len(run.Tool.Driver.Notifications))
		}
	})

	t.Run("nil Stats is not a panic", func(t *testing.T) {
		var run SARIFRun
		attachConfigWarnings(&run, formatters.FormatterOptions{})
		if len(run.Invocations) != 0 {
			t.Errorf("nil Stats produced %d invocation(s)", len(run.Invocations))
		}
	})

	t.Run("one notification per warning, in order, one descriptor", func(t *testing.T) {
		var run SARIFRun
		attachConfigWarnings(&run, statsWithConfigWarnings(warnPattern, warnProvider))
		if len(run.Invocations) != 1 {
			t.Fatalf("got %d invocations, want 1", len(run.Invocations))
		}
		inv := run.Invocations[0]
		if !inv.ExecutionSuccessful {
			t.Error("executionSuccessful is false; the analysis completed, with a value it could not use dropped")
		}
		if len(inv.ToolExecutionNotifications) != 0 {
			t.Errorf("a configuration condition went into toolExecutionNotifications: %+v", inv.ToolExecutionNotifications)
		}
		notes := inv.ToolConfigurationNotifications
		if len(notes) != 2 || notes[0].Message.Text != warnPattern || notes[1].Message.Text != warnProvider {
			t.Fatalf("toolConfigurationNotifications = %+v, want the two warnings in order", notes)
		}
		for i, n := range notes {
			if n.Level != LevelWarning {
				t.Errorf("notification %d level = %q, want %q", i, n.Level, LevelWarning)
			}
			if n.Descriptor == nil || n.Descriptor.ID != configWarningNotificationID {
				t.Errorf("notification %d descriptor = %v, want %q", i, n.Descriptor, configWarningNotificationID)
			}
		}
		if got := len(run.Tool.Driver.Notifications); got != 1 || run.Tool.Driver.Notifications[0].ID != configWarningNotificationID {
			t.Errorf("declared descriptors %+v, want exactly one, %q", run.Tool.Driver.Notifications, configWarningNotificationID)
		}
	})

	t.Run("extends the invocation another disclosure created, and keeps descriptors unique", func(t *testing.T) {
		var run SARIFRun
		attachDisabledDetectionTypes(&run, formatters.FormatterOptions{Stats: &formatters.ScanStats{
			DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}},
		}})
		attachConfigWarnings(&run, formatters.FormatterOptions{Stats: &formatters.ScanStats{ConfigWarnings: []string{warnPattern}}})
		attachConfigWarnings(&run, formatters.FormatterOptions{Stats: &formatters.ScanStats{ConfigWarnings: []string{warnProvider}}})
		if len(run.Invocations) != 1 {
			t.Fatalf("got %d invocations, want the one the disabled-types disclosure created", len(run.Invocations))
		}
		if n := len(run.Invocations[0].ToolExecutionNotifications); n != 1 {
			t.Errorf("toolExecutionNotifications has %d entries, want the disabled-types one", n)
		}
		if n := len(run.Invocations[0].ToolConfigurationNotifications); n != 2 {
			t.Errorf("toolConfigurationNotifications has %d entries, want 2", n)
		}
		seen := map[string]int{}
		for _, d := range run.Tool.Driver.Notifications {
			seen[d.ID]++
		}
		if seen[configWarningNotificationID] != 1 || seen[disabledTypesNotificationID] != 1 || len(seen) != 2 {
			t.Errorf("descriptors %v, want each of the two ids exactly once", seen)
		}
	})
}

// TestFormatCarriesConfigWarnings is the end-to-end half: Format calls attachConfigWarnings, and the
// document spells the slot as the schema does.
func TestFormatCarriesConfigWarnings(t *testing.T) {
	out, err := NewFormatter().Format(nil, nil, statsWithConfigWarnings(warnPattern))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful            bool `json:"executionSuccessful"`
				ToolConfigurationNotifications []struct {
					Descriptor struct {
						ID string `json:"id"`
					} `json:"descriptor"`
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolConfigurationNotifications"`
			} `json:"invocations"`
			Tool struct {
				Driver struct {
					Notifications []struct {
						ID string `json:"id"`
					} `json:"notifications"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("the SARIF document does not parse: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("want one run with one invocation:\n%s", out)
	}
	notes := doc.Runs[0].Invocations[0].ToolConfigurationNotifications
	if len(notes) != 1 || notes[0].Message.Text != warnPattern || notes[0].Level != LevelWarning ||
		notes[0].Descriptor.ID != configWarningNotificationID {
		t.Errorf("toolConfigurationNotifications = %+v, want the one warning", notes)
	}
	declared := false
	for _, d := range doc.Runs[0].Tool.Driver.Notifications {
		declared = declared || d.ID == configWarningNotificationID
	}
	if !declared {
		t.Errorf("the descriptor %q the notification cites is not declared in tool.driver.notifications", configWarningNotificationID)
	}
}
