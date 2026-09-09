// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/email"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
)

func ipConfiguredWith(values ...string) *intellectualproperty.Validator {
	list := make([]any, 0, len(values))
	for _, v := range values {
		list = append(list, v)
	}
	v := intellectualproperty.NewValidator()
	v.Configure(&config.Config{Validators: map[string]map[string]any{
		"intellectual_property": {"disabled_types": list},
	}})
	return v
}

func TestCollectDisabledDetectionTypes(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		validators            map[string]detector.Validator
		wantDisabled, wantBad map[string][]string
	}{
		{
			name:       "no validators at all",
			validators: nil,
		},
		{
			name:       "IP in the run with nothing disabled",
			validators: map[string]detector.Validator{"INTELLECTUAL_PROPERTY": intellectualproperty.NewValidator()},
		},
		{
			name:         "IP with two sub-types disabled",
			validators:   map[string]detector.Validator{"INTELLECTUAL_PROPERTY": ipConfiguredWith("internal_url", "copyright")},
			wantDisabled: map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright", "internal_url"}},
		},
		{
			name:       "a typo is reported as ineffective, not as disabled",
			validators: map[string]detector.Validator{"INTELLECTUAL_PROPERTY": ipConfiguredWith("copyrite")},
			wantBad:    map[string][]string{"INTELLECTUAL_PROPERTY": {"copyrite"}},
		},
		{
			// The case that makes asking the VALIDATOR the right design. A config-derived
			// disclosure would announce reduced EMAIL coverage here; email does not read
			// disabled_types at all, so nothing was disabled and saying otherwise would send the
			// operator to fix a validator that is working.
			name: "a validator that does not honour disabled_types stays silent",
			validators: map[string]detector.Validator{
				"EMAIL":                 email.NewValidator(),
				"INTELLECTUAL_PROPERTY": intellectualproperty.NewValidator(),
			},
		},
		{
			// A disabled_types block for a validator excluded by --checks: nothing ran, so nothing
			// was disabled. The validator is simply absent from the set.
			name:       "IP excluded from the run",
			validators: map[string]detector.Validator{"EMAIL": email.NewValidator()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disabled, bad := collectDisabledDetectionTypes(tc.validators)
			if !reflect.DeepEqual(disabled, tc.wantDisabled) {
				t.Errorf("disabled = %v, want %v", disabled, tc.wantDisabled)
			}
			if !reflect.DeepEqual(bad, tc.wantBad) {
				t.Errorf("unrecognised = %v, want %v", bad, tc.wantBad)
			}
		})
	}
}

func TestReportDisabledDetectionTypes(t *testing.T) {
	t.Run("nothing disabled writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		reportDisabledDetectionTypes(&buf, nil, nil)
		if buf.Len() != 0 {
			t.Errorf("wrote %d bytes for an unnarrowed scan; a note on every run trains people to "+
				"ignore it: %q", buf.Len(), buf.String())
		}
	})

	t.Run("names the validator and every sub-type", func(t *testing.T) {
		var buf bytes.Buffer
		reportDisabledDetectionTypes(&buf,
			map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright", "internal_url"}}, nil)
		out := buf.String()
		for _, want := range []string{"INTELLECTUAL_PROPERTY", "copyright", "internal_url", "not reported"} {
			if !strings.Contains(out, want) {
				t.Errorf("disclosure does not contain %q: %q", want, out)
			}
		}
		// A count without the names is not a disclosure: the output would be identical whether the
		// operator switched off internal URLs or every category.
		if !strings.Contains(out, "2 ") {
			t.Errorf("disclosure does not state how many sub-types: %q", out)
		}
	})

	t.Run("an ineffective entry says detection is STILL RUNNING", func(t *testing.T) {
		var buf bytes.Buffer
		reportDisabledDetectionTypes(&buf, nil, map[string][]string{"INTELLECTUAL_PROPERTY": {"copyrite"}})
		out := buf.String()
		if !strings.Contains(out, "copyrite") || !strings.Contains(out, "NO effect") {
			t.Errorf("does not report the ineffective entry: %q", out)
		}
		// The remedy is the valid list, so the message must carry it.
		for _, name := range intellectualproperty.RecognisedSubTypes() {
			if !strings.Contains(out, name) {
				t.Errorf("the warning does not list valid value %q, so the operator cannot fix the "+
					"typo from it: %q", name, out)
			}
		}
		// Opposite failure from the first message, so it must not read as "coverage is narrower".
		if strings.Contains(out, "not reported") {
			t.Errorf("an ineffective entry must not claim findings were suppressed: %q", out)
		}
	})

	t.Run("line order is fixed across runs", func(t *testing.T) {
		disabled := map[string][]string{"A_VALIDATOR": {"x"}, "B_VALIDATOR": {"y"}, "C_VALIDATOR": {"z"}}
		bad := map[string][]string{"A_VALIDATOR": {"q"}, "B_VALIDATOR": {"r"}}
		var first bytes.Buffer
		reportDisabledDetectionTypes(&first, disabled, bad)
		// Map iteration is randomized, so a single comparison can pass by luck. 40 repeats over
		// three keys makes an unsorted implementation fail with probability ~1.
		for i := 0; i < 40; i++ {
			var again bytes.Buffer
			reportDisabledDetectionTypes(&again, disabled, bad)
			if again.String() != first.String() {
				t.Fatalf("disclosure order varies between runs of an unchanged scan:\n%q\nvs\n%q",
					first.String(), again.String())
			}
		}
		if !strings.Contains(first.String(), "A_VALIDATOR") {
			t.Fatalf("the fixture produced no output, so the comparison above proves nothing: %q",
				first.String())
		}
	})
}
