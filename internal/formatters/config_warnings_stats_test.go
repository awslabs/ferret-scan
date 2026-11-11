// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	jsonfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	sariffmt "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
	yamlfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
	"gopkg.in/yaml.v3"
)

// stats.config_warnings is the machine half of the "Warning: config value …" line (#903): a configured
// value the validators could not use was dropped, so what it configured did not happen. On
// `--stdin --enable-redaction` without --output stderr IS the findings document, so this key is the only
// place the warning can go. These pin the key's spelling in both serializations, that it is omitted when
// there is nothing to say (a usable config keeps every byte), and SARIF's slot.

// unusablePattern is a warning line as core.ConfigWarnings returns it: the path and the problem, never
// the pattern text.
const unusablePattern = "config value validators.cloud_resources.custom_patterns[0]: not a valid RE2 " +
	"regular expression: invalid named capture — skipped"

func statsWithConfigWarnings(lines ...string) formatters.FormatterOptions {
	return formatters.FormatterOptions{Stats: &formatters.ScanStats{TotalFiles: 1, FilesProcessed: 1, ConfigWarnings: lines}}
}

func TestStatsCarryConfigWarningsInJSONAndYAML(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		out, err := jsonfmt.NewFormatter().Format(nil, nil, statsWithConfigWarnings(unusablePattern))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Stats map[string]json.RawMessage `json:"stats"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("the JSON report does not parse: %v\n%s", err, out)
		}
		var got []string
		if err := json.Unmarshal(doc.Stats["config_warnings"], &got); err != nil {
			t.Fatalf("stats.config_warnings is not a list of strings (%v):\n%s", err, out)
		}
		if len(got) != 1 || got[0] != unusablePattern {
			t.Errorf("stats.config_warnings = %q, want [%q]", got, unusablePattern)
		}
	})

	t.Run("yaml uses the same key", func(t *testing.T) {
		out, err := yamlfmt.NewFormatter().Format(nil, nil, statsWithConfigWarnings(unusablePattern))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Stats map[string]any `yaml:"stats"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("the YAML report does not parse: %v\n%s", err, out)
		}
		got, ok := doc.Stats["config_warnings"].([]any)
		if !ok || len(got) != 1 || got[0] != unusablePattern {
			t.Errorf("stats.config_warnings = %#v, want [%q]; json and yaml must agree on the key:\n%s",
				doc.Stats["config_warnings"], unusablePattern, out)
		}
	})
}

func TestNoConfigWarningKeyWhenTheConfigIsUsable(t *testing.T) {
	empty := statsWithConfigWarnings()
	empty.Stats.ConfigWarnings = []string{}
	for name, opts := range map[string]formatters.FormatterOptions{
		"nil list":   statsWithConfigWarnings(),
		"empty list": empty,
	} {
		t.Run(name, func(t *testing.T) {
			j, err := jsonfmt.NewFormatter().Format(nil, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			y, err := yamlfmt.NewFormatter().Format(nil, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			s, err := sariffmt.NewFormatter().Format(nil, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			for format, out := range map[string]string{"json": j, "yaml": y} {
				if strings.Contains(out, "config_warnings") {
					t.Errorf("%s: a run with no warning gained a config_warnings key; a usable config must "+
						"keep every byte:\n%s", format, out)
				}
			}
			for _, banned := range []string{"toolConfigurationNotifications", "config-value-unusable"} {
				if strings.Contains(s, banned) {
					t.Errorf("sarif: a run with no warning gained %q:\n%s", banned, s)
				}
			}
		})
	}
}
