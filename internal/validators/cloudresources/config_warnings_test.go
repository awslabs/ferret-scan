// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// cloudWarningFixture holds one AWS ARN and one value only a custom pattern finds. Synthetic: the
// account ID is not a real one and CUSTOMID is a made-up prefix.
const cloudWarningFixture = "Deployment role: arn:aws:iam::210987654321:role/deploy-runner\nTicket ref: CUSTOMID-482913\n"

// loadCloudConfig decodes doc the way the CLI does (config.LoadConfig, yaml.v3), so a value reaches
// Configure with the type a real config file gives it: `aws: no` is the STRING "no" there.
func loadCloudConfig(t *testing.T, doc string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v\n%s", err, doc)
	}
	return cfg
}

func cloudTypes(t *testing.T, v *Validator) []string {
	t.Helper()
	ms, err := v.ValidateContent(cloudWarningFixture, "cloud.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var types []string
	for _, m := range ms {
		types = append(types, m.Type)
	}
	sort.Strings(types)
	return types
}

// cloudWarningRows are the measured misconfigurations of #903 and their valid twins. Every bad row
// was silent in every mode, --debug included, and lost its effect; the effect column is unchanged by
// the fix (the value is still dropped), the warning is what is new.
var cloudWarningRows = []struct {
	name     string
	section  string // YAML for validators.cloud_resources
	wantPath string // "" = a valid twin: no warning at all
	wantMsg  []string
	wantType string // the scan's types, joined: the bad value's effect is lost, the valid twin's holds
}{
	{name: "custom pattern, valid twin", section: `{custom_patterns: ['CUSTOMID-\d{6}']}`,
		wantType: "AWS_ARN,CLOUD_RESOURCE_ID"},
	{name: "custom pattern, lookbehind", section: `{custom_patterns: ['(?<=Ticket ref: )CUSTOMID-\d{6}']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]",
		wantMsg:  []string{"invalid named capture", `"(?<=" is a PCRE lookbehind`, "— skipped"}, wantType: "AWS_ARN"},
	{name: "custom pattern, negative lookbehind", section: `{custom_patterns: ['(?<!x)CUSTOMID-\d{6}']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{`"(?<!" is a PCRE negative lookbehind`}, wantType: "AWS_ARN"},
	{name: "custom pattern, lookahead", section: `{custom_patterns: ['CUSTOMID-(?=\d)\d{6}']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{`"(?=" is a PCRE lookahead`}, wantType: "AWS_ARN"},
	{name: "custom pattern, negative lookahead", section: `{custom_patterns: ['CUSTOMID-(?!0)\d{6}']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{`"(?!" is a PCRE negative lookahead`}, wantType: "AWS_ARN"},
	{name: "custom pattern, atomic group", section: `{custom_patterns: ['(?>CUSTOMID)-\d{6}']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{`"(?>" is a PCRE atomic group`}, wantType: "AWS_ARN"},
	{name: "custom pattern, possessive quantifier", section: `{custom_patterns: ['CUSTOMID-\d++']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{"possessive quantifier"}, wantType: "AWS_ARN"},
	{name: "custom pattern, backreference", section: `{custom_patterns: ['(CUSTOMID)-\d{6}\1']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{"backreference"}, wantType: "AWS_ARN"},
	{name: "custom pattern, PCRE end anchor", section: `{custom_patterns: ['CUSTOMID-\d{6}\Z']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{`"\Z"`, `"\z"`}, wantType: "AWS_ARN"},
	{name: "custom pattern, unclosed class", section: `{custom_patterns: ['CUSTOMID-[0-9{6}']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{"missing closing ]", `"[" character class is not closed`}, wantType: "AWS_ARN"},
	{name: "custom pattern, at the user's index", section: `{custom_patterns: ['CUSTOMID-\d{6}', '(?<=x)y']}`,
		wantPath: "validators.cloud_resources.custom_patterns[1]", wantMsg: []string{"(?<="}, wantType: "AWS_ARN,CLOUD_RESOURCE_ID"},
	{name: "custom patterns, a scalar", section: `{custom_patterns: 'CUSTOMID-\d{6}'}`,
		wantPath: "validators.cloud_resources.custom_patterns", wantMsg: []string{"expected a list of patterns, got a string", "ignored"}, wantType: "AWS_ARN"},
	{name: "custom pattern, not a string", section: `{custom_patterns: [7, 'CUSTOMID-\d{6}']}`,
		wantPath: "validators.cloud_resources.custom_patterns[0]", wantMsg: []string{"expected a pattern string, got a number"}, wantType: "AWS_ARN,CLOUD_RESOURCE_ID"},
	{name: "providers, valid twin", section: `{enabled_providers: {aws: false}}`, wantType: ""},
	{name: "providers, upper case", section: `{enabled_providers: {AWS: false}}`,
		wantPath: "validators.cloud_resources.enabled_providers.AWS", wantMsg: []string{"unknown provider", `"aws"`}, wantType: "AWS_ARN"},
	{name: "providers, mixed case", section: `{enabled_providers: {Aws: false}}`,
		wantPath: "validators.cloud_resources.enabled_providers.Aws", wantMsg: []string{`"aws"`}, wantType: "AWS_ARN"},
	{name: "providers, unknown name", section: `{enabled_providers: {gcloud: false}}`,
		wantPath: "validators.cloud_resources.enabled_providers.gcloud", wantMsg: []string{"known: alibaba, aws, azure, gcp, ibm, oci"}, wantType: "AWS_ARN"},
	{name: "providers, YAML 1.2 no", section: `{enabled_providers: {aws: no}}`,
		wantPath: "validators.cloud_resources.enabled_providers.aws", wantMsg: []string{`the string "no"`, "YAML 1.2", "aws detection stays on"}, wantType: "AWS_ARN"},
	{name: "providers, YAML 1.2 off", section: `{enabled_providers: {aws: off}}`,
		wantPath: "validators.cloud_resources.enabled_providers.aws", wantMsg: []string{`the string "off"`}, wantType: "AWS_ARN"},
	{name: "providers, quoted false", section: `{enabled_providers: {aws: "false"}}`,
		wantPath: "validators.cloud_resources.enabled_providers.aws", wantMsg: []string{`the string "false"`, "quoted"}, wantType: "AWS_ARN"},
	{name: "providers, a number", section: `{enabled_providers: {aws: 0}}`,
		wantPath: "validators.cloud_resources.enabled_providers.aws", wantMsg: []string{"expected true or false, got a number"}, wantType: "AWS_ARN"},
	{name: "providers, a list", section: `{enabled_providers: [gcp, azure]}`,
		wantPath: "validators.cloud_resources.enabled_providers", wantMsg: []string{"got a list", "switches no provider"}, wantType: "AWS_ARN"},
	{name: "provider with no value", section: `{enabled_providers: {aws: }}`, wantType: "AWS_ARN"},
	{name: "keys present with no value", section: `{custom_patterns: , enabled_providers: }`, wantType: "AWS_ARN"},
	{name: "empty section", section: `{}`, wantType: "AWS_ARN"},
}

func TestConfigureRecordsEveryUnusableValue(t *testing.T) {
	for _, row := range cloudWarningRows {
		t.Run(row.name, func(t *testing.T) {
			v := NewValidator()
			v.Configure(loadCloudConfig(t, "validators: {cloud_resources: "+row.section+"}\n"))
			got := v.ConfigWarnings()

			if row.wantPath == "" {
				if len(got) != 0 {
					t.Fatalf("a usable value warned: %v", got)
				}
			} else {
				if len(got) != 1 {
					t.Fatalf("want exactly one warning for %s, got %d: %v", row.wantPath, len(got), got)
				}
				if got[0].Path != row.wantPath {
					t.Errorf("Path = %q, want %q", got[0].Path, row.wantPath)
				}
				line := got[0].String()
				if !strings.HasPrefix(line, "config value "+row.wantPath+": ") {
					t.Errorf("line %q does not start with the path", line)
				}
				for _, want := range row.wantMsg {
					if !strings.Contains(line, want) {
						t.Errorf("warning %q lacks %q", line, want)
					}
				}
			}

			// The value's effect: a dropped value is still dropped, a valid one still applies.
			if got := strings.Join(cloudTypes(t, v), ","); got != row.wantType {
				t.Errorf("types after Configure = %q, want %q", got, row.wantType)
			}
		})
	}
}

// TestInvalidCustomPatternIgnored was "must not panic" only; it now also pins that the dropped pattern
// is reported, at its index, and that the valid ones beside it still apply.
func TestInvalidCustomPatternIgnored(t *testing.T) {
	v := NewValidator()
	v.Configure(&config.Config{Validators: map[string]map[string]interface{}{
		"cloud_resources": {"custom_patterns": []interface{}{`myc:[a-z]+:[0-9]{6,}`, `[unclosed`}},
	}})
	ms, err := v.ValidateContent("ref myc:prod:123456 and arn:aws:iam::123456789012:role/X", "t.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ms) < 2 {
		t.Errorf("the valid custom pattern and the ARN should both match, got %d matches", len(ms))
	}
	got := v.ConfigWarnings()
	if len(got) != 1 || got[0].Path != "validators.cloud_resources.custom_patterns[1]" {
		t.Fatalf("want one warning at custom_patterns[1], got %v", got)
	}
}

// TestConfigWarningsAccumulateAcrossPasses: the factory configures a validator once per config source
// (global, then profile), so warnings from both passes are kept, and the accessor hands out a copy.
func TestConfigWarningsAccumulateAcrossPasses(t *testing.T) {
	v := NewValidator()
	v.Configure(loadCloudConfig(t, "validators: {cloud_resources: {custom_patterns: ['(?<=a)b']}}\n"))
	v.Configure(loadCloudConfig(t, "validators: {cloud_resources: {enabled_providers: {aws: no}}}\n"))
	got := v.ConfigWarnings()
	if len(got) != 2 || got[0].Path != "validators.cloud_resources.custom_patterns[0]" ||
		got[1].Path != "validators.cloud_resources.enabled_providers.aws" {
		t.Fatalf("want both passes' warnings in order, got %v", got)
	}
	got[0].Path = "mutated"
	if v.ConfigWarnings()[0].Path == "mutated" {
		t.Error("ConfigWarnings returned the validator's own slice")
	}
}

// TestConfigWarningsAreOrdered: providers are a map, so the warnings are put in name order, not map order.
func TestConfigWarningsAreOrdered(t *testing.T) {
	cfg := loadCloudConfig(t, "validators: {cloud_resources: {enabled_providers: {oci: no, AWS: false, gcp: off, Zz: true, azure: yes}}}\n")
	var first []string
	for i := 0; i < 20; i++ {
		v := NewValidator()
		v.Configure(cfg)
		var paths []string
		for _, w := range v.ConfigWarnings() {
			paths = append(paths, w.Path)
		}
		if i == 0 {
			first = paths
			if !sort.StringsAreSorted(paths) || len(paths) != 5 {
				t.Fatalf("want 5 warnings in path order, got %v", paths)
			}
			continue
		}
		if strings.Join(paths, "|") != strings.Join(first, "|") {
			t.Fatalf("run %d ordered the warnings differently: %v vs %v", i, paths, first)
		}
	}
}

// TestConfigureWritesNothingToStderr: Configure records; it never prints, with or without FERRET_DEBUG.
// Before #903 nothing here printed either, but only because the one channel it had was a debug observer
// that is never attached at configure time; this pins that a later fix does not "help" by printing.
func TestConfigureWritesNothingToStderr(t *testing.T) {
	for _, debug := range []string{"", "1"} {
		t.Setenv("FERRET_DEBUG", debug)
		out := captureStderr(t, func() {
			for _, row := range cloudWarningRows {
				NewValidator().Configure(loadCloudConfig(t, "validators: {cloud_resources: "+row.section+"}\n"))
			}
		})
		if out != "" {
			t.Errorf("FERRET_DEBUG=%q: Configure wrote %d bytes to stderr:\n%s", debug, len(out), out)
		}
	}
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stderr = orig }()
	fn()
	os.Stderr = orig
	_ = w.Close()
	return <-done
}
