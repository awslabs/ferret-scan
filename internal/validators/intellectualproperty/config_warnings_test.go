// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// ipWarningFixture holds two internal URLs on the reserved .test TLD; synthetic.
const ipWarningFixture = "Design notes live at https://wiki.zz-intra.test/team/page\nSource is at https://git.zz-intra.test/team/app\n"

const (
	ipWiki = `'https?://wiki\.zz-intra\.test'`
	ipGit  = `'https?://git\.zz-intra\.test'`
)

// loadIPConfig decodes doc the way the CLI does (config.LoadConfig, yaml.v3), so a value reaches
// Configure with the type a real config file gives it.
func loadIPConfig(t *testing.T, doc string) *config.Config {
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

func internalURLTexts(t *testing.T, v *Validator) string {
	t.Helper()
	ms, err := v.ValidateContent(ipWarningFixture, "ip.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var texts []string
	for _, m := range ms {
		texts = append(texts, m.Text)
	}
	sort.Strings(texts)
	return strings.Join(texts, ",")
}

const (
	bothURLs = "https://git.zz-intra.test,https://wiki.zz-intra.test"
	wikiOnly = "https://wiki.zz-intra.test"
)

// ipWarningRows are the measured misconfigurations of #903 and their valid twins. The bad value is
// still dropped (the effect column holds main's behaviour); the warning is what is new.
var ipWarningRows = []struct {
	name      string
	section   string // YAML for validators.intellectual_property
	wantPath  string // "" = a valid twin: no warning
	wantMsg   []string
	wantTexts string // findings on ipWarningFixture
}{
	{name: "internal URLs, valid twin", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "]}", wantTexts: bothURLs},
	{name: "internal URLs, one negative lookahead", section: "{internal_urls: [" + ipWiki + `, 'https?://(?!public)git\.zz-intra\.test']}`,
		wantPath: "validators.intellectual_property.internal_urls[1]",
		wantMsg:  []string{`"(?!" is a PCRE negative lookahead`, "— skipped"}, wantTexts: wikiOnly},
	{name: "internal URLs, all invalid", section: `{internal_urls: ['https?://(?!public)git\.zz-intra\.test']}`,
		wantPath: "validators.intellectual_property.internal_urls[0]",
		wantMsg:  []string{"no valid internal URL pattern remains, so internal URL detection is off"}, wantTexts: ""},
	{name: "internal URLs, not a string", section: "{internal_urls: [7, " + ipWiki + "]}",
		wantPath: "validators.intellectual_property.internal_urls[0]", wantMsg: []string{"expected a pattern string, got a number"}, wantTexts: wikiOnly},
	{name: "internal URLs, a scalar", section: "{internal_urls: " + ipGit + "}",
		wantPath: "validators.intellectual_property.internal_urls",
		wantMsg:  []string{"expected a list of patterns, got a string", "internal URL detection is off"}, wantTexts: ""},
	{name: "disabled types, valid twin", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "], disabled_types: [internal_url]}", wantTexts: ""},
	{name: "disabled types, a scalar", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "], disabled_types: internal_url}",
		wantPath: "validators.intellectual_property.disabled_types",
		wantMsg:  []string{"expected a list of sub-type names, got a string", "it disables nothing"}, wantTexts: bothURLs},
	{name: "disabled types, not a string", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "], disabled_types: [7]}",
		wantPath: "validators.intellectual_property.disabled_types[0]", wantMsg: []string{"got a number"}, wantTexts: bothURLs},
	{name: "pattern override, lookbehind", section: "{internal_urls: [" + ipWiki + ", " + ipGit + `], intellectual_property_patterns: {patent: '(?<=US )\d{7}'}}`,
		wantPath: "validators.intellectual_property.intellectual_property_patterns.patent",
		wantMsg:  []string{`"(?<=" is a PCRE lookbehind`, "the patent pattern in effect is unchanged"}, wantTexts: bothURLs},
	{name: "pattern override, unknown name", section: "{internal_urls: [" + ipWiki + ", " + ipGit + `], intellectual_property_patterns: {patents: 'US \d{7}'}}`,
		wantPath: "validators.intellectual_property.intellectual_property_patterns.patents",
		wantMsg:  []string{"unknown pattern name", "copyright, patent, trade_secret, trademark"}, wantTexts: bothURLs},
	{name: "pattern override, not a string", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "], intellectual_property_patterns: {patent: 7}}",
		wantPath: "validators.intellectual_property.intellectual_property_patterns.patent", wantMsg: []string{"got a number"}, wantTexts: bothURLs},
	{name: "pattern overrides, a list", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "], intellectual_property_patterns: [patent]}",
		wantPath: "validators.intellectual_property.intellectual_property_patterns", wantMsg: []string{"got a list"}, wantTexts: bothURLs},
	{name: "pattern override with no value", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "], intellectual_property_patterns: {patent: }}", wantTexts: bothURLs},
	// An unrecognised sub-type NAME keeps its own disclosure (UnrecognisedDisabledSubTypes); it is not
	// repeated as a config warning.
	{name: "disabled types, unknown name", section: "{internal_urls: [" + ipWiki + ", " + ipGit + "], disabled_types: [internal_urls]}", wantTexts: bothURLs},
	{name: "keys present with no value", section: "{internal_urls: , disabled_types: , intellectual_property_patterns: }", wantTexts: ""},
}

func TestConfigureRecordsEveryUnusableValue(t *testing.T) {
	builtinPatent := NewValidator().patternPatent
	for _, row := range ipWarningRows {
		t.Run(row.name, func(t *testing.T) {
			v := NewValidator()
			v.Configure(loadIPConfig(t, "validators: {intellectual_property: "+row.section+"}\n"))
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
				for _, want := range row.wantMsg {
					if !strings.Contains(line, want) {
						t.Errorf("warning %q lacks %q", line, want)
					}
				}
			}
			if got := internalURLTexts(t, v); got != row.wantTexts {
				t.Errorf("findings = %q, want %q", got, row.wantTexts)
			}
			if v.patternPatent != builtinPatent {
				t.Errorf("an unusable patent override replaced the built-in pattern: %q", v.patternPatent)
			}
		})
	}
}

func TestUnknownDisabledTypeKeepsItsOwnDisclosure(t *testing.T) {
	v := NewValidator()
	v.Configure(loadIPConfig(t, "validators: {intellectual_property: {disabled_types: [copyrite]}}\n"))
	if got := v.ConfigWarnings(); len(got) != 0 {
		t.Errorf("a misspelt name is the UnrecognisedDisabledSubTypes disclosure's, not a config warning: %v", got)
	}
	if got := v.UnrecognisedDisabledSubTypes(); len(got) != 1 || got[0] != "copyrite" {
		t.Errorf("UnrecognisedDisabledSubTypes = %v", got)
	}
}

// TestConfigureWritesNothingToStderr pins item 5 of #903. On main, two of these rows wrote to os.Stderr
// unconditionally (all-invalid internal_urls, 302 B; the bad patent override, 414 B) and the mixed row
// wrote [DEBUG] lines under FERRET_DEBUG=1, all of it past pkg/scan's LogWriter and into the findings
// document `--stdin --enable-redaction` writes to stderr.
func TestConfigureWritesNothingToStderr(t *testing.T) {
	for _, debug := range []string{"", "1"} {
		t.Setenv("FERRET_DEBUG", debug)
		out := captureStderr(t, func() {
			for _, row := range ipWarningRows {
				NewValidator().Configure(loadIPConfig(t, "validators: {intellectual_property: "+row.section+"}\n"))
			}
			NewValidator().Configure(nil)
			NewValidator().Configure(&config.Config{Validators: map[string]map[string]interface{}{"other": {}}})
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
