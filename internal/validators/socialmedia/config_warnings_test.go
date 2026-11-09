// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// smWarningFixture holds one GitHub and one LinkedIn profile URL for a made-up handle.
const smWarningFixture = "Contact the maintainer:\nGitHub profile: https://github.com/zz-sample-dev\nLinkedIn profile: https://www.linkedin.com/in/zz-sample-dev\n"

const smValidPatterns = `platform_patterns: {github: ['github\.com/[A-Za-z0-9-]+'], linkedin: ['linkedin\.com/in/[A-Za-z0-9-]+']}`

// loadSMConfig decodes doc the way the CLI does (config.LoadConfig, yaml.v3).
func loadSMConfig(t *testing.T, doc string) *config.Config {
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

func smTypes(t *testing.T, v *Validator) string {
	t.Helper()
	ms, err := v.ValidateContent(smWarningFixture, "sm.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var types []string
	for _, m := range ms {
		types = append(types, m.Type)
	}
	sort.Strings(types)
	return strings.Join(types, ",")
}

// smWarningRows are the measured misconfigurations of #903 and their valid twins. The bad value is
// still dropped (the effect column holds main's behaviour); the warning is what is new.
var smWarningRows = []struct {
	name     string
	section  string // YAML for validators.social_media, without the braces
	wantPath string // "" = a valid twin: no warning
	wantMsg  []string
	wantType string
}{
	{name: "platform patterns, valid twin", section: smValidPatterns, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "platform pattern, negative lookbehind", section: `platform_patterns: {github: ['github\.com/[A-Za-z0-9-]+'], linkedin: ['(?<!\w)linkedin\.com/in/[A-Za-z0-9-]+']}`,
		wantPath: "validators.social_media.platform_patterns.linkedin[0]",
		wantMsg:  []string{`"(?<!" is a PCRE negative lookbehind`, "linkedin has no valid pattern"}, wantType: "GITHUB"},
	{name: "platform pattern, a scalar", section: `platform_patterns: {github: 'github\.com/[A-Za-z0-9-]+', linkedin: ['linkedin\.com/in/[A-Za-z0-9-]+']}`,
		wantPath: "validators.social_media.platform_patterns.github",
		wantMsg:  []string{"expected a list of patterns, got a string", "github has no valid pattern"}, wantType: "LINKEDIN"},
	{name: "platform pattern, not a string", section: `platform_patterns: {github: ['github\.com/[A-Za-z0-9-]+'], linkedin: [12345]}`,
		wantPath: "validators.social_media.platform_patterns.linkedin[0]", wantMsg: []string{"got a number"}, wantType: "GITHUB"},
	{name: "platform patterns, all invalid", section: `platform_patterns: {linkedin: ['(?<!\w)linkedin\.com/in/[A-Za-z0-9-]+']}`,
		wantPath: "validators.social_media.platform_patterns.linkedin[0]",
		wantMsg:  []string{"no platform has a valid pattern, so social media detection is off"}, wantType: ""},
	{name: "platform patterns, a list", section: `platform_patterns: ['github\.com/[A-Za-z0-9-]+']`,
		wantPath: "validators.social_media.platform_patterns",
		wantMsg:  []string{"expected a map of platform names to pattern lists, got a list", "social media detection is off"}, wantType: ""},
	{name: "platform with no value", section: `platform_patterns: {github: ['github\.com/[A-Za-z0-9-]+'], linkedin: }`, wantType: "GITHUB"},
	{name: "allowlist, valid twin", section: smValidPatterns + `, allowlist_patterns: ['github\.com/zz-sample-dev']`, wantType: "LINKEDIN"},
	{name: "allowlist, lookbehind", section: smValidPatterns + `, allowlist_patterns: ['(?<=github\.com/)zz-sample-dev']`,
		wantPath: "validators.social_media.allowlist_patterns[0]",
		wantMsg:  []string{`"(?<=" is a PCRE lookbehind`, "what it would have excluded is reported"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "allowlist, a scalar", section: smValidPatterns + `, allowlist_patterns: 'github\.com/zz-sample-dev'`,
		wantPath: "validators.social_media.allowlist_patterns", wantMsg: []string{"got a string"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "allowlist, not a string", section: smValidPatterns + `, allowlist_patterns: [7, 'github\.com/zz-sample-dev']`,
		wantPath: "validators.social_media.allowlist_patterns[0]", wantMsg: []string{"got a number"}, wantType: "LINKEDIN"},
	{name: "positive keywords, a scalar", section: smValidPatterns + `, positive_keywords: profile`,
		wantPath: "validators.social_media.positive_keywords", wantMsg: []string{"expected a list of strings, got a string"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "positive keyword, not a string", section: smValidPatterns + `, positive_keywords: [7, profile]`,
		wantPath: "validators.social_media.positive_keywords[0]", wantMsg: []string{"got a number", "skipped"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "negative keywords, a map", section: smValidPatterns + `, negative_keywords: {a: b}`,
		wantPath: "validators.social_media.negative_keywords", wantMsg: []string{"got a map"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "platform keywords, a list", section: smValidPatterns + `, platform_keywords: [code]`,
		wantPath: "validators.social_media.platform_keywords", wantMsg: []string{"got a list"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "platform keywords, a scalar per platform", section: smValidPatterns + `, platform_keywords: {github: code}`,
		wantPath: "validators.social_media.platform_keywords.github", wantMsg: []string{"got a string"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "platform keyword, not a string", section: smValidPatterns + `, platform_keywords: {github: [7, code]}`,
		wantPath: "validators.social_media.platform_keywords.github[0]", wantMsg: []string{"got a number"}, wantType: "SOCIAL_MEDIA_CLUSTER"},
	{name: "keys present with no value", section: `platform_patterns: , allowlist_patterns: , positive_keywords: , platform_keywords: `, wantType: ""},
}

func TestConfigureRecordsEveryUnusableValue(t *testing.T) {
	for _, row := range smWarningRows {
		t.Run(row.name, func(t *testing.T) {
			v := NewValidator()
			v.Configure(loadSMConfig(t, "validators: {social_media: {"+row.section+"}}\n"))
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
			if got := smTypes(t, v); got != row.wantType {
				t.Errorf("types = %q, want %q", got, row.wantType)
			}
		})
	}
}

// TestPlatformWarningsAreOrdered: platform_patterns is a map, so its warnings are put in platform order.
func TestPlatformWarningsAreOrdered(t *testing.T) {
	cfg := loadSMConfig(t, `validators: {social_media: {platform_patterns: {twitter: ['(?<=@)x'], github: [7], linkedin: '(?=x)', bluesky: ['ok\.example']}}}`+"\n")
	want := "validators.social_media.platform_patterns.github[0]|validators.social_media.platform_patterns.linkedin|validators.social_media.platform_patterns.twitter[0]"
	for i := 0; i < 20; i++ {
		v := NewValidator()
		v.Configure(cfg)
		var paths []string
		for _, w := range v.ConfigWarnings() {
			paths = append(paths, w.Path)
		}
		if got := strings.Join(paths, "|"); got != want {
			t.Fatalf("run %d: paths = %s, want %s", i, got, want)
		}
	}
}

// TestConfigureWritesNothingToStderr pins item 5 of #903: on main an all-invalid platform_patterns wrote
// "Warning: Social media detection disabled: …" to os.Stderr unconditionally, and the partly invalid and
// allowlist rows wrote [DEBUG] lines under FERRET_DEBUG=1, past pkg/scan's LogWriter.
func TestConfigureWritesNothingToStderr(t *testing.T) {
	for _, debug := range []string{"", "1"} {
		t.Setenv("FERRET_DEBUG", debug)
		out := captureStderr(t, func() {
			for _, row := range smWarningRows {
				NewValidator().Configure(loadSMConfig(t, "validators: {social_media: {"+row.section+"}}\n"))
			}
			NewValidator().Configure(nil)
			NewValidator().Configure(&config.Config{})
			NewValidator().Configure(&config.Config{Validators: map[string]map[string]interface{}{"other": {}}})
			NewValidator().Configure(loadSMConfig(t, "validators: {social_media: {platform_patterns: {}}}\n"))
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
