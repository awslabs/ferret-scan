// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// An EXTERNAL test package, like schema_registry_test.go: these guards need the validators, core and
// pkg/scan, which all import config, so they cannot live in package config itself.
package config_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/pkg/scan"
)

func writeValueWarningConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadValueWarningConfig(t *testing.T, doc string) *config.Config {
	t.Helper()
	cfg, err := config.LoadConfig(writeValueWarningConfig(t, doc))
	if err != nil {
		t.Fatalf("LoadConfig: %v\n%s", err, doc)
	}
	return cfg
}

func everyCheck() map[string]bool { return core.ParseChecksToRun(nil) }

// captureProcessStderr runs fn with os.Stderr redirected to a pipe and returns what was written.
func captureProcessStderr(t *testing.T, fn func()) string {
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

// TestEveryDeclaredKeyReportsAValueItCannotUse is the self-policing half of #903: every key the
// validators declare they read (validatorConfigKeys, itself held to the source by
// TestValidatorConfigKeysMatchTheSource) set to 7, a value no key accepts, must yield a warning naming
// that key. A key added to a validator without the recording would fail here, not ship silent.
func TestEveryDeclaredKeyReportsAValueItCannotUse(t *testing.T) {
	declared := 0
	for section, keys := range config.ValidatorConfigKeysForTest {
		var all []string
		for key := range keys {
			declared++
			all = append(all, key+": 7")
			cfg := loadValueWarningConfig(t, fmt.Sprintf("validators: {%s: {%s: 7}}\n", section, key))
			got := core.ConfigWarnings(core.BuildValidatorSet(everyCheck(), cfg, nil))
			want := "config value " + config.ValidatorKeyPath(section, key) + ": expected "
			if !hasLinePrefix(got, want) {
				t.Errorf("%s.%s: 7 gave no warning naming the key; got %v", section, key, got)
			}
		}
		// All of a section's keys wrong at once: each is still named.
		cfg := loadValueWarningConfig(t, fmt.Sprintf("validators: {%s: {%s}}\n", section, strings.Join(all, ", ")))
		got := core.ConfigWarnings(core.BuildValidatorSet(everyCheck(), cfg, nil))
		for key := range keys {
			if !hasLinePrefix(got, "config value "+config.ValidatorKeyPath(section, key)+": ") {
				t.Errorf("%s with every key 7: %s not named; got %v", section, key, got)
			}
		}
	}
	if declared < 11 {
		t.Fatalf("only %d keys declared; the declaration was not read", declared)
	}
}

func hasLinePrefix(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

const (
	cloudBadConfig = `validators: {cloud_resources: {custom_patterns: ['(?<=Ticket ref: )CUSTOMID-\d{6}']}}` + "\n"
	cloudBadLine   = `config value validators.cloud_resources.custom_patterns[0]: not a valid RE2 regular expression: invalid named capture ("(?<=" is a PCRE lookbehind; RE2, Go's regex engine, has no lookaround) — skipped`
	cloudText      = "Deployment role: arn:aws:iam::210987654321:role/deploy-runner\nTicket ref: CUSTOMID-482913\n"
)

// TestConfigWarningsReachEveryCarrier: core.ScanContent (the CLI's --stdin path), core.ScanFile (the web
// server's), core.RedactFile, and pkg/scan's ScanText and ScanFile all carry the warning, and none of
// them writes it, or anything else, to the process's stderr when the caller passes io.Discard.
func TestConfigWarningsReachEveryCarrier(t *testing.T) {
	cfgPath := writeValueWarningConfig(t, cloudBadConfig)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "cloud.txt")
	if err := os.WriteFile(file, []byte(cloudText), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := []string{"CLOUD_RESOURCES"}
	carriers := map[string][]string{}

	stderr := captureProcessStderr(t, func() {
		content, err := core.ScanContent(cloudText, core.ContentScanConfig{Checks: checks, Config: cfg, LogWriter: io.Discard})
		if err != nil {
			t.Errorf("ScanContent: %v", err)
		} else {
			carriers["core.ScanContent"] = content.ConfigWarnings
		}
		fileRes, err := core.ScanFile(core.ScanConfig{FilePath: file, Checks: checks, Config: cfg, EnablePreprocessors: true, LogWriter: io.Discard})
		if err != nil {
			t.Errorf("ScanFile: %v", err)
		} else {
			carriers["core.ScanFile"] = fileRes.ConfigWarnings
		}
		red, err := core.RedactFile(core.RedactConfig{FilePath: file, OutputDir: filepath.Join(dir, "out"), Checks: checks, Config: cfg, LogWriter: io.Discard})
		if err != nil {
			t.Errorf("RedactFile: %v", err)
		} else {
			carriers["core.RedactFile"] = red.ConfigWarnings
		}
		text, err := scan.ScanText(context.Background(), cloudText, scan.TextOptions{Checks: checks, ConfigPath: cfgPath, LogWriter: io.Discard})
		if err != nil {
			t.Errorf("scan.ScanText: %v", err)
		} else {
			carriers["scan.ScanText"] = text.ConfigWarnings
		}
		sf, err := scan.ScanFile(context.Background(), file, scan.FileOptions{Checks: checks, ConfigPath: cfgPath, LogWriter: io.Discard})
		if err != nil {
			t.Errorf("scan.ScanFile: %v", err)
		} else {
			carriers["scan.ScanFile"] = sf.ConfigWarnings
		}
	})
	if len(carriers) != 5 {
		t.Fatalf("only %d of 5 carriers ran", len(carriers))
	}
	for name, got := range carriers {
		if len(got) != 1 || got[0] != cloudBadLine {
			t.Errorf("%s.ConfigWarnings = %q, want [%q]", name, got, cloudBadLine)
		}
	}
	if stderr != "" {
		t.Errorf("a carrier wrote %d bytes to the process's stderr:\n%s", len(stderr), stderr)
	}
}

// TestPkgScanWritesNothingToStderrForAnUnusableValue: the two IP cases and the social media case that
// wrote to os.Stderr on main, past LogWriter (302 B for all-invalid internal_urls, 414 B for the patent
// override, measured), through every pkg/scan entry point, with LogWriter: io.Discard.
func TestPkgScanWritesNothingToStderrForAnUnusableValue(t *testing.T) {
	rows := []struct{ name, doc, checks, path string }{
		{"internal_urls all invalid", `validators: {intellectual_property: {internal_urls: ['https?://(?!public)git\.zz-intra\.test']}}`,
			"INTELLECTUAL_PROPERTY", "validators.intellectual_property.internal_urls[0]"},
		{"patent override invalid", `validators: {intellectual_property: {internal_urls: ['https?://wiki\.zz-intra\.test'], intellectual_property_patterns: {patent: '(?<=US )\d{7}'}}}`,
			"INTELLECTUAL_PROPERTY", "validators.intellectual_property.intellectual_property_patterns.patent"},
		{"platform_patterns all invalid", `validators: {social_media: {platform_patterns: {linkedin: ['(?<!\w)linkedin\.com/in/[a-z-]+']}}}`,
			"SOCIAL_MEDIA", "validators.social_media.platform_patterns.linkedin[0]"},
	}
	const text = "Source is at https://git.zz-intra.test/team/app\nUS 1234567\nhttps://www.linkedin.com/in/zz-sample-dev\n"
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, debug := range []string{"", "1"} {
				t.Setenv("FERRET_DEBUG", debug)
				cfgPath := writeValueWarningConfig(t, row.doc+"\n")
				dir := t.TempDir()
				file := filepath.Join(dir, "in.txt")
				if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
				var got []string
				stderr := captureProcessStderr(t, func() {
					res, err := scan.ScanText(context.Background(), text, scan.TextOptions{
						Checks: []string{row.checks}, ConfigPath: cfgPath, LogWriter: io.Discard})
					if err != nil {
						t.Errorf("ScanText: %v", err)
						return
					}
					got = res.ConfigWarnings
					if _, err := scan.RedactFile(file, scan.RedactFileOptions{OutputDir: filepath.Join(dir, "out"),
						Checks: []string{row.checks}, ConfigPath: cfgPath, LogWriter: io.Discard}); err != nil {
						t.Errorf("RedactFile: %v", err)
					}
				})
				if stderr != "" {
					t.Errorf("FERRET_DEBUG=%q: %d bytes on the process's stderr:\n%s", debug, len(stderr), stderr)
				}
				if !hasLinePrefix(got, "config value "+row.path+": ") {
					t.Errorf("Result.ConfigWarnings = %q, want a line for %s", got, row.path)
				}
			}
		})
	}
}

// TestConfigWarningsOnlyFromValidatorsInTheRun: a validator --checks excluded configured nothing, so it
// reports nothing; the same config with it included does.
func TestConfigWarningsOnlyFromValidatorsInTheRun(t *testing.T) {
	cfg := loadValueWarningConfig(t, cloudBadConfig)
	if got := core.ConfigWarnings(core.BuildValidatorSet(core.ParseChecksToRun([]string{"EMAIL"}), cfg, nil)); len(got) != 0 {
		t.Errorf("--checks EMAIL reported a cloud_resources value: %v", got)
	}
	if got := core.ConfigWarnings(core.BuildValidatorSet(core.ParseChecksToRun([]string{"CLOUD_RESOURCES"}), cfg, nil)); len(got) != 1 {
		t.Errorf("--checks CLOUD_RESOURCES: want 1 warning, got %v", got)
	}
}

// TestConfigWarningsFromTheProfilePass: a profile's own bad value is reported, and the same bad value in
// both the global block and the profile is reported once. The path names the validators block the value
// was read from, not the profile it came from: core.BuildValidatorSet does not tell Configure which pass it
// is running (a follow-up on #903, in internal/core/factory.go).
func TestConfigWarningsFromTheProfilePass(t *testing.T) {
	cfg := loadValueWarningConfig(t, `profiles: {zz: {checks: CLOUD_RESOURCES, validators: {cloud_resources: {custom_patterns: ['(?<=Ticket ref: )CUSTOMID-\d{6}']}}}}`+"\n")
	got := core.ConfigWarnings(core.BuildValidatorSet(everyCheck(), cfg, cfg.GetProfile("zz")))
	if len(got) != 1 || !strings.Contains(got[0], "cloud_resources.custom_patterns[0]: ") {
		t.Errorf("profile-only bad value: got %v", got)
	}

	both := loadValueWarningConfig(t, `validators: {cloud_resources: {custom_patterns: ['(?<=a)b']}}
profiles: {zz: {validators: {cloud_resources: {custom_patterns: ['(?<=a)b']}}}}
`)
	if got := core.ConfigWarnings(core.BuildValidatorSet(everyCheck(), both, both.GetProfile("zz"))); len(got) != 1 {
		t.Errorf("the same bad value in both passes: want 1 line, got %v", got)
	}
}

// TestConfigWarningsAreInAFixedOrder: by check name, then in the order each validator met them.
func TestConfigWarningsAreInAFixedOrder(t *testing.T) {
	cfg := loadValueWarningConfig(t, `validators:
  social_media: {platform_patterns: {linkedin: ['(?<!x)y'], github: [7]}}
  intellectual_property: {internal_urls: [7, '(?=x)']}
  cloud_resources: {enabled_providers: {AWS: false, aws: no}, custom_patterns: '(?<=x)'}
`)
	want := []string{
		"validators.cloud_resources.enabled_providers.AWS",
		"validators.cloud_resources.enabled_providers.aws",
		"validators.cloud_resources.custom_patterns",
		"validators.intellectual_property.internal_urls[0]",
		"validators.intellectual_property.internal_urls[1]",
		"validators.social_media.platform_patterns.github[0]",
		"validators.social_media.platform_patterns.linkedin[0]",
	}
	for i := 0; i < 20; i++ {
		got := core.ConfigWarnings(core.BuildValidatorSet(everyCheck(), cfg, nil))
		if len(got) != len(want) {
			t.Fatalf("run %d: want %d warnings, got %d: %q", i, len(want), len(got), got)
		}
		for j := range want {
			if !strings.HasPrefix(got[j], "config value "+want[j]+": ") {
				t.Fatalf("run %d: line %d = %q, want path %s", i, j, got[j], want[j])
			}
		}
	}
}

// TestShippedConfigsWarnAboutNothing: the configs this repository ships, global block and every profile,
// produce no config warning. The precision half of #903: a warning on a working shipped pattern would
// teach users to ignore the channel.
func TestShippedConfigsWarnAboutNothing(t *testing.T) {
	root := valueWarningRepoRoot(t)
	configured := 0
	for _, rel := range []string{"config.yaml", "examples/ferret.yaml", "examples/ferret-windows.yaml"} {
		cfg, err := config.LoadConfig(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("LoadConfig(%s): %v", rel, err)
		}
		configured += len(cfg.Validators)
		if got := core.ConfigWarnings(core.BuildValidatorSet(everyCheck(), cfg, nil)); len(got) != 0 {
			t.Errorf("%s, global block: %q", rel, got)
		}
		for _, name := range cfg.ListProfiles() {
			profile := cfg.GetProfile(name)
			if profile.Validators != nil {
				configured += len(profile.Validators)
			}
			if got := core.ConfigWarnings(core.BuildValidatorSet(everyCheck(), cfg, profile)); len(got) != 0 {
				t.Errorf("%s, profile %s: %q", rel, name, got)
			}
		}
	}
	// NON-VACUITY: the shipped files do configure the three validators (11 blocks were probed for #903).
	if configured < 6 {
		t.Fatalf("only %d validator blocks in the shipped configs; the guard checked almost nothing", configured)
	}
}

func valueWarningRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}
