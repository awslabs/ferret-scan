// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/paths"
)

// This file covers the config keys an audit found to be parsed and then ignored.
// A key that unmarshals into a field nothing reads is indistinguishable, from the
// user's side, from a key that works: there is no error and no effect. These
// tests assert the effect.

// writeConfig writes a config file into a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

// TestAuditLogFileIsHonored covers the one dead key that silently discarded a
// path the user asked for.
//
// The struct field has always been `index_file`, but the shipped config.yaml,
// every doc that mentions it, and the --redaction-audit-log flag all call it
// `audit_log_file`. Setting the documented name wrote to a field nothing read,
// so no log was produced and no error was reported.
func TestAuditLogFileIsHonored(t *testing.T) {
	t.Run("alias fills an empty index_file", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, `
redaction:
  audit_log_file: "/tmp/ferret-audit.json"
`))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.Redaction.IndexFile != "/tmp/ferret-audit.json" {
			t.Errorf("audit_log_file did not reach IndexFile: got %q — the redaction log "+
				"is driven by IndexFile, so an unread alias means no log file is written",
				cfg.Redaction.IndexFile)
		}
	})

	t.Run("index_file wins when both are set", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, `
redaction:
  index_file: "/tmp/from-index.json"
  audit_log_file: "/tmp/from-alias.json"
`))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.Redaction.IndexFile != "/tmp/from-index.json" {
			t.Errorf("IndexFile = %q, want the explicit index_file value: it is the name "+
				"the loader has always honored, so it must not be clobbered by the alias",
				cfg.Redaction.IndexFile)
		}
	})

	t.Run("alias works inside a profile", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, `
profiles:
  audited:
    description: probe
    redaction:
      audit_log_file: "/tmp/profile-audit.json"
`))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		got := cfg.Profiles["audited"].Redaction.IndexFile
		if got != "/tmp/profile-audit.json" {
			t.Errorf("profile audit_log_file did not reach IndexFile: got %q", got)
		}
	})
}

// TestSuppressionsBlockIsParsed covers a block the shipped config.yaml has always
// documented while Config had no field for it at all, so all three keys were
// silently discarded.
func TestSuppressionsBlockIsParsed(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
suppressions:
  file: ".my-suppressions.yaml"
  generate_on_scan: true
  show_suppressed: true
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Suppressions.File != ".my-suppressions.yaml" {
		t.Errorf("suppressions.file = %q, want %q", cfg.Suppressions.File, ".my-suppressions.yaml")
	}
	if !cfg.Suppressions.GenerateOnScan {
		t.Error("suppressions.generate_on_scan did not survive parsing")
	}
	if !cfg.Suppressions.ShowSuppressed {
		t.Error("suppressions.show_suppressed did not survive parsing")
	}
}

// TestUnknownKeysAreReported is the typo guard. yaml.Unmarshal is deliberately
// lenient — erroring on an unknown key would reject configs written for another
// version, including this project's own shipped config.yaml before this change.
// But silence means a misspelled option looks exactly like a working one.
func TestUnknownKeysAreReported(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
defaults:
  shwo_match: true
redaction:
  enabledd: true
nonsense_block:
  x: 1
`))
	if err != nil {
		t.Fatalf("LoadConfig must not fail on unknown keys, only report them: %v", err)
	}

	joined := strings.Join(cfg.UnknownKeys, ",")
	for _, want := range []string{"shwo_match", "enabledd", "nonsense_block"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unknown key %q was not reported (got %v) — an unreported typo is "+
				"applied to nothing and looks like a working setting", want, cfg.UnknownKeys)
		}
	}
}

// TestValidConfigReportsNoUnknownKeys is the other half: a warning that fires on
// correct input would train users to ignore it.
func TestValidConfigReportsNoUnknownKeys(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
defaults:
  format: json
  show_match: true
  confidence_levels: high
redaction:
  enabled: true
  output_dir: "./redacted"
  strategy: simple
  index_file: "./idx.json"
  audit_log_file: ""
suppressions:
  file: ".s.yaml"
  generate_on_scan: false
  show_suppressed: false
validators:
  intellectual_property:
    internal_urls:
      - "internal\\.example\\.invalid"
profiles:
  quick:
    description: probe
    format: text
    redaction:
      enabled: false
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.UnknownKeys) != 0 {
		t.Errorf("a fully valid config reported unknown keys %v — false warnings teach "+
			"users to ignore real ones", cfg.UnknownKeys)
	}
}

// TestShippedConfigsHaveNoUnknownKeys pins the invariant that every config we
// ship validates against our own schema. None of them did: `audit_log_file` and
// the whole `suppressions:` block had no struct fields, so the project's own
// examples documented settings that did nothing.
//
// examples/ferret.yaml matters most: `make install` copies it to the user's
// config directory, so an unknown key there means a warning on every scan for
// every installed user. Covering only the repo-root config.yaml would have
// missed that.
func TestShippedConfigsHaveNoUnknownKeys(t *testing.T) {
	// Paths are relative to internal/config.
	for _, rel := range []string{
		filepath.Join("..", "..", "config.yaml"),
		filepath.Join("..", "..", "examples", "ferret.yaml"),
		filepath.Join("..", "..", "examples", "ferret-windows.yaml"),
	} {
		t.Run(filepath.Base(filepath.Dir(rel))+"/"+filepath.Base(rel), func(t *testing.T) {
			if _, err := os.Stat(rel); err != nil {
				t.Skipf("%s not found: %v", rel, err)
			}

			cfg, err := LoadConfig(rel)
			if err != nil {
				t.Fatalf("%s must load: %v", rel, err)
			}
			if len(cfg.UnknownKeys) != 0 {
				t.Errorf("%s contains keys the schema does not recognize: %v\n"+
					"Either wire the key up or drop it from the file — shipping a "+
					"documented no-op is how these went unnoticed.", rel, cfg.UnknownKeys)
			}
		})
	}
}

// TestPlatformTempDirIsApplied covers the `platform:` block, which was validated
// (a bad path was rejected) and then never applied: GetEffectiveTempDir and
// GetEffectiveConfigDir had zero callers, so a good path was ignored.
func TestPlatformTempDirIsApplied(t *testing.T) {
	// Restore the process-wide override so this test cannot leak into others.
	t.Cleanup(func() { paths.SetTempDirOverride("") })

	want := filepath.Join(t.TempDir(), "ferret-temp")
	body := "platform:\n  unix:\n    temp_dir: " + quoteYAML(want) + "\n"
	if runtime.GOOS == "windows" {
		body = "platform:\n  windows:\n    temp_dir: " + quoteYAML(want) + "\n"
	}

	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if got := GetEffectiveTempDir(cfg); got != want {
		t.Errorf("GetEffectiveTempDir() = %q, want %q", got, want)
	}
	// The real assertion: the override must reach the package everything else
	// calls. GetEffectiveTempDir returning the right value while paths.GetTempDir
	// ignores it is exactly the state this test exists to prevent.
	if got := paths.GetTempDir(); got != want {
		t.Errorf("paths.GetTempDir() = %q, want %q — loading a config with a "+
			"platform temp_dir must change the directory the rest of the program uses",
			got, want)
	}
}

// TestRejectedConfigDoesNotPublishTempDir covers the ordering hazard created by
// making the temp dir a process-wide override: a config that fails validation must
// not leave the process pointing at a directory no accepted config ever named.
// Publishing before ValidateConfig would do exactly that — including when the
// rejected key IS the temp dir.
func TestRejectedConfigDoesNotPublishTempDir(t *testing.T) {
	t.Cleanup(func() { paths.SetTempDirOverride("") })

	paths.SetTempDirOverride("")
	before := paths.GetTempDir()

	// An embedded NUL makes ValidateConfig reject the path — and the rejected key
	// is the temp dir itself, which is the case that matters: publishing before
	// validation would point the process at a path the validator just refused.
	leak := filepath.Join(t.TempDir(), "should-not-leak")
	osKey := "unix"
	if runtime.GOOS == "windows" {
		osKey = "windows"
	}
	body := "platform:\n  " + osKey + ":\n    temp_dir: \"" + leak + "\\0bad\"\n"

	if _, err := LoadConfig(writeConfig(t, body)); err == nil {
		t.Fatal("expected the invalid temp_dir path to be rejected")
	}

	if got := paths.GetTempDir(); got != before {
		t.Errorf("paths.GetTempDir() = %q after a REJECTED config, want the previous "+
			"value %q — a config that was refused must not mutate process state", got, before)
	}
}

// TestPlatformTempDirAbsentLeavesDefault makes sure the override is not applied
// unconditionally, which would silently redirect every scan's temp files.
func TestPlatformTempDirAbsentLeavesDefault(t *testing.T) {
	t.Cleanup(func() { paths.SetTempDirOverride("") })

	// Seed a stale override so a no-op loader would be caught.
	paths.SetTempDirOverride(filepath.Join(t.TempDir(), "stale"))

	cfg, err := LoadConfig(writeConfig(t, "defaults:\n  format: json\n"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil config")
	}

	if got, def := paths.GetTempDir(), osTempDir(); got != def {
		t.Errorf("paths.GetTempDir() = %q after loading a config with no platform "+
			"temp_dir, want the platform default %q — a config that says nothing "+
			"must not redirect temp files", got, def)
	}
}

// osTempDir is the platform default, read without the config override.
func osTempDir() string {
	paths.SetTempDirOverride("")
	return paths.GetTempDir()
}

// quoteYAML renders s as a single-quoted YAML scalar, so Windows backslashes are
// not read as escapes.
func quoteYAML(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
