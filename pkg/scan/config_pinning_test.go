// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A library scan must be able to say what config governs it.
//
// ScanText/ScanFile/RedactFile called config.LoadConfigOrDefault("") unconditionally,
// and neither options struct had a config field. Discovery searches the process WORKING
// DIRECTORY first, so a config.yaml or .ferret-scan.yaml sitting there wins — and such a
// config can switch off whole detection categories through
// validators.<name>.disabled_types.
//
// Measured with an identical ScanText call, only the CWD differing:
//
//	cwd=/tmp/empty  findings=1
//	cwd=/tmp/work   findings=0
//
// So an embedded consumer got behaviour that depended on where its process happened to
// be running, with no way to pin it, no way to request built-in defaults, and no way to
// write a hermetic test. Same shape as the redact.ValidCheckNames()/SOCIAL_MEDIA case —
// a successful call, an empty finding list, input treated as clean — except the cause is
// ambient rather than in the caller's arguments. See #293.

// ipBody trips INTELLECTUAL_PROPERTY on the default config. It is the fixture the issue
// used, because intellectual_property.disabled_types is the lever verified to silence it.
const ipBody = "Copyright (c) 2026 Acme Corporation. All rights reserved.\n" +
	"Internal wiki: https://w.amazon.com/team\n"

// disablingConfig switches off the very types ipBody trips.
const disablingConfig = `validators:
  intellectual_property:
    disabled_types:
      - copyright
      - internal_url
`

// chdir moves the process into dir for the duration of the test.
//
// t.Chdir would be tidier but the process working directory is exactly the ambient input
// under test, so it has to actually change.
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

// planted returns a directory containing a project config that disables detection.
func planted(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".ferret-scan.yaml"),
		[]byte(disablingConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDisableConfigDiscoveryIgnoresAmbientConfig(t *testing.T) {
	// Baseline: with discovery on, the planted config silences the finding. If this
	// stops holding, the fixture no longer reproduces the problem and the assertions
	// below would pass for the wrong reason.
	chdir(t, planted(t))

	ambient, err := ScanText(context.Background(), ipBody,
		TextOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ambient.Findings) != 0 {
		t.Fatalf("fixture does not reproduce: with discovery on and a disabling config in "+
			"the CWD, expected 0 findings, got %d. The rest of this test would be vacuous.",
			len(ambient.Findings))
	}

	// The fix: the same call, opted out of ambient config.
	pinned, err := ScanText(context.Background(), ipBody,
		TextOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}, DisableConfigDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned.Findings) == 0 {
		t.Error("DisableConfigDiscovery still honoured a config file in the working " +
			"directory. A caller that asks for built-in defaults must get detection that " +
			"does not depend on where its process is running.")
	}
}

func TestDisableConfigDiscoveryIsWorkingDirectoryIndependent(t *testing.T) {
	// The property that matters for a hermetic test: same answer from any directory.
	counts := map[string]int{}
	for _, dir := range []string{t.TempDir(), planted(t)} {
		func() {
			chdir(t, dir)
			r, err := ScanText(context.Background(), ipBody,
				TextOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}, DisableConfigDiscovery: true})
			if err != nil {
				t.Fatal(err)
			}
			counts[dir] = len(r.Findings)
		}()
	}
	var seen []int
	for _, n := range counts {
		seen = append(seen, n)
	}
	if len(seen) == 2 && seen[0] != seen[1] {
		t.Errorf("DisableConfigDiscovery produced different results per directory: %v. "+
			"That is the whole point of the flag — a caller cannot write a hermetic test "+
			"otherwise.", counts)
	}
	for dir, n := range counts {
		if n == 0 {
			t.Errorf("0 findings in %s with defaults only; the fixture should trip "+
				"INTELLECTUAL_PROPERTY", dir)
		}
	}
}

func TestConfigPathPinsAnExplicitFile(t *testing.T) {
	// A clean CWD, and the disabling config named explicitly. Pinning must APPLY the
	// named file — a pin that silently ignored it would be worse than no pin.
	dir := planted(t)
	cfg := filepath.Join(dir, ".ferret-scan.yaml")
	chdir(t, t.TempDir()) // deliberately NOT the directory holding the config

	unpinned, err := ScanText(context.Background(), ipBody,
		TextOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(unpinned.Findings) == 0 {
		t.Fatal("baseline found nothing from a clean directory; fixture is broken")
	}

	pinned, err := ScanText(context.Background(), ipBody,
		TextOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}, ConfigPath: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned.Findings) != 0 {
		t.Errorf("ConfigPath=%s was not applied: got %d findings, want 0. The named config "+
			"disables these types, so a pin that changes nothing means the option is "+
			"decorative.", cfg, len(pinned.Findings))
	}
}

func TestDisableConfigDiscoveryBeatsConfigPath(t *testing.T) {
	// Documented precedence: the stricter request wins, so a caller cannot end up
	// honouring a file while believing it asked for defaults.
	cfg := filepath.Join(planted(t), ".ferret-scan.yaml")
	chdir(t, t.TempDir())

	r, err := ScanText(context.Background(), ipBody, TextOptions{
		Checks:                 []string{"INTELLECTUAL_PROPERTY"},
		ConfigPath:             cfg,
		DisableConfigDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) == 0 {
		t.Error("with both set, the ConfigPath file was applied; DisableConfigDiscovery " +
			"must take precedence because it is the stricter request")
	}
}

func TestDefaultBehaviourIsUnchanged(t *testing.T) {
	// Compatibility: an existing caller passing neither field must keep the historical
	// discovery behaviour, including the CWD-sensitivity. This is asserted rather than
	// assumed, because "fixing" it silently would change results for every embedded
	// consumer without them asking.
	chdir(t, planted(t))
	r, err := ScanText(context.Background(), ipBody,
		TextOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("default (no config fields set) no longer discovers the working-directory "+
			"config: got %d findings, want 0. Changing this default is a breaking change "+
			"for embedded callers and is not what #293 asked for.", len(r.Findings))
	}
}

func TestUnreadableConfigPathFallsBackToDefaultsRatherThanCrashing(t *testing.T) {
	chdir(t, t.TempDir())
	r, err := ScanText(context.Background(), ipBody, TextOptions{
		Checks:     []string{"INTELLECTUAL_PROPERTY"},
		ConfigPath: filepath.Join(t.TempDir(), "does-not-exist.yaml"),
	})
	if err != nil {
		t.Fatalf("a missing ConfigPath should not fail the scan outright: %v", err)
	}
	if len(r.Findings) == 0 {
		t.Error("a missing ConfigPath produced no findings; it must fall back to built-in " +
			"defaults so the scan still detects, rather than silently running with " +
			"nothing enabled")
	}
}

// TestResolveConfigFallbackIsRealDefaultsNotAZeroValue tests resolveConfig directly,
// because the end-to-end test above cannot tell the two apart.
//
// A mutation returning &config.Config{} on the error path COMPILED AND PASSED the
// end-to-end test: for that fixture an empty config detects the same as a populated one,
// since nothing in an empty config disables anything. So the end-to-end assertion never
// distinguished "built-in defaults" from "a zero value", and the guard was unproven.
//
// A zero-value Config is not harmless in general — it has no Profiles map, no Validators
// map, and empty Defaults — so anything later reading those gets different behaviour than
// a real default config, or panics on a nil map write. Asserting a field that
// LoadConfig("") populates and a zero value does not is what makes the distinction
// testable.
func TestResolveConfigFallbackIsRealDefaultsNotAZeroValue(t *testing.T) {
	cfg := resolveConfig(filepath.Join(t.TempDir(), "missing.yaml"), false)
	if cfg == nil {
		t.Fatal("resolveConfig returned nil for an unreadable path")
	}
	if cfg.Defaults.Format != "text" {
		t.Errorf("Defaults.Format = %q, want %q — the error path must return the built-in "+
			"default config, not a zero value", cfg.Defaults.Format, "text")
	}
	if cfg.Defaults.Checks != "all" {
		t.Errorf("Defaults.Checks = %q, want \"all\"", cfg.Defaults.Checks)
	}
	if cfg.Profiles == nil {
		t.Error("Profiles map is nil; a zero-value Config would panic on a later write")
	}
	if cfg.Validators == nil {
		t.Error("Validators map is nil; a zero-value Config would panic on a later write")
	}
	if cfg.SourcePath != "" {
		t.Errorf("SourcePath = %q; the fallback applied no file, so it must be empty rather "+
			"than naming one whose contents were never used", cfg.SourcePath)
	}

	// And the same properties for the explicit defaults-only request.
	d := resolveConfig("", true)
	if d == nil || d.Defaults.Format != "text" || d.Profiles == nil || d.SourcePath != "" {
		t.Errorf("DisableConfigDiscovery did not return a populated default config: %+v",
			d.Defaults)
	}
}

func TestScanFileHonoursTheSameKnobs(t *testing.T) {
	// The same contract on the file path, because that is what most embedded callers use.
	dir := planted(t)
	chdir(t, dir)

	path := filepath.Join(dir, "notice.txt")
	if err := os.WriteFile(path, []byte(ipBody), 0o600); err != nil {
		t.Fatal(err)
	}

	ambient, err := ScanFile(context.Background(), path,
		FileOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ambient.Findings) != 0 {
		t.Fatalf("fixture does not reproduce on the file path: got %d findings, want 0",
			len(ambient.Findings))
	}

	pinned, err := ScanFile(context.Background(), path,
		FileOptions{Checks: []string{"INTELLECTUAL_PROPERTY"}, DisableConfigDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned.Findings) == 0 {
		t.Error("ScanFile ignored DisableConfigDiscovery; the two entry points must not " +
			"disagree about whether a caller can opt out")
	}
}
