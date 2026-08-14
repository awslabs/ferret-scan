// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// A config discovered in the working directory must be NAMED.
//
// FindConfigFile searches the CWD before anything else, so a config.yaml or
// .ferret-scan.yaml sitting beside the scanned content wins, and such a config can switch
// off whole detection categories via validators.<name>.disabled_types. Measured on the
// CLI with an empty user config dir:
//
//	without .ferret-scan.yaml -> 1 finding
//	with    .ferret-scan.yaml -> "No matches found." and ZERO mentions of the config
//
// Same binary, same flags, same file. THREAT_MODEL TB-7 already covers "an outside
// contributor's PR run through a maintainer's pre-commit/CI", and TM-11 covers that
// attacker driving confidence to zero through attacker-authored CONTENT; a config file in
// the same PR reaches the same outcome more directly. Naming the config does not close
// that hole — the opt-in gating in #293 is a separate policy call — but it turns an
// invisible substitution into a reviewable one.

func TestProvenanceNamesAConfigFoundInTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	path := filepath.Join(dir, ".ferret-scan.yaml")
	if err := os.WriteFile(path, []byte("validators:\n  intellectual_property:\n    disabled_types:\n      - copyright\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadConfigStrict(path)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	// explicitConfigFlag empty: this is the DISCOVERED case, the one nobody chose.
	reportConfigProvenance(&buf, cfg, "")

	out := buf.String()
	if out == "" {
		t.Fatal("a config discovered in the working directory was not reported at all; the " +
			"substitution stays invisible, which is the bug")
	}
	if !strings.Contains(out, ".ferret-scan.yaml") {
		t.Errorf("the note does not name the file: %q", out)
	}
	// It must say WHY it matters, or a reader has no reason to look.
	if !strings.Contains(out, "disable") {
		t.Errorf("the note does not say the config can disable detection: %q", out)
	}
	// Payload-free: this is a config path, never document content.
	if strings.Contains(out, "copyright") {
		t.Errorf("the note leaked config contents: %q", out)
	}
}

func TestProvenanceStaysQuietWhenTheUserNamedTheConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("defaults:\n  format: text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfigStrict(path)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	// The user passed --config explicitly. Reading it back is noise, not disclosure.
	reportConfigProvenance(&buf, cfg, path)
	if buf.Len() != 0 {
		t.Errorf("reported provenance for a config the user named explicitly: %q\n"+
			"Every run would then carry a line telling the user what they just typed.",
			buf.String())
	}
}

func TestProvenanceStaysQuietForBuiltinDefaults(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SourcePath != "" {
		t.Errorf("built-in defaults carry SourcePath %q; it must be empty so a caller can "+
			"tell \"defaults\" from \"a file\"", cfg.SourcePath)
	}

	var buf bytes.Buffer
	reportConfigProvenance(&buf, cfg, "")
	if buf.Len() != 0 {
		t.Errorf("reported provenance when no config file was involved: %q", buf.String())
	}
}

func TestProvenanceStaysQuietForAConfigOutsideTheWorkingDirectory(t *testing.T) {
	// A config in the user's own config dir is a standing personal preference, not a
	// per-run substitution. Reporting it on every scan would be noise that trains people
	// to ignore the line that matters.
	outside := t.TempDir()
	path := filepath.Join(outside, "config.yaml")
	if err := os.WriteFile(path, []byte("defaults:\n  format: text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfigStrict(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Chdir(t.TempDir()) // somewhere else entirely

	var buf bytes.Buffer
	reportConfigProvenance(&buf, cfg, "")
	if buf.Len() != 0 {
		t.Errorf("reported a config living outside the working directory: %q", buf.String())
	}
}

func TestProvenanceSurvivesNilInputs(t *testing.T) {
	// Called from two entry points; a nil writer or config must not panic the scan.
	reportConfigProvenance(nil, nil, "")
	var buf bytes.Buffer
	reportConfigProvenance(&buf, nil, "")
	if buf.Len() != 0 {
		t.Errorf("wrote something for a nil config: %q", buf.String())
	}
}

// TestConfigSourcePathIsNotSettableFromTheFile — provenance must describe where the
// config came from, not what it claims about itself.
//
// SourcePath carries yaml:"-" for this reason: a config that could set it would be able
// to report a different origin than the one it actually has, which is worse than no
// disclosure because it is a confident lie.
func TestConfigSourcePathIsNotSettableFromTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path,
		[]byte("sourcepath: /etc/innocent.yaml\nSourcePath: /etc/innocent.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfigStrict(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SourcePath != filepath.Clean(path) {
		t.Errorf("SourcePath = %q, want the file actually loaded (%q). A config file must "+
			"not be able to claim a different provenance.", cfg.SourcePath, filepath.Clean(path))
	}
}
