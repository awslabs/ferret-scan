// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #776: a redaction must neither need nor write a configuration directory in the user's home.
//
// The PDF redactor built its pdfcpu configuration with model.NewDefaultConfiguration, which
// ensures <os.UserConfigDir()>/pdfcpu exists, seeds it with config.yml and a font file, and
// panics through pdfcpu's fault.Fail when it cannot. NewDefaultRedactionManager registers that
// redactor for every redaction, PDF or not. So in the shipped container, whose home its own user
// could not write, every --enable-redaction run died with a stack trace at exit 2 before reading
// its input, and on every other host each run left pdfcpu's tree in the user's home.
//
// Measured on main @ d5c4da15 with a one-line text file: HOME pointed at an empty directory ends
// up holding .config/pdfcpu/{config.yml,fonts/Roboto-Regular.gob,certs/}, 187,758 bytes, and HOME
// beneath a regular file panics with "config problem: mkdir ...: not a directory", exit 2.
//
// Each case runs in a child process, this test binary re-executed, for two reasons. pdfcpu caches
// the configuration it loads for the life of the process, so once any earlier test in this package
// has built a redaction manager the defect can no longer be observed in-process. And the home has
// to be in place before anything in the process reads it.
const (
	configDirChildEnv = "FERRET_SCAN_TEST_CONFIG_DIR_CHILD"
	configDirWorkEnv  = "FERRET_SCAN_TEST_CONFIG_DIR_WORK"
)

func TestRedactionNeedsNoUserConfigDir(t *testing.T) {
	if os.Getenv(configDirChildEnv) != "" {
		redactWithoutTouchingHome(t, os.Getenv(configDirWorkEnv))
		return
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate the test binary: %v", err)
	}

	// A regular file where a directory is expected: creating anything beneath it fails with
	// ENOTDIR for every user, root included. A read-only directory would not do, because root
	// writes through it and CI containers commonly run as root.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		home string
		// mustStayEmpty is checked where the home can be written, which is where the old code
		// wrote into it instead of failing.
		mustStayEmpty bool
	}{
		{name: "home cannot be created", home: filepath.Join(blocker, "home")},
		{name: "home is writable", home: t.TempDir(), mustStayEmpty: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestRedactionNeedsNoUserConfigDir$")
			cmd.Env = append(withoutEnv(os.Environ(), "HOME", "XDG_CONFIG_HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"),
				configDirChildEnv+"=1",
				configDirWorkEnv+"="+t.TempDir(),
				// What os.UserConfigDir and os.UserHomeDir read: $XDG_CONFIG_HOME, else
				// $HOME/.config, on Linux; $HOME/Library/Application Support on macOS;
				// %AppData% and %USERPROFILE% on Windows.
				"HOME="+tc.home,
				"XDG_CONFIG_HOME=",
				"USERPROFILE="+tc.home,
				"APPDATA="+tc.home,
				"LOCALAPPDATA="+tc.home,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("a redaction with its home at %s failed (%v); the child said:\n%s", tc.home, err, out)
			}
			if !tc.mustStayEmpty {
				return
			}
			var written []string
			err := filepath.WalkDir(tc.home, func(path string, _ fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if rel, _ := filepath.Rel(tc.home, path); rel != "." {
					written = append(written, filepath.ToSlash(rel))
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(written) > 0 {
				t.Errorf("a redaction wrote into the user's home: %s", strings.Join(written, ", "))
			}
		})
	}
}

// redactWithoutTouchingHome is the child half. It builds the manager that every redaction path
// shares (the CLI, RedactFile and RedactionCapabilities), then runs one whole redaction through
// RedactFile, which pkg/scan.RedactFile wraps. The input and output live under work, so anything
// that appears in the home came from the redaction machinery itself.
func redactWithoutTouchingHome(t *testing.T, work string) {
	if work == "" {
		t.Fatal(configDirWorkEnv + " is not set")
	}
	if _, _, err := NewDefaultRedactionManager(filepath.Join(work, "manager"), redactors.RedactionSimple, nil); err != nil {
		t.Fatalf("NewDefaultRedactionManager: %v", err)
	}

	// Reserved documentation value.
	src := writeTemp(t, work, "leak.txt", "email jordan@example.com\n")
	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: filepath.Join(work, "out"),
		Strategy:  "simple",
		Checks:    []string{"EMAIL"},
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile: %v", err)
	}
	data, err := os.ReadFile(res.RedactedFilePath)
	if err != nil {
		t.Fatalf("read the redacted copy: %v", err)
	}
	if res.RedactionCount == 0 || strings.Contains(string(data), "jordan@example.com") {
		t.Fatalf("expected the address to be redacted; got %d redactions and:\n%s", res.RedactionCount, data)
	}
}

// withoutEnv returns env minus the named variables. Names compare case-insensitively, as Windows
// requires; none of the Unix names involved differ only by case.
func withoutEnv(env []string, names ...string) []string {
	kept := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) }) {
			kept = append(kept, kv)
		}
	}
	return kept
}
