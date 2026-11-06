// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadErrorRecordsTheFailure: the recorded failure is what the web UI's 409 and the CLI read, and
// what every refused save returns.
func TestLoadErrorRecordsTheFailure(t *testing.T) {
	path, _ := unparsedRuleFile(t)
	sm, _ := loadWithWarnings(t, path)
	loadErr := sm.LoadError()
	if loadErr == nil {
		t.Fatal("LoadError is nil for a file that did not parse")
	}
	want := "suppression file " + path + " could not be parsed " + unparsedYAMLError +
		"; fix it or move it aside before regenerating; nothing was written"
	if loadErr.Error() != want {
		t.Errorf("LoadError = %q\nwant      %q", loadErr, want)
	}
	if !errors.Is(loadErr, ErrFileNotLoaded) {
		t.Error("LoadError does not match ErrFileNotLoaded")
	}
	if inner := errors.Unwrap(loadErr); inner == nil || !strings.HasPrefix(inner.Error(), "yaml: line 25:") {
		t.Errorf("LoadError wraps %v, want the YAML error", inner)
	}

	genErr := sm.GenerateSuppressionRules(strictTestMatches(), "generated", false)
	if !errors.Is(genErr, ErrFileNotLoaded) {
		t.Errorf("the refused generation returned %v, which does not match ErrFileNotLoaded", genErr)
	}
	if sm.LoadError() != loadErr {
		t.Error("a refused save changed the recorded load failure")
	}

	for name, file := range map[string]string{
		"a missing file":     filepath.Join(t.TempDir(), "absent.yaml"),
		"a file that parsed": copyToTemp(t, filepath.Join("testdata", "commented-rules.yaml")),
	} {
		mgr, _ := loadWithWarnings(t, file)
		if err := mgr.LoadError(); err != nil {
			t.Errorf("LoadError for %s = %v, want nil", name, err)
		}
	}
}
