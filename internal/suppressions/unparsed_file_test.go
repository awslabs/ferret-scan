// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// A suppression file that exists but does not load (#880). It loads as empty, and every save used to
// write that empty state back over the operator's file: one --generate-suppressions run turned the
// issue's two enabled rules plus one bad line into two DISABLED rules with the bad line gone, and
// exited 0. These tests drive every save path against that file and require it byte-identical.
//
// They use only methods that predate the fix, so they run unchanged against the parent commit, where
// the generate, add, create and restore rows rewrite the file and the rest report "not found".

// unparsedTail is the issue's one bad edit, appended to the generated two-rule file.
const unparsedTail = "    - id: SUP-00000003\n      hash: [unclosed\n"

// unparsedYAMLError is the YAML error that file produces, with its line: the 24 generated lines, then
// the appended rule on line 25.
const unparsedYAMLError = "(yaml: line 25: did not find expected ',' or ']')"

// unparsedRuleFile writes the issue's broken file into a temp dir and returns its path and bytes.
func unparsedRuleFile(t *testing.T) (string, string) {
	t.Helper()
	text := generatedTwoRuleText(t) + unparsedTail
	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, text
}

// anyHash is a well-formed hash no rule in these files carries.
const anyHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // pragma: allowlist secret

// saveAttempts is every exported method that writes the suppression file, each called the way its
// callers call it. The CLI's --generate-suppressions is the first; the web UI reaches the others.
func saveAttempts() map[string]func(sm *SuppressionManager) error {
	finding := map[string]interface{}{"type": "SSN", "text": "fixture-value", "filename": "roster.txt", "line_number": float64(3)}
	extra := detector.Match{Type: "SSN", Text: "fixture-value", Filename: "roster.txt", LineNumber: 3, Validator: "ssn"}
	expiry := time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)
	return map[string]func(sm *SuppressionManager) error{
		"GenerateSuppressionRules": func(sm *SuppressionManager) error {
			return sm.GenerateSuppressionRules(strictTestMatches(), "Auto-generated suppression rule (disabled by default)", false)
		},
		"AddSuppression":               func(sm *SuppressionManager) error { return sm.AddSuppression(extra, "added", "tester", nil) },
		"CreateSuppressionFromFinding": func(sm *SuppressionManager) error { return sm.CreateSuppressionFromFinding("", "web", finding) },
		"CreateSuppressionFromFindingWithExpiration": func(sm *SuppressionManager) error {
			return sm.CreateSuppressionFromFindingWithExpiration("", "web", finding, &expiry)
		},
		"CreateSuppressionFromFindingWithState": func(sm *SuppressionManager) error {
			return sm.CreateSuppressionFromFindingWithState(anyHash, "undo", finding, true)
		},
		"RestoreSuppressions": func(sm *SuppressionManager) error {
			_, _, err := sm.RestoreSuppressions([]RuleRestore{{Rule: SuppressionRule{ID: "SUP-00000009", Hash: anyHash, Enabled: true}, Position: 0}})
			return err
		},
		"EditSuppression": func(sm *SuppressionManager) error {
			return sm.EditSuppression("SUP-00000001", "edited", "tester", true, nil)
		},
		"DisableSuppressionByID":  func(sm *SuppressionManager) error { return sm.DisableSuppressionByID("SUP-00000001") },
		"EnableSuppressionByHash": func(sm *SuppressionManager) error { return sm.EnableSuppressionByHash(anyHash, "enabled") },
		"RemoveSuppression":       func(sm *SuppressionManager) error { return sm.RemoveSuppression("SUP-00000001") },
	}
}

func TestASaveOverAFileThatDidNotParseWritesNothing(t *testing.T) {
	for name, save := range saveAttempts() {
		t.Run(name, func(t *testing.T) {
			path, before := unparsedRuleFile(t)
			sm, warnings := loadWithWarnings(t, path)
			if !strings.Contains(warnings, "is malformed "+unparsedYAMLError) {
				t.Fatalf("the fixture did not load as malformed; the loader printed %q", warnings)
			}

			err := save(sm)
			if err == nil {
				t.Errorf("%s returned no error over a file it could not parse", name)
			} else {
				want := "suppression file " + path + " could not be parsed " + unparsedYAMLError +
					"; fix it or move it aside before regenerating; nothing was written"
				if err.Error() != want {
					t.Errorf("%s: error %q\nwant %q", name, err, want)
				}
			}
			if after := readText(t, path); after != before {
				t.Errorf("%s rewrote the file it could not parse:\nbefore:\n%s\nafter:\n%s", name, before, after)
			}
			if rules := sm.ListSuppressions(); len(rules) != 0 {
				t.Errorf("after the refused %s the manager holds %d rule(s) the file does not", name, len(rules))
			}
		})
	}

	t.Run("CleanupExpired", func(t *testing.T) {
		path, before := unparsedRuleFile(t)
		sm, _ := loadWithWarnings(t, path)
		if removed := sm.CleanupExpired(); removed != 0 {
			t.Errorf("CleanupExpired removed %d rule(s) from a file it could not parse", removed)
		}
		if readText(t, path) != before {
			t.Error("CleanupExpired rewrote the file it could not parse")
		}
	})
}

// TestAFileOfTheWrongShapeIsNotRewritten: valid YAML that does not decode as a rule file loads as
// empty through the same branch, and is refused the same way.
func TestAFileOfTheWrongShapeIsNotRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shape.yaml")
	before := "version: \"1.0\"\nrules: \"SUP-00000001 is reviewed, see the ticket\"\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	sm, warnings := loadWithWarnings(t, path)
	if !strings.Contains(warnings, "is malformed") {
		t.Fatalf("the fixture did not load as malformed; the loader printed %q", warnings)
	}
	err := sm.GenerateSuppressionRules(strictTestMatches(), "generated", false)
	if err == nil || !strings.Contains(err.Error(), "could not be parsed (yaml: unmarshal errors:") {
		t.Errorf("GenerateSuppressionRules over a file of the wrong shape: %v", err)
	}
	if readText(t, path) != before {
		t.Errorf("the file was rewritten:\n%s", readText(t, path))
	}
}

// TestAFileThatCannotBeReadIsNotReplaced: a file that exists but cannot be read holds rules nobody can
// see, so it is not replaced either. A write-only file is the case where the old save succeeded.
func TestAFileThatCannotBeReadIsNotReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits do not deny reading on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	path := filepath.Join(t.TempDir(), "unreadable.yaml")
	before := generatedTwoRuleText(t)
	if err := os.WriteFile(path, []byte(before), 0o200); err != nil {
		t.Fatal(err)
	}
	sm, warnings := loadWithWarnings(t, path)
	err := sm.GenerateSuppressionRules(strictTestMatches(), "generated", false)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warnings, "cannot read suppression file") {
		t.Fatalf("the fixture was readable; the loader printed %q", warnings)
	}
	if err == nil || !strings.Contains(err.Error(), "could not be read (open "+path+": permission denied); fix it or move it aside") {
		t.Errorf("GenerateSuppressionRules over an unreadable file: %v", err)
	}
	if after := readText(t, path); after != before {
		t.Errorf("the unreadable file was replaced:\n%s", after)
	}
}

// The controls: a file that is not there, or is there and empty, is not a load failure, and the first
// save writes it as before; a file fixed after a refusal loads and saves normally.
func TestAMissingOrEmptyFileIsStillWritten(t *testing.T) {
	t.Run("missing, in a directory that does not exist yet", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "rules.yaml")
		sm, warnings := loadWithWarnings(t, path)
		if warnings != "" {
			t.Errorf("a missing file printed %q", warnings)
		}
		if err := sm.GenerateSuppressionRules(strictTestMatches(), "generated", false); err != nil {
			t.Fatalf("GenerateSuppressionRules over a missing file: %v", err)
		}
		if got := len(NewSuppressionManager(path).ListSuppressions()); got != 2 {
			t.Errorf("the created file holds %d rules, want 2", got)
		}
	})
	t.Run("empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rules.yaml")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewSuppressionManager(path).GenerateSuppressionRules(strictTestMatches(), "generated", false); err != nil {
			t.Fatalf("GenerateSuppressionRules over an empty file: %v", err)
		}
		if got := len(NewSuppressionManager(path).ListSuppressions()); got != 2 {
			t.Errorf("the written file holds %d rules, want 2", got)
		}
	})
	t.Run("fixed after a refusal", func(t *testing.T) {
		path, broken := unparsedRuleFile(t)
		refusing, _ := loadWithWarnings(t, path)
		if err := refusing.GenerateSuppressionRules(strictTestMatches(), "generated", false); err == nil {
			t.Fatal("the broken file was not refused")
		}
		if err := os.WriteFile(path, []byte(strings.TrimSuffix(broken, unparsedTail)), 0o600); err != nil {
			t.Fatal(err)
		}
		sm, warnings := loadWithWarnings(t, path)
		if warnings != "" {
			t.Errorf("the fixed file printed %q", warnings)
		}
		if err := sm.GenerateSuppressionRules(strictTestMatches(), "generated", false); err != nil {
			t.Fatalf("GenerateSuppressionRules over the fixed file: %v", err)
		}
		reloaded := NewSuppressionManager(path)
		if got := suppressedCount(reloaded); got != 2 {
			t.Errorf("the fixed file's two enabled rules suppress %d of 2 after a save", got)
		}
	})
}
