// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/version"
)

// scopeTestChecks stands in for core.CheckNames; this package must not import core.
var scopeTestChecks = []string{"EMAIL", "INTELLECTUAL_PROPERTY", "METADATA", "SSN"}

var allBands = map[string]bool{"high": true, "medium": true, "low": true}

func TestNewScanScopeIsNilForAFullScopeRun(t *testing.T) {
	// The compatibility half of #904: a run that ran in full must render exactly what it rendered
	// before, so it must not have a scope at all.
	cases := map[string]ScopeInputs{
		"every check, every band": {
			ChecksRun: scopeTestChecks, AllChecks: scopeTestChecks, ConfidenceLevel: allBands,
		},
		"stdin: every applicable check, METADATA not applicable": {
			ChecksRun:           []string{"EMAIL", "INTELLECTUAL_PROPERTY", "SSN"},
			AllChecks:           scopeTestChecks,
			ChecksNotApplicable: []string{"METADATA"},
			ConfidenceLevel:     allBands,
		},
		"an empty disabled list is not a disabled sub-type": {
			ChecksRun: scopeTestChecks, AllChecks: scopeTestChecks, ConfidenceLevel: allBands,
			DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {}},
		},
		"suppression rules are not narrowing": {
			ChecksRun: scopeTestChecks, AllChecks: scopeTestChecks, ConfidenceLevel: allBands,
			SuppressionRulesEnabled: 3,
		},
		"a profile that narrowed nothing": {
			ChecksRun: scopeTestChecks, AllChecks: scopeTestChecks, ConfidenceLevel: allBands,
			Profile: &ScanProfile{Name: "ci", SelectedBy: ProfileSelectedByFlag},
		},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if s := NewScanScope(in); s != nil {
				t.Errorf("a full-scope run got a scope, so its report would gain bytes: %+v", s)
			}
		})
	}
}

func TestNewScanScopeNamesWhatANarrowedRunCouldReport(t *testing.T) {
	t.Run("checks narrowed", func(t *testing.T) {
		s := NewScanScope(ScopeInputs{
			ChecksRun:       []string{"SSN"},
			AllChecks:       scopeTestChecks,
			ConfidenceLevel: allBands,
			Config:          ScanConfigSource{Source: ConfigSourceExplicit},
		})
		if s == nil {
			t.Fatal("--checks SSN got no scope, so its report is identical to a clean full scan")
		}
		if want := []string{"SSN"}; !reflect.DeepEqual(s.ChecksRun, want) {
			t.Errorf("ChecksRun = %v, want %v", s.ChecksRun, want)
		}
		// Derived from AllChecks, not hard-coded.
		if want := []string{"EMAIL", "INTELLECTUAL_PROPERTY", "METADATA"}; !reflect.DeepEqual(s.ChecksNotRun, want) {
			t.Errorf("ChecksNotRun = %v, want %v", s.ChecksNotRun, want)
		}
		if s.ChecksNotApplicable != nil {
			t.Errorf("ChecksNotApplicable = %v on a file run, want omitted", s.ChecksNotApplicable)
		}
		if want := []string{"high", "medium", "low"}; !reflect.DeepEqual(s.ConfidenceLevels, want) {
			t.Errorf("ConfidenceLevels = %v, want %v", s.ConfidenceLevels, want)
		}
		if s.Config.Source != ConfigSourceExplicit {
			t.Errorf("Config.Source = %q", s.Config.Source)
		}
	})

	t.Run("stdin: METADATA is not applicable rather than not run", func(t *testing.T) {
		s := NewScanScope(ScopeInputs{
			ChecksRun:           []string{"SSN"},
			AllChecks:           scopeTestChecks,
			ChecksNotApplicable: []string{"METADATA"},
			ConfidenceLevel:     allBands,
		})
		if s == nil {
			t.Fatal("nil scope")
		}
		if want := []string{"METADATA"}; !reflect.DeepEqual(s.ChecksNotApplicable, want) {
			t.Errorf("ChecksNotApplicable = %v, want %v", s.ChecksNotApplicable, want)
		}
		for _, c := range s.ChecksNotRun {
			if c == "METADATA" {
				t.Errorf("METADATA listed as not run on stdin, where it cannot run whatever was asked: %v", s.ChecksNotRun)
			}
		}
		if got := s.TotalChecks(); got != len(scopeTestChecks) {
			t.Errorf("TotalChecks = %d, want %d: run + not run + not applicable must cover every check", got, len(scopeTestChecks))
		}
	})

	t.Run("confidence narrowed, in display order", func(t *testing.T) {
		s := NewScanScope(ScopeInputs{
			ChecksRun: scopeTestChecks, AllChecks: scopeTestChecks,
			ConfidenceLevel: map[string]bool{"low": true, "high": true},
		})
		if s == nil {
			t.Fatal("--confidence high,low got no scope, so a hidden band leaves no trace")
		}
		if want := []string{"high", "low"}; !reflect.DeepEqual(s.ConfidenceLevels, want) {
			t.Errorf("ConfidenceLevels = %v, want %v", s.ConfidenceLevels, want)
		}
		if want := []string{"medium"}; !reflect.DeepEqual(s.HiddenConfidenceLevels(), want) {
			t.Errorf("HiddenConfidenceLevels = %v, want %v", s.HiddenConfidenceLevels(), want)
		}
	})

	t.Run("a disabled sub-type narrows, and is carried sorted", func(t *testing.T) {
		s := NewScanScope(ScopeInputs{
			ChecksRun: scopeTestChecks, AllChecks: scopeTestChecks, ConfidenceLevel: allBands,
			DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {"trademark", "copyright"}},
		})
		if s == nil {
			t.Fatal("a disabled sub-type got no scope")
		}
		if want := []string{"INTELLECTUAL_PROPERTY:copyright", "INTELLECTUAL_PROPERTY:trademark"}; !reflect.DeepEqual(s.DisabledTypePairs(), want) {
			t.Errorf("DisabledTypePairs = %v, want %v", s.DisabledTypePairs(), want)
		}
	})

	t.Run("no check ran: an empty list, never null", func(t *testing.T) {
		s := NewScanScope(ScopeInputs{
			ChecksRun: nil, AllChecks: []string{"METADATA"}, ChecksNotApplicable: []string{"METADATA"},
			ConfidenceLevel: map[string]bool{},
		})
		if s == nil {
			t.Fatal("nil scope")
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"checks_run":[]`, `"checks_not_run":[]`, `"confidence_levels":[]`} {
			if !strings.Contains(string(b), want) {
				t.Errorf("%s missing from %s; a null list reads as an absent field", want, b)
			}
		}
	})
}

func TestScanScopeSerialisesWithoutDuplicatingStats(t *testing.T) {
	s := NewScanScope(ScopeInputs{
		ChecksRun: []string{"SSN"}, AllChecks: scopeTestChecks, ConfidenceLevel: allBands,
		DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}},
		Profile:                &ScanProfile{Name: "ci", SelectedBy: ProfileSelectedByFlag},
		Config:                 ScanConfigSource{Source: ConfigSourceWorkingDirectory, Name: ".ferret-scan.yaml"},
	})
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "copyright") || strings.Contains(got, "disabled") {
		t.Errorf("the scope serialised the disabled sub-types, which stats.disabled_detection_types already carries: %s", got)
	}
	for _, want := range []string{`"profile":{"name":"ci","selected_by":"--profile"}`,
		`"config":{"source":"working-directory","name":".ferret-scan.yaml"}`, `"suppressions":{"rules_enabled":0}`,
		`"tool":{"name":"ferret-scan"`} {
		if !strings.Contains(got, want) {
			t.Errorf("%s missing from %s", want, got)
		}
	}
}

func TestScanScopeToolCommitIsTwelveHex(t *testing.T) {
	saved, savedVersion := version.GitCommit, version.Version
	t.Cleanup(func() { version.GitCommit, version.Version = saved, savedVersion })

	version.Version = "2.5.3"
	version.GitCommit = "5fecf59c1decc766139bfe5af752e80884d120c4"
	s := NewScanScope(ScopeInputs{ChecksRun: []string{"SSN"}, AllChecks: scopeTestChecks, ConfidenceLevel: allBands})
	if s == nil || s.Tool == nil {
		t.Fatal("no tool block")
	}
	if s.Tool.Commit != "5fecf59c1dec" || s.Tool.Version != "2.5.3" {
		t.Errorf("tool = %+v, want version 2.5.3 and the 12-hex commit 5fecf59c1dec", *s.Tool)
	}

	version.GitCommit = "unknown"
	if s := NewScanScope(ScopeInputs{ChecksRun: []string{"SSN"}, AllChecks: scopeTestChecks, ConfidenceLevel: allBands}); s.Tool.Commit != "unknown" {
		t.Errorf("a development build's commit = %q, want it as injected", s.Tool.Commit)
	}
}

func TestScanScopeTextLine(t *testing.T) {
	cases := []struct {
		name string
		in   ScopeInputs
		want string
	}{
		{
			name: "the shorter list is the one named",
			in:   ScopeInputs{ChecksRun: []string{"SSN"}, AllChecks: scopeTestChecks, ConfidenceLevel: allBands},
			want: "Scope: ran 1 of 4 checks (SSN)",
		},
		{
			name: "more ran than not: name what did not",
			in: ScopeInputs{ChecksRun: []string{"SSN", "EMAIL", "METADATA"}, AllChecks: scopeTestChecks,
				ConfidenceLevel: map[string]bool{"high": true, "medium": true}},
			want: "Scope: ran 3 of 4 checks (not run: INTELLECTUAL_PROPERTY); confidence shown: high, medium",
		},
		{
			name: "stdin, a profile and a disabled sub-type",
			in: ScopeInputs{ChecksRun: []string{"SSN"}, AllChecks: scopeTestChecks, ChecksNotApplicable: []string{"METADATA"},
				ConfidenceLevel: allBands, Profile: &ScanProfile{Name: "precommit", SelectedBy: ProfileSelectedByPrecommit},
				DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}}},
			want: "Scope: ran 1 of 4 checks (SSN); not applicable to this input: METADATA; profile: precommit (pre-commit mode); disabled sub-types: INTELLECTUAL_PROPERTY:copyright",
		},
		{
			name: "every check ran, a band is hidden",
			in:   ScopeInputs{ChecksRun: scopeTestChecks, AllChecks: scopeTestChecks, ConfidenceLevel: map[string]bool{"high": true}},
			want: "Scope: ran 4 of 4 checks; confidence shown: high",
		},
		{
			name: "nothing ran",
			in:   ScopeInputs{AllChecks: scopeTestChecks, ConfidenceLevel: allBands},
			want: "Scope: ran 0 of 4 checks (none)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewScanScope(tc.in).TextLine(); got != tc.want {
				t.Errorf("TextLine:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
	var nilScope *ScanScope
	if nilScope.TextLine() != "" {
		t.Error("a nil scope rendered a line")
	}
}

func TestConfigSourceOf(t *testing.T) {
	cwd := t.TempDir()
	elsewhere := t.TempDir()
	cases := []struct {
		name       string
		sourcePath string
		explicit   bool
		want       ScanConfigSource
	}{
		{"built-in", "", false, ScanConfigSource{Source: ConfigSourceBuiltin}},
		{"nothing loaded is built-in, whatever the flag says", "", true, ScanConfigSource{Source: ConfigSourceBuiltin}},
		{"explicit: never a path", filepath.Join(cwd, "config.yaml"), true, ScanConfigSource{Source: ConfigSourceExplicit}},
		{"working directory, a discovery name", filepath.Join(cwd, ".ferret-scan.yaml"), false,
			ScanConfigSource{Source: ConfigSourceWorkingDirectory, Name: ".ferret-scan.yaml"}},
		{"working directory, relative as discovery records it", "config.yaml", false,
			ScanConfigSource{Source: ConfigSourceWorkingDirectory, Name: "config.yaml"}},
		{"working directory, a name discovery never uses: no name", filepath.Join(cwd, "sub", "my-team-secrets.yaml"), false,
			ScanConfigSource{Source: ConfigSourceWorkingDirectory}},
		{"user config dir", filepath.Join(elsewhere, "config.yaml"), false, ScanConfigSource{Source: ConfigSourceUserConfigDir}},
	}
	t.Chdir(cwd)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ConfigSourceOf(tc.sourcePath, tc.explicit, cwd); got != tc.want {
				t.Errorf("ConfigSourceOf(%q, %v) = %+v, want %+v", tc.sourcePath, tc.explicit, got, tc.want)
			}
		})
	}
}

// TestConfigSourceNamesTrackDiscovery keeps discoveredConfigNames equal to what config.FindConfigFile
// finds in a working directory: a name missing here would drop from reports, and one added here that
// discovery never uses would let a report carry a name the operator chose.
func TestConfigSourceNamesTrackDiscovery(t *testing.T) {
	t.Setenv("FERRET_CONFIG_DIR", t.TempDir()) // no user config dir to fall through to
	found := map[string]bool{}
	for name := range discoveredConfigNames {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("defaults:\n  format: text\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := config.FindConfigFile(); got != name {
			t.Errorf("with only %s in the working directory, FindConfigFile returned %q: discovery no longer uses that name", name, got)
			continue
		}
		found[name] = true
	}
	// The reverse direction: a decoy name beside the real ones must not be discovered as a sixth.
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "ferret-scan.yaml"), []byte("defaults:\n  format: text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := config.FindConfigFile(); got != "" && filepath.Dir(got) == "." {
		t.Errorf("FindConfigFile discovered %q in the working directory, which discoveredConfigNames does not list", got)
	}
	if len(found) != len(discoveredConfigNames) {
		t.Errorf("discovery confirmed %d of %d names", len(found), len(discoveredConfigNames))
	}
}
