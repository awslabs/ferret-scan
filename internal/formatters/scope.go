// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/paths"
	"github.com/awslabs/ferret-scan/v2/internal/version"
)

// ScanScope says what a NARROWED run could report: which checks ran and which did not, which
// confidence bands the report shows, and the profile and config that chose them (#904).
//
// Without it a narrowed run was byte-identical to a clean full scan. Measured on main at 5fecf59 with
// a file holding a copyright notice and an email address: `--checks SSN`, `defaults.checks: SSN` in a
// `--config`, `--profile ci` from one, and `--profile precommit` each gave the same report as a clean
// scan of a neutral file in all seven formats, exit 0, 0 B of stderr. A CI job reading `"results": []`
// could not tell "nothing there" from "nothing looked for".
//
// nil renders nothing, and NewScanScope returns nil for a run that was NOT narrowed, so a full-scope
// report keeps every byte it had before this type existed, in every format. That is also why the
// golden corpus does not move: its harness builds FormatterOptions without a scope.
//
// Every field is sourced from what RAN, never echoed from a flag: the checks are the keys of the
// validator set the detector was given, and the disabled sub-types are what those validators report.
// An echo would list METADATA as run on --stdin, where it cannot run, and would trust a flag the input
// path ignores.
type ScanScope struct {
	// Tool names the build that wrote the report. Its commit is 12 hex digits at most, because a
	// 40-hex commit in a report scans as API_KEY_OR_SECRET (see version.ReportCommit).
	Tool *ScanTool `json:"tool,omitempty" yaml:"tool,omitempty"`

	// ChecksRun is sorted and never null: an empty list is a run in which nothing could be found.
	ChecksRun []string `json:"checks_run" yaml:"checks_run"`

	// ChecksNotRun is every known check that neither ran nor was inapplicable, sorted.
	ChecksNotRun []string `json:"checks_not_run" yaml:"checks_not_run"`

	// ChecksNotApplicable is what the input path cannot run whatever was asked: METADATA on --stdin,
	// which has no file for the metadata extractors to read. Omitted when empty, which it is for files.
	ChecksNotApplicable []string `json:"checks_not_applicable,omitempty" yaml:"checks_not_applicable,omitempty"`

	// ConfidenceLevels is the bands the report shows, in high, medium, low order.
	ConfidenceLevels []string `json:"confidence_levels" yaml:"confidence_levels"`

	// Profile is the profile the run was under, omitted when none was.
	Profile *ScanProfile `json:"profile,omitempty" yaml:"profile,omitempty"`

	// Config says which kind of configuration governed the run. Never its path (#715) or contents.
	Config ScanConfigSource `json:"config" yaml:"config"`

	// Suppressions counts the rules that were in force.
	Suppressions ScanSuppressions `json:"suppressions" yaml:"suppressions"`

	// DisabledDetectionTypes is what the configured validators report config switched off. It is
	// carried here for the formats that have no stats block (junit, gitlab-sast, text) and is NOT
	// serialised: json and yaml already carry it as stats.disabled_detection_types, and two copies of
	// one fact in one document is how a report comes to disagree with itself.
	DisabledDetectionTypes map[string][]string `json:"-" yaml:"-"`
}

// ScanTool names the build that wrote a report.
type ScanTool struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
	Commit  string `json:"commit" yaml:"commit"`
}

// ScanProfile is the profile a run was under and what selected it.
type ScanProfile struct {
	Name string `json:"name" yaml:"name"`
	// SelectedBy is ProfileSelectedByFlag or ProfileSelectedByPrecommit.
	SelectedBy string `json:"selected_by" yaml:"selected_by"`
}

// The two ways a profile is selected. The name alone does not say what ran: a config can redefine the
// precommit profile, which is why ChecksRun is reported beside it.
const (
	ProfileSelectedByFlag      = "--profile"
	ProfileSelectedByPrecommit = "pre-commit mode"
)

// ScanConfigSource is which kind of configuration governed a run.
type ScanConfigSource struct {
	// Source is one of the ConfigSource* values.
	Source string `json:"source" yaml:"source"`
	// Name is the file's base name, only for a working-directory config, and only when it is one of
	// the fixed names discovery looks for. A path would leak the checkout layout (#715).
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// The kinds of configuration source.
const (
	ConfigSourceBuiltin          = "built-in"
	ConfigSourceExplicit         = "explicit"
	ConfigSourceWorkingDirectory = "working-directory"
	ConfigSourceUserConfigDir    = "user-config-dir"
)

// ScanSuppressions describes the suppression rules a run applied.
type ScanSuppressions struct {
	// RulesEnabled counts the enabled, unexpired, applied rules loaded for the run.
	RulesEnabled int `json:"rules_enabled" yaml:"rules_enabled"`
}

// ScopeInputs is what a caller knows about a run, for NewScanScope.
type ScopeInputs struct {
	// ChecksRun is the check names of the validator set the detector was given, in any order.
	ChecksRun []string
	// AllChecks is every known check name (core.CheckNames); the not-run list is derived from it, so
	// adding a validator needs no change here.
	AllChecks []string
	// ChecksNotApplicable is what the input path cannot run, in any order.
	ChecksNotApplicable []string
	// ConfidenceLevel is the parsed display filter, FormatterOptions.ConfidenceLevel.
	ConfidenceLevel map[string]bool
	// DisabledDetectionTypes is what the configured validators report config switched off.
	DisabledDetectionTypes map[string][]string
	// Profile is the active profile, nil for none.
	Profile *ScanProfile
	// Config is the configuration source, see ConfigSourceOf.
	Config ScanConfigSource
	// SuppressionRulesEnabled counts the rules in force.
	SuppressionRulesEnabled int
}

// confidenceBands is the display order of the bands, which is also the order ConfidenceLevels uses.
var confidenceBands = []string{"high", "medium", "low"}

// NewScanScope returns the scope of a NARROWED run, and nil for one that ran in full.
//
// Narrowed means a config, a profile or a flag switched something off that a full scan reports: a
// check did not run, a confidence band is hidden, or a detection sub-type was disabled. A check the
// input path cannot run (METADATA on --stdin) is not narrowing; it is reported only when something
// else was.
//
// Suppression is not narrowing either: a suppressed finding was detected and is counted in
// stats.suppressed, while a check that did not run could not have produced one.
func NewScanScope(in ScopeInputs) *ScanScope {
	run := sortedUnique(in.ChecksRun)
	notApplicable := minus(sortedUnique(in.ChecksNotApplicable), run)
	notRun := minus(minus(sortedUnique(in.AllChecks), run), notApplicable)

	levels := make([]string, 0, len(confidenceBands))
	for _, band := range confidenceBands {
		if in.ConfidenceLevel[band] {
			levels = append(levels, band)
		}
	}

	if len(notRun) == 0 && len(levels) == len(confidenceBands) && !anyDisabled(in.DisabledDetectionTypes) {
		return nil
	}

	scope := &ScanScope{
		Tool: &ScanTool{
			Name:    "ferret-scan",
			Version: version.Short(),
			Commit:  version.ReportCommit(),
		},
		ChecksRun:              run,
		ChecksNotRun:           notRun,
		ConfidenceLevels:       levels,
		Config:                 in.Config,
		Suppressions:           ScanSuppressions{RulesEnabled: in.SuppressionRulesEnabled},
		DisabledDetectionTypes: sortedDisabled(in.DisabledDetectionTypes),
	}
	if len(notApplicable) > 0 {
		scope.ChecksNotApplicable = notApplicable
	}
	if in.Profile != nil && in.Profile.Name != "" {
		p := *in.Profile
		scope.Profile = &p
	}
	if scope.Config.Source == "" {
		scope.Config.Source = ConfigSourceBuiltin
	}
	return scope
}

// discoveredConfigNames are the names config.FindConfigFile looks for in the working directory. A
// working-directory config's base name is reported only when it is one of these, so the report can
// never carry a name the operator chose; TestConfigSourceNamesTrackDiscovery fails if the two drift.
var discoveredConfigNames = map[string]bool{
	"config.yaml":       true,
	"ferret.yaml":       true,
	"ferret.yml":        true,
	".ferret-scan.yaml": true,
	".ferret-scan.yml":  true,
}

// ConfigSourceOf classifies the configuration that governed a run.
//
// sourcePath is config.Config.SourcePath ("" for the built-in configuration), explicit says --config
// named it, and cwd is the working directory. The working-directory test is paths.RelInside, the same
// predicate the CLI's provenance note uses, so the report and the note cannot disagree about which
// configs were discovered beside the scanned content.
func ConfigSourceOf(sourcePath string, explicit bool, cwd string) ScanConfigSource {
	switch {
	case sourcePath == "":
		return ScanConfigSource{Source: ConfigSourceBuiltin}
	case explicit:
		return ScanConfigSource{Source: ConfigSourceExplicit}
	}
	if rel, inside := paths.RelInside(cwd, sourcePath); inside {
		src := ScanConfigSource{Source: ConfigSourceWorkingDirectory}
		if rel == filepath.Base(rel) && discoveredConfigNames[rel] {
			src.Name = rel
		}
		return src
	}
	return ScanConfigSource{Source: ConfigSourceUserConfigDir}
}

// DisabledTypePairs flattens the disabled sub-types to sorted VALIDATOR:sub-type pairs, the form the
// formats without a nested structure use (junit, text).
func (s *ScanScope) DisabledTypePairs() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, name := range sortedMapKeys(s.DisabledDetectionTypes) {
		for _, sub := range s.DisabledDetectionTypes[name] {
			out = append(out, name+":"+sub)
		}
	}
	return out
}

// TotalChecks is the number of checks the scope accounts for: run, not run and not applicable.
func (s *ScanScope) TotalChecks() int {
	if s == nil {
		return 0
	}
	return len(s.ChecksRun) + len(s.ChecksNotRun) + len(s.ChecksNotApplicable)
}

// HiddenConfidenceLevels is the bands the report does NOT show, in display order.
func (s *ScanScope) HiddenConfidenceLevels() []string {
	if s == nil {
		return nil
	}
	shown := make(map[string]bool, len(s.ConfidenceLevels))
	for _, l := range s.ConfidenceLevels {
		shown[l] = true
	}
	var hidden []string
	for _, band := range confidenceBands {
		if !shown[band] {
			hidden = append(hidden, band)
		}
	}
	return hidden
}

// TextLine is the one-line human summary of the scope, for the text report.
//
// It lists whichever of the run and not-run checks is shorter, so `--checks SSN` reads
// "Scope: ran 1 of 19 checks (SSN)" and the pre-commit set reads "ran 6 of 19 checks (CREDIT_CARD,
// ...)" rather than thirteen names, then only the clauses that apply. The total comes from the scope,
// which takes it from core.CheckNames, so no count is hard-coded.
func (s *ScanScope) TextLine() string {
	if s == nil {
		return ""
	}
	// "ran 6 of 19 checks", never "6 of 19 checks run": the report is scanned too, and "19 checks run"
	// reads as a street address ("Run" is a USPS street suffix), US_STREET_ADDRESS LOW 30 when measured.
	var b strings.Builder
	b.WriteString("Scope: ran " + strconv.Itoa(len(s.ChecksRun)) + " of " + strconv.Itoa(s.TotalChecks()) + " checks")
	switch {
	case len(s.ChecksNotRun) == 0:
		// Every applicable check ran; the narrowing is in a clause below.
	case len(s.ChecksRun) == 0:
		b.WriteString(" (none)")
	case len(s.ChecksRun) <= len(s.ChecksNotRun):
		b.WriteString(" (" + strings.Join(s.ChecksRun, ", ") + ")")
	default:
		b.WriteString(" (not run: " + strings.Join(s.ChecksNotRun, ", ") + ")")
	}
	if len(s.ChecksNotApplicable) > 0 {
		b.WriteString("; not applicable to this input: " + strings.Join(s.ChecksNotApplicable, ", "))
	}
	if len(s.ConfidenceLevels) != len(confidenceBands) {
		shown := "none"
		if len(s.ConfidenceLevels) > 0 {
			shown = strings.Join(s.ConfidenceLevels, ", ")
		}
		b.WriteString("; confidence shown: " + shown)
	}
	if s.Profile != nil {
		b.WriteString("; profile: " + s.Profile.Name + " (" + s.Profile.SelectedBy + ")")
	}
	if pairs := s.DisabledTypePairs(); len(pairs) > 0 {
		b.WriteString("; disabled sub-types: " + strings.Join(pairs, ", "))
	}
	return b.String()
}

func anyDisabled(m map[string][]string) bool {
	for _, v := range m {
		if len(v) > 0 {
			return true
		}
	}
	return false
}

// sortedDisabled copies the map with each list sorted, dropping empty entries, or returns nil.
func sortedDisabled(m map[string][]string) map[string][]string {
	if !anyDisabled(m) {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		if len(v) == 0 {
			continue
		}
		out[k] = sortedUnique(v)
	}
	return out
}

// sortedUnique returns a sorted, de-duplicated copy without empty names, never nil.
func sortedUnique(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// minus returns the members of a (sorted) not in b, never nil.
func minus(a, b []string) []string {
	drop := make(map[string]bool, len(b))
	for _, s := range b {
		drop[s] = true
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if !drop[s] {
			out = append(out, s)
		}
	}
	return out
}

func sortedMapKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
