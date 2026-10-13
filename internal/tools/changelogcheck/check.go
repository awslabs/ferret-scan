// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Command changelogcheck decides, for one pull request, whether CHANGELOG.md must change and
// whether the change landed under [Unreleased].
//
// It exists because the release-time promotion (scripts/promote-changelog.sh) only stamps what is
// already written. v2.5.3 shipped four PRs that changed the binary — a secrets false-positive fix,
// a secrets recall widening, a dependency fix, a TLD-snapshot refresh — and none of them added an
// entry, because nothing asked. The promotion then found [Unreleased] empty and, correctly, did
// nothing. The gap is not at release time; it is at PR time, where the author still knows what
// changed.
//
// WHAT "MUST CHANGE" MEANS. A PR needs an entry when it changes what a release ships: code or data
// compiled into the binaries or the pkg/ library — derived from the import graph (`go list -deps
// ./cmd/... ./pkg/...`), not from a path list, so a new package is covered the day it is imported
// and a test-support package (perfguard, goldencorpus) never is — plus the build inputs (go.mod,
// .go-version), the artifacts published at the same tag that are not Go (the pre-commit hook
// definition and the PyPI wrapper), and any title marked breaking.
//
// WHERE IT MUST LAND. The added lines must include an entry under [Unreleased], checked on GitHub's
// merge result. Release sections repeat the same subsection headings, so an entry placed beside the
// first matching heading can land in an old release. Replayed over the 129 PRs merged 2026-08-28 to
// 2026-10-06, 82 required an entry and 67 had one under [Unreleased]; 4 had none at all, and 12
// entries — 11 of them a PR's only entry — had landed in releases from months earlier.
//
// AFTER THE MERGE. A PR-time result goes stale when a release is promoted while the PR is open: its
// check ran against the old layout, and nothing re-runs it when main moves, so its entry can merge
// into the section the release just promoted. EvaluatePostMerge catches that on the push to main,
// by comparing where the PR's own branch put the entry with where the merge put it.
package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// optOutLabel is the explicit escape hatch. Explicit on purpose: silence was the failure, so the
// alternative to writing an entry is a visible decision on the PR, not the absence of one.
const optOutLabel = "no-changelog"

// breakingTitle matches a conventional-commit subject marked breaking, scoped or not.
var breakingTitle = regexp.MustCompile(`^[a-z]+(\([^)]*\))?!:`)

// rootDirs are the import roots of everything this repository publishes as Go: the binaries under
// cmd/ and the importable library under pkg/. main.go derives its `go list` patterns from these.
var rootDirs = []string{"cmd", "pkg"}

// releasedFiles are repository files outside the Go graph that still change what a release ships:
// the module's requirements and the toolchain version (a toolchain bump is how stdlib CVE fixes
// reach the binary); the pre-commit hook definitions and the hook's install stub, which every
// pre-commit user pins by tag; and the PyPI wrapper's packaging, published on every tag. go.sum is
// deliberately absent — it records checksums, and a go.sum-only change builds the identical binary.
var releasedFiles = map[string]bool{
	"go.mod":                                true,
	".go-version":                           true,
	".pre-commit-hooks.yaml":                true,
	"pyproject.toml":                        true,
	"python-package/.pre-commit-hooks.yaml": true,
	"python-package/pyproject.toml":         true,
	"python-package/setup.py":               true,
	"python-package/MANIFEST.in":            true,
}

// pypiModule is the PyPI wrapper's import package; its non-test .py files are the `ferret-scan`
// entry point every pip and pre-commit user runs.
const pypiModule = "python-package/ferret_scan/"

// ShippedSet answers whether a repository-relative path is compiled into, embedded in, or published
// with a release.
type ShippedSet struct {
	dirs  map[string]bool // directories of shipped packages
	files map[string]bool // embedded files, repository-relative
}

// NewShippedSet builds the set from shipped package directories and every embedded file, both
// repository-relative and slash-separated.
func NewShippedSet(dirs, embedded []string) ShippedSet {
	s := ShippedSet{dirs: map[string]bool{}, files: map[string]bool{}}
	for _, d := range dirs {
		s.dirs[path.Clean(d)] = true
	}
	for _, f := range embedded {
		s.files[path.Clean(f)] = true
	}
	return s
}

// Contains reports whether p ships. Every non-test .go file in a shipped package's directory counts
// regardless of build tags — a windows-only file ships on windows — plus embedded files and
// releasedFiles.
//
// So does any non-test .go file under a root, shipped or not. The import graph is computed on the
// merge result, so a PR that DELETES pkg/scan, or moves it under internal/, leaves files that match
// no shipped directory — and removing a public package is the most breaking change a v2 module can
// make. Under the roots, every buildable file is part of some binary or of the library.
func (s ShippedSet) Contains(p string) bool {
	p = path.Clean(p)
	if releasedFiles[p] || s.files[p] {
		return true
	}
	base := path.Base(p)
	if strings.HasPrefix(p, pypiModule) {
		return strings.HasSuffix(base, ".py") && !strings.HasPrefix(base, "test_") && !ignoredByGo(p)
	}
	if !strings.HasSuffix(base, ".go") || strings.HasSuffix(base, "_test.go") || ignoredByGo(p) {
		return false
	}
	if s.dirs[path.Dir(p)] {
		return true
	}
	for _, r := range rootDirs {
		if strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// ignoredByGo reports a path the go command never builds: one under testdata/, or under a directory
// whose name starts with "." or "_".
func ignoredByGo(p string) bool {
	segs := strings.Split(path.Dir(p), "/")
	for _, s := range segs {
		if s == "testdata" || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "_") {
			return true
		}
	}
	return false
}

// Len is the number of shipped package directories, for non-vacuity checks.
func (s ShippedSet) Len() int { return len(s.dirs) }

// Input is everything one decision needs. It carries no I/O, so every rule is unit-testable.
type Input struct {
	Title        string
	Author       string
	Labels       []string
	ChangedFiles []string
	Shipped      ShippedSet

	// ChangelogAfter is CHANGELOG.md on the merge result, split into lines; nil when the PR does
	// not touch it. ChangelogAdded holds the 1-based line numbers the PR added in that file.
	ChangelogAfter []string
	ChangelogAdded []int
}

// Result is the decision plus the human-readable reasons behind it.
type Result struct {
	Required bool
	Pass     bool
	Messages []string // why it passed or failed, shown on the PR
	Warnings []string // non-blocking
}

// Evaluate applies the rules.
func Evaluate(in Input) Result {
	var r Result

	if isBot(in.Author) {
		r.Pass = true
		r.Messages = append(r.Messages, fmt.Sprintf("exempt: %s is a dependency bot; a dependency bump that "+
			"needs code changes arrives as a follow-up PR, which is checked", in.Author))
		return r
	}

	// Placement is analysed for every PR that touches the file, required or not: a docs PR that files
	// its entry under an old release is the same defect, and deserves the same warning.
	pl := place(in.ChangelogAfter, in.ChangelogAdded)
	if pl.outside > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d added CHANGELOG line(s) sit outside [Unreleased] (under %s) — "+
			"fine for a deliberate history correction, wrong for a new entry", pl.outside, strings.Join(pl.outsideSections, ", ")))
	}

	var shipped []string
	for _, f := range in.ChangedFiles {
		if in.Shipped.Contains(f) {
			shipped = append(shipped, f)
		}
	}
	sort.Strings(shipped)
	breaking := breakingTitle.MatchString(in.Title)
	r.Required = len(shipped) > 0 || breaking

	if !r.Required {
		r.Pass = true
		r.Messages = append(r.Messages, "no entry required: this PR changes nothing compiled into, embedded "+
			"in or published with a release, and its title is not marked breaking")
		return r
	}

	why := ""
	if len(shipped) > 0 {
		show := shipped
		if len(show) > 5 {
			show = append(append([]string{}, show[:5]...), fmt.Sprintf("… %d more", len(shipped)-5))
		}
		why = "it changes what a release ships: " + strings.Join(show, ", ")
	}
	if breaking {
		if why != "" {
			why += "; and "
		}
		why += "its title is marked breaking"
	}

	if hasLabel(in.Labels, optOutLabel) {
		r.Pass = true
		r.Messages = append(r.Messages, fmt.Sprintf("an entry would be required (%s), but the PR carries "+
			"the %q label — recorded as a deliberate decision", why, optOutLabel))
		return r
	}

	if in.ChangelogAfter == nil {
		r.Messages = append(r.Messages, fmt.Sprintf("CHANGELOG.md needs an entry under [Unreleased] because %s. "+
			"Add one describing the user-visible change, or, if nothing user-visible changed, add the %q "+
			"label to the PR.", why, optOutLabel))
		return r
	}

	if !pl.found {
		r.Messages = append(r.Messages, "CHANGELOG.md has no '## [Unreleased]' heading on the merge result "+
			"(it must match exactly — scripts/promote-changelog.sh anchors on that line), so there is "+
			"nowhere valid for this PR's entry to go")
		return r
	}
	if pl.inside == 0 {
		r.Messages = append(r.Messages, fmt.Sprintf("CHANGELOG.md changed, but no entry was added under "+
			"[Unreleased] on the merge result (lines %d–%d); a subsection heading on its own is not an entry. "+
			"Release sections repeat the same subsection headings, so an entry placed beside the first match "+
			"can land in an old release; and a PR open across a release can merge into the section that "+
			"release just promoted. Move it under [Unreleased].", pl.start+1, pl.end-1))
		return r
	}
	r.Pass = true
	r.Messages = append(r.Messages, fmt.Sprintf("entry present under [Unreleased] (%d line(s)); required because %s",
		pl.inside, why))
	return r
}

// EvaluatePostMerge runs on the push to main, after a PR has merged. own is where the PR's branch put
// its additions (diffed against its merge-base with main), merged is where the merge put them. The
// one defect it reports is the stale anchor: an entry the branch filed under [Unreleased] that the
// merge filed under a released section, which happens when a release is promoted while the PR is
// open. A PR that deliberately adds to a released section — a backfill — files it there on its own
// branch too, so it does not match and is not reported.
func EvaluatePostMerge(own, merged placement) Result {
	if own.inside > 0 && merged.inside == 0 && merged.outside > 0 {
		return Result{Messages: []string{fmt.Sprintf("this PR's CHANGELOG entry was under [Unreleased] on its "+
			"own branch, but the merge put it under %s — a release was promoted while the PR was open, after "+
			"its check had passed. Move the entry under [Unreleased] in a follow-up PR, or it ships "+
			"unannounced in the next release.", strings.Join(merged.outsideSections, ", "))}}
	}
	return Result{Pass: true, Messages: []string{fmt.Sprintf("post-merge placement consistent "+
		"(branch: %d under [Unreleased], %d elsewhere; merged: %d under [Unreleased], %d elsewhere)",
		own.inside, own.outside, merged.inside, merged.outside)}}
}

// placement counts a change's added CHANGELOG entry lines inside and outside [Unreleased]. An
// entry line is non-blank and not a markdown heading: a PR that adds `### 🐛 Bug Fixes` under
// [Unreleased] and its bullet under an old release has added no entry where it counts.
type placement struct {
	found           bool // the file has an exact '## [Unreleased]' heading
	start, end      int  // its heading line and the next release heading (or len+1), 1-based
	inside, outside int
	outsideSections []string // the release headings the outside lines fall under, in file order
}

func place(lines []string, added []int) placement {
	var p placement
	if len(lines) == 0 {
		return p
	}
	p.start, p.end, p.found = unreleasedRange(lines)
	seen := map[string]bool{}
	for _, n := range added {
		if n < 1 || n > len(lines) {
			continue
		}
		l := strings.TrimSpace(lines[n-1])
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if p.found && n > p.start && n < p.end {
			p.inside++
			continue
		}
		p.outside++
		sec := "the file's preamble"
		for i := n - 1; i >= 0; i-- {
			if strings.HasPrefix(lines[i], "## ") {
				sec = "'" + strings.TrimSpace(lines[i]) + "'"
				break
			}
		}
		if !seen[sec] {
			seen[sec] = true
			p.outsideSections = append(p.outsideSections, sec)
		}
	}
	return p
}

// unreleasedRange returns the 1-based line of '## [Unreleased]' and of the next '## [' heading (or
// len+1). Lines strictly between them belong to [Unreleased]. The heading must match exactly, as
// scripts/promote-changelog.sh requires (`^## \[Unreleased\]$`): a heading this check accepted and
// the release-time promotion rejected would pass every PR and then fail the release.
func unreleasedRange(lines []string) (start, end int, found bool) {
	for i, l := range lines {
		if strings.TrimSuffix(l, "\r") == "## [Unreleased]" {
			start, found = i+1, true
			end = len(lines) + 1
			for j := i + 1; j < len(lines); j++ {
				if strings.HasPrefix(lines[j], "## [") {
					end = j + 1
					break
				}
			}
			return
		}
	}
	return 0, 0, false
}

func isBot(author string) bool {
	a := strings.ToLower(author)
	return a == "dependabot[bot]" || a == "app/dependabot" || a == "dependabot"
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if strings.EqualFold(strings.TrimSpace(l), want) {
			return true
		}
	}
	return false
}
