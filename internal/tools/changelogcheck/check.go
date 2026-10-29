// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Command changelogcheck decides, for one pull request, whether it must add a release-note
// fragment under changelog.d/, and whether what it did to changelog.d/ and CHANGELOG.md is
// something the release-time promotion will accept.
//
// It exists because the release-time promotion (scripts/promote-changelog.sh) only renders what is
// already written. v2.5.3 shipped four PRs that changed the binary — a secrets false-positive fix,
// a secrets recall widening, a dependency fix, a TLD-snapshot refresh — and none of them added an
// entry, because nothing asked. The promotion then found nothing to promote and, correctly, did
// nothing. The gap is not at release time; it is at PR time, where the author still knows what
// changed.
//
// WHAT "MUST ADD" MEANS. A PR needs a note when it changes what a release ships: code or data
// compiled into the binaries or the pkg/ library — derived from the import graph (`go list -deps
// ./cmd/... ./pkg/...`), not from a path list, so a new package is covered the day it is imported
// and a test-support package (perfguard, goldencorpus) never is — plus the build inputs (go.mod,
// .go-version), the artifacts published at the same tag that are not Go (the pre-commit hook
// definition and the PyPI wrapper), and any title marked breaking.
//
// WHAT IT MUST ADD. A new file under changelog.d/ in the fragment format of
// internal/tools/changelogfrag (changelog.d/README.md says it for people). Notes used to be written
// under `## [Unreleased]` in CHANGELOG.md, and every PR edited the same lines there, so any two PRs
// open at once conflicted when the second merged (#821). A PR that adds an entry-shaped line under
// [Unreleased] now fails whatever else it changes: that is the old habit, and the next PR to merge
// would conflict with it.
//
// WHAT IS CHECKED ON EVERY PR. Every fragment a PR adds or edits must parse, and when the PR
// touches CHANGELOG.md, its [Unreleased] block must stay one the promotion can insert a section
// below. Each would otherwise pass the PR and stop the release, after the tag is public. Neither
// the no-changelog label nor the dependabot exemption lifts these; they only lift the requirement.
//
// NO POST-MERGE MODE. Until #821 an `after-merge` job compared, on the push to main, where a PR's
// branch had put its entry with where the merge put it: a release promoted while the PR was open
// could carry the entry into the section that release had just promoted, by a clean three-way
// merge. Release sections repeat the same subsection headings, and replayed over the 129 PRs merged
// 2026-08-28 to 2026-10-06, 12 entries had landed in releases from months earlier. A fragment is a
// file of its own that no release moves and no heading can be mistaken for, so that failure no
// longer has a mechanism, and the mode went with it.
package main

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/tools/changelogfrag"
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

	// Fragments are the paths the PR added or modified under changelog.d/, with their content on
	// the merge result. Deletions are not listed: removing a fragment is how a PR withdraws a note.
	Fragments []FragmentChange

	// ChangelogAfter is CHANGELOG.md on the merge result, split into lines; nil when the PR does
	// not touch it. ChangelogAdded holds the 1-based line numbers the PR added in that file.
	ChangelogAfter []string
	ChangelogAdded []int
}

// FragmentChange is one added or modified path under changelog.d/.
type FragmentChange struct {
	Path    string // repository-relative, e.g. changelog.d/0800-otp-lowercase-word-not-base32.md
	Added   bool   // new in this PR, rather than an edit of a file already on the base
	Regular bool   // a regular file on the merge result, not a symlink or a submodule
	Content []byte // on the merge result
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
	var failures []string

	// Checked on every PR, whatever it changes and whoever opened it: each of these passes the PR
	// and then stops the release.
	var added []string
	for _, f := range in.Fragments {
		if msg := fragmentProblem(f); msg != "" {
			failures = append(failures, msg)
		} else if f.Added && f.Path != changelogfrag.Dir+"/"+changelogfrag.Readme {
			added = append(added, f.Path)
		}
	}
	if in.ChangelogAfter != nil {
		fs, ws := changelogProblems(in.ChangelogAfter, in.ChangelogAdded)
		failures = append(failures, fs...)
		r.Warnings = append(r.Warnings, ws...)
	}

	var shipped []string
	for _, f := range in.ChangedFiles {
		if in.Shipped.Contains(f) {
			shipped = append(shipped, f)
		}
	}
	sort.Strings(shipped)
	breaking := breakingTitle.MatchString(in.Title)
	r.Required = !isBot(in.Author) && (len(shipped) > 0 || breaking)

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

	var info string
	switch {
	case isBot(in.Author):
		info = fmt.Sprintf("exempt: %s is a dependency bot; a dependency bump that needs code changes "+
			"arrives as a follow-up PR, which is checked", in.Author)
	case !r.Required && len(added) > 0:
		info = fmt.Sprintf("no note was required (this PR changes nothing compiled into, embedded in or "+
			"published with a release, and its title is not marked breaking); the release renders %s anyway",
			strings.Join(added, ", "))
	case !r.Required:
		info = "no note required: this PR changes nothing compiled into, embedded in or published with a " +
			"release, and its title is not marked breaking"
	case hasLabel(in.Labels, optOutLabel):
		info = fmt.Sprintf("a release note would be required (%s), but the PR carries the %q label — "+
			"recorded as a deliberate decision", why, optOutLabel)
	case len(added) == 0:
		failures = append(failures, missingFragment(why, in.Fragments))
	default:
		info = fmt.Sprintf("release note present: %s; required because %s", strings.Join(added, ", "), why)
	}

	r.Pass = len(failures) == 0
	if r.Pass {
		r.Messages = []string{info}
	} else {
		r.Messages = failures
	}
	return r
}

// missingFragment says what to add, in full: the person reading it may never have seen a fragment.
func missingFragment(why string, edited []FragmentChange) string {
	msg := fmt.Sprintf("this PR needs a release note because %s. Add a new file under %s/, named %s, "+
		"holding the entry as it should read in CHANGELOG.md: %s. `make changelog-preview` shows it "+
		"rendered. If nothing user-visible changed, add the %q label to the PR instead.",
		why, changelogfrag.Dir, changelogfrag.NameRule, changelogfrag.Format(), optOutLabel)
	for _, f := range edited {
		if !f.Added && f.Path != changelogfrag.Dir+"/"+changelogfrag.Readme {
			return msg + fmt.Sprintf(" Editing %s does not count: that note belongs to the PR that added "+
				"it, and each PR adds its own.", f.Path)
		}
	}
	return msg
}

// fragmentProblem returns why the release would refuse f, or "" when it would render it.
func fragmentProblem(f FragmentChange) string {
	rel := strings.TrimPrefix(f.Path, changelogfrag.Dir+"/")
	switch {
	case rel == changelogfrag.Readme:
		return ""
	case strings.Contains(rel, "/"):
		return fmt.Sprintf("%s would stop the release: fragments live directly in %s/, and a "+
			"subdirectory is not read. Move it to %s/%s.", f.Path, changelogfrag.Dir, changelogfrag.Dir, path.Base(rel))
	case !changelogfrag.ValidName(rel):
		return fmt.Sprintf("%s would stop the release: %s/ holds fragments and its %s, nothing else, "+
			"and a fragment is named %s.", f.Path, changelogfrag.Dir, changelogfrag.Readme, changelogfrag.NameRule)
	case !f.Regular:
		return fmt.Sprintf("%s would stop the release: it is a symlink or a submodule, and the release "+
			"reads fragments as plain files.", f.Path)
	}
	if _, err := changelogfrag.ParseFragment(f.Content); err != nil {
		return fmt.Sprintf("%s would stop the release: %v. (%s.)", f.Path, err, changelogfrag.Format())
	}
	return ""
}

// changelogProblems applies the CHANGELOG.md rules to the merge result: the [Unreleased] block must
// stay one the promotion accepts, and no PR may add an entry under it. Lines added under released
// sections are a correction to a past release's notes, which is allowed, and only noted.
func changelogProblems(lines []string, added []int) (failures, warnings []string) {
	u, err := changelogfrag.FindUnreleased(lines)
	switch {
	case errors.Is(err, changelogfrag.ErrNoAnchor):
		failures = append(failures, "CHANGELOG.md has no '## [Unreleased]' line on the merge result (it must "+
			"match exactly — scripts/promote-changelog.sh inserts each release's section below that line), "+
			"so the release would refuse the file")
	case err != nil:
		failures = append(failures, "the release would refuse CHANGELOG.md on the merge result: "+err.Error())
	default:
		if _, err := changelogfrag.Legacy(lines, u); err != nil {
			failures = append(failures, "the old-style entries under [Unreleased] in CHANGELOG.md would stop "+
				"the release: "+err.Error())
		}
	}
	found := !errors.Is(err, changelogfrag.ErrNoAnchor)

	var entry, prose []int
	outside := 0
	var outsideSections []string
	seen := map[string]bool{}
	for _, n := range added {
		if n < 1 || n > len(lines) {
			continue
		}
		l := lines[n-1]
		if found && n-1 > u.Heading && n-1 < u.End {
			switch {
			case changelogfrag.EntryShaped(l):
				entry = append(entry, n)
			case strings.TrimSpace(l) != "":
				prose = append(prose, n)
			}
			continue
		}
		if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		outside++
		sec := "the file's preamble"
		for i := n - 1; i >= 0; i-- {
			if strings.HasPrefix(lines[i], "## ") {
				sec = "'" + strings.TrimSpace(lines[i]) + "'"
				break
			}
		}
		if !seen[sec] {
			seen[sec] = true
			outsideSections = append(outsideSections, sec)
		}
	}

	if len(entry) > 0 {
		failures = append(failures, fmt.Sprintf("this PR adds %s under '## [Unreleased]' in CHANGELOG.md "+
			"that read as a changelog entry. Release notes no longer go there: every PR edited those same "+
			"lines, so every two open PRs conflicted (#821). Write a fragment under %s/ instead — named %s, "+
			"and holding %s — and leave [Unreleased] as it is on main.",
			lineList(entry), changelogfrag.Dir, changelogfrag.NameRule, changelogfrag.Format()))
	}
	if len(prose) > 0 {
		warnings = append(warnings, fmt.Sprintf("this PR adds %s of prose under '## [Unreleased]' in "+
			"CHANGELOG.md. A release keeps that prose under the heading and never promotes it; a release "+
			"note belongs in a fragment under %s/.", lineList(prose), changelogfrag.Dir))
	}
	if outside > 0 {
		warnings = append(warnings, fmt.Sprintf("%d added CHANGELOG.md line(s) sit under %s — fine for a "+
			"correction to a past release's notes; a note for the next release belongs in %s/",
			outside, strings.Join(outsideSections, ", "), changelogfrag.Dir))
	}
	return failures, warnings
}

// lineList names 1-based line numbers compactly: "line 5", "lines 5–7, 9".
func lineList(ns []int) string {
	var parts []string
	for i := 0; i < len(ns); {
		j := i
		for j+1 < len(ns) && ns[j+1] == ns[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d–%d", ns[i], ns[j]))
		} else {
			parts = append(parts, fmt.Sprint(ns[i]))
		}
		i = j + 1
	}
	if len(ns) == 1 {
		return "line " + parts[0]
	}
	return fmt.Sprintf("%d lines (%s)", len(ns), strings.Join(parts, ", "))
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
