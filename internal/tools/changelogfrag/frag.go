// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package changelogfrag is the release-note fragment format (#821): one file per pull request under
// changelog.d/, rendered into CHANGELOG.md when a release tag is pushed.
//
// WHY FILES. Entries used to be written under `## [Unreleased]` in CHANGELOG.md itself. Every PR
// edited the same few lines there, so any two PRs open at once conflicted when the second merged,
// and `merge=union` cannot help because GitHub's merge ignores custom merge drivers. Two PRs that
// each add a file of their own never conflict.
//
// WHY THIS GRAMMAR. A fragment is the old entry moved, not rewritten: a canonical `### ` heading, a
// blank line, and `- ` bullets whose lines are copied into CHANGELOG.md byte for byte at release.
// It is strict because the release-time renderer must never guess. internal/tools/changelogcheck
// runs this parser on every fragment a PR adds or edits, so a file the release would refuse fails
// the PR, while its author is still looking, instead of the promotion after the tag is public.
//
// Two programs use it: internal/tools/changelogrender at release time and
// internal/tools/changelogcheck at PR time. Keeping the grammar in one place means they cannot
// disagree about it.
package changelogfrag

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Dir is the fragment directory, relative to the repository root, and Readme the only file in it
// that is not a fragment.
const (
	Dir    = "changelog.d"
	Readme = "README.md"
)

// Headings are the subsection headings a fragment may open with, character for character, in the
// order a release section lists them.
var Headings = []string{
	"### ⚠️ Breaking Changes",
	"### 🔒 Security",
	"### 🚀 Features",
	"### 🐛 Bug Fixes",
	"### ⚡ Performance",
	"### 📚 Documentation",
	"### 🛠 Build System",
	"### 📦 Code Refactoring",
	"### ✅ Tests",
	"### 🔨 Internal",
}

// HeadingIndex returns h's position in Headings, or -1 when h is not one of them.
func HeadingIndex(h string) int {
	for i, c := range Headings {
		if h == c {
			return i
		}
	}
	return -1
}

var namePattern = regexp.MustCompile(`^\d{4}-[a-z0-9]+(-[a-z0-9]+)*\.md$`)

// NameRule is namePattern in words, for the people who have to satisfy it.
const NameRule = "NNNN-slug.md, where NNNN is the issue number zero-padded to four digits and the " +
	"slug is lowercase kebab-case (letters, digits, single hyphens), e.g. " +
	"changelog.d/0800-otp-lowercase-word-not-base32.md"

// ValidName reports whether a base name is a fragment's.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// Format is the whole grammar in one sentence, for error messages.
func Format() string {
	return "a fragment is one heading copied exactly from this list: " + strings.Join(Headings, ", ") +
		"; then one blank line; then one or more bullets, each starting \"- \" at column 0, with " +
		"continuation lines indented two spaces and no blank line anywhere in the list; then the end " +
		"of the file, after a single newline"
}

// A Bullet is one entry: its `- ` line and the continuation lines after it, verbatim.
type Bullet []string

// A Section is one heading and its bullets, in file order.
type Section struct {
	Heading string
	Bullets []Bullet
}

// Error is a grammar violation. Line is 1-based, and 0 when the problem is the file as a whole.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

// ParseFragment parses one fragment file: exactly one Section, heading on line 1, ending with a
// single newline.
func ParseFragment(content []byte) (Section, error) {
	switch {
	case len(content) == 0:
		return Section{}, &Error{Msg: "the file is empty"}
	case !utf8.Valid(content):
		return Section{}, &Error{Msg: "the file is not valid UTF-8"}
	case bytes.HasPrefix(content, []byte("\ufeff")):
		return Section{}, &Error{Line: 1, Msg: "the file starts with a byte-order mark; save it without one"}
	case content[len(content)-1] != '\n':
		return Section{}, &Error{Msg: "the file must end with a newline"}
	}
	secs, err := parse(strings.Split(string(content[:len(content)-1]), "\n"), 0, true)
	if err != nil {
		return Section{}, err
	}
	return secs[0], nil
}

// ParseSections parses old-style entries: what pull requests merged under `## [Unreleased]` in
// CHANGELOG.md before fragments existed, from the first heading to the next release heading. They
// follow the fragment grammar, except that several sections may follow one another, separated by
// blank lines, and blank lines may trail. firstLine is the 1-based file line of lines[0], so an
// error names the line a person has to fix.
func ParseSections(lines []string, firstLine int) ([]Section, error) {
	return parse(lines, firstLine-1, false)
}

const secondHeading = "a second heading; a fragment holds one, so put this entry in a fragment of its own"

func parse(lines []string, offset int, fragment bool) ([]Section, error) {
	at := func(i int, format string, args ...any) error {
		return &Error{Line: offset + i + 1, Msg: fmt.Sprintf(format, args...)}
	}
	if len(lines) == 0 {
		return nil, &Error{Msg: "nothing to parse"}
	}
	for i, l := range lines {
		if strings.ContainsRune(l, '\r') {
			return nil, at(i, "carriage return in the line; save the file with LF line endings")
		}
	}
	list := strings.Join(Headings, ", ")
	var out []Section
	i := 0
	for {
		// lines[i] must be a heading.
		h := lines[i]
		switch {
		case HeadingIndex(h) >= 0:
		case h == "":
			return nil, at(i, "a blank line before the heading; the first line must be the heading, one of: %s", list)
		case len(out) == 0 && !strings.HasPrefix(h, "#"):
			return nil, at(i, "%q comes before any heading; the first line must be one of: %s", short(h), list)
		default:
			return nil, at(i, "%q is not one of the canonical headings, which are: %s", short(h), list)
		}
		if fragment && len(out) == 1 {
			return nil, at(i, secondHeading)
		}
		sec := Section{Heading: h}

		// Exactly one blank line, then the first bullet.
		switch {
		case i+1 == len(lines):
			return nil, at(i, "%q has no bullet under it", h)
		case lines[i+1] != "":
			return nil, at(i+1, "the heading must be followed by one blank line, then its first bullet")
		case i+2 == len(lines):
			return nil, at(i, "%q has no bullet under it", h)
		case lines[i+2] == "":
			return nil, at(i+2, "one blank line, not more, goes between the heading and its first bullet")
		case lines[i+2] == "-" || (strings.HasPrefix(lines[i+2], "- ") && !isBullet(lines[i+2])):
			return nil, at(i+2, "an empty bullet")
		case !isBullet(lines[i+2]):
			return nil, at(i+2, "the first line under a heading must be a bullet, starting \"- \" at column 0")
		}
		i += 2

		// Bullets back to back, each with its continuation lines.
		for ; i < len(lines) && (isBullet(lines[i]) || isContinuation(lines[i])); i++ {
			if isBullet(lines[i]) {
				sec.Bullets = append(sec.Bullets, Bullet{lines[i]})
				continue
			}
			last := len(sec.Bullets) - 1
			sec.Bullets[last] = append(sec.Bullets[last], lines[i])
		}
		out = append(out, sec)
		if i == len(lines) {
			return out, nil
		}

		// Only a blank line may end the list.
		switch l := lines[i]; {
		case l == "":
		case strings.TrimSpace(l) == "":
			return nil, at(i, "a line of only whitespace; make it empty or delete it")
		case l == "-" || strings.HasPrefix(l, "- "):
			return nil, at(i, "an empty bullet")
		case strings.HasPrefix(l, "#") && fragment:
			return nil, at(i, secondHeading)
		case strings.HasPrefix(l, "#"):
			return nil, at(i, "a heading must follow a blank line")
		default:
			return nil, at(i, "%q is neither a bullet (\"- \" at column 0) nor a continuation line (indented two spaces)", short(l))
		}
		j := i
		for j < len(lines) && lines[j] == "" {
			j++
		}
		switch {
		case j == len(lines) && fragment:
			return nil, at(i, "a blank line at the end of the file; it must end with a single newline")
		case j == len(lines):
			return out, nil
		case isBullet(lines[j]) || isContinuation(lines[j]):
			return nil, at(i, "a blank line inside the bullet list; bullets go back to back, and a bullet's continuation lines follow it with no blank line")
		case fragment && strings.HasPrefix(lines[j], "#"):
			return nil, at(j, secondHeading)
		case fragment:
			return nil, at(j, "%q after the bullets; nothing else goes in a fragment", short(lines[j]))
		case !strings.HasPrefix(lines[j], "#"):
			return nil, at(j, "%q after the bullets; old-style entries are headings and bullets only", short(lines[j]))
		}
		i = j
	}
}

// isBullet: "- " at column 0 with something after it.
func isBullet(l string) bool { return strings.HasPrefix(l, "- ") && strings.TrimSpace(l[2:]) != "" }

// isContinuation: indented at least two spaces, with something after the indentation.
func isContinuation(l string) bool { return strings.HasPrefix(l, "  ") && strings.TrimSpace(l) != "" }

func short(s string) string {
	if r := []rune(s); len(r) > 60 {
		return string(r[:57]) + "..."
	}
	return s
}

var orderedItem = regexp.MustCompile(`^[0-9]+[.)]( |$)`)

// EntryShaped reports whether a line under `## [Unreleased]` reads as part of a changelog entry: a
// Markdown heading, a list item, or an indented line. Prose does not, so the paragraph that points
// readers at changelog.d/ can live there. scripts/promote-changelog.sh applies the same predicate
// in awk; the two must stay in step, and the script's line-count guard refuses a promotion where
// they disagree.
func EntryShaped(l string) bool {
	switch {
	case strings.HasPrefix(l, "#"):
		return true
	case l == "-" || l == "*" || l == "+":
		return true
	case strings.HasPrefix(l, "- ") || strings.HasPrefix(l, "* ") || strings.HasPrefix(l, "+ "):
		return true
	case orderedItem.MatchString(l):
		return true
	case l != "" && (l[0] == ' ' || l[0] == '\t'):
		return strings.TrimLeft(l, " \t") != ""
	}
	return false
}

// ErrNoAnchor is a CHANGELOG.md with no `## [Unreleased]` line.
var ErrNoAnchor = errors.New("CHANGELOG.md has no '## [Unreleased]' line, which must match exactly")

// Unreleased is the `## [Unreleased]` block of CHANGELOG.md, as 0-based indices into its lines:
// the heading, the first entry-shaped line after it (End when there is none) and the next `## [`
// heading (len(lines) when there is none). Lines between Heading and LegacyStart are prose about
// the section, which stays where it is; lines from LegacyStart to End are old-style entries, which
// a release promotes. A release's section is inserted at LegacyStart.
type Unreleased struct {
	Heading, LegacyStart, End int
}

// FindUnreleased locates the block and checks that a release section can be inserted in it. The
// anchor must match exactly, as scripts/promote-changelog.sh requires (`^## \[Unreleased\]$`), and
// the line before the insertion point must be blank, so the inserted heading never runs into the
// text above it. On a non-nil error other than ErrNoAnchor the returned block is still located.
func FindUnreleased(lines []string) (Unreleased, error) {
	u := Unreleased{Heading: -1, End: len(lines)}
	for i, l := range lines {
		if l != "## [Unreleased]" {
			continue
		}
		if u.Heading >= 0 {
			return Unreleased{}, fmt.Errorf("CHANGELOG.md has two '## [Unreleased]' lines (%d and %d); a release cannot tell which to promote below", u.Heading+1, i+1)
		}
		u.Heading = i
	}
	if u.Heading < 0 {
		return Unreleased{}, ErrNoAnchor
	}
	for j := u.Heading + 1; j < len(lines); j++ {
		if strings.HasPrefix(lines[j], "## [") {
			u.End = j
			break
		}
	}
	u.LegacyStart = u.End
	for j := u.Heading + 1; j < u.End; j++ {
		if EntryShaped(lines[j]) {
			u.LegacyStart = j
			break
		}
	}
	switch before := u.LegacyStart - 1; {
	case before == u.Heading:
		return u, fmt.Errorf("line %d: a blank line must follow '## [Unreleased]'; a release inserts its section below it", u.Heading+1)
	case lines[before] != "":
		return u, fmt.Errorf("line %d must be blank: a release inserts its section right after it, below the [Unreleased] heading and its prose", before+1)
	}
	return u, nil
}

// Legacy parses the old-style entries in u, which may be none.
func Legacy(lines []string, u Unreleased) ([]Section, error) {
	if u.LegacyStart == u.End {
		return nil, nil
	}
	return ParseSections(lines[u.LegacyStart:u.End], u.LegacyStart+1)
}
