// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/tools/changelogfrag"
)

// Fragment is one parsed file under changelog.d/.
type Fragment struct {
	Name    string // base name, e.g. 0765-secrets-line-precheck-veto.md
	Section changelogfrag.Section
}

// Render returns the lines of the release section headed `## [tag] - date`: every canonical heading
// that has a bullet, in changelogfrag.Headings order, each followed by a blank line, its bullets
// back to back and a blank line. Within a heading the old-style bullets from under [Unreleased]
// come first, in the order CHANGELOG.md held them, then the fragments', in file-name order. Every
// bullet line is copied as it is: nothing is reflowed, merged or deduplicated.
func Render(tag, date string, legacy []changelogfrag.Section, frags []Fragment) []string {
	byHeading := make([][]changelogfrag.Bullet, len(changelogfrag.Headings))
	add := func(s changelogfrag.Section) {
		i := changelogfrag.HeadingIndex(s.Heading)
		if i < 0 {
			// Sections come from the parser, which admits canonical headings only; anything else
			// here is a programming error, and dropping its bullets would lose release notes.
			panic(fmt.Sprintf("changelogrender: non-canonical heading %q reached Render", s.Heading))
		}
		byHeading[i] = append(byHeading[i], s.Bullets...)
	}
	for _, s := range legacy {
		add(s)
	}
	sorted := append([]Fragment(nil), frags...)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].Name < sorted[b].Name })
	for _, f := range sorted {
		add(f.Section)
	}

	out := []string{fmt.Sprintf("## [%s] - %s", tag, date), ""}
	for i, h := range changelogfrag.Headings {
		if len(byHeading[i]) == 0 {
			continue
		}
		out = append(out, h, "")
		for _, b := range byHeading[i] {
			out = append(out, b...)
		}
		out = append(out, "")
	}
	return out
}

var (
	errAlreadyPromoted = errors.New("already promoted")
	errNothingToRender = errors.New("nothing to render")
)

// collect reads what a release would promote out of CHANGELOG.md: the [Unreleased] block and its
// old-style entries, if any.
func collect(lines []string) (changelogfrag.Unreleased, []changelogfrag.Section, error) {
	u, err := changelogfrag.FindUnreleased(lines)
	if err != nil {
		return u, nil, err
	}
	legacy, err := changelogfrag.Legacy(lines, u)
	if err != nil {
		return u, nil, fmt.Errorf("old-style entries under [Unreleased]: %w", err)
	}
	return u, legacy, nil
}

// promotion is the result of cutting a release into CHANGELOG.md.
type promotion struct {
	lines       []string // the whole new file
	section     []string // the inserted release section, as Render returned it
	legacyLines int      // lines removed from under [Unreleased]
}

// promote inserts the release section for tag at the [Unreleased] block's insertion point: after
// the heading and its prose (the pointer to changelog.d/, kept as it is), before the next release
// heading, in place of any old-style entries, which the section now carries. Every line outside
// the removed entries is kept, in order; the new file has exactly
// len(lines) - legacyLines + len(section) lines, which scripts/promote-changelog.sh verifies on its
// own before it writes anything.
func promote(lines []string, frags []Fragment, tag, date string) (promotion, error) {
	for _, l := range lines {
		if strings.HasPrefix(l, "## ["+tag+"]") {
			return promotion{}, errAlreadyPromoted
		}
	}
	u, legacy, err := collect(lines)
	if err != nil {
		return promotion{}, err
	}
	if len(legacy) == 0 && len(frags) == 0 {
		return promotion{}, errNothingToRender
	}
	sec := Render(tag, date, legacy, frags)
	out := make([]string, 0, len(lines)-(u.End-u.LegacyStart)+len(sec))
	out = append(out, lines[:u.LegacyStart]...)
	out = append(out, sec...)
	out = append(out, lines[u.End:]...)
	return promotion{lines: out, section: sec, legacyLines: u.End - u.LegacyStart}, nil
}

// splitLines splits file content into lines without their newline characters, and reports whether
// the content ended with one, so joinLines can give back the same bytes.
func splitLines(b []byte) ([]string, bool) {
	s := string(b)
	if s == "" {
		return nil, false
	}
	if strings.HasSuffix(s, "\n") {
		return strings.Split(s[:len(s)-1], "\n"), true
	}
	return strings.Split(s, "\n"), false
}

func joinLines(lines []string, finalNewline bool) []byte {
	s := strings.Join(lines, "\n")
	if finalNewline && len(lines) > 0 {
		s += "\n"
	}
	return []byte(s)
}
