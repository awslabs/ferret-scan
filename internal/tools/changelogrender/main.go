// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Command changelogrender turns the release-note fragments under changelog.d/ into the section of
// CHANGELOG.md that a release adds (#821).
//
// Without -write it prints that section to stdout; `make changelog-preview` runs it with
// -tag vNEXT to show what the next release would say. With -write it promotes: the section goes
// into -changelog right below the `## [Unreleased]` heading and its prose, in place of any
// old-style entries still under it, which the section now carries. scripts/promote-changelog.sh is
// the release entry point. It runs this twice, printing and then writing a copy, refuses a result
// whose lines it cannot account for, and `git rm`s the fragments itself so the deletion is staged
// for the promote commit; -delete-fragments is for a run outside git.
//
// WHAT IT PRESERVES. Every bullet line is copied byte for byte from its fragment or from under
// [Unreleased]; the headings come from the canonical list in internal/tools/changelogfrag; no line
// outside the [Unreleased] block changes. #646 removed git-chglog for regenerating CHANGELOG.md
// from commit subjects. This tool generates no prose: it moves hand-written lines.
//
// WHAT IT REFUSES, with exit 1: a file in changelog.d/ other than README.md that is not a
// well-formed fragment; a CHANGELOG.md without exactly one `## [Unreleased]` line, or without a
// blank line where the section goes; and old-style entries that do not parse. A release must never
// drop a note silently, so the alternative to rendering a file is stopping, not skipping it. The
// PR check (internal/tools/changelogcheck) applies the same parser, so these surface on the PR.
//
// Exit 0 also covers the two no-ops of -write: the tag's heading already exists (a re-pushed tag),
// and nothing to promote. Usage errors exit 2.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/tools/changelogfrag"
)

var (
	releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	previewTag = regexp.MustCompile(`^v[0-9A-Za-z][0-9A-Za-z.+-]*$`)
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("changelogrender", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", changelogfrag.Dir, "the fragment directory")
	tag := flags.String("tag", "", "the release the section is headed with: vX.Y.Z, or any v-name for a preview (make changelog-preview passes vNEXT)")
	changelog := flags.String("changelog", "CHANGELOG.md", "CHANGELOG.md: read for old-style entries under [Unreleased] and, with -write, rewritten; empty renders the fragments alone")
	write := flags.Bool("write", false, "promote into -changelog instead of printing the section")
	del := flags.Bool("delete-fragments", false, "with -write: delete the rendered fragment files afterwards (scripts/promote-changelog.sh uses git rm instead)")
	date := flags.String("date", "", "the section's date, YYYY-MM-DD (default: today, UTC)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "changelogrender: "+format+"\n", a...)
		flags.Usage()
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "changelogrender: "+format+"\n", a...)
		return 1
	}
	switch {
	case flags.NArg() > 0:
		return usage("unexpected argument %q", flags.Arg(0))
	case *write && !releaseTag.MatchString(*tag):
		return usage("-write needs -tag vX.Y.Z, got %q", *tag)
	case !previewTag.MatchString(*tag):
		return usage("-tag must be v followed by a release name, such as v2.6.0 or vNEXT, got %q", *tag)
	case *write && *changelog == "":
		return usage("-write needs -changelog")
	case *del && !*write:
		return usage("-delete-fragments needs -write")
	}
	if *date == "" {
		*date = time.Now().UTC().Format("2006-01-02")
	} else if _, err := time.Parse("2006-01-02", *date); err != nil {
		return usage("-date must be YYYY-MM-DD, got %q", *date)
	}

	frags, err := loadFragments(*dir)
	if err != nil {
		return fail("%v", err)
	}
	var lines []string
	finalNewline := true
	if *changelog != "" {
		b, err := os.ReadFile(*changelog)
		if err != nil {
			return fail("%v", err)
		}
		lines, finalNewline = splitLines(b)
	}

	if !*write {
		var legacy []changelogfrag.Section
		if *changelog != "" {
			if _, legacy, err = collect(lines); err != nil {
				return fail("%s: %v", *changelog, err)
			}
		}
		if len(legacy) == 0 && len(frags) == 0 {
			fmt.Fprintf(stderr, "changelogrender: nothing to render: no fragments in %s and no entries under [Unreleased]\n", *dir)
			return 0
		}
		if _, err := stdout.Write(joinLines(Render(*tag, *date, legacy, frags), true)); err != nil {
			return fail("%v", err)
		}
		return 0
	}

	p, err := promote(lines, frags, *tag, *date)
	switch {
	case errors.Is(err, errAlreadyPromoted):
		fmt.Fprintf(stderr, "changelogrender: %s already has a '## [%s]' heading; nothing to do\n", *changelog, *tag)
		return 0
	case errors.Is(err, errNothingToRender):
		fmt.Fprintf(stderr, "changelogrender: nothing to promote for %s: no fragments in %s and no entries under [Unreleased]\n", *tag, *dir)
		return 0
	case err != nil:
		return fail("%s: %v", *changelog, err)
	}
	if err := writeFile(*changelog, joinLines(p.lines, finalNewline)); err != nil {
		return fail("%v", err)
	}
	if *del {
		for _, f := range frags {
			if err := os.Remove(filepath.Join(*dir, f.Name)); err != nil {
				return fail("wrote %s, but could not delete a rendered fragment (%v); delete it before the next release, or that release renders it again", *changelog, err)
			}
		}
	}
	fmt.Fprintf(stderr, "changelogrender: wrote '## [%s] - %s' into %s from %d fragment(s) and %d old-style line(s) under [Unreleased]\n",
		*tag, *date, *changelog, len(frags), p.legacyLines)
	return 0
}

// loadFragments reads every file in dir except README.md, in file-name order, and parses each as a
// fragment. A missing dir holds no fragments. Every problem is reported, not only the first, so a
// release that stops on them lists everything there is to fix.
func loadFragments(dir string) ([]Fragment, error) {
	entries, err := os.ReadDir(dir) // sorted by file name
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var frags []Fragment
	var errs []error
	for _, e := range entries {
		name := e.Name()
		p := filepath.Join(dir, name)
		switch {
		case name == changelogfrag.Readme:
			continue
		case !e.Type().IsRegular():
			errs = append(errs, fmt.Errorf("%s: not a regular file; %s holds fragment files and its %s, nothing else", p, dir, changelogfrag.Readme))
			continue
		case !changelogfrag.ValidName(name):
			errs = append(errs, fmt.Errorf("%s: not a fragment name; %s holds fragments and its %s only, and a fragment is named %s", p, dir, changelogfrag.Readme, changelogfrag.NameRule))
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sec, err := changelogfrag.ParseFragment(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		frags = append(frags, Fragment{Name: name, Section: sec})
	}
	if len(errs) > 0 {
		errs = append(errs, errors.New("("+changelogfrag.Format()+")"))
		return nil, errors.Join(errs...)
	}
	return frags, nil
}

// writeFile replaces path with data by renaming a temporary file over it, so a failed write never
// leaves a truncated CHANGELOG.md, and keeps the file's permission bits.
func writeFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once the rename has happened
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
