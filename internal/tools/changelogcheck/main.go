// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// targetOSes are unioned because `go list` resolves build constraints for one GOOS at a time: a
// package imported only from a _windows.go file is absent from a linux runner's graph, and that
// package ships in the windows binary.
var targetOSes = []string{"linux", "darwin", "windows"}

// hunkHeader matches the new-file half of a unified-diff hunk header: "@@ -a,b +c,d @@".
var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

func main() {
	base := flag.String("base", "HEAD^1", "commit the PR is compared against (on a pull_request checkout, HEAD^1 is the base tip)")
	head := flag.String("head", "HEAD", "commit holding the merge result")
	prHead := flag.String("pr-head", "", "post-merge mode: the merged PR's head commit; compares where its branch put the CHANGELOG entry with where the merge put it")
	flag.Parse()

	var res Result
	var err error
	if *prHead != "" {
		res, err = runPostMerge(*base, *head, *prHead)
	} else {
		res, err = run(*base, *head)
	}
	if err != nil {
		annotate("error", "changelog check could not run: "+err.Error())
		os.Exit(2)
	}
	for _, w := range res.Warnings {
		annotate("warning", w)
	}
	level := "notice"
	if !res.Pass {
		level = "error"
	}
	for _, m := range res.Messages {
		annotate(level, m)
	}
	if !res.Pass {
		os.Exit(1)
	}
}

func run(base, head string) (Result, error) {
	module, err := output("go", "list", "-m")
	if err != nil {
		return Result{}, err
	}
	module = strings.TrimSpace(module)
	root, err := output("git", "rev-parse", "--show-toplevel")
	if err != nil {
		return Result{}, err
	}
	shipped, err := loadShipped(strings.TrimSpace(root), module)
	if err != nil {
		return Result{}, err
	}
	// Non-vacuity: an empty set would make every PR "no entry required" and pass silently — the
	// failure this tool exists to end. The binary's own main package must be in it.
	if shipped.Len() == 0 || !shipped.Contains("cmd/main.go") {
		return Result{}, fmt.Errorf("shipped-package set is empty or lacks cmd/main.go (%d dirs); go list output is not what this tool expects", shipped.Len())
	}

	// -z: git otherwise C-quotes paths with unusual bytes, and a quoted path never matches the set.
	// Plumbing (diff-tree) rather than `git diff`, so a developer's diff.relative, diff.external or
	// rename config cannot change what this reads when it runs from make pr-checklist.
	changedOut, err := output("git", "diff-tree", "-r", "--name-only", "--no-renames", "-z", base, head)
	if err != nil {
		return Result{}, err
	}
	var changed []string
	for _, f := range strings.Split(changedOut, "\x00") {
		if f != "" {
			changed = append(changed, f)
		}
	}

	in := Input{
		Title:        os.Getenv("PR_TITLE"),
		Author:       os.Getenv("PR_AUTHOR"),
		ChangedFiles: changed,
		Shipped:      shipped,
	}
	if raw := os.Getenv("PR_LABELS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &in.Labels); err != nil {
			return Result{}, fmt.Errorf("PR_LABELS is not a JSON string array: %w", err)
		}
	}

	for _, f := range changed {
		if f == "CHANGELOG.md" {
			if in.ChangelogAfter, in.ChangelogAdded, err = changelogAdditions(base, head); err != nil {
				return Result{}, err
			}
		}
	}
	return Evaluate(in), nil
}

// runPostMerge checks a merge that already landed on main: base..head is the push, prHead the
// merged PR's last commit. The PR's own view is diffed from its merge-base with base, which is the
// main it was written against.
func runPostMerge(base, head, prHead string) (Result, error) {
	mergedLines, mergedAdded, err := changelogAdditions(base, head)
	if err != nil {
		return Result{}, err
	}
	mb, err := output("git", "merge-base", prHead, base)
	if err != nil {
		return Result{}, err
	}
	ownLines, ownAdded, err := changelogAdditions(strings.TrimSpace(mb), prHead)
	if err != nil {
		return Result{}, err
	}
	return EvaluatePostMerge(place(ownLines, ownAdded), place(mergedLines, mergedAdded)), nil
}

// changelogAdditions returns CHANGELOG.md at head and the line numbers base..head added to it. A file
// deleted at head yields an empty, non-nil slice: no [Unreleased] heading exists to satisfy a rule.
func changelogAdditions(base, head string) ([]string, []int, error) {
	after, err := output("git", "show", head+":CHANGELOG.md")
	if err != nil {
		return []string{}, nil, nil
	}
	// Explicit flags, so no diff config of the caller's (diff.interHunkContext fusing hunks with
	// context lines, colour, an external differ) can shift the line numbers addedLines computes.
	diff, err := output("git", "diff-tree", "-p", "-U0", "--inter-hunk-context=0", "--no-renames",
		"--no-color", "--no-ext-diff", base, head, "--", "CHANGELOG.md")
	if err != nil {
		return nil, nil, err
	}
	return strings.Split(after, "\n"), addedLines(diff), nil
}

// loadShipped unions the shipped package set across targetOSes. A package belongs to the module
// only if `.Module.Path` is this module; standard-library and third-party packages carry a
// different module (or none) and are dropped.
func loadShipped(root, module string) (ShippedSet, error) {
	type pkg struct {
		Dir        string
		EmbedFiles []string
		Module     *struct{ Path string }
	}
	// git and go can spell one directory two ways through a symlink (macOS's /var is /private/var),
	// and then every package looks like it is outside the repository.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	dirs, embeds := map[string]bool{}, map[string]bool{}
	for _, goos := range targetOSes {
		args := []string{"list", "-deps", "-json=Dir,EmbedFiles,Module"}
		for _, r := range rootDirs {
			args = append(args, "./"+r+"/...")
		}
		cmd := exec.Command("go", args...)
		cmd.Dir = root // the patterns are relative to the module root, wherever this was started
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return ShippedSet{}, fmt.Errorf("go list (GOOS=%s): %v: %s", goos, err, strings.TrimSpace(stderr.String()))
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		for dec.More() {
			var p pkg
			if err := dec.Decode(&p); err != nil {
				return ShippedSet{}, fmt.Errorf("go list (GOOS=%s): %w", goos, err)
			}
			if p.Module == nil || p.Module.Path != module {
				continue
			}
			dir := p.Dir
			if d, err := filepath.EvalSymlinks(dir); err == nil {
				dir = d
			}
			rel, err := filepath.Rel(root, dir)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			rel = filepath.ToSlash(rel)
			dirs[rel] = true
			for _, e := range p.EmbedFiles {
				embeds[rel+"/"+filepath.ToSlash(e)] = true
			}
		}
	}
	return NewShippedSet(keys(dirs), keys(embeds)), nil
}

// addedLines returns the new-file line numbers of every '+' line in a -U0 unified diff.
func addedLines(diff string) []int {
	var added []int
	next, inHunk := 0, false
	sc := bufio.NewScanner(strings.NewReader(diff))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024) // CHANGELOG bullets are single very long lines
	for sc.Scan() {
		l := sc.Text()
		if m := hunkHeader.FindStringSubmatch(l); m != nil {
			next, _ = strconv.Atoi(m[1])
			inHunk = true
			continue
		}
		// The "+++ b/CHANGELOG.md" header precedes the first hunk. Inside a hunk, a line starting
		// "+++" is an added line whose content starts "++", and must be counted.
		if !inHunk {
			continue
		}
		switch {
		case strings.HasPrefix(l, "+"):
			added = append(added, next)
			next++
		case strings.HasPrefix(l, " "):
			next++ // a context line, if any reached here, still occupies a new-file line
		}
	}
	return added
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// annotate prints one line, as a GitHub workflow command when running in Actions so it surfaces on
// the PR, and plainly otherwise.
func annotate(level, msg string) { annotateTo(os.Stdout, level, msg) }

func annotateTo(w io.Writer, level, msg string) {
	// File paths in a message are PR-controlled, and the runner's legacy parser acts on "##[" anywhere
	// in a line; break the sequence so a crafted file name cannot become a second command.
	msg = strings.ReplaceAll(msg, "##[", "#\u200b#[")
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		// Workflow-command data must escape %, CR and LF or the message is truncated or misparsed.
		r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
		fmt.Fprintf(w, "::%s title=CHANGELOG::%s\n", level, r.Replace(msg))
		return
	}
	fmt.Fprintf(w, "%s: %s\n", level, msg)
}
